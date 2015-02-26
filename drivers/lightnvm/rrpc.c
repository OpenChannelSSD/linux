/*
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mabj@itu.dk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 * Implementation of a Round-robin page-based Hybrid FTL for Open-channel SSDs.
 */

#include "rrpc.h"

static struct kmem_cache *_addr_cache;
static DECLARE_RWSEM(_lock);

#define rrpc_for_each_lun(rrpc, rlun, i) \
		for ((i) = 0, rlun = &(rrpc)->luns[0]; \
			(i) < (rrpc)->nr_luns; (i)++, rlun = &(rrpc)->luns[(i)])

static void invalidate_block_page(struct nvm_dev *dev, struct nvm_addr *p)
{
	struct nvm_block *block = p->block;
	unsigned int page_offset;

	if (!block)
		return;

	spin_lock(&block->lock);
	page_offset = p->addr % dev->nr_pages_per_blk;
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
	spin_unlock(&block->lock);
}

static inline void __nvm_page_invalidate(struct rrpc *rrpc, struct nvm_addr *a)
{
	BUG_ON(!spin_is_locked(&rrpc->rev_lock));
	if (a->addr == ADDR_EMPTY)
		return;

	invalidate_block_page(rrpc->q_nvm, a);
	rrpc->rev_trans_map[a->addr - rrpc->poffset].addr = ADDR_EMPTY;
}

static void rrpc_invalidate_range(struct rrpc *rrpc, sector_t slba, unsigned len)
{
	sector_t i;

	spin_lock(&rrpc->rev_lock);
	for (i = slba; i < slba + len; i++) {
		struct nvm_addr *gp = &rrpc->trans_map[i];

		__nvm_page_invalidate(rrpc, gp);
		gp->block = NULL;
	}
	spin_unlock(&rrpc->rev_lock);
}

static struct request *rrpc_inflight_laddr_acquire(struct rrpc *rrpc,
					sector_t laddr, unsigned int pages)
{
	struct request *rq;
	struct rrpc_inflight_rq *inf;

	rq = blk_mq_alloc_request(rrpc->q_dev, READ, GFP_NOIO, false);
	if (!rq)
		return ERR_PTR(-ENOMEM);

	inf = rrpc_get_inflight_rq(rq);
	while (rrpc_lock_laddr(rrpc, laddr, pages, inf))
		schedule();

	return rq;
}

static void rrpc_inflight_laddr_release(struct rrpc *rrpc, struct request *rq)
{
	struct rrpc_inflight_rq *inf;

	inf = rrpc_get_inflight_rq(rq);
	rrpc_unlock_laddr(rrpc, inf->l_start, inf);

	blk_mq_free_request(rq);
}

static void rrpc_discard(struct rrpc *rrpc, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t len = bio->bi_iter.bi_size / EXPOSED_PAGE_SIZE;
	struct request *rq;

	rq = rrpc_inflight_laddr_acquire(rrpc, slba, len);
	if (IS_ERR(rq)) {
		bio_io_error(bio);
		return;
	}

	rrpc_invalidate_range(rrpc, slba, len);
	rrpc_inflight_laddr_release(rrpc, rq);
}

/* requires lun->lock taken */
static void rrpc_set_lun_cur(struct rrpc_lun *rlun, struct nvm_block *block)
{
	BUG_ON(!block);

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(rlun->cur));
		spin_unlock(&rlun->cur->lock);
	}
	rlun->cur = block;
}

static struct rrpc_lun *get_next_lun(struct rrpc *rrpc)
{
	int next = atomic_inc_return(&rrpc->next_lun);

	return &rrpc->luns[next % rrpc->nr_luns];
}

static void rrpc_gc_kick(struct rrpc *rrpc)
{
	struct rrpc_lun *rlun;
	unsigned int i;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];
		queue_work(rrpc->krqd_wq, &rlun->ws_gc);
	}
}

/**
 * rrpc_gc_timer - default gc timer function.
 * @data: ptr to the 'nvm' structure
 *
 * Description:
 *   rrpc configures a timer to kick the GC to force proactive behavior.
 *
 **/
static void rrpc_gc_timer(unsigned long data)
{
	struct rrpc *rrpc = (struct rrpc *)data;

	rrpc_gc_kick(rrpc);

	blk_mq_kick_requeue_list(rrpc->q_dev);

	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));
}

static void rrpc_end_sync_bio(struct bio *bio, int error)
{
	struct completion *waiting = bio->bi_private;

	if (error)
		pr_err("lightnvm: gc request failed.\n");

	complete(waiting);
}

/*
 * rrpc_move_valid_pages -- migrate live data off the block
 * @rrpc: the 'rrpc' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
static int rrpc_move_valid_pages(struct rrpc *rrpc, struct nvm_block *block)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct request_queue *q = rrpc->q_dev;
	struct nvm_rev_addr *rev;
	struct bio *bio;
	struct request *rq;
	struct page *page;
	int slot;
	sector_t phys_addr;
	DECLARE_COMPLETION_ONSTACK(wait);

	if (bitmap_full(block->invalid_pages, dev->nr_pages_per_blk))
		return 0;

	bio = bio_alloc(GFP_NOIO, 1);
	if (!bio) {
		pr_err("lightnvm: could not alloc bio on gc\n");
		return -ENOMEM;
	}

	page = mempool_alloc(rrpc->page_pool, GFP_NOIO);

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   dev->nr_pages_per_blk)) <
						dev->nr_pages_per_blk) {

		/* Lock laddr */
		phys_addr = block_to_addr(block) + slot;

		spin_lock(&rrpc->rev_lock);
		/* Get logical address from physical to logical table */
		rev = &rrpc->rev_trans_map[phys_addr - rrpc->poffset];
		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&rrpc->rev_lock);
			continue;
		}

		rq = rrpc_inflight_laddr_acquire(rrpc, rev->addr, 1);
		spin_unlock(&rrpc->rev_lock);

		/* Perform read to do GC */
		bio->bi_iter.bi_sector = nvm_get_sector(rev->addr);
		bio->bi_rw |= (READ | REQ_NVM_NO_INFLIGHT);
		bio->bi_private = &wait;
		bio->bi_end_io = rrpc_end_sync_bio;

		/* TODO: may fail when EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, bio, page, EXPOSED_PAGE_SIZE, 0);

		/* execute read */
		q->make_request_fn(q, bio);
		wait_for_completion_io(&wait);

		/* and write it back */
		bio_reset(bio);
		reinit_completion(&wait);

		bio->bi_iter.bi_sector = nvm_get_sector(rev->addr);
		bio->bi_rw |= (WRITE | REQ_NVM_NO_INFLIGHT);
		bio->bi_private = &wait;
		bio->bi_end_io = rrpc_end_sync_bio;
		/* TODO: may fail when EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, bio, page, EXPOSED_PAGE_SIZE, 0);

		q->make_request_fn(q, bio);
		wait_for_completion_io(&wait);

		rrpc_inflight_laddr_release(rrpc, rq);

		/* reset structures for next run */
		reinit_completion(&wait);
		bio_reset(bio);
	}

	mempool_free(page, rrpc->page_pool);
	bio_put(bio);

	if (!bitmap_full(block->invalid_pages, rrpc->q_nvm->nr_pages_per_blk)) {
		pr_err("lightnvm: failed to garbage collect block\n");
		return -EIO;
	}

	return 0;
}

static void rrpc_block_gc(struct work_struct *work)
{
	struct rrpc_block_gc *gcb = container_of(work, struct rrpc_block_gc,
									ws_gc);
	struct rrpc *rrpc = gcb->rrpc;
	struct nvm_block *block = gcb->block;
	struct nvm_dev *dev = rrpc->q_nvm;

	pr_debug("lightnvm: block '%d' being reclaimed\n", block->id);

	if (rrpc_move_valid_pages(rrpc, block))
		goto done;

	blk_nvm_erase_blk(dev, block);
	blk_nvm_put_blk(block);
done:
	kfree(gcb);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct rrpc_block *rblock_max_invalid(struct rrpc_block *ra,
					       struct rrpc_block *rb)
{
	struct nvm_block *a = ra->parent;
	struct nvm_block *b = rb->parent;

	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return ra;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock */
static struct rrpc_block *block_prio_find_max(struct rrpc_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct rrpc_block *rblock, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct rrpc_block, prio);
	list_for_each_entry(rblock, prio_list, prio)
		max = rblock_max_invalid(max, rblock);

	return max;
}

static void rrpc_lun_gc(struct work_struct *work)
{
	struct rrpc_lun *rlun = container_of(work, struct rrpc_lun, ws_gc);
	struct rrpc *rrpc = rlun->rrpc;
	struct nvm_lun *lun = rlun->parent;
	struct rrpc_block_gc *gcb;
	unsigned int nr_blocks_need;

	nr_blocks_need = lun->nr_blocks / GC_LIMIT_INVERSE;

	if (nr_blocks_need < rrpc->nr_luns)
		nr_blocks_need = rrpc->nr_luns;

	spin_lock(&lun->lock);
	while (nr_blocks_need > lun->nr_free_blocks &&
					!list_empty(&rlun->prio_list)) {
		struct rrpc_block *rblock = block_prio_find_max(rlun);
		struct nvm_block *block = rblock->parent;

		if (!block->nr_invalid_pages)
			break;

		list_del_init(&rblock->prio);

		BUG_ON(!block_is_full(block));

		pr_debug("lightnvm: selected block '%d' as GC victim\n",
								block->id);

		gcb = kmalloc(sizeof(struct rrpc_block_gc), GFP_ATOMIC);
		if (!gcb)
			break;

		gcb->rrpc = rrpc;
		gcb->block = rblock->parent;
		INIT_WORK(&gcb->ws_gc, rrpc_block_gc);

		queue_work(rrpc->kgc_wq, &gcb->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&lun->lock);

	/* TODO: Hint that request queue can be started again */
}

static void rrpc_gc_queue(struct rrpc* rrpc, struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;
	struct rrpc_lun *rlun = &rrpc->luns[lun->id - rrpc->lun_offset];
	struct rrpc_block *rblock =
			&rlun->blocks[block->id % lun->nr_blocks];

	spin_lock(&lun->lock);
	list_add_tail(&rblock->prio, &rlun->prio_list);
	spin_unlock(&lun->lock);

	pr_debug("nvm: block '%d' is full, allow GC (sched)\n", block->id);
}

static int rrpc_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	return 0;
}

static int rrpc_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void rrpc_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations rrpc_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= rrpc_ioctl,
	.open		= rrpc_open,
	.release	= rrpc_release,
};

static struct rrpc_lun *__rrpc_get_lun_rr(struct rrpc *rrpc, int is_gc)
{
	unsigned int i;
	struct rrpc_lun *rlun, *max_free;

	if (!is_gc)
		return get_next_lun(rrpc);

	/* FIXME */
	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns. */
	max_free = &rrpc->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate. */
	rrpc_for_each_lun(rrpc, rlun, i) {
		if (rlun->parent->nr_free_blocks >
					max_free->parent->nr_free_blocks)
			max_free = rlun;
	}

	return max_free;
}

static inline void __rrpc_page_invalidate(struct rrpc *rrpc,
							struct nvm_addr *gp)
{
	BUG_ON(!spin_is_locked(&rrpc->rev_lock));
	if (gp->addr == ADDR_EMPTY)
		return;

	invalidate_block_page(rrpc->q_nvm, gp);
	rrpc->rev_trans_map[gp->addr - rrpc->poffset].addr = ADDR_EMPTY;
}

void nvm_update_map(struct rrpc *rrpc, sector_t l_addr, struct nvm_addr *p,
					int is_gc)
{
	struct nvm_addr *gp;
	struct nvm_rev_addr *rev;

	BUG_ON(l_addr >= rrpc->nr_pages);

	gp = &rrpc->trans_map[l_addr];
	spin_lock(&rrpc->rev_lock);
	if (gp->block)
		__nvm_page_invalidate(rrpc, gp);

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &rrpc->rev_trans_map[p->addr - rrpc->poffset];
	rev->addr = l_addr;
	spin_unlock(&rrpc->rev_lock);
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns nvm_addr with the physical address and block. Remember to return to
 * rrpc->addr_cache when request is finished.
 */
static struct nvm_addr *rrpc_map_page(struct rrpc *rrpc, sector_t laddr,
								int is_gc)
{
	struct nvm_addr *p;
	struct rrpc_lun *rlun;
	struct nvm_lun *lun;
	struct nvm_block *p_block;
	sector_t p_addr;

	p = mempool_alloc(rrpc->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	rlun = __rrpc_get_lun_rr(rrpc, is_gc);
	lun = rlun->parent;

	spin_lock(&rlun->lock);

	p_block = rlun->cur;
	p_addr = blk_nvm_alloc_addr(p_block);

	if (p_addr == ADDR_EMPTY) {
		p_block = blk_nvm_get_blk(lun, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = blk_nvm_alloc_addr(rlun->gc_cur);
				if (p_addr == ADDR_EMPTY) {
					p_block = blk_nvm_get_blk(lun, 1);
					if (!p_block) {
						pr_err("rrpc: no more blocks");
						goto finished;
					} else {
						rlun->gc_cur = p_block;
						p_addr =
						blk_nvm_alloc_addr(rlun->gc_cur);
					}
				}
				p_block = rlun->gc_cur;
			}
			goto finished;
		}

		rrpc_set_lun_cur(rlun, p_block);
		p_addr = blk_nvm_alloc_addr(p_block);
	}

finished:
	if (p_addr == ADDR_EMPTY)
		goto err;

	p->addr = p_addr;
	p->block = p_block;

	if (!p_block)
		WARN_ON(is_gc);

	spin_unlock(&rlun->lock);
	if (p)
		nvm_update_map(rrpc, laddr, p, is_gc);
	return p;
err:
	spin_unlock(&rlun->lock);
	mempool_free(p, rrpc->addr_pool);
	return NULL;
}

static int rrpc_map_update(void *targetdata, u64 slba, u64 pba, u64 blk_page)
{
	struct rrpc *rrpc = targetdata;
	struct nvm_addr *addr = rrpc->trans_map + slba;
	struct nvm_rev_addr *raddr = rrpc->rev_trans_map;

	addr[blk_page].addr = pba;
	/* FIXME: missing rrpc->poffset */
	raddr[pba].addr = slba + blk_page;

	return 0;
}

static struct nvm_addr *rrpc_map_get_addr(void *targetdata, sector_t paddr)
{
	struct rrpc *rrpc = targetdata;
	sector_t pladdr;

	pladdr = rrpc->rev_trans_map[paddr - rrpc->poffset].addr;
	if (pladdr == ADDR_EMPTY)
		return NULL;

	return &rrpc->trans_map[pladdr];
}

static void __rrpc_unprep_rq(struct rrpc *rrpc, struct request *rq)
{
	struct nvm_per_rq *pb = get_per_rq_data(rq);
	struct nvm_addr *p = pb->addr;
	struct nvm_block *block = p->block;
	int fill;

	rrpc_unlock_rq(rrpc, rq);

	if (rq_data_dir(rq) == WRITE) {
		fill = atomic_inc_return(&block->data_cmnt_size);
		if (fill == rrpc->q_nvm->nr_pages_per_blk)
			rrpc_gc_queue(rrpc, block);
	}

	/* all submitted requests allocate their own addr,
	 * except GC reads */
	if (rq->cmd_flags & REQ_NVM_NO_INFLIGHT)
		return;

	mempool_free(pb->addr, rrpc->addr_pool);
}

static void rrpc_unprep_rq(struct request_queue *q, struct request *rq)
{
	struct rrpc *rrpc;
	struct bio *bio;

	bio = rq->bio;
	if (unlikely(!bio))
		return;

	rrpc = container_of(bio->bi_lightnvm, struct rrpc, payload);

	if (rq->cmd_flags & REQ_NVM_MAPPED) {
		__rrpc_unprep_rq(rrpc, rq);
		BUG_ON(rq->cmd_flags & REQ_NVM_NO_INFLIGHT);
	}
}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We assume that there is no data and doesn't take a ref */
static struct nvm_addr *rrpc_lookup_ltop(struct rrpc *rrpc, sector_t laddr)
{
	struct nvm_addr *gp, *p;

	BUG_ON(!(laddr >= 0 && laddr < rrpc->nr_pages));

	p = mempool_alloc(rrpc->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	gp = &rrpc->trans_map[laddr];

	p->addr = gp->addr;
	p->block = gp->block;

	return p;
}

static int rrpc_read_rq(struct rrpc *rrpc, struct request *rq)
{
	struct nvm_addr *p;
	struct nvm_per_rq *pb;
	sector_t l_addr = nvm_get_laddr(rq);

	if (rrpc_lock_rq(rrpc, rq))
		return BLK_MQ_RQ_QUEUE_BUSY;

	p = rrpc_lookup_ltop(rrpc, l_addr);
	if (!p) {
		rrpc_unlock_rq(rrpc, rq);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	if (p->block)
		rq->phys_sector = nvm_get_sector(p->addr) +
					(blk_rq_pos(rq) % NR_PHY_IN_LOG);

	pb = get_per_rq_data(rq);
	pb->addr = p;

	return BLK_MQ_RQ_QUEUE_OK;
}

static int rrpc_write_rq(struct rrpc *rrpc, struct request *rq)
{
	struct nvm_per_rq *pb;
	struct nvm_addr *p;
	int is_gc = 0;
	sector_t l_addr = nvm_get_laddr(rq);

	if (rq->cmd_flags & REQ_NVM_NO_INFLIGHT)
		is_gc = 1;

	if (rrpc_lock_rq(rrpc, rq))
		return BLK_MQ_RQ_QUEUE_BUSY;

	p = rrpc_map_page(rrpc, l_addr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		rrpc_unlock_rq(rrpc, rq);
		rrpc_gc_kick(rrpc);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	rq->phys_sector = nvm_get_sector(p->addr);

	pb = get_per_rq_data(rq);
	pb->addr = p;

	return BLK_MQ_RQ_QUEUE_OK;
}

static int __rrpc_prep_rq(struct rrpc *rrpc, struct request *rq)
{
	int rw = rq_data_dir(rq);
	int ret;

	if (rw == WRITE)
		ret = rrpc_write_rq(rrpc, rq);
	else
		ret = rrpc_read_rq(rrpc, rq);

	if (!ret)
		rq->cmd_flags |= (REQ_NVM_MAPPED|REQ_DONTPREP);

	return ret;
}

static int rrpc_prep_rq(struct request_queue *q, struct request *rq)
{
	struct rrpc *rrpc;
	struct bio *bio;

	bio = rq->bio;
	if (unlikely(!bio))
		return 0;

	if (unlikely(!bio->bi_lightnvm)) {
		pr_err("lightnvm: attempting to map unsupported bio\n");
		return BLK_MQ_RQ_QUEUE_ERROR;
	}

	rrpc = container_of(bio->bi_lightnvm, struct rrpc, payload);

	return __rrpc_prep_rq(rrpc, rq);
}

static void rrpc_make_rq(struct request_queue *q, struct bio *bio)
{
	struct rrpc *rrpc = q->queuedata;

	if (bio->bi_rw & REQ_DISCARD) {
		rrpc_discard(rrpc, bio);
		return;
	}

	bio->bi_lightnvm = &rrpc->payload;
	bio->bi_bdev = rrpc->q_bdev;

	generic_make_request(bio);
}

static void rrpc_gc_free(struct rrpc *rrpc)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct rrpc_lun *rlun;
	int i;

	del_timer(&rrpc->gc_timer);

	if (rrpc->krqd_wq)
		destroy_workqueue(rrpc->krqd_wq);

	if (rrpc->kgc_wq)
		destroy_workqueue(rrpc->kgc_wq);

	if (!rrpc->luns)
		return;

	for (i = 0; i < rrpc->nr_luns; i++) {
		rlun = &rrpc->luns[i];

		if (!rlun->blocks)
			break;
		vfree(rlun->blocks);
	}
}

static int rrpc_gc_init(struct rrpc *rrpc)
{
	rrpc->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						rrpc->nr_luns);
	if (!rrpc->krqd_wq)
		return -ENOMEM;

	rrpc->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!rrpc->kgc_wq)
		return -ENOMEM;

	setup_timer(&rrpc->gc_timer, rrpc_gc_timer, (unsigned long)rrpc);

	return 0;
}

static void rrpc_map_free(struct rrpc *rrpc)
{
	vfree(rrpc->rev_trans_map);
	vfree(rrpc->trans_map);
}

static int rrpc_map_init(struct rrpc *rrpc)
{
	sector_t i;

	rrpc->trans_map = vzalloc(sizeof(struct nvm_addr) * rrpc->nr_pages);
	if (!rrpc->trans_map)
		return -ENOMEM;

	rrpc->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* rrpc->nr_pages);
	if (!rrpc->rev_trans_map)
		return -ENOMEM;

	for (i = 0; i < rrpc->nr_pages; i++) {
		struct nvm_addr *p = &rrpc->trans_map[i];
		struct nvm_rev_addr *r = &rrpc->rev_trans_map[i];

		p->addr = ADDR_EMPTY;
		r->addr = ADDR_EMPTY;
	}

	return 0;
}


/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int rrpc_core_init(struct rrpc *rrpc)
{
	int i;

	down_write(&_lock);
	if (!_addr_cache) {
		_addr_cache = kmem_cache_create("nvm_addr_cache",
				sizeof(struct nvm_addr), 0, 0, NULL);
		if (!_addr_cache) {
			up_write(&_lock);
			return -ENOMEM;
		}
	}
	up_write(&_lock);

	rrpc->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!rrpc->page_pool)
		return -ENOMEM;

	rrpc->addr_pool = mempool_create_slab_pool(ADDR_POOL_SIZE, _addr_cache);
	if (!rrpc->addr_pool)
		return -ENOMEM;

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		struct nvm_inflight *map = &rrpc->inflight_map[i];

		spin_lock_init(&map->lock);
		INIT_LIST_HEAD(&map->reqs);
	}

	return 0;
}

static void rrpc_core_free(struct rrpc *rrpc)
{
	down_write(&_lock);
	if (_addr_cache)
		kmem_cache_destroy(_addr_cache);
	up_write(&_lock);

	if (rrpc->addr_pool)
		mempool_destroy(rrpc->addr_pool);
	if (rrpc->page_pool)
		mempool_destroy(rrpc->page_pool);
}

static void rrpc_luns_free(struct rrpc *rrpc)
{
	kfree(rrpc->luns);
}

static int rrpc_luns_init(struct rrpc *rrpc, int lun_begin, int lun_end)
{
	struct nvm_dev *dev = rrpc->q_nvm;
	struct nvm_block *block;
	struct rrpc_lun *rlun;
	int i, j;

	spin_lock_init(&rrpc->rev_lock);

	rrpc->luns = kcalloc(rrpc->nr_luns, sizeof(struct rrpc_lun),
								GFP_KERNEL);
	if (!rrpc->luns)
		return -ENOMEM;

	/* 1:1 mapping */
	for (i = 0; i < rrpc->nr_luns; i++) {
		struct nvm_lun *lun = &dev->luns[i + lun_begin];

		rlun = &rrpc->luns[i];
		rlun->rrpc = rrpc;
		rlun->parent = lun;
		rlun->nr_blocks = lun->nr_blocks;

		rrpc->total_blocks += lun->nr_blocks;
		rrpc->nr_pages += lun->nr_blocks * lun->nr_pages_per_blk;

		block = blk_nvm_get_blk(lun, 0);
		rrpc_set_lun_cur(rlun, block);

		/* Emergency gc block */
		block = blk_nvm_get_blk(lun, 1);
		rlun->gc_cur = block;

		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_WORK(&rlun->ws_gc, rrpc_lun_gc);
		spin_lock_init(&rlun->lock);

		rlun->blocks = vzalloc(sizeof(struct rrpc_block) *
						 rlun->nr_blocks);
		if (!rlun->blocks)
			goto err;

		lun_for_each_block(lun, block, j) {
			struct rrpc_block *rblock = &rlun->blocks[j];

			rblock->parent = block;
			INIT_LIST_HEAD(&rblock->prio);
		}
	}

	return 0;
err:
	return -ENOMEM;
}

static void rrpc_free(struct rrpc *rrpc)
{
	rrpc_gc_free(rrpc);
	rrpc_map_free(rrpc);
	rrpc_core_free(rrpc);
	rrpc_luns_free(rrpc);

	kfree(rrpc);
}

static void rrpc_exit(void *private)
{
	struct rrpc *rrpc = private;

	blkdev_put(rrpc->q_bdev, FMODE_WRITE | FMODE_READ);

	/* FIXME: bring down gendisk and everything else */

	rrpc_free(rrpc);
}

static sector_t rrpc_capacity(void *private)
{
	struct rrpc *rrpc = private;
	struct nvm_lun *lun;
	sector_t reserved;
	int i, max_pages_per_blk = 0;

	nvm_for_each_lun(rrpc->q_nvm, lun, i) {
		if (lun->nr_pages_per_blk > max_pages_per_blk)
			max_pages_per_blk = lun->nr_pages_per_blk;
	}

	/* cur, gc, and two emergency blocks for each lun */
	reserved = rrpc->nr_luns * max_pages_per_blk * 4;

	if (reserved > rrpc->nr_pages) {
		pr_err("rrpc: not enough space available to expose storage.\n");
		return 0;
	}

	return ((rrpc->nr_pages - reserved) / 10) * 9 * NR_PHY_IN_LOG;
}

static void *rrpc_init(struct request_queue *q, struct gendisk *disk,
						int lun_begin, int lun_end)
{
	struct nvm_dev *dev;
	struct block_device *bdev;
	struct rrpc *rrpc;
	int ret;

	if (!blk_queue_lightnvm(q)) {
		pr_err("lightnvm: block device not supported.\n");
		return ERR_PTR(-EINVAL);
	}

	bdev = bdget_disk(disk, 0);
	if (blkdev_get(bdev, FMODE_WRITE | FMODE_READ, NULL)) {
		pr_err("lightnvm: could not access backing device\n");
		return ERR_PTR(-EINVAL);
	}

	dev = blk_nvm_get_dev(q);

	rrpc = kzalloc(sizeof(struct rrpc), GFP_KERNEL);
	if (!rrpc) {
		ret = -ENOMEM;
		goto err;
	}

	rrpc->q_dev = q;
	rrpc->q_nvm = q->nvm;
	rrpc->q_bdev = bdev;
	rrpc->nr_luns = lun_end - lun_begin + 1;

	/* simple round-robin strategy */
	atomic_set(&rrpc->next_lun, -1);

	ret = rrpc_luns_init(rrpc, lun_begin, lun_end);
	if (ret) {
		pr_err("lightnvm: could not initialize luns\n");
		goto err;
	}

	rrpc->poffset = rrpc->luns[0].parent->nr_blocks * rrpc->luns[0].parent->nr_pages_per_blk * lun_begin;
	rrpc->lun_offset = lun_begin;

	ret = rrpc_core_init(rrpc);
	if (ret) {
		pr_err("lightnvm: rrpc: could not initialize core\n");
		goto err;
	}

	ret = rrpc_map_init(rrpc);
	if (ret) {
		pr_err("lightnvm: rrpc: could not initialize maps\n");
		goto err;
	}

	ret = rrpc_gc_init(rrpc);
	if (ret) {
		pr_err("lightnvm: rrpc: could not initialize gc\n");
		goto err;
	}

	pr_info("lightnvm: rrpc initialized with %u luns and %llu pages.\n",
			rrpc->nr_luns, (unsigned long long)rrpc->nr_pages);

	mod_timer(&rrpc->gc_timer, jiffies + msecs_to_jiffies(10));

	return rrpc;
err:
	blkdev_put(bdev, FMODE_WRITE | FMODE_READ);
	rrpc_free(rrpc);
	return ERR_PTR(ret);
}

/* round robin, page-based FTL, and cost-based GC */
static struct nvm_target_type tt_rrpc = {
	.name		= "rrpc",

	.make_rq	= rrpc_make_rq,
	.prep_rq	= rrpc_prep_rq,
	.unprep_rq	= rrpc_unprep_rq,
	.capacity	= rrpc_capacity,
	.init		= rrpc_init,
	.exit		= rrpc_exit,
};

static int __init rrpc_module_init (void)
{
	return nvm_register_target(&tt_rrpc);
}

static void rrpc_module_exit (void)
{
	nvm_unregister_target(&tt_rrpc);
}

module_init(rrpc_module_init);
module_exit(rrpc_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Round-Robin Cost-based Hybrid Layer for Open-Channel SSDs");

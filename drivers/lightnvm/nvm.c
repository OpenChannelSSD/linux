/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * Todo
 *
 * - Implement fetching of bad pages from flash
 * - configurable sector size
 * - handle case of in-page bv_offset (currently hidden assumption of offset=0,
 *   and bv_len spans entire page)
 *
 * Optimization possibilities
 * - Implement per-cpu nvm_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   nvm_block lists.
 */

#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/sem.h>
#include <linux/types.h>
#include <linux/lightnvm.h>

#include <linux/ktime.h>

#define CREATE_TRACE_POINTS
#include <trace/events/nvm.h>

#include "nvm.h"


/* Defaults
 * Number of append points per pool. We assume that accesses within a pool is
 * serial (NAND flash/PCM/etc.)
 */
#define APS_PER_POOL 1

/* Run GC every X seconds */
#define GC_TIME 10

/* Minimum pages needed within a pool */
#define MIN_POOL_PAGES 16

extern struct nvm_target_type nvm_target_rrpc;
extern struct nvm_gc_type nvm_gc_greedy;

static struct kmem_cache *_addr_cache;

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

struct nvm_target_type *find_nvm_target_type(const char *name)
{
	struct nvm_target_type *tt;

	list_for_each_entry(tt, &_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *tt)
{
	int ret = 0;

	down_write(&_lock);
	if (find_nvm_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &_targets);
	up_write(&_lock);
	return ret;
}

void nvm_unregister_target(struct nvm_target_type *tt)
{
	if (!tt)
		return;

	down_write(&_lock);
	list_del(&tt->list);
	up_write(&_lock);
}

int nvm_map_rq(struct nvm_dev *dev, struct request *rq)
{
	struct nvm_stor *s = dev->stor;
	int ret;

	trace_nvm_rq_map_begin(rq);

	if (rq_data_dir(rq) == WRITE)
		ret = s->type->write_rq(s, rq);
	else
		ret = s->type->read_rq(s, rq);

	if (!ret)
		rq->cmd_flags |= (REQ_NVM|REQ_NVM_MAPPED);

	trace_nvm_rq_map_end(rq);

	return ret;
}

int nvm_discard_rq(struct nvm_dev *dev, struct request *rq)
{
	sector_t npages = blk_rq_bytes(rq) / EXPOSED_PAGE_SIZE;
	sector_t l_addr = blk_rq_pos(rq) / NR_PHY_IN_LOG;
	struct nvm_stor *s = dev->stor;

	while (npages > 0)
	{
		sector_t cur_pages = min_t(sector_t,
						npages, NVM_INFLIGHT_TAGS / 2);

		nvm_lock_laddr_range(s, l_addr, cur_pages);
		nvm_invalidate_range(s, l_addr, cur_pages);
		nvm_unlock_laddr_range(s, l_addr, cur_pages);

		l_addr += cur_pages;
		npages -= cur_pages;
	}

	rq->cmd_flags |= REQ_NVM;
	blk_mq_end_request(rq, 0);
	return NVM_RQ_PROCESSED;
}

int nvm_process_rq(struct nvm_dev *dev, struct request *rq)
{
	if (unlikely(rq->cmd_flags & REQ_NVM_MAPPED)) {
		pr_err("lightnvm: attempting to map already mapped request\n");
		return NVM_RQ_ERR_MAPPED;
	}

	if (rq->cmd_flags & REQ_DISCARD)
		return nvm_discard_rq(dev, rq);

	return nvm_map_rq(dev, rq);
}
EXPORT_SYMBOL_GPL(nvm_process_rq);

void nvm_complete_request(struct nvm_dev *nvm_dev, struct request *rq, int error)
{
	if (rq->cmd_flags & REQ_DISCARD)
		return;

	if (rq->cmd_flags & (REQ_NVM|REQ_NVM_MAPPED))
		nvm_endio(nvm_dev, rq, error);

	if (!(rq->cmd_flags & REQ_NVM))
		pr_info("lightnvm: request outside lightnvm detected.\n");
}
EXPORT_SYMBOL_GPL(nvm_complete_request);

unsigned int nvm_cmd_size(void)
{
	return sizeof(struct per_rq_data);
}
EXPORT_SYMBOL_GPL(nvm_cmd_size);

static void nvm_aps_free(struct nvm_stor *s)
{
	kfree(s->aps);
}

static void nvm_pools_free(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	int i;

	if (s->krqd_wq)
		destroy_workqueue(s->krqd_wq);

	if (s->kgc_wq)
		destroy_workqueue(s->kgc_wq);

	nvm_for_each_pool(s, pool, i) {
		if (!pool->blocks)
			break;
		vfree(pool->blocks);
	}

	kfree(s->pools);
}

static int nvm_pools_init(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	struct nvm_id_chnl *chnl;
	int i;

	spin_lock_init(&s->rev_lock);

	s->pools = kcalloc(s->nr_pools, sizeof(struct nvm_pool), GFP_KERNEL);
	if (!s->pools)
		return -ENOMEM;

	nvm_for_each_pool(s, pool, i) {
		chnl = &s->id.chnls[i];
		pr_info("lightnvm: p %u qsize %u gr %u ge %u begin %llu end %llu\n",
			i, chnl->queue_size, chnl->gran_read, chnl->gran_erase,
			chnl->laddr_begin, chnl->laddr_end);

		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);

		pool->id = i;
		pool->s = s;
		pool->chnl = chnl;
		pool->nr_free_blocks = pool->nr_blocks =
				(chnl->laddr_end - chnl->laddr_begin + 1) /
				(chnl->gran_erase / chnl->gran_read);

		/* TODO: Global values derived from variable size pools */
		s->total_blocks += pool->nr_blocks;
		/* TODO: make blks per pool variable amond channels */
		s->nr_blks_per_pool = pool->nr_free_blocks;
		/* TODO: gran_{read,write} may differ */
		s->nr_pages_per_blk = chnl->gran_erase / chnl->gran_read *
					(chnl->gran_read / s->sector_size);
	}

	/* we make room for each pool context. */
	s->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						s->nr_pools);
	if (!s->krqd_wq)
		return -ENOMEM;

	s->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!s->kgc_wq)
		return -ENOMEM;

	return 0;
}

/*
 * Looks up the logical address from reverse trans map and check if its valid by
 * comparing the logical to physical address with the physical address.
 * Returns 0 on free, otherwise 1 if in use
 */
static int nvm_block_map(struct nvm_stor *s, struct nvm_block *block)
{
	int offset, used = 0;
	struct nvm_addr *laddr;
	sector_t paddr, pladdr;

	for (offset = 0; offset < s->nr_pages_per_blk; offset++) {
		paddr = block_to_addr(block) + offset;

		pladdr = s->rev_trans_map[paddr].addr;
		if (pladdr == ADDR_EMPTY)
			continue;

		laddr = &s->trans_map[pladdr];

		if (paddr == laddr->addr) {
			laddr->block = block;
		} else {
			set_bit(offset, block->invalid_pages);
			block->nr_invalid_pages++;
		}

		used = 1;
	}

	return used;
}

static int nvm_blocks_init(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	struct nvm_block *block;
	sector_t pool_iter, block_iter, cur_block_id = 0;

	nvm_for_each_pool(s, pool, pool_iter) {
		pool->blocks = vzalloc(sizeof(struct nvm_block) *
						pool->nr_blocks);
		if (!pool->blocks)
			return -ENOMEM;

		pool_for_each_block(pool, block, block_iter) {
			spin_lock_init(&block->lock);
			atomic_set(&block->gc_running, 0);
			INIT_LIST_HEAD(&block->list);

			block->pool = pool;
			block->id = cur_block_id++;

			if (nvm_block_map(s, block))
				list_add_tail(&block->list, &pool->used_list);
			else
				list_add_tail(&block->list, &pool->free_list);
		}
	}

	return 0;
}

static int nvm_aps_init(struct nvm_stor *s)
{
	struct nvm_block *block;
	struct nvm_ap *ap;
	int i;

	s->nr_aps = s->nr_aps_per_pool * s->nr_pools;
	s->aps = kcalloc(s->nr_aps, sizeof(struct nvm_ap), GFP_KERNEL);
	if (!s->aps)
		return -ENOMEM;;

	nvm_for_each_ap(s, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = s;
		ap->pool = &s->pools[i / s->nr_aps_per_pool];

		block = s->type->pool_get_blk(ap->pool, 0);
		nvm_set_ap_cur(ap, block);

		/* Emergency gc block */
		block = s->type->pool_get_blk(ap->pool, 1);
		ap->gc_cur = block;
	}

	return 0;
}

static void nvm_stor_free(struct nvm_stor *s)
{
	percpu_ida_destroy(&s->free_inflight);
	if (s->addr_pool)
		mempool_destroy(s->addr_pool);
	if (s->page_pool)
		mempool_destroy(s->page_pool);
	vfree(s->rev_trans_map);
	vfree(s->trans_map);
	kfree(s);
}

static int nvm_stor_map_init(struct nvm_stor *s)
{
	sector_t i;

	s->trans_map = vzalloc(sizeof(struct nvm_addr) * s->nr_pages);
	if (!s->trans_map)
		return -ENOMEM;

	s->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* s->nr_pages);
	if (!s->rev_trans_map)
		return -ENOMEM;;

	for (i = 0; i < s->nr_pages; i++) {
		struct nvm_addr *p = &s->trans_map[i];
		struct nvm_rev_addr *r = &s->rev_trans_map[i];

		p->addr = ADDR_EMPTY;
		r->addr = ADDR_EMPTY;
	}

	return 0;
}

static int nvm_stor_init(struct nvm_stor *s)
{
	int i;

	s->nr_pools = s->id.nchannels;
	s->nr_aps_per_pool = APS_PER_POOL;
	s->config.gc_time = GC_TIME;
	s->sector_size = EXPOSED_PAGE_SIZE;

	s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
	if (!s->page_pool)
		return -ENOMEM;

	s->addr_pool = mempool_create_slab_pool(64, _addr_cache);
	if (!s->addr_pool)
		return -ENOMEM;

	/* inflight maintenance */
	if (percpu_ida_init(&s->free_inflight, NVM_INFLIGHT_TAGS))
		return -ENOMEM;

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&s->inflight_map[i].lock);
		INIT_LIST_HEAD(&s->inflight_map[i].reqs);
	}

	/* simple round-robin strategy */
	atomic_set(&s->next_write_ap, -1);

	return 0;
}

static int nvm_l2p_tbl_init(struct nvm_stor *s, u64 slba, u64 nlb,
							__le64 *tbl_sgmt)
{
	struct nvm_addr *addr = s->trans_map + slba;
	struct nvm_rev_addr *raddr = s->rev_trans_map;
	sector_t max_pages = s->nr_pages * (s->sector_size >> 9);
	u64 elba = slba + nlb;
	u64 i;

	if (unlikely(elba > s->nr_pages)) {
		pr_err("lightnvm: L2P data from device is out of bounds - stopping!\n");
		return -EINVAL;
	}

	for (i = 0; i < nlb; i++) {
		/* notice that the values are 1-indexed. 0 is unmapped */
		u64 pba = le64_to_cpu(tbl_sgmt[i]);
		/* LNVM treats address-spaces as silos, i.e. LBA and PBA are
		 * equally large and zero-indexed. */
		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("lightnvm: L2P data entry is out of bounds - stopping!\n");
			return -EINVAL;
		}

		if (!pba)
			continue;

		addr[i].addr = pba - 1;
		raddr[pba - 1].addr = slba + i;
	}
	return 0;
}

void nvm_free_nvm_id(struct nvm_id *id)
{
	kfree(id->chnls);
}

static void nvm_free(struct nvm_dev *nvm)
{
	struct nvm_stor *s = nvm->stor;

	s = nvm->stor;

	if (!s)
		return;

	del_timer(&s->gc_timer);

	nvm_aps_free(s);
	/* also frees blocks */
	nvm_pools_free(s);

	if (s->gc_ops->exit)
		s->gc_ops->exit(s);

	if (s->type->exit)
		s->type->exit(s);

	nvm_free_nvm_id(&s->id);

	nvm_stor_free(s);

	down_write(&_lock);
	if (_addr_cache)
		kmem_cache_destroy(_addr_cache);
	up_write(&_lock);
}

static int nvm_targets_init(struct nvm_stor *s)
{
	int ret;

	nvm_register_target(&nvm_target_rrpc);

	/* hardcode initialization values until user-space util is avail. */
	s->type = &nvm_target_rrpc;
	s->gc_ops = &nvm_gc_greedy;

	if (s->type->init) {
		ret = s->type->init(s);
		if (ret)
			goto done;
	}

	if (s->gc_ops->init) {
		ret = s->gc_ops->init(s);
		if (ret)
			goto done;
	}

	setup_timer(&s->gc_timer, s->gc_ops->gc_timer, (unsigned long)s);
done:
	return ret;
}

int nvm_init(struct nvm_dev *nvm)
{
	struct nvm_stor *s;
	int ret = 0;

	if (!nvm->q || !nvm->ops)
		return -EINVAL;

	down_write(&_lock);
	if (!_addr_cache) {
		_addr_cache = kmem_cache_create("nvm_addr_cache",
				sizeof(struct nvm_addr), 0, 0, NULL);
		if (!_addr_cache) {
			ret = -ENOMEM;
			up_write(&_lock);
			goto err;
		}
	}
	up_write(&_lock);

	s = kzalloc(sizeof(struct nvm_stor), GFP_KERNEL);
	if (!s) {
		ret = -ENOMEM;
		goto err;
	}

	nvm->stor = s;
	s->dev = (void *)nvm;

	/* TODO: We're limited to the same setup for each channel */
	if (nvm->ops->identify(nvm->q, &s->id)) {
		ret = -EINVAL;
		goto err;
	}

	pr_debug("lightnvm dev: ver %u type %u chnls %u\n",
			s->id.ver_id, s->id.nvm_type, s->id.nchannels);

	ret = nvm_stor_init(s);
	if (ret)
		goto err;

	ret = nvm_pools_init(s);
	if (ret)
		goto err;

	/* s->nr_pages_per_blk obtained from nvm_pools_init */
	if (s->nr_pages_per_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Number of pages per block too high. Increase MAX_INVALID_PAGES_STORAGE.");
		ret = -EINVAL;
		goto err;
	}
	s->nr_pages = s->nr_pools * s->nr_blks_per_pool * s->nr_pages_per_blk;

	ret = nvm_stor_map_init(s);
	if (ret)
		goto err;

	ret = nvm->ops->get_l2p_tbl(nvm->q, 0, s->nr_pages, nvm_l2p_tbl_init, s);
	if (ret) {
		pr_err("lightnvm: cannot read L2P table.");
		goto err;
	}

	ret = nvm_blocks_init(s);
	if (ret)
		goto err;

	ret = nvm_targets_init(s);
	if (ret)
		goto err;

	ret = nvm_aps_init(s);
	if (ret)
		goto err;

	pr_info("lightnvm: allocating %lu physical pages (%lu KB)\n",
			s->nr_pages, s->nr_pages * s->sector_size / 1024);
	pr_info("lightnvm: pools: %u\n", s->nr_pools);
	pr_info("lightnvm: blocks: %u\n", s->nr_blks_per_pool);
	pr_info("lightnvm: append points per pool: %u\n", s->nr_aps_per_pool);
	pr_info("lightnvm: target sector size=%d\n", s->sector_size);
	pr_info("lightnvm: append points: %u\n", s->nr_aps);
	pr_info("lightnvm: pages per block: %u\n", s->nr_pages_per_blk);

	/* Enable garbage collection timer */
	mod_timer(&s->gc_timer, jiffies + msecs_to_jiffies(1000));

	return 0;
err:
	nvm_free(nvm);
	pr_err("lightnvm: failed to initialize nvm\n");
	return ret;
}
EXPORT_SYMBOL_GPL(nvm_init);

void nvm_exit(struct nvm_dev *nvm)
{
	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_free(nvm);

	pr_info("lightnvm: successfully unloaded\n");
}
EXPORT_SYMBOL_GPL(nvm_exit);

MODULE_DESCRIPTION("LightNVM");
MODULE_AUTHOR("Matias Bjorling <mabj@itu.dk>");
MODULE_LICENSE("GPL");

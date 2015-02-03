#include <linux/lightnvm.h>
#include <trace/events/block.h>
#include "nvm.h"

struct request *nvm_inflight_laddr_acquire(struct nvm_stor *s, sector_t laddr,
					   unsigned int pages,
					   spinlock_t *parent_lock)
{
	struct request *rq;
	struct nvm_inflight_rq *inf;

	rq = blk_mq_alloc_request(s->dev->q, READ, GFP_NOIO, false);
	if (!rq)
		return ERR_PTR(-ENOMEM);

	inf = nvm_get_inflight_rq(s->dev, rq);
	while (nvm_lock_laddr(s, laddr, pages, inf)) {
		if (parent_lock)
			spin_unlock(parent_lock);
		schedule();
		if (parent_lock)
			spin_lock(parent_lock);
	}

	return rq;
}

void nvm_inflight_laddr_release(struct nvm_stor *s, struct request *rq)
{
	struct nvm_inflight_rq *inf;

	inf = nvm_get_inflight_rq(s->dev, rq);
	nvm_unlock_laddr(s, inf->l_start, inf);

	blk_mq_free_request(rq);
}

static void invalidate_block_page(struct nvm_stor *s, struct nvm_addr *p)
{
	struct nvm_block *block = p->block;
	unsigned int page_offset;

	NVM_ASSERT(spin_is_locked(&s->rev_lock));
	if (!block)
		return;

	spin_lock(&block->lock);
	page_offset = p->addr % s->nr_pages_per_blk;
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
	spin_unlock(&block->lock);
}

static inline void __nvm_page_invalidate(struct nvm_stor *s,
							struct nvm_addr *gp)
{
	NVM_ASSERT(spin_is_locked(&s->rev_lock));
	if (gp->addr == ADDR_EMPTY)
		return;

	invalidate_block_page(s, gp);
	s->rev_trans_map[gp->addr].addr = ADDR_EMPTY;
}

void nvm_invalidate_range(struct nvm_stor *s, sector_t slba, unsigned len)
{
	sector_t i;

	spin_lock(&s->rev_lock);

	for (i = slba; i < slba+len; i++) {
		struct nvm_addr *gp = &s->trans_map[i];

		__nvm_page_invalidate(s, gp);
		gp->block = NULL;
	}
	spin_unlock(&s->rev_lock);
}

void nvm_update_map(struct nvm_stor *s, sector_t l_addr, struct nvm_addr *p,
					int is_gc)
{
	struct nvm_addr *gp;
	struct nvm_rev_addr *rev;

	BUG_ON(l_addr >= s->nr_pages);
	BUG_ON(p->addr >= s->nr_pages);

	gp = &s->trans_map[l_addr];
	spin_lock(&s->rev_lock);
	if (gp->block)
		__nvm_page_invalidate(s, gp);

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &s->rev_trans_map[p->addr];
	rev->addr = l_addr;
	spin_unlock(&s->rev_lock);
}

/* requires lun->lock lock */
void nvm_reset_block(struct nvm_block *block)
{
	struct nvm_stor *s = block->lun->s;

	spin_lock(&block->lock);
	bitmap_zero(block->invalid_pages, s->nr_pages_per_blk);
	block->ap = NULL;
	block->next_page = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->data_cmnt_size, 0);
	spin_unlock(&block->lock);
}

sector_t nvm_alloc_phys_addr(struct nvm_block *block)
{
	sector_t addr = ADDR_EMPTY;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;

	addr = block_to_addr(block) + block->next_page;

	block->next_page++;

out:
	spin_unlock(&block->lock);
	return addr;
}

/* requires ap->lock taken */
void nvm_set_ap_cur(struct nvm_ap *ap, struct nvm_block *block)
{
	BUG_ON(!block);

	if (ap->cur) {
		spin_lock(&ap->cur->lock);
		WARN_ON(!block_is_full(ap->cur));
		spin_unlock(&ap->cur->lock);
		ap->cur->ap = NULL;
	}
	ap->cur = block;
	ap->cur->ap = ap;
}

/* Send erase command to device */
int nvm_erase_block(struct nvm_stor *s, struct nvm_block *block)
{
	struct nvm_dev *dev = s->dev;

	if (dev->ops->erase_block)
		return dev->ops->erase_block(dev->q, block->id);

	return 0;
}

void nvm_endio(struct nvm_dev *nvm_dev, struct request *rq, int err)
{
	struct nvm_stor *s = nvm_dev->stor;
	struct per_rq_data *pb = get_per_rq_data(nvm_dev, rq);
	struct nvm_addr *p = pb->addr;
	struct nvm_block *block = p->block;
	unsigned int data_cnt;

	nvm_unlock_rq(s, rq);

	if (rq_data_dir(rq) == WRITE) {
		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == s->nr_pages_per_blk) {
			/* cannot take the lun lock here, defer if necessary */
			s->gc_ops->queue(block);
		}
	}

	/* all submitted requests allocate their own addr,
	 * except GC reads */
	if (rq->cmd_flags & REQ_NVM_NO_INFLIGHT)
		return;

	mempool_free(pb->addr, s->addr_pool);
}

/* remember to lock l_add before calling nvm_submit_rq */
void nvm_setup_rq(struct nvm_stor *s, struct request *rq, struct nvm_addr *p)
{
	struct per_rq_data *pb;

	pb = get_per_rq_data(s->dev, rq);
	pb->addr = p;
}

int nvm_read_rq(struct nvm_stor *s, struct request *rq)
{
	struct nvm_addr *p;
	sector_t l_addr = nvm_get_laddr(rq);

	if (nvm_lock_rq(s, rq))
		return BLK_MQ_RQ_QUEUE_BUSY;

	p = s->type->lookup_ltop(s, l_addr);
	if (!p) {
		nvm_unlock_rq(s, rq);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	if (p->block)
		rq->phys_sector = nvm_get_sector(p->addr) +
					(blk_rq_pos(rq) % NR_PHY_IN_LOG);

	nvm_setup_rq(s, rq, p);
	return BLK_MQ_RQ_QUEUE_OK;
}

int nvm_write_rq(struct nvm_stor *s, struct request *rq)
{
	struct nvm_addr *p;
	int is_gc = 0;
	sector_t l_addr = nvm_get_laddr(rq);

	if (rq->cmd_flags & REQ_NVM_NO_INFLIGHT)
		is_gc = 1;

	if (nvm_lock_rq(s, rq))
		return BLK_MQ_RQ_QUEUE_BUSY;

	p = s->type->map_page(s, l_addr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		nvm_unlock_rq(s, rq);
		s->gc_ops->kick(s);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	rq->phys_sector = nvm_get_sector(p->addr);

	nvm_setup_rq(s, rq, p);

	return BLK_MQ_RQ_QUEUE_OK;
}

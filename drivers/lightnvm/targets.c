#include "nvm.h"

/* use lun_[get/put]_block to administer the blocks in use for each lun.
 * Whenever a block is in used by an append point, we store it within the
 * used_list. We then move it back when its free to be used by another append
 * point.
 *
 * The newly claimed block is always added to the back of used_list. As we
 * assume that the start of used list is the oldest block, and therefore
 * more likely to contain invalidated pages.
 */
struct nvm_block *nvm_lun_get_block(struct nvm_lun *lun, int is_gc)
{
	struct nvm_stor *s;
	struct nvm_block *block = NULL;
	unsigned long flags;

	BUG_ON(!lun);

	s = lun->s;
	spin_lock_irqsave(&lun->lock, flags);

	if (list_empty(&lun->free_list)) {
		pr_err_ratelimited("lightnvm: lun %u have no free pages available",
								lun->id);
		spin_unlock_irqrestore(&lun->lock, flags);
		goto out;
	}

	while (!is_gc && lun->nr_free_blocks < s->nr_aps) {
		spin_unlock_irqrestore(&lun->lock, flags);
		goto out;
	}

	block = list_first_entry(&lun->free_list, struct nvm_block, list);
	list_move_tail(&block->list, &lun->used_list);

	lun->nr_free_blocks--;

	spin_unlock_irqrestore(&lun->lock, flags);

	nvm_reset_block(block);

out:
	return block;
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void nvm_lun_put_block(struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;
	unsigned long flags;

	spin_lock_irqsave(&lun->lock, flags);

	list_move_tail(&block->list, &lun->free_list);
	lun->nr_free_blocks++;

	spin_unlock_irqrestore(&lun->lock, flags);
}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We assume that there is no data and doesn't take a ref */
struct nvm_addr *nvm_lookup_ltop(struct nvm_stor *s, sector_t l_addr)
{
	struct nvm_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < s->nr_pages));

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	gp = &s->trans_map[l_addr];

	p->addr = gp->addr;
	p->block = gp->block;

	return p;
}

static inline unsigned int nvm_rq_sectors(const struct request *rq)
{
	/*TODO: remove hardcoding, query nvm_dev for setting*/
	return blk_rq_bytes(rq) >> 9;
}

static struct nvm_ap *__nvm_get_ap_rr(struct nvm_stor *s, int is_gc)
{
	unsigned int i;
	struct nvm_lun *lun, *max_free;

	if (!is_gc)
		return get_next_ap(s);

	/* during GC, we don't care about RR, instead we want to make
	 * sure that we maintain evenness between the block luns. */
	max_free = &s->luns[0];
	/* prevent GC-ing lun from devouring pages of a lun with
	 * little free blocks. We don't take the lock as we only need an
	 * estimate. */
	nvm_for_each_lun(s, lun, i) {
		if (lun->nr_free_blocks > max_free->nr_free_blocks)
			max_free = lun;
	}

	return &s->aps[max_free->id];
}

/*read/write RQ has locked addr range already*/

static struct nvm_block *nvm_map_block_rr(struct nvm_stor *s, sector_t l_addr,
					int is_gc)
{
	struct nvm_ap *ap = NULL;
	struct nvm_block *block;

	ap = __nvm_get_ap_rr(s, is_gc);

	spin_lock(&ap->lock);
	block = s->type->lun_get_blk(ap->lun, is_gc);
	spin_unlock(&ap->lock);
	return block; /*NULL iff. no free blocks*/
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns nvm_addr with the physical address and block. Remember to return to
 * s->addr_cache when request is finished.
 */
static struct nvm_addr *nvm_map_page_rr(struct nvm_stor *s, sector_t l_addr,
					int is_gc)
{
	struct nvm_addr *p;
	struct nvm_ap *ap;
	struct nvm_lun *lun;
	struct nvm_block *p_block;
	sector_t p_addr;

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	ap = __nvm_get_ap_rr(s, is_gc);
	lun = ap->lun;

	spin_lock(&ap->lock);

	p_block = ap->cur;
	p_addr = nvm_alloc_phys_addr(p_block);

	if (p_addr == ADDR_EMPTY) {
		p_block = s->type->lun_get_blk(lun, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = nvm_alloc_phys_addr(ap->gc_cur);
				if (p_addr == ADDR_EMPTY) {
					p_block = s->type->lun_get_blk(lun, 1);
					if (!p_block) {
						pr_err("lightnvm: no more blocks");
						goto finished;
					} else {
						ap->gc_cur = p_block;
						ap->gc_cur->ap = ap;
						p_addr =
						nvm_alloc_phys_addr(ap->gc_cur);
					}
				}
				p_block = ap->gc_cur;
			}
			goto finished;
		}

		nvm_set_ap_cur(ap, p_block);
		p_addr = nvm_alloc_phys_addr(p_block);
	}

finished:
	if (p_addr == ADDR_EMPTY)
		goto err;

	p->addr = p_addr;
	p->block = p_block;

	if (!p_block)
		WARN_ON(is_gc);

	spin_unlock(&ap->lock);
	if (p)
		nvm_update_map(s, l_addr, p, is_gc);
	return p;
err:
	spin_unlock(&ap->lock);
	mempool_free(p, s->addr_pool);
	return NULL;
}

/* none target type, round robin, page-based FTL, and cost-based GC */
struct nvm_target_type nvm_target_rrpc = {
	.name		= "rrpc",
	.version	= {1, 0, 0},
	.lookup_ltop	= nvm_lookup_ltop,
	.map_page	= nvm_map_page_rr,
	.map_block	= nvm_map_block_rr,

	.write_rq	= nvm_write_rq,
	.read_rq	= nvm_read_rq,

	.lun_get_blk	= nvm_lun_get_block,
	.lun_put_blk	= nvm_lun_put_block,
};

/* none target type, round robin, block-based FTL, and cost-based GC */
struct nvm_target_type nvm_target_rrbc = {
	.name		= "rrbc",
	.version	= {1, 0, 0},
	.lookup_ltop	= nvm_lookup_ltop,
	.map_page	= NULL,
	.map_block	= nvm_map_block_rr,

	/*rewrite these to support multi-page writes*/
	.write_rq	= nvm_write_rq,
	.read_rq	= nvm_read_rq,

	.lun_get_blk	= nvm_lun_get_block,
	.lun_put_blk	= nvm_lun_put_block,
};

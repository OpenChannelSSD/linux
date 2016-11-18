/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
 *                  Matias Bjorling <m@bjorling.me>
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
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 * TODO:
 *   - Choose strategy:
 *     - Stripe across writable luns
 *     - Write to one block (one lun) at a time
 *   - Configure mapping parameters for relevant strategies (sysfs)
 */

#include "pblk.h"

int __pblk_map_replace_lun(struct pblk *pblk, int lun_pos)
{
	int next_lun;

	if (lun_pos > pblk->w_luns.nr_luns)
		return 1;

	if (unlikely(lun_pos < 0 || lun_pos >= pblk->w_luns.nr_luns)) {
		pr_err("pblk: corrupt mapping\n");
		return 0;
	}

	next_lun = ++pblk->w_luns.next_lun;
	if (pblk->w_luns.next_lun == pblk->nr_luns)
		next_lun = pblk->w_luns.next_lun = 0;

	pblk->w_luns.luns[lun_pos] = &pblk->luns[next_lun];
	return 1;
}

int pblk_map_replace_lun(struct pblk *pblk, int lun_pos)
{
	int ret = 1;

	spin_lock(&pblk->w_luns.lock);
	if (pblk->w_luns.nr_blocks == -1)
		goto out;

	if (++pblk->w_luns.lun_blocks[lun_pos] >= pblk->w_luns.nr_blocks) {
		ret = __pblk_map_replace_lun(pblk, lun_pos);
		pblk->w_luns.lun_blocks[lun_pos] = 0;
	}

out:
	spin_unlock(&pblk->w_luns.lock);

	return ret;
}

static struct pblk_lun *get_map_next_lun(struct pblk *pblk, int *lun_pos)
{
	struct pblk_lun *rlun;

	spin_lock(&pblk->w_luns.lock);
	*lun_pos = ++pblk->w_luns.next_w_lun;
	if (pblk->w_luns.next_w_lun == pblk->w_luns.nr_luns)
		*lun_pos = pblk->w_luns.next_w_lun = 0;

	rlun = pblk->w_luns.luns[*lun_pos];
	spin_unlock(&pblk->w_luns.lock);

	return rlun;
}

static struct pblk_lun *pblk_map_get_lun_rr(struct pblk *pblk, int *lun_pos,
					    unsigned long *lun_bitmap,
					    int is_gc)
{
	struct pblk_lun *rlun;

	do {
		rlun = get_map_next_lun(pblk, lun_pos);
	} while (test_bit(rlun->id, lun_bitmap));

	return rlun;
}

/* rblk->lock must be taken */
static inline u64 pblk_next_base_sec(struct pblk *pblk, struct pblk_block *rblk,
				     int nr_secs)
{
	u64 old = rblk->cur_sec;

#ifdef CONFIG_NVM_DEBUG
	int i;
	int cur_sec = old;

	for (i = 0; i < nr_secs; i++) {
		WARN_ON(test_bit(cur_sec, rblk->sector_bitmap));
		cur_sec++;
	}
#endif

	/* logic error: lba out-of-bounds */
	BUG_ON(rblk->cur_sec + nr_secs > pblk->nr_blk_dsecs);

	bitmap_set(rblk->sector_bitmap, rblk->cur_sec, nr_secs);
	rblk->cur_sec += nr_secs;

	return old;
}

/* The ppa in pblk_addr comes with an offset format, not a global format */
static void pblk_page_pad_invalidate(struct pblk *pblk, struct pblk_block *rblk,
				     struct ppa_addr a)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rblk->lock);
#endif

	WARN_ON(test_and_set_bit(a.ppa, rblk->invalid_bitmap));
	rblk->nr_invalid_secs++;

	pblk_rb_sync_init(&pblk->rwb, NULL);
	WARN_ON(test_and_set_bit(a.ppa, rblk->sync_bitmap));
	if (bitmap_full(rblk->sync_bitmap, pblk->nr_blk_dsecs))
		pblk_run_blk_ws(pblk, rblk, pblk_close_blk);
	pblk_rb_sync_end(&pblk->rwb, NULL);
}

static u64 pblk_alloc_page(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 addr = ADDR_EMPTY;
	int nr_secs = pblk->min_write_pgs;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rblk->lock);
#endif

	if (block_is_full(pblk, rblk))
		goto out;

	addr = pblk_next_base_sec(pblk, rblk, nr_secs);

out:
	return addr;
}

int pblk_map_page(struct pblk *pblk, struct pblk_block *rblk,
		  unsigned int sentry, struct ppa_addr *ppa_list,
		  struct pblk_sec_meta *meta_list,
		  unsigned int nr_secs, unsigned int valid_secs)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_blk_rec_lpg *rlpg = rblk->rlpg;
	struct pblk_w_ctx *w_ctx;
	u64 *lba_list;
	u64 paddr;
	int i;

	lba_list = pblk_rlpg_to_llba(rlpg);

	spin_lock(&rblk->lock);
	paddr = pblk_alloc_page(pblk, rblk);

	if (paddr == ADDR_EMPTY) {
		spin_unlock(&rblk->lock);
		return 1;
	}

	for (i = 0; i < nr_secs; i++, paddr++) {
		if (paddr == ADDR_EMPTY) {
			/* We should always have available sectors for a full
			 * page write at this point. We get a new block for this
			 * LUN when the current block is full.
			 */
			pr_err("pblk: corrupted l2p mapping, blk:%d,n:%d/%d\n",
					rblk->id,
					i, nr_secs);
			spin_unlock(&rblk->lock);
			return -EINVAL;
		}

		/* ppa to be sent to the device */
		ppa_list[i] = pblk_blk_ppa_to_gaddr(dev, rblk, paddr);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and only one of the writer threads have access to each
		 * specific entry at a time. Thus, it is safe to modify the
		 * context for the entry we are setting up for submission
		 * without taking any lock and/or memory barrier.
		 */
		if (i < valid_secs) {
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->paddr = paddr;
			w_ctx->ppa.ppa = ppa_list[i];
			w_ctx->ppa.rblk = rblk;
			meta_list[i].lba = w_ctx->lba;
			lba_list[paddr] = w_ctx->lba;
			rlpg->nr_lbas++;
		} else {
			meta_list[i].lba = ADDR_EMPTY;
			lba_list[paddr] = ADDR_EMPTY;
			pblk_page_pad_invalidate(pblk, rblk,
							addr_to_ppa(paddr));
			rlpg->nr_padded++;
		}
	}
	spin_unlock(&rblk->lock);

#ifdef CONFIG_NVM_DEBUG
	if (pblk_boundary_checks(pblk->dev, ppa_list, nr_secs))
		WARN_ON(1);
#endif

	return 0;
}


/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk. Mapping occurs at a page granurality, i.e., if a
 * page is 4 sectors, then each map entails 4 lba-ppa mappings - @nr_secs is the
 * number of sectors in the page, taking number of planes also into
 * consideration
 *
 * TODO: We are missing GC path
 * TODO: Add support for MLC and TLC padding. For now only supporting SLC
 */
int pblk_map_rr_page(struct pblk *pblk, unsigned int sentry,
		     struct ppa_addr *ppa_list,
		     struct pblk_sec_meta *meta_list,
		     unsigned int nr_secs, unsigned int valid_secs,
		     unsigned long *lun_bitmap)
{
	struct pblk_block *rblk;
	struct pblk_lun *rlun;
	int lun_pos;
	int ret = 0;

try_lun:
	rlun = pblk_map_get_lun_rr(pblk, &lun_pos, lun_bitmap,
							pblk_gc_status(pblk));
	spin_lock(&rlun->lock);

try_cur:
	rblk = rlun->cur;

	/* Account for grown bad blocks */
	if (unlikely(block_is_bad(rblk))) {
		if (!pblk_replace_blk(pblk, rblk, rlun, lun_pos)) {
			spin_unlock(&rlun->lock);
			goto try_lun;
		}
		goto try_cur;
	}

	ret = pblk_map_page(pblk, rblk, sentry, ppa_list, meta_list,
							nr_secs, valid_secs);
	if (ret) {
		if (!pblk_replace_blk(pblk, rblk, rlun, lun_pos)) {
			spin_unlock(&rlun->lock);
			goto try_lun;
		}
		goto try_cur;
	}
	spin_unlock(&rlun->lock);

	if (down_interruptible(&rlun->wr_sem))
		pr_err("pblk: lun semaphore failed\n");

	return ret;
}

ssize_t pblk_map_set_active_luns(struct pblk *pblk, int nr_luns)
{
	struct pblk_lun **luns;
	int *lun_blocks;
	ssize_t ret = 0;
	int old_nr_luns, cpy_luns;
	int i;

	spin_lock(&pblk->w_luns.lock);
	if (nr_luns > pblk->nr_luns) {
		pr_err("pblk: Not enough luns (%d > %d)\n",
						nr_luns, pblk->nr_luns);
		ret = -EINVAL;
		goto out;
	}

	old_nr_luns = pblk->w_luns.nr_luns;
	pblk->w_luns.nr_luns = nr_luns;
	pblk->w_luns.next_lun = (nr_luns == pblk->nr_luns) ? 0 : nr_luns + 1;

	luns = kcalloc(nr_luns, sizeof(void *), GFP_ATOMIC);
	if (!luns) {
		ret = -ENOMEM;
		goto out;
	}

	lun_blocks = kcalloc(nr_luns, sizeof(int), GFP_ATOMIC);
	if (!lun_blocks) {
		kfree(luns);
		ret = -ENOMEM;
		goto out;
	}

	cpy_luns = (old_nr_luns > nr_luns) ? nr_luns : old_nr_luns;

	for (i = 0; i < cpy_luns; i++) {
		luns[i] = pblk->w_luns.luns[i];
		lun_blocks[i] = pblk->w_luns.lun_blocks[i];
	}

	kfree(pblk->w_luns.luns);
	kfree(pblk->w_luns.lun_blocks);

	pblk->w_luns.luns = luns;
	pblk->w_luns.lun_blocks = lun_blocks;

	/* By default consume one block per active lun */
	pblk->w_luns.nr_blocks = 1;

	for (i = cpy_luns; i < nr_luns; i++) {
		pblk->w_luns.lun_blocks[i] = 0;
		if (!__pblk_map_replace_lun(pblk, i))
			goto out;
	}

	pblk->w_luns.next_w_lun = -1;

out:
	spin_unlock(&pblk->w_luns.lock);
	return ret;
}

int pblk_map_get_active_luns(struct pblk *pblk)
{
	int nr_luns;

	spin_lock(&pblk->w_luns.lock);
	nr_luns = pblk->w_luns.nr_luns;
	spin_unlock(&pblk->w_luns.lock);

	return nr_luns;
}

int pblk_map_set_consume_blocks(struct pblk *pblk, int value)
{
	spin_lock(&pblk->w_luns.lock);
	pblk->w_luns.nr_blocks = value;
	spin_unlock(&pblk->w_luns.lock);

	return 0;
}

int pblk_map_get_consume_blocks(struct pblk *pblk)
{
	int nr_blocks;

	spin_lock(&pblk->w_luns.lock);
	nr_blocks = pblk->w_luns.nr_blocks;
	spin_unlock(&pblk->w_luns.lock);

	return nr_blocks;
}

int pblk_map_init(struct pblk *pblk)
{
	int i;

	pblk->w_luns.nr_luns = pblk->nr_luns;

	pblk->w_luns.next_lun = -1;
	pblk->w_luns.next_w_lun = -1;

	/* By default, all luns are active. No need to replace on alloc. */
	pblk->w_luns.nr_blocks = -1;

	pblk->w_luns.luns = kcalloc(pblk->w_luns.nr_luns, sizeof(void *),
								GFP_KERNEL);
	if (!pblk->w_luns.luns)
		return -ENOMEM;

	pblk->w_luns.lun_blocks = kcalloc(pblk->w_luns.nr_luns, sizeof(int),
								GFP_KERNEL);
	if (!pblk->w_luns.lun_blocks) {
		kfree(pblk->w_luns.luns);
		return -ENOMEM;
	}

	spin_lock_init(&pblk->w_luns.lock);

	/* Set write luns in order to start with */
	for (i = 0; i < pblk->w_luns.nr_luns; i++) {
		pblk->w_luns.luns[i] = &pblk->luns[i];
		pblk->w_luns.lun_blocks[i] = 0;
	}

	return 0;
}

void pblk_map_free(struct pblk *pblk)
{
	kfree(pblk->w_luns.luns);
	kfree(pblk->w_luns.lun_blocks);
}

/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
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

#if 0
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
#endif

static void pblk_page_pad_invalidate(struct pblk *pblk, struct pblk_line *line,
				     u64 paddr)
{
	spin_lock(&line->lock);
	WARN_ON(test_and_set_bit(paddr, line->invalid_bitmap));
	line->vsc--;
	spin_unlock(&line->lock);

	pblk_rb_sync_init(&pblk->rwb, NULL);
	WARN_ON(--line->left_ssecs == 0);
	pblk_rb_sync_end(&pblk->rwb, NULL);
}

static void pblk_map_page_data(struct pblk *pblk, struct pblk_line *line,
			       unsigned int sentry, struct ppa_addr *ppa_list,
			       unsigned long *lun_bitmap,
			       struct pblk_sec_meta *meta_list,
			       unsigned int valid_secs)
{
	struct line_emeta *emeta = line->emeta;
	struct pblk_w_ctx *w_ctx;
	u64 *lba_list = pblk_line_emeta_to_lbas(emeta);
	u64 paddr;
	int nr_secs = pblk->min_write_pgs;
	int i;

	paddr = pblk_alloc_page(pblk, line);

	for (i = 0; i < nr_secs; i++, paddr++) {
		/* ppa to be sent to the device */
		ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);
		kref_get(&line->ref);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
		if (i < valid_secs) {
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->paddr = paddr;
			w_ctx->ppa = ppa_list[i];
			meta_list[i].lba = w_ctx->lba;
			lba_list[paddr] = w_ctx->lba;
		} else {
			meta_list[i].lba = ADDR_EMPTY;
			lba_list[paddr] = ADDR_EMPTY;
			pblk_page_pad_invalidate(pblk, line, paddr);
		}
	}

	pblk_down_rq(pblk, ppa_list, nr_secs, lun_bitmap);
	pblk_map_provision(pblk);
}

int pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
		unsigned long *lun_bitmap, unsigned int valid_secs,
		unsigned int off)
{
	struct pblk_line *w_line = pblk_line_get_data(pblk);
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i;

	for (i = off; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		pblk_map_page_data(pblk, w_line, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i], map_secs);
	}

	return 0;
}

int pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
		      unsigned long *lun_bitmap, unsigned int valid_secs,
		      struct ppa_addr *erase_ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line *w_line = pblk_line_get_data(pblk);
	struct pblk_line *e_line = pblk_line_get_data_next(pblk);
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int erase_lun;
	int i;

	for (i = 0; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		pblk_map_page_data(pblk, w_line, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i], map_secs);

		erase_lun = rqd->ppa_list[i].g.lun * geo->nr_chnls +
							rqd->ppa_list[i].g.ch;
		if (!test_and_set_bit(erase_lun, e_line->erase_bitmap)) {
			e_line->left_eblks--;
			*erase_ppa = rqd->ppa_list[i];
			erase_ppa->g.blk = e_line->id;

			/* Avoid evaluating e_line->left_eblks */
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min);
		}
	}

	/* Erase blocks that are bad in this line but might not be in next */
	if (unlikely(e_line->left_eblks) && ppa_empty(*erase_ppa)) {
		struct pblk_line_meta *lm = &pblk->lm;

		i = find_first_zero_bit(e_line->erase_bitmap, lm->blk_per_line);

		set_bit(i, e_line->erase_bitmap);
		e_line->left_eblks--;
		*erase_ppa = pblk->luns[i].bppa; /* set ch and lun */
		erase_ppa->g.blk = e_line->id;
	}

	return 0;
}

void pblk_map_provision(struct pblk *pblk) {
	struct pblk_line *line = pblk_line_get_data(pblk);

	if (pblk_line_is_full(line))
		if (!pblk_line_replace_data(pblk))
			pr_err("pblk: no space in media\n");
}

#if 0
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
#endif

#if 0
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
#endif


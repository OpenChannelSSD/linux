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
 * pblk-write.c - pblk's write path from write buffer to media
 */

#include "pblk.h"

#if 0
int pblk_replace_blk(struct pblk *pblk, struct pblk_block *rblk,
		     struct pblk_lun *rlun, int lun_pos)
{
	rblk = pblk_get_blk(pblk, rlun);
	if (!rblk) {
		pr_debug("pblk: could not get new block\n");
		return 0;
	}

	pblk_set_lun_cur(rlun, rblk);
	return pblk_map_replace_lun(pblk, lun_pos);
}
#endif

static void pblk_sync_buffer(struct pblk *pblk, struct pblk_line *line,
			     u64 paddr, int flags)
{
#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->sync_writes);
#endif

	/* Counter protected by rb sync lock */
	if (--line->left_ssecs == 0)
		pblk_line_run_ws(pblk, line, pblk_line_close);
}

static unsigned long pblk_end_w_bio(struct pblk *pblk, struct nvm_rq *rqd,
				    struct pblk_compl_ctx *c_ctx)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct bio *original_bio;
	unsigned long ret;
	int nr_entries = c_ctx->nr_valid;
	int i;

	for (i = 0; i < nr_entries; i++) {
		struct ppa_addr p = rqd->ppa_list[i];
		struct pblk_line *line;
		struct pblk_w_ctx *w_ctx;

		w_ctx = pblk_rb_w_ctx(&pblk->rwb, c_ctx->sentry + i);
		line = &pblk->lines[pblk_ppa_to_line(p)];

		pblk_sync_buffer(pblk, line, w_ctx->paddr, w_ctx->flags);
		while ((original_bio = bio_list_pop(&w_ctx->bios)))
			bio_endio(original_bio);
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_entries, &pblk->compl_writes);
#endif

	ret = pblk_rb_sync_advance(&pblk->rwb, nr_entries);

	if (nr_entries > 1)
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(dev->parent, rqd->meta_list,
							rqd->dma_meta_list);

	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, WRITE);

	return ret;
}

static unsigned long pblk_end_queued_w_bio(struct pblk *pblk,
					   struct nvm_rq *rqd,
					   struct pblk_compl_ctx *c_ctx)
{
	list_del(&c_ctx->list);
	return pblk_end_w_bio(pblk, rqd, c_ctx);
}

static void pblk_compl_queue(struct pblk *pblk, struct nvm_rq *rqd,
			     struct pblk_compl_ctx *c_ctx)
{
	struct pblk_compl_ctx *c, *r;
	unsigned long flags;
	unsigned long pos;

#ifdef CONFIG_NVM_DEBUG
	atomic_sub(c_ctx->nr_valid, &pblk->inflight_writes);
#endif

	pblk_up_rq(pblk, rqd->ppa_list, rqd->nr_ppas, c_ctx->lun_bitmap);

	pos = pblk_rb_sync_init(&pblk->rwb, &flags);
	if (pos == c_ctx->sentry) {
		pos = pblk_end_w_bio(pblk, rqd, c_ctx);

retry:
		list_for_each_entry_safe(c, r, &pblk->compl_list, list) {
			rqd = nvm_rq_from_c_ctx(c);
			if (c->sentry == pos) {
				pos = pblk_end_queued_w_bio(pblk, rqd, c);
				goto retry;
			}
		}
	} else {
		BUG_ON(nvm_rq_from_c_ctx(c_ctx) != rqd);
		list_add_tail(&c_ctx->list, &pblk->compl_list);
	}

	pblk_rb_sync_end(&pblk->rwb, &flags);
}


void pblk_end_io_write(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_compl_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pblk_log_write_err(pblk, rqd);
		/* BUG_ON(1); */
		/* return pblk_end_w_fail(pblk, rqd); */
	}
#ifdef CONFIG_NVM_DEBUG
	else
		BUG_ON(rqd->bio->bi_error);
#endif

	pblk_compl_queue(pblk, rqd, c_ctx);
}

static int pblk_alloc_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   unsigned int nr_secs)
{
	struct nvm_tgt_dev *dev = pblk->dev;

	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = nr_secs;
	rqd->flags = pblk_set_progr_mode(pblk, WRITE);
	rqd->private = pblk;
	rqd->end_io = pblk_end_io_write;

	rqd->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
	if (!rqd->meta_list)
		return -ENOMEM;

	if (unlikely(nr_secs == 1))
		return 0;

	/* TODO: Reuse same dma region for ppa_list and metadata */
	rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_ppa_list);
	if (!rqd->ppa_list) {
		nvm_dev_dma_free(dev->parent, rqd->meta_list,
							rqd->dma_meta_list);
		return -ENOMEM;
	}

	return 0;
}

static int pblk_setup_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   struct pblk_compl_ctx *c_ctx,
			   struct ppa_addr *erase_ppa)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *e_line = pblk_line_get_data_next(pblk);
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	unsigned long *lun_bitmap;
	int ret = 0;

	lun_bitmap = kzalloc(lm->lun_bitmap_len, GFP_KERNEL);
	if (!lun_bitmap) {
		ret = -ENOMEM;
		goto out;
	}
	c_ctx->lun_bitmap = lun_bitmap;

	ret = pblk_alloc_w_rq(pblk, rqd, nr_secs);
	if (ret) {
		kfree(lun_bitmap);
		goto out;
	}

	ppa_set_empty(erase_ppa);
	if (likely(!e_line->left_eblks)) {
		ret = pblk_map_rq(pblk, rqd, c_ctx->sentry, lun_bitmap,
								valid_secs, 0);
		if (ret)
			goto out;
	} else {
		ret = pblk_map_erase_rq(pblk, rqd, c_ctx->sentry, lun_bitmap,
							valid_secs, erase_ppa);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static int pblk_calc_secs_to_sync(struct pblk *pblk, unsigned long secs_avail,
				  unsigned long secs_to_flush)
{
	int secs_in_line;
	int secs_to_sync;

	secs_to_sync = pblk_calc_secs(pblk, secs_avail, secs_to_flush);

	/* Since the write thread is a pipeline, we know where in the line we
	 * are going to map the incoming data. Reserve part of the I/O for
	 * metadata if necessary
	 */
	secs_in_line = pblk_line_secs_data(pblk);
	if (secs_in_line < secs_to_sync)
		secs_to_sync = secs_in_line;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!secs_to_sync && secs_to_flush);
	BUG_ON(secs_to_sync > secs_avail && !secs_to_flush);
	BUG_ON(secs_to_sync < 0 || secs_to_sync > pblk->max_write_pgs);
#endif

	return secs_to_sync;
}

int pblk_submit_write(struct pblk *pblk)
{
	struct bio *bio;
	struct nvm_rq *rqd;
	struct pblk_compl_ctx *c_ctx;
	struct ppa_addr erase_ppa;
	unsigned int pgs_read;
	unsigned int secs_avail, secs_to_sync, secs_to_com;
	unsigned int secs_to_flush;
	unsigned long sync_point = 0;
	unsigned long pos;
	int err;

	/* Pre-check if we should start writing before doing allocations */
	secs_to_flush = pblk_rb_sync_point_count(&pblk->rwb);
	secs_avail = pblk_rb_read_count(&pblk->rwb);
	if (!secs_to_flush && secs_avail < pblk->max_write_pgs)
		return 1;

	rqd = pblk_alloc_rqd(pblk, WRITE);
	if (IS_ERR(rqd)) {
		pr_err("pblk: cannot allocate write req.\n");
		return 1;
	}
	c_ctx = nvm_rq_to_pdu(rqd);

	bio = bio_alloc(GFP_KERNEL, pblk->max_write_pgs);
	if (!bio) {
		pr_err("pblk: cannot allocate write bio\n");
		goto fail_free_rqd;
	}
	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;

	secs_to_sync = pblk_calc_secs_to_sync(pblk, secs_avail, secs_to_flush);
	if (secs_to_sync < 0) {
		pr_err("pblk: bad buffer sync calculation\n");
		goto fail_put_bio;
	}

	secs_to_com = (secs_to_sync > secs_avail) ? secs_avail : secs_to_sync;
	pos = pblk_rb_read_commit(&pblk->rwb, secs_to_com);

	pgs_read = pblk_rb_read_to_bio(&pblk->rwb, bio, c_ctx, pos,
					secs_to_sync, secs_avail, &sync_point);
	if (!pgs_read) {
		//TOGO
		printk(KERN_CRIT "ERROR! !pgs_read, avail:%d,com:%d,sync:%d,,flush:%d\n",
				secs_to_com, secs_avail, secs_to_sync, secs_to_flush);
		goto fail_put_bio;
	}

	if (secs_to_flush && secs_to_flush <= secs_to_sync)
		pblk_rb_sync_point_reset(&pblk->rwb, sync_point);

	if (c_ctx->nr_padded)
		if (pblk_bio_add_pages(pblk, bio, GFP_KERNEL, c_ctx->nr_padded))
			goto fail_put_bio;

	/* Assign lbas to ppas and populate request structure */
	err = pblk_setup_w_rq(pblk, rqd, c_ctx, &erase_ppa);
	if (err) {
		pr_err("pblk: could not setup write request\n");
		goto fail_free_bio;
	}

	err = pblk_submit_io(pblk, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		goto fail_free_bio;
	}

	if (unlikely(!ppa_empty(erase_ppa)))
		pblk_blk_erase_async(pblk, erase_ppa);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(secs_to_sync, &pblk->sub_writes);
#endif

	return 0;
fail_free_bio:
	if (c_ctx->nr_padded)
		pblk_bio_free_pages(pblk, bio, secs_to_sync, c_ctx->nr_padded);
fail_put_bio:
	bio_put(bio);
fail_free_rqd:
	pblk_free_rqd(pblk, rqd, WRITE);

	return 1;
}

int pblk_write_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		if (!pblk_submit_write(pblk))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

/*
 * When a write fails we assume for now that the flash block has grown bad.
 * Thus, we start a recovery mechanism to (in general terms):
 *  - Take block out of the active open block list
 *  - Complete the successful writes on the request
 *  - Remap failed writes to a new request
 *  - Move written data on grown bad block(s) to new block(s)
 *  - Mark grown bad block(s) as bad and return to media manager
 *
 *  This function assumes that ppas in rqd are in generic mode. This is,
 *  nvm_addr_to_generic_mode(dev, rqd) has been called.
 *
 *  TODO: Depending on the type of memory, try write retry
 */
// JAVIER: 
#if 0
static void pblk_end_w_fail(struct pblk *pblk, struct nvm_rq *rqd)
{
	void *comp_bits = &rqd->ppa_status;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct pblk_rec_ctx *recovery;
	struct ppa_addr ppa, prev_ppa;
	unsigned int c_entries;
	int nr_ppas = rqd->nr_ppas;
	int bit;
	int ret;

	/* The last page of a block contains recovery metadata, if a block
	 * becomes bad when writing this page, there is no need to recover what
	 * is being written; this metadata is generated in a per-block basis.
	 * This block is on its way to being closed. Mark as bad and trigger
	 * recovery
	 */
	if (ctx->flags & PBLK_IOTYPE_CLOSE_BLK) {
		struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

		pblk_run_recovery(pblk, c_ctx->rblk);
		pblk_end_close_blk_bio(pblk, rqd, 0);
		return;
	}

	/* look up blocks and mark them as bad
	 * TODO: RECOVERY HERE TOO
	 */
	if (nr_ppas == 1)
		return;

	recovery = mempool_alloc(pblk->rec_pool, GFP_ATOMIC);
	if (!recovery) {
		pr_err("pblk: could not allocate recovery context\n");
		return;
	}
	INIT_LIST_HEAD(&recovery->failed);

	c_entries = find_first_bit(comp_bits, nr_ppas);

	/* Replace all grown bad blocks on RR mapping scheme, mark them as bad
	 * and return them to the media manager.
	 */
	ppa_set_empty(&prev_ppa);
	bit = -1;
	while ((bit = find_next_bit(comp_bits, nr_ppas, bit + 1)) < nr_ppas) {
		if (bit > c_ctx->nr_valid)
			goto out;

		ppa = rqd->ppa_list[bit];

		entry = pblk_rb_sync_scan_entry(&pblk->rwb, &ppa);
		if (!entry) {
			pr_err("pblk: could not scan entry on write failure\n");
			continue;
		}
		w_ctx = &entry->w_ctx;

		/* The list is filled first and emptied afterwards. No need for
		 * protecting it with a lock
		 */
		list_add_tail(&entry->index, &recovery->failed);

		if (ppa_cmp_blk(ppa, prev_ppa))
			continue;

		pblk_mark_bb(pblk, ppa);

		prev_ppa.ppa = ppa.ppa;
		pblk_run_recovery(pblk, w_ctx->ppa.rblk);
	}

out:
	ret = pblk_recov_setup_rq(pblk, ctx, recovery, comp_bits, c_entries);
	if (ret)
		pr_err("pblk: could not recover from write failure\n");

	INIT_WORK(&recovery->ws_rec, pblk_submit_rec);
	queue_work(pblk->kw_wq, &recovery->ws_rec);

	pblk_compl_queue(pblk, rqd, ctx);
}
#endif


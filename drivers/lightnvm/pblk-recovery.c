/*
 * Copyright (C) 2016 CNEX Labs
 * Initial: Javier Gonzalez <javier@cnexlabs.com>
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
 * pblk-recovery.c - pblk's recovery path
 */

#include "pblk.h"

/* pblk_submit_rec -- thread to submit recovery requests
 *
 * When a write request fails, rqd->ppa_status signals which specific ppas could
 * not be written to the media. All ppas previous to the failed writes could be
 * completed when the io finished, as part of the end_io recovery. However,
 * successful writes after the failed ppas are not completed in order to
 * maintain the consistency of the back pointer that guarantees sequentiality on
 * the write buffer.
 */
void pblk_submit_rec(struct work_struct *work)
{
	struct pblk_rec_ctx *recovery =
			container_of(work, struct pblk_rec_ctx, ws_rec);
	struct pblk *pblk = recovery->pblk;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_rq *rqd = recovery->rqd;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	int max_secs = nvm_max_phys_sects(dev);
	struct bio *bio;
	unsigned int nr_rec_secs;
	unsigned int pgs_read;
	int ret;

	nr_rec_secs =
		bitmap_weight((unsigned long int *)&rqd->ppa_status, max_secs);

	bio = bio_alloc(GFP_KERNEL, nr_rec_secs);
	if (!bio) {
		pr_err("pblk: not able to create recovery bio\n");
		return;
	}
	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;
	rqd->nr_ppas = nr_rec_secs;

	pgs_read = pblk_rb_read_to_bio_list(&pblk->rwb, bio, &recovery->failed,
								nr_rec_secs);
	if (pgs_read != nr_rec_secs) {
		pr_err("pblk: could not read recovery entries\n");
		goto fail;
	}

	if (pblk_setup_w_rec_rq(pblk, rqd, c_ctx)) {
		pr_err("pblk: could not setup recovery request\n");
		goto fail;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_rec_secs, &pblk->recov_writes);
#endif

	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		goto fail;
	}

	mempool_free(recovery, pblk->rec_pool);
	return;

fail:
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, WRITE);
}

int pblk_recov_setup_rq(struct pblk *pblk, struct pblk_c_ctx *c_ctx,
			struct pblk_rec_ctx *recovery, u64 *comp_bits,
			unsigned int comp)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	int max_secs = nvm_max_phys_sects(dev);
	struct nvm_rq *rec_rqd;
	struct pblk_c_ctx *rec_ctx;
	int nr_entries = c_ctx->nr_valid + c_ctx->nr_padded;

	rec_rqd = pblk_alloc_rqd(pblk, WRITE);
	if (IS_ERR(rec_rqd)) {
		pr_err("pblk: could not create recovery req.\n");
		return -ENOMEM;
	}

	rec_ctx = nvm_rq_to_pdu(rec_rqd);

	/* Copy completion bitmap, but exclude the first X completed entries */
	bitmap_shift_right((unsigned long int *)&rec_rqd->ppa_status,
				(unsigned long int *)comp_bits,
				comp, max_secs);

	/* Save the context for the entries that need to be re-written and
	 * update current context with the completed entries.
	 */
	rec_ctx->sentry = pblk_rb_wrap_pos(&pblk->rwb, c_ctx->sentry + comp);
	if (comp >= c_ctx->nr_valid) {
		rec_ctx->nr_valid = 0;
		rec_ctx->nr_padded = nr_entries - comp;

		c_ctx->nr_padded = comp - c_ctx->nr_valid;
	} else {
		rec_ctx->nr_valid = c_ctx->nr_valid - comp;
		rec_ctx->nr_padded = c_ctx->nr_padded;

		c_ctx->nr_valid = comp;
		c_ctx->nr_padded = 0;
	}

	recovery->rqd = rec_rqd;
	recovery->pblk = pblk;

	return 0;
}

u64 *pblk_recov_get_lba_list(struct pblk *pblk, struct line_emeta *emeta)
{
	struct pblk_line_meta *lm = &pblk->lm;
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)emeta + sizeof(crc),
					lm->emeta_len - sizeof(crc));
	if (emeta->crc != crc)
		return NULL;

	return pblk_line_emeta_to_lbas(emeta);
}

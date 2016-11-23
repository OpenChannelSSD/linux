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
 * pblk-core.c - pblk's core functionality
 *
 * TODO:
 *   - Implement L2P snapshot on graceful tear down.
 *   - Separate mapping from actual stripping strategy to enable
 *     workload-specific optimizations
 */

#include "pblk.h"
#include <linux/time.h>

struct nvm_rq *pblk_alloc_rqd(struct pblk *pblk, int rw)
{
	mempool_t *pool;
	struct nvm_rq *rqd;
	int rq_size;

	if (rw == WRITE) {
		pool = pblk->w_rq_pool;
		rq_size = pblk_w_rq_size;
	} else {
		pool = pblk->r_rq_pool;
		rq_size = pblk_r_rq_size;
	}

	rqd = mempool_alloc(pool, GFP_KERNEL);
	if (!rqd)
		return ERR_PTR(-ENOMEM);

	memset(rqd, 0, rq_size);
	return rqd;
}

void pblk_free_rqd(struct pblk *pblk, struct nvm_rq *rqd, int rw)
{
	mempool_t *pool;

	if (rw == WRITE)
		pool = pblk->w_rq_pool;
	else
		pool = pblk->r_rq_pool;

	mempool_free(rqd, pool);
}

void pblk_print_failed_rqd(struct pblk *pblk, struct nvm_rq *rqd, int error)
{
	int offset = -1;
	struct ppa_addr p;

	if (rqd->nr_ppas ==  1) {
		p = dev_to_generic_addr(pblk->dev, rqd->ppa_addr);
		print_ppa(&p, "rqd", error);
		return;
	}

	while ((offset =
		find_next_bit((void *)&rqd->ppa_status, rqd->nr_ppas,
						offset + 1)) < rqd->nr_ppas) {
		p = dev_to_generic_addr(pblk->dev, rqd->ppa_list[offset]);
		print_ppa(&p, "rqd", error);
	}

	pr_err("error:%d, ppa_status:%llx\n", error, rqd->ppa_status);
}

void pblk_bio_free_pages(struct pblk *pblk, struct bio *bio, int off,
			 int nr_pages)
{
		struct bio_vec bv;
		int i;

		WARN_ON(off + nr_pages != bio->bi_vcnt);

		bio_advance(bio, off * PBLK_EXPOSED_PAGE_SIZE);
		for (i = off; i < nr_pages + off; i++) {
			bv = bio->bi_io_vec[i];
			mempool_free(bv.bv_page, pblk->page_pool);
		}
}

/* This function must only be used on bios owned by pblk */
int pblk_bio_add_pages(struct pblk *pblk, struct bio *bio, gfp_t flags,
		       int nr_pages)
{
	struct request_queue *q = pblk->dev->q;
	struct page *page;
	int ret;
	int i;

	for (i = 0; i < nr_pages; i++) {
		page = mempool_alloc(pblk->page_pool, flags);
		if (!page)
			goto err;

		ret = bio_add_pc_page(q, bio, page,
						PBLK_EXPOSED_PAGE_SIZE, 0);
		if (ret != PBLK_EXPOSED_PAGE_SIZE) {
			pr_err("pblk: could not add page to bio\n");
			mempool_free(page, pblk->page_pool);
			goto err;
		}
	}

	return 0;
err:
	pblk_bio_free_pages(pblk, bio, 0, i - 1);
	return -1;
}

void pblk_end_sync_bio(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
}

void pblk_write_timer_fn(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	/* Kick user I/O rate limiter queue if waiting */
	if (waitqueue_active(&pblk->wait))
		wake_up_nr(&pblk->wait, 1);

	/* kick the write thread every tick to flush outstanding data */
	pblk_write_kick(pblk);

	mod_timer(&pblk->wtimer, jiffies + msecs_to_jiffies(1000));
}

void pblk_flush_writer(struct pblk *pblk)
{
	struct bio *bio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio)
		return;

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_OP_FLUSH);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	ret = pblk_write_to_cache(pblk, bio, 0);
	if (ret == NVM_IO_OK)
		wait_for_completion_io(&wait);
	else if (ret != NVM_IO_DONE)
		pr_err("pblk: tear down bio failed\n");

	if (bio->bi_error)
		pr_err("pblk: flush sync write failed (%u)\n", bio->bi_error);

	bio_put(bio);
}

static void pblk_page_invalidate(struct pblk *pblk, struct pblk_addr *a)
{
	struct pblk_block *rblk = a->rblk;
	u64 block_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(a->ppa));
	BUG_ON(ppa_empty(a->ppa));
#endif

	block_ppa = pblk_gaddr_to_pg_offset(pblk->dev, a->ppa);

	spin_lock(&rblk->lock);
	WARN_ON(test_and_set_bit(block_ppa, rblk->invalid_bitmap));
	rblk->nr_invalid_secs++;
	spin_unlock(&rblk->lock);
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
				  unsigned int nr_secs)
{
	sector_t i;

	spin_lock(&pblk->trans_lock);
	for (i = slba; i < slba + nr_secs; i++) {
		struct pblk_addr *gp = &pblk->trans_map[i];

		if (gp->rblk)
			pblk_page_invalidate(pblk, gp);
		ppa_set_empty(&gp->ppa);
		gp->rblk = NULL;
	}
	spin_unlock(&pblk->trans_lock);
}

void pblk_discard(struct pblk *pblk, struct bio *bio)
{
	sector_t slba = bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
	sector_t nr_secs = bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;

	pblk_invalidate_range(pblk, slba, nr_secs);
}

struct ppa_addr pblk_get_lba_map(struct pblk *pblk, sector_t lba)
{
	struct pblk_addr *gp;
	struct ppa_addr ppa;

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[lba];
	ppa = gp->ppa;
	spin_unlock(&pblk->trans_lock);

	return ppa;
}

static void pblk_init_rlpg(struct pblk *pblk, struct pblk_block *rblk,
			   struct pblk_blk_rec_lpg *rlpg)
{
	u64 *lbas = pblk_rlpg_to_llba(rlpg);
	unsigned long *bitmaps;
	int nr_entries = pblk->nr_blk_dsecs;

	rblk->cur_sec = 0;
	rblk->nr_invalid_secs = 0;
	rblk->rlpg = rlpg;

	bitmaps = (void *)(lbas + nr_entries);

	rblk->sector_bitmap = bitmaps;
	rblk->sync_bitmap = (rblk->sector_bitmap) + rlpg->bitmap_len;
	rblk->invalid_bitmap = (rblk->sync_bitmap) + rlpg->bitmap_len;
}

struct pblk_blk_rec_lpg *pblk_alloc_blk_meta(struct pblk *pblk,
					     struct pblk_block *rblk,
					     u32 status)
{
	struct pblk_blk_rec_lpg *rlpg = NULL;
	unsigned int rlpg_len, req_len, bitmap_len;

	if (pblk_recov_calc_meta_len(pblk, &bitmap_len, &rlpg_len, &req_len))
		goto out;

	rlpg = mempool_alloc(pblk->blk_meta_pool, GFP_KERNEL);
	if (!rlpg)
		goto out;
	memset(rlpg, 0, req_len);

	rlpg->status = status;
	rlpg->rlpg_len = rlpg_len;
	rlpg->req_len = req_len;
	rlpg->bitmap_len = bitmap_len;
	rlpg->crc = 0;
	rlpg->nr_lbas = 0;
	rlpg->nr_padded = 0;

	pblk_init_rlpg(pblk, rblk, rlpg);

out:
	return rlpg;
}

struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun)
{
	struct pblk_block *rblk;
	struct pblk_blk_rec_lpg *rlpg;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rlun->lock);
#endif

	if (list_empty(&rlun->free_list))
		goto err;

	/* Blocks are erased when put */
	rblk = list_first_entry(&rlun->free_list, struct pblk_block, list);
	rblk->state = NVM_BLK_ST_TGT;
	pblk_rl_free_blks_dec(pblk, rlun);

	list_move_tail(&rblk->list, &rlun->open_list);

	rlpg = pblk_alloc_blk_meta(pblk, rblk, PBLK_BLK_ST_OPEN);
	if (!rlpg)
		goto fail_put_blk;

	return rblk;

fail_put_blk:
	pblk_put_blk(pblk, rblk);
err:
	return NULL;
}

void pblk_set_lun_cur(struct pblk_lun *rlun, struct pblk_block *rblk)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rlun->lock);

	if (rlun->cur) {
		spin_lock(&rlun->cur->lock);
		WARN_ON(!block_is_full(rlun->pblk, rlun->cur) &&
							!block_is_bad(rblk));
		spin_unlock(&rlun->cur->lock);
	}
#endif

	rlun->cur = rblk;
}

void pblk_run_blk_ws(struct pblk *pblk, struct pblk_block *rblk,
		     void (*work)(struct work_struct *))
{
	struct pblk_block_ws *blk_ws;

	blk_ws = mempool_alloc(pblk->blk_ws_pool, GFP_ATOMIC);
	if (!blk_ws)
		return;

	blk_ws->pblk = pblk;
	blk_ws->rblk = rblk;

	INIT_WORK(&blk_ws->ws_blk, work);
	queue_work(pblk->kgc_wq, &blk_ws->ws_blk);
}

void pblk_end_close_blk_bio(struct pblk *pblk, struct nvm_rq *rqd, int run_gc)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_ctx *ctx = pblk_set_ctx(pblk, rqd);
	struct pblk_compl_close_ctx *c_ctx = ctx->c_ctx;

	up(&c_ctx->rblk->rlun->wr_sem);

	if (run_gc)
		pblk_run_blk_ws(pblk, c_ctx->rblk, pblk_gc_queue);

	nvm_free_rqd_ppalist(dev->parent, rqd);
	bio_put(rqd->bio);
	kfree(rqd);
}

static void pblk_end_w_pad(struct pblk *pblk, struct nvm_rq *rqd,
			   struct pblk_ctx *ctx)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(c_ctx->nr_valid != 0);
#endif

	if (c_ctx->nr_padded > 1)
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, WRITE);
}

void pblk_end_io(struct nvm_rq *rqd)
{
	struct pblk *pblk = container_of(rqd->ins, struct pblk, instance);
	uint8_t nr_secs = rqd->nr_ppas;

	if (bio_data_dir(rqd->bio) == READ)
		pblk_end_io_read(pblk, rqd, nr_secs);
	else
		pblk_end_io_write(pblk, rqd);
}

int pblk_update_map(struct pblk *pblk, sector_t laddr, struct pblk_block *rblk,
		    struct ppa_addr ppa)
{
	struct pblk_addr *gp;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!rblk &&
		pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	/* logic error: lba out-of-bounds */
	BUG_ON(laddr >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];

	if (gp->rblk)
		pblk_page_invalidate(pblk, gp);
	gp->ppa = ppa;
	gp->rblk = rblk;
	spin_unlock(&pblk->trans_lock);

	return 0;
}

int pblk_update_map_gc(struct pblk *pblk, sector_t laddr,
		       struct pblk_block *rblk, struct ppa_addr ppa,
		       struct pblk_block *gc_rblk)
{
	struct pblk_addr *gp;

	/* logic error: lba out-of-bounds */
	BUG_ON(laddr >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];

	/* Prevent updated entries to be overwritten by GC */
	if (gp->rblk && gc_rblk->id != gp->rblk->id)
		goto out;
	gp->ppa = ppa;
	gp->rblk = rblk;
out:
	spin_unlock(&pblk->trans_lock);

	return 0;
}

static int pblk_setup_pad_rq(struct pblk *pblk, struct pblk_block *rblk,
			     struct nvm_rq *rqd, struct pblk_ctx *ctx)
{
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	unsigned int valid_secs = c_ctx->nr_valid;
	unsigned int padded_secs = c_ctx->nr_padded;
	unsigned int nr_secs = valid_secs + padded_secs;
	struct pblk_sec_meta *meta;
	int min = pblk->min_write_pgs;
	int i;
	int ret;

	ret = pblk_write_alloc_rq(pblk, rqd, ctx, nr_secs);
	if (ret)
		goto out;

	meta = rqd->meta_list;

	if (unlikely(nr_secs == 1)) {
		/*
		 * Single sector path - this path is highly improbable since
		 * controllers typically deal with multi-sector and multi-plane
		 * pages. This path is though useful for testing on QEMU
		 */

		ret = pblk_map_page(pblk, rblk, c_ctx->sentry, &rqd->ppa_addr,
								&meta[0], 1, 0);
		/* There is no more available pages to map the current
		 * request. Rate limiter had probably failed
		 */
		WARN_ON(ret);

		goto out;
	}

	for (i = 0; i < nr_secs; i += min) {
		ret = pblk_map_page(pblk, rblk, c_ctx->sentry + i,
						&rqd->ppa_list[i],
						&meta[i], min, 0);
		/* There is no more available pages to map the current
		 * request. Rate limiter had probably failed
		 */
		WARN_ON(ret);
	}

#ifdef CONFIG_NVM_DEBUG
	if (pblk_boundary_checks(pblk->dev, rqd->ppa_list, rqd->nr_ppas))
		WARN_ON(1);
#endif

out:
	return ret;
}

static void pblk_pad_blk(struct pblk *pblk, struct pblk_block *rblk,
			 int nr_free_secs)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct bio *bio;
	struct nvm_rq *rqd;
	struct pblk_ctx *ctx;
	struct pblk_compl_ctx *c_ctx;
	void *pad_data;
	unsigned int bio_len;
	int nr_secs, err;
	DECLARE_COMPLETION_ONSTACK(wait);

	pad_data = kzalloc(pblk->max_write_pgs * geo->sec_size, GFP_KERNEL);
	if (!pad_data)
		return;

	do {
		nr_secs = (nr_free_secs > pblk->max_write_pgs) ?
					pblk->max_write_pgs : nr_free_secs;

		rqd = pblk_alloc_rqd(pblk, WRITE);
		if (IS_ERR(rqd)) {
			pr_err("pblk: could not alloc write req.\n ");
			goto free_pad_data;
		}
		ctx = pblk_set_ctx(pblk, rqd);
		c_ctx = ctx->c_ctx;

		bio_len = nr_secs * geo->sec_size;
		bio = bio_map_kern(dev->q, pad_data, bio_len, GFP_KERNEL);
		if (!bio) {
			pr_err("pblk: could not alloc tear down bio\n");
			goto free_rqd;
		}

		bio->bi_iter.bi_sector = 0; /* artificial bio */
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		bio->bi_private = &wait;
		bio->bi_end_io = pblk_end_sync_bio;
		rqd->bio = bio;

		ctx->flags = PBLK_IOTYPE_SYNC;
		c_ctx->sentry = 0;
		c_ctx->nr_valid = 0;
		c_ctx->nr_padded = nr_secs;

		if (pblk_setup_pad_rq(pblk, rblk, rqd, ctx)) {
			pr_err("pblk: could not setup tear down req.\n");
			goto free_bio;
		}

		err = nvm_submit_io(dev, rqd);
		if (err) {
			pr_err("pblk: I/O submission failed: %d\n", err);
			goto free_bio;
		}
		wait_for_completion_io(&wait);
		pblk_end_w_pad(pblk, rqd, ctx);

		nr_free_secs -= nr_secs;
	} while (nr_free_secs > 0);

	kfree(pad_data);
	return;

free_bio:
	bio_put(bio);
free_rqd:
	pblk_free_rqd(pblk, rqd, WRITE);
free_pad_data:
	kfree(pad_data);
}

static inline u64 pblk_nr_free_secs(struct pblk *pblk, struct pblk_block *rblk)
{
	u64 free_secs = pblk->nr_blk_dsecs;

	spin_lock(&rblk->lock);
	free_secs -= bitmap_weight(rblk->sector_bitmap, pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

	return free_secs;
}

static void pblk_free_blk_meta(struct pblk *pblk, struct pblk_block *rblk)
{
	/* All bitmaps are allocated together with the rlpg structure */
	mempool_free(rblk->rlpg, pblk->blk_meta_pool);
}

unsigned long pblk_nr_free_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	unsigned long avail = 0;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		spin_lock(&rlun->lock);
		avail += rlun->nr_free_blocks;
		spin_unlock(&rlun->lock);
	}

	return avail;
}

/*
 * TODO: For now, we pad the whole block. In the future, pad only the pages that
 * are needed to guarantee that future reads will come, and delegate bringing up
 * the block for writing to the bring up recovery. Basically, this means
 * implementing l2p snapshot and in case of power failure, if a block belongs
 * to a target and it is not closed, scan the OOB area for each page to
 * recover the state of the block. There should only be NUM_LUNS active blocks
 * at any moment in time.
 */
void pblk_pad_open_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i, mod;
	int nr_free_secs;
	LIST_HEAD(open_list);

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock);
		list_cut_position(&open_list, &rlun->open_list,
							rlun->open_list.prev);
		spin_unlock(&rlun->lock);

		list_for_each_entry_safe(rblk, trblk, &open_list, list) {
			nr_free_secs = pblk_nr_free_secs(pblk, rblk);
			div_u64_rem(nr_free_secs, pblk->min_write_pgs, &mod);
			if (mod) {
				pr_err("pblk: corrupted block\n");
				continue;
			}

			/* empty block - no need for padding */
			if (nr_free_secs == pblk->nr_blk_dsecs) {
				pblk_put_blk(pblk, rblk);
				continue;
			}

			pr_debug("pblk: padding %d sectors in blk:%d\n",
						nr_free_secs, rblk->id);

			pblk_pad_blk(pblk, rblk, nr_free_secs);
		}

		spin_lock(&rlun->lock);
		list_splice(&open_list, &rlun->open_list);
		spin_unlock(&rlun->lock);
	}

	/* Wait until padding completes and blocks are closed */
	pblk_for_each_lun(pblk, rlun, i) {
retry:
		spin_lock(&rlun->lock);
		if (!list_empty(&rlun->open_list)) {
			spin_unlock(&rlun->lock);
			io_schedule();
			goto retry;
		}
		spin_unlock(&rlun->lock);
	}
}

void pblk_free_blks(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	unsigned int i;

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock);
		list_for_each_entry_safe(rblk, trblk, &rlun->prio_list, prio) {
			pblk_free_blk_meta(pblk, rblk);
			list_del(&rblk->prio);
		}
		spin_unlock(&rlun->lock);
	}
}

void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock);
	if (rblk->state & NVM_BLK_ST_TGT) {
		list_move_tail(&rblk->list, &rlun->free_list);
		pblk_rl_free_blks_inc(pblk, rlun);
		rblk->state = NVM_BLK_ST_FREE;
	} else if (rblk->state & NVM_BLK_ST_BAD) {
		list_move_tail(&rblk->list, &rlun->bb_list);
		rblk->state = NVM_BLK_ST_BAD;
	} else {
		pr_err("pblk: erroneous block type (%d-> %u)\n",
							rblk->id, rblk->state);
		list_move_tail(&rblk->list, &rlun->bb_list);
	}
	spin_unlock(&rlun->lock);

	pblk_free_blk_meta(pblk, rblk);
}

/* TODO: No need to scan if LUNs are balanced */
static struct pblk_lun *pblk_ppa_to_lun(struct pblk *pblk, struct ppa_addr p)
{
	struct pblk_lun *rlun = NULL;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		if (pblk->luns[i].bppa.g.ch == p.g.ch &&
				pblk->luns[i].bppa.g.lun == p.g.lun) {
			rlun = &pblk->luns[i];
			break;
		}
	}

	return rlun;
}

void pblk_mark_bb(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_lun *rlun;
	struct pblk_block *rblk;

	rlun = pblk_ppa_to_lun(pblk, ppa);
	rblk = &rlun->blocks[ppa.g.blk];
	rblk->state = NVM_BLK_ST_BAD;

	nvm_set_bb_tbl(dev->parent, &ppa, 1, NVM_BLK_T_GRWN_BAD);
}

void pblk_erase_blk(struct pblk *pblk, struct pblk_block *rblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_lun *rlun = rblk->rlun;
	int flags = pblk_set_progr_mode(pblk, ERASE);
	struct ppa_addr ppa = pblk_blk_ppa_to_gaddr(pblk->dev, rblk, 0);
	int error;

	down(&rlun->wr_sem);
	error = nvm_erase_blk(dev, &ppa, flags);
	up(&rlun->wr_sem);

	if (error) {
		pblk_mark_bb(pblk, ppa);
		inc_stat(pblk, &pblk->erase_failed, 0);
		print_ppa(&ppa, "erase", 0);
	}
}


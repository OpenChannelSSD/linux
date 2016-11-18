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

	if (rqd->nr_ppas ==  1) {
		print_ppa(&rqd->ppa_addr, "rqd", error);
		return;
	}

	while ((offset =
		find_next_bit((void *)&rqd->ppa_status, rqd->nr_ppas,
						offset + 1)) < rqd->nr_ppas) {
		print_ppa(&rqd->ppa_list[offset], "rqd", error);
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

		ret = bio_add_pc_page(q, bio, page, PBLK_EXPOSED_PAGE_SIZE, 0);
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

void pblk_write_timer_fn(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	/* kick the write thread every tick to flush outstanding data */
	pblk_write_kick(pblk);
}

/* Erase completion assumes that only one block is erased at the time */
static void pblk_end_io_erase(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_line *line;
	int left_seblks;

	line = &pblk->lines[pblk_ppa_to_line(rqd->ppa_list[0])];
	left_seblks = READ_ONCE(line->left_seblks);
	left_seblks--;
	WARN_ONCE(left_seblks < 0, "pblk: corrupted erase counter");
	smp_store_release(&line->left_seblks, left_seblks);

	if (rqd->error) {
		struct ppa_addr *ppa;
		int pos;

		ppa = kmalloc(sizeof(struct ppa_addr), GFP_ATOMIC);
		if (!ppa)
			goto out;

		*ppa = rqd->ppa_list[0];
		pos = pblk_ppa_to_pos(&dev->geo, *ppa);

		pr_err("pblk: erase failed: line:%d, pos:%d\n", line->id, pos);
		inc_stat(pblk, &pblk->erase_failed, 0);

		if (test_and_set_bit(pos, line->blk_bitmap))
			pr_err("pblk: attempted to erase bb: line:%d, pos:%d\n",
							line->id, pos);

		pblk_line_run_ws(pblk, ppa, pblk_line_mark_bb);
	}

out:
	if (rqd->nr_ppas > 1)
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

	mempool_free(rqd, pblk->r_rq_pool);
}

void pblk_end_bio_sync(struct bio *bio)
{
	struct completion *waiting = bio->bi_private;

	complete(waiting);
}

void pblk_end_io_sync(struct nvm_rq *rqd)
{
	struct completion *waiting = rqd->private;

	complete(waiting);
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
	bio->bi_end_io = pblk_end_bio_sync;

	ret = pblk_write_to_cache(pblk, bio, 0);
	if (ret == NVM_IO_OK)
		wait_for_completion_io(&wait);
	else if (ret != NVM_IO_DONE)
		pr_err("pblk: tear down bio failed\n");

	if (bio->bi_error)
		pr_err("pblk: flush sync write failed (%u)\n", bio->bi_error);

	bio_put(bio);
}

struct list_head *pblk_line_gc_list(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list = NULL;

	if (line->vsc == 0) {
		if (line->gc_group != PBLK_LINEGC_FULL) {
			line->gc_group = PBLK_LINEGC_FULL;
			move_list = &l_mg->gc_full_list;
		}
	} else if (line->vsc < lm->mid_thrs) {
		if (line->gc_group != PBLK_LINEGC_HIGH) {
			line->gc_group = PBLK_LINEGC_HIGH;
			move_list = &l_mg->gc_high_list;
		}
	} else if (line->vsc < lm->high_thrs) {
		if (line->gc_group != PBLK_LINEGC_MID) {
			line->gc_group = PBLK_LINEGC_MID;
			move_list = &l_mg->gc_mid_list;
		}
	} else if (line->vsc < line->sec_in_line) {
		if (line->gc_group != PBLK_LINEGC_LOW) {
			line->gc_group = PBLK_LINEGC_LOW;
			move_list = &l_mg->gc_low_list;
		}
	} else if (line->vsc == line->sec_in_line) {
		if (line->gc_group != PBLK_LINEGC_EMPTY) {
			line->gc_group = PBLK_LINEGC_EMPTY;
			move_list = &l_mg->gc_empty_list;
		}
	} else {
		line->state = PBLK_LINESTATE_CORRUPT;
		line->gc_group = PBLK_LINEGC_NONE;
		move_list =  &l_mg->corrupt_list;
		pr_err("pblk: corrupted vsc for line %d, vsc:%d (%d/%d/%d)\n",
						line->id, line->vsc,
						line->sec_in_line,
						lm->high_thrs, lm->mid_thrs);
	}

	return move_list;
}

static void pblk_page_invalidate(struct pblk *pblk, struct ppa_addr ppa)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list = NULL;
	struct pblk_line *line;
	int line_id;
	u64 paddr;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(ppa));
	BUG_ON(ppa_empty(ppa));
#endif

	line_id = pblk_ppa_to_line(ppa);
	line = &pblk->lines[line_id];

	/* Lines being reclaimed (GC'ed) do not need to be invalidated. Before
	 * the L2P table is modified with valid reclaimed sectors a check is
	 * done to endure that newer updates are not overwritten.
	 */
	spin_lock(&line->lock);
	if (line->state == PBLK_LINESTATE_GC ||
					line->state == PBLK_LINESTATE_FREE) {
		spin_unlock(&line->lock);
		return;
	}

	paddr = pblk_ppa_to_line_addr(pblk, ppa);
	if (test_and_set_bit(paddr, line->invalid_bitmap)) {
		WARN_ONCE(1, "pblk: double invalidate\n");
		spin_unlock(&line->lock);
		return;
	}
	line->vsc--;

	if (line->state == PBLK_LINESTATE_CLOSED)
		move_list = pblk_line_gc_list(pblk, line);
	spin_unlock(&line->lock);

	if (move_list) {
		spin_lock(&l_mg->gc_lock);
		list_move_tail(&line->list, move_list);
		spin_unlock(&l_mg->gc_lock);
	}
}

static void pblk_invalidate_range(struct pblk *pblk, sector_t slba,
				  unsigned int nr_secs)
{
	sector_t i;

	spin_lock(&pblk->trans_lock);
	for (i = slba; i < slba + nr_secs; i++) {
		struct ppa_addr *ppa = &pblk->trans_map[i];

		if (!nvm_addr_in_cache(*ppa) && !ppa_empty(*ppa))
			pblk_page_invalidate(pblk, *ppa);
		ppa_set_empty(ppa);
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
	struct ppa_addr ppa;

	spin_lock(&pblk->trans_lock);
	ppa = pblk->trans_map[lba];
	spin_unlock(&pblk->trans_lock);

	return ppa;
}

void pblk_log_write_err(struct pblk *pblk, struct nvm_rq *rqd)
{
	inc_stat(pblk, &pblk->write_failed, 1);
#ifdef CONFIG_NVM_DEBUG
	pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
}
void pblk_log_read_err(struct pblk *pblk, struct nvm_rq *rqd)
{
	switch (rqd->error) {
	case NVM_RSP_WARN_HIGHECC:
		inc_stat(pblk, &pblk->read_high_ecc, 1);
		break;
	case NVM_RSP_ERR_FAILECC:
		inc_stat(pblk, &pblk->read_failed, 1);
		break;
	case NVM_RSP_ERR_FAILCRC:
		inc_stat(pblk, &pblk->read_failed, 1);
		break;
	case NVM_RSP_ERR_EMPTYPAGE:
		inc_stat(pblk, &pblk->read_empty, 1);
		break;
	default:
		pr_err("pblk: unknown read error:%d\n", rqd->error);
	}
#ifdef CONFIG_NVM_DEBUG
	pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
}

int pblk_submit_io(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct nvm_tgt_dev *dev = pblk->dev;

#ifdef CONFIG_NVM_DEBUG
	struct ppa_addr *ppa_list;

	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
	if (pblk_boundary_checks(dev, ppa_list, rqd->nr_ppas)) {
		WARN_ON(1);
		return -EINVAL;
	}

	if (rqd->opcode == NVM_OP_PWRITE) {
		struct pblk_line *line;
		struct ppa_addr ppa;
		int i;

		for (i = 0; i < rqd->nr_ppas; i++) {
			ppa = ppa_list[i];
			line = &pblk->lines[pblk_ppa_to_line(ppa)];

			spin_lock(&line->lock);
			if (line->state != PBLK_LINESTATE_OPEN) {
				pr_err("pblk: bad ppa: line:%d,state:%d\n",
						line->id, line->state);
				WARN_ON(1);
				spin_unlock(&line->lock);
				return -EINVAL;
			}
			spin_unlock(&line->lock);
		}
	}
#endif

	return nvm_submit_io(dev, rqd);
}

struct bio *pblk_bio_map_addr(struct pblk *pblk, void *data,
			      unsigned int nr_secs, unsigned int len,
			      gfp_t gfp_mask)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct page *page;
	struct bio *bio;
	void *kaddr = data;
	int i, ret;

	if (l_mg->emeta_alloc_type == PBLK_KMALLOC_META)
		return bio_map_kern(dev->q, kaddr, len, gfp_mask);

	bio = bio_kmalloc(gfp_mask, nr_secs);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < nr_secs; i++) {
		page = vmalloc_to_page(kaddr);
		if (!page) {
			pr_err("pblk: could not map vmalloc emeta\n");
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		ret = bio_add_pc_page(dev->q, bio, page, PAGE_SIZE, 0);
		if (ret != PAGE_SIZE) {
			pr_err("pblk: could not add page to emeta bio\n");
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		kaddr += PAGE_SIZE;
	}

out:
	return bio;
}

int pblk_calc_secs(struct pblk *pblk, unsigned long secs_avail,
		    unsigned long secs_to_flush)
{
	int max = pblk->max_write_pgs;
	int min = pblk->min_write_pgs;
	int secs_to_sync = 0;

	if ((secs_avail >= max) || (secs_to_flush >= max)) {
		secs_to_sync = max;
	} else if (secs_avail >= min) {
		if (secs_to_flush) {
			secs_to_sync = min * (secs_to_flush / min);
			while (1) {
				int inc = secs_to_sync + min;

				if (inc <= secs_avail && inc <= max)
					secs_to_sync += min;
				else
					break;
			}
		} else
			secs_to_sync = min * (secs_avail / min);
	} else {
		if (secs_to_flush)
			secs_to_sync = min;
	}

	return secs_to_sync;
}

u64 pblk_alloc_page(struct pblk *pblk, struct pblk_line *line)
{
	int nr_secs = pblk->min_write_pgs;
	u64 addr;
	int i;

	/* logic error: ppa out-of-bounds */
	BUG_ON(line->cur_sec + nr_secs > pblk->lm.sec_per_line);

	line->cur_sec = addr = find_next_zero_bit(line->map_bitmap,
					pblk->lm.sec_per_line, line->cur_sec);
	for (i = 0; i < nr_secs; i++, line->cur_sec++, line->left_msecs--)
		WARN_ON(test_and_set_bit(line->cur_sec, line->map_bitmap));

	return addr;
}

/*
 * Submit emeta to one LUN in the raid line at the time to avoid a deadlock when
 * taking the per LUN semaphore.
 */
static int pblk_line_submit_emeta_io(struct pblk *pblk, struct pblk_line *line,
				     u64 paddr, int dir)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct bio *bio;
	struct nvm_rq *rqd;
	struct ppa_addr *ppa_list;
	dma_addr_t dma_ppa_list;
	void *emeta = line->emeta;
	int left_ppas = lm->emeta_sec;
	int id = line->id;
	int rq_ppas, rq_len;
	int cmd_op, bio_op;
	int flags;
	int i, j;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	if (dir == WRITE) {
		bio_op = REQ_OP_WRITE;
		cmd_op = NVM_OP_PWRITE;
		flags = pblk_set_progr_mode(pblk, WRITE);
	} else if (dir == READ) {
		bio_op = REQ_OP_READ;
		cmd_op = NVM_OP_PREAD;
		flags = pblk_set_read_mode(pblk);
	} else
		return -EINVAL;

	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd)
		return -ENOMEM;

	ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_ppa_list);
	if (!ppa_list) {
		ret = -ENOMEM;
		goto free_rqd;
	}

next_rq:
	memset(rqd, 0, pblk_r_rq_size);

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	rq_len = rq_ppas * geo->sec_size;

	bio = pblk_bio_map_addr(pblk, emeta, rq_ppas, rq_len, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto free_rqd_dma;
	}

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, bio_op, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	rqd->bio = bio;
	rqd->opcode = cmd_op;
	rqd->flags = flags;
	rqd->meta_list = NULL;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->end_io = NULL;

	if (dir == WRITE) {
		for (i = 0; i < rqd->nr_ppas; ) {
			paddr = pblk_alloc_page(pblk, line);
			for (j = 0; j < pblk->min_write_pgs; j++, i++, paddr++)
				rqd->ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, id);
		}
	} else {
		for (i = 0; i < rqd->nr_ppas; ){
			struct ppa_addr ppa = addr_to_gen_ppa(pblk, paddr, id);
			int pos = pblk_ppa_to_pos(geo, ppa);

			while (test_bit(pos, line->blk_bitmap)) {
				paddr += pblk->min_write_pgs;
				ppa = addr_to_gen_ppa(pblk, paddr, id);
				pos = pblk_ppa_to_pos(geo, ppa);
			}

			for (j = 0; j < pblk->min_write_pgs; j++, i++, paddr++)
				rqd->ppa_list[i] =
					addr_to_gen_ppa(pblk, paddr, line->id);
		}
	}

	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		pr_err("pblk: emeta I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_rqd_dma;
	}
	wait_for_completion_io(&wait);
	reinit_completion(&wait);

	if (rqd->error) {
		if (dir == WRITE)
			pblk_log_write_err(pblk, rqd);
		else
			pblk_log_read_err(pblk, rqd);
	}
#ifdef CONFIG_NVM_DEBUG
	else
		BUG_ON(rqd->bio->bi_error);
#endif

	bio_put(bio);

	emeta += rq_len;
	left_ppas -= rq_ppas;
	if (left_ppas)
		goto next_rq;

free_rqd_dma:
	nvm_dev_dma_free(dev->parent, ppa_list, dma_ppa_list);
free_rqd:
	mempool_free(rqd, pblk->r_rq_pool);

	return ret;
}

/*
 * TODO: Implement error handling in case that this I/O fails
 * smeta operations are always synchronous
 */
static int pblk_line_submit_smeta_io(struct pblk *pblk, struct pblk_line *line,
				     u64 paddr, int dir)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_line_meta *lm = &pblk->lm;
	struct bio *bio;
	struct nvm_rq *rqd;
	u64 *lba_list = NULL;
	int i, ret;
	int cmd_op, bio_op;
	int flags;
	DECLARE_COMPLETION_ONSTACK(wait);

	if (dir == WRITE) {
		bio_op = REQ_OP_WRITE;
		cmd_op = NVM_OP_PWRITE;
		flags = pblk_set_progr_mode(pblk, WRITE);
		lba_list = pblk_line_emeta_to_lbas(line->emeta);
	} else if (dir == READ) {
		bio_op = REQ_OP_READ;
		cmd_op = NVM_OP_PREAD;
		flags = pblk_set_read_mode(pblk);
	} else
		return -EINVAL;

	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd)
		return -ENOMEM;
	memset(rqd, 0, pblk_r_rq_size);

	rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_ppa_list);
	if (!rqd->ppa_list) {
		ret = -ENOMEM;
		goto free_rqd;
	}

	bio = bio_map_kern(dev->q, line->smeta, lm->smeta_len, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto free_ppa_list;
	}

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, bio_op, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	rqd->bio = bio;
	rqd->opcode = cmd_op;
	rqd->flags = flags;
	rqd->meta_list = NULL;
	rqd->nr_ppas = lm->smeta_sec;
	rqd->end_io = NULL;

	for (i = 0; i < lm->smeta_sec; i++, paddr++) {
		rqd->ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);
		if (dir == WRITE)
			lba_list[paddr] = ADDR_EMPTY;
	}

	/*
	 * This I/O is sent by the write thread when a line is replace. Since
	 * the write thread is the only one sending write and erase commands,
	 * there is no need to take the LUN semaphore.
	 */
	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		pr_err("pblk: smeta I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_bio;
	}
	wait_for_completion_io(&wait);

	if (rqd->error) {
		if (dir == WRITE)
			pblk_log_write_err(pblk, rqd);
		else
			pblk_log_read_err(pblk, rqd);
	}
#ifdef CONFIG_NVM_DEBUG
	else
		BUG_ON(rqd->bio->bi_error);
#endif

free_bio:
	bio_put(bio);
free_ppa_list:
	nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);
free_rqd:
	mempool_free(rqd, pblk->r_rq_pool);

	return ret;
}

/* For now lines are always assumed full lines. Thus, smeta former and current
 * lun bitmaps are omitted.
 */
static void pblk_line_setup(struct pblk *pblk, struct pblk_line *line,
			    struct pblk_line *cur, int line_type)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct line_smeta *smeta = line->smeta;
	struct line_emeta *emeta = line->emeta;
	u32 crc = ~(u32)0;
	int nr_bb = 0;
	int slun;
	u64 off;
	int bit;

	line->type = line_type;

	/* Run-time metadata */
	line->lun_bitmap = ((void *)(smeta)) + sizeof(struct line_smeta);

	/* Mark LUNs allocated in this line (all for now) */
	line->sec_in_line = lm->sec_per_line;
	bitmap_set(line->lun_bitmap, 0, lm->lun_bitmap_len);
	slun = find_first_bit(line->lun_bitmap, lm->lun_bitmap_len);

	/* Start metadata */
	smeta->nr_luns = geo->nr_luns;
	smeta->line_type = line->type;
	smeta->id = line->id;
	smeta->slun = slun;
	smeta->seq_nr = line->seq_nr;
	smeta->smeta_len = lm->smeta_len;

	/* Fill metadata among lines */
	if (likely(cur)) {
		memcpy(line->lun_bitmap, cur->lun_bitmap, lm->lun_bitmap_len);
		smeta->p_id = cur->id;
		smeta->p_slun =
			find_first_bit(cur->lun_bitmap, lm->lun_bitmap_len);
		cur->emeta->n_id = line->id;
		cur->emeta->n_slun =
			find_first_bit(line->lun_bitmap, lm->lun_bitmap_len);
	} else {
		smeta->p_id = PBLK_LINE_EMPTY;
		smeta->p_slun = PBLK_LINE_EMPTY;
	}

	crc = crc32_le(crc, (unsigned char *)smeta + sizeof(crc),
					lm->smeta_len - sizeof(crc));
	smeta->crc = crc;

	/* End metadata */
	emeta->nr_luns = geo->nr_luns;
	emeta->line_type = line->type;
	emeta->id = line->id;
	emeta->slun = slun;
	emeta->seq_nr = line->seq_nr;
	emeta->nr_lbas = lm->sec_per_line - lm->emeta_sec - lm->smeta_sec;
	emeta->n_id = PBLK_LINE_EMPTY;
	emeta->n_slun = PBLK_LINE_EMPTY;
	emeta->emeta_len = lm->emeta_len;
	emeta->crc = 0;

	/* Capture bad block information on line mapping bitmaps */
	bit = -1;
	while ((bit = find_next_bit(line->blk_bitmap, lm->blk_per_line,
					bit + 1)) < lm->blk_per_line) {
		off = bit * geo->sec_per_pl;
		bitmap_shift_left(l_mg->bb_aux, l_mg->bb_template, off,
							lm->sec_per_line);
		bitmap_or(line->map_bitmap, line->map_bitmap, l_mg->bb_aux,
							lm->sec_per_line);
		line->sec_in_line -= geo->sec_per_blk;
		if (bit >= lm->emeta_bb)
			nr_bb++;
	}

	/* Mark smeta metadata sectors as bad sectors */
	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	off = bit * geo->sec_per_pl;
	bitmap_set(line->map_bitmap, off, lm->smeta_sec);
	line->sec_in_line -= lm->smeta_sec;
	line->smeta_ssec = off;
	line->cur_sec = off + lm->smeta_sec;

	bitmap_copy(line->invalid_bitmap, line->map_bitmap, lm->sec_per_line);

	/* TODO: Explore how to improve this sync I/O */
	/* TODO: do error handling. smeta write must succeed */
	if (pblk_line_submit_smeta_io(pblk, line, off, WRITE))
		pr_err("pblk: line smeta I/O failed\n");

	/* Mark emeta metadata sectors as bad sectors. We need to consider bad
	 * blocks to make sure that there are enough sectors to store emeta
	 */
	bit = lm->sec_per_line;
	off = lm->sec_per_line - lm->emeta_sec;
	bitmap_set(line->invalid_bitmap, off, lm->emeta_sec);
	while (nr_bb) {
		off -= geo->sec_per_pl;
		if (!test_bit(off, line->invalid_bitmap)) {
			bitmap_set(line->invalid_bitmap, off, geo->sec_per_pl);
			nr_bb--;
		}
	}

	line->sec_in_line -= lm->emeta_sec;
	line->emeta_ssec = off;
	line->vsc = line->left_ssecs = line->left_msecs = line->sec_in_line;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(lm->sec_per_line - line->sec_in_line !=
		bitmap_weight(line->invalid_bitmap, lm->sec_per_line));
#endif
}

struct pblk_line *pblk_line_get(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *line = NULL;
	int bit;

retry_get:
	if (list_empty(&l_mg->free_list)) {
		pr_err("pblk: no free lines\n");
		goto out;
	}

	line = list_first_entry(&l_mg->free_list, struct pblk_line, list);
	list_del(&line->list);

	/* Bad blocks do not need to be erased */
	bitmap_copy(line->erase_bitmap, line->blk_bitmap, lm->blk_per_line);
	line->left_seblks = line->left_eblks = line->blk_in_line;

	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	if (unlikely(bit >= lm->blk_per_line)) {
		pr_debug("pblk: line %d is bad\n", line->id);
		goto retry_get;
	}

	line->map_bitmap = mempool_alloc(pblk->blk_meta_pool, GFP_ATOMIC);
	if (!line->map_bitmap) {
		list_add(&line->list, &l_mg->free_list);
		goto out;
	}
	memset(line->map_bitmap, 0, lm->sec_bitmap_len);

	/* invalid_bitmap is special since it is used when line is closed. No
	 * need to zeroized; it will be initialized using bb info form
	 * map_bitmap
	 */
	line->invalid_bitmap = mempool_alloc(pblk->blk_meta_pool, GFP_ATOMIC);
	if (!line->invalid_bitmap) {
		mempool_free(line->map_bitmap, pblk->blk_meta_pool);
		list_add(&line->list, &l_mg->free_list);
		goto out;
	}

	spin_lock(&line->lock);
	BUG_ON(line->state != PBLK_LINESTATE_FREE);
	line->state = PBLK_LINESTATE_OPEN;
	spin_unlock(&line->lock);

	kref_init(&line->ref);
out:
	return line;
}

struct pblk_line *pblk_line_get_first_data(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;
	int meta_line;

	spin_lock(&l_mg->free_lock);
	line = pblk_line_get(pblk);
	if (!line) {
		spin_unlock(&l_mg->free_lock);
		return NULL;
	}

	line->seq_nr = l_mg->d_seq_nr++;
	l_mg->data_line = line;
	l_mg->nr_free_lines--;

	meta_line = find_first_zero_bit(&l_mg->meta_bitmap, PBLK_DATA_LINES);
	set_bit(meta_line, &l_mg->meta_bitmap);
	line->smeta = l_mg->sline_meta[meta_line].meta;
	line->emeta = l_mg->eline_meta[meta_line].meta;
	line->meta_line = meta_line;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_dec(&pblk->rl, line);

	pblk_line_erase(pblk, line);
	pblk_line_setup(pblk, line, NULL, PBLK_LINETYPE_DATA);

	return line;
}

static struct pblk_line *__pblk_line_get_next_data(struct pblk *pblk,
						   struct pblk_line_mgmt *l_mg)
{
	struct pblk_line *line;

	line = pblk_line_get(pblk);
	if (!line) {
		l_mg->data_next = NULL;
		return NULL;
	}

	line->seq_nr = l_mg->d_seq_nr++;
	l_mg->data_next = line;
	l_mg->nr_free_lines--;

	return line;
}

struct pblk_line *pblk_line_get_next_data(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;

	spin_lock(&l_mg->free_lock);
	line = __pblk_line_get_next_data(pblk, l_mg);
	spin_unlock(&l_mg->free_lock);

	return line;
}

struct pblk_line *pblk_line_replace_data(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *cur, *new;
	unsigned int left_seblks;
	int meta_line;

	cur = l_mg->data_line;
	new = l_mg->data_next;
	if (!new)
		return NULL;
	l_mg->data_line = new;

retry_line:
	left_seblks = READ_ONCE(new->left_seblks);
	if (left_seblks) {
		io_schedule();
		goto retry_line;
	}

	spin_lock(&l_mg->free_lock);
#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!bitmap_full(new->erase_bitmap, lm->blk_per_line));
#endif

	l_mg->data_next = __pblk_line_get_next_data(pblk, l_mg);
	if (!l_mg->data_next)
		pr_debug("pblk: using last line\n");

retry_meta:
	meta_line = find_first_zero_bit(&l_mg->meta_bitmap, PBLK_DATA_LINES);
	if (meta_line == PBLK_DATA_LINES) {
		spin_unlock(&l_mg->free_lock);
		schedule();
		spin_lock(&l_mg->free_lock);
		goto retry_meta;
	}

	set_bit(meta_line, &l_mg->meta_bitmap);
	new->smeta = l_mg->sline_meta[meta_line].meta;
	new->emeta = l_mg->eline_meta[meta_line].meta;
	new->meta_line = meta_line;

	memset(new->smeta, 0, lm->smeta_len);
	memset(new->emeta, 0, lm->emeta_len);
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_dec(&pblk->rl, new);

	pblk_line_setup(pblk, new, cur, PBLK_LINETYPE_DATA);

	return new;
}

struct pblk_line *pblk_line_get_first_log(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = NULL;

	spin_lock(&l_mg->free_lock);
	line = pblk_line_get(pblk);
	if (!line) {
		spin_unlock(&l_mg->free_lock);
		return NULL;
	}

	line->seq_nr = l_mg->l_seq_nr++;
	l_mg->log_line = line;
	l_mg->nr_free_lines--;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_dec(&pblk->rl, line);

	pblk_line_setup(pblk, line, NULL, PBLK_LINETYPE_LOG);

	return line;
}

struct pblk_line *pblk_line_replace_log(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *cur_line, *new_line;

	spin_lock(&l_mg->free_lock);
	new_line = pblk_line_get(pblk);
	if (!new_line) {
		spin_unlock(&l_mg->free_lock);
		return NULL;
	}

	new_line->seq_nr = l_mg->d_seq_nr++;
	cur_line = l_mg->log_line;
	l_mg->log_line = new_line;
	l_mg->nr_free_lines--;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_dec(&pblk->rl, new_line);

	pblk_line_setup(pblk, new_line, cur_line, PBLK_LINETYPE_LOG);

	return new_line;
}

void pblk_line_put(struct kref *ref)
{
	struct pblk_line *line = container_of(ref, struct pblk_line, ref);
	struct pblk *pblk = line->pblk;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	spin_lock(&line->lock);
	BUG_ON(line->state != PBLK_LINESTATE_GC);
	line->state = PBLK_LINESTATE_FREE;
	line->gc_group = PBLK_LINEGC_NONE;
	pblk_line_free(pblk, line);
	spin_unlock(&line->lock);

	spin_lock(&l_mg->free_lock);
	list_add_tail(&line->list, &l_mg->free_list);
	l_mg->nr_free_lines++;
	spin_unlock(&l_mg->free_lock);

	pblk_rl_free_lines_inc(&pblk->rl, line);
}

int pblk_alloc_e_rq(struct pblk *pblk, struct nvm_rq *rqd, struct ppa_addr ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int nr_secs = geo->plane_mode;
	int i;

	/* Setup write request */
	rqd->opcode = NVM_OP_ERASE;
	rqd->nr_ppas = nr_secs;
	rqd->flags = pblk_set_progr_mode(pblk, ERASE);
	rqd->bio = NULL;

	if (unlikely(nr_secs == 1)) {
		rqd->ppa_addr = ppa;
		rqd->ppa_addr.g.pl = 0;
		return 0;
	}

	rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_ppa_list);
	if (!rqd->ppa_list)
		return -ENOMEM;

	for (i = 0; i < nr_secs; i++) {
		ppa.g.pl = i;
		rqd->ppa_list[i] = ppa;
	}

	return 0;
}

void pblk_blk_erase_async(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

retry_rqd:
	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd) {
		schedule();
		goto retry_rqd;
	}
	memset(rqd, 0, pblk_r_rq_size);

retry_e_rq:
	if (pblk_alloc_e_rq(pblk, rqd, ppa)) {
		schedule();
		goto retry_e_rq;
	}
	rqd->end_io = pblk_end_io_erase;
	rqd->private = pblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = pblk_submit_io(pblk, rqd);
	if (err) {
		struct nvm_tgt_dev *dev = pblk->dev;
		struct nvm_geo *geo = &dev->geo;

		pr_err("pblk: could not async erase line:%llu,blk:%llu\n",
			pblk_ppa_to_line(ppa), pblk_ppa_to_pos(geo, ppa));
	}
}

static void pblk_blk_erase_sync(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

retry_rqd:
	rqd = mempool_alloc(pblk->r_rq_pool, GFP_KERNEL);
	if (!rqd) {
		schedule();
		goto retry_rqd;
	}
	memset(rqd, 0, pblk_r_rq_size);

retry_e_rq:
	if (pblk_alloc_e_rq(pblk, rqd, ppa)) {
		schedule();
		goto retry_e_rq;
	}
	rqd->end_io = pblk_end_io_sync;
	rqd->private = &wait;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		struct nvm_tgt_dev *dev = pblk->dev;
		struct nvm_geo *geo = &dev->geo;

		pr_err("pblk: could not sync erase line:%llu,blk:%llu\n",
			pblk_ppa_to_line(ppa), pblk_ppa_to_pos(geo, ppa));
		goto out;
	}
	wait_for_completion_io(&wait);

out:
	rqd->private = pblk;
	pblk_end_io_erase(rqd);
}

void pblk_line_erase(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct ppa_addr ppa;
	int bit = -1;

	/* Erase one block at the time and only erase good blocks */
	while ((bit = find_next_zero_bit(line->blk_bitmap, lm->blk_per_line,
					bit + 1)) < lm->blk_per_line) {
		ppa = pblk->luns[bit].bppa; /* set ch and lun */
		ppa.g.blk = line->id;

		pblk_blk_erase_sync(pblk, ppa);
		line->left_eblks--;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(line->left_eblks != 0);
#endif
}

int pblk_line_secs_data(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;

	spin_lock(&l_mg->free_lock);
	line = l_mg->data_line;
	spin_unlock(&l_mg->free_lock);

	return line->left_msecs;
}

struct pblk_line *pblk_line_get_data(struct pblk *pblk)
{
	return pblk->l_mg.data_line;
}

struct pblk_line *pblk_line_get_data_next(struct pblk *pblk)
{
	return pblk->l_mg.data_next;
}

int pblk_line_is_full(struct pblk_line *line)
{
	return (line->left_msecs == 0);
}

void pblk_line_free(struct pblk *pblk, struct pblk_line *line)
{
	if (line->map_bitmap)
		mempool_free(line->map_bitmap, pblk->blk_meta_pool);
	if (line->invalid_bitmap)
		mempool_free(line->invalid_bitmap, pblk->blk_meta_pool);

	line->map_bitmap = NULL;
	line->invalid_bitmap = NULL;
}

void pblk_line_close(struct work_struct *work)
{
	struct pblk_line_ws *line_ws = container_of(work, struct pblk_line_ws,
									ws);
	struct pblk *pblk = line_ws->pblk;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = line_ws->priv;
	struct list_head *move_list;
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)line->emeta + sizeof(crc),
					lm->emeta_len - sizeof(crc));
	line->emeta->crc = cpu_to_le32(crc);

	if (pblk_line_submit_emeta_io(pblk, line, line->cur_sec, WRITE))
		pr_err("pblk: line %d close I/O failed\n", line->id);

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!bitmap_full(line->map_bitmap, line->sec_in_line));
#endif

	spin_lock(&l_mg->free_lock);
	BUG_ON(!test_and_clear_bit(line->meta_line, &l_mg->meta_bitmap));
	spin_unlock(&l_mg->free_lock);

	spin_lock(&line->lock);
	BUG_ON(line->state != PBLK_LINESTATE_OPEN);
	line->state = PBLK_LINESTATE_CLOSED;
	move_list = pblk_line_gc_list(pblk, line);
	BUG_ON(!move_list);
	spin_unlock(&line->lock);

	spin_lock(&l_mg->gc_lock);
	list_add_tail(&line->list, move_list);
	spin_unlock(&l_mg->gc_lock);

	mempool_free(line->map_bitmap, pblk->blk_meta_pool);
	line->map_bitmap = NULL;
	line->smeta = NULL;
	line->emeta = NULL;

	mempool_free(line_ws, pblk->line_ws_pool);
}

void pblk_line_mark_bb(struct work_struct *work)
{
	struct pblk_line_ws *line_ws = container_of(work, struct pblk_line_ws,
									ws);
	struct pblk *pblk = line_ws->pblk;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct ppa_addr *ppa = line_ws->priv;
	int ret;

	ret = nvm_set_tgt_bb_tbl(dev, ppa, 1, NVM_BLK_T_GRWN_BAD);
	if (ret) {
		struct pblk_line *line;
		int pos;

		line = &pblk->lines[pblk_ppa_to_line(*ppa)];
		pos = pblk_ppa_to_pos(&dev->geo, *ppa);

		pr_err("pblk: failed to mark bb, line:%d, pos:%d\n",
				line->id, pos);
	}

	kfree(ppa);
	mempool_free(line_ws, pblk->line_ws_pool);
}

void pblk_line_run_ws(struct pblk *pblk, void *priv,
		      void (*work)(struct work_struct *))
{
	struct pblk_line_ws *line_ws;

	line_ws = mempool_alloc(pblk->line_ws_pool, GFP_ATOMIC);
	if (!line_ws)
		return;

	line_ws->pblk = pblk;
	line_ws->priv = priv;

	INIT_WORK(&line_ws->ws, work);
	queue_work(pblk->kw_wq, &line_ws->ws);
}

int pblk_line_read_smeta(struct pblk *pblk, struct pblk_line *line)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	u64 bpaddr;
	int bit;

	bit = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);
	if (unlikely(bit >= lm->blk_per_line)) {
		pr_err("pblk: corrupted line %d\n", line->id);
		return -EFAULT;
	}

	bpaddr = bit * geo->sec_per_blk;

	return pblk_line_submit_smeta_io(pblk, line, bpaddr, READ);
}

int pblk_line_read_emeta(struct pblk *pblk, struct pblk_line *line)
{
	return pblk_line_submit_emeta_io(pblk, line, line->emeta_ssec, READ);
}

void pblk_down_rq(struct pblk *pblk, struct ppa_addr *ppa_list, int nr_ppas,
		  unsigned long *lun_bitmap)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int lun_id = ppa_list[0].g.ch * geo->luns_per_chnl + ppa_list[0].g.lun;
	int ret;

	/*
	 * Only send one inflight I/O per LUN. Since we map at a page
	 * granurality, all ppas in the I/O will map to the same LUN
	 */
#ifdef CONFIG_NVM_DEBUG
	int i;

	for (i = 1; i < nr_ppas; i++)
		BUG_ON(ppa_list[0].g.lun != ppa_list[i].g.lun ||
				ppa_list[0].g.ch != ppa_list[i].g.ch);
#endif
	/* If the LUN has been locked for this same request, to no attempt to
	 * lock it again
	 */
	if (test_and_set_bit(lun_id, lun_bitmap))
		return;

	rlun = &pblk->luns[lun_id];
	ret = down_timeout(&rlun->wr_sem, msecs_to_jiffies(5000));
	if (ret) {
		switch (ret) {
		case -ETIME:
			pr_err("pblk: lun semaphore timed out\n");
			break;
		case -EINTR:
			pr_err("pblk: lun semaphore timed out\n");
			break;
		}
	}
}

void pblk_up_rq(struct pblk *pblk, struct ppa_addr *ppa_list, int nr_ppas,
		unsigned long *lun_bitmap)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int nr_luns = geo->nr_luns;
	int bit = -1;

	while ((bit = find_next_bit(lun_bitmap, nr_luns, bit + 1)) < nr_luns) {
		rlun = &pblk->luns[bit];
		up(&rlun->wr_sem);
	}

	kfree(lun_bitmap);
}

void pblk_update_map_cache(struct pblk *pblk, sector_t laddr,
			  struct ppa_addr ppa)
{
	struct ppa_addr *l2p_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!nvm_addr_in_cache(ppa));
	BUG_ON(pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	/* logic error: lba out-of-bounds */
	BUG_ON(laddr >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_ppa = &pblk->trans_map[laddr];

	if (!nvm_addr_in_cache(*l2p_ppa) && !ppa_empty(*l2p_ppa))
		pblk_page_invalidate(pblk, *l2p_ppa);

	*l2p_ppa = ppa;
	spin_unlock(&pblk->trans_lock);
}

void pblk_update_map_gc(struct pblk *pblk, sector_t laddr, struct ppa_addr ppa,
		       struct pblk_line *gc_line)
{
	struct ppa_addr *l2p_ppa;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!nvm_addr_in_cache(ppa));
	BUG_ON(pblk_rb_pos_oob(&pblk->rwb, nvm_addr_to_cacheline(ppa)));
#endif

	/* logic error: lba out-of-bounds */
	BUG_ON(laddr >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_ppa = &pblk->trans_map[laddr];

	/* Prevent updated entries to be overwritten by GC */
	if (nvm_addr_in_cache(*l2p_ppa) || ppa_empty(*l2p_ppa) ||
				pblk_ppa_to_line(*l2p_ppa) != gc_line->id)
		goto out;

	*l2p_ppa = ppa;
out:
	spin_unlock(&pblk->trans_lock);
}

void pblk_update_map_dev(struct pblk *pblk, sector_t laddr,
			struct ppa_addr ppa, struct ppa_addr entry_line)
{
	struct ppa_addr *l2p_line;

	/* logic error: lba out-of-bounds */
	BUG_ON(laddr >= pblk->rl.nr_secs);

	spin_lock(&pblk->trans_lock);
	l2p_line = &pblk->trans_map[laddr];

	/* Do not update L2P if the cacheline has been updated. In this case,
	 * the mapped ppa must be einvalidated
	 */
	if (l2p_line->ppa != entry_line.ppa && !ppa_empty(ppa)) {
		pblk_page_invalidate(pblk, ppa);
		goto out;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nvm_addr_in_cache(ppa));
	BUG_ON(!nvm_addr_in_cache(*l2p_line) && !ppa_empty(*l2p_line));
#endif

	*l2p_line = ppa;
out:
	spin_unlock(&pblk->trans_lock);
}

#if 0
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

	nvm_set_tgt_bb_tbl(dev, &ppa, 1, NVM_BLK_T_GRWN_BAD);
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
#endif


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
 * pblk-gc.c - pblk's garbage collector
 */

#include "pblk.h"

static void pblk_free_gc_rqd(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	uint8_t nr_secs = rqd->nr_ppas;

	if (nr_secs > 1)
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(dev->parent, rqd->meta_list,
							rqd->dma_meta_list);

	pblk_free_rqd(pblk, rqd, READ);
}

static void pblk_gc_setup_rq(struct pblk *pblk, struct pblk_block *rblk,
			     u64 *lba_list, unsigned int secs_to_gc, int off,
			     unsigned int *ignored)
{
	u64 lba;
	int i;

	/* Discard invalid addresses for current GC I/O */
	for (i = 0; i < secs_to_gc; i++) {
		lba = lba_list[i + off];

		/* Omit padded entries on GC */
		if (lba == ADDR_EMPTY) {
			(*ignored)++;
			continue;
		}
#ifdef CONFIG_NVM_DEBUG
	BUG_ON(!(lba >= 0 && lba < pblk->rl.nr_secs));
#endif
	}
}

static int pblk_gc_read_victim_blk(struct pblk *pblk, u64 *lba_list,
				   void *data, unsigned int data_len,
				   unsigned int secs_to_gc,
				   unsigned int secs_in_disk, int off)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct request_queue *q = dev->q;
	struct bio *bio;
	struct nvm_rq *rqd;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio = bio_map_kern(q, data, data_len, GFP_KERNEL);
	if (!bio) {
		pr_err("pblk: could not allocate GC bio\n");
		goto fail;
	}

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_sync_bio;

	rqd = pblk_alloc_rqd(pblk, READ);
	if (IS_ERR(rqd)) {
		pr_err("pblk: could not allocate GC request\n");
		goto fail_free_bio;
	}

	ret = pblk_submit_read_gc(pblk, bio, rqd, &lba_list[off],
					secs_to_gc, secs_in_disk,
					PBLK_IOTYPE_SYNC);
	if (ret == NVM_IO_ERR) {
		pr_err("pblk: GC read request failed: (%d)\n", ret);
		goto fail_free_rqd;
	}

	wait_for_completion_io(&wait);
	pblk_free_gc_rqd(pblk, rqd);

	if (bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed_gc, 0);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, bio->bi_error);
#endif
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(secs_to_gc, &pblk->sync_reads);
	atomic_sub(secs_to_gc, &pblk->inflight_reads);
#endif

	bio_put(bio);

	return NVM_IO_OK;

fail_free_rqd:
	pblk_free_gc_rqd(pblk, rqd);
fail_free_bio:
	bio_put(bio);
fail:
	return NVM_IO_ERR;
}

static void pblk_gc_kick(struct pblk *pblk)
{
	queue_work(pblk->krqd_wq, &pblk->ws_gc);
}

static int pblk_gc_write_to_buffer(struct pblk *pblk, u64 *lba_list,
				   void *data, struct pblk_kref_buf *ref_buf,
				   unsigned int data_len,
				   unsigned int secs_to_gc,
				   unsigned int secs_in_disk, int off,
				   struct pblk_block *gc_rblk)
{
	pblk_rl_gc_in(pblk, secs_to_gc);

	pblk_write_gc_to_cache(pblk, data, &lba_list[off], ref_buf,
						secs_to_gc, secs_in_disk,
						PBLK_IOTYPE_REF, gc_rblk);

	spin_lock(&pblk->kick_lock);
	pblk->write_cnt += secs_to_gc;
	if (pblk->write_cnt > PBLK_KICK_SECTS) {
		pblk->write_cnt -= PBLK_KICK_SECTS;
		spin_unlock(&pblk->kick_lock);

		pblk_write_kick(pblk);
	} else
		spin_unlock(&pblk->kick_lock);

	return NVM_IO_OK;
}

int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_block *rblk,
			    u64 *lba_list, unsigned int nr_entries)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_kref_buf *ref_buf;
	void *data;
	unsigned int data_len;
	unsigned int alloc_entries, secs_to_gc, secs_in_disk;
	unsigned int read_left, ignored;
	int max = pblk->max_write_pgs;
	int off;
	int moved = 0;

	if (nr_entries == 0)
		return 0;

	alloc_entries = (nr_entries > max) ? max : nr_entries;
	data = kmalloc(alloc_entries * geo->sec_size, GFP_KERNEL);
	if (!data)
		goto out;

	ref_buf = kmalloc(sizeof(struct pblk_kref_buf), GFP_KERNEL);
	if (!ref_buf)
		goto fail_free_data;

	kref_init(&ref_buf->ref);
	ref_buf->data = data;

	off = 0;
	read_left = nr_entries;
	do {
		secs_to_gc = (read_left > max) ? max : read_left;
		ignored = 0;

		pblk_gc_setup_rq(pblk, rblk, lba_list, secs_to_gc, off,
								&ignored);

		if (ignored == secs_to_gc)
			goto next;

		secs_in_disk = secs_to_gc - ignored;
		data_len = secs_in_disk * geo->sec_size;

		/* Read from GC victim block */
		if (pblk_gc_read_victim_blk(pblk, lba_list, data, data_len,
						secs_to_gc, secs_in_disk, off))
			goto fail_free_krefbuf;

		/* Write to buffer */
		if (pblk_gc_write_to_buffer(pblk, lba_list, data, ref_buf,
						data_len, secs_to_gc,
						secs_in_disk, off, rblk))
			goto fail_free_krefbuf;

next:
		read_left -= secs_to_gc;
		off += secs_to_gc;
		moved += secs_to_gc;
	} while (read_left > 0);

	kref_put(&ref_buf->ref, pblk_free_ref_mem);

	return moved;

fail_free_krefbuf:
	kfree(ref_buf);
fail_free_data:
	kfree(data);
out:
	return moved;
}

void pblk_gc_queue(struct work_struct *work)
{
	struct pblk_block_ws *blk_ws = container_of(work, struct pblk_block_ws,
									ws_blk);
	struct pblk *pblk = blk_ws->pblk;
	struct pblk_block *rblk = blk_ws->rblk;
	struct pblk_lun *rlun = rblk->rlun;

	spin_lock(&rlun->lock);
	list_move_tail(&rblk->list, &rlun->closed_list);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

#ifdef CONFIG_NVM_DEBUG
	atomic_sub(PBLK_RECOVERY_SECTORS, &pblk->inflight_meta);
	atomic_add(PBLK_RECOVERY_SECTORS, &pblk->compl_meta);
#endif

	mempool_free(blk_ws, pblk->blk_ws_pool);
	pr_debug("nvm: block '%d' is full, allow GC (sched)\n",
							rblk->id);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list
 */
static struct pblk_block *rblock_max_invalid(struct pblk_block *ra,
					     struct pblk_block *rb)
{
	if (ra->nr_invalid_secs == rb->nr_invalid_secs)
		return ra;

	return (ra->nr_invalid_secs < rb->nr_invalid_secs) ? rb : ra;
}

/* linearly find the block with highest number of invalid pages
 * requires lun->lock
 */
static struct pblk_block *block_prio_find_max(struct pblk_lun *rlun)
{
	struct list_head *prio_list = &rlun->prio_list;
	struct pblk_block *rblk, *max;

	/* logic error */
	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct pblk_block, prio);
	list_for_each_entry(rblk, prio_list, prio)
		max = rblock_max_invalid(max, rblk);

	return max;
}

static void pblk_block_gc(struct work_struct *work)
{
	struct pblk_block_ws *blk_ws = container_of(work, struct pblk_block_ws,
									ws_blk);
	struct pblk *pblk = blk_ws->pblk;
	struct pblk_block *rblk = blk_ws->rblk;
	struct pblk_lun *rlun = rblk->rlun;
	unsigned int page_size = pblk_recov_page_size(pblk);
	void *recov_page;
	u64 *lba_list;
	u64 gc_lba_list[PBLK_MAX_REQ_ADDRS];
	unsigned long *invalid_bitmap;
	int moved, total_moved = 0;
	int nr_invalid_secs;
	int nr_valid_secs;
	int bit;
	int nr_ppas;

	invalid_bitmap = kmalloc(BITS_TO_LONGS(pblk->nr_blk_dsecs) *
				sizeof(unsigned long), GFP_KERNEL);
	if (!invalid_bitmap)
		return;

	spin_lock(&rblk->lock);
	nr_invalid_secs = rblk->nr_invalid_secs;
	nr_valid_secs = pblk->nr_blk_dsecs - rblk->nr_invalid_secs;
	bitmap_copy(invalid_bitmap, rblk->invalid_bitmap, pblk->nr_blk_dsecs);
	spin_unlock(&rblk->lock);

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_valid_secs !=
	pblk->nr_blk_dsecs - bitmap_weight(invalid_bitmap, pblk->nr_blk_dsecs));
#endif

	mempool_free(blk_ws, pblk->blk_ws_pool);
	pr_debug("pblk: block '%d' being reclaimed\n", rblk->id);

	recov_page = kzalloc(page_size, GFP_KERNEL);
	if (!recov_page)
		goto put_back;

	if (pblk_recov_read(pblk, rblk, recov_page)) {
		pr_err("pblk: could not recover last page. Blk:%d\n",
						rblk->id);
		goto free_recov_page;
	}

	lba_list = pblk_recov_get_lba_list(pblk, recov_page);
	if (!lba_list) {
		pr_err("pblk: Could not interpret recover page. Blk:%d\n",
							rblk->id);
		goto free_recov_page;
	}

	bit = -1;
next_lba_list:
	nr_ppas = 0;
	do {
		bit = find_next_zero_bit(invalid_bitmap,
						pblk->nr_blk_dsecs, bit + 1);
		gc_lba_list[nr_ppas] = lba_list[bit];

		if (bit >= pblk->nr_blk_dsecs)
			goto prepare_ppas;

		nr_ppas++;
	} while (nr_ppas < PBLK_MAX_REQ_ADDRS);

prepare_ppas:
	moved = pblk_gc_move_valid_secs(pblk, rblk, gc_lba_list, nr_ppas);
	if (moved != nr_ppas) {
		pr_err("pblk: could not GC all sectors:blk:%d, GC:%d/%d/%d\n",
						rblk->id,
						moved, nr_ppas,
						nr_valid_secs);
		goto put_back;
	}

	total_moved += moved;
	if (total_moved < nr_valid_secs)
		goto next_lba_list;

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(pblk->nr_blk_dsecs -
		bitmap_weight(invalid_bitmap, pblk->nr_blk_dsecs) !=
		total_moved);
#endif

	/* Block are erased before being returned to the media manager */
	pblk_erase_blk(pblk, rblk);
	pblk_put_blk(pblk, rblk);

	kfree(invalid_bitmap);
	kfree(recov_page);
	return;

free_recov_page:
	kfree(recov_page);
put_back:
	spin_lock(&rlun->lock);
	list_add_tail(&rblk->prio, &rlun->prio_list);
	spin_unlock(&rlun->lock);

	kfree(invalid_bitmap);
}

static void pblk_lun_gc(struct pblk *pblk, struct pblk_lun *rlun)
{
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_block_ws *blk_ws;
	struct pblk_block *rblk, *trblk;
	unsigned int nr_free_blocks, nr_blocks_need;
	int run_gc;
	LIST_HEAD(gc_list);

	nr_blocks_need = pblk_rl_gc_thrs(pblk);

	if (nr_blocks_need < pblk->nr_luns)
		nr_blocks_need = pblk->nr_luns;

	spin_lock(&rlun->lock);
	nr_free_blocks = rlun->nr_free_blocks;

	run_gc = (nr_blocks_need > nr_free_blocks || gc->gc_forced);
	while (run_gc && !list_empty(&rlun->prio_list)) {
		rblk = block_prio_find_max(rlun);
		if (!rblk->nr_invalid_secs)
			goto start_gc;

		nr_free_blocks++;
		list_move_tail(&rblk->prio, &gc_list);

		run_gc = (nr_blocks_need > nr_free_blocks || gc->gc_forced);
	}

start_gc:
	spin_unlock(&rlun->lock);

	list_for_each_entry_safe(rblk, trblk, &gc_list, prio) {
		blk_ws = mempool_alloc(pblk->blk_ws_pool, GFP_ATOMIC);
		if (!blk_ws)
			break;

		list_del_init(&rblk->prio);

		/* logic error */
		BUG_ON(!block_is_full(pblk, rblk));

		blk_ws->pblk = pblk;
		blk_ws->rblk = rblk;

		INIT_WORK(&blk_ws->ws_blk, pblk_block_gc);
		queue_work(pblk->kgc_wq, &blk_ws->ws_blk);

		nr_blocks_need--;
	}

	if (unlikely(!list_empty(&rlun->g_bb_list)))
		pblk_recov_clean_g_bb_list(pblk, rlun);
}

void pblk_gc(struct work_struct *work)
{
	struct pblk *pblk = container_of(work, struct pblk, ws_gc);
	struct pblk_lun *rlun;
	int i;

	pblk_for_each_lun(pblk, rlun, i)
		pblk_lun_gc(pblk, rlun);
}

/*
 * timed GC every interval.
 */
static void pblk_gc_timer(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	pblk_gc_kick(pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));
}

static void pblk_gc_start(struct pblk *pblk)
{
	setup_timer(&pblk->gc_timer, pblk_gc_timer, (unsigned long)pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(5000));

	pblk->gc.gc_active = 1;

	pr_debug("pblk: gc running\n");
}

/*
 * If flush_wq == 1 then no lock should be held by the caller since
 * flush_workqueue can sleep
 */
static void pblk_gc_stop(struct pblk *pblk, int flush_wq)
{
	del_timer(&pblk->gc_timer);

	if (flush_wq)
		flush_workqueue(pblk->kgc_wq);

	spin_lock(&pblk->gc.lock);
	pblk->gc.gc_active = 0;
	spin_unlock(&pblk->gc.lock);

	pr_debug("pblk: gc paused\n");
}

int pblk_gc_status(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;
	int ret;

	spin_lock(&gc->lock);
	ret = gc->gc_active;
	spin_unlock(&gc->lock);

	return ret;
}

static void __pblk_gc_should_start(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&gc->lock);
#endif

	if (gc->gc_enabled && !gc->gc_active)
		pblk_gc_start(pblk);
}

void pblk_gc_should_start(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

	spin_lock(&gc->lock);
	__pblk_gc_should_start(pblk);
	spin_unlock(&gc->lock);
}

void pblk_gc_should_stop(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

	if (gc->gc_active && !gc->gc_forced)
		pblk_gc_stop(pblk, 0);
}

int pblk_gc_init(struct pblk *pblk)
{
	pblk->krqd_wq = alloc_workqueue("pblk-lun", WQ_MEM_RECLAIM | WQ_UNBOUND,
								pblk->nr_luns);
	if (!pblk->krqd_wq)
		return -ENOMEM;

	pblk->kgc_wq = alloc_workqueue("pblk-bg", WQ_MEM_RECLAIM, 1);
	if (!pblk->kgc_wq)
		goto fail_destrow_krqd_qw;

	pblk->gc.gc_active = 0;
	pblk->gc.gc_forced = 0;
	pblk->gc.gc_enabled = 1;

	spin_lock_init(&pblk->gc.lock);

	return 0;

fail_destrow_krqd_qw:
	destroy_workqueue(pblk->krqd_wq);
	return -ENOMEM;
}

void pblk_gc_exit(struct pblk *pblk)
{
	pblk_gc_stop(pblk, 1);

	if (pblk->krqd_wq)
		destroy_workqueue(pblk->krqd_wq);

	if (pblk->kgc_wq)
		destroy_workqueue(pblk->kgc_wq);
}

void pblk_gc_sysfs_state_show(struct pblk *pblk, int *gc_enabled,
			      int *gc_active)
{
	struct pblk_gc *gc = &pblk->gc;

	spin_lock(&gc->lock);
	*gc_enabled = gc->gc_enabled;
	*gc_active = gc->gc_active;
	spin_unlock(&gc->lock);
}

int pblk_gc_sysfs_force(struct pblk *pblk, int value)
{
	struct pblk_gc *gc = &pblk->gc;
	int rsv = 0;

	if (value != 0 && value != 1)
		return -EINVAL;

	spin_lock(&gc->lock);
	if (value == 1) {
		gc->gc_enabled = 1;
		rsv = 64;
	}
	pblk_rl_set_gc_rsc(pblk, rsv);
	gc->gc_forced = value;
	__pblk_gc_should_start(pblk);
	spin_unlock(&gc->lock);

	return 0;
}

int pblk_gc_sysfs_enable(struct pblk *pblk, int value)
{
	struct pblk_gc *gc = &pblk->gc;
	int ret = 0;

	if (value == 0) {
		spin_lock(&gc->lock);
		gc->gc_enabled = value;
		spin_unlock(&gc->lock);
		if (gc->gc_active)
			pblk_gc_stop(pblk, 0);
	} else if (value == 1) {
		spin_lock(&gc->lock);
		gc->gc_enabled = value;
		if (!gc->gc_active)
			pblk_gc_start(pblk);
		spin_unlock(&gc->lock);
	} else {
		ret = -EINVAL;
	}

	return ret;
}


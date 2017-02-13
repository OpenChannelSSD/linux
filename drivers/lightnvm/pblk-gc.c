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
 * pblk-gc.c - pblk's garbage collector
 */

#include "pblk.h"
#include <linux/delay.h>

static void pblk_gc_free_gc_rq(struct pblk_gc_rq *gc_rq)
{
	kfree(gc_rq->data);
	kfree(gc_rq->lba_list);
	kfree(gc_rq);
}

static int pblk_gc_write(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_gc_rq *gc_rq, *tgc_rq;
	LIST_HEAD(w_list);

	spin_lock(&gc->w_lock);
	if (list_empty(&gc->w_list)) {
		spin_unlock(&gc->w_lock);
		return 1;
	}

	list_for_each_entry_safe(gc_rq, tgc_rq, &gc->w_list, list) {
		list_move_tail(&gc_rq->list, &w_list);
		gc->w_entries--;
	}
	spin_unlock(&gc->w_lock);

	list_for_each_entry_safe(gc_rq, tgc_rq, &w_list, list) {
		pblk_write_gc_to_cache(pblk, gc_rq->data, gc_rq->lba_list,
				gc_rq->nr_secs, gc_rq->secs_to_gc,
				gc_rq->line, PBLK_IOTYPE_GC);

		kref_put(&gc_rq->line->ref, pblk_line_put);

		list_del(&gc_rq->list);
		pblk_gc_free_gc_rq(gc_rq);
	}

	return 0;
}

static void pblk_gc_writer_kick(struct pblk_gc *gc)
{
	wake_up_process(gc->gc_writer_ts);
}

/*
 * Responsible for managing all memory related to a gc request. Also in case of
 * failure
 */
static int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_line *line,
				   u64 *lba_list, unsigned int nr_secs)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_gc_rq *gc_rq;
	void *data;
	unsigned int secs_to_gc;
	int ret = NVM_IO_OK;

	data = kmalloc(nr_secs * geo->sec_size, GFP_KERNEL);
	if (!data) {
		ret = NVM_IO_ERR;
		goto free_lba_list;
	}

	/* Read from GC victim block */
	if (pblk_submit_read_gc(pblk, lba_list, data, nr_secs,
							&secs_to_gc, line)) {
		ret = NVM_IO_ERR;
		goto free_data;
	}

	if (!secs_to_gc)
		goto free_data;

	gc_rq = kmalloc(sizeof(struct pblk_gc_rq), GFP_KERNEL);
	if (!gc_rq) {
		ret = NVM_IO_ERR;
		goto free_data;
	}

	gc_rq->line = line;
	gc_rq->data = data;
	gc_rq->lba_list = lba_list;
	gc_rq->nr_secs = nr_secs;
	gc_rq->secs_to_gc = secs_to_gc;

	kref_get(&line->ref);

retry:
	spin_lock(&gc->w_lock);
	if (gc->w_entries > 256) {
		spin_unlock(&gc->w_lock);
		usleep_range(256, 1024);
		goto retry;
	}
	gc->w_entries++;
	list_add_tail(&gc_rq->list, &gc->w_list);
	spin_unlock(&gc->w_lock);

	pblk_gc_writer_kick(&pblk->gc);

	return NVM_IO_OK;

free_data:
	kfree(data);
free_lba_list:
	kfree(lba_list);

	return ret;
}

static void pblk_put_line_back(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list;

	spin_lock(&line->lock);
	WARN_ON(line->state != PBLK_LINESTATE_GC);
	line->state = PBLK_LINESTATE_CLOSED;
	move_list = pblk_line_gc_list(pblk, line);
	spin_unlock(&line->lock);

	if (move_list) {
		spin_lock(&l_mg->gc_lock);
		list_add_tail(&line->list, move_list);
		spin_unlock(&l_mg->gc_lock);
	}
}

static void pblk_gc_line_ws(struct work_struct *work)
{
	struct pblk_line_ws *line_ws = container_of(work, struct pblk_line_ws,
									ws);
	struct pblk *pblk = line_ws->pblk;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = line_ws->line;
	struct pblk_line_meta *lm = &pblk->lm;
	__le64 *lba_list = line_ws->priv;
	u64 *gc_list;
	int sec_left;
	int nr_ppas, bit;
	int put_line = 1;

	pr_debug("pblk: line '%d' being reclaimed for GC\n", line->id);

	spin_lock(&line->lock);
	sec_left = line->vsc;
	if (!sec_left) {
		/* Lines are erased before being used (l_mg->data_/log_next) */
		spin_unlock(&line->lock);
		goto out;
	}
	spin_unlock(&line->lock);

	if (sec_left < 0) {
		pr_err("pblk: corrupted GC line (%d)\n", line->id);
		put_line = 0;
		pblk_put_line_back(pblk, line);
		goto out;
	}

	bit = -1;
next_rq:
	gc_list = kmalloc_array(pblk->max_write_pgs, sizeof(u64), GFP_KERNEL);
	if (!gc_list) {
		put_line = 0;
		pblk_put_line_back(pblk, line);
		goto out;
	}

	nr_ppas = 0;
	do {
		bit = find_next_zero_bit(line->invalid_bitmap, lm->sec_per_line,
								bit + 1);
		if (bit > line->emeta_ssec)
			break;

		gc_list[nr_ppas++] = le64_to_cpu(lba_list[bit]);
	} while (nr_ppas < pblk->max_write_pgs);

	if (unlikely(!nr_ppas)) {
		kfree(gc_list);
		goto out;
	}

	if (pblk_gc_move_valid_secs(pblk, line, gc_list, nr_ppas)) {
		pr_err("pblk: could not GC all sectors: line:%d (%d/%d/%d)\n",
						line->id, line->vsc,
						nr_ppas, nr_ppas);
		put_line = 0;
		pblk_put_line_back(pblk, line);
		goto out;
	}

	sec_left -= nr_ppas;
	if (sec_left > 0)
		goto next_rq;

out:
	pblk_mfree(line->emeta, l_mg->emeta_alloc_type);
	mempool_free(line_ws, pblk->line_ws_pool);
	atomic_dec(&pblk->gc.inflight_gc);
	if (put_line)
		kref_put(&line->ref, pblk_line_put);
}

static int pblk_gc_line(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_ws *line_ws;
	__le64 *lba_list;
	int ret;

	line_ws = mempool_alloc(pblk->line_ws_pool, GFP_KERNEL);
	line->emeta = pblk_malloc(lm->emeta_len, l_mg->emeta_alloc_type,
								GFP_KERNEL);
	if (!line->emeta) {
		pr_err("pblk: cannot use GC emeta\n");
		goto fail_free_ws;
	}

	ret = pblk_line_read_emeta(pblk, line);
	if (ret) {
		pr_err("pblk: line %d read emeta failed (%d)\n", line->id, ret);
		goto fail_free_emeta;
	}

	/* If this read fails, it means that emeta is corrupted. For now, leave
	 * the line untouched. TODO: Implement a recovery routine that scans and
	 * moves all sectors on the line.
	 */
	lba_list = pblk_recov_get_lba_list(pblk, line->emeta);
	if (!lba_list) {
		pr_err("pblk: could not interpret emeta (line %d)\n", line->id);
		goto fail_free_emeta;
	}

	line_ws->pblk = pblk;
	line_ws->line = line;
	line_ws->priv = lba_list;

	INIT_WORK(&line_ws->ws, pblk_gc_line_ws);
	queue_work(pblk->gc.gc_reader_wq, &line_ws->ws);

	return 0;

fail_free_emeta:
	pblk_mfree(line->emeta, l_mg->emeta_alloc_type);
fail_free_ws:
	mempool_free(line_ws, pblk->line_ws_pool);
	pblk_put_line_back(pblk, line);

	return 1;
}

static void pblk_gc_lines(struct pblk *pblk, struct list_head *gc_list)
{
	struct pblk_line *line, *tline;

	list_for_each_entry_safe(line, tline, gc_list, list) {
		if (pblk_gc_line(pblk, line))
			pr_err("pblk: failed to GC line %d\n", line->id);
		list_del(&line->list);
	}
}

/*
 * Lines with no valid sectors will be returned to the free list immediately. If
 * GC is activated - either because the free block count is under the determined
 * threshold, or because it is being forced from user space - only lines with a
 * high count of invalid sectors will be recycled.
 */
static void pblk_gc_run(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_line *line, *tline;
	unsigned int nr_blocks_free, nr_blocks_need;
	struct list_head *group_list;
	int run_gc, gc_group = 0;
	int prev_gc = 0;
	int inflight_gc = atomic_read(&gc->inflight_gc);
	LIST_HEAD(gc_list);

	spin_lock(&l_mg->gc_lock);
	list_for_each_entry_safe(line, tline, &l_mg->gc_full_list, list) {
		spin_lock(&line->lock);
		WARN_ON(line->state != PBLK_LINESTATE_CLOSED);
		line->state = PBLK_LINESTATE_GC;
		spin_unlock(&line->lock);

		list_del(&line->list);
		kref_put(&line->ref, pblk_line_put);
	}
	spin_unlock(&l_mg->gc_lock);

	nr_blocks_need = pblk_rl_gc_thrs(&pblk->rl);
	nr_blocks_free = pblk_rl_nr_free_blks(&pblk->rl);
	run_gc = (nr_blocks_need > nr_blocks_free || gc->gc_forced);

next_gc_group:
	group_list = l_mg->gc_lists[gc_group++];
	spin_lock(&l_mg->gc_lock);
	while (run_gc && !list_empty(group_list)) {
		/* No need to queue up more GC lines than we can handle */
		if (!run_gc || inflight_gc > gc->gc_jobs_active) {
			spin_unlock(&l_mg->gc_lock);
			pblk_gc_lines(pblk, &gc_list);
			return;
		}

		line = list_first_entry(group_list, struct pblk_line, list);
		nr_blocks_free += atomic_read(&line->blk_in_line);

		spin_lock(&line->lock);
		WARN_ON(line->state != PBLK_LINESTATE_CLOSED);
		line->state = PBLK_LINESTATE_GC;
		list_move_tail(&line->list, &gc_list);
		atomic_inc(&gc->inflight_gc);
		inflight_gc++;
		spin_unlock(&line->lock);

		prev_gc = 1;
		run_gc = (nr_blocks_need > nr_blocks_free || gc->gc_forced);
	}
	spin_unlock(&l_mg->gc_lock);

	pblk_gc_lines(pblk, &gc_list);

	if (!prev_gc && pblk->rl.rb_state > gc_group &&
						gc_group < PBLK_NR_GC_LISTS)
		goto next_gc_group;
}


static void pblk_gc_kick(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

	wake_up_process(gc->gc_ts);
	pblk_gc_writer_kick(gc);
	mod_timer(&gc->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));
}

static void pblk_gc_timer(unsigned long data)
{
	struct pblk *pblk = (struct pblk *)data;

	pblk_gc_kick(pblk);
}

static int pblk_gc_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		pblk_gc_run(pblk);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

static int pblk_gc_writer_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		if (!pblk_gc_write(pblk))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

static void pblk_gc_start(struct pblk *pblk)
{
	pblk->gc.gc_active = 1;

	pr_debug("pblk: gc start\n");
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

	lockdep_assert_held(&gc->lock);

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

/*
 * If flush_wq == 1 then no lock should be held by the caller since
 * flush_workqueue can sleep
 */
static void pblk_gc_stop(struct pblk *pblk, int flush_wq)
{
	spin_lock(&pblk->gc.lock);
	pblk->gc.gc_active = 0;
	spin_unlock(&pblk->gc.lock);

	pr_debug("pblk: gc stop\n");
}

void pblk_gc_should_stop(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

	if (gc->gc_active && !gc->gc_forced)
		pblk_gc_stop(pblk, 0);
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

void pblk_gc_sysfs_force(struct pblk *pblk, int force)
{
	struct pblk_gc *gc = &pblk->gc;
	int rsv = 0;

	spin_lock(&gc->lock);
	if (force) {
		gc->gc_enabled = 1;
		rsv = 64;
	}
	pblk_rl_set_gc_rsc(&pblk->rl, rsv);
	gc->gc_forced = force;
	__pblk_gc_should_start(pblk);
	spin_unlock(&gc->lock);
}

static void pblk_gc_log_page_sector(struct pblk *pblk,
				    struct nvm_log_page log_page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct bio *bio;
	struct pblk_sec_meta *meta_list;
	struct pblk_line *line;
	struct nvm_rq rqd;
	dma_addr_t dma_meta_list;
	void *data;
	u64 lba;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
	if (!meta_list)
		return;

	data = kcalloc(pblk->max_write_pgs, geo->sec_size, GFP_KERNEL);
	if (!data)
		goto free_meta_list;

	bio = bio_map_kern(dev->q, data, geo->sec_size, GFP_KERNEL);
	if (IS_ERR(bio))
		goto out;

	memset(&rqd, 0, sizeof(struct nvm_rq));

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	rqd.bio = bio;
	rqd.opcode = NVM_OP_PREAD;
	rqd.flags = pblk_set_read_mode(pblk);
	rqd.meta_list = meta_list;
	rqd.nr_ppas = 1;
	rqd.ppa_addr = log_page.ppa;
	rqd.dma_meta_list = dma_meta_list;
	rqd.end_io = NULL;

	ret = pblk_submit_io(pblk, &rqd);
	if (ret) {
		pr_err("pblk: recovery I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto out;
	}
	wait_for_completion_io(&wait);
	bio_put(bio);

	if (rqd.error) {
		pr_err("pblk: page log read error: %d\n", rqd.error);
		goto out;
	}

	lba = meta_list[0].lba;
	if (lba > pblk->rl.nr_secs) {
		pr_err("pblk: corrupted P2L map - LBA:%llu", lba);
#ifdef CONFIG_NVM_DEBUG
		print_ppa(&log_page.ppa, "BAD PPA", 0);
#endif
		goto out;
	}

	line = &pblk->lines[pblk_dev_ppa_to_line(log_page.ppa)];

	/* L2P is updated as a normal GC write */
	if (pblk_write_gc_to_cache(pblk, data, &lba, 1, 1, line,
							PBLK_IOTYPE_GC)) {
		pr_err("pblk: could not recover log page\n");
#ifdef CONFIG_NVM_DEBUG
		print_ppa(&log_page.ppa, "UNREC. LOGPAGE", log_page.scope);
#endif
	}

#ifdef CONFIG_PBLK_AER_DEBUG
	printk(KERN_CRIT "sector (ppa %llx) put in cache\n", log_page.ppa.ppa);
#endif

out:
	kfree(data);
free_meta_list:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);
}

static void pblk_gc_log_page_block(struct pblk *pblk,
				   struct nvm_log_page log_page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr bppa = log_page.ppa;
	struct bio *bio;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct pblk_line *line;
	struct nvm_rq rqd;
	struct ppa_addr ppa;
	void *data;
	dma_addr_t dma_meta_list;
	dma_addr_t dma_ppa_list;
	u64 *lba_list;
	int i, j, k, recov_pgs = 0;
	int rq_ppas, rq_len;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_ppa_list);
	if (!ppa_list)
		return;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
	if (!meta_list)
		goto free_ppa_list;

	lba_list = kcalloc(pblk->max_write_pgs, sizeof(u64), GFP_KERNEL);
	if (!lba_list)
		goto free_meta_list;

	data = kcalloc(pblk->max_write_pgs, geo->sec_size, GFP_KERNEL);
	if (!data)
		goto free_lba_list;

next_rq:
	memset(&rqd, 0, sizeof(struct nvm_rq));

	rq_ppas = pblk->max_write_pgs;
	rq_len = rq_ppas * geo->sec_size;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		goto free_data;

	bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_private = &wait;
	bio->bi_end_io = pblk_end_bio_sync;

	rqd.bio = bio;
	rqd.opcode = NVM_OP_PREAD;
	rqd.flags = pblk_set_progr_mode(pblk, READ);
	rqd.flags |= NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
	rqd.nr_ppas = rq_ppas;
	rqd.meta_list = meta_list;
	rqd.ppa_list = ppa_list;
	rqd.dma_ppa_list = dma_ppa_list;
	rqd.dma_meta_list = dma_meta_list;
	rqd.end_io = NULL;

	for (i = 0; i < rqd.nr_ppas; ) {
		ppa = bppa;
		ppa.g.pg = recov_pgs++;

		for (j = 0; j < geo->nr_planes; j++) {
			ppa.g.pl = j;

			for (k = 0; k < geo->sec_per_pg; k++) {
				ppa.g.sec = k;
				rqd.ppa_list[i++] = ppa;
			}
		}
	}

	ret = pblk_submit_io(pblk, &rqd);
	if (ret) {
		pr_err("pblk: recovery I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_data;
	}
	wait_for_completion_io(&wait);

	if (rqd.error) {
		pr_err("pblk: page log read error: %d\n", rqd.error);
		goto out;
	}

	for (i = 0; i < rqd.nr_ppas; i++) {
		u64 lba = lba_list[i] = meta_list[i].lba;

		if (lba > pblk->rl.nr_secs) {
			pr_err("pblk: corrupted P2L map - LBA:%llu", lba);
#ifdef CONFIG_NVM_DEBUG
			print_ppa(&log_page.ppa, "BAD PPA", 0);
#endif
			goto out;
		}
	}

	line = &pblk->lines[pblk_dev_ppa_to_line(log_page.ppa)];

	/* L2P updates since the event are handled by the write buffer */
	if (pblk_write_gc_to_cache(pblk, data, lba_list, rqd.nr_ppas,
					rqd.nr_ppas, line, PBLK_IOTYPE_GC)) {
		pr_err("pblk: could not recover log page\n");
#ifdef CONFIG_NVM_DEBUG
		print_ppa(&log_page.ppa, "UNREC. LOGPAGE", log_page.scope);
#endif
	}

out:
	bio_put(bio);
	if (recov_pgs < geo->pgs_per_blk)
		goto next_rq;

#ifdef CONFIG_PBLK_AER_DEBUG
	printk(KERN_CRIT "block (ppa %llx) put in cache\n", log_page.ppa.ppa);
#endif

free_data:
	kfree(data);
free_lba_list:
	kfree(lba_list);
free_meta_list:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);
free_ppa_list:
	nvm_dev_dma_free(dev->parent, ppa_list, dma_ppa_list);
}

/* If a LUN fails, reads will not succeed. Another form for redundancy is
 * necessary to cover this case.
 */
static void pblk_gc_log_page_lun(struct pblk *pblk,
				 struct nvm_log_page log_page)
{
	pr_err("pblk: unrecoverable LUN failure: ch:%d, lun:%d\n",
					log_page.ppa.g.ch,
					log_page.ppa.g.lun);
}

void pblk_gc_log_page(struct pblk *pblk, struct nvm_log_page log_page)
{
	if (log_page.scope & NVM_LOGPAGE_SCOPE_SECTOR)
		pblk_gc_log_page_sector(pblk, log_page);
	else if (log_page.scope & NVM_LOGPAGE_SCOPE_CHUNK)
		pblk_gc_log_page_block(pblk, log_page);
	else if (log_page.scope & NVM_LOGPAGE_SCOPE_LUN)
		pblk_gc_log_page_lun(pblk, log_page);
	else
		pr_err("pblk: unknown log page error (0x%x\n)", log_page.scope);
}

int pblk_gc_init(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;
	int ret;

	gc->gc_ts = kthread_create(pblk_gc_ts, pblk, "pblk-gc-ts");
	if (IS_ERR(gc->gc_ts)) {
		pr_err("pblk: could not allocate GC main kthread\n");
		return PTR_ERR(gc->gc_ts);
	}

	gc->gc_writer_ts = kthread_create(pblk_gc_writer_ts, pblk,
							"pblk-gc-writer-ts");
	if (IS_ERR(gc->gc_writer_ts)) {
		pr_err("pblk: could not allocate GC writer kthread\n");
		ret = PTR_ERR(gc->gc_writer_ts);
		goto fail_free_main_kthread;
	}

	setup_timer(&gc->gc_timer, pblk_gc_timer, (unsigned long)pblk);
	mod_timer(&gc->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));

	gc->gc_active = 0;
	gc->gc_forced = 0;
	gc->gc_enabled = 1;
	gc->gc_jobs_active = 8;
	gc->w_entries = 0;
	atomic_set(&gc->inflight_gc, 0);

	gc->gc_reader_wq = alloc_workqueue("pblk-gc-reader-wq",
			WQ_MEM_RECLAIM | WQ_UNBOUND, gc->gc_jobs_active);
	if (!gc->gc_reader_wq) {
		pr_err("pblk: could not allocate GC reader workqueue\n");
		ret = -ENOMEM;
		goto fail_free_writer_kthread;
	}

	spin_lock_init(&gc->lock);
	spin_lock_init(&gc->w_lock);
	INIT_LIST_HEAD(&gc->w_list);

	return 0;

fail_free_writer_kthread:
	kthread_stop(gc->gc_writer_ts);
fail_free_main_kthread:
	kthread_stop(gc->gc_ts);

	return ret;
}

void pblk_gc_exit(struct pblk *pblk)
{
	struct pblk_gc *gc = &pblk->gc;

	flush_workqueue(gc->gc_reader_wq);

	del_timer(&gc->gc_timer);
	pblk_gc_stop(pblk, 1);

	if (gc->gc_ts)
		kthread_stop(gc->gc_ts);

	if (pblk->gc.gc_reader_wq)
		destroy_workqueue(pblk->gc.gc_reader_wq);

	if (gc->gc_writer_ts)
		kthread_stop(gc->gc_writer_ts);
}

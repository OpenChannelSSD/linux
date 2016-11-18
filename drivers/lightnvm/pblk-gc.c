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

static int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_line *line,
				   u64 *lba_list, unsigned int secs_to_move)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	void *data;
	unsigned int alloc_entries, nr_secs, secs_to_gc;
	unsigned int secs_left = secs_to_move;
	int off = 0, max = pblk->max_write_pgs;

	if (!secs_to_move)
		return 0;

	alloc_entries = (secs_to_move > max) ? max : secs_to_move;

	data = kmalloc(alloc_entries * geo->sec_size, GFP_KERNEL);
	if (!data)
		goto out;

	do {
		nr_secs = (secs_left > max) ? max : secs_left;

		/* Read from GC victim block */
		if (pblk_submit_read_gc(pblk, &lba_list[off], data, nr_secs,
							&secs_to_gc, line))
			goto fail_free_data;

		if (!secs_to_gc)
			goto next;

		/* Write to buffer */
		if (pblk_write_gc_to_cache(pblk, data, &lba_list[off],
				nr_secs, secs_to_gc, line, PBLK_IOTYPE_GC))
			goto fail_free_data;

next:
		secs_left -= nr_secs;
		off += nr_secs;
	} while (secs_left > 0);

fail_free_data:
	kfree(data);
out:
	return off;
}

static void pblk_put_line_back(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct list_head *move_list = NULL;

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
	struct pblk_line *line = line_ws->priv;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_meta *lm = &pblk->lm;
	struct line_emeta *emeta;
	int sec_moved, sec_left;
	u64 *gc_lba_list, *lba_list;
	int nr_ppas, bit, ret;

	pr_debug("pblk: line '%d' being reclaimed for GC\n", line->id);

	spin_lock(&line->lock);
	sec_left = line->vsc;
	if (!sec_left) {
		/* Lines are erased before being used (l_mg->data_/log_next) */
		spin_unlock(&line->lock);
		kref_put(&line->ref, pblk_line_put);
		goto out;
	}
	spin_unlock(&line->lock);

	/* logic error */
	BUG_ON(sec_left < 0);

	gc_lba_list = kmalloc(pblk->max_write_pgs * sizeof(u64), GFP_KERNEL);
	if (!gc_lba_list)
		goto out;

	emeta = l_mg->gc_meta.meta;
	if (!emeta) {
		pr_err("pblk: cannot use GC emeta\n");
		goto free_lba_list;
	}

	line->emeta = emeta;
	ret = pblk_line_read_emeta(pblk, line);
	if (ret) {
		pr_err("pblk: line %d read emeta failed (%d)\n", line->id, ret);
		goto free_emeta;
	}

	/* If this read fails, it means that emeta is corrupted. For now, leave
	 * the line untouched. TODO: Implement a recovery routine that scans and
	 * moves all sectors on the line.
	 */
	lba_list = pblk_recov_get_lba_list(pblk, emeta);
	if (!lba_list) {
		pr_err("pblk: could not interpret emeta (line %d)\n", line->id);
		goto put_line;
	}

	bit = -1;
next_rq:
	nr_ppas = 0;
	do {
		bit = find_next_zero_bit(line->invalid_bitmap, lm->sec_per_line,
								bit + 1);
		if (bit > line->emeta_ssec)
			goto prepare_rq;

		gc_lba_list[nr_ppas] = lba_list[bit];
		nr_ppas++;
	} while (nr_ppas < pblk->max_write_pgs);

prepare_rq:
	sec_moved = pblk_gc_move_valid_secs(pblk, line, gc_lba_list, nr_ppas);
	if (sec_moved != nr_ppas) {
		pr_err("pblk: could not GC all sectors: line:%d (%d/%d/%d)\n",
						line->id, line->vsc,
						sec_moved, nr_ppas);
		pblk_put_line_back(pblk, line);
		goto free_emeta;
	}

	sec_left -= sec_moved;
	if (sec_left > 0)
		goto next_rq;

	/* Logic error */
	BUG_ON(sec_left != 0);

put_line:
	/* Lines are erased before being used (l_mg->data_/log_next) */
	kref_put(&line->ref, pblk_line_put);

free_emeta:
	line->emeta = NULL;
free_lba_list:
	kfree(gc_lba_list);
out:
	mempool_free(line_ws, pblk->line_ws_pool);
}

static int pblk_gc_line(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_ws *line_ws;

	line_ws = mempool_alloc(pblk->line_ws_pool, GFP_ATOMIC);
	if (!line_ws)
		return 1;

	line_ws->pblk = pblk;
	line_ws->priv = line;

	INIT_WORK(&line_ws->ws, pblk_gc_line_ws);
	queue_work(pblk->gc_wq, &line_ws->ws);

	return 0;
}

static void pblk_gc_run(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_gc *gc = &pblk->gc;
	struct pblk_line *line, *tline;
	unsigned int nr_blocks_free, nr_blocks_need;
	struct list_head *group_list;
	int run_gc, gc_group = 0;
	LIST_HEAD(gc_list);

	spin_lock(&l_mg->gc_lock);
	list_for_each_entry_safe(line, tline, &l_mg->gc_full_list, list) {
		spin_lock(&line->lock);
		BUG_ON(line->state != PBLK_LINESTATE_CLOSED);
		line->state = PBLK_LINESTATE_GC;
		spin_unlock(&line->lock);

		list_del(&line->list);
		kref_put(&line->ref, pblk_line_put);
	}

	nr_blocks_need = pblk_rl_gc_thrs(&pblk->rl);
	nr_blocks_free = pblk_rl_nr_free_blks(&pblk->rl);
	run_gc = (nr_blocks_need > nr_blocks_free || gc->gc_forced);

next_gc_group:
	group_list = l_mg->gc_lists[gc_group++];
	while (run_gc && !list_empty(group_list)) {
		if (!run_gc) {
			goto out;
		}

		line = list_first_entry(group_list, struct pblk_line, list);
		nr_blocks_free += line->blk_in_line;

		spin_lock(&line->lock);
		BUG_ON(line->state != PBLK_LINESTATE_CLOSED);
		line->state = PBLK_LINESTATE_GC;
		spin_unlock(&line->lock);

		list_del(&line->list);
		if (pblk_gc_line(pblk, line)) {
			pr_err("pblk: failed to GC line %d\n", line->id);
			goto out;
		}

		run_gc = (nr_blocks_need > nr_blocks_free || gc->gc_forced);
	}

	if (gc_group < PBLK_NR_GC_LISTS)
		goto next_gc_group;

out:
	spin_unlock(&l_mg->gc_lock);
}

static void pblk_gc_kick(struct pblk *pblk)
{
	wake_up_process(pblk->ts_gc);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));
}

/*
 * timed GC every interval.
 */
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

static void pblk_gc_start(struct pblk *pblk)
{
	pblk->gc.gc_active = 1;

	pr_debug("pblk: gc running\n");
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

/*
 * If flush_wq == 1 then no lock should be held by the caller since
 * flush_workqueue can sleep
 */
static void pblk_gc_stop(struct pblk *pblk, int flush_wq)
{
	spin_lock(&pblk->gc.lock);
	pblk->gc.gc_active = 0;
	spin_unlock(&pblk->gc.lock);

	pr_debug("pblk: gc paused\n");
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
	pblk_rl_set_gc_rsc(&pblk->rl, rsv);
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

int pblk_gc_init(struct pblk *pblk)
{
	pblk->ts_gc = kthread_create(pblk_gc_ts, pblk, "pblk-gc");

	setup_timer(&pblk->gc_timer, pblk_gc_timer, (unsigned long)pblk);
	mod_timer(&pblk->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));

	pblk->gc_wq = alloc_workqueue("pblk-gc", WQ_MEM_RECLAIM | WQ_UNBOUND,
									1);
	if (!pblk->gc_wq)
		return -ENOMEM;

	pblk->gc.gc_active = 0;
	pblk->gc.gc_forced = 0;
	pblk->gc.gc_enabled = 1;

	spin_lock_init(&pblk->gc.lock);

	return 0;
}

void pblk_gc_exit(struct pblk *pblk)
{
	del_timer(&pblk->gc_timer);
	pblk_gc_stop(pblk, 1);

	if (pblk->ts_gc)
		kthread_stop(pblk->ts_gc);

	if (pblk->gc_wq)
		destroy_workqueue(pblk->gc_wq);
}

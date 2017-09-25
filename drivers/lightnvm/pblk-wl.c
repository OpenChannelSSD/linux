/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
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
 * pblk-wl.c - pblk's wear-leveling
 */

#include "pblk.h"

/*
 * Get line with the lowest PE cycle count. This provides static wear-leveling
 * at the free line level.
 */
struct pblk_line *pblk_wl_get_line(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line = NULL;

	spin_lock(&l_mg->free_lock);
	if (list_empty(&l_mg->free_list)) {
		pr_err("pblk: no free lines\n");
		goto out;
	}

	line = list_first_entry(&l_mg->free_list, struct pblk_line, list);
	list_del(&line->list);

	line->seq_nr = l_mg->d_seq_nr++;
	l_mg->nr_free_lines--;

out:
	spin_unlock(&l_mg->free_lock);
	return line;
}

static void __pblk_wl_update_pec_thres(struct pblk_line_mgmt *l_mg,
				       struct pblk_line *cur)
{
	struct pblk_line *line, *min;
	struct list_head *next = cur->wl_list.next;
	int cur_pec;

	/* It is ok to increase the P/E counter when selecting the line for GC,
	 * since this will not be persisted until a line is allocated for usage
	 * again.
	 */
	cur_pec = atomic_inc_return(&cur->pec);

	if (cur_pec > l_mg->pec_max)
		l_mg->pec_max = cur_pec;

	min = list_first_entry(&l_mg->wear_list, struct pblk_line, wl_list);
	if (l_mg->pec_max - atomic_read(&min->pec) > l_mg->pec_thres)
		atomic_inc(&l_mg->under_wear);

	/* Maintain global WL list ordered. P/E cycles only increase */
	do {
		line = list_entry(next, struct pblk_line, wl_list);
		if (atomic_read(&line->pec) >= cur_pec ||
			list_is_last(&line->wl_list, &l_mg->wear_list))
			break;

		next = line->wl_list.next;
	} while (1);

	if (list_is_last(&line->wl_list, &l_mg->wear_list)) {
		list_move_tail(&cur->wl_list, &l_mg->wear_list);
	} else if (!list_is_last(&cur->wl_list, &l_mg->wear_list) &&
					&cur->wl_list != line->wl_list.prev) {
		list_del(&cur->wl_list);
		__list_add(&cur->wl_list, line->wl_list.prev, &line->wl_list);
	}
}

void pblk_wl_update_pec_thres(struct pblk_line_mgmt *l_mg,
			      struct pblk_line *cur)
{
	spin_lock(&l_mg->wl_lock);
	__pblk_wl_update_pec_thres(l_mg, cur);
	spin_unlock(&l_mg->wl_lock);
}

static void pblk_wl_put_line_order(struct pblk_line_mgmt *l_mg,
				  struct pblk_line *line)
{
	struct pblk_line *t = NULL;
	int line_pec = atomic_read(&line->pec);

	/* Width ~1000 lines O(n) is acceptable. If this becomes a bottleneck we
	 * can either use a red black tree (O(log n)) or just use free buckets
	 * and do not require allocating the optimal block.
	 */
	list_for_each_entry_reverse(t, &l_mg->free_list, list)
		if (atomic_read(&t->pec) <= line_pec)
			break;

	__list_add(&line->list, &t->list, t->list.next);
}

void pblk_wl_put_line_free(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	spin_lock(&l_mg->free_lock);
	pblk_wl_put_line_order(l_mg, line);
	l_mg->nr_free_lines++;

	spin_lock(&line->lock);

	if (line->gc_group == PBLK_LINEGC_WEAR)
		atomic_dec(&l_mg->inflight_wear);

	line->state = PBLK_LINESTATE_FREE;
	line->gc_group = PBLK_LINEGC_NONE;

	pblk_line_free(pblk, line);
	spin_unlock(&line->lock);
	spin_unlock(&l_mg->free_lock);
}

static inline void pblk_wl_put_line(struct pblk_line_mgmt *l_mg,
				    struct pblk_line *line,
				    struct list_head *list, int state)
{
	spin_lock(&l_mg->free_lock);
	list_add(&line->list, list);

	spin_lock(&l_mg->wl_lock);
	spin_lock(&line->lock);
	line->state = state;
	line->gc_group = PBLK_LINEGC_NONE;
	spin_unlock(&line->lock);

	list_del(&line->wl_list);
	spin_unlock(&l_mg->wl_lock);

	spin_unlock(&l_mg->free_lock);
}

void pblk_wl_put_line_corrupt(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	pblk_wl_put_line(l_mg, line, &l_mg->corrupt_list,
						PBLK_LINESTATE_CORRUPT);
}

void pblk_wl_put_line_bad(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	pblk_wl_put_line(l_mg, line, &l_mg->bad_list, PBLK_LINESTATE_BAD);
}

struct pblk_line *pblk_wl_victim_line(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *victim;

	if (atomic_read(&l_mg->under_wear) == 0)
		return NULL;

	spin_lock(&l_mg->wl_lock);
	victim = list_first_entry(&l_mg->wear_list, struct pblk_line, wl_list);

	spin_lock(&victim->lock);

	/* Do not choose a victim that is already on its way to under wear GC */
	while (victim->gc_group == PBLK_LINEGC_WEAR) {
		spin_unlock(&victim->lock);
		victim = list_next_entry(victim, wl_list);
		spin_lock(&victim->lock);
	}

	__pblk_wl_update_pec_thres(l_mg, victim);

	atomic_dec(&l_mg->under_wear);
	atomic_inc(&l_mg->inflight_wear);

	/* Do not recycle the line if it already is in the free list */
	if (victim->gc_group == PBLK_LINEGC_NONE) {
		spin_unlock(&victim->lock);
		victim = NULL;
		goto out;
	}

	WARN_ON(victim->state != PBLK_LINESTATE_CLOSED);
	victim->state = PBLK_LINESTATE_GC;
	victim->gc_group = PBLK_LINEGC_WEAR;
	spin_unlock(&victim->lock);

out:
	spin_unlock(&l_mg->wl_lock);
	return victim;
}

int pblk_wl_inflight_lines(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	return (atomic_read(&l_mg->inflight_wear));
}

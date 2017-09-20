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

void pblk_wl_put_line_free(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;

	spin_lock(&l_mg->free_lock);
	list_add(&line->list, &l_mg->free_list);
	l_mg->nr_free_lines++;

	spin_lock(&line->lock);
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

	spin_lock(&line->lock);
	line->state = state;
	line->gc_group = PBLK_LINEGC_NONE;
	spin_unlock(&line->lock);

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

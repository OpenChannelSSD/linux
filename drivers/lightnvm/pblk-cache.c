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
 * pblk-cache.c - pblk's write cache
 */

#include "pblk.h"

/*
 * Copy data from current bio to write buffer. This if necessary to guarantee
 * that (i) writes to the media at issued at the right granularity and (ii) that
 * memory-specific constrains are respected (e.g., TLC memories need to write
 * upper, medium and lower pages to guarantee that data has been persisted).
 *
 * This path is exclusively taken by user I/O.
 *
 * return: 1 if bio has been written to buffer, 0 otherwise.
 */
int pblk_write_to_cache(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct pblk_w_ctx w_ctx;
	int nr_entries = pblk_get_secs(bio);
	unsigned long bpos, pos;
	unsigned int i;
	int ret = NVM_IO_DONE;

	if (bio->bi_opf & REQ_PREFLUSH) {
#ifdef CONFIG_NVM_DEBUG
		atomic_inc(&pblk->nr_flush);
#endif
		if (pblk_rb_sync_point_set(&pblk->rwb, bio))
			ret = NVM_IO_OK;

		if (!bio_has_data(bio)) {
			pblk_write_kick(pblk);
			goto out;
		}
	}

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	if (!pblk_rb_may_write_user(&pblk->rwb, nr_entries, &bpos)) {
		io_schedule();
		goto retry;
	}

	w_ctx.flags = flags;
	w_ctx.paddr = 0;
	ppa_set_empty(&w_ctx.ppa);

	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);
		struct ppa_addr ppa;

		w_ctx.lba = laddr + i;

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + i);
		ppa = pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos);

		pblk_update_map_cache(pblk, w_ctx.lba, ppa);
		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_entries, &pblk->inflight_writes);
	atomic_add(nr_entries, &pblk->req_writes);
#endif

	if (bio->bi_opf & REQ_PREFLUSH)
		pblk_write_kick(pblk);

out:
	return ret;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int pblk_write_gc_to_cache(struct pblk *pblk, void *data, u64 *lba_list,
			   unsigned int nr_entries, unsigned int nr_rec_entries,
			   struct pblk_line *gc_line, unsigned long flags)
{
	struct pblk_w_ctx w_ctx;
	unsigned long bpos, pos;
	unsigned int valid_entries;
	unsigned int i;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	if (!pblk_rb_may_write_gc(&pblk->rwb, nr_rec_entries, &bpos)) {
		io_schedule();
		goto retry;
	}

	w_ctx.flags = flags;
	w_ctx.paddr = 0;
	ppa_set_empty(&w_ctx.ppa);

	for (i = 0, valid_entries = 0; i < nr_entries; i++) {
		struct ppa_addr ppa;

		if (lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.lba = lba_list[i];

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + valid_entries);
		ppa = pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos);

		pblk_update_map_gc(pblk, w_ctx.lba, ppa, gc_line);

		data += PBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_entries != valid_entries);
	atomic_add(valid_entries, &pblk->inflight_writes);
	atomic_add(valid_entries, &pblk->recov_gc_writes);
#endif

	return NVM_IO_OK;
}

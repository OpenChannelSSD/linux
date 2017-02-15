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

int pblk_write_to_cache(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	sector_t lba = pblk_get_lba(bio);
	struct pblk_w_ctx w_ctx;
	int nr_entries = pblk_get_secs(bio);
	unsigned int bpos, pos;
	int i, ret;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	ret = pblk_rb_may_write_user(&pblk->rwb, bio, nr_entries, &bpos);
	if (ret == NVM_IO_REQUEUE) {
		io_schedule();
		goto retry;
	}

	if (unlikely(!bio_has_data(bio)))
		goto out;

	w_ctx.flags = flags;
	w_ctx.paddr = 0;
	ppa_set_empty(&w_ctx.ppa);

	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);
		struct ppa_addr ppa;

		w_ctx.lba = lba + i;

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + i);
		ppa = pblk_rb_write_entry(&pblk->rwb, data, w_ctx, pos);

		pblk_update_map_cache(pblk, w_ctx.lba, ppa);
		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_entries, &pblk->inflight_writes);
	atomic_add(nr_entries, &pblk->req_writes);
#endif

out:
	pblk_write_kick(pblk);
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
	unsigned int bpos, pos;
	int i, valid_entries;

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

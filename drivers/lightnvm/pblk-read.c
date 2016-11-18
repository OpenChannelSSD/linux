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
 *
 * pblk-read.c - pblk's read path
 */

#include "pblk.h"

static void pblk_setup_seq_reads(struct pblk *pblk, struct ppa_addr *ppas,
				sector_t bladdr, int nr_secs)
{
	struct pblk_addr *gp;
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		gp = &pblk->trans_map[bladdr + i];
		ppas[i] = gp->ppa;
	}
	spin_unlock(&pblk->trans_lock);
}

static void pblk_setup_rand_reads(struct pblk *pblk, struct ppa_addr *ppas,
				 u64 *lba_list, int nr_secs)
{
	struct pblk_addr *gp;
	sector_t lba;
	int i;

	spin_lock(&pblk->trans_lock);
	for (i = 0; i < nr_secs; i++) {
		lba = lba_list[i];
		if (lba == ADDR_EMPTY)
			continue;

		gp = &pblk->trans_map[lba];
		ppas[i] = gp->ppa;
	}
	spin_unlock(&pblk->trans_lock);
}

/*
 * There is no guarantee that the value read from cache has not been updated. In
 * order to guarantee that writes and reads are ordered, a flush must be issued.
 */
static void pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
				 struct ppa_addr ppa)
{
	pblk_rb_copy_to_bio(&pblk->rwb, bio, nvm_addr_to_cacheline(ppa));
}

static int pblk_try_read_from_cache(struct pblk *pblk, struct bio *bio,
				    struct ppa_addr ppa)
{
	/* The write thread commits the changes to the buffer once the l2p table
	 * has been updated. In this way, if the address read from the l2p table
	 * points to a cacheline, the lba lock guarantees that the entry is not
	 * going to be updated by new writes.
	 */
	if (!nvm_addr_in_cache(ppa))
		return 0;

	pblk_read_from_cache(pblk, bio, ppa);
	return 1;
}

static int pblk_read_ppalist_rq(struct pblk *pblk, struct bio *bio,
				struct nvm_rq *rqd, unsigned long flags,
				int nr_secs, unsigned long *read_bitmap)
{
	sector_t laddr = pblk_get_laddr(bio);
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	int advanced_bio = 0;
	int i, j = 0;

	/* logic error: lba out-of-bounds */
	BUG_ON(!(laddr >= 0 && laddr + nr_secs < pblk->rl.nr_secs));

	pblk_setup_seq_reads(pblk, ppas, laddr, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];

		if (ppa_empty(*p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
			continue;
		}

		/* Try to read from write buffer. Those addresses that cannot be
		 * read from the write buffer are sequentially added to the ppa
		 * list, which will later on be used to submit an I/O to the
		 * device to retrieve data.
		 */
		if (nvm_addr_in_cache(*p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
			if (unlikely(!advanced_bio)) {
				/* This is at least a partially filled bio,
				 * advance it to copy data to the right place.
				 * We will deal with partial bios later on.
				 */
				bio_advance(bio, i * PBLK_EXPOSED_PAGE_SIZE);
				advanced_bio = 1;
			}
			pblk_read_from_cache(pblk, bio, *p);
		} else {
			/* Fill ppa_list with the sectors that cannot be
			 * read from cache
			 */
			rqd->ppa_list[j] = *p;
			j++;
		}

		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
		atomic_add(nr_secs, &pblk->inflight_reads);
#endif

	return NVM_IO_OK;
}

static int pblk_submit_read_io(struct pblk *pblk, struct bio *bio,
			       struct nvm_rq *rqd, unsigned long flags)
{
	int err;

	rqd->flags = pblk_set_read_mode(pblk);

	err = nvm_submit_io(pblk->dev, rqd);
	if (err) {
		pr_err("pblk: I/O submission failed: %d\n", err);
		bio_put(bio);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

static int pblk_fill_partial_read_bio(struct pblk *pblk, struct bio *bio,
				      unsigned int bio_init_idx,
				      unsigned long *read_bitmap,
				      struct nvm_rq *rqd, uint8_t nr_secs)
{
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	void *ppa_ptr = NULL;
	dma_addr_t dma_ppa_list = 0;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	struct bio *new_bio;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int hole;
	int i;
	int ret;
	uint16_t flags;
	DECLARE_COMPLETION_ONSTACK(wait);
#ifdef CONFIG_NVM_DEBUG
	struct ppa_addr *ppa_list;
#endif

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);
	if (!new_bio) {
		pr_err("pblk: could not alloc read bio\n");
		return NVM_IO_ERR;
	}

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes))
		goto err;

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err;
	}

	new_bio->bi_iter.bi_sector = 0; /* artificial bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_sync_bio;

	flags = r_ctx->flags;
	r_ctx->flags |= PBLK_IOTYPE_SYNC;
	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		ppa_ptr = rqd->ppa_list;
		dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

#ifdef CONFIG_NVM_DEBUG
	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
	if (pblk_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
		WARN_ON(1);
#endif

	ret = pblk_submit_read_io(pblk, new_bio, rqd, r_ctx->flags);
	wait_for_completion_io(&wait);
	if (ret) {
		pr_err("pblk: read IO submission failed\n");
		r_ctx->flags = 0;
		goto err;
	}

	if (new_bio->bi_error) {
		inc_stat(pblk, &pblk->read_failed, 0);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, new_bio->bi_error);
#endif
	}

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		rqd->ppa_list = ppa_ptr;
		rqd->dma_ppa_list = dma_ppa_list;
	}

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		src_bv = new_bio->bi_io_vec[i];
		dst_bv = bio->bi_io_vec[bio_init_idx + hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		mempool_free(src_p, pblk->page_pool);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		i++;
		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
	r_ctx->flags = flags;
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;

	bio_endio(bio);
	pblk_end_io(rqd);
	return NVM_IO_OK;

err:
	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
	pblk_end_io(rqd);
	return NVM_IO_ERR;
}

static int __pblk_submit_read(struct pblk *pblk, struct nvm_rq *rqd,
			      struct bio *bio, unsigned long *read_bitmap,
			      unsigned int bio_init_idx, int flags, int nr_secs,
			      int clone_read)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	int ret = NVM_IO_OK;

	/* All sectors are to be read from the device */
	if (bitmap_empty(read_bitmap, nr_secs)) {
		struct bio *int_bio = NULL;
#ifdef CONFIG_NVM_DEBUG
		struct ppa_addr *ppa_list;

		ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;
		if (pblk_boundary_checks(pblk->dev, ppa_list, rqd->nr_ppas))
			WARN_ON(1);
#endif

		if (clone_read) {
			struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);

			/* Clone read bio to deal with read errors internally */
			int_bio = bio_clone_bioset(bio, GFP_KERNEL, fs_bio_set);
			if (!int_bio) {
				pr_err("pblk: could not clone read bio\n");
				goto fail_ppa_free;
			}

			rqd->bio = int_bio;
			r_ctx->orig_bio = bio;
		}

		ret = pblk_submit_read_io(pblk, int_bio, rqd, flags);
		if (ret) {
			pr_err("pblk: read IO submission failed\n");
			if (int_bio)
				bio_put(int_bio);
			goto fail_ppa_free;
		}

		return NVM_IO_OK;
	}

	/* The read bio request could be partially filled by the write buffer,
	 * but there are some holes that need to be read from the drive.
	 */
	ret = pblk_fill_partial_read_bio(pblk, bio, bio_init_idx, read_bitmap,
								rqd, nr_secs);
	if (ret) {
		pr_err("pblk: failed to perform partial read\n");
		goto fail_ppa_free;
	}

	return NVM_IO_OK;

fail_ppa_free:
	if ((nr_secs > 1) && (!(flags & PBLK_IOTYPE_GC)))
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);
	return ret;
}

static int pblk_read_rq(struct pblk *pblk, struct bio *bio, struct nvm_rq *rqd,
			sector_t laddr, unsigned long *read_bitmap,
			unsigned long flags)
{
	struct pblk_addr *gp;
	struct ppa_addr ppa;
	int ret = NVM_IO_OK;

	if (laddr == ADDR_EMPTY) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		ret = NVM_IO_DONE;
		goto out;
	}

	/* logic error: lba out-of-bounds */
	BUG_ON(!(laddr >= 0 && laddr < pblk->rl.nr_secs));

	spin_lock(&pblk->trans_lock);
	gp = &pblk->trans_map[laddr];
	ppa = gp->ppa;
	spin_unlock(&pblk->trans_lock);

	if (ppa_empty(ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		return NVM_IO_DONE;
	}

	if (pblk_try_read_from_cache(pblk, bio, ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
		return NVM_IO_DONE;
	}

	rqd->ppa_addr = ppa;

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_reads);
#endif
	return NVM_IO_OK;
out:
	return ret;
}

int pblk_submit_read(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	int nr_secs = pblk_get_secs(bio);
	unsigned int bio_init_idx;
	struct nvm_rq *rqd;
	struct pblk_r_ctx *r_ctx;
	unsigned long read_bitmap; /* Max 64 ppas per request */
	int ret = NVM_IO_ERR;

	if (nr_secs > PBLK_MAX_REQ_ADDRS)
		return NVM_IO_ERR;

	bitmap_zero(&read_bitmap, nr_secs);

	rqd = pblk_alloc_rqd(pblk, READ);
	if (IS_ERR(rqd)) {
		pr_err_ratelimited("pblk: not able to alloc rqd");
		bio_io_error(bio);
		return NVM_IO_ERR;
	}
	r_ctx = nvm_rq_to_pdu(rqd);

	/* Save the index for this bio's start. This is needed in case
	 * we need to fill a partial read.
	 */
	bio_init_idx = pblk_get_bi_idx(bio);

	if (nr_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
						&rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			goto fail_rqd_free;
		}

		pblk_read_ppalist_rq(pblk, bio, rqd, flags, nr_secs,
								&read_bitmap);
	} else {
		sector_t laddr = pblk_get_laddr(bio);

		ret = pblk_read_rq(pblk, bio, rqd, laddr, &read_bitmap, flags);
		if (ret)
			goto fail_rqd_free;
	}

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = nr_secs;
	r_ctx->flags = flags;

	bio_get(bio);
	if (bitmap_full(&read_bitmap, nr_secs)) {
		bio_endio(bio);
		pblk_end_io(rqd);
		return NVM_IO_OK;
	}

	return __pblk_submit_read(pblk, rqd, bio, &read_bitmap, bio_init_idx,
							flags, nr_secs, 1);

fail_rqd_free:
	pblk_free_rqd(pblk, rqd, READ);
	return ret;
}

static int read_ppalist_rq_gc(struct pblk *pblk, struct bio *bio,
			      struct nvm_rq *rqd, u64 *lba_list,
			      unsigned int nr_secs, unsigned long *read_bitmap,
			      unsigned long flags)
{
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	sector_t lba;
	int advanced_bio = 0;
	int valid_secs = 0;
	int i, j = 0;

	pblk_setup_rand_reads(pblk, ppas, lba_list, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr *p = &ppas[i];

		lba = lba_list[i];

		if (lba == ADDR_EMPTY || ppa_empty(*p))
			continue;

		/* logic error: lba out-of-bounds */
		BUG_ON(!(lba >= 0 && lba < pblk->rl.nr_secs));

		/* Try to read from write buffer. Those addresses that cannot be
		 * read from the write buffer are sequentially added to the ppa
		 * list, which will later on be used to submit an I/O to the
		 * device to retrieve data.
		 */
		if (nvm_addr_in_cache(*p)) {
			WARN_ON(test_and_set_bit(valid_secs, read_bitmap));
			if (unlikely(!advanced_bio)) {
				/* This is at least a partially filled bio,
				 * advance it to copy data to the right place.
				 * We will deal with partial bios later on.
				 */
				bio_advance(bio, valid_secs *
							PBLK_EXPOSED_PAGE_SIZE);
				advanced_bio = 1;
			}
			pblk_read_from_cache(pblk, bio, *p);
		} else {
			/* Fill ppa_list with the sectors that cannot be
			 * read from cache
			 */
			rqd->ppa_list[j] = *p;
			j++;
		}

		valid_secs++;

		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

#ifdef CONFIG_NVM_DEBUG
		atomic_add(nr_secs, &pblk->inflight_reads);
#endif
	return valid_secs;
}

int pblk_submit_read_gc(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, u64 *lba_list,
			unsigned int nr_secs, unsigned int nr_rec_secs,
			unsigned long flags)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned int bio_init_idx;
	unsigned long read_bitmap; /* Max 64 ppas per request */
	unsigned int valid_secs = 1;
	int ret;

	if ((nr_rec_secs != bio->bi_vcnt) || (nr_rec_secs > PBLK_MAX_REQ_ADDRS))
		return NVM_IO_ERR;

	bitmap_zero(&read_bitmap, nr_secs);

	/* Save the bvl_vec index for this bio's start. This is needed in case
	 * we need to fill a partial read.
	 */
	bio_init_idx = pblk_get_bi_idx(bio);

	if (nr_rec_secs > 1) {
		rqd->ppa_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
						  &rqd->dma_ppa_list);
		if (!rqd->ppa_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			return NVM_IO_ERR;
		}

		valid_secs = read_ppalist_rq_gc(pblk, bio, rqd, lba_list,
						nr_secs, &read_bitmap, flags);
	} else {
		sector_t laddr = lba_list[0];

		ret = pblk_read_rq(pblk, bio, rqd, laddr, &read_bitmap, flags);
		if (ret)
			return ret;
	}

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(nr_rec_secs != valid_secs);
#endif

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->ins = &pblk->instance;
	rqd->nr_ppas = valid_secs;
	r_ctx->flags = flags;

	if (bitmap_full(&read_bitmap, valid_secs)) {
		bio_endio(bio);
		return NVM_IO_OK;
	}

	return __pblk_submit_read(pblk, rqd, bio, &read_bitmap, bio_init_idx,
							flags, valid_secs, 0);
}

void pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd, uint8_t nr_secs)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_r_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	struct bio *orig_bio = r_ctx->orig_bio;

	if (bio->bi_error) {
		switch (bio->bi_error) {
		case NVM_RSP_WARN_HIGHECC:
			inc_stat(pblk, &pblk->read_high_ecc, 1);
			break;
		case NVM_RSP_ERR_FAILECC:
			inc_stat(pblk, &pblk->read_failed, 1);
			break;
		case NVM_RSP_ERR_EMPTYPAGE:
			inc_stat(pblk, &pblk->read_empty, 1);
			break;
		default:
			pr_err("pblk: unknown read error:%d\n", bio->bi_error);
		}
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, bio->bi_error);
#endif
	}

	if (r_ctx->flags & PBLK_IOTYPE_SYNC)
		return;

	if (nr_secs > 1)
		nvm_dev_dma_free(dev->parent, rqd->ppa_list, rqd->dma_ppa_list);

	if (rqd->meta_list)
		nvm_dev_dma_free(dev->parent, rqd->meta_list,
							rqd->dma_meta_list);

	bio_put(bio);
	if (orig_bio) {
#ifdef CONFIG_NVM_DEBUG
		BUG_ON(orig_bio->bi_error);
#endif
		bio_endio(orig_bio);
		bio_put(orig_bio);
	}

	pblk_free_rqd(pblk, rqd, READ);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(nr_secs, &pblk->sync_reads);
	atomic_sub(nr_secs, &pblk->inflight_reads);
#endif
}


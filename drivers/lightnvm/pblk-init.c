/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.c)
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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * pblk-init.c - pblk's initialization. Derived from rrpc.c
 */

#include "pblk.h"

static struct kmem_cache *pblk_blk_ws_cache, *pblk_rec_cache, *pblk_r_rq_cache,
					*pblk_w_rq_cache, *pblk_blk_meta_cache;
static DECLARE_RWSEM(pblk_lock);

static const struct block_device_operations pblk_fops = {
	.owner		= THIS_MODULE,
};

static int pblk_submit_io_checks(struct pblk *pblk, struct bio *bio)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int bio_size = bio_sectors(bio) << 9;
	int is_flush = (bio->bi_opf & REQ_PREFLUSH);

	if ((bio_size < geo->sec_size) && (!is_flush))
		return 1;

	return 0;
}

static int pblk_submit_io(struct request_queue *q, struct pblk *pblk,
			  struct bio *bio, unsigned long flags)
{
	int ret;

	if (pblk_submit_io_checks(pblk, bio))
		return NVM_IO_ERR;

	/* Read requests must be <= 256kb due to NVMe's 64 bit completion bitmap
	 * constraint. Writes can be of arbitrary size.
	 */
	if (bio_data_dir(bio) == READ) {
		blk_queue_split(q, &bio, q->bio_split);
		ret = pblk_submit_read(pblk, bio, flags);
		if (ret == NVM_IO_DONE && bio_flagged(bio, BIO_CLONED))
			bio_put(bio);

		return ret;
	}

	/* Prevent deadlock in the case of a modest LUN configuration and large
	 * user I/Os. Unless stalled, the rate limiter leaves at least 256KB
	 * available for user I/O.
	 */
	if (unlikely(pblk_get_secs(bio) >= pblk_rl_sysfs_rate_show(pblk)))
		blk_queue_split(q, &bio, q->bio_split);

	ret = pblk_write_to_cache(pblk, bio, flags);
	if (bio_flagged(bio, BIO_CLONED))
		bio_put(bio);

	return ret;
}

static blk_qc_t pblk_make_rq(struct request_queue *q, struct bio *bio)
{
	struct pblk *pblk = q->queuedata;
	int err;

	if (bio_op(bio) == REQ_OP_DISCARD) {
		pblk_discard(pblk, bio);
		if (!(bio->bi_opf & REQ_PREFLUSH))
			return BLK_QC_T_NONE;
	}

	err = pblk_submit_io(q, pblk, bio, PBLK_IOTYPE_USER);
	switch (err) {
	case NVM_IO_OK:
		return BLK_QC_T_NONE;
	case NVM_IO_ERR:
		bio_io_error(bio);
		break;
	case NVM_IO_DONE:
		bio_endio(bio);
		break;
	case NVM_IO_REQUEUE:
		spin_lock(&pblk->bio_lock);
		bio_list_add(&pblk->requeue_bios, bio);
		spin_unlock(&pblk->bio_lock);
		queue_work(pblk->kgc_wq, &pblk->ws_requeue);
		break;
	}

	return BLK_QC_T_NONE;
}

static void pblk_requeue(struct work_struct *work)
{
	struct pblk *pblk = container_of(work, struct pblk, ws_requeue);
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock(&pblk->bio_lock);
	bio_list_merge(&bios, &pblk->requeue_bios);
	bio_list_init(&pblk->requeue_bios);
	spin_unlock(&pblk->bio_lock);

	while ((bio = bio_list_pop(&bios)))
		pblk_make_rq(pblk->disk->queue, bio);
}

static void pblk_l2p_free(struct pblk *pblk)
{
	vfree(pblk->trans_map);
}

static int pblk_l2p_init(struct pblk *pblk)
{
	sector_t i;

	pblk->trans_map = vzalloc(sizeof(struct pblk_addr) * pblk->rl.nr_secs);
	if (!pblk->trans_map)
		return -ENOMEM;

	for (i = 0; i < pblk->rl.nr_secs; i++) {
		struct pblk_addr *p = &pblk->trans_map[i];

		p->rblk = NULL;
		ppa_set_empty(&p->ppa);
	}

	return 0;
}

static void pblk_rwb_free(struct pblk *pblk)
{
	pblk_rb_data_free(&pblk->rwb);
	vfree(pblk_rb_entries_ref(&pblk->rwb));
}

static int pblk_rwb_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_rb_entry *entries;
	unsigned long nr_entries;
	unsigned int power_size, power_seg_sz;

	nr_entries = pblk_rb_calculate_size(pblk->pgs_in_buffer);

	entries = vzalloc(nr_entries * sizeof(struct pblk_rb_entry));
	if (!entries)
		return -ENOMEM;

	power_size = get_count_order(nr_entries);
	power_seg_sz = get_count_order(geo->sec_size);

	return pblk_rb_init(&pblk->rwb, entries, power_size, power_seg_sz);
}

/* Minimum pages needed within a lun */
#define PAGE_POOL_SIZE 16
#define ADDR_POOL_SIZE 64

static int pblk_core_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	down_write(&pblk_lock);
	if (!pblk_blk_ws_cache) {
		pblk_blk_ws_cache = kmem_cache_create("pblk_blk_ws",
				sizeof(struct pblk_block_ws), 0, 0, NULL);
		if (!pblk_blk_ws_cache) {
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_rec_cache = kmem_cache_create("pblk_rec",
				sizeof(struct pblk_rec_ctx), 0, 0, NULL);
		if (!pblk_rec_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_r_rq_cache = kmem_cache_create("pblk_r_rq", pblk_r_rq_size,
				0, 0, NULL);
		if (!pblk_r_rq_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			kmem_cache_destroy(pblk_rec_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_w_rq_cache = kmem_cache_create("pblk_w_rq", pblk_w_rq_size,
				0, 0, NULL);
		if (!pblk_w_rq_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			kmem_cache_destroy(pblk_rec_cache);
			kmem_cache_destroy(pblk_r_rq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}

		pblk_blk_meta_cache = kmem_cache_create("pblk_blk_m",
				pblk->blk_meta.rlpg_page_len, 0, 0, NULL);
		if (!pblk_blk_meta_cache) {
			kmem_cache_destroy(pblk_blk_ws_cache);
			kmem_cache_destroy(pblk_rec_cache);
			kmem_cache_destroy(pblk_r_rq_cache);
			kmem_cache_destroy(pblk_w_rq_cache);
			up_write(&pblk_lock);
			return -ENOMEM;
		}
	}
	up_write(&pblk_lock);

	pblk->page_pool = mempool_create_page_pool(PAGE_POOL_SIZE, 0);
	if (!pblk->page_pool)
		return -ENOMEM;

	pblk->blk_ws_pool = mempool_create_slab_pool(geo->nr_luns,
							pblk_blk_ws_cache);
	if (!pblk->blk_ws_pool)
		goto free_page_pool;

	pblk->rec_pool = mempool_create_slab_pool(geo->nr_luns, pblk_rec_cache);
	if (!pblk->rec_pool)
		goto free_blk_ws_pool;

	pblk->r_rq_pool = mempool_create_slab_pool(64, pblk_r_rq_cache);
	if (!pblk->r_rq_pool)
		goto free_rec_pool;

	pblk->w_rq_pool = mempool_create_slab_pool(64, pblk_w_rq_cache);
	if (!pblk->w_rq_pool)
		goto free_r_rq_pool;

	pblk->blk_meta_pool = mempool_create_slab_pool(16, pblk_blk_meta_cache);
	if (!pblk->blk_meta_pool)
		goto free_w_rq_pool;

	pblk->kw_wq = alloc_workqueue("pblk-writer",
				WQ_MEM_RECLAIM | WQ_UNBOUND, pblk->nr_luns);
	if (!pblk->kw_wq)
		goto free_blk_meta_pool;

	/* Init write buffer */
	if (pblk_rwb_init(pblk))
		goto free_kw_wq;

	INIT_LIST_HEAD(&pblk->compl_list);
	return 0;

free_kw_wq:
	destroy_workqueue(pblk->kw_wq);
free_blk_meta_pool:
	mempool_destroy(pblk->blk_meta_pool);
free_w_rq_pool:
	mempool_destroy(pblk->w_rq_pool);
free_r_rq_pool:
	mempool_destroy(pblk->r_rq_pool);
free_rec_pool:
	mempool_destroy(pblk->rec_pool);
free_blk_ws_pool:
	mempool_destroy(pblk->blk_ws_pool);
free_page_pool:
	mempool_destroy(pblk->page_pool);
	return -ENOMEM;
}

static void pblk_core_free(struct pblk *pblk)
{
	if (pblk->kw_wq)
		destroy_workqueue(pblk->kw_wq);

	mempool_destroy(pblk->page_pool);
	mempool_destroy(pblk->blk_ws_pool);
	mempool_destroy(pblk->rec_pool);
	mempool_destroy(pblk->r_rq_pool);
	mempool_destroy(pblk->w_rq_pool);
	mempool_destroy(pblk->blk_meta_pool);
}

static void pblk_luns_free(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	int i;

	if (!pblk->luns)
		return;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];
		vfree(rlun->blocks);
	}

	kfree(pblk->luns);
}

static int pblk_bb_discovery(struct nvm_tgt_dev *dev, struct pblk_lun *rlun)
{
	struct nvm_geo *geo = &dev->geo;
	struct pblk_block *rblk;
	struct ppa_addr ppa;
	u8 *blks;
	int nr_blks;
	int i;
	int ret;

	nr_blks = geo->blks_per_lun * geo->plane_mode;
	blks = kmalloc(nr_blks, GFP_KERNEL);
	if (!blks)
		return -ENOMEM;

	ppa.ppa = 0;
	ppa.g.ch = rlun->bppa.g.ch;
	ppa.g.lun = rlun->bppa.g.lun;

	ret = nvm_get_bb_tbl(dev->parent, ppa, blks);
	if (ret) {
		pr_err("pblk: could not get BB table\n");
		kfree(blks);
		goto out;
	}

	nr_blks = nvm_bb_tbl_fold(dev->parent, blks, nr_blks);
	if (nr_blks < 0)
		return nr_blks;

	rlun->nr_free_blocks = geo->blks_per_lun;
	for (i = 0; i < nr_blks; i++) {
		if (blks[i] == NVM_BLK_T_FREE && i > 16)
			continue;

		rblk = &rlun->blocks[i];
		list_move_tail(&rblk->list, &rlun->bb_list);
		rblk->state = NVM_BLK_ST_BAD;
		rlun->nr_free_blocks--;
	}

out:
	kfree(blks);
	return ret;
}

static void pblk_set_lun_ppa(struct pblk_lun *rlun, struct ppa_addr ppa)
{
	rlun->bppa.ppa = 0;
	rlun->bppa.g.ch = ppa.g.ch;
	rlun->bppa.g.lun = ppa.g.lun;
}

static int pblk_luns_init(struct pblk *pblk, struct ppa_addr *luns)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	int i, j, mod, ret = -EINVAL;
	int max_write_ppas;

	pblk->nr_luns = geo->nr_luns;

	pblk->min_write_pgs = geo->sec_per_pl * (geo->sec_size / PAGE_SIZE);
	max_write_ppas = pblk->min_write_pgs * pblk->nr_luns;
	pblk->max_write_pgs = (max_write_ppas < nvm_max_phys_sects(dev)) ?
				max_write_ppas : nvm_max_phys_sects(dev);

	/* TODO: Implement unbalanced LUN support */
	if (geo->luns_per_chnl < 0) {
		pr_err("pblk: unbalanced LUN config. not supported yet\n");
		return -EINVAL;
	}

	if (pblk->max_write_pgs > PBLK_MAX_REQ_ADDRS) {
		pr_err("pblk: device exposes too many sectors per write");
		return -EINVAL;
	}

	pblk->pgs_in_buffer = NVM_MEM_PAGE_WRITE * geo->sec_per_pg *
				geo->nr_planes * pblk->nr_luns;

	if (pblk->max_write_pgs > PBLK_MAX_REQ_ADDRS) {
		pr_err("pblk: cannot support device max_phys_sect\n");
		return -EINVAL;
	}

	div_u64_rem(geo->sec_per_blk, pblk->min_write_pgs, &mod);
	if (mod) {
		pr_err("pblk: bad configuration of sectors/pages\n");
		return -EINVAL;
	}

	pblk->luns = kcalloc(pblk->nr_luns, sizeof(struct pblk_lun),
								GFP_KERNEL);
	if (!pblk->luns)
		return -ENOMEM;

	pblk->rl.total_blocks = pblk->rl.nr_secs = 0;

	/* 1:1 mapping */
	for (i = 0; i < pblk->nr_luns; i++) {
		/* Stripe across channels as much as we can*/
		int ch = i % geo->nr_chnls;
		int lun_raw = i / geo->nr_chnls;
		int lunid = lun_raw + ch * geo->luns_per_chnl;
		struct ppa_addr ppa = luns[lunid];

		rlun = &pblk->luns[i];
		rlun->pblk = pblk;
		rlun->id = i;
		pblk_set_lun_ppa(rlun, ppa);
		rlun->blocks = vzalloc(sizeof(struct pblk_block) *
							geo->blks_per_lun);
		if (!rlun->blocks) {
			ret = -ENOMEM;
			goto err;
		}

		INIT_LIST_HEAD(&rlun->free_list);
		INIT_LIST_HEAD(&rlun->bb_list);
		INIT_LIST_HEAD(&rlun->g_bb_list);
		INIT_LIST_HEAD(&rlun->prio_list);
		INIT_LIST_HEAD(&rlun->open_list);
		INIT_LIST_HEAD(&rlun->closed_list);

		sema_init(&rlun->wr_sem, 1);

		for (j = 0; j < geo->blks_per_lun; j++) {
			struct pblk_block *rblk = &rlun->blocks[j];

			rblk->id = j;
			rblk->rlun = rlun;
			rblk->state = NVM_BLK_T_FREE;
			INIT_LIST_HEAD(&rblk->prio);
			spin_lock_init(&rblk->lock);

			list_add_tail(&rblk->list, &rlun->free_list);
		}

		if (pblk_bb_discovery(dev, rlun))
			goto err;

		spin_lock_init(&rlun->lock);

		pblk->rl.total_blocks += geo->blks_per_lun;
		pblk->rl.nr_secs += geo->sec_per_lun;
	}

	return 0;
err:
	return ret;
}

static int pblk_writer_init(struct pblk *pblk)
{
	setup_timer(&pblk->wtimer, pblk_write_timer_fn, (unsigned long)pblk);
	mod_timer(&pblk->wtimer, jiffies + msecs_to_jiffies(100));

	pblk->ts_writer = kthread_create(pblk_write_ts, pblk, "pblk-writer");
	pblk_rl_init(pblk);

	return 0;
}

static void pblk_writer_free(struct pblk *pblk)
{
	kthread_stop(pblk->ts_writer);
	del_timer(&pblk->wtimer);
}

static void pblk_free(struct pblk *pblk)
{
	pblk_l2p_free(pblk);
	pblk_core_free(pblk);
	pblk_luns_free(pblk);
	pblk_map_free(pblk);
	pblk_writer_free(pblk);
	pblk_rwb_free(pblk);
	pblk_sysfs_exit(pblk);

	kfree(pblk);
}

static void pblk_tear_down(struct pblk *pblk)
{
	pblk_flush_writer(pblk);
	pblk_pad_open_blks(pblk);
	pblk_rb_sync_l2p(&pblk->rwb);

	if (pblk_rb_tear_down_check(&pblk->rwb)) {
		pr_err("pblk: write buffer error on tear down\n");
		return;
	}

	pblk_free_blks(pblk);

	pr_debug("pblk: consistent tear down\n");

	/* TODO: Save FTL snapshot for fast recovery */
}

static void pblk_exit(void *private)
{
	struct pblk *pblk = private;

	down_write(&pblk_lock);
	flush_workqueue(pblk->krqd_wq);
	pblk_tear_down(pblk);
	pblk_gc_exit(pblk);
	pblk_free(pblk);
	up_write(&pblk_lock);
}

static sector_t pblk_capacity(void *private)
{
	struct pblk *pblk = private;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	sector_t reserved, provisioned;

	/* cur, gc, and two emergency blocks for each lun */
	reserved = pblk->nr_luns * geo->sec_per_blk * 4;
	provisioned = pblk->capacity - reserved;

	if (reserved > pblk->rl.nr_secs) {
		pr_err("pblk: not enough space available to expose storage.\n");
		return 0;
	}

	sector_div(provisioned, 10);
	return provisioned * 9 * NR_PHY_IN_LOG;
}

static int pblk_blocks_init(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int lun, blk;
	int ret = 0;

	/* TODO: Recover from l2p snapshot. Only perform scanning in
	 * case of failure
	 */

	for (lun = 0; lun < pblk->nr_luns; lun++) {
		rlun = &pblk->luns[lun];
		for (blk = 0; blk < geo->blks_per_lun; blk++) {
			rblk = &rlun->blocks[blk];

			if (!rblk->state)
				pblk->capacity += geo->sec_per_blk;

#ifndef CONFIG_NVM_PBLK_NO_RECOV
			ret = pblk_recov_scan_blk(pblk, rblk);
			if (ret) {
				pr_err("nvm: pblk: could not recover l2p\n");
				return ret;
			}
#endif
		}
	}

	return ret;
}

int pblk_luns_configure(struct pblk *pblk)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;

	for (i = 0; i < pblk->nr_luns; i++) {
		rlun = &pblk->luns[i];

		/* Get first active block directly from mm pool */
		spin_lock(&rlun->lock);
		rblk = pblk_get_blk(pblk, rlun);
		if (!rblk) {
			spin_unlock(&rlun->lock);
			goto err;
		}

		pblk_set_lun_cur(rlun, rblk);
		spin_unlock(&rlun->lock);
	}

	return 0;
err:
	while (--i >= 0) {
		rlun = &pblk->luns[i];

		if (rlun->cur)
			pblk_put_blk(pblk, rlun->cur);
	}

	return -ENOMEM;
}

static void *pblk_init(struct nvm_tgt_dev *dev, struct gendisk *tdisk);

/* physical block device target */
static struct nvm_tgt_type tt_pblk = {
	.name		= "pblk",
	.version	= {1, 0, 0},

	.make_rq	= pblk_make_rq,
	.capacity	= pblk_capacity,
	.end_io		= pblk_end_io,

	.init		= pblk_init,
	.exit		= pblk_exit,

	.sysfs_init	= pblk_sysfs_init,
};

static void *pblk_init(struct nvm_tgt_dev *dev, struct gendisk *tdisk)
{
	struct request_queue *bqueue = dev->q;
	struct request_queue *tqueue = tdisk->queue;
	struct pblk *pblk;
	int ret;

	/* if (dev->identity.dom & NVM_RSP_L2P) { */
		/* pr_err("pblk: device-side L2P table not supported. (%x)\n", */
							/* dev->identity.dom); */
		/* return ERR_PTR(-EINVAL); */
	/* } */

	pblk = kzalloc(sizeof(struct pblk), GFP_KERNEL);
	if (!pblk)
		return ERR_PTR(-ENOMEM);

	pblk->instance.tt = &tt_pblk;
	pblk->dev = dev;
	pblk->disk = tdisk;

	bio_list_init(&pblk->requeue_bios);
	spin_lock_init(&pblk->bio_lock);
	spin_lock_init(&pblk->trans_lock);
	spin_lock_init(&pblk->lock);
	spin_lock_init(&pblk->kick_lock);
	INIT_WORK(&pblk->ws_requeue, pblk_requeue);
	INIT_WORK(&pblk->ws_gc, pblk_gc);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&pblk->inflight_writes, 0);
	atomic_set(&pblk->padded_writes, 0);
	atomic_set(&pblk->nr_flush, 0);
	atomic_set(&pblk->req_writes, 0);
	atomic_set(&pblk->sub_writes, 0);
	atomic_set(&pblk->sync_writes, 0);
	atomic_set(&pblk->compl_writes, 0);
	atomic_set(&pblk->inflight_meta, 0);
	atomic_set(&pblk->compl_meta, 0);
	atomic_set(&pblk->inflight_reads, 0);
	atomic_set(&pblk->sync_reads, 0);
	atomic_set(&pblk->recov_writes, 0);
	atomic_set(&pblk->recov_gc_writes, 0);
	atomic_set(&pblk->requeued_writes, 0);
#endif

	init_waitqueue_head(&pblk->wait);

	ret = pblk_luns_init(pblk, dev->luns);
	if (ret) {
		pr_err("pblk: could not initialize luns\n");
		goto err;
	}

	ret = pblk_map_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize map\n");
		goto err;
	}

	ret = pblk_recov_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize recovery\n");
		goto err;
	}

	ret = pblk_core_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize core\n");
		goto err;
	}

	ret = pblk_l2p_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize maps\n");
		goto err;
	}

	ret = pblk_blocks_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize state for blocks\n");
		goto err;
	}

	ret = pblk_writer_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize write thread\n");
		goto err;
	}

	ret = pblk_luns_configure(pblk);
	if (ret) {
		pr_err("pblk: not enough blocks available in LUNs.\n");
		goto err;
	}

	ret = pblk_gc_init(pblk);
	if (ret) {
		pr_err("pblk: could not initialize gc\n");
		goto err;
	}

	/* inherit the size from the underlying device */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));

	blk_queue_write_cache(tqueue, true, false);

	pr_info("pblk init: luns:%u, %llu sectors, buffer entries:%lu\n",
			pblk->nr_luns, (unsigned long long)pblk->rl.nr_secs,
			pblk_rb_nr_entries(&pblk->rwb));

	wake_up_process(pblk->ts_writer);
	return pblk;
err:
	pblk_free(pblk);
	return ERR_PTR(ret);
}

static int __init pblk_module_init(void)
{
	return nvm_register_tgt_type(&tt_pblk);
}

static void pblk_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_pblk);
}

module_init(pblk_module_init);
module_exit(pblk_module_exit);
MODULE_AUTHOR("Javier Gonzalez <jg@lightnvm.io>");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Physical Block-Device Target for Open-Channel SSDs");

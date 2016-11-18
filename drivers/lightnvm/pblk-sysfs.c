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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * pblk-sysfs.c - pblk's sysfs
 */

#include "pblk.h"

static ssize_t pblk_sysfs_luns_active_show(struct pblk *pblk, char *page)
{
	return sprintf(page, "luns_active=%d\n",
					pblk_map_get_active_luns(pblk));
}

static ssize_t pblk_sysfs_luns_show(struct pblk *pblk, char *page)
{
	struct pblk_lun *rlun;
	ssize_t sz = 0;
	int i;

	spin_lock(&pblk->w_luns.lock);
	for (i = 0; i < pblk->w_luns.nr_luns; i++) {
		int active = 1;

		rlun = pblk->w_luns.luns[i];
		if (!down_trylock(&rlun->wr_sem)) {
			active = 0;
			up(&rlun->wr_sem);
		}
		sz += sprintf(page + sz, "POS:%d, CH:%d, LUN:%d - %d\n",
					i,
					rlun->bppa.g.ch,
					rlun->bppa.g.lun,
					active);
	}
	spin_unlock(&pblk->w_luns.lock);

	return sz;
}

static ssize_t pblk_sysfs_consume_blocks_show(struct pblk *pblk, char *page)
{
	return sprintf(page, "consume_blocks=%d\n",
					pblk_map_get_consume_blocks(pblk));
}

static ssize_t pblk_sysfs_rate_limiter(struct pblk *pblk, char *page)
{
	unsigned long free_blocks;
	int rb_user_max, rb_user_cnt;
	int rb_gc_max, rb_gc_rsv, rb_gc_cnt;

	spin_lock(&pblk->rl.lock);
	free_blocks = pblk->rl.free_blocks;
	rb_user_max = pblk->rl.rb_user_max;
	rb_user_cnt = pblk->rl.rb_user_cnt;
	rb_gc_max = pblk->rl.rb_gc_max;
	rb_gc_rsv = pblk->rl.rb_gc_rsv;
	rb_gc_cnt = pblk->rl.rb_gc_cnt;
	spin_unlock(&pblk->rl.lock);

	return sprintf(page,
		"u:%u/%u,gc:%u/%u/%u(%lu)(stop:<%u/%u,full:>%u/%u,free:%lu)\n",
				rb_user_max,
				rb_user_cnt,
				rb_gc_max,
				rb_gc_rsv,
				rb_gc_cnt,
				pblk_rb_nr_entries(&pblk->rwb),
				1 << pblk->rl.low_pw,
				pblk->rl.low_lun,
				1 << pblk->rl.high_pw,
				pblk->rl.high_lun,
				free_blocks);
}

static ssize_t pblk_sysfs_gc_state_show(struct pblk *pblk, char *page)
{
	int gc_enabled, gc_active;

	pblk_gc_sysfs_state_show(pblk, &gc_enabled, &gc_active);
	return sprintf(page, "gc_enabled=%d, gc_active=%d\n",
					gc_enabled, gc_active);
}

static ssize_t pblk_sysfs_stats(struct pblk *pblk, char *page)
{
	ssize_t offset;

	spin_lock_irq(&pblk->lock);
	offset = sprintf(page, "read_failed=%lu, read_high_ecc=%lu, read_empty=%lu, read_failed_gc=%lu, write_failed=%lu, erase_failed=%lu\n",
			pblk->read_failed, pblk->read_high_ecc,
			pblk->read_empty, pblk->read_failed_gc,
			pblk->write_failed, pblk->erase_failed);
	spin_unlock_irq(&pblk->lock);

	return offset;
}

#ifdef CONFIG_NVM_DEBUG
static ssize_t pblk_sysfs_stats_debug(struct pblk *pblk, char *page)
{
	return sprintf(page, "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
			atomic_read(&pblk->inflight_writes),
			atomic_read(&pblk->inflight_reads),
			atomic_read(&pblk->req_writes),
			atomic_read(&pblk->nr_flush),
			atomic_read(&pblk->padded_writes),
			atomic_read(&pblk->sub_writes),
			atomic_read(&pblk->sync_writes),
			atomic_read(&pblk->compl_writes),
			atomic_read(&pblk->inflight_meta),
			atomic_read(&pblk->compl_meta),
			atomic_read(&pblk->recov_writes),
			atomic_read(&pblk->recov_gc_writes),
			atomic_read(&pblk->requeued_writes),
			atomic_read(&pblk->sync_reads));
}

static ssize_t pblk_sysfs_blocks(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	unsigned int free, used_int, used_cnt, bad, total_lun;
	int i;
	ssize_t line, sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		free = used_int = bad = 0;

		spin_lock(&rlun->lock);
		list_for_each_entry(rblk, &rlun->free_list, list)
			free++;
		list_for_each_entry(rblk, &rlun->bb_list, list)
			bad++;

		list_for_each_entry(rblk, &rlun->open_list, list)
			used_int++;
		list_for_each_entry(rblk, &rlun->closed_list, list)
			used_int++;
		list_for_each_entry(rblk, &rlun->g_bb_list, list)
			used_int++;
		spin_unlock(&rlun->lock);

		used_cnt = geo->blks_per_lun - free - bad;
		total_lun = used_int + free + bad;

		if (used_cnt != used_int)
			pr_err("pblk: used list corruption (i:%u,c:%u)\n",
					used_int, used_cnt);

		if (geo->blks_per_lun != total_lun)
			pr_err("pblk: list corruption (t:%u,c:%u)\n",
					geo->blks_per_lun, total_lun);

		line = sprintf(page + sz,
			"lun(%i %i):u=%u,f=%u,b=%u,t=%u,v=%u\n",
			rlun->bppa.g.ch, rlun->bppa.g.lun,
			used_int, free, bad, total_lun, rlun->nr_free_blocks);

		sz += line;
		if (sz + line > PAGE_SIZE) {
			sz += sprintf(page + sz, "Cannot fit all LUNs\n");
			break;
		}
	}

	return sz;
}

static ssize_t pblk_sysfs_open_blks(struct pblk *pblk, char *page)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;
	ssize_t sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		sz += sprintf(page + sz, "LUN:%d\n", rlun->id);

		spin_lock(&rlun->lock);
		list_for_each_entry(rblk, &rlun->open_list, list) {
			spin_lock(&rblk->lock);
			sz += sprintf(page + sz,
				"open:\tblk:%d\t%u\t%u\t%u\t%u\t%u\t%u\n",
				rblk->id,
				pblk->dev->geo.sec_per_blk,
				pblk->nr_blk_dsecs,
				bitmap_weight(rblk->sector_bitmap,
						pblk->dev->geo.sec_per_blk),
				bitmap_weight(rblk->sync_bitmap,
						pblk->dev->geo.sec_per_blk),
				bitmap_weight(rblk->invalid_bitmap,
						pblk->dev->geo.sec_per_blk),
				rblk->nr_invalid_secs);
			spin_unlock(&rblk->lock);
		}
		spin_unlock(&rlun->lock);
	}

	return sz;
}

static ssize_t pblk_sysfs_bad_blks(struct pblk *pblk, char *page)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;
	ssize_t line, sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		int bad_blks = 0;

		spin_lock(&rlun->lock);
		list_for_each_entry(rblk, &rlun->g_bb_list, list)
			bad_blks++;
		spin_unlock(&rlun->lock);

		line = sprintf(page + sz, "lun(%i %i):bad=%u\n",
				rlun->bppa.g.ch,
				rlun->bppa.g.lun,
				bad_blks);

		sz += line;
		if (sz + line > PAGE_SIZE) {
			sz += sprintf(page + sz, "Cannot fit all LUNs\n");
			break;
		}
	}

	return sz;
}

static ssize_t pblk_sysfs_gc_blks(struct pblk *pblk, char *page)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk;
	int i;
	ssize_t line, sz = 0;

	pblk_for_each_lun(pblk, rlun, i) {
		int gc_blks = 0;

		spin_lock(&rlun->lock);
		list_for_each_entry(rblk, &rlun->prio_list, prio)
			gc_blks++;
		spin_unlock(&rlun->lock);

		line = sprintf(page + sz, "lun(%i %i):gc=%u\n",
				rlun->bppa.g.ch,
				rlun->bppa.g.lun,
				gc_blks);

		sz += line;
		if (sz + line > PAGE_SIZE) {
			sz += sprintf(page + sz, "Cannot fit all LUNs\n");
			break;
		}
	}

	return sz;
}

static ssize_t pblk_sysfs_write_buffer(struct pblk *pblk, char *page)
{
	return pblk_rb_sysfs(&pblk->rwb, page);
}
#endif

static ssize_t pblk_sysfs_luns_active_store(struct pblk *pblk, const char *page,
					    size_t len)
{
	size_t c_len;
	int value;
	int ret;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtouint(page, 0, &value))
		return -EINVAL;

	ret = pblk_map_set_active_luns(pblk, value);
	if (ret)
		return ret;

	return len;
}

static ssize_t pblk_sysfs_consume_blocks_store(struct pblk *pblk,
					       const char *page, size_t len)
{
	size_t c_len;
	int value;
	int ret;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtouint(page, 0, &value))
		return -EINVAL;

	ret = pblk_map_set_consume_blocks(pblk, value);
	if (ret)
		return ret;

	return len;
}

static ssize_t pblk_sysfs_rate_store(struct pblk *pblk, const char *page,
				     size_t len)
{
	size_t c_len;
	int value;
	int ret;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtouint(page, 0, &value))
		return -EINVAL;

	ret = pblk_rl_sysfs_rate_store(pblk, value);
	if (ret)
		return ret;

	return len;
}

static ssize_t pblk_sysfs_gc_state_store(struct pblk *pblk,
					 const char *page, size_t len)
{
	size_t c_len;
	int value;
	int ret;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtouint(page, 0, &value))
		return -EINVAL;

	ret = pblk_gc_sysfs_enable(pblk, value);
	if (ret)
		return ret;

	return len;
}

static ssize_t pblk_sysfs_gc_force(struct pblk *pblk, const char *page,
				   size_t len)
{
	size_t c_len;
	int value;
	int ret;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtouint(page, 0, &value))
		return -EINVAL;

	ret = pblk_gc_sysfs_force(pblk, value);
	if (ret)
		return ret;

	return len;
}

#ifdef CONFIG_NVM_DEBUG
static ssize_t pblk_sysfs_l2p_map_print(struct pblk *pblk, const char *page,
					ssize_t len)
{
	size_t c_len;
	sector_t lba_init, lba_end;
	struct ppa_addr ppa;
	sector_t i;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (sscanf(page, "%lu-%lu", &lba_init, &lba_end) != 2)
		return -EINVAL;

	for (i = lba_init; i < lba_end; i++) {
		ppa = pblk_get_lba_map(pblk, i);

		if (ppa_empty(ppa)) {
			pr_debug("pblk: lba:%lu - ppa: EMPTY ADDRESS\n", i);
		} else {
			if (ppa.c.is_cached) {
				pr_debug("pblk: lba:%lu - ppa: cacheline:%llu\n",
					i,
					(u64)ppa.c.line);

				continue;
			}

			pr_debug("pblk: lba:%lu - ppa: %llx: ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
				i,
				ppa.ppa,
				ppa.g.ch,
				ppa.g.lun,
				ppa.g.blk,
				ppa.g.pg,
				ppa.g.pl,
				ppa.g.sec);
		}
	}

	return len;
}

static ssize_t pblk_sysfs_l2p_map_sanity(struct pblk *pblk, const char *page,
					 ssize_t len)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	size_t c_len;
	struct pblk_addr *gp;
	struct ppa_addr ppa;
	void *read_sec;
	struct nvm_rq *rqd;
	struct pblk_r_ctx *r_ctx;
	struct bio *bio;
	sector_t lba_init, lba_end;
	sector_t i;
	DECLARE_COMPLETION_ONSTACK(wait);

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (sscanf(page, "%llx-%lu-%lu", &ppa.ppa, &lba_init, &lba_end) != 3)
		return -EINVAL;

	if (lba_end == 0) {
		lba_init = 0;
		lba_end = pblk->rl.nr_secs;
	}

	if (lba_end > pblk->rl.nr_secs) {
		pr_err("pblk: Incorrect lba limit\n");
		goto out;
	}

	spin_lock(&pblk->trans_lock);
	for (i = lba_init; i < lba_end; i++) {
		gp = &pblk->trans_map[i];

		if (ppa.ppa == gp->ppa.ppa)
			pr_debug("pblk: lba:%lu - ppa: %llx: ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
				i,
				gp->ppa.ppa,
				gp->ppa.g.ch,
				gp->ppa.g.lun,
				gp->ppa.g.blk,
				gp->ppa.g.pg,
				gp->ppa.g.pl,
				gp->ppa.g.sec);
	}
	spin_unlock(&pblk->trans_lock);

	read_sec = kmalloc(geo->sec_size, GFP_KERNEL);
	if (!read_sec)
		goto out;

	bio = bio_map_kern(dev->q, read_sec, geo->sec_size, GFP_KERNEL);
	if (!bio) {
		pr_err("pblk: could not allocate recovery bio\n");
		goto out;
	}

	rqd = pblk_alloc_rqd(pblk, READ);
	if (IS_ERR(rqd)) {
		pr_err("pblk: not able to create write req.\n");
		bio_put(bio);
		goto out;
	}

	bio->bi_iter.bi_sector = 0;
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_end_io = pblk_end_sync_bio;
	bio->bi_private = &wait;

	rqd->opcode = NVM_OP_PREAD;
	rqd->ins = &pblk->instance;
	rqd->bio = bio;
	rqd->meta_list = NULL;
	rqd->flags = NVM_IO_SNGL_ACCESS | NVM_IO_SUSPEND;

	r_ctx = nvm_rq_to_pdu(rqd);
	r_ctx->flags = PBLK_IOTYPE_SYNC;

	if (nvm_set_rqd_ppalist(dev->parent, rqd, &ppa, 1, 0)) {
		pr_err("pblk: could not set rqd ppa list\n");
		goto out;
	}

	if (nvm_submit_io(dev, rqd)) {
		pr_err("pblk: I/O submission failed\n");
		nvm_free_rqd_ppalist(dev->parent, rqd);
		goto out;
	}

	wait_for_completion_io(&wait);
	if (bio->bi_error) {
		struct ppa_addr p;

		p = dev_to_generic_addr(pblk->dev, rqd->ppa_addr);
		pr_err("pblk: read failed (%u)\n", bio->bi_error);
		print_ppa(&p, "rqd", bio->bi_error);
		goto out;
	}

out:
	return len;
}

static ssize_t pblk_sysfs_block_meta(struct pblk *pblk, const char *page,
				     ssize_t len)
{
	size_t c_len;
	u64 value;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtoull(page, 0, &value))
		return -EINVAL;

	pblk_recov_blk_meta_sysfs(pblk, value);
	return len;
}

static ssize_t pblk_sysfs_cleanup(struct pblk *pblk, const char *page,
				  ssize_t len)
{
	struct pblk_lun *rlun;
	struct pblk_block *rblk, *trblk;
	size_t c_len;
	int value;
	sector_t i;
	LIST_HEAD(cleanup_list);

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (kstrtoint(page, 0, &value))
		return -EINVAL;
	if (value != 1)
		return -EINVAL;

	/* Cleanup L2P table */
	spin_lock(&pblk->trans_lock);
	for (i = 0; i < pblk->rl.nr_secs; i++) {
		struct pblk_addr *p = &pblk->trans_map[i];

		p->rblk = NULL;
		ppa_set_empty(&p->ppa);
	}
	spin_unlock(&pblk->trans_lock);

	pblk_for_each_lun(pblk, rlun, i) {
		spin_lock(&rlun->lock);
		list_for_each_entry_safe(rblk, trblk, &rlun->open_list, list)
			list_move_tail(&rblk->list, &cleanup_list);
		list_for_each_entry_safe(rblk, trblk, &rlun->closed_list, list)
			list_move_tail(&rblk->list, &cleanup_list);
		spin_unlock(&rlun->lock);

		/* Blocks in closed_list are a superset of prio_list */
		spin_lock(&rlun->lock);
		list_for_each_entry_safe(rblk, trblk, &rlun->prio_list, prio)
			list_del_init(&rblk->prio);
		spin_unlock(&rlun->lock);

		rlun->cur = NULL;
	}

	list_for_each_entry_safe(rblk, trblk, &cleanup_list, list) {
		pblk_erase_blk(pblk, rblk);

		spin_lock(&rblk->lock);
		pblk_put_blk(pblk, rblk);
		spin_unlock(&rblk->lock);
	}

	/* Reset write luns */
	pblk_luns_configure(pblk);

	return len;
}
#endif


static struct attribute sys_luns_active = {
	.name = "luns_active",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_consume_blocks = {
	.name = "consume_blocks",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_write_luns = {
	.name = "write_luns",
	.mode = S_IRUGO,
};

static struct attribute sys_rate_limiter_attr = {
	.name = "rate_limiter",
	.mode = S_IRUGO,
};

static struct attribute sys_gc_state = {
	.name = "gc_state",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_gc_force = {
	.name = "gc_force",
	.mode = S_IWUSR,
};

static struct attribute sys_errors_attr = {
	.name = "errors",
	.mode = S_IRUGO,
};

#ifdef CONFIG_NVM_DEBUG
static struct attribute sys_stats_debug_attr = {
	.name = "stats",
	.mode = S_IRUGO,
};

static struct attribute sys_blocks_attr = {
	.name = "blocks",
	.mode = S_IRUGO,
};

static struct attribute sys_open_blocks_attr = {
	.name = "open_blks",
	.mode = S_IRUGO,
};

static struct attribute sys_bad_blocks_attr = {
	.name = "bad_blks",
	.mode = S_IRUGO,
};

static struct attribute sys_gc_blocks_attr = {
	.name = "gc_blks",
	.mode = S_IRUGO,
};

static struct attribute sys_rb_attr = {
	.name = "write_buffer",
	.mode = S_IRUGO,
};

static struct attribute sys_blk_meta_attr = {
	.name = "block_metadata",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_l2p_map_attr = {
	.name = "l2p_map",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_l2p_sanity_attr = {
	.name = "l2p_sanity",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_cleanup = {
	.name = "cleanup",
	.mode = S_IWUSR,
};
#endif

static struct attribute *pblk_attrs[] = {
	&sys_luns_active,
	&sys_consume_blocks,
	&sys_write_luns,
	&sys_rate_limiter_attr,
	&sys_errors_attr,
	&sys_gc_state,
	&sys_gc_force,
#ifdef CONFIG_NVM_DEBUG
	&sys_stats_debug_attr,
	&sys_blocks_attr,
	&sys_open_blocks_attr,
	&sys_bad_blocks_attr,
	&sys_gc_blocks_attr,
	&sys_rb_attr,
	&sys_blk_meta_attr,
	&sys_l2p_map_attr,
	&sys_l2p_sanity_attr,
	&sys_cleanup,
#endif
	NULL,
};

static ssize_t pblk_sysfs_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct pblk *pblk = container_of(kobj, struct pblk, kobj);

	if (strcmp(attr->name, "luns_active") == 0)
		return pblk_sysfs_luns_active_show(pblk, buf);
	else if (strcmp(attr->name, "write_luns") == 0)
		return pblk_sysfs_luns_show(pblk, buf);
	else if (strcmp(attr->name, "consume_blocks") == 0)
		return pblk_sysfs_consume_blocks_show(pblk, buf);
	else if (strcmp(attr->name, "rate_limiter") == 0)
		return pblk_sysfs_rate_limiter(pblk, buf);
	else if (strcmp(attr->name, "gc_state") == 0)
		return pblk_sysfs_gc_state_show(pblk, buf);
	else if (strcmp(attr->name, "errors") == 0)
		return pblk_sysfs_stats(pblk, buf);
#ifdef CONFIG_NVM_DEBUG
	else if (strcmp(attr->name, "stats") == 0)
		return pblk_sysfs_stats_debug(pblk, buf);
	else if (strcmp(attr->name, "blocks") == 0)
		return pblk_sysfs_blocks(pblk, buf);
	else if (strcmp(attr->name, "open_blks") == 0)
		return pblk_sysfs_open_blks(pblk, buf);
	else if (strcmp(attr->name, "bad_blks") == 0)
		return pblk_sysfs_bad_blks(pblk, buf);
	else if (strcmp(attr->name, "gc_blks") == 0)
		return pblk_sysfs_gc_blks(pblk, buf);
	else if (strcmp(attr->name, "write_buffer") == 0)
		return pblk_sysfs_write_buffer(pblk, buf);
#endif
	return 0;
}

static ssize_t pblk_sysfs_store(struct kobject *kobj, struct attribute *attr,
				const char *buf, size_t len)
{
	struct pblk *pblk = container_of(kobj, struct pblk, kobj);

	if (strcmp(attr->name, "luns_active") == 0)
		return pblk_sysfs_luns_active_store(pblk, buf, len);
	else if (strcmp(attr->name, "consume_blocks") == 0)
		return pblk_sysfs_consume_blocks_store(pblk, buf, len);
	else if (strcmp(attr->name, "rate_limiter") == 0)
		return pblk_sysfs_rate_store(pblk, buf, len);
	else if (strcmp(attr->name, "gc_state") == 0)
		return pblk_sysfs_gc_state_store(pblk, buf, len);
	else if (strcmp(attr->name, "gc_force") == 0)
		return pblk_sysfs_gc_force(pblk, buf, len);
#ifdef CONFIG_NVM_DEBUG
	else if (strcmp(attr->name, "l2p_map") == 0)
		return pblk_sysfs_l2p_map_print(pblk, buf, len);
	else if (strcmp(attr->name, "l2p_sanity") == 0)
		return pblk_sysfs_l2p_map_sanity(pblk, buf, len);
	else if (strcmp(attr->name, "block_metadata") == 0)
		return pblk_sysfs_block_meta(pblk, buf, len);
	else if (strcmp(attr->name, "cleanup") == 0)
		return pblk_sysfs_cleanup(pblk, buf, len);
#endif

	return 0;
}

static const struct sysfs_ops pblk_sysfs_ops = {
	.show = pblk_sysfs_show,
	.store = pblk_sysfs_store,
};

static struct kobj_type pblk_ktype = {
	.sysfs_ops	= &pblk_sysfs_ops,
	.default_attrs	= pblk_attrs,
};

int pblk_sysfs_init(struct gendisk *tdisk)
{
	struct pblk *pblk = tdisk->private_data;
	struct device *parent_dev = disk_to_dev(pblk->disk);
	int ret;

	ret = kobject_init_and_add(&pblk->kobj, &pblk_ktype,
					kobject_get(&parent_dev->kobj),
					"%s", "lightnvm");
	if (ret) {
		pr_err("pblk: could not register %s/lightnvm - name in use\n",
						tdisk->disk_name);
		return ret;
	}

	kobject_uevent(&pblk->kobj, KOBJ_ADD);
	return 0;
}

void pblk_sysfs_exit(struct pblk *pblk)
{
	kobject_uevent(&pblk->kobj, KOBJ_REMOVE);
	kobject_del(&pblk->kobj);
	kobject_put(&pblk->kobj);
}


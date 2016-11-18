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
 * Implementation of a physical block-device target for Open-channel SSDs.
 *
 * pblk-sysfs.c - pblk's sysfs
 *
 */

#include "pblk.h"

static ssize_t pblk_sysfs_luns_show(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun;
	ssize_t sz = 0;
	int i;

	for (i = 0; i < geo->nr_luns; i++) {
		int active = 1;

		rlun = &pblk->luns[i];
		if (!down_trylock(&rlun->wr_sem)) {
			active = 0;
			up(&rlun->wr_sem);
		}
		sz += sprintf(page + sz, "pblk: pos:%d, ch:%d, lun:%d - %d\n",
					i,
					rlun->bppa.g.ch,
					rlun->bppa.g.lun,
					active);
	}

	return sz;
}

static ssize_t pblk_sysfs_rate_limiter(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned long free_blocks, total_blocks;
	int rb_user_max, rb_user_cnt;
	int rb_gc_max, rb_gc_rsv, rb_gc_cnt, rb_budget;

	spin_lock(pblk->rl.lock);
	free_blocks = pblk->rl.free_blocks;
	rb_user_max = pblk->rl.rb_user_max;
	rb_user_cnt = pblk->rl.rb_user_cnt;
	rb_gc_max = pblk->rl.rb_gc_max;
	rb_gc_rsv = pblk->rl.rb_gc_rsv;
	rb_gc_cnt = pblk->rl.rb_gc_cnt;
	rb_budget = pblk->rl.rb_budget;
	spin_unlock(pblk->rl.lock);

	total_blocks = geo->blks_per_lun * geo->nr_luns;

	return sprintf(page,
		"u:%u/%u,gc:%u/%u/%u(%u)(stop:<%u,full:>%u,free:%lu/%lu)\n",
				rb_user_cnt,
				rb_user_max,
				rb_gc_cnt,
				rb_gc_max,
				rb_gc_rsv,
				rb_budget,
				1 << pblk->rl.low_pw,
				1 << pblk->rl.high_pw,
				free_blocks,
				total_blocks);
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

static ssize_t pblk_sysfs_write_buffer(struct pblk *pblk, char *page)
{
	return pblk_rb_sysfs(&pblk->rwb, page);
}

static ssize_t pblk_sysfs_ppaf(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	ssize_t sz = 0;

	sz = sprintf(page,
		"g:blk:%d/%d,pg:%d/%d,lun:%d/%d,ch:%d/%d,pl:%d/%d,sec:%d/%d\n",
		pblk->ppaf.blk_offset, geo->ppaf.blk_len,
		pblk->ppaf.pg_offset, geo->ppaf.pg_len,
		pblk->ppaf.lun_offset, geo->ppaf.lun_len,
		pblk->ppaf.ch_offset, geo->ppaf.ch_len,
		pblk->ppaf.pln_offset, geo->ppaf.pln_len,
		pblk->ppaf.sec_offset, geo->ppaf.sect_len);

	sz += sprintf(page + sz,
		"d:blk:%d/%d,pg:%d/%d,lun:%d/%d,ch:%d/%d,pl:%d/%d,sec:%d/%d\n",
		geo->ppaf.blk_offset, geo->ppaf.blk_len,
		geo->ppaf.pg_offset, geo->ppaf.pg_len,
		geo->ppaf.lun_offset, geo->ppaf.lun_len,
		geo->ppaf.ch_offset, geo->ppaf.ch_len,
		geo->ppaf.pln_offset, geo->ppaf.pln_len,
		geo->ppaf.sect_offset, geo->ppaf.sect_len);

	return sz;
}

static ssize_t pblk_sysfs_lines(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;
	ssize_t sz = 0;
	int nr_free_lines;
	int cur_data, cur_log;
	int free_line_cnt = 0, closed_line_cnt = 0;
	int d_line_cnt = 0, l_line_cnt = 0;
	int gc_full = 0, gc_high = 0, gc_mid = 0, gc_low = 0, gc_empty = 0;

	spin_lock(&l_mg->free_lock);
	cur_data = (l_mg->data_line) ? l_mg->data_line->id : -1;
	cur_log = (l_mg->log_line) ? l_mg->log_line->id : -1;
	nr_free_lines = l_mg->nr_free_lines;

	list_for_each_entry(line, &l_mg->free_list, list)
			free_line_cnt++;
	spin_unlock(&l_mg->free_lock);

	spin_lock(&l_mg->gc_lock);
	list_for_each_entry(line, &l_mg->gc_full_list, list) {
		if (line->type == PBLK_LINETYPE_DATA)
			d_line_cnt++;
		else if (line->type == PBLK_LINETYPE_LOG)
			l_line_cnt++;
		closed_line_cnt++;
		gc_full++;
	}

	list_for_each_entry(line, &l_mg->gc_high_list, list) {
		if (line->type == PBLK_LINETYPE_DATA)
			d_line_cnt++;
		else if (line->type == PBLK_LINETYPE_LOG)
			l_line_cnt++;
		closed_line_cnt++;
		gc_high++;
	}

	list_for_each_entry(line, &l_mg->gc_mid_list, list) {
		if (line->type == PBLK_LINETYPE_DATA)
			d_line_cnt++;
		else if (line->type == PBLK_LINETYPE_LOG)
			l_line_cnt++;
		closed_line_cnt++;
		gc_mid++;
	}

	list_for_each_entry(line, &l_mg->gc_low_list, list) {
		if (line->type == PBLK_LINETYPE_DATA)
			d_line_cnt++;
		else if (line->type == PBLK_LINETYPE_LOG)
			l_line_cnt++;
		closed_line_cnt++;
		gc_low++;
	}

	list_for_each_entry(line, &l_mg->gc_empty_list, list) {
		if (line->type == PBLK_LINETYPE_DATA)
			d_line_cnt++;
		else if (line->type == PBLK_LINETYPE_LOG)
			l_line_cnt++;
		closed_line_cnt++;
		gc_empty++;
	}
	spin_unlock(&l_mg->gc_lock);

	if (nr_free_lines != free_line_cnt)
		pr_err("pblk: corrupted free line list\n");

	sz = sprintf(page,
		"line: nluns:%d, nblks:%d, nsecs:%d\n",
		geo->nr_luns, lm->blk_per_line, lm->sec_per_line);

	sz += sprintf(page + sz,
		"lines:cur_d:%d,cur_l:%d - free:%d/%d, closed:%d(d:%d,l:%d)\n",
		cur_data, cur_log, nr_free_lines,
		l_mg->nr_lines, closed_line_cnt,
		d_line_cnt, l_line_cnt);

	sz += sprintf(page + sz,
		"lines GC: full:%d, high:%d, mid:%d, low:%d, empty:%d\n",
		gc_full, gc_high, gc_mid, gc_low, gc_empty);

	return sz;
}

static ssize_t pblk_sysfs_lines_info(struct pblk *pblk, char *page)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	ssize_t sz = 0;

	sz = sprintf(page, "smeta - len:%d, secs:%d\n",
					lm->smeta_len, lm->smeta_sec);
	sz += sprintf(page + sz, "emeta - len:%d, sec:%d, bb_start:%d\n",
					lm->emeta_len, lm->emeta_sec,
					lm->emeta_bb);
	sz += sprintf(page + sz, "bitmap lengths: sec:%d, blk:%d, lun:%d\n",
					lm->sec_bitmap_len,
					lm->blk_bitmap_len,
					lm->lun_bitmap_len);
	sz += sprintf(page + sz, "blk_line:%d, sec_line:%d, sec_blk:%d\n",
					lm->blk_per_line,
					lm->sec_per_line,
					geo->sec_per_blk);

	return sz;
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

static ssize_t pblk_sysfs_write_buffer_vb(struct pblk *pblk, char *page)
{
	return pblk_rb_sysfs_vb(&pblk->rwb, page);
}

enum {
	PBLK_SEE_ONLY_LINE_META = 0,
	PBLK_SEE_META_AND_LBAS = 1,
	PBLK_SEE_META_AND_LBAS_F = 3,
};

static void __pblk_sysfs_line_meta(struct pblk *pblk, struct pblk_line *line,
				   int cmd)
{
	u64 *lba_list;
	int ret;

	ret = pblk_line_read_smeta(pblk, line);
	if (ret) {
		pr_err("pblk: line %d read smeta failed (%d)\n", line->id, ret);
		return;
	}

	pr_info("pblk: smeta line: %d\n", line->id);
	pr_info("\tsmeta: id: %d\n", line->smeta->id);
	pr_info("\tsmeta: type: %d\n", line->smeta->line_type);
	pr_info("\tsmeta: seq_nr: %llu\n", line->smeta->seq_nr);
	pr_info("\tsmeta: slun: %d\n", line->smeta->slun);
	pr_info("\tsmeta: nr_luns: %d\n", line->smeta->nr_luns);
	pr_info("\tsmeta: p_id: %d\n", line->smeta->p_id);
	pr_info("\tsmeta: p_slun: %d\n", line->smeta->p_slun);
	pr_info("\tsmeta: smeta_len: %d\n", line->smeta->smeta_len);
	pr_info("\tsmeta: crc: %d\n", line->smeta->crc);

	ret = pblk_line_read_emeta(pblk, line);
	if (ret) {
		pr_err("pblk: line %d read emeta failed (%d)\n", line->id, ret);
		return;
	}

	pr_info("pblk: emeta line: %d\n", line->id);
	pr_info("\temeta: id: %d\n", line->emeta->id);
	pr_info("\temeta: type: %d\n", line->emeta->line_type);
	pr_info("\temeta: seq_nr: %llu\n", line->emeta->seq_nr);
	pr_info("\temeta: slun: %d\n", line->emeta->slun);
	pr_info("\temeta: nr_luns: %d\n", line->emeta->nr_luns);
	pr_info("\temeta: nr_lbas: %d\n", line->emeta->nr_lbas);
	pr_info("\temeta: n_id: %d\n", line->emeta->n_id);
	pr_info("\temeta: n_slun: %d\n", line->emeta->n_slun);
	pr_info("\temeta: emeta_len: %d\n", line->emeta->emeta_len);
	pr_info("\temeta: crc: %d\n", line->emeta->crc);

	lba_list = pblk_recov_get_lba_list(pblk, line->emeta);
	if (!lba_list) {
		pr_info("pblk: emeta CRC failed\n");
		if (cmd != PBLK_SEE_META_AND_LBAS_F)
			return;
	} else {
		pr_info("pblk: emeta CRC correct\n");
	}

	if (cmd & PBLK_SEE_META_AND_LBAS) {
		int i;

		for (i = 0; i < line->emeta->nr_lbas; i++) {
			pr_info("pblk: emeta lbas:\n");
			pr_info("\tpos:%d, lba:%llu\n", i, lba_list[i]);
		}
	}
}

static ssize_t pblk_sysfs_line_bb(struct pblk *pblk, const char *page,
				    ssize_t len)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;
	size_t c_len;
	int bit = -1;
	int nr_bbs;
	int line_id;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (sscanf(page, "%d", &line_id) != 1)
		return -EINVAL;

	if (line_id > l_mg->nr_lines) {
		pr_err("pblk: line %d out-of-bound (max: %d)\n",
				line_id, l_mg->nr_lines);
		return -EINVAL;
	}

	line = &pblk->lines[line_id];
	nr_bbs = bitmap_weight(line->blk_bitmap, lm->blk_per_line);

	pr_info("pblk: line %d, nr_bb:%d, smeta:%d, emeta:%d/%d\n",
				line->id, nr_bbs, lm->smeta_sec,
				lm->emeta_sec, lm->emeta_bb);
	while ((bit = find_next_bit(line->blk_bitmap, lm->blk_per_line,
					bit + 1)) < lm->blk_per_line)
		pr_info("bb: %d\n", bit);

	return len;
}

static ssize_t pblk_sysfs_line_meta(struct pblk *pblk, const char *page,
				    ssize_t len)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line *line;
	struct line_smeta *smeta;
	struct line_emeta *emeta;
	size_t c_len;
	int line_id, cmd;
	int cur_data = -1, cur_log = -1;

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (sscanf(page, "%d-%d", &line_id, &cmd) != 2)
		return -EINVAL;

	if (line_id > l_mg->nr_lines) {
		pr_err("pblk: line %d out-of-bound (max: %d)\n",
				line_id, l_mg->nr_lines);
		return -EINVAL;
	}

	smeta = pblk_malloc(lm->smeta_len, l_mg->smeta_alloc_type, GFP_KERNEL);
	if (!smeta)
		goto out;
	memset(smeta, 0, lm->smeta_len);

	emeta = pblk_malloc(lm->emeta_len, l_mg->emeta_alloc_type, GFP_KERNEL);
	if (!emeta)
		goto free_smeta;
	memset(emeta, 0, lm->emeta_len);

	if (line_id != -1) {
		line = &pblk->lines[line_id];
		spin_lock(&line->lock);
		if (line->type == PBLK_LINETYPE_FREE) {
			pr_info("pblk: line: %d is free\n", line->id);
			spin_unlock(&line->lock);
			goto free_emeta;
		} else if (line->type == PBLK_LINESTATE_BAD) {
			pr_info("pblk: line: %d is bad\n", line->id);
			spin_unlock(&line->lock);
			goto free_emeta;
		}
		spin_unlock(&line->lock);

		spin_lock(&l_mg->free_lock);
		if (l_mg->data_line)
			cur_data = l_mg->data_line->id;
		if (l_mg->log_line)
			cur_log = l_mg->log_line->id;
		spin_unlock(&l_mg->free_lock);

		pr_info("pblk: line: %d\t%d\t%d\t%d\t%d\t%d\n",
				line->id, line->seq_nr, line->vsc, line->state,
				line->type, line->gc_group);

		if (line->id == cur_data){
			pr_info("pblk: cannot read metadata (active data line)\n");
			goto free_emeta;
		} else if (line->id == cur_log) {
			pr_info("pblk: cannot read metadata (active log line)\n");
			goto free_emeta;
		}

		line->smeta = smeta;
		line->emeta = emeta;

		__pblk_sysfs_line_meta(pblk, line, cmd);
	} else {
		struct list_head *group_list;
		int i = 0;

		spin_lock(&l_mg->gc_lock);
		for (i = 0; i < PBLK_NR_GC_LISTS; i++){
			group_list = l_mg->gc_lists[i];
			list_for_each_entry(line, group_list, list) {
				spin_lock(&line->lock);
				if (line->type != PBLK_LINESTATE_CLOSED) {
					pr_info("pblk: line: %d corrupted\n",
								line->id);
					spin_unlock(&line->lock);
					continue;
				}
				spin_unlock(&line->lock);

				line->smeta = smeta;
				line->emeta = emeta;

				__pblk_sysfs_line_meta(pblk, line, cmd);
			}
		}
		spin_unlock(&l_mg->gc_lock);
	}

free_emeta:
	pblk_mfree(emeta, l_mg->emeta_alloc_type);
free_smeta:
	pblk_mfree(smeta, l_mg->smeta_alloc_type);
out:
	return len;
}
#endif

#if 0
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
#endif

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

	ret = pblk_rl_sysfs_rate_store(&pblk->rl, value);
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
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct bio *bio;
	struct ppa_addr ppa;
	struct nvm_rq rqd;
	struct pblk_sec_meta *meta_list;
	void *data;
	dma_addr_t dma_meta_list;
	sector_t lba_init, lba_end;
	sector_t i;
	size_t c_len;
	u64 lba;
	int ret;
	DECLARE_COMPLETION_ONSTACK(wait);

	c_len = strcspn(page, "\n");
	if (c_len >= len)
		return -EINVAL;

	if (sscanf(page, "%llu-%llu", (unsigned long long *)&lba_init,
					(unsigned long long *)&lba_end) != 2)
		return -EINVAL;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
	if (!meta_list)
		return -ENOMEM;

	data = kcalloc(pblk->max_write_pgs, geo->sec_size, GFP_KERNEL);
	if (!data)
		goto free_meta_list;

	for (i = lba_init; i < lba_end; i++) {
		ppa = pblk_get_lba_map(pblk, i);

		bio = bio_map_kern(dev->q, data, geo->sec_size, GFP_KERNEL);
		if (IS_ERR(bio))
			goto free_data;

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
		rqd.ppa_addr = ppa;
		rqd.dma_meta_list = dma_meta_list;
		rqd.end_io = NULL;

		ret = pblk_submit_io(pblk, &rqd);
		wait_for_completion_io(&wait);

		if (rqd.error || ret)
			lba = ADDR_EMPTY;
		else
			lba = meta_list[0].lba;

		if (ppa_empty(ppa)) {
			pr_info("pblk: lba:%lu - ppa: EMPTY ADDRESS\n", i);
		} else {
			if (ppa.c.is_cached) {
				pr_debug("pblk: lba:%lu - ppa: cacheline:%llu\n",
					i,
					(u64)ppa.c.line);

				continue;
			}

			pr_info("pblk: lba:%lu(%llu) - ppa: %llx: ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
				i, lba,
				ppa.ppa,
				ppa.g.ch,
				ppa.g.lun,
				ppa.g.blk,
				ppa.g.pg,
				ppa.g.pl,
				ppa.g.sec);
		}

		bio_put(bio);
	}

free_data:
	kfree(data);
free_meta_list:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);

	return len;
}

static ssize_t pblk_sysfs_l2p_map_sanity(struct pblk *pblk, const char *page,
					 ssize_t len)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	size_t c_len;
	struct ppa_addr ppa, l2p_ppa;
	void *read_sec;
	struct nvm_rq *rqd;
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
		l2p_ppa = pblk->trans_map[i];

		if (ppa.ppa == l2p_ppa.ppa)
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
	bio->bi_end_io = pblk_end_bio_sync;
	bio->bi_private = &wait;

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->meta_list = NULL;
	rqd->flags = pblk_set_read_mode(pblk);
	rqd->end_io = NULL;

	if (nvm_set_rqd_ppalist(dev->parent, rqd, &ppa, 1, 0)) {
		pr_err("pblk: could not set rqd ppa list\n");
		goto out;
	}

	if (pblk_submit_io(pblk, rqd)) {
		pr_err("pblk: I/O submission failed\n");
		nvm_free_rqd_ppalist(dev->parent, rqd);
		goto out;
	}
	wait_for_completion_io(&wait);

	if (rqd->error) {
		struct ppa_addr p;

		p = dev_to_generic_addr(pblk->dev, rqd->ppa_addr);
		pr_err("pblk: read failed (%u)\n", bio->bi_error);
		print_ppa(&p, "rqd", bio->bi_error);
		goto out;
	}

out:
	return len;
}
#endif

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

static struct attribute sys_rb_attr = {
	.name = "write_buffer",
	.mode = S_IRUGO,
};

static struct attribute sys_stats_ppaf_attr = {
	.name = "ppa_format",
	.mode = S_IRUGO,
};

static struct attribute sys_lines_attr = {
	.name = "lines",
	.mode = S_IRUGO,
};

static struct attribute sys_lines_info_attr = {
	.name = "lines_info",
	.mode = S_IRUGO,
};

#ifdef CONFIG_NVM_DEBUG
static struct attribute sys_stats_debug_attr = {
	.name = "stats",
	.mode = S_IRUGO,
};

static struct attribute sys_rb_vb_attr = {
	.name = "write_buffer_vb",
	.mode = S_IRUGO,
};

static struct attribute sys_line_meta_attr = {
	.name = "line_metadata",
	.mode = S_IRUGO | S_IWUSR,
};

static struct attribute sys_line_bb_attr = {
	.name = "line_bb",
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

#endif

static struct attribute *pblk_attrs[] = {
	&sys_write_luns,
	&sys_rate_limiter_attr,
	&sys_errors_attr,
	&sys_gc_state,
	&sys_gc_force,
	&sys_rb_attr,
	&sys_stats_ppaf_attr,
	&sys_lines_attr,
	&sys_lines_info_attr,
#ifdef CONFIG_NVM_DEBUG
	&sys_stats_debug_attr,
	&sys_rb_vb_attr,
	&sys_line_meta_attr,
	&sys_line_bb_attr,
	&sys_l2p_map_attr,
	&sys_l2p_sanity_attr,
#endif
	NULL,
};

static ssize_t pblk_sysfs_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct pblk *pblk = container_of(kobj, struct pblk, kobj);

	if (strcmp(attr->name, "rate_limiter") == 0)
		return pblk_sysfs_rate_limiter(pblk, buf);
	else if (strcmp(attr->name, "write_luns") == 0)
		return pblk_sysfs_luns_show(pblk, buf);
	else if (strcmp(attr->name, "gc_state") == 0)
		return pblk_sysfs_gc_state_show(pblk, buf);
	else if (strcmp(attr->name, "errors") == 0)
		return pblk_sysfs_stats(pblk, buf);
	else if (strcmp(attr->name, "write_buffer") == 0)
		return pblk_sysfs_write_buffer(pblk, buf);
	else if (strcmp(attr->name, "ppa_format") == 0)
		return pblk_sysfs_ppaf(pblk, buf);
	else if (strcmp(attr->name, "lines") == 0)
		return pblk_sysfs_lines(pblk, buf);
	else if (strcmp(attr->name, "lines_info") == 0)
		return pblk_sysfs_lines_info(pblk, buf);
#ifdef CONFIG_NVM_DEBUG
	else if (strcmp(attr->name, "stats") == 0)
		return pblk_sysfs_stats_debug(pblk, buf);
	else if (strcmp(attr->name, "write_buffer_vb") == 0)
		return pblk_sysfs_write_buffer_vb(pblk, buf);
#endif
	return 0;
}

static ssize_t pblk_sysfs_store(struct kobject *kobj, struct attribute *attr,
				const char *buf, size_t len)
{
	struct pblk *pblk = container_of(kobj, struct pblk, kobj);

	if (strcmp(attr->name, "rate_limiter") == 0)
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
	else if (strcmp(attr->name, "line_metadata") == 0)
		return pblk_sysfs_line_meta(pblk, buf, len);
	else if (strcmp(attr->name, "line_bb") == 0)
		return pblk_sysfs_line_bb(pblk, buf, len);
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
					"%s", "pblk");
	if (ret) {
		pr_err("pblk: could not register %s/pblk\n",
						tdisk->disk_name);
		return ret;
	}

	kobject_uevent(&pblk->kobj, KOBJ_ADD);
	return 0;
}

void pblk_sysfs_exit(void *tt)
{
	struct pblk *pblk = tt;

	kobject_uevent(&pblk->kobj, KOBJ_REMOVE);
	kobject_del(&pblk->kobj);
	kobject_put(&pblk->kobj);
}


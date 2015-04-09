/*
 * blk-nvm.c - Block layer Open-channel SSD integration
 *
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mabj@itu.dk>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/sem.h>
#include <linux/bitmap.h>

#include <linux/nvm.h>

#include "blk.h"

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

struct nvm_target_type *nvm_find_target_type(const char *name)
{
	struct nvm_target_type *tt;

	list_for_each_entry(tt, &_targets, list)
		if (!strcmp(name, tt->name))
			return tt;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *tt)
{
	int ret = 0;

	down_write(&_lock);
	if (nvm_find_target_type(tt->name))
		ret = -EEXIST;
	else
		list_add(&tt->list, &_targets);
	up_write(&_lock);

	return ret;
}

void nvm_unregister_target(struct nvm_target_type *tt)
{
	if (!tt)
		return;

	down_write(&_lock);
	list_del(&tt->list);
	up_write(&_lock);
}

static void nvm_reset_block(struct nvm_dev *dev, struct nvm_block *block)
{
	spin_lock(&block->lock);
	bitmap_zero(block->invalid_pages, dev->nr_pages_per_blk);
	block->next_page = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->data_cmnt_size, 0);
	spin_unlock(&block->lock);
}

/* use blk_nvm_lun_[get/put]_block to administer the blocks in use for each lun.
 * Whenever a block is in used by an append point, we store it within the
 * used_list. We then move it back when its free to be used by another append
 * point.
 *
 * The newly claimed block is always added to the back of used_list. As we
 * assume that the start of used list is the oldest block, and therefore
 * more likely to contain invalidated pages.
 */
struct nvm_block *blk_nvm_get_blk(struct nvm_lun *lun, int is_gc)
{
	struct nvm_dev *dev;
	struct nvm_block *block = NULL;

	BUG_ON(!lun);

	dev = lun->dev;
	spin_lock(&lun->lock);

	if (list_empty(&lun->free_list)) {
		pr_err_ratelimited("nvm: lun %u have no free pages available",
								lun->id);
		spin_unlock(&lun->lock);
		goto out;
	}

	while (!is_gc && lun->nr_free_blocks < lun->reserved_blocks) {
		spin_unlock(&lun->lock);
		goto out;
	}

	block = list_first_entry(&lun->free_list, struct nvm_block, list);
	list_move_tail(&block->list, &lun->used_list);

	lun->nr_free_blocks--;

	spin_unlock(&lun->lock);

	nvm_reset_block(dev, block);

out:
	return block;
}
EXPORT_SYMBOL(blk_nvm_get_blk);

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void blk_nvm_put_blk(struct nvm_block *block)
{
	struct nvm_lun *lun = block->lun;

	spin_lock(&lun->lock);

	list_move_tail(&block->list, &lun->free_list);
	lun->nr_free_blocks++;

	spin_unlock(&lun->lock);
}
EXPORT_SYMBOL(blk_nvm_put_blk);

sector_t blk_nvm_alloc_addr(struct nvm_block *block)
{
	sector_t addr = ADDR_EMPTY;

	spin_lock(&block->lock);
	if (block_is_full(block))
		goto out;

	addr = block_to_addr(block) + block->next_page;

	block->next_page++;
out:
	spin_unlock(&block->lock);
	return addr;
}
EXPORT_SYMBOL(blk_nvm_alloc_addr);

/* Send erase command to device */
int blk_nvm_erase_blk(struct nvm_dev *dev, struct nvm_block *block)
{
	if (dev->ops->erase_block)
		return dev->ops->erase_block(dev->q, block->id);

	return 0;
}
EXPORT_SYMBOL(blk_nvm_erase_blk);


static void nvm_luns_free(struct nvm_dev *dev)
{
	struct nvm_lun *lun;
	int i;

	nvm_for_each_lun(dev, lun, i) {
		if (!lun->blocks)
			break;
		vfree(lun->blocks);
	}

	kfree(dev->luns);
}

static int nvm_luns_init(struct nvm_dev *dev)
{
	struct nvm_lun *lun;
	struct nvm_id_chnl *chnl;
	int i;

	dev->luns = kcalloc(dev->nr_luns, sizeof(struct nvm_lun), GFP_KERNEL);
	if (!dev->luns)
		return -ENOMEM;

	nvm_for_each_lun(dev, lun, i) {
		chnl = &dev->identity.chnls[i];
		pr_info("nvm: p %u qsize %u gr %u ge %u begin %llu end %llu\n",
			i, chnl->queue_size, chnl->gran_read, chnl->gran_erase,
			chnl->laddr_begin, chnl->laddr_end);

		spin_lock_init(&lun->lock);

		INIT_LIST_HEAD(&lun->free_list);
		INIT_LIST_HEAD(&lun->used_list);

		lun->id = i;
		lun->dev = dev;
		lun->chnl = chnl;
		lun->reserved_blocks = 2; /* for GC only */
		lun->nr_free_blocks = lun->nr_blocks =
				(chnl->laddr_end - chnl->laddr_begin + 1) /
				(chnl->gran_erase / chnl->gran_read);

		dev->total_blocks += lun->nr_blocks;
		/* TODO: make blks per lun variable among luns */
		dev->nr_blks_per_lun = lun->nr_free_blocks;
		dev->nr_pages_per_blk = chnl->gran_erase / chnl->gran_write *
					(chnl->gran_write / dev->sector_size);
		lun->nr_pages_per_blk = dev->nr_pages_per_blk;
	}

	return 0;
}

static int nvm_block_map(u64 slba, u64 nlb, u64 *entries, void *private)
{
	struct nvm_dev *dev = private;
	sector_t max_pages = dev->nr_pages * (dev->sector_size >> 9);
	u64 elba = slba + nlb;
	struct nvm_lun *lun;
	struct nvm_block *blk;
	sector_t total_blks_per_lun;
	u64 i;
	int lun_id;

	if (unlikely(elba > dev->nr_pages)) {
		pr_err("nvm: L2P data from device is out of bounds!\n");
		return -EINVAL;
	}

	total_blks_per_lun = dev->nr_blks_per_lun * dev->nr_pages_per_blk;

	for (i = 0; i < nlb; i++) {
		u64 pba = le64_to_cpu(entries[i]);

		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("nvm: L2P data entry is out of bounds!\n");
			return -EINVAL;
		}

		/* Address zero is a special one. The first page on a disk is
		 * protected. As it often holds internal device boot
		 * information. */
		if (!pba)
			continue;

		/* resolve block from physical address */
		lun_id = pba / total_blks_per_lun;
		lun = &dev->luns[lun_id];

		/* Calculate block offset into lun */
		pba = pba - (total_blks_per_lun * lun_id);
		blk = &lun->blocks[pba / dev->nr_pages_per_blk];

		if (!blk->type) {
			/* at this point, we don't know anything about the
			 * block. It's up to the FTL on top to re-etablish the
			 * block state */
			list_move_tail(&blk->list, &lun->used_list);
			blk->type = 1;
			lun->nr_free_blocks--;
		}
	}

	return 0;
}

static int nvm_blocks_init(struct nvm_dev *dev)
{
	struct nvm_lun *lun;
	struct nvm_block *block;
	sector_t lun_iter, block_iter, cur_block_id = 0;
	int ret;

	nvm_for_each_lun(dev, lun, lun_iter) {
		lun->blocks = vzalloc(sizeof(struct nvm_block) *
						lun->nr_blocks);
		if (!lun->blocks)
			return -ENOMEM;

		lun_for_each_block(lun, block, block_iter) {
			spin_lock_init(&block->lock);
			INIT_LIST_HEAD(&block->list);

			block->lun = lun;
			block->id = cur_block_id++;

			/* First block is reserved for device */
			if (unlikely(lun_iter == 0 && block_iter == 0))
				continue;

			list_add_tail(&block->list, &lun->free_list);
		}
	}

	/* Without bad block table support, we can use the mapping table to get
	   restore the state of each block. */
	if (dev->ops->get_l2p_tbl) {
		ret = dev->ops->get_l2p_tbl(dev->q, 0, dev->nr_pages,
							nvm_block_map, dev);
		if (ret) {
			pr_err("nvm: could not read L2P table.\n");
			pr_warn("nvm: default block initialization");
		}
	}

	return 0;
}

static void nvm_core_free(struct nvm_dev *dev)
{
	kfree(dev);
}

static int nvm_core_init(struct nvm_dev *dev, int max_qdepth)
{
	dev->nr_luns = dev->identity.nchannels;
	dev->sector_size = EXPOSED_PAGE_SIZE;
	INIT_LIST_HEAD(&dev->online_targets);

	return 0;
}

void nvm_free_nvm_id(struct nvm_id *id)
{
	kfree(id->chnls);
}

static void nvm_free(struct nvm_dev *dev)
{
	if (!dev)
		return;

	/* also frees blocks */
	nvm_luns_free(dev);

	nvm_free_nvm_id(&dev->identity);

	nvm_core_free(dev);
}

int nvm_validate_features(struct nvm_dev *dev)
{
	struct nvm_get_features gf;
	int ret;

	ret = dev->ops->get_features(dev->q, &gf);
	if (ret)
		return ret;

	/* Only default configuration is supported.
	 * I.e. L2P, No ondrive GC and drive performs ECC */
	if (gf.rsp != 0 || gf.ext != 0)
		return -EINVAL;

	return 0;
}

int nvm_validate_responsibility(struct nvm_dev *dev)
{
	if (!dev->ops->set_responsibility)
		return 0;

	return dev->ops->set_responsibility(dev->q, 0);
}

int nvm_init(struct nvm_dev *dev)
{
	struct blk_mq_tag_set *tag_set = dev->q->tag_set;
	int max_qdepth;
	int ret = 0;

	if (!dev->q || !dev->ops)
		return -EINVAL;

	/* TODO: We're limited to the same setup for each channel */
	if (dev->ops->identify(dev->q, &dev->identity)) {
		pr_err("nvm: device could not be identified\n");
		ret = -EINVAL;
		goto err;
	}

	max_qdepth = tag_set->queue_depth * tag_set->nr_hw_queues;

	pr_debug("nvm dev: ver %u type %u chnls %u max qdepth: %i\n",
			dev->identity.ver_id,
			dev->identity.nvm_type,
			dev->identity.nchannels,
			max_qdepth);

	ret = nvm_validate_features(dev);
	if (ret) {
		pr_err("nvm: disk features are not supported.");
		goto err;
	}

	ret = nvm_validate_responsibility(dev);
	if (ret) {
		pr_err("nvm: disk responsibilities are not supported.");
		goto err;
	}

	ret = nvm_core_init(dev, max_qdepth);
	if (ret) {
		pr_err("nvm: could not initialize core structures.\n");
		goto err;
	}

	ret = nvm_luns_init(dev);
	if (ret) {
		pr_err("nvm: could not initialize luns\n");
		goto err;
	}

	/* s->nr_pages_per_blk obtained from nvm_luns_init */
	if (dev->nr_pages_per_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("nvm: number of pages per block too high.");
		ret = -EINVAL;
		goto err;
	}
	dev->nr_pages = dev->nr_luns * dev->nr_blks_per_lun *
							dev->nr_pages_per_blk;

	ret = nvm_blocks_init(dev);
	if (ret) {
		pr_err("nvm: could not initialize blocks\n");
		goto err;
	}

	pr_info("nvm: allocating %lu physical pages (%lu KB)\n",
			dev->nr_pages, dev->nr_pages * dev->sector_size / 1024);
	pr_info("nvm: luns: %u\n", dev->nr_luns);
	pr_info("nvm: blocks: %u\n", dev->nr_blks_per_lun);
	pr_info("nvm: target sector size=%d\n", dev->sector_size);
	pr_info("nvm: pages per block: %u\n", dev->nr_pages_per_blk);

	return 0;
err:
	nvm_free(dev);
	pr_err("nvm: failed to initialize nvm\n");
	return ret;
}

void nvm_exit(struct nvm_dev *dev)
{
	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_free(dev);

	pr_info("nvm: successfully unloaded\n");
}

int blk_nvm_register(struct request_queue *q, struct nvm_dev_ops *ops)
{
	struct nvm_dev *dev;
	int ret;

	if (!ops->identify || !ops->get_features)
		return -EINVAL;

	/* TODO: NVM does not yet support multi-page IOs. */
	blk_queue_max_hw_sectors(q, queue_logical_block_size(q) >> 9);

	dev = kmalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->q = q;
	dev->ops = ops;

	ret = nvm_init(dev);
	if (ret)
		goto err_init;

	q->nvm = dev;

	return 0;
err_init:
	kfree(dev);
	return ret;
}
EXPORT_SYMBOL(blk_nvm_register);

void blk_nvm_unregister(struct request_queue *q)
{
	if (!blk_queue_nvm(q))
		return;

	nvm_exit(q->nvm);
}

static int nvm_create_target(struct gendisk *qdisk, char *ttname, char *tname,
						int lun_begin, int lun_end)
{
	struct request_queue *qqueue = qdisk->queue;
	struct nvm_dev *qnvm = qqueue->nvm;
	struct request_queue *tqueue;
	struct gendisk *tdisk;
	struct nvm_target_type *tt;
	struct nvm_target *t;
	void *targetdata;

	tt = nvm_find_target_type(ttname);
	if (!tt) {
		pr_err("nvm: target type %s not found\n", ttname);
		return -EINVAL;
	}

	down_write(&_lock);
	list_for_each_entry(t, &qnvm->online_targets, list) {
		if (!strcmp(tname, t->disk->disk_name)) {
			pr_err("nvm: target name already exists.\n");
			up_write(&_lock);
			return -EINVAL;
		}
	}
	up_write(&_lock);

	t = kmalloc(sizeof(struct nvm_target), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	tqueue = blk_alloc_queue_node(GFP_KERNEL, qqueue->node);
	if (!tqueue)
		goto err_t;
	blk_queue_make_request(tqueue, tt->make_rq);

	targetdata = tt->init(qqueue, tqueue, qdisk, lun_begin, lun_end);
	if (IS_ERR(targetdata))
		goto err_queue;

	tdisk = alloc_disk(0);
	if (!tdisk)
		goto err_init;

	tqueue->queuedata = targetdata;

	blk_queue_prep_rq(qqueue, tt->prep_rq);
	blk_queue_unprep_rq(qqueue, tt->unprep_rq);

	sprintf(tdisk->disk_name, "%s", tname);
	tdisk->flags = GENHD_FL_EXT_DEVT;
	tdisk->major = 0;
	tdisk->first_minor = 0;
        tdisk->fops = qdisk->fops;
	tdisk->private_data = targetdata;
	tdisk->queue = tqueue;

	set_capacity(tdisk, tt->capacity(targetdata));
	add_disk(tdisk);

	t->type = tt;
	t->disk = tdisk;

	down_write(&_lock);
	list_add_tail(&t->list, &qnvm->online_targets);
	up_write(&_lock);

	return 0;
err_init:
	tt->exit(targetdata);
err_queue:
	blk_cleanup_queue(tqueue);
err_t:
	kfree(t);
	return -ENOMEM;
}

/* _lock must be taken */
static void nvm_remove_target(struct nvm_target *t)
{
	struct nvm_target_type *tt = t->type;
	struct gendisk *tdisk = t->disk;
	struct request_queue *q = tdisk->queue;

	del_gendisk(tdisk);
	if (tt->exit)
		tt->exit(tdisk->private_data);
	blk_cleanup_queue(q);

	put_disk(tdisk);

	list_del(&t->list);
	kfree(t);
}

static ssize_t free_blocks_show(struct device *d, struct device_attribute *attr,
		char *page)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->queue->nvm;

	char *page_start = page;
	struct nvm_lun *lun;
	unsigned int i;

	nvm_for_each_lun(dev, lun, i)
		page += sprintf(page, "%8u\t%u\n", i, lun->nr_free_blocks);

	return page - page_start;
}

DEVICE_ATTR_RO(free_blocks);

static ssize_t configure_store(struct device *d, struct device_attribute *attr,
						const char *buf, size_t cnt)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->queue->nvm;
	char name[255], ttname[255];
	int lun_begin, lun_end, ret;

	if (cnt >= 255)
		return -EINVAL;

	ret = sscanf(buf, "%s %s %u:%u", name, ttname, &lun_begin, &lun_end);
	if (ret != 4) {
		pr_err("nvm: configure must be in the format of \"name targetname lun_begin:lun_end\".\n");
		return -EINVAL;
	}

	if (lun_begin > lun_end || lun_end > dev->nr_luns) {
		pr_err("nvm: lun out of bound (%u:%u > %u)\n",
					lun_begin, lun_end, dev->nr_luns);
		return -EINVAL;
	}

	ret = nvm_create_target(disk, name, ttname, lun_begin, lun_end);
	if (ret)
		pr_err("nvm: configure disk failed\n");

	return cnt;
}
DEVICE_ATTR_WO(configure);

static ssize_t remove_store(struct device *d, struct device_attribute *attr,
						const char *buf, size_t cnt)
{
	struct gendisk *disk = dev_to_disk(d);
	struct nvm_dev *dev = disk->queue->nvm;
	struct nvm_target *t = NULL;
	char tname[255];
	int ret;

	if (cnt >= 255)
		return -EINVAL;

	ret = sscanf(buf, "%s", tname);
	if (ret != 1) {
		pr_err("nvm: remove use the following format \"targetname\".\n");
		return -EINVAL;
	}

	down_write(&_lock);
	list_for_each_entry(t, &dev->online_targets, list) {
		if (!strcmp(tname, t->disk->disk_name)) {
			nvm_remove_target(t);
			ret = 0;
			break;
		}
	}
	up_write(&_lock);

	if (ret)
		pr_err("nvm: target \"%s\" doesn't exist.\n", tname);

	return cnt;
}

DEVICE_ATTR_WO(remove);

static struct attribute *nvm_attrs[] = {
	&dev_attr_free_blocks.attr,
	&dev_attr_configure.attr,
	&dev_attr_remove.attr,
	NULL,
};

static struct attribute_group nvm_attribute_group = {
	.name = "nvm",
	.attrs = nvm_attrs,
};

int blk_nvm_init_sysfs(struct device *dev)
{
	int ret;

	ret = sysfs_create_group(&dev->kobj, &nvm_attribute_group);
	if (ret)
		return ret;

	kobject_uevent(&dev->kobj, KOBJ_CHANGE);

	return 0;
}

void blk_nvm_remove_sysfs(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &nvm_attribute_group);
}

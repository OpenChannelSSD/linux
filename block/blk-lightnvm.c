/*
 * blk-lightnvm.c - Block layer LightNVM Open-channel SSD integration
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

#include <linux/lightnvm.h>

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

/* use lun_[get/put]_block to administer the blocks in use for each lun.
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
		pr_err_ratelimited("lightnvm: lun %u have no free pages available",
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
		pr_info("lightnvm: p %u qsize %u gr %u ge %u begin %llu end %llu\n",
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

		/* TODO: Global values derived from variable size luns */
		dev->total_blocks += lun->nr_blocks;
		/* TODO: make blks per lun variable amond channels */
		dev->nr_blks_per_lun = lun->nr_free_blocks;
		/* TODO: gran_{read,write} may differ */
		dev->nr_pages_per_blk = chnl->gran_erase / chnl->gran_read *
					(chnl->gran_read / dev->sector_size);
		lun->nr_pages_per_blk = dev->nr_pages_per_blk;
	}

	return 0;
}

/*
 * Looks up the logical address from reverse trans map and check if its valid by
 * comparing the logical to physical address with the physical address.
 * Returns 0 on free, otherwise 1 if in use
 */
static int nvm_block_map(struct nvm_dev *dev, struct nvm_block *block)
{
	int offset, used = 0;
	struct nvm_addr *laddr;
	sector_t paddr, pladdr;

	for (offset = 0; offset < dev->nr_pages_per_blk; offset++) {
		paddr = block_to_addr(block) + offset;

		/* FIXME */
	//	laddr = s->mgmt_target->nvm_map_get_addr(s->mgmt_data, paddr);
	//	if (!laddr)
	//		continue;

/*		if (paddr == laddr->addr) {
			laddr->block = block;
		} else {
			set_bit(offset, block->invalid_pages);
			block->nr_invalid_pages++;
		}

		used = 1;
		*/
	}

	return used;
}

static int nvm_blocks_init(struct nvm_dev *dev)
{
	struct nvm_lun *lun;
	struct nvm_block *block;
	sector_t lun_iter, block_iter, cur_block_id = 0;

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

			if (nvm_block_map(dev, block))
				list_add_tail(&block->list, &lun->used_list);
			else
				list_add_tail(&block->list, &lun->free_list);
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

	return 0;
}

static int nvm_l2p_update(u64 slba, u64 nlb, u64 *entries, void *private)
{
	struct nvm_dev *dev = (struct nvm_dev *)private;
	sector_t max_pages = dev->nr_pages * (dev->sector_size >> 9);
	u64 elba = slba + nlb;
	u64 i;

	if (unlikely(elba > dev->nr_pages)) {
		pr_err("lightnvm: L2P data from device is out of bounds!\n");
		return -EINVAL;
	}

	for (i = 0; i < nlb; i++) {
		/* notice that the values are 1-indexed. 0 is unmapped */
		u64 pba = le64_to_cpu(entries[i]);
		/* LNVM treats address-spaces as silos, LBA and PBA are
		 * equally large and zero-indexed. */
		if (unlikely(pba >= max_pages && pba != U64_MAX)) {
			pr_err("lightnvm: L2P data entry is out of bounds!\n");
			return -EINVAL;
		}

		if (!pba)
			continue;

		/* FIXME */
		//if (s->mgmt_target->update_map(s->mgmtdata, slba, pba - 1, i))
		//	return -EINVAL;
	}

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
	int max_qdepth;
	struct blk_mq_tag_set *tag_set = dev->q->tag_set;
	int ret = 0;

	if (!dev->q || !dev->ops)
		return -EINVAL;

	/* TODO: We're limited to the same setup for each channel */
	if (dev->ops->identify(dev->q, &dev->identity)) {
		pr_err("lightnvm: device could not be identified\n");
		ret = -EINVAL;
		goto err;
	}

	max_qdepth = tag_set->queue_depth * tag_set->nr_hw_queues;

	pr_debug("lightnvm dev: ver %u type %u chnls %u max qdepth: %i\n",
			dev->identity.ver_id,
			dev->identity.nvm_type,
			dev->identity.nchannels,
			max_qdepth);

	ret = nvm_validate_features(dev);
	if (ret) {
		pr_err("lightnvm: disk features are not supported.");
		goto err;
	}

	ret = nvm_validate_responsibility(dev);
	if (ret) {
		pr_err("lightnvm: disk responsibilities are not supported.");
		goto err;
	}

	ret = nvm_core_init(dev, max_qdepth);
	if (ret) {
		pr_err("lightnvm: could not initialize core structure.\n");
		goto err;
	}

	ret = nvm_luns_init(dev);
	if (ret) {
		pr_err("lightnvm: could not initialize luns\n");
		goto err;
	}

	/* s->nr_pages_per_blk obtained from nvm_luns_init */
	if (dev->nr_pages_per_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: number of pages per block too high.");
		ret = -EINVAL;
		goto err;
	}
	dev->nr_pages = dev->nr_luns * dev->nr_blks_per_lun *
							dev->nr_pages_per_blk;

	if (dev->ops->get_l2p_tbl) {
		ret = dev->ops->get_l2p_tbl(dev->q, 0, dev->nr_pages,
							nvm_l2p_update, dev);
		if (ret) {
			pr_err("lightnvm: could not read L2P table.\n");
			goto err;
		}
	}

	ret = nvm_blocks_init(dev);
	if (ret) {
		pr_err("lightnvm: could not initialize blocks\n");
		goto err;
	}

	pr_info("lightnvm: allocating %lu physical pages (%lu KB)\n",
			dev->nr_pages, dev->nr_pages * dev->sector_size / 1024);
	pr_info("lightnvm: luns: %u\n", dev->nr_luns);
	pr_info("lightnvm: blocks: %u\n", dev->nr_blks_per_lun);
	pr_info("lightnvm: target sector size=%d\n", dev->sector_size);
	pr_info("lightnvm: pages per block: %u\n", dev->nr_pages_per_blk);

	/* Enable garbage collection timer */
/*	mod_timer(&dev->gc_timer, jiffies + msecs_to_jiffies(1000));*/

	return 0;
err:
	nvm_free(dev);
	pr_err("lightnvm: failed to initialize nvm\n");
	return ret;
}

void nvm_exit(struct nvm_dev *dev)
{
	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_free(dev);

	pr_info("lightnvm: successfully unloaded\n");
}

int blk_lightnvm_register(struct request_queue *q, struct lightnvm_dev_ops *ops)
{
	struct nvm_dev *dev;
	int ret;

	if (!ops->identify || !ops->get_features)
		return -EINVAL;

	/* TODO: LightNVM does not yet support multi-page IOs. */
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
EXPORT_SYMBOL(blk_lightnvm_register);

void blk_nvm_unregister(struct request_queue *q)
{
	if (!blk_queue_lightnvm(q))
		return;

	nvm_exit(q->nvm);
}

static int nvm_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	return 0;
}

#ifdef CONFIG_COMPAT
static int nvm_compat_ioctl(struct block_device *bdev, fmode_t mode,
					unsigned int cmd, unsigned long arg)
{
	return 0;
}
#else
#define nvme_compat_ioctl	NULL
#endif

static int nvm_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void nvm_release(struct gendisk *disk, fmode_t mode)
{
	return;
}

static const struct block_device_operations nvm_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= nvm_ioctl,
	.compat_ioctl	= nvm_compat_ioctl,
	.open		= nvm_open,
	.release	= nvm_release,
};

static int nvm_create_disk(struct gendisk *qdisk, char *ttname, char *devname,
						int lun_begin, int lun_end)
{
	struct gendisk *disk;
	struct request_queue *q, *qnvm = qdisk->queue;
	struct nvm_target_type *tt;
	void *target;

	tt = nvm_find_target_type(ttname);
	if (!tt) {
		pr_err("lightnvm: target type %s not found\n", ttname);
		return -EINVAL;
	}

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	target = tt->init(qnvm, qdisk);
	if (IS_ERR(target)) {
		blk_cleanup_queue(q);
		return -ENOMEM;
	}

	disk = alloc_disk(0);
	if (!disk) {
		tt->exit(target);
		blk_cleanup_queue(q);
		return -ENOMEM;
	}

	q->queuedata = target;
	blk_queue_make_request(q, tt->make_rq);
	blk_queue_prep_rq(qnvm, tt->prep_rq);
	blk_queue_unprep_rq(qnvm, tt->unprep_rq);

	sprintf(disk->disk_name, "%s", devname);
	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major = 0;
	disk->first_minor = 0;
	disk->fops = &nvm_fops;
	disk->private_data = target;
	disk->queue = q;

	set_capacity(disk, tt->capacity(target));

	add_disk(disk);

	return 0;
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
		pr_err("lightnvm: configure must be in the format of \"name targetname lun_begin:lun_end\".\n");
		return -EINVAL;
	}

	if (lun_begin > lun_end || lun_end > dev->nr_luns) {
		pr_err("lightnvm: lun out of bound (%u:%u > %u)\n",
					lun_begin, lun_end, dev->nr_luns);
		return -EINVAL;
	}

	ret = nvm_create_disk(disk, name, ttname, lun_begin, lun_end);
	if (ret)
		pr_err("lightnvm: configure disk failed\n");

	return cnt;
}

DEVICE_ATTR_WO(configure);

static struct attribute *nvm_attrs[] = {
	&dev_attr_free_blocks.attr,
	&dev_attr_configure.attr,
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

#ifndef LIGHTNVM_H
#define LIGHTNVM_H

#include <linux/blkdev.h>
#include <linux/types.h>

#define nvm_for_each_lun(dev, lun, i) \
		for ((i) = 0, lun = &(dev)->luns[0]; \
			(i) < (dev)->nr_luns; (i)++, lun = &(dev)->luns[(i)])

#define lun_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

#define block_for_each_page(b, p) \
		for ((p)->addr = block_to_addr((b)), (p)->block = (b); \
			(p)->addr < block_to_addr((b)) \
				+ (b)->lun->dev->nr_pages_per_blk; \
			(p)->addr++)

/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */
#define NVM_SECTOR 512
#define EXPOSED_PAGE_SIZE 4096

#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / NVM_SECTOR)

#define NVM_MSG_PREFIX "nvm"
#define ADDR_EMPTY (~0ULL)
#define LTOP_POISON 0xD3ADB33F

/* core.c */

static inline int block_is_full(struct nvm_block *block)
{
	struct nvm_dev *dev = block->lun->dev;

	return block->next_page == dev->nr_pages_per_blk;
}

static inline sector_t block_to_addr(struct nvm_block *block)
{
	struct nvm_dev *dev = block->lun->dev;

	return block->id * dev->nr_pages_per_blk;
}

static inline struct nvm_lun *paddr_to_lun(struct nvm_dev *dev,
							sector_t p_addr)
{
	return &dev->luns[p_addr / (dev->nr_pages / dev->nr_luns)];
}

static inline int physical_to_slot(struct nvm_dev *dev, sector_t phys)
{
	return phys % dev->nr_pages_per_blk;
}

#endif

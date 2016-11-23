/*
 * Copyright (C) 2015 IT University of Copenhagen (rrpc.h)
 * Initial release: Matias Bjorling <m@bjorling.me>
 * Write buffering: Javier Gonzalez <jg@lightnvm.io>
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
 * Implementation of a Physical Block-device target for Open-channel SSDs.
 *
 * Derived from rrpc.h
 */

#ifndef PBLK_H_
#define PBLK_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/crc32.h>

#include <linux/lightnvm.h>

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 5
#define GC_TIME_MSECS 5000

#define PBLK_SECTOR (512)
#define PBLK_EXPOSED_PAGE_SIZE (4096)
#define PBLK_MAX_REQ_ADDRS (64)
#define PBLK_MAX_REQ_ADDRS_PW (6)

/* Max 512 LUNs per device */
#define PBLK_MAX_LUNS_BITMAP (4)

#define NR_PHY_IN_LOG (PBLK_EXPOSED_PAGE_SIZE / PBLK_SECTOR)

#define pblk_for_each_lun(pblk, rlun, i) \
		for ((i) = 0, rlun = &(pblk)->luns[0]; \
			(i) < (pblk)->nr_luns; (i)++, rlun = &(pblk)->luns[(i)])

#define ERASE 2 /* READ = 0, WRITE = 1 */

enum {
	/* IO Types */
	PBLK_IOTYPE_USER = 1,
	PBLK_IOTYPE_GC = 2,
	PBLK_IOTYPE_SYNC = 4,
	PBLK_IOTYPE_CLOSE_BLK = 8,
	PBLK_IOTYPE_REF = 16,

	/* Write buffer flags */
	PBLK_WRITTEN_DATA = 128,
	PBLK_WRITABLE_ENTRY = 256,
};

enum {
	PBLK_BLK_ST_OPEN =	0x1,
	PBLK_BLK_ST_CLOSED =	0x2,
};

struct pblk_sec_meta {
	u64 lba;
	u64 reserved;
};

/* Buffer allocated after counter */
struct pblk_kref_buf {
	struct kref ref;
	void *data;
};

/* Logical to physical mapping */
struct pblk_addr {
	struct ppa_addr ppa;		/* cacheline OR physical address */
	struct pblk_block *rblk;	/* reference to pblk block for lookup */
};

/* Completion context */
struct pblk_compl_ctx {
	unsigned int sentry;
	unsigned int nr_valid;
	unsigned int nr_padded;
};

struct pblk_compl_close_ctx {
	struct pblk_block *rblk;	/* reference to pblk block for lookup */
};

struct pblk_ctx {
	struct list_head list;		/* Head for out-of-order completion */
	void *c_ctx;			/* Completion context */
	int flags;			/* Context flags */
};

/* Read context */
struct pblk_r_ctx {
	int flags;			/* Read context flags */
	struct bio *orig_bio;
};

/* Recovery context */
struct pblk_rec_ctx {
	struct pblk *pblk;
	struct nvm_rq *rqd;
	struct list_head failed;
	struct work_struct ws_rec;
};

/* Write context */
struct pblk_w_ctx {
	struct bio_list bios;		/* Original bios - used for completion
					   in REQ_FUA, REQ_FLUSH case
					 */
	void *priv;			/* Private pointer */
	sector_t lba;			/* Logic addr. associated with entry */
	u64 paddr;			/* pblk block physical address */
	struct pblk_addr ppa;		/* Physic addr. associated with entry */
	int flags;			/* Write context flags */
};

struct pblk_rb_entry {
	void *data;			/* Pointer to data on this entry */
	struct pblk_w_ctx w_ctx;	/* Context for this entry */
	struct list_head index;		/* List head to enable indexes */
};

#define RB_EMPTY_ENTRY (~0ULL)

struct pblk_rb_pages {
	struct page *pages;
	int order;
	struct list_head list;
};

struct pblk_rb {
	struct pblk_rb_entry *entries;	/* Ring buffer entries */
	unsigned long mem;		/* Write offset - points to next
					 * writable entry in memory
					 */
	unsigned long subm;		/* Read offset - points to last entry
					 * that has been submitted to the media
					 * to be persisted
					 */
	unsigned long sync;		/* Synced - backpointer that signals
					 * the last submitted entry that has
					 * been successfully persisted to media
					 */
	unsigned long sync_point;	/* Sync point - last entry that must be
					 * flushed to the media. Used with
					 * REQ_FLUSH and REQ_FUA
					 */
	unsigned long l2p_update;	/* l2p update point - next entry for
					 * which l2p mapping will be updated to
					 * contain a device ppa address (instead
					 * of a cacheline
					 */
	unsigned long nr_entries;	/* Number of entries in write buffer -
					 * must be a power of two
					 */
	unsigned int seg_size;		/* Size of the data segments being
					 * stored on each entry. Typically this
					 * will be 4KB
					 */

	struct list_head pages;		/* List of data pages */

	spinlock_t w_lock;		/* Write lock */
	spinlock_t r_lock;		/* Read lock */
	spinlock_t s_lock;		/* Sync lock */

#ifdef CONFIG_NVM_DEBUG
	atomic_t inflight_sync_point;	/* Not served REQ_FLUSH | REQ_FUA */
#endif
};

#define PBLK_RECOVERY_SECTORS 16
#define PBLK_RECOVERY_BITMAPS 3 /* sector_bitmap, sync_bitmap, invalid_bitmap */

/*
 * Recovery stored in the last page of the block. A list of lbas (u64) is
 * allocated together with this structure to allow block recovery and GC.
 * After this structure, we store the following block bitmaps on the last page:
 * sector_bitmap, sync_bitmap and invalid_bitmap in this order.
 */
struct pblk_blk_rec_lpg {
	u32 crc;
	u32 status;
	u32 blk_state;
	u32 rlpg_len;
	u32 req_len;
	u32 nr_lbas;
	u32 nr_padded;
	u32 cur_sec;
	u32 nr_invalid_secs;
	u32 bitmap_len;
};

struct pblk_blk_rec_lenghts {
	unsigned int bitmap_len;
	unsigned int rlpg_page_len;
};

struct pblk_block {
	int id;				/* id inside of LUN */
	struct pblk_lun *rlun;
	struct list_head prio;
	struct list_head list;

	struct pblk_blk_rec_lpg *rlpg;

	unsigned long *sector_bitmap;	/* Bitmap for free (0) / used sectors
					 * (1) in the block
					 */
	unsigned long *sync_bitmap;	/* Bitmap representing physical
					 * addresses that have been synced to
					 * the media
					 */
	unsigned long *invalid_bitmap;	/* Bitmap for invalid sector entries */
	unsigned long cur_sec;
	/* number of secs that are invalid, wrt host page size */
	unsigned int nr_invalid_secs;

	int state;

	spinlock_t lock;
};

struct pblk_lun {
	struct pblk *pblk;

	int id;
	struct ppa_addr bppa;

	struct pblk_block *cur;
	struct pblk_block *blocks;	/* Reference to block allocation */

	/* In-use blocks - pblk block */
	struct list_head prio_list;	/* Blocks that may be GC'ed */
	struct list_head open_list;	/* In-use open blocks. These are blocks
					 * that can be both written to and read
					 * from
					 */
	struct list_head closed_list;	/* In-use closed blocks. These are
					 * blocks that can _only_ be read from
					 * and that have not been reclaimed by
					 * GC
					 */
	struct list_head g_bb_list;	/* Grown bad blocks waiting to be
					 *disposed
					 */

	/* lun block lists */
	struct list_head free_list;	/* Not used blocks i.e. released
					 * and ready for use
					 */
	struct list_head bb_list;	/* Bad blocks. Mutually exclusive with
					 * free_list and used blocks
					 * (open_list + closed_list + g_bb_list)
					 */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct semaphore wr_sem;

	spinlock_t lock;
};

struct pblk_gc {
	int gc_active;
	int gc_enabled;
	int gc_forced;

	spinlock_t lock;
};

struct pblk_prov {

	unsigned int high_pw;	/* Upper threshold for rate limiter (free run -
				 * user I/O rate limiter. Given as a power-of-2
				 */
	unsigned int high_lun;	/* Upper threshold for per-LUN rate limiter.
				 * Given as absolute value
				 */
	unsigned int low_pw;	/* Lower threshold for rate limiter (user I/O
				 * rate limiter - stall). Given as a power-of-2
				 */
	unsigned int low_lun;	/* Lower threshold for per-LUN rate limiter.
				 * Given as absolute value
				 */

#define PBLK_USER_LOW_THRS 50	/* full stop at 2 percent of available
				 * blocks
				 */
#define PBLK_USER_HIGH_THRS 4	/* begin write limit at 25 percent
				 * available blks
				 */

	int rb_windows_pw;	/* Number of rate windows in the write buffer
				 * given as a power-of-2. This guarantees that
				 * when user I/O is being rate limited, there
				 * will be reserved enough space for the GC to
				 * place its payload. A window is of
				 * pblk->max_write_pgs size, which in NVMe is
				 * 64, i.e., 256kb.
				 */
	int rb_user_max;	/* Max buffer entries available for user I/O */
	int rb_user_cnt;	/* User I/O buffer counter */
	int rb_gc_max;		/* Max buffer entries available for GC I/O */
	int rb_gc_rsv;		/* Reserved buffer entries for GC I/O */
	int rb_gc_cnt;		/* GC I/O buffer counter */

	unsigned long long nr_secs;
	unsigned long total_blocks;
	unsigned long free_blocks;

	spinlock_t lock;
};

struct pblk_prov_queue {
	struct list_head list;
	spinlock_t lock;
	int nr_elems;
	int qd;
};

/* Write strategy */
struct pblk_w_luns {
	int nr_luns;		/* Number of writable luns */
	int nr_blocks;		/* Number of blocks to be consumed per lun. -1
				 * signals that the lun must not change and
				 * consume only blocks from the set luns. Active
				 * luns can be then set through sysfs
				 */

	struct pblk_lun **luns; /* Pointers to writable luns */
	int *lun_blocks;	/* Consumed blocks per lun */

	int next_w_lun;		/* Whenever sector is written, this is updated
				 * to point to the next write lun
				 */
	int next_lun;		/* Next non-writable lun to become writable */

	spinlock_t lock;
};

#define NVM_MEM_PAGE_WRITE (8)

struct pblk {
	/* instance must be kept in top to resolve pblk in unprep */
	struct nvm_tgt_instance instance;

	struct nvm_tgt_dev *dev;
	struct gendisk *disk;

	struct kobject kobj;

	int nr_luns;
	struct pblk_lun *luns;

	struct pblk_w_luns w_luns;

	struct pblk_rb rwb;

	int min_write_pgs; /* minimum amount of pages required by controller */
	int max_write_pgs; /* maximum amount of pages supported by controller */

	int pgs_in_buffer; /* Number of pages that need to be old in buffer to
			    * guarantee successful reads
			    */

	unsigned int nr_blk_dsecs; /* Number of data sectors in block */
	struct pblk_blk_rec_lenghts blk_meta;

	/* capacity of devices when bad blocks are subtracted */
	sector_t capacity;

	/* pblk provisioning values. Used by rate limiter */
	struct pblk_prov rl;

	/* counter for pblk_write_kick */
#define PBLK_KICK_SECTS 16
	int write_cnt;
	spinlock_t kick_lock;

#ifdef CONFIG_NVM_DEBUG
	/* All debug counters apply to 4kb sector I/Os */
	atomic_t inflight_writes;	/* Inflight writes (user and gc) */
	atomic_t padded_writes;		/* Sectors padded due to flush/fua */
	atomic_t nr_flush;		/* Number of flush/fua I/O */
	atomic_t req_writes;		/* Sectors stored on write buffer */
	atomic_t sub_writes;		/* Sectors submitted from buffer */
	atomic_t sync_writes;		/* Sectors synced to media */
	atomic_t compl_writes;		/* Sectors completed in write bio */
	atomic_t inflight_meta;		/* Inflight metadata sectors */
	atomic_t compl_meta;		/* Completed metadata sectors */
	atomic_t inflight_reads;	/* Inflight sector read requests */
	atomic_t sync_reads;		/* Completed sector read requests */
	atomic_t recov_writes;		/* Sectors submitted from recovery */
	atomic_t recov_gc_writes;	/* Sectors submitted from recovery GC */
	atomic_t requeued_writes;	/* Sectors requeued in cache */
#endif

	spinlock_t lock;
	unsigned long read_failed;
	unsigned long read_empty;
	unsigned long read_high_ecc;
	unsigned long read_failed_gc;
	unsigned long write_failed;
	unsigned long erase_failed;

	spinlock_t bio_lock;
	spinlock_t trans_lock;
	struct bio_list requeue_bios;
	struct work_struct ws_requeue;
	struct work_struct ws_gc;
	struct task_struct *ts_writer;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	struct pblk_addr *trans_map;

	struct list_head compl_list;

	mempool_t *page_pool;
	mempool_t *blk_ws_pool;
	mempool_t *rec_pool;
	mempool_t *r_rq_pool;
	mempool_t *w_rq_pool;
	mempool_t *blk_meta_pool;

	struct timer_list gc_timer;
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;
	struct workqueue_struct *kw_wq;

	wait_queue_head_t wait;
	struct timer_list wtimer;

	struct pblk_gc gc;
};

struct pblk_block_ws {
	struct pblk *pblk;
	struct pblk_block *rblk;
	struct work_struct ws_blk;
};

#define pblk_r_rq_size (sizeof(struct nvm_rq) + sizeof(struct pblk_r_ctx))
#define pblk_w_rq_size (sizeof(struct nvm_rq) + sizeof(struct pblk_ctx) + \
			sizeof(struct pblk_compl_ctx))

/*
 * pblk ring buffer operations
 */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
		 unsigned int power_size, unsigned int power_seg_sz);
unsigned long pblk_rb_calculate_size(unsigned long nr_entries);
unsigned long pblk_rb_nr_entries(struct pblk_rb *rb);
void *pblk_rb_entries_ref(struct pblk_rb *rb);

int pblk_rb_may_write(struct pblk_rb *rb, unsigned int nr_up,
		      unsigned int nr_com, unsigned long *pos);
void pblk_rb_write_entry(struct pblk_rb *rb, void *data,
			 struct pblk_w_ctx w_ctx, unsigned int pos);
struct pblk_w_ctx *pblk_rb_w_ctx(struct pblk_rb *rb, unsigned long pos);

void pblk_rb_sync_l2p(struct pblk_rb *rb);

unsigned long pblk_rb_read_lock(struct pblk_rb *rb);
unsigned int pblk_rb_read(struct pblk_rb *rb, void *buf,
			  struct pblk_ctx *ctx,
			  unsigned int nr_entries);
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
				 struct pblk_ctx *ctx,
				 unsigned long pos,
				 unsigned int nr_entries,
				 unsigned int count,
				 unsigned long *sp);
unsigned int pblk_rb_read_to_bio_list(struct pblk_rb *rb, struct bio *bio,
				      struct pblk_ctx *ctx,
				      struct list_head *list,
				      unsigned int max);
void pblk_rb_copy_to_bio(struct pblk_rb *rb, struct bio *bio, u64 pos);
unsigned long pblk_rb_read_commit(struct pblk_rb *rb, unsigned int entries);
void pblk_rb_read_unlock(struct pblk_rb *rb);

unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags);
unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nr_entries);
struct pblk_rb_entry *pblk_rb_sync_scan_entry(struct pblk_rb *rb,
					      struct ppa_addr *ppa);
void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long *flags);

int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio);
unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb);
void pblk_rb_sync_point_reset(struct pblk_rb *rb, unsigned long sp);

unsigned long pblk_rb_space(struct pblk_rb *rb);
unsigned long pblk_rb_count(struct pblk_rb *rb);
unsigned long pblk_rb_wrap_pos(struct pblk_rb *rb, unsigned long pos);

int pblk_rb_tear_down_check(struct pblk_rb *rb);
int pblk_rb_pos_oob(struct pblk_rb *rb, u64 pos);

void pblk_rb_data_free(struct pblk_rb *rb);

#ifdef CONFIG_NVM_DEBUG
ssize_t pblk_rb_sysfs(struct pblk_rb *rb, char *buf);
#endif

/*
 * pblk core
 */
struct nvm_rq *pblk_alloc_rqd(struct pblk *pblk, int rw);
void pblk_free_rqd(struct pblk *pblk, struct nvm_rq *rqd, int rw);
void pblk_flush_writer(struct pblk *pblk);
struct ppa_addr pblk_get_lba_map(struct pblk *pblk, sector_t lba);
void pblk_discard(struct pblk *pblk, struct bio *bio);
struct pblk_blk_rec_lpg *pblk_alloc_blk_meta(struct pblk *pblk,
					     struct pblk_block *rblk,
					     u32 status);
void pblk_put_blk(struct pblk *pblk, struct pblk_block *rblk);
void pblk_erase_blk(struct pblk *pblk, struct pblk_block *rblk);
void pblk_mark_bb(struct pblk *pblk, struct ppa_addr ppa);
void pblk_end_io(struct nvm_rq *rqd);
void pblk_end_sync_bio(struct bio *bio);
void pblk_free_blks(struct pblk *pblk);
void pblk_pad_open_blks(struct pblk *pblk);
struct pblk_block *pblk_get_blk(struct pblk *pblk, struct pblk_lun *rlun);
int pblk_replace_blk(struct pblk *pblk, struct pblk_block *rblk,
		     struct pblk_lun *rlun, int lun_pos);
void pblk_end_close_blk_bio(struct pblk *pblk, struct nvm_rq *rqd, int run_gc);
void pblk_set_lun_cur(struct pblk_lun *rlun, struct pblk_block *rblk);
void pblk_run_blk_ws(struct pblk *pblk, struct pblk_block *rblk,
		     void (*work)(struct work_struct *));
int pblk_bio_add_pages(struct pblk *pblk, struct bio *bio, gfp_t flags,
		       int nr_pages);
void pblk_bio_free_pages(struct pblk *pblk, struct bio *bio, int off,
			 int nr_pages);
int pblk_update_map(struct pblk *pblk, sector_t laddr, struct pblk_block *rblk,
		    struct ppa_addr ppa);
int pblk_update_map_gc(struct pblk *pblk, sector_t laddr,
		       struct pblk_block *rblk, struct ppa_addr ppa,
		       struct pblk_block *gc_rblk);
unsigned long pblk_nr_free_blks(struct pblk *pblk);

#ifdef CONFIG_NVM_DEBUG
void pblk_print_failed_rqd(struct pblk *pblk, struct nvm_rq *rqd, int error);
int pblk_luns_configure(struct pblk *pblk);
#endif

/*
 * pblk user I/O write path
 */
int pblk_write_to_cache(struct pblk *pblk, struct bio *bio,
			unsigned long flags);
int pblk_write_gc_to_cache(struct pblk *pblk, void *data, u64 *lba_list,
			   struct pblk_kref_buf *ref_buf,
			   unsigned int nr_entries, unsigned int nr_rec_entries,
			   unsigned long flags, struct pblk_block *gc_rblk);

/*
 * pblk map
 */
int pblk_map_init(struct pblk *pblk);
void pblk_map_free(struct pblk *pblk);
int pblk_map_page(struct pblk *pblk, struct pblk_block *rblk,
		  unsigned int sentry, struct ppa_addr *ppa_list,
		  struct pblk_sec_meta *meta_list,
		  unsigned int nr_secs, unsigned int valid_secs);
int pblk_map_rr_page(struct pblk *pblk, unsigned int sentry,
		     struct ppa_addr *ppa_list,
		     struct pblk_sec_meta *meta_list,
		     unsigned int nr_secs, unsigned int valid_secs,
		     unsigned long *lun_bitmap);
int pblk_map_replace_lun(struct pblk *pblk, int lun_pos);
ssize_t pblk_map_set_active_luns(struct pblk *pblk, int nr_luns);
ssize_t pblk_map_set_offset_active_luns(struct pblk *pblk, int offset);
int pblk_map_get_active_luns(struct pblk *pblk);
int pblk_map_set_consume_blocks(struct pblk *pblk, int value);
int pblk_map_get_consume_blocks(struct pblk *pblk);

/*
 * pblk write thread
 */
int pblk_write_ts(void *data);
void pblk_write_timer_fn(unsigned long data);
int pblk_write_setup_m(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned int valid_secs, int off,
		       unsigned long *lun_bitmap);
int pblk_write_setup_s(struct pblk *pblk, struct nvm_rq *rqd,
		       struct pblk_ctx *ctx, struct pblk_sec_meta *meta,
		       unsigned long *lun_bitmap);
int pblk_write_alloc_rq(struct pblk *pblk, struct nvm_rq *rqd,
		    struct pblk_ctx *ctx, unsigned int nr_secs);
void pblk_end_io_write(struct pblk *pblk, struct nvm_rq *rqd);

/*
 * pblk read path
 */
int pblk_submit_read(struct pblk *pblk, struct bio *bio, unsigned long flags);
int pblk_submit_read_gc(struct pblk *pblk, struct bio *bio,
			struct nvm_rq *rqd, u64 *lba_list,
			unsigned int nr_secs, unsigned int nr_rec_secs,
			unsigned long flags);
void pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd, uint8_t nr_secs);

/*
 * pblk recovery
 */
void pblk_submit_rec(struct work_struct *work);
int pblk_recov_page_size(struct pblk *pblk);
void pblk_run_recovery(struct pblk *pblk, struct pblk_block *rblk);
int pblk_recov_init(struct pblk *pblk);
int pblk_recov_setup_rq(struct pblk *pblk, struct pblk_ctx *ctx,
			struct pblk_rec_ctx *recovery, u64 *comp_bits,
			unsigned int c_entries);
int pblk_recov_read(struct pblk *pblk, struct pblk_block *rblk,
		    void *recov_page);
struct nvm_rq *pblk_recov_setup(struct pblk *pblk, void *recov_page);
u64 *pblk_recov_get_lba_list(struct pblk *pblk, struct pblk_blk_rec_lpg *rlpg);
int pblk_recov_scan_blk(struct pblk *pblk, struct pblk_block *rblk);
void pblk_recov_clean_g_bb_list(struct pblk *pblk, struct pblk_lun *rlun);
void pblk_close_blk(struct work_struct *work);
int pblk_recov_calc_meta_len(struct pblk *pblk, unsigned int *bitmap_len,
			  unsigned int *rlpg_len,
			  unsigned int *req_len);

#ifdef CONFIG_NVM_DEBUG
void pblk_recov_blk_meta_sysfs(struct pblk *pblk, u64 value);
#endif

/*
 * pblk gc
 */
#define PBLK_GC_TRIES 3

int pblk_gc_init(struct pblk *pblk);
void pblk_gc_exit(struct pblk *pblk);
void pblk_gc_should_start(struct pblk *pblk);
void pblk_gc_should_stop(struct pblk *pblk);
int pblk_gc_status(struct pblk *pblk);
void pblk_gc_queue(struct work_struct *work);
void pblk_gc(struct work_struct *work);
int pblk_gc_move_valid_secs(struct pblk *pblk, struct pblk_block *rblk,
			    u64 *lba_list, unsigned int nr_entries);
void pblk_gc_sysfs_state_show(struct pblk *pblk, int *gc_enabled,
			      int *gc_active);
int pblk_gc_sysfs_force(struct pblk *pblk, int value);
int pblk_gc_sysfs_enable(struct pblk *pblk, int value);

/*
 * pblk rate limiter
 */
void pblk_rl_init(struct pblk *pblk);
int pblk_rl_gc_thrs(struct pblk *pblk);
void pblk_rl_user_in(struct pblk *pblk, int nr_entries);
void pblk_rl_gc_in(struct pblk *pblk, int nr_entries);
void pblk_rl_out(struct pblk *pblk, int nr_user, int nr_gc);
void pblk_rl_set_gc_rsc(struct pblk *pblk, int rsv);
int pblk_rl_sysfs_rate_show(struct pblk *pblk);
int pblk_rl_sysfs_rate_store(struct pblk *pblk, int value);
void pblk_rl_free_blks_inc(struct pblk *pblk, struct pblk_lun *rlun);
void pblk_rl_free_blks_dec(struct pblk *pblk, struct pblk_lun *rlun);

/*
 * pblk sysfs
 */
int pblk_sysfs_init(struct gendisk *tdisk);
void pblk_sysfs_exit(struct pblk *pblk);

static inline int nvm_addr_in_cache(struct ppa_addr gp)
{
	if (gp.ppa != ADDR_EMPTY && gp.c.is_cached)
		return 1;
	return 0;
}

static inline u64 nvm_addr_to_cacheline(struct ppa_addr gp)
{
#ifdef CONFIG_NVM_DEBUG
	BUG_ON(gp.ppa == ADDR_EMPTY);
#endif
	return gp.c.line;
}

static inline void pblk_write_kick(struct pblk *pblk)
{
	wake_up_process(pblk->ts_writer);
}

static inline void *pblk_rlpg_to_llba(struct pblk_blk_rec_lpg *lpg)
{
	return lpg + 1;
}

static inline struct pblk_ctx *pblk_set_ctx(struct pblk *pblk,
							struct nvm_rq *rqd)
{
	struct pblk_ctx *c;

	c = nvm_rq_to_pdu(rqd);
	c->c_ctx = (void *)(c + 1);

	return c;
}

static inline void pblk_memcpy_addr(struct pblk_addr *to,
				    struct pblk_addr *from)
{
	to->ppa = from->ppa;
	to->rblk = from->rblk;
}

static inline void pblk_ppa_set_empty(struct pblk_addr *ppa)
{
	ppa_set_empty(&ppa->ppa);
	ppa->rblk = NULL;
}

static inline void pblk_free_ref_mem(struct kref *ref)
{
	struct pblk_kref_buf *ref_buf;
	void *data;

	ref_buf = container_of(ref, struct pblk_kref_buf, ref);
	data = ref_buf->data;

	kfree(data);
	kfree(ref_buf);
}

/* Calculate the page offset of within a block from a generic address */
static inline u64 pblk_gaddr_to_pg_offset(struct nvm_tgt_dev *dev,
					  struct ppa_addr p)
{
	struct nvm_geo *geo = &dev->geo;

	return (u64) (p.g.pg * geo->sec_per_pl) +
				(p.g.pl * geo->sec_per_pg) + p.g.sec;
}

static inline struct ppa_addr pblk_cacheline_to_ppa(u64 addr)
{
	struct ppa_addr p;

	p.c.line = (u64)addr;
	p.c.is_cached = 1;

	return p;
}

static inline struct ppa_addr pblk_dev_addr_to_ppa(u64 addr)
{
	struct ppa_addr gp;

	gp.ppa = (u64)addr;
	gp.c.is_cached = 0;

	return gp;
}

static inline struct ppa_addr addr_to_ppa(u64 paddr)
{
	struct ppa_addr ppa;

	ppa.ppa = paddr;
	return ppa;
}

static inline u64 ppa_to_addr(struct ppa_addr ppa)
{
	return ppa.ppa;
}

static inline int pblk_set_progr_mode(struct pblk *pblk, int type)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int flags;

	switch (geo->plane_mode) {
	case NVM_PLANE_QUAD:
		flags = NVM_IO_QUAD_ACCESS;
		break;
	case NVM_PLANE_DOUBLE:
		flags = NVM_IO_DUAL_ACCESS;
		break;
	case NVM_PLANE_SINGLE:
		flags = NVM_IO_SNGL_ACCESS;
		break;
	default:
		pr_err("pblk: invalid plane configuration\n");
		return -EINVAL;
	}

	if (type == WRITE)
		flags |= NVM_IO_SCRAMBLE_ENABLE;

	return flags;
}

static inline int pblk_set_read_mode(struct pblk *pblk)
{
	return NVM_IO_SNGL_ACCESS | NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
}

static inline struct ppa_addr pblk_blk_ppa_to_gaddr(struct nvm_tgt_dev *dev,
						    struct pblk_block *rblk,
						    u64 page_addr)
{
	struct nvm_geo *geo = &dev->geo;
	struct pblk_lun *rlun = rblk->rlun;
	struct ppa_addr p;
	int secs, pgs, pls;

	/* Set base address for LUN and block */
	p = rlun->bppa;
	p.g.blk = rblk->id;

	/* Calculate page, plane and sector */
	div_u64_rem(page_addr, geo->sec_per_pg, &secs);
	p.g.sec = secs;

	sector_div(page_addr, geo->sec_per_pg);
	div_u64_rem(page_addr, geo->nr_planes, &pls);
	p.g.pl = pls;

	sector_div(page_addr, geo->nr_planes);
	div_u64_rem(page_addr, geo->pgs_per_blk, &pgs);
	p.g.pg = pgs;

	return p;
}

static inline int pblk_boundary_checks(struct nvm_tgt_dev *tgt_dev,
				       struct ppa_addr *ppas, int nr_ppas)
{
	struct nvm_geo *geo = &tgt_dev->geo;
	struct ppa_addr *ppa;
	int i;

	for (i = 0; i < nr_ppas; i++) {
		ppa = &ppas[i];

		if (ppa->g.ch < geo->nr_chnls &&
				ppa->g.lun < geo->nr_luns &&
				ppa->g.pl < geo->nr_planes &&
				ppa->g.blk < geo->blks_per_lun &&
				ppa->g.pg < geo->pgs_per_blk &&
				ppa->g.sec < geo->sec_per_pg)
			continue;

#ifdef CONFIG_NVM_DEBUG
		if (ppa->c.is_cached)
			pr_err("nvm: ppa oob(cacheline:%llu)\n",
							(u64)ppa->c.line);
		else
		pr_err("nvm: ppa oob(ch:%u,lun:%u,pl:%u,blk:%u,pg:%u,sec:%u\n)",
				ppa->g.ch, ppa->g.lun, ppa->g.pl,
				ppa->g.blk, ppa->g.pg, ppa->g.sec);
#endif
		return 1;
	}
	return 0;
}

static inline void print_ppa(struct ppa_addr *p, char *msg, int error)
{
	if (p->c.is_cached) {
		pr_err("ppa: (%s: %x) cache line: %llu\n",
				msg, error, (u64)p->c.line);
	} else {
		pr_err("ppa: (%s: %x):ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
			msg, error,
			p->g.ch, p->g.lun, p->g.blk,
			p->g.pg, p->g.pl, p->g.sec);
	}
}

static inline unsigned int pblk_get_bi_idx(struct bio *bio)
{
	return bio->bi_iter.bi_idx;
}

static inline sector_t pblk_get_laddr(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static inline unsigned int pblk_get_secs(struct bio *bio)
{
	return  bio->bi_iter.bi_size / PBLK_EXPOSED_PAGE_SIZE;
}

static inline sector_t pblk_get_sector(sector_t laddr)
{
	return laddr * NR_PHY_IN_LOG;
}

static inline int block_is_bad(struct pblk_block *rblk)
{
	return (rblk->state == NVM_BLK_ST_BAD);
}

static inline int block_is_full(struct pblk *pblk, struct pblk_block *rblk)
{
#ifdef CONFIG_NVM_DEBUG
	if (!block_is_bad(rblk))
		BUG_ON(!bitmap_full(rblk->sector_bitmap, pblk->nr_blk_dsecs) &&
				rblk->cur_sec >= pblk->nr_blk_dsecs);
#endif

	return (rblk->cur_sec >= pblk->nr_blk_dsecs);
}

static inline void inc_stat(struct pblk *pblk, unsigned long *stat, int interr)
{
	if (interr) {
		unsigned long flags;

		spin_lock_irqsave(&pblk->lock, flags);
		(*stat)++;
		spin_unlock_irqrestore(&pblk->lock, flags);
	} else {
		spin_lock_irq(&pblk->lock);
		(*stat)++;
		spin_unlock_irq(&pblk->lock);
	}
}
#endif /* PBLK_H_ */

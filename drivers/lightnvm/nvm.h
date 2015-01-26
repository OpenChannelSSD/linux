/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef NVM_H_
#define NVM_H_

#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/mempool.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/hashtable.h>
#include <linux/lightnvm.h>
#include <linux/blk-mq.h>
#include <linux/slab.h>

#ifdef NVM_DEBUG
#define NVM_ASSERT(c) BUG_ON((c) == 0)
#else
#define NVM_ASSERT(c)
#endif

#define NVM_MSG_PREFIX "nvm"
#define ADDR_EMPTY (~0ULL)
#define LTOP_POISON 0xD3ADB33F

/*
 * For now we hardcode some of the configuration for the LightNVM device that we
 * have. In the future this should be made configurable.
 *
 * Configuration:
 * EXPOSED_PAGE_SIZE - the page size of which we tell the layers above the
 * driver to issue. This usually is 512 bytes for 4K for simplivity.
 */

/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */
#define NVM_SECTOR 512
#define EXPOSED_PAGE_SIZE 4096

#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / NVM_SECTOR)

/* We partition the namespace of translation map into these pieces for tracking
 * in-flight addresses. */
#define NVM_INFLIGHT_PARTITIONS 8

/* Pool descriptions */
struct nvm_block {
	struct {
		spinlock_t lock;
		/* points to the next writable page within a block */
		unsigned int next_page;
		/* number of pages that are invalid, wrt host page size */
		unsigned int nr_invalid_pages;
#define MAX_INVALID_PAGES_STORAGE 8
		/* Bitmap for invalid page intries */
		unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	} ____cacheline_aligned_in_smp;

	unsigned int id;
	struct nvm_pool *pool;
	struct nvm_ap *ap;

	/* Management structures */
	struct list_head list;

	/* Persistent data structures */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */

	/* Block state handling */
	atomic_t gc_running;

	/* For target and GC algorithms  */
	void *tgt_private;
	void *gc_private;
};

/* Logical to physical mapping */
struct nvm_addr {
	sector_t addr;
	struct nvm_block *block;
};

/* Physical to logical mapping */
struct nvm_rev_addr {
	sector_t addr;
};

struct nvm_pool {
	/* Pool block lists */
	struct {
		spinlock_t lock;
	} ____cacheline_aligned_in_smp;

	struct list_head used_list;	/* In-use blocks */
	struct list_head free_list;	/* Not used blocks i.e. released
					 *  and ready for use */

	unsigned int id;

	struct nvm_id_chnl *chnl;

	unsigned int nr_blocks;		/* end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct nvm_block *blocks;
	struct nvm_stor *s;

	void *tgt_private;	/*target-specific per-pool data*/
	void *gc_private;	/*GC-specific per-pool data*/
};

/*
 * nvm_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full,
 * it requests a new block, of which it continues its writes.
 *
 * one ap per pool may be reserved for pack-hints related writes.
 * In those that are not not, private is NULL.
 */
struct nvm_ap {
	spinlock_t lock;
	struct nvm_stor *parent;
	struct nvm_pool *pool;
	struct nvm_block *cur;
	struct nvm_block *gc_cur;

	unsigned long io_delayed;

	/* Private field for submodules */
	void *private;
};

struct nvm_config {
	unsigned long flags;

	unsigned int gc_time; /* GC every X microseconds */
};

struct nvm_inflight_request {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
};

struct nvm_inflight {
	spinlock_t lock;
	struct list_head reqs;
};

struct nvm_stor;
struct per_rq_data;
struct nvm_block;
struct nvm_pool;

/* overridable functionality */
typedef struct nvm_addr *(nvm_lookup_ltop_fn)(struct nvm_stor *, sector_t);
typedef struct nvm_addr *(nvm_map_ltop_page_fn)(struct nvm_stor *, sector_t,
						int);
typedef struct nvm_block *(nvm_map_ltop_block_fn)(struct nvm_stor *, sector_t,
						int);
typedef int (nvm_write_rq_fn)(struct nvm_stor *, struct request *);
typedef int (nvm_read_rq_fn)(struct nvm_stor *, struct request *);
typedef void (nvm_alloc_phys_addr_fn)(struct nvm_stor *, struct nvm_block *);
typedef struct nvm_block *(nvm_pool_get_blk_fn)(struct nvm_pool *pool,
						int is_gc);
typedef void (nvm_pool_put_blk_fn)(struct nvm_block *block);
typedef int (nvm_ioctl_fn)(struct nvm_stor *,
					unsigned int cmd, unsigned long arg);
typedef int (nvm_tgt_init_fn)(struct nvm_stor *);
typedef void (nvm_tgt_exit_fn)(struct nvm_stor *);
typedef void (nvm_endio_fn)(struct nvm_stor *, struct request *,
				struct per_rq_data *, unsigned long *delay);

typedef void (nvm_gc_timer_fn)(unsigned long s_addr);
typedef void (nvm_deferred_fn)(struct work_struct *work);
typedef void (nvm_gc_queue_fn)(struct nvm_block *block);
typedef void (nvm_gc_kick_fn)(struct nvm_stor *s);
typedef int (nvm_gc_init_fn)(struct nvm_stor *s);
typedef void (nvm_gc_exit_fn)(struct nvm_stor *s);

struct nvm_target_type {
	const char *name;
	unsigned int version[3];

	/* lookup functions */
	nvm_lookup_ltop_fn *lookup_ltop;

	/* handling of request */
	nvm_write_rq_fn *write_rq;
	nvm_read_rq_fn *read_rq;
	nvm_ioctl_fn *ioctl;
	nvm_endio_fn *end_rq;

	/* engine-specific overrides */
	nvm_pool_get_blk_fn *pool_get_blk;
	nvm_pool_put_blk_fn *pool_put_blk;
	nvm_map_ltop_page_fn *map_page;
	nvm_map_ltop_block_fn *map_block;

	/* module-specific init/teardown */
	nvm_tgt_init_fn *init;
	nvm_tgt_exit_fn *exit;

	/* For lightnvm internal use */
	struct list_head list;
};

struct nvm_gc_type {
	const char *name;
	unsigned int version[3];

	/*GC interface*/
	nvm_gc_timer_fn *gc_timer;
	nvm_gc_queue_fn *queue;
	nvm_gc_kick_fn *kick;

	/* module-specific init/teardown */
	nvm_gc_init_fn *init;
	nvm_gc_exit_fn *exit;
};

struct kv_entry;

struct nvmkv_tbl {
	u8 bucket_len;
	u64 tbl_len;
	struct kv_entry *entries;
	spinlock_t lock;
};

struct nvmkv_inflight {
	struct kmem_cache *entry_pool;
	spinlock_t lock;
	struct list_head list;
};

struct nvmkv {
	struct nvmkv_tbl tbl;
	struct nvmkv_inflight inflight;
};

/* Main structure */
struct nvm_stor {
	struct nvm_dev *dev;
	uint32_t sector_size;

	struct nvm_target_type *type;
	struct nvm_gc_type *gc_ops;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct nvm_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct nvm_rev_addr *rev_trans_map;
	spinlock_t rev_lock;
	/* Usually instantiated to the number of available parallel channels
	 * within the hardware device. i.e. a controller with 4 flash channels,
	 * would have 4 pools.
	 *
	 * We assume that the device exposes its channels as a linear address
	 * space. A pool therefore have a phy_addr_start and phy_addr_end that
	 * denotes the start and end. This abstraction is used to let the
	 * lightnvm (or any other device) expose its read/write/erase interface
	 * and be administrated by the host system.
	 */
	struct nvm_pool *pools;

	/* Append points */
	struct nvm_ap *aps;

	mempool_t *addr_pool;
	mempool_t *page_pool;

	/* Frequently used config variables */
	int nr_pools;
	int nr_blks_per_pool;
	int nr_pages_per_blk;
	int nr_aps;
	int nr_aps_per_pool;

	struct nvm_id id;
	/* Calculated/Cached values. These do not reflect the actual usuable
	 * blocks at run-time. */
	unsigned long nr_pages;
	unsigned long total_blocks;

	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated
				 * to point to the next write append point */
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;

	struct timer_list gc_timer;

	struct nvm_inflight inflight_map[NVM_INFLIGHT_PARTITIONS];
	struct nvm_inflight_request *inflight_addrs;

	/* nvm module specific data */
	void *private;

	/* User configuration */
	struct nvm_config config;

	unsigned int per_rq_offset;

	struct nvmkv kv;
};

struct per_rq_data_nvm {
	struct nvm_dev *dev;
};

enum {
	NVM_RQ_NONE = 0,
	NVM_RQ_GC = 1,
};

struct per_rq_data {
	struct nvm_ap *ap;
	struct nvm_addr *addr;
	sector_t l_addr;
	unsigned int flags;
};

/* reg.c */
int nvm_register_target(struct nvm_target_type *t);
void nvm_unregister_target(struct nvm_target_type *t);
struct nvm_target_type *find_nvm_target_type(const char *name);

/* core.c */
void nvm_invalidate_range(struct nvm_stor *s, sector_t slba, unsigned len);
/*   Helpers */
void nvm_set_ap_cur(struct nvm_ap *, struct nvm_block *);
sector_t nvm_alloc_phys_addr(struct nvm_block *);

/*   Naive implementations */
void nvm_delayed_bio_submit(struct work_struct *);
void nvm_deferred_bio_submit(struct work_struct *);

/* Allocation of physical addresses from block
 * when increasing responsibility. */
struct nvm_addr *nvm_alloc_addr_from_ap(struct nvm_ap *, int is_gc);

/*   I/O request related */
int nvm_write_rq(struct nvm_stor *, struct request *);
int __nvm_write_rq(struct nvm_stor *, struct request *, int);
int nvm_read_rq(struct nvm_stor *, struct request *rq);
int nvm_erase_block(struct nvm_stor *, struct nvm_block *);
void nvm_update_map(struct nvm_stor *, sector_t, struct nvm_addr *, int);
void nvm_setup_rq(struct nvm_stor *, struct request *, struct nvm_addr *, sector_t, unsigned int flags);

/*   Block maintanence */
void nvm_reset_block(struct nvm_block *);

void nvm_endio(struct nvm_dev *, struct request *, int);

/* targets.c */
struct nvm_block *nvm_pool_get_block(struct nvm_pool *, int is_gc);

/* nvmkv.c */
int nvmkv_init(struct nvm_stor *s, unsigned long size);
void nvmkv_exit(struct nvm_stor *s);
int nvmkv_unpack(struct nvm_dev *dev, struct lightnvm_cmd_kv __user *ucmd);
void nvm_pool_put_block(struct nvm_block *);

#define nvm_for_each_pool(n, pool, i) \
		for ((i) = 0, pool = &(n)->pools[0]; \
			(i) < (n)->nr_pools; (i)++, pool = &(n)->pools[(i)])

#define nvm_for_each_ap(n, ap, i) \
		for ((i) = 0, ap = &(n)->aps[0]; \
			(i) < (n)->nr_aps; (i)++, ap = &(n)->aps[(i)])

#define pool_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

#define block_for_each_page(b, p) \
		for ((p)->addr = block_to_addr((b)), (p)->block = (b); \
			(p)->addr < block_to_addr((b)) \
				+ (b)->pool->s->nr_pages_per_blk; \
			(p)->addr++)

static inline struct nvm_ap *get_next_ap(struct nvm_stor *s)
{
	return &s->aps[atomic_inc_return(&s->next_write_ap) % s->nr_aps];
}

static inline int block_is_full(struct nvm_block *block)
{
	struct nvm_stor *s = block->pool->s;

	return block->next_page == s->nr_pages_per_blk;
}

static inline sector_t block_to_addr(struct nvm_block *block)
{
	struct nvm_stor *s = block->pool->s;

	return block->id * s->nr_pages_per_blk;
}

static inline struct nvm_pool *paddr_to_pool(struct nvm_stor *s,
							sector_t p_addr)
{
	return &s->pools[p_addr / (s->nr_pages / s->nr_pools)];
}

static inline struct nvm_ap *block_to_ap(struct nvm_stor *s,
							struct nvm_block *b)
{
	unsigned int ap_idx, div, mod;

	div = b->id / s->nr_blks_per_pool;
	mod = b->id % s->nr_blks_per_pool;
	ap_idx = div + (mod / (s->nr_blks_per_pool / s->nr_aps_per_pool));

	return &s->aps[ap_idx];
}

static inline int physical_to_slot(struct nvm_stor *s, sector_t phys)
{
	return phys % s->nr_pages_per_blk;
}

static inline void *get_per_rq_data(struct nvm_dev *dev, struct request *rq)
{
	BUG_ON(!dev);
	return blk_mq_rq_to_pdu(rq) + dev->drv_cmd_size;
}

static inline int request_intersects(struct nvm_inflight_request *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start && laddr_end <= r->l_end) &&
		(laddr_start >= r->l_start && laddr_start <= r->l_end);
}

static void __nvm_lock_laddr(struct nvm_stor *s, sector_t laddr,
			     unsigned pages, int rq_tag, int do_spin)
{
	struct nvm_inflight_request *r;
	struct nvm_inflight *map =
			&s->inflight_map[laddr % NVM_INFLIGHT_PARTITIONS];
	sector_t laddr_end = laddr + pages - 1;

retry:
	spin_lock(&map->lock);

	list_for_each_entry(r, &map->reqs, list) {
		if (unlikely(request_intersects(r, laddr, laddr_end))) {
			/* existing, overlapping request, come back later */
			spin_unlock(&map->lock);
			if (!do_spin) {
				/*
				 * blk-mq runs in non-preemptible mode after it
				 * has allocated a request. Release the CPU and
				 * get it again, so we don't schedule in atomic
				 * context. This seldom happens, we therefore
				 * take the hit if the process isn't scheduled
				 * on the same CPU.
				 */
				put_cpu();
				schedule();
				get_cpu();
			}
			goto retry;
		}
	}

	r = &s->inflight_addrs[rq_tag];

	r->l_start = laddr;
	r->l_end = laddr_end;

	list_add_tail(&r->list, &map->reqs);
	spin_unlock(&map->lock);
}

static void inline nvm_lock_laddr(struct nvm_stor *s, sector_t laddr,
				   unsigned pages, int rq_tag, int do_spin)
{
	BUG_ON((laddr + pages) > s->nr_pages);

	__nvm_lock_laddr(s, laddr, pages, rq_tag, do_spin);
}

static inline void nvm_lock_rq(struct nvm_stor *s, struct request *rq)
{
	sector_t laddr = blk_rq_pos(rq) / NR_PHY_IN_LOG;
	unsigned int pages = blk_rq_bytes(rq) / EXPOSED_PAGE_SIZE;

	return nvm_lock_laddr(s, laddr, pages, rq->tag, 0);
}

static inline void nvm_unlock_laddr(struct nvm_stor *s, sector_t laddr,
			     unsigned int pages, int rq_tag)
{
	struct nvm_inflight_request *r = &s->inflight_addrs[rq_tag];
	struct nvm_inflight *map =
			&s->inflight_map[laddr % NVM_INFLIGHT_PARTITIONS];
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	list_del_init(&r->list);
	spin_unlock_irqrestore(&map->lock, flags);

	/* On bug -> The submission size and complete size properly differs */
	r->l_start = r->l_end = LTOP_POISON;
}

static inline void nvm_unlock_rq(struct nvm_stor *s, struct request *rq)
{
	sector_t laddr = blk_rq_pos(rq) / NR_PHY_IN_LOG;
	unsigned int pages = blk_rq_bytes(rq) / EXPOSED_PAGE_SIZE;

	BUG_ON((laddr + pages) > s->nr_pages);

	nvm_unlock_laddr(s, laddr, pages, rq->tag);
}
#endif /* NVM_H_ */


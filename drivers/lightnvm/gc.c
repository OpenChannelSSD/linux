#include <linux/lightnvm.h>
#include "nvm.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

struct greedy_block {
	struct nvm_block *block;
	struct list_head prio;
	struct work_struct ws_gc;		/* Schedule when to reclaim */
	struct work_struct ws_queue_gc;	/* Schedule when GC'ing is allowed */
};

struct greedy_pool {
	struct nvm_pool *pool;
	struct list_head prio_list;		/* Blocks that may be GC'ed */
	struct work_struct ws_gc;		/* Schedule GC'ing of pool */
	struct greedy_block *block_mem;	/* Reference to block allocation */
};

/**
 * nvm_gc_timer - default gc timer function.
 * @data: ptr to the 'nvm_stor' structure
 *
 * Description:
 *   NVM core configures a timer to call '.gc_timer', the default
 *   implementation kicks the GC to force proactive behavior.
 *
 **/
void nvm_gc_timer(unsigned long data)
{
	struct nvm_stor *s = (struct nvm_stor *)data;

	s->gc_ops->kick(s);

	mod_timer(&s->gc_timer,
			jiffies + msecs_to_jiffies(s->config.gc_time));
}

/* Move data away from flash block to be erased. Additionally update the
 * l to p and p to l mappings. */
/**
 * nvm_move_valid_pages -- migrate live data off the block
 * @s: the 'nvm_stor' structure
 * @block: the block from which to migrate live pages
 *
 * Description:
 *   GC algorithms may call this function to migrate remaining live
 *   pages off the block prior to erasing it. This function blocks
 *   further execution until the operation is complete.
 */
void nvm_move_valid_pages(struct nvm_stor *s, struct nvm_block *block)
{
	struct nvm_dev *dev = s->dev;
	struct request_queue *q = dev->q;
	struct nvm_addr src;
	struct nvm_rev_addr *rev;
	struct bio *src_bio;
	struct request *src_rq, *dst_rq = NULL;
	struct page *page;
	int slot;
	DECLARE_COMPLETION(sync);

	if (bitmap_full(block->invalid_pages, s->nr_pages_per_blk))
		return;

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   s->nr_pages_per_blk)) <
						s->nr_pages_per_blk) {
		/* Perform read */
		src.addr = block_to_addr(block) + slot;
		src.block = block;

		BUG_ON(src.addr >= s->nr_pages);

		src_bio = bio_alloc(GFP_NOIO, 1);
		if (!src_bio) {
			pr_err("nvm: failed to alloc gc bio request");
			break;
		}
		src_bio->bi_iter.bi_sector = src.addr * NR_PHY_IN_LOG;
		page = mempool_alloc(s->page_pool, GFP_NOIO);

		/* TODO: may fail when EXP_PG_SIZE > PAGE_SIZE */
		bio_add_pc_page(q, src_bio, page, EXPOSED_PAGE_SIZE, 0);

		src_rq = blk_mq_alloc_request(q, READ, GFP_KERNEL, false);
		if (!src_rq) {
			mempool_free(page, s->page_pool);
			pr_err("nvm: failed to alloc gc request");
			break;
		}

		blk_init_request_from_bio(src_rq, src_bio);

		/* We take the reverse lock here, and make sure that we only
		 * release it when we have locked its logical address. If
		 * another write on the same logical address is
		 * occuring, we just let it stall the pipeline.
		 *
		 * We do this for both the read and write. Fixing it after each
		 * IO.
		 */
		spin_lock(&s->rev_lock);
		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		rev = &s->rev_trans_map[src.addr];

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		/* unlocked by nvm_submit_bio nvm_endio */
		__nvm_lock_laddr_range(s, 1, rev->addr, 1);
		spin_unlock(&s->rev_lock);

		nvm_setup_rq(s, src_rq, &src, rev->addr, NVM_RQ_GC);
		blk_execute_rq(q, dev->disk, src_rq, 0);
		blk_put_request(src_rq);

		dst_rq = blk_mq_alloc_request(q, WRITE, GFP_KERNEL, false);
		blk_init_request_from_bio(dst_rq, src_bio);

		/* ok, now fix the write and make sure that it haven't been
		 * moved in the meantime. */
		spin_lock(&s->rev_lock);

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		src_bio->bi_iter.bi_sector = rev->addr * NR_PHY_IN_LOG;

		/* again, unlocked by nvm_endio */
		__nvm_lock_laddr_range(s, 1, rev->addr, 1);

		spin_unlock(&s->rev_lock);

		__nvm_write_rq(s, dst_rq, 1);
		blk_execute_rq(q, dev->disk, dst_rq, 0);

overwritten:
		blk_put_request(dst_rq);
		bio_put(src_bio);
		mempool_free(page, s->page_pool);
	}

	WARN_ON(!bitmap_full(block->invalid_pages, s->nr_pages_per_blk));
}

static inline struct greedy_pool *greedy_pool(struct nvm_pool *pool)
{
	return (struct greedy_pool *)pool->gc_private;
}

static inline struct greedy_block *greedy_block(struct nvm_block *block)
{
	return (struct greedy_block *)block->gc_private;
}

static void nvm_greedy_queue_pool_gc(struct nvm_pool *pool)
{
	struct greedy_pool *gpool = greedy_pool(pool);
	struct nvm_stor *s = pool->s;

	queue_work(s->krqd_wq, &gpool->ws_gc);
}

static void nvm_greedy_kick(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	unsigned int i;

	BUG_ON(!s);

	nvm_for_each_pool(s, pool, i)
		nvm_greedy_queue_pool_gc(pool);
}

void nvm_greedy_block_gc(struct work_struct *work)
{
	struct greedy_block *block_data = container_of(work, struct greedy_block, ws_gc);
	struct nvm_block *block = block_data->block;
	struct nvm_stor *s = block->pool->s;

	pr_debug("nvm: block '%d' being reclaimed now\n", block->id);
	nvm_move_valid_pages(s, block);
	nvm_erase_block(s, block);
	s->type->pool_put_blk(block);
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct greedy_block *gblock_max_invalid(struct greedy_block *ga,
					       struct greedy_block *gb)
{
	struct nvm_block *a = ga->block;
	struct nvm_block *b = gb->block;
	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return ga;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? gb : ga;
}

/* linearly find the block with highest number of invalid pages
 * requires pool->lock */
static struct greedy_block *block_prio_find_max(struct greedy_pool *gpool)
{
	struct list_head *prio_list = &gpool->prio_list;
	struct greedy_block *gblock, *max;

	BUG_ON(list_empty(prio_list));

	max = list_first_entry(prio_list, struct greedy_block, prio);
	list_for_each_entry(gblock, prio_list, prio)
		max = gblock_max_invalid(max, gblock);

	return max;
}

static void nvm_greedy_pool_gc(struct work_struct *work)
{
	struct greedy_pool *gpool = container_of(work, struct greedy_pool, ws_gc);
	struct nvm_pool *pool = gpool->pool;
	struct nvm_stor *s = pool->s;
	unsigned int nr_blocks_need;
	unsigned long flags;

	nr_blocks_need = pool->nr_blocks / GC_LIMIT_INVERSE;

	if (nr_blocks_need < s->nr_aps)
		nr_blocks_need = s->nr_aps;

	local_irq_save(flags);
	spin_lock(&pool->lock);
	while (nr_blocks_need > pool->nr_free_blocks &&
					!list_empty(&gpool->prio_list)) {
		struct greedy_block *gblock = block_prio_find_max(gpool);
		struct nvm_block *block = gblock->block;

		if (!block->nr_invalid_pages) {
			pr_err("nvm: no invalid pages");
			break;
		}

		list_del_init(&gblock->prio);

		BUG_ON(!block_is_full(block));
		BUG_ON(atomic_inc_return(&block->gc_running) != 1);

		pr_debug("nvm: selected block '%d' as GC victim\n", block->id);
		queue_work(s->kgc_wq, &gblock->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&pool->lock);
	local_irq_restore(flags);

	/* TODO: Hint that request queue can be started again */
}

static void nvm_greedy_queue_gc(struct work_struct *work)
{
	struct greedy_block *gblock = container_of(work, struct greedy_block, ws_queue_gc);
	struct nvm_pool *pool = gblock->block->pool;
	struct greedy_pool *gpool = pool->gc_private;

	spin_lock(&pool->lock);
	list_add_tail(&gblock->prio, &gpool->prio_list);
	spin_unlock(&pool->lock);
	pr_debug("nvm: block '%d' is full, allow GC (DONE)\n", gblock->block->id);
}

static void nvm_greedy_queue(struct nvm_block *block)
{
	struct greedy_block *gblock = greedy_block(block);
	struct nvm_pool *pool = block->pool;
	struct nvm_stor *s = pool->s;
	pr_debug("nvm: block '%d' is full, allow GC (sched)\n", block->id);

	queue_work(s->kgc_wq, &gblock->ws_queue_gc);
}

static void nvm_greedy_free(struct nvm_stor *s)
{
	struct nvm_pool *pool;
	int i;

	nvm_for_each_pool(s, pool, i) {
		struct greedy_pool *gpool = greedy_pool(pool);
		if (!gpool || !gpool->block_mem)
			break;
		vfree(gpool->block_mem);
	}

	/* All per-pool GC-data space was allocated in one go, so this suffices */
	if (s->nr_pools && s->pools && s->pools[0].gc_private)
		kfree(s->pools[0].gc_private);
}

static int nvm_greedy_init(struct nvm_stor *s)
{
	struct greedy_pool *pool_mem;
	struct nvm_pool *pool;
	int i, j;

	pool_mem = kcalloc(s->nr_pools, sizeof(struct greedy_pool),
						GFP_KERNEL);
	if (!pool_mem) {
		pr_err("nvm: failed allocating pools for greedy GC\n");
		return -ENOMEM;
	}

	nvm_for_each_pool(s, pool, i) {
		struct greedy_pool *gpool = &pool_mem[i];
		struct nvm_block *block;

		pool->gc_private = gpool;
		gpool->pool = pool;

		INIT_LIST_HEAD(&gpool->prio_list);
		INIT_WORK(&gpool->ws_gc, nvm_greedy_pool_gc);

		gpool->block_mem = vzalloc(sizeof(struct greedy_block) * s->nr_blks_per_pool);
		if (!gpool->block_mem) {
			pr_err("nvm: failed allocating blocks for greedy "
				"GC (in pool %d of %d)!\n", i, s->nr_pools);
			nvm_greedy_free(s);
			return -ENOMEM;
		}

		pool_for_each_block(pool, block, j) {
			struct greedy_block *gblock = &gpool->block_mem[j];

			block->gc_private = gblock;
			gblock->block = block;

			INIT_LIST_HEAD(&gblock->prio);
			INIT_WORK(&gblock->ws_gc, nvm_greedy_block_gc);
			INIT_WORK(&gblock->ws_queue_gc, nvm_greedy_queue_gc);
		}
	}

	return 0;
}

static void nvm_greedy_exit(struct nvm_stor *s)
{
	nvm_greedy_free(s);
}

struct nvm_gc_type nvm_gc_greedy = {
	.name 		= "greedy",
	.version 	= {1, 0, 0},

	.gc_timer	= nvm_gc_timer,
	.queue		= nvm_greedy_queue,
	.kick		= nvm_greedy_kick,

	.init		= nvm_greedy_init,
	.exit		= nvm_greedy_exit,
};

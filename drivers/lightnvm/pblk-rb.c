/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <jg@lightnvm.io>
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
 * pblk-rb.c - pblk's ring buffer
 */

#include <linux/circ_buf.h>

#include "pblk.h"

static DECLARE_RWSEM(pblk_rb_lock);

void pblk_rb_data_free(struct pblk_rb *rb)
{
	struct pblk_rb_pages *p, *t;

	down_write(&pblk_rb_lock);
	list_for_each_entry_safe(p, t, &rb->pages, list) {
		free_pages((unsigned long)page_address(p->pages), p->order);
		list_del(&p->list);
		kfree(p);
	}
	up_write(&pblk_rb_lock);
}

/*
 * Initialize ring buffer. The data and metadata buffers must be previously
 * allocated and their size must be a power of two
 * (Documentation/circular-buffers.txt)
 */
int pblk_rb_init(struct pblk_rb *rb, struct pblk_rb_entry *rb_entry_base,
		 unsigned int power_size, unsigned int power_seg_sz)
{
	unsigned long init_entries = 0;
	unsigned int alloc_order = power_size;
	unsigned int max_order = MAX_ORDER - 1;
	unsigned int order, iter;

	down_write(&pblk_rb_lock);
	rb->entries = rb_entry_base;
	rb->seg_size = (1 << power_seg_sz);
	rb->nr_entries = (1 << power_size);
	rb->mem = rb->subm = rb->sync = rb->l2p_update = 0;
	rb->sync_point = RB_EMPTY_ENTRY;

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->r_lock);
	spin_lock_init(&rb->s_lock);

	INIT_LIST_HEAD(&rb->pages);

	if (alloc_order >= max_order) {
		order = max_order;
		iter = (1 << (alloc_order - max_order));
	} else {
		order = alloc_order;
		iter = 1;
	}

	do {
		struct pblk_rb_entry *entry;
		struct pblk_rb_pages *page_set;
		void *kaddr;
		unsigned long set_size;
		int i;

		page_set = kmalloc(sizeof(struct pblk_rb_pages), GFP_KERNEL);
		if (!page_set) {
			up_write(&pblk_rb_lock);
			return -ENOMEM;
		}

		page_set->order = order;
		page_set->pages = alloc_pages(GFP_KERNEL, order);
		if (!page_set->pages) {
			kfree(page_set);
			pblk_rb_data_free(rb);
			up_write(&pblk_rb_lock);
			return -ENOMEM;
		}
		kaddr = page_address(page_set->pages);

		entry = &rb->entries[init_entries++];
		entry->data = kaddr;
		entry->w_ctx.flags |= PBLK_WRITABLE_ENTRY;

		set_size = (1 << order);
		for (i = 1; i < set_size; i++) {
			entry = &rb->entries[init_entries++];
			entry->data = kaddr + (i * rb->seg_size);
			entry->w_ctx.flags |= PBLK_WRITABLE_ENTRY;
		}

		list_add_tail(&page_set->list, &rb->pages);
		iter--;
	} while (iter > 0);
	up_write(&pblk_rb_lock);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&rb->inflight_sync_point, 0);
#endif

	return 0;
}

unsigned long pblk_rb_nr_entries(struct pblk_rb *rb)
{
	return rb->nr_entries;
}

/*
 * pblk_rb_calculate_size -- calculate the size of the write buffer
 */
unsigned long pblk_rb_calculate_size(unsigned long nr_entries)
{
	unsigned int power_size;

	power_size = get_count_order(nr_entries);

	/* Have a write buffer that can fit 256KB I/Os */
	power_size = (power_size < 7) ? 7 : power_size;
	return (1 << power_size);
}

void *pblk_rb_entries_ref(struct pblk_rb *rb)
{
	return rb->entries;
}

static void clean_wctx(struct pblk_w_ctx *w_ctx)
{
	w_ctx->flags = PBLK_WRITABLE_ENTRY;
	ppa_set_empty(&w_ctx->ppa.ppa);
	w_ctx->ppa.rblk = NULL;
}

#define pblk_rb_ring_count(head, tail, size) CIRC_CNT(head, tail, size)
#define pblk_rb_ring_space(rb, head, tail, size) \
					(CIRC_SPACE(head, tail, size))

/*
 * Buffer space is calculated with respect to the back pointer signaling
 * synchronized entries to the media.
 */
unsigned long pblk_rb_space(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long sync = READ_ONCE(rb->sync);

	return pblk_rb_ring_space(rb, mem, sync, rb->nr_entries);
}

/*
 * Buffer count is calculated with respect to the submission entry signaling the
 * entries that are available to send to the media
 */
unsigned long pblk_rb_count(struct pblk_rb *rb)
{
	unsigned long mem = READ_ONCE(rb->mem);
	unsigned long subm = READ_ONCE(rb->subm);

	return pblk_rb_ring_count(mem, subm, rb->nr_entries);
}

/*
 * Returns how many entries are on the write buffer at the time of call and
 * takes the submission lock. The lock is only taken if there are any entries on
 * the buffer. This guarantees that at least the returned amount of entries
 * will be on the buffer when reading from it.
 */
unsigned long pblk_rb_read_lock(struct pblk_rb *rb)
{
	unsigned long ret;

	spin_lock(&rb->r_lock);

	ret = pblk_rb_count(rb);
	if (!ret)
		spin_unlock(&rb->r_lock);
	return ret;
}

unsigned long pblk_rb_read_commit(struct pblk_rb *rb, unsigned int nr_entries)
{
	unsigned long subm;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rb->r_lock);
#endif

	subm = READ_ONCE(rb->subm);
	/* Commit read means updating submission pointer */
	smp_store_release(&rb->subm,
				(subm + nr_entries) & (rb->nr_entries - 1));
	spin_unlock(&rb->r_lock);

	return subm;
}

void pblk_rb_read_unlock(struct pblk_rb *rb)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rb->r_lock);
#endif
	spin_unlock(&rb->r_lock);
}

static void pblk_rb_requeue_entry(struct pblk_rb *rb,
				  struct pblk_rb_entry *entry)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct ppa_addr ppa;
	unsigned long mem, sync;

	/* Serialized in pblk_rb_write_init */
	mem = READ_ONCE(rb->mem);
	sync = READ_ONCE(rb->sync);

	/* Maintain original bio, lba and flags */
	pblk_ppa_set_empty(&entry->w_ctx.ppa);
	entry->w_ctx.paddr = 0;

	/* Move entry to the head of the write buffer and update l2p */
	while (pblk_rb_ring_space(rb, mem, sync, rb->nr_entries) < 1)
		;
	pblk_rb_write_entry(rb, entry->data, entry->w_ctx, mem);

	ppa = pblk_cacheline_to_ppa(mem);
	pblk_update_map(pblk, entry->w_ctx.lba, NULL, ppa);

	/* Update memory pointer (head) */
	smp_store_release(&rb->mem, (mem + 1) & (rb->nr_entries - 1));

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&pblk->inflight_writes);
	atomic_inc(&pblk->requeued_writes);
#endif
}

static void pblk_rb_update_map(struct pblk *pblk, struct pblk_w_ctx *w_ctx)
{
	struct pblk_block *rblk = w_ctx->ppa.rblk;
	struct ppa_addr ppa = w_ctx->ppa.ppa;

	pblk_update_map(pblk, w_ctx->lba, rblk, ppa);
}

static int __pblk_rb_update_l2p(struct pblk_rb *rb, unsigned long *l2p_upd,
				unsigned long to_update)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct pblk_block *rblk;
	unsigned long i;

	for (i = 0; i < to_update; i++) {
		entry = &rb->entries[*l2p_upd];
		w_ctx = &entry->w_ctx;
		rblk = w_ctx->ppa.rblk;

		/* Grown bad block. For now, we requeue the entry to the write
		 * buffer and make it take the normal path to get a new ppa
		 * mapping. Since the requeue takes a place on the buffer,
		 * unpdate an extra entry.
		 */
		if (unlikely(block_is_bad(rblk))) {
			pblk_rb_requeue_entry(rb, entry);
			goto next_unlock;
		}

		pblk_rb_update_map(pblk, w_ctx);
next_unlock:
		clean_wctx(w_ctx);
		*l2p_upd = (*l2p_upd + 1) & (rb->nr_entries - 1);
	}

	return 0;
}

/*
 * When we move the l2p_update pointer, we update the l2p table - lookups will
 * point to the physical address instead of to the cacheline in the write buffer
 * from this moment on.
 */
static int pblk_rb_update_l2p(struct pblk_rb *rb, unsigned int nr_entries,
			      unsigned long mem, unsigned long sync)
{
	unsigned long count;
	int ret = 0;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rb->w_lock);
#endif

	/* Update l2p as data is being overwritten */
	if (pblk_rb_ring_space(rb, mem, rb->l2p_update, rb->nr_entries) >
								nr_entries)
		goto out;

	count = pblk_rb_ring_count(sync, rb->l2p_update, rb->nr_entries);
	ret = __pblk_rb_update_l2p(rb, &rb->l2p_update, count);

out:
	return ret;
}

/*
 * Update the l2p entry for all sectors stored on the write buffer. This means
 * that all future lookups to the l2p table will point to a device address, not
 * to the cacheline in the write buffer.
 */
void pblk_rb_sync_l2p(struct pblk_rb *rb)
{
	unsigned long sync;
	unsigned int to_update;

	spin_lock(&rb->w_lock);

	/* Protect from reads and writes */
	sync = smp_load_acquire(&rb->sync);

	to_update = pblk_rb_ring_count(sync, rb->l2p_update, rb->nr_entries);
	__pblk_rb_update_l2p(rb, &rb->l2p_update, to_update);

	spin_unlock(&rb->w_lock);
}

/*
 * Write @nr_entries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 */
void pblk_rb_write_entry(struct pblk_rb *rb, void *data,
			 struct pblk_w_ctx w_ctx,
			 unsigned int ring_pos)
{
	struct pblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
try:
	flags = READ_ONCE(entry->w_ctx.flags);
	if (!(flags & PBLK_WRITABLE_ENTRY))
		goto try;

	memcpy(entry->data, data, rb->seg_size);

	entry->w_ctx.bio = w_ctx.bio;
	entry->w_ctx.lba = w_ctx.lba;
	entry->w_ctx.ppa = w_ctx.ppa;
	entry->w_ctx.paddr = w_ctx.paddr;
	entry->w_ctx.priv = w_ctx.priv;
	flags |= w_ctx.flags;

	if (w_ctx.bio) {
		/* Release pointer controlling flushes */
		smp_store_release(&rb->sync_point, ring_pos);
	}

	flags &= ~PBLK_WRITABLE_ENTRY;
	flags |= PBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

int pblk_rb_may_write(struct pblk_rb *rb, unsigned int nr_upd,
		      unsigned int nr_com, unsigned long *pos)
{
	unsigned long mem;
	unsigned long sync;

	spin_lock(&rb->w_lock);
	sync = READ_ONCE(rb->sync);
	mem = rb->mem;

	if (pblk_rb_ring_space(rb, mem, sync, rb->nr_entries) < nr_upd) {
		spin_unlock(&rb->w_lock);
		return 0;
	}

	if (pblk_rb_update_l2p(rb, nr_upd, mem, sync)) {
		spin_unlock(&rb->w_lock);
		return 0;
	}

	/* Protect from read count */
	smp_store_release(&rb->mem, (mem + nr_com) & (rb->nr_entries - 1));
	spin_unlock(&rb->w_lock);

	*pos = mem;
	return 1;
}

/*
 * The caller of this function must ensure that the backpointer will not
 * overwrite the entries passed on the list.
 */
unsigned int pblk_rb_read_to_bio_list(struct pblk_rb *rb, struct bio *bio,
				      struct pblk_ctx *ctx,
				      struct list_head *list,
				      unsigned int max)
{
	struct pblk_rb_entry *entry, *tentry;
	struct page *page;
	unsigned int read = 0;
	int ret;

	list_for_each_entry_safe(entry, tentry, list, index) {
		if (read > max) {
			pr_err("pblk: too many entries on list\n");
			goto out;
		}

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("pblk: could not allocate write bio page\n");
			goto out;
		}

		ret = bio_add_page(bio, page, rb->seg_size, 0);
		if (ret != rb->seg_size) {
			pr_err("pblk: could not add page to write bio\n");
			goto out;
		}

		list_del(&entry->index);
		read++;
	}

out:
	return read;
}

/*
 * Read available entries on rb and add them to the given bio. To avoid a memory
 * copy, a page reference to the write buffer is used to be added to the bio.
 *
 * This function is used by the write thread to form the write bio that will
 * persist data on the write buffer to the media.
 */
unsigned int pblk_rb_read_to_bio(struct pblk_rb *rb, struct bio *bio,
				 struct pblk_ctx *ctx,
				 unsigned long pos,
				 unsigned int nr_entries,
				 unsigned int count,
				 unsigned long *sync_point)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct pblk_compl_ctx *c_ctx = ctx->c_ctx;
	struct pblk_rb_entry *entry;
	struct page *page;
	unsigned int pad = 0, read = 0, to_read = nr_entries;
	unsigned int user_io = 0, gc_io = 0;
	unsigned int i;
	int flags;
	int ret;

	if (count < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	c_ctx->sentry = pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[pos];

		/* A write has been allowed into the buffer, but data is still
		 * being copied to it. It is ok to busy wait.
		 */
try:
		flags = READ_ONCE(entry->w_ctx.flags);
		if (!(flags & PBLK_WRITTEN_DATA))
			goto try;

		if (flags & PBLK_IOTYPE_USER)
			user_io++;
		else if (flags & PBLK_IOTYPE_GC)
			gc_io++;
		else
			WARN(1, "pblk: unknown IO type\n");

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("pblk: could not allocate write bio page\n");
			flags &= ~PBLK_WRITTEN_DATA;
			flags |= PBLK_WRITABLE_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			goto out;
		}

		ret = bio_add_page(bio, page, rb->seg_size, 0);
		if (ret != rb->seg_size) {
			pr_err("pblk: could not add page to write bio\n");
			flags &= ~PBLK_WRITTEN_DATA;
			flags |= PBLK_WRITABLE_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			goto out;
		}

		if (entry->w_ctx.bio != NULL) {
			*sync_point = pos;
#ifdef CONFIG_NVM_DEBUG
			atomic_dec(&rb->inflight_sync_point);
#endif
		}

		flags &= ~PBLK_WRITTEN_DATA;
		flags |= PBLK_WRITABLE_ENTRY;

		/* Release flags on context. Protect from writes */
		smp_store_release(&entry->w_ctx.flags, flags);

		pos = (pos + 1) & (rb->nr_entries - 1);
	}

	read = to_read;

	pblk_rl_out(pblk, user_io, gc_io);

#ifdef CONFIG_NVM_DEBUG
	atomic_add(pad, &((struct pblk *)
			(container_of(rb, struct pblk, rwb)))->padded_writes);
#endif

out:
	return read;
}

void pblk_rb_copy_to_bio(struct pblk_rb *rb, struct bio *bio, u64 pos)
{
	struct pblk_rb_entry *entry;
	void *data;

	spin_lock(&rb->w_lock);

#ifdef CONFIG_NVM_DEBUG
	BUG_ON(pos >= rb->nr_entries);
#endif
	entry = &rb->entries[pos];

	data = bio_data(bio);
	memcpy(data, entry->data, rb->seg_size);

	spin_unlock(&rb->w_lock);
}

struct pblk_w_ctx *pblk_rb_w_ctx(struct pblk_rb *rb, unsigned long pos)
{
	unsigned long entry = pos & (rb->nr_entries - 1);

	return &rb->entries[entry].w_ctx;
}

unsigned long pblk_rb_sync_init(struct pblk_rb *rb, unsigned long *flags)
{
	if (flags)
		spin_lock_irqsave(&rb->s_lock, *flags);
	else
		spin_lock_irq(&rb->s_lock);

	return rb->sync;
}

unsigned long pblk_rb_sync_advance(struct pblk_rb *rb, unsigned int nr_entries)
{
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	unsigned long sync;
	unsigned long i;

#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rb->s_lock);
#endif

	sync = READ_ONCE(rb->sync);

	for (i = 0; i < nr_entries; i++) {
		entry = &rb->entries[sync];
		w_ctx = &entry->w_ctx;

		if (w_ctx->flags & PBLK_IOTYPE_REF) {
			struct pblk_kref_buf *ref_buf;

			/* logic error */
			BUG_ON(!w_ctx->priv);
			ref_buf = w_ctx->priv;
			if (kref_put(&ref_buf->ref, pblk_free_ref_mem))
				w_ctx->priv = NULL;

			w_ctx->flags &= ~PBLK_IOTYPE_REF;
		}

		sync = (sync + 1) & (rb->nr_entries - 1);
	}

	/* Protect from counts */
	smp_store_release(&rb->sync, sync);

	return sync;
}

void pblk_rb_sync_end(struct pblk_rb *rb, unsigned long *flags)
{
#ifdef CONFIG_NVM_DEBUG
	lockdep_assert_held(&rb->s_lock);
#endif

	if (flags)
		spin_unlock_irqrestore(&rb->s_lock, *flags);
	else
		spin_unlock_irq(&rb->s_lock);
}

int pblk_rb_sync_point_set(struct pblk_rb *rb, struct bio *bio)
{
	struct pblk_rb_entry *entry;
	unsigned long mem, subm, sync_point;
	int ret = 0;

	spin_lock(&rb->r_lock);

	/* Protect from reads and writes */
	mem = smp_load_acquire(&rb->mem);
	/* Protect syncs */
	sync_point = smp_load_acquire(&rb->sync_point);
	subm = READ_ONCE(rb->subm);

#ifdef CONFIG_NVM_DEBUG
	atomic_inc(&rb->inflight_sync_point);
#endif

	if (mem == subm)
		goto out;

	sync_point = (mem == 0) ? (rb->nr_entries - 1) : (mem - 1);
	entry = &rb->entries[sync_point];

	if (entry->w_ctx.bio) {
		pr_err("pblk: Duplicated sync point:%lu\n", sync_point);
		ret = -EINVAL;
		goto out;
	}

	entry->w_ctx.bio = bio;

	/* Protect syncs */
	smp_store_release(&rb->sync_point, sync_point);

	ret = 1;

out:
	spin_unlock(&rb->r_lock);
	return ret;
}

void pblk_rb_sync_point_reset(struct pblk_rb *rb, unsigned long sp)
{
	unsigned long sync_point;

	/* Protect syncs */
	sync_point = smp_load_acquire(&rb->sync_point);

	if (sync_point == sp) {
		/* Protect syncs */
		smp_store_release(&rb->sync_point, ADDR_EMPTY);
	}
}

unsigned long pblk_rb_sync_point_count(struct pblk_rb *rb)
{
	unsigned long subm, sync_point, count;

	/* Protect syncs */
	sync_point = smp_load_acquire(&rb->sync_point);
	if (sync_point == ADDR_EMPTY)
		return 0;

	subm = READ_ONCE(rb->subm);

	/* The sync point itself counts as a sector to sync */
	count = pblk_rb_ring_count(sync_point, subm, rb->nr_entries) + 1;

	return count;
}

/*
 * Scan from the current position of the sync pointer to find the entry that
 * corresponds to the given ppa. This is necessary since write requests can be
 * completed out of order. The assumption is that the ppa is close to the sync
 * pointer thus the search will not take long.
 *
 * The caller of this function must guarantee that the sync pointer will no
 * reach the entry while it is using the metadata associated with it. With this
 * assumption in mind, there is no need to take the sync lock.
 */
struct pblk_rb_entry *pblk_rb_sync_scan_entry(struct pblk_rb *rb,
					      struct ppa_addr *ppa)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_rb_entry *entry;
	struct pblk_w_ctx *w_ctx;
	struct ppa_addr gppa;
	unsigned long sync, subm, count;
	unsigned long i;

	sync = READ_ONCE(rb->sync);
	subm = READ_ONCE(rb->subm);
	count = pblk_rb_ring_count(subm, sync, rb->nr_entries);

	for (i = 0; i < count; i++) {
		entry = &rb->entries[sync];
		w_ctx = &entry->w_ctx;

		gppa = pblk_blk_ppa_to_gaddr(dev, w_ctx->ppa.rblk, w_ctx->paddr);

		if (gppa.ppa == ppa->ppa)
			return entry;

		sync = (sync + 1) & (rb->nr_entries - 1);
	}

	return NULL;
}

int pblk_rb_tear_down_check(struct pblk_rb *rb)
{
	struct pblk_rb_entry *entry;
	int i;
	int ret = 0;

	spin_lock(&rb->w_lock);
	spin_lock(&rb->r_lock);
	spin_lock_irq(&rb->s_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				(rb->sync_point == RB_EMPTY_ENTRY)) {
		goto out;
	}

	if (rb->entries)
		goto out;

	for (i = 0; i < rb->nr_entries; i++) {
		entry = &rb->entries[i];

		if (entry->data)
			goto out;
	}

	ret = 1;

out:
	spin_unlock(&rb->w_lock);
	spin_unlock(&rb->r_lock);
	spin_unlock_irq(&rb->s_lock);

	return ret;
}

unsigned long pblk_rb_wrap_pos(struct pblk_rb *rb, unsigned long pos)
{
	return (pos & (rb->nr_entries - 1));
}

int pblk_rb_pos_oob(struct pblk_rb *rb, u64 pos)
{
	return (pos >= rb->nr_entries);
}

#ifdef CONFIG_NVM_DEBUG
ssize_t pblk_rb_sysfs(struct pblk_rb *rb, char *buf)
{
	ssize_t offset;

	if (rb->sync_point != ADDR_EMPTY)
		offset = scnprintf(buf, PAGE_SIZE,
			"%lu\t%lu\t%lu\t%lu\t%lu\t%u\t%lu\n",
			rb->nr_entries,
			rb->mem,
			rb->subm,
			rb->sync,
			rb->l2p_update,
			atomic_read(&rb->inflight_sync_point),
			rb->sync_point);
	else
		offset = scnprintf(buf, PAGE_SIZE,
			"%lu\t%lu\t%lu\t%lu\t%lu\t%u\tNULL\n",
			rb->nr_entries,
			rb->mem,
			rb->subm,
			rb->sync,
			rb->l2p_update,
			atomic_read(&rb->inflight_sync_point));

	return offset;
}
#endif


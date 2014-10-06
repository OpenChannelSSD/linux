#define DEBUG
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include "nvm.h"

/* inflight uses jenkins hash - less to compare, collisions only result
 * in unecessary serialisation.
 *
 * could restrict oneself to only grabbing table lock whenever you specifically
 * want a new entry -- otherwise no concurrent threads will ever be interested
 * in the same entry
 */

#define BUCKET_LEN 16
#define BUCKET_OCCUPANCY_AVG (BUCKET_LEN / 4)

struct kv_inflight {
	struct list_head list;
	u32	h1;
};

struct kv_entry {
	u64 hash[2];
	struct nvm_block *blk;
};

struct nvmkv_io {
	int offset;
	unsigned npages;
	unsigned length;
	struct page **pages;
	struct nvm_block *block;
	int write;
};

enum {
	EXISTING_ENTRY	= 0,
	NEW_ENTRY	= 1,
};

static inline unsigned bucket_idx(struct nvmkv_tbl *tbl, u32 hash)
{
	return hash % (tbl->tbl_len / BUCKET_LEN);
}

static void inflight_lock(struct nvmkv_inflight *ilist,
						struct kv_inflight *ientry)
{
	struct kv_inflight *lentry;
	unsigned long flags;

retry:
	spin_lock_irqsave(&ilist->lock, flags);

	list_for_each_entry(lentry, &ilist->list, list) {
		if (lentry->h1 == ientry->h1) {
			spin_unlock_irqrestore(&ilist->lock, flags);
			schedule();
			goto retry;
		}
	}

	list_add_tail(&ientry->list, &ilist->list);
	spin_unlock_irqrestore(&ilist->lock, flags);
}

static void inflight_unlock(struct nvmkv_inflight *ilist, u32 h1)
{
	struct kv_inflight *lentry;
	unsigned long flags;

	spin_lock_irqsave(&ilist->lock, flags);
	BUG_ON(list_empty(&ilist->list));

	list_for_each_entry(lentry, &ilist->list, list) {
		if (lentry->h1 == h1) {
			list_del(&lentry->list);
			goto out;
		}
	}

	BUG();
out:
	spin_unlock_irqrestore(&ilist->lock, flags);
}

/*TODO reserving '0' for empty entries is technically a no-go as it could be
  a hash value.*/
static int __tbl_get_idx(struct nvmkv_tbl *tbl, u32 h1, const u64 *h2,
							unsigned int type)
{
	unsigned b_idx = bucket_idx(tbl, h1);
	unsigned idx = BUCKET_LEN * b_idx;
	struct kv_entry *entry = &tbl->entries[idx];
	unsigned i;

	for (i = 0; i < BUCKET_LEN; i++, entry++) {
		if (!memcmp(entry->hash, h2, sizeof(u64) * 2)) {
			if (type == NEW_ENTRY)
				entry->hash[0] = 1;
			idx += i;
			break;
		}
	}

	if (i == BUCKET_LEN)
		idx = -1;

	return idx;
}

static int tbl_get_idx(struct nvmkv_tbl *tbl, u32 h1, const u64 *h2,
							unsigned int type)
{
	int idx;

	spin_lock(&tbl->lock);
	idx = __tbl_get_idx(tbl, h1, h2, type);
	spin_unlock(&tbl->lock);
	return idx;
}


static int tbl_new_entry(struct nvmkv_tbl *tbl, u32 h1)
{
	const u64 empty[2] = { 0, 0 };

	return tbl_get_idx(tbl, h1, empty, NEW_ENTRY);
}

static u32 hash1(void *key, unsigned key_len)
{
	u32 hash;
	u32 *p = (u32 *) key;
	u32 len = key_len / sizeof(u32);
	u32 offset = key_len % sizeof(u32);

	if (offset) {
		memcpy(&offset, p + len, offset);
		hash = jhash2(p, len, 0);
		return jhash2(&offset, 1, hash);
	}
	return jhash2(p, len, 0);
}

static void hash2(void *dst, void *src, size_t src_len)
{
	struct scatterlist sg;
	struct hash_desc hdesc;

	sg_init_one(&sg, src, src_len);
	hdesc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	crypto_hash_init(&hdesc);
	crypto_hash_update(&hdesc, &sg, src_len);
	crypto_hash_final(&hdesc, (u8 *)dst);
	crypto_free_hash(hdesc.tfm);
}

static void *cpy_val(u64 addr, size_t len)
{
	void *buf;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(buf, (void *)addr, len)) {
		kfree(buf);
		return ERR_PTR(-EFAULT);
	}
	return buf;
}

static int do_io(struct nvm_stor *s, int rw, u64 blk_addr, void __user *ubuf,
							unsigned long len)
{
	struct nvm_dev *dev = s->dev;
	struct request_queue *q = dev->q;
	struct request *rq;
	struct bio *orig_bio;
	int ret;

	rq = blk_mq_alloc_request(q, rw, GFP_KERNEL, false);
	if (!rq) {
		pr_err("lightnvm: failed to allocate request\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = blk_rq_map_user(q, rq, NULL, ubuf, len, GFP_KERNEL);
	if (ret) {
		pr_err("lightnvm: failed to map userspace memory into request\n");
		goto err_umap;
	}
	orig_bio = rq->bio;

	rq->cmd_flags |= REQ_NVM;
	rq->__sector = blk_addr * NR_PHY_IN_LOG;
	rq->errors = 0;

	ret = blk_execute_rq(q, dev->disk, rq, 0);
	if (ret)
		pr_err("lightnvm: failed to execute request..\n");

	blk_rq_unmap_user(orig_bio);

err_umap:
	blk_put_request(rq);
out:
	return ret;
}

/**
 *	get	-	get value from KV store
 *	@s: nvm stor
 *	@cmd: LightNVM KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Fetch value identified by the supplied key.
 */
static int get(struct nvm_stor *s, struct lightnvm_cmd_kv *cmd, void *key,
									u32 h1)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;

	u64 h2[2];
	int idx;

	hash2(&h2, key, cmd->key_len);

	idx = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY);
	if (idx < 0)
		return LIGHTNVM_KV_ERR_NOKEY;

	entry = &tbl->entries[idx];

	return do_io(s, READ, block_to_addr(entry->blk),
			(void __user *)cmd->val_addr, cmd->val_len);
}

static struct nvm_block *acquire_block(struct nvm_stor *s)
{
	struct nvm_ap *ap;
	struct nvm_pool *pool;
	struct nvm_block *block = NULL;
	int i;

	for (i = 0; i < s->nr_aps; i++) {
		ap = get_next_ap(s);
		pool = ap->pool;

		block = s->type->pool_get_blk(pool, 0);
		if (block)
			break;
	}
	return block;
}

static int update_entry(struct nvm_stor *s, struct lightnvm_cmd_kv *cmd,
			struct kv_entry *entry)
{
	struct nvm_block *block;
	int ret;

	BUG_ON(!s);
	BUG_ON(!cmd);
	BUG_ON(!entry);

	block = acquire_block(s);
	if (!block) {
		pr_err("lightnvm: failed to acquire a block\n");
		ret = -ENOSPC;
		goto no_block;
	}
	ret = do_io(s, WRITE, block_to_addr(block),
				(void __user *)cmd->val_addr, cmd->val_len);
	if (ret) {
		pr_err("lightnvm: failed to write entry\n");
		ret = -EIO;
		goto io_err;
	}

	if (entry->blk)
		s->type->pool_put_blk(entry->blk);

	entry->blk = block;

	return ret;
io_err:
	s->type->pool_put_blk(block);
no_block:
	return ret;
}

/**
 * put - put/update value in KV store
 * @s: nvm stor
 * @cmd: LightNVM KV command
 * @key: copy of key supplied from userspace.
 * @h1: hash of key value using hash function 1
 *
 * Store the supplied value in an entry identified by the
 * supplied key. Will overwrite existing entry if necessary.
 */
static int put(struct nvm_stor *s, struct lightnvm_cmd_kv *cmd, void *key,
									u32 h1)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int idx, ret;

	hash2(&h2, key, cmd->key_len);

	idx = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY);
	if (idx != -1) {
		entry = &tbl->entries[idx];
	} else {
		idx = tbl_new_entry(tbl, h1);
		if (idx != -1) {
			entry = &tbl->entries[idx];
			memcpy(entry->hash, &h2, sizeof(entry->hash));
		} else {
			pr_err("lightnvm: no empty entries\n");
			BUG();
		}
	}

	ret = update_entry(s, cmd, entry);

	/* If update_entry failed, we reset the entry->hash, as it was updated
	 * by the previous statements and is no longer valid */
	if (!entry->blk)
		memset(entry->hash, 0, sizeof(entry->hash));

	return ret;
}

/**
 *	update	-	 update existing entry
 *	@s: nvm stor
 *	@cmd: LightNVM KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Updates existing value identified by 'k' to the new value.
 *	Operation only succeeds if k points to an existing value.
 */
static int update(struct nvm_stor *s, struct lightnvm_cmd_kv *cmd, void *key,
									u32 h1)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int ret;

	hash2(&h2, key, cmd->key_len);

	ret = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY);
	if (ret < 0) {
		pr_debug("lightnvm: no entry, skipping\n");
		return 0;
	}

	entry = &tbl->entries[ret];

	ret = update_entry(s, cmd, entry);
	if (ret)
		memset(entry->hash, 0, sizeof(entry->hash));
	return ret;
}

/**
 *	del	 -	 delete entry.
 *	@s: nvm stor
 *	@cmd: LightNVM KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Removes the value associated the supplied key.
 */
static int del(struct nvm_stor *s, struct lightnvm_cmd_kv *cmd, void *key,
									u32 h1)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int idx;

	hash2(&h2, key, cmd->key_len);

	idx = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY);
	if (idx != -1) {
		entry = &tbl->entries[idx];
		s->type->pool_put_blk(entry->blk);
		memset(entry, 0, sizeof(struct kv_entry));
	} else {
		pr_debug("lightnvm: could not find entry!\n");
	}

	return 0;
}

int nvm_rq_kv(struct nvm_dev *dev, struct lightnvm_cmd_kv __user *ucmd)
{
	struct nvm_stor *s = dev->stor;
	struct nvmkv_inflight *inflight = &s->kv.inflight;
	struct kv_inflight *ientry;
	struct lightnvm_cmd_kv cmd;
	u32 h1;
	void *key;
	int ret = 0;

	if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;

	key = cpy_val(cmd.key_addr, cmd.key_len);
	if (IS_ERR(key)) {
		ret = -ENOMEM;
		goto out;
	}

	h1 = hash1(key, cmd.key_len);
	ientry = kmem_cache_alloc(inflight->entry_pool, GFP_KERNEL);
	if (!ientry) {
		ret = -ENOMEM;
		goto err_ientry;
	}
	ientry->h1 = h1;

	inflight_lock(inflight, ientry);

	switch (cmd.opcode) {
	case LIGHTNVM_KV_GET:
		ret = get(s, &cmd, key, h1);
		break;
	case LIGHTNVM_KV_PUT:
		ret = put(s, &cmd, key, h1);
		break;
	case LIGHTNVM_KV_UPDATE:
		ret = update(s, &cmd, key, h1);
		break;
	case LIGHTNVM_KV_DEL:
		ret = del(s, &cmd, key, h1);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	inflight_unlock(inflight, h1);

err_ientry:
	kfree(key);
out:
	if (ret > 0) {
		ucmd->errcode = ret;
		ret = 0;
	}
	return ret;
}

int nvmkv_init(struct nvm_stor *s, unsigned long size)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct nvmkv_inflight *inflight = &s->kv.inflight;
	int ret = 0;

	unsigned long buckets = s->total_blocks
					/ (BUCKET_LEN / BUCKET_OCCUPANCY_AVG);

	tbl->bucket_len = BUCKET_LEN;
	tbl->tbl_len = buckets * tbl->bucket_len;

	tbl->entries = vzalloc(tbl->tbl_len * sizeof(struct kv_entry));
	if (!tbl->entries) {
		ret = -ENOMEM;
		goto err_tbl_entries;
	}

	inflight->entry_pool = kmem_cache_create("nvmkv_inflight_pool",
				sizeof(struct kv_inflight), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
				NULL);
	if (!inflight->entry_pool) {
		ret = -ENOMEM;
		goto err_inflight_pool;
	}

	spin_lock_init(&tbl->lock);
	INIT_LIST_HEAD(&inflight->list);
	spin_lock_init(&inflight->lock);

	return 0;

err_inflight_pool:
	vfree(tbl->entries);
err_tbl_entries:
	return ret;
}

void nvmkv_exit(struct nvm_stor *s)
{
	struct nvmkv_tbl *tbl = &s->kv.tbl;
	struct nvmkv_inflight *inflight = &s->kv.inflight;

	vfree(tbl->entries);
	kmem_cache_destroy(inflight->entry_pool);
}

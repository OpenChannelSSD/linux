/*
 * drivers/net/ethernet/mellanox/mlxsw/core_acl_flex_actions.c
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2017 Jiri Pirko <jiri@mellanox.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/rhashtable.h>
#include <linux/list.h>

#include "item.h"
#include "core_acl_flex_actions.h"

enum mlxsw_afa_set_type {
	MLXSW_AFA_SET_TYPE_NEXT,
	MLXSW_AFA_SET_TYPE_GOTO,
};

/* afa_set_type
 * Type of the record at the end of the action set.
 */
MLXSW_ITEM32(afa, set, type, 0xA0, 28, 4);

/* afa_set_next_action_set_ptr
 * A pointer to the next action set in the KVD Centralized database.
 */
MLXSW_ITEM32(afa, set, next_action_set_ptr, 0xA4, 0, 24);

/* afa_set_goto_g
 * group - When set, the binding is of an ACL group. When cleared,
 * the binding is of an ACL.
 * Must be set to 1 for Spectrum.
 */
MLXSW_ITEM32(afa, set, goto_g, 0xA4, 29, 1);

enum mlxsw_afa_set_goto_binding_cmd {
	/* continue go the next binding point */
	MLXSW_AFA_SET_GOTO_BINDING_CMD_NONE,
	/* jump to the next binding point no return */
	MLXSW_AFA_SET_GOTO_BINDING_CMD_JUMP,
	/* terminate the acl binding */
	MLXSW_AFA_SET_GOTO_BINDING_CMD_TERM = 4,
};

/* afa_set_goto_binding_cmd */
MLXSW_ITEM32(afa, set, goto_binding_cmd, 0xA4, 24, 3);

/* afa_set_goto_next_binding
 * ACL/ACL group identifier. If the g bit is set, this field should hold
 * the acl_group_id, else it should hold the acl_id.
 */
MLXSW_ITEM32(afa, set, goto_next_binding, 0xA4, 0, 16);

/* afa_all_action_type
 * Action Type.
 */
MLXSW_ITEM32(afa, all, action_type, 0x00, 24, 6);

struct mlxsw_afa {
	unsigned int max_acts_per_set;
	const struct mlxsw_afa_ops *ops;
	void *ops_priv;
	struct rhashtable set_ht;
	struct rhashtable fwd_entry_ht;
};

#define MLXSW_AFA_SET_LEN 0xA8

struct mlxsw_afa_set_ht_key {
	char enc_actions[MLXSW_AFA_SET_LEN]; /* Encoded set */
	bool is_first;
};

/* Set structure holds one action set record. It contains up to three
 * actions (depends on size of particular actions). The set is either
 * put directly to a rule, or it is stored in KVD linear area.
 * To prevent duplicate entries in KVD linear area, a hashtable is
 * used to track sets that were previously inserted and may be shared.
 */

struct mlxsw_afa_set {
	struct rhash_head ht_node;
	struct mlxsw_afa_set_ht_key ht_key;
	u32 kvdl_index;
	bool shared; /* Inserted in hashtable (doesn't mean that
		      * kvdl_index is valid).
		      */
	unsigned int ref_count;
	struct mlxsw_afa_set *next; /* Pointer to the next set. */
	struct mlxsw_afa_set *prev; /* Pointer to the previous set,
				     * note that set may have multiple
				     * sets from multiple blocks
				     * pointing at it. This is only
				     * usable until commit.
				     */
};

static const struct rhashtable_params mlxsw_afa_set_ht_params = {
	.key_len = sizeof(struct mlxsw_afa_set_ht_key),
	.key_offset = offsetof(struct mlxsw_afa_set, ht_key),
	.head_offset = offsetof(struct mlxsw_afa_set, ht_node),
	.automatic_shrinking = true,
};

struct mlxsw_afa_fwd_entry_ht_key {
	u8 local_port;
};

struct mlxsw_afa_fwd_entry {
	struct rhash_head ht_node;
	struct mlxsw_afa_fwd_entry_ht_key ht_key;
	u32 kvdl_index;
	unsigned int ref_count;
};

static const struct rhashtable_params mlxsw_afa_fwd_entry_ht_params = {
	.key_len = sizeof(struct mlxsw_afa_fwd_entry_ht_key),
	.key_offset = offsetof(struct mlxsw_afa_fwd_entry, ht_key),
	.head_offset = offsetof(struct mlxsw_afa_fwd_entry, ht_node),
	.automatic_shrinking = true,
};

struct mlxsw_afa *mlxsw_afa_create(unsigned int max_acts_per_set,
				   const struct mlxsw_afa_ops *ops,
				   void *ops_priv)
{
	struct mlxsw_afa *mlxsw_afa;
	int err;

	mlxsw_afa = kzalloc(sizeof(*mlxsw_afa), GFP_KERNEL);
	if (!mlxsw_afa)
		return ERR_PTR(-ENOMEM);
	err = rhashtable_init(&mlxsw_afa->set_ht, &mlxsw_afa_set_ht_params);
	if (err)
		goto err_set_rhashtable_init;
	err = rhashtable_init(&mlxsw_afa->fwd_entry_ht,
			      &mlxsw_afa_fwd_entry_ht_params);
	if (err)
		goto err_fwd_entry_rhashtable_init;
	mlxsw_afa->max_acts_per_set = max_acts_per_set;
	mlxsw_afa->ops = ops;
	mlxsw_afa->ops_priv = ops_priv;
	return mlxsw_afa;

err_fwd_entry_rhashtable_init:
	rhashtable_destroy(&mlxsw_afa->set_ht);
err_set_rhashtable_init:
	kfree(mlxsw_afa);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(mlxsw_afa_create);

void mlxsw_afa_destroy(struct mlxsw_afa *mlxsw_afa)
{
	rhashtable_destroy(&mlxsw_afa->fwd_entry_ht);
	rhashtable_destroy(&mlxsw_afa->set_ht);
	kfree(mlxsw_afa);
}
EXPORT_SYMBOL(mlxsw_afa_destroy);

static void mlxsw_afa_set_goto_set(struct mlxsw_afa_set *set,
				   enum mlxsw_afa_set_goto_binding_cmd cmd,
				   u16 group_id)
{
	char *actions = set->ht_key.enc_actions;

	mlxsw_afa_set_type_set(actions, MLXSW_AFA_SET_TYPE_GOTO);
	mlxsw_afa_set_goto_g_set(actions, true);
	mlxsw_afa_set_goto_binding_cmd_set(actions, cmd);
	mlxsw_afa_set_goto_next_binding_set(actions, group_id);
}

static void mlxsw_afa_set_next_set(struct mlxsw_afa_set *set,
				   u32 next_set_kvdl_index)
{
	char *actions = set->ht_key.enc_actions;

	mlxsw_afa_set_type_set(actions, MLXSW_AFA_SET_TYPE_NEXT);
	mlxsw_afa_set_next_action_set_ptr_set(actions, next_set_kvdl_index);
}

static struct mlxsw_afa_set *mlxsw_afa_set_create(bool is_first)
{
	struct mlxsw_afa_set *set;

	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return NULL;
	/* Need to initialize the set to pass by default */
	mlxsw_afa_set_goto_set(set, MLXSW_AFA_SET_GOTO_BINDING_CMD_TERM, 0);
	set->ht_key.is_first = is_first;
	set->ref_count = 1;
	return set;
}

static void mlxsw_afa_set_destroy(struct mlxsw_afa_set *set)
{
	kfree(set);
}

static int mlxsw_afa_set_share(struct mlxsw_afa *mlxsw_afa,
			       struct mlxsw_afa_set *set)
{
	int err;

	err = rhashtable_insert_fast(&mlxsw_afa->set_ht, &set->ht_node,
				     mlxsw_afa_set_ht_params);
	if (err)
		return err;
	err = mlxsw_afa->ops->kvdl_set_add(mlxsw_afa->ops_priv,
					   &set->kvdl_index,
					   set->ht_key.enc_actions,
					   set->ht_key.is_first);
	if (err)
		goto err_kvdl_set_add;
	set->shared = true;
	set->prev = NULL;
	return 0;

err_kvdl_set_add:
	rhashtable_remove_fast(&mlxsw_afa->set_ht, &set->ht_node,
			       mlxsw_afa_set_ht_params);
	return err;
}

static void mlxsw_afa_set_unshare(struct mlxsw_afa *mlxsw_afa,
				  struct mlxsw_afa_set *set)
{
	mlxsw_afa->ops->kvdl_set_del(mlxsw_afa->ops_priv,
				     set->kvdl_index,
				     set->ht_key.is_first);
	rhashtable_remove_fast(&mlxsw_afa->set_ht, &set->ht_node,
			       mlxsw_afa_set_ht_params);
	set->shared = false;
}

static void mlxsw_afa_set_put(struct mlxsw_afa *mlxsw_afa,
			      struct mlxsw_afa_set *set)
{
	if (--set->ref_count)
		return;
	if (set->shared)
		mlxsw_afa_set_unshare(mlxsw_afa, set);
	mlxsw_afa_set_destroy(set);
}

static struct mlxsw_afa_set *mlxsw_afa_set_get(struct mlxsw_afa *mlxsw_afa,
					       struct mlxsw_afa_set *orig_set)
{
	struct mlxsw_afa_set *set;
	int err;

	/* There is a hashtable of sets maintained. If a set with the exact
	 * same encoding exists, we reuse it. Otherwise, the current set
	 * is shared by making it available to others using the hash table.
	 */
	set = rhashtable_lookup_fast(&mlxsw_afa->set_ht, &orig_set->ht_key,
				     mlxsw_afa_set_ht_params);
	if (set) {
		set->ref_count++;
		mlxsw_afa_set_put(mlxsw_afa, orig_set);
	} else {
		set = orig_set;
		err = mlxsw_afa_set_share(mlxsw_afa, set);
		if (err)
			return ERR_PTR(err);
	}
	return set;
}

/* Block structure holds a list of action sets. One action block
 * represents one chain of actions executed upon match of a rule.
 */

struct mlxsw_afa_block {
	struct mlxsw_afa *afa;
	bool finished;
	struct mlxsw_afa_set *first_set;
	struct mlxsw_afa_set *cur_set;
	unsigned int cur_act_index; /* In current set. */
	struct list_head fwd_entry_ref_list;
};

struct mlxsw_afa_block *mlxsw_afa_block_create(struct mlxsw_afa *mlxsw_afa)
{
	struct mlxsw_afa_block *block;

	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (!block)
		return NULL;
	INIT_LIST_HEAD(&block->fwd_entry_ref_list);
	block->afa = mlxsw_afa;

	/* At least one action set is always present, so just create it here */
	block->first_set = mlxsw_afa_set_create(true);
	if (!block->first_set)
		goto err_first_set_create;
	block->cur_set = block->first_set;
	return block;

err_first_set_create:
	kfree(block);
	return NULL;
}
EXPORT_SYMBOL(mlxsw_afa_block_create);

static void mlxsw_afa_fwd_entry_refs_destroy(struct mlxsw_afa_block *block);

void mlxsw_afa_block_destroy(struct mlxsw_afa_block *block)
{
	struct mlxsw_afa_set *set = block->first_set;
	struct mlxsw_afa_set *next_set;

	do {
		next_set = set->next;
		mlxsw_afa_set_put(block->afa, set);
		set = next_set;
	} while (set);
	mlxsw_afa_fwd_entry_refs_destroy(block);
	kfree(block);
}
EXPORT_SYMBOL(mlxsw_afa_block_destroy);

int mlxsw_afa_block_commit(struct mlxsw_afa_block *block)
{
	struct mlxsw_afa_set *set = block->cur_set;
	struct mlxsw_afa_set *prev_set;

	block->cur_set = NULL;
	block->finished = true;

	/* Go over all linked sets starting from last
	 * and try to find existing set in the hash table.
	 * In case it is not there, assign a KVD linear index
	 * and insert it.
	 */
	do {
		prev_set = set->prev;
		set = mlxsw_afa_set_get(block->afa, set);
		if (IS_ERR(set))
			/* No rollback is needed since the chain is
			 * in consistent state and mlxsw_afa_block_destroy
			 * will take care of putting it away.
			 */
			return PTR_ERR(set);
		if (prev_set) {
			prev_set->next = set;
			mlxsw_afa_set_next_set(prev_set, set->kvdl_index);
			set = prev_set;
		}
	} while (prev_set);

	block->first_set = set;
	return 0;
}
EXPORT_SYMBOL(mlxsw_afa_block_commit);

char *mlxsw_afa_block_first_set(struct mlxsw_afa_block *block)
{
	return block->first_set->ht_key.enc_actions;
}
EXPORT_SYMBOL(mlxsw_afa_block_first_set);

u32 mlxsw_afa_block_first_set_kvdl_index(struct mlxsw_afa_block *block)
{
	return block->first_set->kvdl_index;
}
EXPORT_SYMBOL(mlxsw_afa_block_first_set_kvdl_index);

void mlxsw_afa_block_continue(struct mlxsw_afa_block *block)
{
	if (WARN_ON(block->finished))
		return;
	mlxsw_afa_set_goto_set(block->cur_set,
			       MLXSW_AFA_SET_GOTO_BINDING_CMD_NONE, 0);
	block->finished = true;
}
EXPORT_SYMBOL(mlxsw_afa_block_continue);

void mlxsw_afa_block_jump(struct mlxsw_afa_block *block, u16 group_id)
{
	if (WARN_ON(block->finished))
		return;
	mlxsw_afa_set_goto_set(block->cur_set,
			       MLXSW_AFA_SET_GOTO_BINDING_CMD_JUMP, group_id);
	block->finished = true;
}
EXPORT_SYMBOL(mlxsw_afa_block_jump);

static struct mlxsw_afa_fwd_entry *
mlxsw_afa_fwd_entry_create(struct mlxsw_afa *mlxsw_afa, u8 local_port)
{
	struct mlxsw_afa_fwd_entry *fwd_entry;
	int err;

	fwd_entry = kzalloc(sizeof(*fwd_entry), GFP_KERNEL);
	if (!fwd_entry)
		return ERR_PTR(-ENOMEM);
	fwd_entry->ht_key.local_port = local_port;
	fwd_entry->ref_count = 1;

	err = rhashtable_insert_fast(&mlxsw_afa->fwd_entry_ht,
				     &fwd_entry->ht_node,
				     mlxsw_afa_fwd_entry_ht_params);
	if (err)
		goto err_rhashtable_insert;

	err = mlxsw_afa->ops->kvdl_fwd_entry_add(mlxsw_afa->ops_priv,
						 &fwd_entry->kvdl_index,
						 local_port);
	if (err)
		goto err_kvdl_fwd_entry_add;
	return fwd_entry;

err_kvdl_fwd_entry_add:
	rhashtable_remove_fast(&mlxsw_afa->fwd_entry_ht, &fwd_entry->ht_node,
			       mlxsw_afa_fwd_entry_ht_params);
err_rhashtable_insert:
	kfree(fwd_entry);
	return ERR_PTR(err);
}

static void mlxsw_afa_fwd_entry_destroy(struct mlxsw_afa *mlxsw_afa,
					struct mlxsw_afa_fwd_entry *fwd_entry)
{
	mlxsw_afa->ops->kvdl_fwd_entry_del(mlxsw_afa->ops_priv,
					   fwd_entry->kvdl_index);
	rhashtable_remove_fast(&mlxsw_afa->fwd_entry_ht, &fwd_entry->ht_node,
			       mlxsw_afa_fwd_entry_ht_params);
	kfree(fwd_entry);
}

static struct mlxsw_afa_fwd_entry *
mlxsw_afa_fwd_entry_get(struct mlxsw_afa *mlxsw_afa, u8 local_port)
{
	struct mlxsw_afa_fwd_entry_ht_key ht_key = {0};
	struct mlxsw_afa_fwd_entry *fwd_entry;

	ht_key.local_port = local_port;
	fwd_entry = rhashtable_lookup_fast(&mlxsw_afa->fwd_entry_ht, &ht_key,
					   mlxsw_afa_fwd_entry_ht_params);
	if (fwd_entry) {
		fwd_entry->ref_count++;
		return fwd_entry;
	}
	return mlxsw_afa_fwd_entry_create(mlxsw_afa, local_port);
}

static void mlxsw_afa_fwd_entry_put(struct mlxsw_afa *mlxsw_afa,
				    struct mlxsw_afa_fwd_entry *fwd_entry)
{
	if (--fwd_entry->ref_count)
		return;
	mlxsw_afa_fwd_entry_destroy(mlxsw_afa, fwd_entry);
}

struct mlxsw_afa_fwd_entry_ref {
	struct list_head list;
	struct mlxsw_afa_fwd_entry *fwd_entry;
};

static struct mlxsw_afa_fwd_entry_ref *
mlxsw_afa_fwd_entry_ref_create(struct mlxsw_afa_block *block, u8 local_port)
{
	struct mlxsw_afa_fwd_entry_ref *fwd_entry_ref;
	struct mlxsw_afa_fwd_entry *fwd_entry;
	int err;

	fwd_entry_ref = kzalloc(sizeof(*fwd_entry_ref), GFP_KERNEL);
	if (!fwd_entry_ref)
		return ERR_PTR(-ENOMEM);
	fwd_entry = mlxsw_afa_fwd_entry_get(block->afa, local_port);
	if (IS_ERR(fwd_entry)) {
		err = PTR_ERR(fwd_entry);
		goto err_fwd_entry_get;
	}
	fwd_entry_ref->fwd_entry = fwd_entry;
	list_add(&fwd_entry_ref->list, &block->fwd_entry_ref_list);
	return fwd_entry_ref;

err_fwd_entry_get:
	kfree(fwd_entry_ref);
	return ERR_PTR(err);
}

static void
mlxsw_afa_fwd_entry_ref_destroy(struct mlxsw_afa_block *block,
				struct mlxsw_afa_fwd_entry_ref *fwd_entry_ref)
{
	list_del(&fwd_entry_ref->list);
	mlxsw_afa_fwd_entry_put(block->afa, fwd_entry_ref->fwd_entry);
	kfree(fwd_entry_ref);
}

static void mlxsw_afa_fwd_entry_refs_destroy(struct mlxsw_afa_block *block)
{
	struct mlxsw_afa_fwd_entry_ref *fwd_entry_ref;
	struct mlxsw_afa_fwd_entry_ref *tmp;

	list_for_each_entry_safe(fwd_entry_ref, tmp,
				 &block->fwd_entry_ref_list, list)
		mlxsw_afa_fwd_entry_ref_destroy(block, fwd_entry_ref);
}

#define MLXSW_AFA_ONE_ACTION_LEN 32
#define MLXSW_AFA_PAYLOAD_OFFSET 4

static char *mlxsw_afa_block_append_action(struct mlxsw_afa_block *block,
					   u8 action_code, u8 action_size)
{
	char *oneact;
	char *actions;

	if (WARN_ON(block->finished))
		return NULL;
	if (block->cur_act_index + action_size >
	    block->afa->max_acts_per_set) {
		struct mlxsw_afa_set *set;

		/* The appended action won't fit into the current action set,
		 * so create a new set.
		 */
		set = mlxsw_afa_set_create(false);
		if (!set)
			return NULL;
		set->prev = block->cur_set;
		block->cur_act_index = 0;
		block->cur_set->next = set;
		block->cur_set = set;
	}

	actions = block->cur_set->ht_key.enc_actions;
	oneact = actions + block->cur_act_index * MLXSW_AFA_ONE_ACTION_LEN;
	block->cur_act_index += action_size;
	mlxsw_afa_all_action_type_set(oneact, action_code);
	return oneact + MLXSW_AFA_PAYLOAD_OFFSET;
}

/* Trap / Discard Action
 * ---------------------
 * The Trap / Discard action enables trapping / mirroring packets to the CPU
 * as well as discarding packets.
 * The ACL Trap / Discard separates the forward/discard control from CPU
 * trap control. In addition, the Trap / Discard action enables activating
 * SPAN (port mirroring).
 */

#define MLXSW_AFA_TRAPDISC_CODE 0x03
#define MLXSW_AFA_TRAPDISC_SIZE 1

enum mlxsw_afa_trapdisc_forward_action {
	MLXSW_AFA_TRAPDISC_FORWARD_ACTION_DISCARD = 3,
};

/* afa_trapdisc_forward_action
 * Forward Action.
 */
MLXSW_ITEM32(afa, trapdisc, forward_action, 0x00, 0, 4);

static inline void
mlxsw_afa_trapdisc_pack(char *payload,
			enum mlxsw_afa_trapdisc_forward_action forward_action)
{
	mlxsw_afa_trapdisc_forward_action_set(payload, forward_action);
}

int mlxsw_afa_block_append_drop(struct mlxsw_afa_block *block)
{
	char *act = mlxsw_afa_block_append_action(block,
						  MLXSW_AFA_TRAPDISC_CODE,
						  MLXSW_AFA_TRAPDISC_SIZE);

	if (!act)
		return -ENOBUFS;
	mlxsw_afa_trapdisc_pack(act, MLXSW_AFA_TRAPDISC_FORWARD_ACTION_DISCARD);
	return 0;
}
EXPORT_SYMBOL(mlxsw_afa_block_append_drop);

/* Forwarding Action
 * -----------------
 * Forwarding Action can be used to implement Policy Based Switching (PBS)
 * as well as OpenFlow related "Output" action.
 */

#define MLXSW_AFA_FORWARD_CODE 0x07
#define MLXSW_AFA_FORWARD_SIZE 1

enum mlxsw_afa_forward_type {
	/* PBS, Policy Based Switching */
	MLXSW_AFA_FORWARD_TYPE_PBS,
	/* Output, OpenFlow output type */
	MLXSW_AFA_FORWARD_TYPE_OUTPUT,
};

/* afa_forward_type */
MLXSW_ITEM32(afa, forward, type, 0x00, 24, 2);

/* afa_forward_pbs_ptr
 * A pointer to the PBS entry configured by PPBS register.
 * Reserved when in_port is set.
 */
MLXSW_ITEM32(afa, forward, pbs_ptr, 0x08, 0, 24);

/* afa_forward_in_port
 * Packet is forwarded back to the ingress port.
 */
MLXSW_ITEM32(afa, forward, in_port, 0x0C, 0, 1);

static inline void
mlxsw_afa_forward_pack(char *payload, enum mlxsw_afa_forward_type type,
		       u32 pbs_ptr, bool in_port)
{
	mlxsw_afa_forward_type_set(payload, type);
	mlxsw_afa_forward_pbs_ptr_set(payload, pbs_ptr);
	mlxsw_afa_forward_in_port_set(payload, in_port);
}

int mlxsw_afa_block_append_fwd(struct mlxsw_afa_block *block,
			       u8 local_port, bool in_port)
{
	struct mlxsw_afa_fwd_entry_ref *fwd_entry_ref;
	u32 kvdl_index;
	char *act;
	int err;

	if (in_port)
		return -EOPNOTSUPP;
	fwd_entry_ref = mlxsw_afa_fwd_entry_ref_create(block, local_port);
	if (IS_ERR(fwd_entry_ref))
		return PTR_ERR(fwd_entry_ref);
	kvdl_index = fwd_entry_ref->fwd_entry->kvdl_index;

	act = mlxsw_afa_block_append_action(block, MLXSW_AFA_FORWARD_CODE,
					    MLXSW_AFA_FORWARD_SIZE);
	if (!act) {
		err = -ENOBUFS;
		goto err_append_action;
	}
	mlxsw_afa_forward_pack(act, MLXSW_AFA_FORWARD_TYPE_PBS,
			       kvdl_index, in_port);
	return 0;

err_append_action:
	mlxsw_afa_fwd_entry_ref_destroy(block, fwd_entry_ref);
	return err;
}
EXPORT_SYMBOL(mlxsw_afa_block_append_fwd);

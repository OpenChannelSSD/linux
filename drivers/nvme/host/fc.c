/*
 * Copyright (c) 2016 Avago Technologies.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful.
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES,
 * INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO
 * THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID.
 * See the GNU General Public License for more details, a copy of which
 * can be found in the file COPYING included with this package
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/parser.h>
#include <uapi/scsi/fc/fc_fs.h>
#include <uapi/scsi/fc/fc_els.h>

#include "nvme.h"
#include "fabrics.h"
#include <linux/nvme-fc-driver.h>
#include <linux/nvme-fc.h>


/* *************************** Data Structures/Defines ****************** */


/*
 * We handle AEN commands ourselves and don't even let the
 * block layer know about them.
 */
#define NVME_FC_NR_AEN_COMMANDS	1
#define NVME_FC_AQ_BLKMQ_DEPTH	\
	(NVMF_AQ_DEPTH - NVME_FC_NR_AEN_COMMANDS)
#define AEN_CMDID_BASE		(NVME_FC_AQ_BLKMQ_DEPTH + 1)

enum nvme_fc_queue_flags {
	NVME_FC_Q_CONNECTED = (1 << 0),
};

#define NVMEFC_QUEUE_DELAY	3		/* ms units */

struct nvme_fc_queue {
	struct nvme_fc_ctrl	*ctrl;
	struct device		*dev;
	struct blk_mq_hw_ctx	*hctx;
	void			*lldd_handle;
	int			queue_size;
	size_t			cmnd_capsule_len;
	u32			qnum;
	u32			rqcnt;
	u32			seqno;

	u64			connection_id;
	atomic_t		csn;

	unsigned long		flags;
} __aligned(sizeof(u64));	/* alignment for other things alloc'd with */

struct nvmefc_ls_req_op {
	struct nvmefc_ls_req	ls_req;

	struct nvme_fc_ctrl	*ctrl;
	struct nvme_fc_queue	*queue;
	struct request		*rq;

	int			ls_error;
	struct completion	ls_done;
	struct list_head	lsreq_list;	/* ctrl->ls_req_list */
	bool			req_queued;
};

enum nvme_fcpop_state {
	FCPOP_STATE_UNINIT	= 0,
	FCPOP_STATE_IDLE	= 1,
	FCPOP_STATE_ACTIVE	= 2,
	FCPOP_STATE_ABORTED	= 3,
};

struct nvme_fc_fcp_op {
	struct nvme_request	nreq;		/*
						 * nvme/host/core.c
						 * requires this to be
						 * the 1st element in the
						 * private structure
						 * associated with the
						 * request.
						 */
	struct nvmefc_fcp_req	fcp_req;

	struct nvme_fc_ctrl	*ctrl;
	struct nvme_fc_queue	*queue;
	struct request		*rq;

	atomic_t		state;
	u32			rqno;
	u32			nents;

	struct nvme_fc_cmd_iu	cmd_iu;
	struct nvme_fc_ersp_iu	rsp_iu;
};

struct nvme_fc_lport {
	struct nvme_fc_local_port	localport;

	struct ida			endp_cnt;
	struct list_head		port_list;	/* nvme_fc_port_list */
	struct list_head		endp_list;
	struct device			*dev;	/* physical device for dma */
	struct nvme_fc_port_template	*ops;
	struct kref			ref;
} __aligned(sizeof(u64));	/* alignment for other things alloc'd with */

struct nvme_fc_rport {
	struct nvme_fc_remote_port	remoteport;

	struct list_head		endp_list; /* for lport->endp_list */
	struct list_head		ctrl_list;
	spinlock_t			lock;
	struct kref			ref;
} __aligned(sizeof(u64));	/* alignment for other things alloc'd with */

enum nvme_fcctrl_state {
	FCCTRL_INIT		= 0,
	FCCTRL_ACTIVE		= 1,
};

struct nvme_fc_ctrl {
	spinlock_t		lock;
	struct nvme_fc_queue	*queues;
	u32			queue_count;

	struct device		*dev;
	struct nvme_fc_lport	*lport;
	struct nvme_fc_rport	*rport;
	u32			cnum;

	u64			association_id;

	u64			cap;

	struct list_head	ctrl_list;	/* rport->ctrl_list */
	struct list_head	ls_req_list;

	struct blk_mq_tag_set	admin_tag_set;
	struct blk_mq_tag_set	tag_set;

	struct work_struct	delete_work;
	struct kref		ref;
	int			state;

	struct nvme_fc_fcp_op	aen_ops[NVME_FC_NR_AEN_COMMANDS];

	struct nvme_ctrl	ctrl;
};

static inline struct nvme_fc_ctrl *
to_fc_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_fc_ctrl, ctrl);
}

static inline struct nvme_fc_lport *
localport_to_lport(struct nvme_fc_local_port *portptr)
{
	return container_of(portptr, struct nvme_fc_lport, localport);
}

static inline struct nvme_fc_rport *
remoteport_to_rport(struct nvme_fc_remote_port *portptr)
{
	return container_of(portptr, struct nvme_fc_rport, remoteport);
}

static inline struct nvmefc_ls_req_op *
ls_req_to_lsop(struct nvmefc_ls_req *lsreq)
{
	return container_of(lsreq, struct nvmefc_ls_req_op, ls_req);
}

static inline struct nvme_fc_fcp_op *
fcp_req_to_fcp_op(struct nvmefc_fcp_req *fcpreq)
{
	return container_of(fcpreq, struct nvme_fc_fcp_op, fcp_req);
}



/* *************************** Globals **************************** */


static DEFINE_SPINLOCK(nvme_fc_lock);

static LIST_HEAD(nvme_fc_lport_list);
static DEFINE_IDA(nvme_fc_local_port_cnt);
static DEFINE_IDA(nvme_fc_ctrl_cnt);

static struct workqueue_struct *nvme_fc_wq;



/* *********************** FC-NVME Port Management ************************ */

static int __nvme_fc_del_ctrl(struct nvme_fc_ctrl *);
static void __nvme_fc_delete_hw_queue(struct nvme_fc_ctrl *,
			struct nvme_fc_queue *, unsigned int);


/**
 * nvme_fc_register_localport - transport entry point called by an
 *                              LLDD to register the existence of a NVME
 *                              host FC port.
 * @pinfo:     pointer to information about the port to be registered
 * @template:  LLDD entrypoints and operational parameters for the port
 * @dev:       physical hardware device node port corresponds to. Will be
 *             used for DMA mappings
 * @lport_p:   pointer to a local port pointer. Upon success, the routine
 *             will allocate a nvme_fc_local_port structure and place its
 *             address in the local port pointer. Upon failure, local port
 *             pointer will be set to 0.
 *
 * Returns:
 * a completion status. Must be 0 upon success; a negative errno
 * (ex: -ENXIO) upon failure.
 */
int
nvme_fc_register_localport(struct nvme_fc_port_info *pinfo,
			struct nvme_fc_port_template *template,
			struct device *dev,
			struct nvme_fc_local_port **portptr)
{
	struct nvme_fc_lport *newrec;
	unsigned long flags;
	int ret, idx;

	if (!template->localport_delete || !template->remoteport_delete ||
	    !template->ls_req || !template->fcp_io ||
	    !template->ls_abort || !template->fcp_abort ||
	    !template->max_hw_queues || !template->max_sgl_segments ||
	    !template->max_dif_sgl_segments || !template->dma_boundary) {
		ret = -EINVAL;
		goto out_reghost_failed;
	}

	newrec = kmalloc((sizeof(*newrec) + template->local_priv_sz),
			 GFP_KERNEL);
	if (!newrec) {
		ret = -ENOMEM;
		goto out_reghost_failed;
	}

	idx = ida_simple_get(&nvme_fc_local_port_cnt, 0, 0, GFP_KERNEL);
	if (idx < 0) {
		ret = -ENOSPC;
		goto out_fail_kfree;
	}

	if (!get_device(dev) && dev) {
		ret = -ENODEV;
		goto out_ida_put;
	}

	INIT_LIST_HEAD(&newrec->port_list);
	INIT_LIST_HEAD(&newrec->endp_list);
	kref_init(&newrec->ref);
	newrec->ops = template;
	newrec->dev = dev;
	ida_init(&newrec->endp_cnt);
	newrec->localport.private = &newrec[1];
	newrec->localport.node_name = pinfo->node_name;
	newrec->localport.port_name = pinfo->port_name;
	newrec->localport.port_role = pinfo->port_role;
	newrec->localport.port_id = pinfo->port_id;
	newrec->localport.port_state = FC_OBJSTATE_ONLINE;
	newrec->localport.port_num = idx;

	spin_lock_irqsave(&nvme_fc_lock, flags);
	list_add_tail(&newrec->port_list, &nvme_fc_lport_list);
	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	if (dev)
		dma_set_seg_boundary(dev, template->dma_boundary);

	*portptr = &newrec->localport;
	return 0;

out_ida_put:
	ida_simple_remove(&nvme_fc_local_port_cnt, idx);
out_fail_kfree:
	kfree(newrec);
out_reghost_failed:
	*portptr = NULL;

	return ret;
}
EXPORT_SYMBOL_GPL(nvme_fc_register_localport);

static void
nvme_fc_free_lport(struct kref *ref)
{
	struct nvme_fc_lport *lport =
		container_of(ref, struct nvme_fc_lport, ref);
	unsigned long flags;

	WARN_ON(lport->localport.port_state != FC_OBJSTATE_DELETED);
	WARN_ON(!list_empty(&lport->endp_list));

	/* remove from transport list */
	spin_lock_irqsave(&nvme_fc_lock, flags);
	list_del(&lport->port_list);
	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	/* let the LLDD know we've finished tearing it down */
	lport->ops->localport_delete(&lport->localport);

	ida_simple_remove(&nvme_fc_local_port_cnt, lport->localport.port_num);
	ida_destroy(&lport->endp_cnt);

	put_device(lport->dev);

	kfree(lport);
}

static void
nvme_fc_lport_put(struct nvme_fc_lport *lport)
{
	kref_put(&lport->ref, nvme_fc_free_lport);
}

static int
nvme_fc_lport_get(struct nvme_fc_lport *lport)
{
	return kref_get_unless_zero(&lport->ref);
}

/**
 * nvme_fc_unregister_localport - transport entry point called by an
 *                              LLDD to deregister/remove a previously
 *                              registered a NVME host FC port.
 * @localport: pointer to the (registered) local port that is to be
 *             deregistered.
 *
 * Returns:
 * a completion status. Must be 0 upon success; a negative errno
 * (ex: -ENXIO) upon failure.
 */
int
nvme_fc_unregister_localport(struct nvme_fc_local_port *portptr)
{
	struct nvme_fc_lport *lport = localport_to_lport(portptr);
	unsigned long flags;

	if (!portptr)
		return -EINVAL;

	spin_lock_irqsave(&nvme_fc_lock, flags);

	if (portptr->port_state != FC_OBJSTATE_ONLINE) {
		spin_unlock_irqrestore(&nvme_fc_lock, flags);
		return -EINVAL;
	}
	portptr->port_state = FC_OBJSTATE_DELETED;

	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	nvme_fc_lport_put(lport);

	return 0;
}
EXPORT_SYMBOL_GPL(nvme_fc_unregister_localport);

/**
 * nvme_fc_register_remoteport - transport entry point called by an
 *                              LLDD to register the existence of a NVME
 *                              subsystem FC port on its fabric.
 * @localport: pointer to the (registered) local port that the remote
 *             subsystem port is connected to.
 * @pinfo:     pointer to information about the port to be registered
 * @rport_p:   pointer to a remote port pointer. Upon success, the routine
 *             will allocate a nvme_fc_remote_port structure and place its
 *             address in the remote port pointer. Upon failure, remote port
 *             pointer will be set to 0.
 *
 * Returns:
 * a completion status. Must be 0 upon success; a negative errno
 * (ex: -ENXIO) upon failure.
 */
int
nvme_fc_register_remoteport(struct nvme_fc_local_port *localport,
				struct nvme_fc_port_info *pinfo,
				struct nvme_fc_remote_port **portptr)
{
	struct nvme_fc_lport *lport = localport_to_lport(localport);
	struct nvme_fc_rport *newrec;
	unsigned long flags;
	int ret, idx;

	newrec = kmalloc((sizeof(*newrec) + lport->ops->remote_priv_sz),
			 GFP_KERNEL);
	if (!newrec) {
		ret = -ENOMEM;
		goto out_reghost_failed;
	}

	if (!nvme_fc_lport_get(lport)) {
		ret = -ESHUTDOWN;
		goto out_kfree_rport;
	}

	idx = ida_simple_get(&lport->endp_cnt, 0, 0, GFP_KERNEL);
	if (idx < 0) {
		ret = -ENOSPC;
		goto out_lport_put;
	}

	INIT_LIST_HEAD(&newrec->endp_list);
	INIT_LIST_HEAD(&newrec->ctrl_list);
	kref_init(&newrec->ref);
	spin_lock_init(&newrec->lock);
	newrec->remoteport.localport = &lport->localport;
	newrec->remoteport.private = &newrec[1];
	newrec->remoteport.port_role = pinfo->port_role;
	newrec->remoteport.node_name = pinfo->node_name;
	newrec->remoteport.port_name = pinfo->port_name;
	newrec->remoteport.port_id = pinfo->port_id;
	newrec->remoteport.port_state = FC_OBJSTATE_ONLINE;
	newrec->remoteport.port_num = idx;

	spin_lock_irqsave(&nvme_fc_lock, flags);
	list_add_tail(&newrec->endp_list, &lport->endp_list);
	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	*portptr = &newrec->remoteport;
	return 0;

out_lport_put:
	nvme_fc_lport_put(lport);
out_kfree_rport:
	kfree(newrec);
out_reghost_failed:
	*portptr = NULL;
	return ret;

}
EXPORT_SYMBOL_GPL(nvme_fc_register_remoteport);

static void
nvme_fc_free_rport(struct kref *ref)
{
	struct nvme_fc_rport *rport =
		container_of(ref, struct nvme_fc_rport, ref);
	struct nvme_fc_lport *lport =
			localport_to_lport(rport->remoteport.localport);
	unsigned long flags;

	WARN_ON(rport->remoteport.port_state != FC_OBJSTATE_DELETED);
	WARN_ON(!list_empty(&rport->ctrl_list));

	/* remove from lport list */
	spin_lock_irqsave(&nvme_fc_lock, flags);
	list_del(&rport->endp_list);
	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	/* let the LLDD know we've finished tearing it down */
	lport->ops->remoteport_delete(&rport->remoteport);

	ida_simple_remove(&lport->endp_cnt, rport->remoteport.port_num);

	kfree(rport);

	nvme_fc_lport_put(lport);
}

static void
nvme_fc_rport_put(struct nvme_fc_rport *rport)
{
	kref_put(&rport->ref, nvme_fc_free_rport);
}

static int
nvme_fc_rport_get(struct nvme_fc_rport *rport)
{
	return kref_get_unless_zero(&rport->ref);
}

/**
 * nvme_fc_unregister_remoteport - transport entry point called by an
 *                              LLDD to deregister/remove a previously
 *                              registered a NVME subsystem FC port.
 * @remoteport: pointer to the (registered) remote port that is to be
 *              deregistered.
 *
 * Returns:
 * a completion status. Must be 0 upon success; a negative errno
 * (ex: -ENXIO) upon failure.
 */
int
nvme_fc_unregister_remoteport(struct nvme_fc_remote_port *portptr)
{
	struct nvme_fc_rport *rport = remoteport_to_rport(portptr);
	struct nvme_fc_ctrl *ctrl;
	unsigned long flags;

	if (!portptr)
		return -EINVAL;

	spin_lock_irqsave(&rport->lock, flags);

	if (portptr->port_state != FC_OBJSTATE_ONLINE) {
		spin_unlock_irqrestore(&rport->lock, flags);
		return -EINVAL;
	}
	portptr->port_state = FC_OBJSTATE_DELETED;

	/* tear down all associations to the remote port */
	list_for_each_entry(ctrl, &rport->ctrl_list, ctrl_list)
		__nvme_fc_del_ctrl(ctrl);

	spin_unlock_irqrestore(&rport->lock, flags);

	nvme_fc_rport_put(rport);
	return 0;
}
EXPORT_SYMBOL_GPL(nvme_fc_unregister_remoteport);


/* *********************** FC-NVME DMA Handling **************************** */

/*
 * The fcloop device passes in a NULL device pointer. Real LLD's will
 * pass in a valid device pointer. If NULL is passed to the dma mapping
 * routines, depending on the platform, it may or may not succeed, and
 * may crash.
 *
 * As such:
 * Wrapper all the dma routines and check the dev pointer.
 *
 * If simple mappings (return just a dma address, we'll noop them,
 * returning a dma address of 0.
 *
 * On more complex mappings (dma_map_sg), a pseudo routine fills
 * in the scatter list, setting all dma addresses to 0.
 */

static inline dma_addr_t
fc_dma_map_single(struct device *dev, void *ptr, size_t size,
		enum dma_data_direction dir)
{
	return dev ? dma_map_single(dev, ptr, size, dir) : (dma_addr_t)0L;
}

static inline int
fc_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	return dev ? dma_mapping_error(dev, dma_addr) : 0;
}

static inline void
fc_dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size,
	enum dma_data_direction dir)
{
	if (dev)
		dma_unmap_single(dev, addr, size, dir);
}

static inline void
fc_dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr, size_t size,
		enum dma_data_direction dir)
{
	if (dev)
		dma_sync_single_for_cpu(dev, addr, size, dir);
}

static inline void
fc_dma_sync_single_for_device(struct device *dev, dma_addr_t addr, size_t size,
		enum dma_data_direction dir)
{
	if (dev)
		dma_sync_single_for_device(dev, addr, size, dir);
}

/* pseudo dma_map_sg call */
static int
fc_map_sg(struct scatterlist *sg, int nents)
{
	struct scatterlist *s;
	int i;

	WARN_ON(nents == 0 || sg[0].length == 0);

	for_each_sg(sg, s, nents, i) {
		s->dma_address = 0L;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
		s->dma_length = s->length;
#endif
	}
	return nents;
}

static inline int
fc_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir)
{
	return dev ? dma_map_sg(dev, sg, nents, dir) : fc_map_sg(sg, nents);
}

static inline void
fc_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir)
{
	if (dev)
		dma_unmap_sg(dev, sg, nents, dir);
}


/* *********************** FC-NVME LS Handling **************************** */

static void nvme_fc_ctrl_put(struct nvme_fc_ctrl *);
static int nvme_fc_ctrl_get(struct nvme_fc_ctrl *);


static void
__nvme_fc_finish_ls_req(struct nvme_fc_ctrl *ctrl,
		struct nvmefc_ls_req_op *lsop)
{
	struct nvmefc_ls_req *lsreq = &lsop->ls_req;
	unsigned long flags;

	spin_lock_irqsave(&ctrl->lock, flags);

	if (!lsop->req_queued) {
		spin_unlock_irqrestore(&ctrl->lock, flags);
		return;
	}

	list_del(&lsop->lsreq_list);

	lsop->req_queued = false;

	spin_unlock_irqrestore(&ctrl->lock, flags);

	fc_dma_unmap_single(ctrl->dev, lsreq->rqstdma,
				  (lsreq->rqstlen + lsreq->rsplen),
				  DMA_BIDIRECTIONAL);

	nvme_fc_ctrl_put(ctrl);
}

static int
__nvme_fc_send_ls_req(struct nvme_fc_ctrl *ctrl,
		struct nvmefc_ls_req_op *lsop,
		void (*done)(struct nvmefc_ls_req *req, int status))
{
	struct nvmefc_ls_req *lsreq = &lsop->ls_req;
	unsigned long flags;
	int ret;

	if (!nvme_fc_ctrl_get(ctrl))
		return -ESHUTDOWN;

	lsreq->done = done;
	lsop->ctrl = ctrl;
	lsop->req_queued = false;
	INIT_LIST_HEAD(&lsop->lsreq_list);
	init_completion(&lsop->ls_done);

	lsreq->rqstdma = fc_dma_map_single(ctrl->dev, lsreq->rqstaddr,
				  lsreq->rqstlen + lsreq->rsplen,
				  DMA_BIDIRECTIONAL);
	if (fc_dma_mapping_error(ctrl->dev, lsreq->rqstdma)) {
		nvme_fc_ctrl_put(ctrl);
		dev_err(ctrl->dev,
			"els request command failed EFAULT.\n");
		return -EFAULT;
	}
	lsreq->rspdma = lsreq->rqstdma + lsreq->rqstlen;

	spin_lock_irqsave(&ctrl->lock, flags);

	list_add_tail(&lsop->lsreq_list, &ctrl->ls_req_list);

	lsop->req_queued = true;

	spin_unlock_irqrestore(&ctrl->lock, flags);

	ret = ctrl->lport->ops->ls_req(&ctrl->lport->localport,
					&ctrl->rport->remoteport, lsreq);
	if (ret)
		lsop->ls_error = ret;

	return ret;
}

static void
nvme_fc_send_ls_req_done(struct nvmefc_ls_req *lsreq, int status)
{
	struct nvmefc_ls_req_op *lsop = ls_req_to_lsop(lsreq);

	lsop->ls_error = status;
	complete(&lsop->ls_done);
}

static int
nvme_fc_send_ls_req(struct nvme_fc_ctrl *ctrl, struct nvmefc_ls_req_op *lsop)
{
	struct nvmefc_ls_req *lsreq = &lsop->ls_req;
	struct fcnvme_ls_rjt *rjt = lsreq->rspaddr;
	int ret;

	ret = __nvme_fc_send_ls_req(ctrl, lsop, nvme_fc_send_ls_req_done);

	if (!ret)
		/*
		 * No timeout/not interruptible as we need the struct
		 * to exist until the lldd calls us back. Thus mandate
		 * wait until driver calls back. lldd responsible for
		 * the timeout action
		 */
		wait_for_completion(&lsop->ls_done);

	__nvme_fc_finish_ls_req(ctrl, lsop);

	if (ret) {
		dev_err(ctrl->dev,
			"ls request command failed (%d).\n", ret);
		return ret;
	}

	/* ACC or RJT payload ? */
	if (rjt->w0.ls_cmd == FCNVME_LS_RJT)
		return -ENXIO;

	return 0;
}

static void
nvme_fc_send_ls_req_async(struct nvme_fc_ctrl *ctrl,
		struct nvmefc_ls_req_op *lsop,
		void (*done)(struct nvmefc_ls_req *req, int status))
{
	int ret;

	ret = __nvme_fc_send_ls_req(ctrl, lsop, done);

	/* don't wait for completion */

	if (ret)
		done(&lsop->ls_req, ret);
}

/* Validation Error indexes into the string table below */
enum {
	VERR_NO_ERROR		= 0,
	VERR_LSACC		= 1,
	VERR_LSDESC_RQST	= 2,
	VERR_LSDESC_RQST_LEN	= 3,
	VERR_ASSOC_ID		= 4,
	VERR_ASSOC_ID_LEN	= 5,
	VERR_CONN_ID		= 6,
	VERR_CONN_ID_LEN	= 7,
	VERR_CR_ASSOC		= 8,
	VERR_CR_ASSOC_ACC_LEN	= 9,
	VERR_CR_CONN		= 10,
	VERR_CR_CONN_ACC_LEN	= 11,
	VERR_DISCONN		= 12,
	VERR_DISCONN_ACC_LEN	= 13,
};

static char *validation_errors[] = {
	"OK",
	"Not LS_ACC",
	"Not LSDESC_RQST",
	"Bad LSDESC_RQST Length",
	"Not Association ID",
	"Bad Association ID Length",
	"Not Connection ID",
	"Bad Connection ID Length",
	"Not CR_ASSOC Rqst",
	"Bad CR_ASSOC ACC Length",
	"Not CR_CONN Rqst",
	"Bad CR_CONN ACC Length",
	"Not Disconnect Rqst",
	"Bad Disconnect ACC Length",
};

static int
nvme_fc_connect_admin_queue(struct nvme_fc_ctrl *ctrl,
	struct nvme_fc_queue *queue, u16 qsize, u16 ersp_ratio)
{
	struct nvmefc_ls_req_op *lsop;
	struct nvmefc_ls_req *lsreq;
	struct fcnvme_ls_cr_assoc_rqst *assoc_rqst;
	struct fcnvme_ls_cr_assoc_acc *assoc_acc;
	int ret, fcret = 0;

	lsop = kzalloc((sizeof(*lsop) +
			 ctrl->lport->ops->lsrqst_priv_sz +
			 sizeof(*assoc_rqst) + sizeof(*assoc_acc)), GFP_KERNEL);
	if (!lsop) {
		ret = -ENOMEM;
		goto out_no_memory;
	}
	lsreq = &lsop->ls_req;

	lsreq->private = (void *)&lsop[1];
	assoc_rqst = (struct fcnvme_ls_cr_assoc_rqst *)
			(lsreq->private + ctrl->lport->ops->lsrqst_priv_sz);
	assoc_acc = (struct fcnvme_ls_cr_assoc_acc *)&assoc_rqst[1];

	assoc_rqst->w0.ls_cmd = FCNVME_LS_CREATE_ASSOCIATION;
	assoc_rqst->desc_list_len =
			cpu_to_be32(sizeof(struct fcnvme_lsdesc_cr_assoc_cmd));

	assoc_rqst->assoc_cmd.desc_tag =
			cpu_to_be32(FCNVME_LSDESC_CREATE_ASSOC_CMD);
	assoc_rqst->assoc_cmd.desc_len =
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_cr_assoc_cmd));

	assoc_rqst->assoc_cmd.ersp_ratio = cpu_to_be16(ersp_ratio);
	assoc_rqst->assoc_cmd.sqsize = cpu_to_be16(qsize);
	/* Linux supports only Dynamic controllers */
	assoc_rqst->assoc_cmd.cntlid = cpu_to_be16(0xffff);
	memcpy(&assoc_rqst->assoc_cmd.hostid, &ctrl->ctrl.opts->host->id,
		min_t(size_t, FCNVME_ASSOC_HOSTID_LEN, sizeof(uuid_be)));
	strncpy(assoc_rqst->assoc_cmd.hostnqn, ctrl->ctrl.opts->host->nqn,
		min(FCNVME_ASSOC_HOSTNQN_LEN, NVMF_NQN_SIZE));
	strncpy(assoc_rqst->assoc_cmd.subnqn, ctrl->ctrl.opts->subsysnqn,
		min(FCNVME_ASSOC_SUBNQN_LEN, NVMF_NQN_SIZE));

	lsop->queue = queue;
	lsreq->rqstaddr = assoc_rqst;
	lsreq->rqstlen = sizeof(*assoc_rqst);
	lsreq->rspaddr = assoc_acc;
	lsreq->rsplen = sizeof(*assoc_acc);
	lsreq->timeout = NVME_FC_CONNECT_TIMEOUT_SEC;

	ret = nvme_fc_send_ls_req(ctrl, lsop);
	if (ret)
		goto out_free_buffer;

	/* process connect LS completion */

	/* validate the ACC response */
	if (assoc_acc->hdr.w0.ls_cmd != FCNVME_LS_ACC)
		fcret = VERR_LSACC;
	else if (assoc_acc->hdr.desc_list_len !=
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_ls_cr_assoc_acc)))
		fcret = VERR_CR_ASSOC_ACC_LEN;
	else if (assoc_acc->hdr.rqst.desc_tag !=
			cpu_to_be32(FCNVME_LSDESC_RQST))
		fcret = VERR_LSDESC_RQST;
	else if (assoc_acc->hdr.rqst.desc_len !=
			fcnvme_lsdesc_len(sizeof(struct fcnvme_lsdesc_rqst)))
		fcret = VERR_LSDESC_RQST_LEN;
	else if (assoc_acc->hdr.rqst.w0.ls_cmd != FCNVME_LS_CREATE_ASSOCIATION)
		fcret = VERR_CR_ASSOC;
	else if (assoc_acc->associd.desc_tag !=
			cpu_to_be32(FCNVME_LSDESC_ASSOC_ID))
		fcret = VERR_ASSOC_ID;
	else if (assoc_acc->associd.desc_len !=
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_assoc_id)))
		fcret = VERR_ASSOC_ID_LEN;
	else if (assoc_acc->connectid.desc_tag !=
			cpu_to_be32(FCNVME_LSDESC_CONN_ID))
		fcret = VERR_CONN_ID;
	else if (assoc_acc->connectid.desc_len !=
			fcnvme_lsdesc_len(sizeof(struct fcnvme_lsdesc_conn_id)))
		fcret = VERR_CONN_ID_LEN;

	if (fcret) {
		ret = -EBADF;
		dev_err(ctrl->dev,
			"q %d connect failed: %s\n",
			queue->qnum, validation_errors[fcret]);
	} else {
		ctrl->association_id =
			be64_to_cpu(assoc_acc->associd.association_id);
		queue->connection_id =
			be64_to_cpu(assoc_acc->connectid.connection_id);
		set_bit(NVME_FC_Q_CONNECTED, &queue->flags);
	}

out_free_buffer:
	kfree(lsop);
out_no_memory:
	if (ret)
		dev_err(ctrl->dev,
			"queue %d connect admin queue failed (%d).\n",
			queue->qnum, ret);
	return ret;
}

static int
nvme_fc_connect_queue(struct nvme_fc_ctrl *ctrl, struct nvme_fc_queue *queue,
			u16 qsize, u16 ersp_ratio)
{
	struct nvmefc_ls_req_op *lsop;
	struct nvmefc_ls_req *lsreq;
	struct fcnvme_ls_cr_conn_rqst *conn_rqst;
	struct fcnvme_ls_cr_conn_acc *conn_acc;
	int ret, fcret = 0;

	lsop = kzalloc((sizeof(*lsop) +
			 ctrl->lport->ops->lsrqst_priv_sz +
			 sizeof(*conn_rqst) + sizeof(*conn_acc)), GFP_KERNEL);
	if (!lsop) {
		ret = -ENOMEM;
		goto out_no_memory;
	}
	lsreq = &lsop->ls_req;

	lsreq->private = (void *)&lsop[1];
	conn_rqst = (struct fcnvme_ls_cr_conn_rqst *)
			(lsreq->private + ctrl->lport->ops->lsrqst_priv_sz);
	conn_acc = (struct fcnvme_ls_cr_conn_acc *)&conn_rqst[1];

	conn_rqst->w0.ls_cmd = FCNVME_LS_CREATE_CONNECTION;
	conn_rqst->desc_list_len = cpu_to_be32(
				sizeof(struct fcnvme_lsdesc_assoc_id) +
				sizeof(struct fcnvme_lsdesc_cr_conn_cmd));

	conn_rqst->associd.desc_tag = cpu_to_be32(FCNVME_LSDESC_ASSOC_ID);
	conn_rqst->associd.desc_len =
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_assoc_id));
	conn_rqst->associd.association_id = cpu_to_be64(ctrl->association_id);
	conn_rqst->connect_cmd.desc_tag =
			cpu_to_be32(FCNVME_LSDESC_CREATE_CONN_CMD);
	conn_rqst->connect_cmd.desc_len =
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_cr_conn_cmd));
	conn_rqst->connect_cmd.ersp_ratio = cpu_to_be16(ersp_ratio);
	conn_rqst->connect_cmd.qid  = cpu_to_be16(queue->qnum);
	conn_rqst->connect_cmd.sqsize = cpu_to_be16(qsize);

	lsop->queue = queue;
	lsreq->rqstaddr = conn_rqst;
	lsreq->rqstlen = sizeof(*conn_rqst);
	lsreq->rspaddr = conn_acc;
	lsreq->rsplen = sizeof(*conn_acc);
	lsreq->timeout = NVME_FC_CONNECT_TIMEOUT_SEC;

	ret = nvme_fc_send_ls_req(ctrl, lsop);
	if (ret)
		goto out_free_buffer;

	/* process connect LS completion */

	/* validate the ACC response */
	if (conn_acc->hdr.w0.ls_cmd != FCNVME_LS_ACC)
		fcret = VERR_LSACC;
	else if (conn_acc->hdr.desc_list_len !=
			fcnvme_lsdesc_len(sizeof(struct fcnvme_ls_cr_conn_acc)))
		fcret = VERR_CR_CONN_ACC_LEN;
	else if (conn_acc->hdr.rqst.desc_tag != cpu_to_be32(FCNVME_LSDESC_RQST))
		fcret = VERR_LSDESC_RQST;
	else if (conn_acc->hdr.rqst.desc_len !=
			fcnvme_lsdesc_len(sizeof(struct fcnvme_lsdesc_rqst)))
		fcret = VERR_LSDESC_RQST_LEN;
	else if (conn_acc->hdr.rqst.w0.ls_cmd != FCNVME_LS_CREATE_CONNECTION)
		fcret = VERR_CR_CONN;
	else if (conn_acc->connectid.desc_tag !=
			cpu_to_be32(FCNVME_LSDESC_CONN_ID))
		fcret = VERR_CONN_ID;
	else if (conn_acc->connectid.desc_len !=
			fcnvme_lsdesc_len(sizeof(struct fcnvme_lsdesc_conn_id)))
		fcret = VERR_CONN_ID_LEN;

	if (fcret) {
		ret = -EBADF;
		dev_err(ctrl->dev,
			"q %d connect failed: %s\n",
			queue->qnum, validation_errors[fcret]);
	} else {
		queue->connection_id =
			be64_to_cpu(conn_acc->connectid.connection_id);
		set_bit(NVME_FC_Q_CONNECTED, &queue->flags);
	}

out_free_buffer:
	kfree(lsop);
out_no_memory:
	if (ret)
		dev_err(ctrl->dev,
			"queue %d connect command failed (%d).\n",
			queue->qnum, ret);
	return ret;
}

static void
nvme_fc_disconnect_assoc_done(struct nvmefc_ls_req *lsreq, int status)
{
	struct nvmefc_ls_req_op *lsop = ls_req_to_lsop(lsreq);
	struct nvme_fc_ctrl *ctrl = lsop->ctrl;

	__nvme_fc_finish_ls_req(ctrl, lsop);

	if (status)
		dev_err(ctrl->dev,
			"disconnect assoc ls request command failed (%d).\n",
			status);

	/* fc-nvme iniator doesn't care about success or failure of cmd */

	kfree(lsop);
}

/*
 * This routine sends a FC-NVME LS to disconnect (aka terminate)
 * the FC-NVME Association.  Terminating the association also
 * terminates the FC-NVME connections (per queue, both admin and io
 * queues) that are part of the association. E.g. things are torn
 * down, and the related FC-NVME Association ID and Connection IDs
 * become invalid.
 *
 * The behavior of the fc-nvme initiator is such that it's
 * understanding of the association and connections will implicitly
 * be torn down. The action is implicit as it may be due to a loss of
 * connectivity with the fc-nvme target, so you may never get a
 * response even if you tried.  As such, the action of this routine
 * is to asynchronously send the LS, ignore any results of the LS, and
 * continue on with terminating the association. If the fc-nvme target
 * is present and receives the LS, it too can tear down.
 */
static void
nvme_fc_xmt_disconnect_assoc(struct nvme_fc_ctrl *ctrl)
{
	struct fcnvme_ls_disconnect_rqst *discon_rqst;
	struct fcnvme_ls_disconnect_acc *discon_acc;
	struct nvmefc_ls_req_op *lsop;
	struct nvmefc_ls_req *lsreq;

	lsop = kzalloc((sizeof(*lsop) +
			 ctrl->lport->ops->lsrqst_priv_sz +
			 sizeof(*discon_rqst) + sizeof(*discon_acc)),
			GFP_KERNEL);
	if (!lsop)
		/* couldn't sent it... too bad */
		return;

	lsreq = &lsop->ls_req;

	lsreq->private = (void *)&lsop[1];
	discon_rqst = (struct fcnvme_ls_disconnect_rqst *)
			(lsreq->private + ctrl->lport->ops->lsrqst_priv_sz);
	discon_acc = (struct fcnvme_ls_disconnect_acc *)&discon_rqst[1];

	discon_rqst->w0.ls_cmd = FCNVME_LS_DISCONNECT;
	discon_rqst->desc_list_len = cpu_to_be32(
				sizeof(struct fcnvme_lsdesc_assoc_id) +
				sizeof(struct fcnvme_lsdesc_disconn_cmd));

	discon_rqst->associd.desc_tag = cpu_to_be32(FCNVME_LSDESC_ASSOC_ID);
	discon_rqst->associd.desc_len =
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_assoc_id));

	discon_rqst->associd.association_id = cpu_to_be64(ctrl->association_id);

	discon_rqst->discon_cmd.desc_tag = cpu_to_be32(
						FCNVME_LSDESC_DISCONN_CMD);
	discon_rqst->discon_cmd.desc_len =
			fcnvme_lsdesc_len(
				sizeof(struct fcnvme_lsdesc_disconn_cmd));
	discon_rqst->discon_cmd.scope = FCNVME_DISCONN_ASSOCIATION;
	discon_rqst->discon_cmd.id = cpu_to_be64(ctrl->association_id);

	lsreq->rqstaddr = discon_rqst;
	lsreq->rqstlen = sizeof(*discon_rqst);
	lsreq->rspaddr = discon_acc;
	lsreq->rsplen = sizeof(*discon_acc);
	lsreq->timeout = NVME_FC_CONNECT_TIMEOUT_SEC;

	nvme_fc_send_ls_req_async(ctrl, lsop, nvme_fc_disconnect_assoc_done);

	/* only meaningful part to terminating the association */
	ctrl->association_id = 0;
}


/* *********************** NVME Ctrl Routines **************************** */


static int
nvme_fc_reinit_request(void *data, struct request *rq)
{
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_cmd_iu *cmdiu = &op->cmd_iu;

	memset(cmdiu, 0, sizeof(*cmdiu));
	cmdiu->scsi_id = NVME_CMD_SCSI_ID;
	cmdiu->fc_id = NVME_CMD_FC_ID;
	cmdiu->iu_len = cpu_to_be16(sizeof(*cmdiu) / sizeof(u32));
	memset(&op->rsp_iu, 0, sizeof(op->rsp_iu));

	return 0;
}

static void
__nvme_fc_exit_request(struct nvme_fc_ctrl *ctrl,
		struct nvme_fc_fcp_op *op)
{
	fc_dma_unmap_single(ctrl->lport->dev, op->fcp_req.rspdma,
				sizeof(op->rsp_iu), DMA_FROM_DEVICE);
	fc_dma_unmap_single(ctrl->lport->dev, op->fcp_req.cmddma,
				sizeof(op->cmd_iu), DMA_TO_DEVICE);

	atomic_set(&op->state, FCPOP_STATE_UNINIT);
}

static void
nvme_fc_exit_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx)
{
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);

	return __nvme_fc_exit_request(data, op);
}

static void
nvme_fc_exit_aen_ops(struct nvme_fc_ctrl *ctrl)
{
	struct nvme_fc_fcp_op *aen_op = ctrl->aen_ops;
	int i;

	for (i = 0; i < NVME_FC_NR_AEN_COMMANDS; i++, aen_op++) {
		if (atomic_read(&aen_op->state) == FCPOP_STATE_UNINIT)
			continue;
		__nvme_fc_exit_request(ctrl, aen_op);
		nvme_fc_ctrl_put(ctrl);
	}
}

void
nvme_fc_fcpio_done(struct nvmefc_fcp_req *req)
{
	struct nvme_fc_fcp_op *op = fcp_req_to_fcp_op(req);
	struct request *rq = op->rq;
	struct nvmefc_fcp_req *freq = &op->fcp_req;
	struct nvme_fc_ctrl *ctrl = op->ctrl;
	struct nvme_fc_queue *queue = op->queue;
	struct nvme_completion *cqe = &op->rsp_iu.cqe;
	u16 status = NVME_SC_SUCCESS;

	/*
	 * WARNING:
	 * The current linux implementation of a nvme controller
	 * allocates a single tag set for all io queues and sizes
	 * the io queues to fully hold all possible tags. Thus, the
	 * implementation does not reference or care about the sqhd
	 * value as it never needs to use the sqhd/sqtail pointers
	 * for submission pacing.
	 *
	 * This affects the FC-NVME implementation in two ways:
	 * 1) As the value doesn't matter, we don't need to waste
	 *    cycles extracting it from ERSPs and stamping it in the
	 *    cases where the transport fabricates CQEs on successful
	 *    completions.
	 * 2) The FC-NVME implementation requires that delivery of
	 *    ERSP completions are to go back to the nvme layer in order
	 *    relative to the rsn, such that the sqhd value will always
	 *    be "in order" for the nvme layer. As the nvme layer in
	 *    linux doesn't care about sqhd, there's no need to return
	 *    them in order.
	 *
	 * Additionally:
	 * As the core nvme layer in linux currently does not look at
	 * every field in the cqe - in cases where the FC transport must
	 * fabricate a CQE, the following fields will not be set as they
	 * are not referenced:
	 *      cqe.sqid,  cqe.sqhd,  cqe.command_id
	 */

	fc_dma_sync_single_for_cpu(ctrl->lport->dev, op->fcp_req.rspdma,
				sizeof(op->rsp_iu), DMA_FROM_DEVICE);

	if (atomic_read(&op->state) == FCPOP_STATE_ABORTED)
		status = NVME_SC_ABORT_REQ | NVME_SC_DNR;
	else if (freq->status)
		status = NVME_SC_FC_TRANSPORT_ERROR;

	/*
	 * For the linux implementation, if we have an unsuccesful
	 * status, they blk-mq layer can typically be called with the
	 * non-zero status and the content of the cqe isn't important.
	 */
	if (status)
		goto done;

	/*
	 * command completed successfully relative to the wire
	 * protocol. However, validate anything received and
	 * extract the status and result from the cqe (create it
	 * where necessary).
	 */

	switch (freq->rcv_rsplen) {

	case 0:
	case NVME_FC_SIZEOF_ZEROS_RSP:
		/*
		 * No response payload or 12 bytes of payload (which
		 * should all be zeros) are considered successful and
		 * no payload in the CQE by the transport.
		 */
		if (freq->transferred_length !=
			be32_to_cpu(op->cmd_iu.data_len)) {
			status = NVME_SC_FC_TRANSPORT_ERROR;
			goto done;
		}
		op->nreq.result.u64 = 0;
		break;

	case sizeof(struct nvme_fc_ersp_iu):
		/*
		 * The ERSP IU contains a full completion with CQE.
		 * Validate ERSP IU and look at cqe.
		 */
		if (unlikely(be16_to_cpu(op->rsp_iu.iu_len) !=
					(freq->rcv_rsplen / 4) ||
			     be32_to_cpu(op->rsp_iu.xfrd_len) !=
					freq->transferred_length ||
			     op->rsp_iu.status_code ||
			     op->rqno != le16_to_cpu(cqe->command_id))) {
			status = NVME_SC_FC_TRANSPORT_ERROR;
			goto done;
		}
		op->nreq.result = cqe->result;
		status = le16_to_cpu(cqe->status) >> 1;
		break;

	default:
		status = NVME_SC_FC_TRANSPORT_ERROR;
		goto done;
	}

done:
	if (!queue->qnum && op->rqno >= AEN_CMDID_BASE) {
		nvme_complete_async_event(&queue->ctrl->ctrl, status,
					&op->nreq.result);
		nvme_fc_ctrl_put(ctrl);
		return;
	}

	blk_mq_complete_request(rq, status);
}

static int
__nvme_fc_init_request(struct nvme_fc_ctrl *ctrl,
		struct nvme_fc_queue *queue, struct nvme_fc_fcp_op *op,
		struct request *rq, u32 rqno)
{
	struct nvme_fc_cmd_iu *cmdiu = &op->cmd_iu;
	int ret = 0;

	memset(op, 0, sizeof(*op));
	op->fcp_req.cmdaddr = &op->cmd_iu;
	op->fcp_req.cmdlen = sizeof(op->cmd_iu);
	op->fcp_req.rspaddr = &op->rsp_iu;
	op->fcp_req.rsplen = sizeof(op->rsp_iu);
	op->fcp_req.done = nvme_fc_fcpio_done;
	op->fcp_req.first_sgl = (struct scatterlist *)&op[1];
	op->fcp_req.private = &op->fcp_req.first_sgl[SG_CHUNK_SIZE];
	op->ctrl = ctrl;
	op->queue = queue;
	op->rq = rq;
	op->rqno = rqno;

	cmdiu->scsi_id = NVME_CMD_SCSI_ID;
	cmdiu->fc_id = NVME_CMD_FC_ID;
	cmdiu->iu_len = cpu_to_be16(sizeof(*cmdiu) / sizeof(u32));

	op->fcp_req.cmddma = fc_dma_map_single(ctrl->lport->dev,
				&op->cmd_iu, sizeof(op->cmd_iu), DMA_TO_DEVICE);
	if (fc_dma_mapping_error(ctrl->lport->dev, op->fcp_req.cmddma)) {
		dev_err(ctrl->dev,
			"FCP Op failed - cmdiu dma mapping failed.\n");
		ret = EFAULT;
		goto out_on_error;
	}

	op->fcp_req.rspdma = fc_dma_map_single(ctrl->lport->dev,
				&op->rsp_iu, sizeof(op->rsp_iu),
				DMA_FROM_DEVICE);
	if (fc_dma_mapping_error(ctrl->lport->dev, op->fcp_req.rspdma)) {
		dev_err(ctrl->dev,
			"FCP Op failed - rspiu dma mapping failed.\n");
		ret = EFAULT;
	}

	atomic_set(&op->state, FCPOP_STATE_IDLE);
out_on_error:
	return ret;
}

static int
nvme_fc_init_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	struct nvme_fc_ctrl *ctrl = data;
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_queue *queue = &ctrl->queues[hctx_idx+1];

	return __nvme_fc_init_request(ctrl, queue, op, rq, queue->rqcnt++);
}

static int
nvme_fc_init_admin_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	struct nvme_fc_ctrl *ctrl = data;
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_queue *queue = &ctrl->queues[0];

	return __nvme_fc_init_request(ctrl, queue, op, rq, queue->rqcnt++);
}

static int
nvme_fc_init_aen_ops(struct nvme_fc_ctrl *ctrl)
{
	struct nvme_fc_fcp_op *aen_op;
	struct nvme_fc_cmd_iu *cmdiu;
	struct nvme_command *sqe;
	int i, ret;

	aen_op = ctrl->aen_ops;
	for (i = 0; i < NVME_FC_NR_AEN_COMMANDS; i++, aen_op++) {
		cmdiu = &aen_op->cmd_iu;
		sqe = &cmdiu->sqe;
		ret = __nvme_fc_init_request(ctrl, &ctrl->queues[0],
				aen_op, (struct request *)NULL,
				(AEN_CMDID_BASE + i));
		if (ret)
			return ret;

		memset(sqe, 0, sizeof(*sqe));
		sqe->common.opcode = nvme_admin_async_event;
		sqe->common.command_id = AEN_CMDID_BASE + i;
	}
	return 0;
}


static inline void
__nvme_fc_init_hctx(struct blk_mq_hw_ctx *hctx, struct nvme_fc_ctrl *ctrl,
		unsigned int qidx)
{
	struct nvme_fc_queue *queue = &ctrl->queues[qidx];

	hctx->driver_data = queue;
	queue->hctx = hctx;
}

static int
nvme_fc_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_fc_ctrl *ctrl = data;

	__nvme_fc_init_hctx(hctx, ctrl, hctx_idx + 1);

	return 0;
}

static int
nvme_fc_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_fc_ctrl *ctrl = data;

	__nvme_fc_init_hctx(hctx, ctrl, hctx_idx);

	return 0;
}

static void
nvme_fc_init_queue(struct nvme_fc_ctrl *ctrl, int idx, size_t queue_size)
{
	struct nvme_fc_queue *queue;

	queue = &ctrl->queues[idx];
	memset(queue, 0, sizeof(*queue));
	queue->ctrl = ctrl;
	queue->qnum = idx;
	atomic_set(&queue->csn, 1);
	queue->dev = ctrl->dev;

	if (idx > 0)
		queue->cmnd_capsule_len = ctrl->ctrl.ioccsz * 16;
	else
		queue->cmnd_capsule_len = sizeof(struct nvme_command);

	queue->queue_size = queue_size;

	/*
	 * Considered whether we should allocate buffers for all SQEs
	 * and CQEs and dma map them - mapping their respective entries
	 * into the request structures (kernel vm addr and dma address)
	 * thus the driver could use the buffers/mappings directly.
	 * It only makes sense if the LLDD would use them for its
	 * messaging api. It's very unlikely most adapter api's would use
	 * a native NVME sqe/cqe. More reasonable if FC-NVME IU payload
	 * structures were used instead.
	 */
}

/*
 * This routine terminates a queue at the transport level.
 * The transport has already ensured that all outstanding ios on
 * the queue have been terminated.
 * The transport will send a Disconnect LS request to terminate
 * the queue's connection. Termination of the admin queue will also
 * terminate the association at the target.
 */
static void
nvme_fc_free_queue(struct nvme_fc_queue *queue)
{
	if (!test_and_clear_bit(NVME_FC_Q_CONNECTED, &queue->flags))
		return;

	/*
	 * Current implementation never disconnects a single queue.
	 * It always terminates a whole association. So there is never
	 * a disconnect(queue) LS sent to the target.
	 */

	queue->connection_id = 0;
	clear_bit(NVME_FC_Q_CONNECTED, &queue->flags);
}

static void
__nvme_fc_delete_hw_queue(struct nvme_fc_ctrl *ctrl,
	struct nvme_fc_queue *queue, unsigned int qidx)
{
	if (ctrl->lport->ops->delete_queue)
		ctrl->lport->ops->delete_queue(&ctrl->lport->localport, qidx,
				queue->lldd_handle);
	queue->lldd_handle = NULL;
}

static void
nvme_fc_destroy_admin_queue(struct nvme_fc_ctrl *ctrl)
{
	__nvme_fc_delete_hw_queue(ctrl, &ctrl->queues[0], 0);
	blk_cleanup_queue(ctrl->ctrl.admin_q);
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
	nvme_fc_free_queue(&ctrl->queues[0]);
}

static void
nvme_fc_free_io_queues(struct nvme_fc_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_fc_free_queue(&ctrl->queues[i]);
}

static int
__nvme_fc_create_hw_queue(struct nvme_fc_ctrl *ctrl,
	struct nvme_fc_queue *queue, unsigned int qidx, u16 qsize)
{
	int ret = 0;

	queue->lldd_handle = NULL;
	if (ctrl->lport->ops->create_queue)
		ret = ctrl->lport->ops->create_queue(&ctrl->lport->localport,
				qidx, qsize, &queue->lldd_handle);

	return ret;
}

static void
nvme_fc_delete_hw_io_queues(struct nvme_fc_ctrl *ctrl)
{
	struct nvme_fc_queue *queue = &ctrl->queues[ctrl->queue_count - 1];
	int i;

	for (i = ctrl->queue_count - 1; i >= 1; i--, queue--)
		__nvme_fc_delete_hw_queue(ctrl, queue, i);
}

static int
nvme_fc_create_hw_io_queues(struct nvme_fc_ctrl *ctrl, u16 qsize)
{
	struct nvme_fc_queue *queue = &ctrl->queues[1];
	int i, ret;

	for (i = 1; i < ctrl->queue_count; i++, queue++) {
		ret = __nvme_fc_create_hw_queue(ctrl, queue, i, qsize);
		if (ret)
			goto delete_queues;
	}

	return 0;

delete_queues:
	for (; i >= 0; i--)
		__nvme_fc_delete_hw_queue(ctrl, &ctrl->queues[i], i);
	return ret;
}

static int
nvme_fc_connect_io_queues(struct nvme_fc_ctrl *ctrl, u16 qsize)
{
	int i, ret = 0;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_fc_connect_queue(ctrl, &ctrl->queues[i], qsize,
					(qsize / 5));
		if (ret)
			break;
		ret = nvmf_connect_io_queue(&ctrl->ctrl, i);
		if (ret)
			break;
	}

	return ret;
}

static void
nvme_fc_init_io_queues(struct nvme_fc_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_fc_init_queue(ctrl, i, ctrl->ctrl.sqsize);
}

static void
nvme_fc_ctrl_free(struct kref *ref)
{
	struct nvme_fc_ctrl *ctrl =
		container_of(ref, struct nvme_fc_ctrl, ref);
	unsigned long flags;

	if (ctrl->state != FCCTRL_INIT) {
		/* remove from rport list */
		spin_lock_irqsave(&ctrl->rport->lock, flags);
		list_del(&ctrl->ctrl_list);
		spin_unlock_irqrestore(&ctrl->rport->lock, flags);
	}

	put_device(ctrl->dev);
	nvme_fc_rport_put(ctrl->rport);

	kfree(ctrl->queues);
	ida_simple_remove(&nvme_fc_ctrl_cnt, ctrl->cnum);
	nvmf_free_options(ctrl->ctrl.opts);
	kfree(ctrl);
}

static void
nvme_fc_ctrl_put(struct nvme_fc_ctrl *ctrl)
{
	kref_put(&ctrl->ref, nvme_fc_ctrl_free);
}

static int
nvme_fc_ctrl_get(struct nvme_fc_ctrl *ctrl)
{
	return kref_get_unless_zero(&ctrl->ref);
}

/*
 * All accesses from nvme core layer done - can now free the
 * controller. Called after last nvme_put_ctrl() call
 */
static void
nvme_fc_free_nvme_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_fc_ctrl *ctrl = to_fc_ctrl(nctrl);

	WARN_ON(nctrl != &ctrl->ctrl);

	/*
	 * Tear down the association, which will generate link
	 * traffic to terminate connections
	 */

	if (ctrl->state != FCCTRL_INIT) {
		/* send a Disconnect(association) LS to fc-nvme target */
		nvme_fc_xmt_disconnect_assoc(ctrl);

		if (ctrl->ctrl.tagset) {
			blk_cleanup_queue(ctrl->ctrl.connect_q);
			blk_mq_free_tag_set(&ctrl->tag_set);
			nvme_fc_delete_hw_io_queues(ctrl);
			nvme_fc_free_io_queues(ctrl);
		}

		nvme_fc_exit_aen_ops(ctrl);

		nvme_fc_destroy_admin_queue(ctrl);
	}

	nvme_fc_ctrl_put(ctrl);
}


static int
__nvme_fc_abort_op(struct nvme_fc_ctrl *ctrl, struct nvme_fc_fcp_op *op)
{
	int state;

	state = atomic_xchg(&op->state, FCPOP_STATE_ABORTED);
	if (state != FCPOP_STATE_ACTIVE) {
		atomic_set(&op->state, state);
		return -ECANCELED; /* fail */
	}

	ctrl->lport->ops->fcp_abort(&ctrl->lport->localport,
					&ctrl->rport->remoteport,
					op->queue->lldd_handle,
					&op->fcp_req);

	return 0;
}

enum blk_eh_timer_return
nvme_fc_timeout(struct request *rq, bool reserved)
{
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_ctrl *ctrl = op->ctrl;
	int ret;

	if (reserved)
		return BLK_EH_RESET_TIMER;

	ret = __nvme_fc_abort_op(ctrl, op);
	if (ret)
		/* io wasn't active to abort consider it done */
		return BLK_EH_HANDLED;

	/*
	 * TODO: force a controller reset
	 *   when that happens, queues will be torn down and outstanding
	 *   ios will be terminated, and the above abort, on a single io
	 *   will no longer be needed.
	 */

	return BLK_EH_HANDLED;
}

static int
nvme_fc_map_data(struct nvme_fc_ctrl *ctrl, struct request *rq,
		struct nvme_fc_fcp_op *op)
{
	struct nvmefc_fcp_req *freq = &op->fcp_req;
	enum dma_data_direction dir;
	int ret;

	freq->sg_cnt = 0;

	if (!blk_rq_payload_bytes(rq))
		return 0;

	freq->sg_table.sgl = freq->first_sgl;
	ret = sg_alloc_table_chained(&freq->sg_table,
			blk_rq_nr_phys_segments(rq), freq->sg_table.sgl);
	if (ret)
		return -ENOMEM;

	op->nents = blk_rq_map_sg(rq->q, rq, freq->sg_table.sgl);
	WARN_ON(op->nents > blk_rq_nr_phys_segments(rq));
	dir = (rq_data_dir(rq) == WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	freq->sg_cnt = fc_dma_map_sg(ctrl->lport->dev, freq->sg_table.sgl,
				op->nents, dir);
	if (unlikely(freq->sg_cnt <= 0)) {
		sg_free_table_chained(&freq->sg_table, true);
		freq->sg_cnt = 0;
		return -EFAULT;
	}

	/*
	 * TODO: blk_integrity_rq(rq)  for DIF
	 */
	return 0;
}

static void
nvme_fc_unmap_data(struct nvme_fc_ctrl *ctrl, struct request *rq,
		struct nvme_fc_fcp_op *op)
{
	struct nvmefc_fcp_req *freq = &op->fcp_req;

	if (!freq->sg_cnt)
		return;

	fc_dma_unmap_sg(ctrl->lport->dev, freq->sg_table.sgl, op->nents,
				((rq_data_dir(rq) == WRITE) ?
					DMA_TO_DEVICE : DMA_FROM_DEVICE));

	nvme_cleanup_cmd(rq);

	sg_free_table_chained(&freq->sg_table, true);

	freq->sg_cnt = 0;
}

/*
 * In FC, the queue is a logical thing. At transport connect, the target
 * creates its "queue" and returns a handle that is to be given to the
 * target whenever it posts something to the corresponding SQ.  When an
 * SQE is sent on a SQ, FC effectively considers the SQE, or rather the
 * command contained within the SQE, an io, and assigns a FC exchange
 * to it. The SQE and the associated SQ handle are sent in the initial
 * CMD IU sents on the exchange. All transfers relative to the io occur
 * as part of the exchange.  The CQE is the last thing for the io,
 * which is transferred (explicitly or implicitly) with the RSP IU
 * sent on the exchange. After the CQE is received, the FC exchange is
 * terminaed and the Exchange may be used on a different io.
 *
 * The transport to LLDD api has the transport making a request for a
 * new fcp io request to the LLDD. The LLDD then allocates a FC exchange
 * resource and transfers the command. The LLDD will then process all
 * steps to complete the io. Upon completion, the transport done routine
 * is called.
 *
 * So - while the operation is outstanding to the LLDD, there is a link
 * level FC exchange resource that is also outstanding. This must be
 * considered in all cleanup operations.
 */
static int
nvme_fc_start_fcp_op(struct nvme_fc_ctrl *ctrl, struct nvme_fc_queue *queue,
	struct nvme_fc_fcp_op *op, u32 data_len,
	enum nvmefc_fcp_datadir	io_dir)
{
	struct nvme_fc_cmd_iu *cmdiu = &op->cmd_iu;
	struct nvme_command *sqe = &cmdiu->sqe;
	u32 csn;
	int ret;

	if (!nvme_fc_ctrl_get(ctrl))
		return BLK_MQ_RQ_QUEUE_ERROR;

	/* format the FC-NVME CMD IU and fcp_req */
	cmdiu->connection_id = cpu_to_be64(queue->connection_id);
	csn = atomic_inc_return(&queue->csn);
	cmdiu->csn = cpu_to_be32(csn);
	cmdiu->data_len = cpu_to_be32(data_len);
	switch (io_dir) {
	case NVMEFC_FCP_WRITE:
		cmdiu->flags = FCNVME_CMD_FLAGS_WRITE;
		break;
	case NVMEFC_FCP_READ:
		cmdiu->flags = FCNVME_CMD_FLAGS_READ;
		break;
	case NVMEFC_FCP_NODATA:
		cmdiu->flags = 0;
		break;
	}
	op->fcp_req.payload_length = data_len;
	op->fcp_req.io_dir = io_dir;
	op->fcp_req.transferred_length = 0;
	op->fcp_req.rcv_rsplen = 0;
	op->fcp_req.status = NVME_SC_SUCCESS;
	op->fcp_req.sqid = cpu_to_le16(queue->qnum);

	/*
	 * validate per fabric rules, set fields mandated by fabric spec
	 * as well as those by FC-NVME spec.
	 */
	WARN_ON_ONCE(sqe->common.metadata);
	WARN_ON_ONCE(sqe->common.dptr.prp1);
	WARN_ON_ONCE(sqe->common.dptr.prp2);
	sqe->common.flags |= NVME_CMD_SGL_METABUF;

	/*
	 * format SQE DPTR field per FC-NVME rules
	 *    type=data block descr; subtype=offset;
	 *    offset is currently 0.
	 */
	sqe->rw.dptr.sgl.type = NVME_SGL_FMT_OFFSET;
	sqe->rw.dptr.sgl.length = cpu_to_le32(data_len);
	sqe->rw.dptr.sgl.addr = 0;

	/* odd that we set the command_id - should come from nvme-fabrics */
	WARN_ON_ONCE(sqe->common.command_id != cpu_to_le16(op->rqno));

	if (op->rq) {				/* skipped on aens */
		ret = nvme_fc_map_data(ctrl, op->rq, op);
		if (ret < 0) {
			dev_err(queue->ctrl->ctrl.device,
			     "Failed to map data (%d)\n", ret);
			nvme_cleanup_cmd(op->rq);
			nvme_fc_ctrl_put(ctrl);
			return (ret == -ENOMEM || ret == -EAGAIN) ?
				BLK_MQ_RQ_QUEUE_BUSY : BLK_MQ_RQ_QUEUE_ERROR;
		}
	}

	fc_dma_sync_single_for_device(ctrl->lport->dev, op->fcp_req.cmddma,
				  sizeof(op->cmd_iu), DMA_TO_DEVICE);

	atomic_set(&op->state, FCPOP_STATE_ACTIVE);

	if (op->rq)
		blk_mq_start_request(op->rq);

	ret = ctrl->lport->ops->fcp_io(&ctrl->lport->localport,
					&ctrl->rport->remoteport,
					queue->lldd_handle, &op->fcp_req);

	if (ret) {
		dev_err(ctrl->dev,
			"Send nvme command failed - lldd returned %d.\n", ret);

		if (op->rq) {			/* normal request */
			nvme_fc_unmap_data(ctrl, op->rq, op);
			nvme_cleanup_cmd(op->rq);
		}
		/* else - aen. no cleanup needed */

		nvme_fc_ctrl_put(ctrl);

		if (ret != -EBUSY)
			return BLK_MQ_RQ_QUEUE_ERROR;

		if (op->rq) {
			blk_mq_stop_hw_queues(op->rq->q);
			blk_mq_delay_queue(queue->hctx, NVMEFC_QUEUE_DELAY);
		}
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	return BLK_MQ_RQ_QUEUE_OK;
}

static int
nvme_fc_queue_rq(struct blk_mq_hw_ctx *hctx,
			const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_fc_queue *queue = hctx->driver_data;
	struct nvme_fc_ctrl *ctrl = queue->ctrl;
	struct request *rq = bd->rq;
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_cmd_iu *cmdiu = &op->cmd_iu;
	struct nvme_command *sqe = &cmdiu->sqe;
	enum nvmefc_fcp_datadir	io_dir;
	u32 data_len;
	int ret;

	ret = nvme_setup_cmd(ns, rq, sqe);
	if (ret)
		return ret;

	data_len = blk_rq_payload_bytes(rq);
	if (data_len)
		io_dir = ((rq_data_dir(rq) == WRITE) ?
					NVMEFC_FCP_WRITE : NVMEFC_FCP_READ);
	else
		io_dir = NVMEFC_FCP_NODATA;

	return nvme_fc_start_fcp_op(ctrl, queue, op, data_len, io_dir);
}

static struct blk_mq_tags *
nvme_fc_tagset(struct nvme_fc_queue *queue)
{
	if (queue->qnum == 0)
		return queue->ctrl->admin_tag_set.tags[queue->qnum];

	return queue->ctrl->tag_set.tags[queue->qnum - 1];
}

static int
nvme_fc_poll(struct blk_mq_hw_ctx *hctx, unsigned int tag)

{
	struct nvme_fc_queue *queue = hctx->driver_data;
	struct nvme_fc_ctrl *ctrl = queue->ctrl;
	struct request *req;
	struct nvme_fc_fcp_op *op;

	req = blk_mq_tag_to_rq(nvme_fc_tagset(queue), tag);
	if (!req) {
		dev_err(queue->ctrl->ctrl.device,
			 "tag 0x%x on QNum %#x not found\n",
			tag, queue->qnum);
		return 0;
	}

	op = blk_mq_rq_to_pdu(req);

	if ((atomic_read(&op->state) == FCPOP_STATE_ACTIVE) &&
		 (ctrl->lport->ops->poll_queue))
		ctrl->lport->ops->poll_queue(&ctrl->lport->localport,
						 queue->lldd_handle);

	return ((atomic_read(&op->state) != FCPOP_STATE_ACTIVE));
}

static void
nvme_fc_submit_async_event(struct nvme_ctrl *arg, int aer_idx)
{
	struct nvme_fc_ctrl *ctrl = to_fc_ctrl(arg);
	struct nvme_fc_fcp_op *aen_op;
	int ret;

	if (aer_idx > NVME_FC_NR_AEN_COMMANDS)
		return;

	aen_op = &ctrl->aen_ops[aer_idx];

	ret = nvme_fc_start_fcp_op(ctrl, aen_op->queue, aen_op, 0,
					NVMEFC_FCP_NODATA);
	if (ret)
		dev_err(ctrl->ctrl.device,
			"failed async event work [%d]\n", aer_idx);
}

static void
nvme_fc_complete_rq(struct request *rq)
{
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(rq);
	struct nvme_fc_ctrl *ctrl = op->ctrl;
	int state;

	state = atomic_xchg(&op->state, FCPOP_STATE_IDLE);

	nvme_cleanup_cmd(rq);
	nvme_fc_unmap_data(ctrl, rq, op);
	nvme_complete_rq(rq);
	nvme_fc_ctrl_put(ctrl);

}

static const struct blk_mq_ops nvme_fc_mq_ops = {
	.queue_rq	= nvme_fc_queue_rq,
	.complete	= nvme_fc_complete_rq,
	.init_request	= nvme_fc_init_request,
	.exit_request	= nvme_fc_exit_request,
	.reinit_request	= nvme_fc_reinit_request,
	.init_hctx	= nvme_fc_init_hctx,
	.poll		= nvme_fc_poll,
	.timeout	= nvme_fc_timeout,
};

static const struct blk_mq_ops nvme_fc_admin_mq_ops = {
	.queue_rq	= nvme_fc_queue_rq,
	.complete	= nvme_fc_complete_rq,
	.init_request	= nvme_fc_init_admin_request,
	.exit_request	= nvme_fc_exit_request,
	.reinit_request	= nvme_fc_reinit_request,
	.init_hctx	= nvme_fc_init_admin_hctx,
	.timeout	= nvme_fc_timeout,
};

static int
nvme_fc_configure_admin_queue(struct nvme_fc_ctrl *ctrl)
{
	u32 segs;
	int error;

	nvme_fc_init_queue(ctrl, 0, NVME_FC_AQ_BLKMQ_DEPTH);

	error = nvme_fc_connect_admin_queue(ctrl, &ctrl->queues[0],
				NVME_FC_AQ_BLKMQ_DEPTH,
				(NVME_FC_AQ_BLKMQ_DEPTH / 4));
	if (error)
		return error;

	memset(&ctrl->admin_tag_set, 0, sizeof(ctrl->admin_tag_set));
	ctrl->admin_tag_set.ops = &nvme_fc_admin_mq_ops;
	ctrl->admin_tag_set.queue_depth = NVME_FC_AQ_BLKMQ_DEPTH;
	ctrl->admin_tag_set.reserved_tags = 2; /* fabric connect + Keep-Alive */
	ctrl->admin_tag_set.numa_node = NUMA_NO_NODE;
	ctrl->admin_tag_set.cmd_size = sizeof(struct nvme_fc_fcp_op) +
					(SG_CHUNK_SIZE *
						sizeof(struct scatterlist)) +
					ctrl->lport->ops->fcprqst_priv_sz;
	ctrl->admin_tag_set.driver_data = ctrl;
	ctrl->admin_tag_set.nr_hw_queues = 1;
	ctrl->admin_tag_set.timeout = ADMIN_TIMEOUT;

	error = blk_mq_alloc_tag_set(&ctrl->admin_tag_set);
	if (error)
		goto out_free_queue;

	ctrl->ctrl.admin_q = blk_mq_init_queue(&ctrl->admin_tag_set);
	if (IS_ERR(ctrl->ctrl.admin_q)) {
		error = PTR_ERR(ctrl->ctrl.admin_q);
		goto out_free_tagset;
	}

	error = __nvme_fc_create_hw_queue(ctrl, &ctrl->queues[0], 0,
				NVME_FC_AQ_BLKMQ_DEPTH);
	if (error)
		goto out_cleanup_queue;

	error = nvmf_connect_admin_queue(&ctrl->ctrl);
	if (error)
		goto out_delete_hw_queue;

	error = nvmf_reg_read64(&ctrl->ctrl, NVME_REG_CAP, &ctrl->cap);
	if (error) {
		dev_err(ctrl->ctrl.device,
			"prop_get NVME_REG_CAP failed\n");
		goto out_delete_hw_queue;
	}

	ctrl->ctrl.sqsize =
		min_t(int, NVME_CAP_MQES(ctrl->cap) + 1, ctrl->ctrl.sqsize);

	error = nvme_enable_ctrl(&ctrl->ctrl, ctrl->cap);
	if (error)
		goto out_delete_hw_queue;

	segs = min_t(u32, NVME_FC_MAX_SEGMENTS,
			ctrl->lport->ops->max_sgl_segments);
	ctrl->ctrl.max_hw_sectors = (segs - 1) << (PAGE_SHIFT - 9);

	error = nvme_init_identify(&ctrl->ctrl);
	if (error)
		goto out_delete_hw_queue;

	nvme_start_keep_alive(&ctrl->ctrl);

	return 0;

out_delete_hw_queue:
	__nvme_fc_delete_hw_queue(ctrl, &ctrl->queues[0], 0);
out_cleanup_queue:
	blk_cleanup_queue(ctrl->ctrl.admin_q);
out_free_tagset:
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
out_free_queue:
	nvme_fc_free_queue(&ctrl->queues[0]);
	return error;
}

/*
 * This routine is used by the transport when it needs to find active
 * io on a queue that is to be terminated. The transport uses
 * blk_mq_tagset_busy_itr() to find the busy requests, which then invoke
 * this routine to kill them on a 1 by 1 basis.
 *
 * As FC allocates FC exchange for each io, the transport must contact
 * the LLDD to terminate the exchange, thus releasing the FC exchange.
 * After terminating the exchange the LLDD will call the transport's
 * normal io done path for the request, but it will have an aborted
 * status. The done path will return the io request back to the block
 * layer with an error status.
 */
static void
nvme_fc_terminate_exchange(struct request *req, void *data, bool reserved)
{
	struct nvme_ctrl *nctrl = data;
	struct nvme_fc_ctrl *ctrl = to_fc_ctrl(nctrl);
	struct nvme_fc_fcp_op *op = blk_mq_rq_to_pdu(req);
int status;

	if (!blk_mq_request_started(req))
		return;

	/* this performs an ABTS-LS on the FC exchange for the io */
	status = __nvme_fc_abort_op(ctrl, op);
	/*
	 * if __nvme_fc_abort_op failed: io wasn't active to abort
	 * consider it done. Assume completion path already completing
	 * in parallel
	 */
	if (status)
		/* io wasn't active to abort consider it done */
		/* assume completion path already completing in parallel */
		return;
}


/*
 * This routine stops operation of the controller. Admin and IO queues
 * are stopped, outstanding ios on them terminated, and the nvme ctrl
 * is shutdown.
 */
static void
nvme_fc_shutdown_ctrl(struct nvme_fc_ctrl *ctrl)
{
	/*
	 * If io queues are present, stop them and terminate all outstanding
	 * ios on them. As FC allocates FC exchange for each io, the
	 * transport must contact the LLDD to terminate the exchange,
	 * thus releasing the FC exchange. We use blk_mq_tagset_busy_itr()
	 * to tell us what io's are busy and invoke a transport routine
	 * to kill them with the LLDD.  After terminating the exchange
	 * the LLDD will call the transport's normal io done path, but it
	 * will have an aborted status. The done path will return the
	 * io requests back to the block layer as part of normal completions
	 * (but with error status).
	 */
	if (ctrl->queue_count > 1) {
		nvme_stop_queues(&ctrl->ctrl);
		blk_mq_tagset_busy_iter(&ctrl->tag_set,
				nvme_fc_terminate_exchange, &ctrl->ctrl);
	}

	if (ctrl->ctrl.state == NVME_CTRL_LIVE)
		nvme_shutdown_ctrl(&ctrl->ctrl);

	/*
	 * now clean up the admin queue. Same thing as above.
	 * use blk_mq_tagset_busy_itr() and the transport routine to
	 * terminate the exchanges.
	 */
	blk_mq_stop_hw_queues(ctrl->ctrl.admin_q);
	blk_mq_tagset_busy_iter(&ctrl->admin_tag_set,
				nvme_fc_terminate_exchange, &ctrl->ctrl);
}

/*
 * Called to teardown an association.
 * May be called with association fully in place or partially in place.
 */
static void
__nvme_fc_remove_ctrl(struct nvme_fc_ctrl *ctrl)
{
	nvme_stop_keep_alive(&ctrl->ctrl);

	/* stop and terminate ios on admin and io queues */
	nvme_fc_shutdown_ctrl(ctrl);

	/*
	 * tear down the controller
	 * This will result in the last reference on the nvme ctrl to
	 * expire, calling the transport nvme_fc_free_nvme_ctrl() callback.
	 * From there, the transport will tear down it's logical queues and
	 * association.
	 */
	nvme_uninit_ctrl(&ctrl->ctrl);

	nvme_put_ctrl(&ctrl->ctrl);
}

static void
nvme_fc_del_ctrl_work(struct work_struct *work)
{
	struct nvme_fc_ctrl *ctrl =
			container_of(work, struct nvme_fc_ctrl, delete_work);

	__nvme_fc_remove_ctrl(ctrl);
}

static int
__nvme_fc_del_ctrl(struct nvme_fc_ctrl *ctrl)
{
	if (!nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_DELETING))
		return -EBUSY;

	if (!queue_work(nvme_fc_wq, &ctrl->delete_work))
		return -EBUSY;

	return 0;
}

/*
 * Request from nvme core layer to delete the controller
 */
static int
nvme_fc_del_nvme_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_fc_ctrl *ctrl = to_fc_ctrl(nctrl);
	struct nvme_fc_rport *rport = ctrl->rport;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&rport->lock, flags);
	ret = __nvme_fc_del_ctrl(ctrl);
	spin_unlock_irqrestore(&rport->lock, flags);
	if (ret)
		return ret;

	flush_work(&ctrl->delete_work);

	return 0;
}

static int
nvme_fc_reset_nvme_ctrl(struct nvme_ctrl *nctrl)
{
	return -EIO;
}

static const struct nvme_ctrl_ops nvme_fc_ctrl_ops = {
	.name			= "fc",
	.module			= THIS_MODULE,
	.is_fabrics		= true,
	.reg_read32		= nvmf_reg_read32,
	.reg_read64		= nvmf_reg_read64,
	.reg_write32		= nvmf_reg_write32,
	.reset_ctrl		= nvme_fc_reset_nvme_ctrl,
	.free_ctrl		= nvme_fc_free_nvme_ctrl,
	.submit_async_event	= nvme_fc_submit_async_event,
	.delete_ctrl		= nvme_fc_del_nvme_ctrl,
	.get_subsysnqn		= nvmf_get_subsysnqn,
	.get_address		= nvmf_get_address,
};

static int
nvme_fc_create_io_queues(struct nvme_fc_ctrl *ctrl)
{
	struct nvmf_ctrl_options *opts = ctrl->ctrl.opts;
	int ret;

	ret = nvme_set_queue_count(&ctrl->ctrl, &opts->nr_io_queues);
	if (ret) {
		dev_info(ctrl->ctrl.device,
			"set_queue_count failed: %d\n", ret);
		return ret;
	}

	ctrl->queue_count = opts->nr_io_queues + 1;
	if (!opts->nr_io_queues)
		return 0;

	dev_info(ctrl->ctrl.device, "creating %d I/O queues.\n",
			opts->nr_io_queues);

	nvme_fc_init_io_queues(ctrl);

	memset(&ctrl->tag_set, 0, sizeof(ctrl->tag_set));
	ctrl->tag_set.ops = &nvme_fc_mq_ops;
	ctrl->tag_set.queue_depth = ctrl->ctrl.opts->queue_size;
	ctrl->tag_set.reserved_tags = 1; /* fabric connect */
	ctrl->tag_set.numa_node = NUMA_NO_NODE;
	ctrl->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ctrl->tag_set.cmd_size = sizeof(struct nvme_fc_fcp_op) +
					(SG_CHUNK_SIZE *
						sizeof(struct scatterlist)) +
					ctrl->lport->ops->fcprqst_priv_sz;
	ctrl->tag_set.driver_data = ctrl;
	ctrl->tag_set.nr_hw_queues = ctrl->queue_count - 1;
	ctrl->tag_set.timeout = NVME_IO_TIMEOUT;

	ret = blk_mq_alloc_tag_set(&ctrl->tag_set);
	if (ret)
		return ret;

	ctrl->ctrl.tagset = &ctrl->tag_set;

	ctrl->ctrl.connect_q = blk_mq_init_queue(&ctrl->tag_set);
	if (IS_ERR(ctrl->ctrl.connect_q)) {
		ret = PTR_ERR(ctrl->ctrl.connect_q);
		goto out_free_tag_set;
	}

	ret = nvme_fc_create_hw_io_queues(ctrl, ctrl->ctrl.opts->queue_size);
	if (ret)
		goto out_cleanup_blk_queue;

	ret = nvme_fc_connect_io_queues(ctrl, ctrl->ctrl.opts->queue_size);
	if (ret)
		goto out_delete_hw_queues;

	return 0;

out_delete_hw_queues:
	nvme_fc_delete_hw_io_queues(ctrl);
out_cleanup_blk_queue:
	nvme_stop_keep_alive(&ctrl->ctrl);
	blk_cleanup_queue(ctrl->ctrl.connect_q);
out_free_tag_set:
	blk_mq_free_tag_set(&ctrl->tag_set);
	nvme_fc_free_io_queues(ctrl);

	/* force put free routine to ignore io queues */
	ctrl->ctrl.tagset = NULL;

	return ret;
}


static struct nvme_ctrl *
__nvme_fc_create_ctrl(struct device *dev, struct nvmf_ctrl_options *opts,
	struct nvme_fc_lport *lport, struct nvme_fc_rport *rport)
{
	struct nvme_fc_ctrl *ctrl;
	unsigned long flags;
	int ret, idx;
	bool changed;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl) {
		ret = -ENOMEM;
		goto out_fail;
	}

	idx = ida_simple_get(&nvme_fc_ctrl_cnt, 0, 0, GFP_KERNEL);
	if (idx < 0) {
		ret = -ENOSPC;
		goto out_free_ctrl;
	}

	ctrl->ctrl.opts = opts;
	INIT_LIST_HEAD(&ctrl->ctrl_list);
	INIT_LIST_HEAD(&ctrl->ls_req_list);
	ctrl->lport = lport;
	ctrl->rport = rport;
	ctrl->dev = lport->dev;
	ctrl->state = FCCTRL_INIT;
	ctrl->cnum = idx;

	ret = nvme_init_ctrl(&ctrl->ctrl, dev, &nvme_fc_ctrl_ops, 0);
	if (ret)
		goto out_free_ida;

	get_device(ctrl->dev);
	kref_init(&ctrl->ref);

	INIT_WORK(&ctrl->delete_work, nvme_fc_del_ctrl_work);
	spin_lock_init(&ctrl->lock);

	/* io queue count */
	ctrl->queue_count = min_t(unsigned int,
				opts->nr_io_queues,
				lport->ops->max_hw_queues);
	opts->nr_io_queues = ctrl->queue_count;	/* so opts has valid value */
	ctrl->queue_count++;	/* +1 for admin queue */

	ctrl->ctrl.sqsize = opts->queue_size - 1;
	ctrl->ctrl.kato = opts->kato;

	ret = -ENOMEM;
	ctrl->queues = kcalloc(ctrl->queue_count, sizeof(struct nvme_fc_queue),
				GFP_KERNEL);
	if (!ctrl->queues)
		goto out_uninit_ctrl;

	ret = nvme_fc_configure_admin_queue(ctrl);
	if (ret)
		goto out_uninit_ctrl;

	/* sanity checks */

	/* FC-NVME does not have other data in the capsule */
	if (ctrl->ctrl.icdoff) {
		dev_err(ctrl->ctrl.device, "icdoff %d is not supported!\n",
				ctrl->ctrl.icdoff);
		goto out_remove_admin_queue;
	}

	/* FC-NVME supports normal SGL Data Block Descriptors */

	if (opts->queue_size > ctrl->ctrl.maxcmd) {
		/* warn if maxcmd is lower than queue_size */
		dev_warn(ctrl->ctrl.device,
			"queue_size %zu > ctrl maxcmd %u, reducing "
			"to queue_size\n",
			opts->queue_size, ctrl->ctrl.maxcmd);
		opts->queue_size = ctrl->ctrl.maxcmd;
	}

	ret = nvme_fc_init_aen_ops(ctrl);
	if (ret)
		goto out_exit_aen_ops;

	if (ctrl->queue_count > 1) {
		ret = nvme_fc_create_io_queues(ctrl);
		if (ret)
			goto out_exit_aen_ops;
	}

	spin_lock_irqsave(&ctrl->lock, flags);
	ctrl->state = FCCTRL_ACTIVE;
	spin_unlock_irqrestore(&ctrl->lock, flags);

	changed = nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_LIVE);
	WARN_ON_ONCE(!changed);

	dev_info(ctrl->ctrl.device,
		"NVME-FC{%d}: new ctrl: NQN \"%s\"\n",
		ctrl->cnum, ctrl->ctrl.opts->subsysnqn);

	kref_get(&ctrl->ctrl.kref);

	spin_lock_irqsave(&rport->lock, flags);
	list_add_tail(&ctrl->ctrl_list, &rport->ctrl_list);
	spin_unlock_irqrestore(&rport->lock, flags);

	if (opts->nr_io_queues) {
		nvme_queue_scan(&ctrl->ctrl);
		nvme_queue_async_events(&ctrl->ctrl);
	}

	return &ctrl->ctrl;

out_exit_aen_ops:
	nvme_fc_exit_aen_ops(ctrl);
out_remove_admin_queue:
	/* send a Disconnect(association) LS to fc-nvme target */
	nvme_fc_xmt_disconnect_assoc(ctrl);
	nvme_stop_keep_alive(&ctrl->ctrl);
	nvme_fc_destroy_admin_queue(ctrl);
out_uninit_ctrl:
	nvme_uninit_ctrl(&ctrl->ctrl);
	nvme_put_ctrl(&ctrl->ctrl);
	if (ret > 0)
		ret = -EIO;
	/* exit via here will follow ctlr ref point callbacks to free */
	return ERR_PTR(ret);

out_free_ida:
	ida_simple_remove(&nvme_fc_ctrl_cnt, ctrl->cnum);
out_free_ctrl:
	kfree(ctrl);
out_fail:
	nvme_fc_rport_put(rport);
	/* exit via here doesn't follow ctlr ref points */
	return ERR_PTR(ret);
}

enum {
	FCT_TRADDR_ERR		= 0,
	FCT_TRADDR_WWNN		= 1 << 0,
	FCT_TRADDR_WWPN		= 1 << 1,
};

struct nvmet_fc_traddr {
	u64	nn;
	u64	pn;
};

static const match_table_t traddr_opt_tokens = {
	{ FCT_TRADDR_WWNN,	"nn-%s"		},
	{ FCT_TRADDR_WWPN,	"pn-%s"		},
	{ FCT_TRADDR_ERR,	NULL		}
};

static int
nvme_fc_parse_address(struct nvmet_fc_traddr *traddr, char *buf)
{
	substring_t args[MAX_OPT_ARGS];
	char *options, *o, *p;
	int token, ret = 0;
	u64 token64;

	options = o = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	while ((p = strsep(&o, ":\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, traddr_opt_tokens, args);
		switch (token) {
		case FCT_TRADDR_WWNN:
			if (match_u64(args, &token64)) {
				ret = -EINVAL;
				goto out;
			}
			traddr->nn = token64;
			break;
		case FCT_TRADDR_WWPN:
			if (match_u64(args, &token64)) {
				ret = -EINVAL;
				goto out;
			}
			traddr->pn = token64;
			break;
		default:
			pr_warn("unknown traddr token or missing value '%s'\n",
					p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	kfree(options);
	return ret;
}

static struct nvme_ctrl *
nvme_fc_create_ctrl(struct device *dev, struct nvmf_ctrl_options *opts)
{
	struct nvme_fc_lport *lport;
	struct nvme_fc_rport *rport;
	struct nvmet_fc_traddr laddr = { 0L, 0L };
	struct nvmet_fc_traddr raddr = { 0L, 0L };
	unsigned long flags;
	int ret;

	ret = nvme_fc_parse_address(&raddr, opts->traddr);
	if (ret || !raddr.nn || !raddr.pn)
		return ERR_PTR(-EINVAL);

	ret = nvme_fc_parse_address(&laddr, opts->host_traddr);
	if (ret || !laddr.nn || !laddr.pn)
		return ERR_PTR(-EINVAL);

	/* find the host and remote ports to connect together */
	spin_lock_irqsave(&nvme_fc_lock, flags);
	list_for_each_entry(lport, &nvme_fc_lport_list, port_list) {
		if (lport->localport.node_name != laddr.nn ||
		    lport->localport.port_name != laddr.pn)
			continue;

		list_for_each_entry(rport, &lport->endp_list, endp_list) {
			if (rport->remoteport.node_name != raddr.nn ||
			    rport->remoteport.port_name != raddr.pn)
				continue;

			/* if fail to get reference fall through. Will error */
			if (!nvme_fc_rport_get(rport))
				break;

			spin_unlock_irqrestore(&nvme_fc_lock, flags);

			return __nvme_fc_create_ctrl(dev, opts, lport, rport);
		}
	}
	spin_unlock_irqrestore(&nvme_fc_lock, flags);

	return ERR_PTR(-ENOENT);
}


static struct nvmf_transport_ops nvme_fc_transport = {
	.name		= "fc",
	.required_opts	= NVMF_OPT_TRADDR | NVMF_OPT_HOST_TRADDR,
	.allowed_opts	= NVMF_OPT_RECONNECT_DELAY,
	.create_ctrl	= nvme_fc_create_ctrl,
};

static int __init nvme_fc_init_module(void)
{
	int ret;

	nvme_fc_wq = create_workqueue("nvme_fc_wq");
	if (!nvme_fc_wq)
		return -ENOMEM;

	ret = nvmf_register_transport(&nvme_fc_transport);
	if (ret)
		goto err;

	return 0;
err:
	destroy_workqueue(nvme_fc_wq);
	return ret;
}

static void __exit nvme_fc_exit_module(void)
{
	/* sanity check - all lports should be removed */
	if (!list_empty(&nvme_fc_lport_list))
		pr_warn("%s: localport list not empty\n", __func__);

	nvmf_unregister_transport(&nvme_fc_transport);

	destroy_workqueue(nvme_fc_wq);

	ida_destroy(&nvme_fc_local_port_cnt);
	ida_destroy(&nvme_fc_ctrl_cnt);
}

module_init(nvme_fc_init_module);
module_exit(nvme_fc_exit_module);

MODULE_LICENSE("GPL v2");

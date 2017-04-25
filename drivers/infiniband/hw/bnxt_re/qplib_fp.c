/*
 * Broadcom NetXtreme-E RoCE driver.
 *
 * Copyright (c) 2016 - 2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Fast Path Operators
 */

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/prefetch.h>

#include "roce_hsi.h"

#include "qplib_res.h"
#include "qplib_rcfw.h"
#include "qplib_sp.h"
#include "qplib_fp.h"

static void bnxt_qplib_arm_cq_enable(struct bnxt_qplib_cq *cq);

static void bnxt_qplib_free_qp_hdr_buf(struct bnxt_qplib_res *res,
				       struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_q *sq = &qp->sq;

	if (qp->rq_hdr_buf)
		dma_free_coherent(&res->pdev->dev,
				  rq->hwq.max_elements * qp->rq_hdr_buf_size,
				  qp->rq_hdr_buf, qp->rq_hdr_buf_map);
	if (qp->sq_hdr_buf)
		dma_free_coherent(&res->pdev->dev,
				  sq->hwq.max_elements * qp->sq_hdr_buf_size,
				  qp->sq_hdr_buf, qp->sq_hdr_buf_map);
	qp->rq_hdr_buf = NULL;
	qp->sq_hdr_buf = NULL;
	qp->rq_hdr_buf_map = 0;
	qp->sq_hdr_buf_map = 0;
	qp->sq_hdr_buf_size = 0;
	qp->rq_hdr_buf_size = 0;
}

static int bnxt_qplib_alloc_qp_hdr_buf(struct bnxt_qplib_res *res,
				       struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_q *sq = &qp->rq;
	int rc = 0;

	if (qp->sq_hdr_buf_size && sq->hwq.max_elements) {
		qp->sq_hdr_buf = dma_alloc_coherent(&res->pdev->dev,
					sq->hwq.max_elements *
					qp->sq_hdr_buf_size,
					&qp->sq_hdr_buf_map, GFP_KERNEL);
		if (!qp->sq_hdr_buf) {
			rc = -ENOMEM;
			dev_err(&res->pdev->dev,
				"QPLIB: Failed to create sq_hdr_buf");
			goto fail;
		}
	}

	if (qp->rq_hdr_buf_size && rq->hwq.max_elements) {
		qp->rq_hdr_buf = dma_alloc_coherent(&res->pdev->dev,
						    rq->hwq.max_elements *
						    qp->rq_hdr_buf_size,
						    &qp->rq_hdr_buf_map,
						    GFP_KERNEL);
		if (!qp->rq_hdr_buf) {
			rc = -ENOMEM;
			dev_err(&res->pdev->dev,
				"QPLIB: Failed to create rq_hdr_buf");
			goto fail;
		}
	}
	return 0;

fail:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
	return rc;
}

static void bnxt_qplib_service_nq(unsigned long data)
{
	struct bnxt_qplib_nq *nq = (struct bnxt_qplib_nq *)data;
	struct bnxt_qplib_hwq *hwq = &nq->hwq;
	struct nq_base *nqe, **nq_ptr;
	int num_cqne_processed = 0;
	u32 sw_cons, raw_cons;
	u16 type;
	int budget = nq->budget;
	u64 q_handle;

	/* Service the NQ until empty */
	raw_cons = hwq->cons;
	while (budget--) {
		sw_cons = HWQ_CMP(raw_cons, hwq);
		nq_ptr = (struct nq_base **)hwq->pbl_ptr;
		nqe = &nq_ptr[NQE_PG(sw_cons)][NQE_IDX(sw_cons)];
		if (!NQE_CMP_VALID(nqe, raw_cons, hwq->max_elements))
			break;

		type = le16_to_cpu(nqe->info10_type) & NQ_BASE_TYPE_MASK;
		switch (type) {
		case NQ_BASE_TYPE_CQ_NOTIFICATION:
		{
			struct nq_cn *nqcne = (struct nq_cn *)nqe;

			q_handle = le32_to_cpu(nqcne->cq_handle_low);
			q_handle |= (u64)le32_to_cpu(nqcne->cq_handle_high)
						     << 32;
			bnxt_qplib_arm_cq_enable((struct bnxt_qplib_cq *)
						 ((unsigned long)q_handle));
			if (!nq->cqn_handler(nq, (struct bnxt_qplib_cq *)
						 ((unsigned long)q_handle)))
				num_cqne_processed++;
			else
				dev_warn(&nq->pdev->dev,
					 "QPLIB: cqn - type 0x%x not handled",
					 type);
			break;
		}
		case NQ_BASE_TYPE_DBQ_EVENT:
			break;
		default:
			dev_warn(&nq->pdev->dev,
				 "QPLIB: nqe with type = 0x%x not handled",
				 type);
			break;
		}
		raw_cons++;
	}
	if (hwq->cons != raw_cons) {
		hwq->cons = raw_cons;
		NQ_DB_REARM(nq->bar_reg_iomem, hwq->cons, hwq->max_elements);
	}
}

static irqreturn_t bnxt_qplib_nq_irq(int irq, void *dev_instance)
{
	struct bnxt_qplib_nq *nq = dev_instance;
	struct bnxt_qplib_hwq *hwq = &nq->hwq;
	struct nq_base **nq_ptr;
	u32 sw_cons;

	/* Prefetch the NQ element */
	sw_cons = HWQ_CMP(hwq->cons, hwq);
	nq_ptr = (struct nq_base **)nq->hwq.pbl_ptr;
	prefetch(&nq_ptr[NQE_PG(sw_cons)][NQE_IDX(sw_cons)]);

	/* Fan out to CPU affinitized kthreads? */
	tasklet_schedule(&nq->worker);

	return IRQ_HANDLED;
}

void bnxt_qplib_disable_nq(struct bnxt_qplib_nq *nq)
{
	/* Make sure the HW is stopped! */
	synchronize_irq(nq->vector);
	tasklet_disable(&nq->worker);
	tasklet_kill(&nq->worker);

	if (nq->requested) {
		free_irq(nq->vector, nq);
		nq->requested = false;
	}
	if (nq->bar_reg_iomem)
		iounmap(nq->bar_reg_iomem);
	nq->bar_reg_iomem = NULL;

	nq->cqn_handler = NULL;
	nq->srqn_handler = NULL;
	nq->vector = 0;
}

int bnxt_qplib_enable_nq(struct pci_dev *pdev, struct bnxt_qplib_nq *nq,
			 int msix_vector, int bar_reg_offset,
			 int (*cqn_handler)(struct bnxt_qplib_nq *nq,
					    struct bnxt_qplib_cq *),
			 int (*srqn_handler)(struct bnxt_qplib_nq *nq,
					     void *, u8 event))
{
	resource_size_t nq_base;
	int rc;

	nq->pdev = pdev;
	nq->vector = msix_vector;

	nq->cqn_handler = cqn_handler;

	nq->srqn_handler = srqn_handler;

	tasklet_init(&nq->worker, bnxt_qplib_service_nq, (unsigned long)nq);

	nq->requested = false;
	rc = request_irq(nq->vector, bnxt_qplib_nq_irq, 0, "bnxt_qplib_nq", nq);
	if (rc) {
		dev_err(&nq->pdev->dev,
			"Failed to request IRQ for NQ: %#x", rc);
		bnxt_qplib_disable_nq(nq);
		goto fail;
	}
	nq->requested = true;
	nq->bar_reg = NQ_CONS_PCI_BAR_REGION;
	nq->bar_reg_off = bar_reg_offset;
	nq_base = pci_resource_start(pdev, nq->bar_reg);
	if (!nq_base) {
		rc = -ENOMEM;
		goto fail;
	}
	nq->bar_reg_iomem = ioremap_nocache(nq_base + nq->bar_reg_off, 4);
	if (!nq->bar_reg_iomem) {
		rc = -ENOMEM;
		goto fail;
	}
	NQ_DB_REARM(nq->bar_reg_iomem, nq->hwq.cons, nq->hwq.max_elements);

	return 0;
fail:
	bnxt_qplib_disable_nq(nq);
	return rc;
}

void bnxt_qplib_free_nq(struct bnxt_qplib_nq *nq)
{
	if (nq->hwq.max_elements)
		bnxt_qplib_free_hwq(nq->pdev, &nq->hwq);
}

int bnxt_qplib_alloc_nq(struct pci_dev *pdev, struct bnxt_qplib_nq *nq)
{
	nq->pdev = pdev;
	if (!nq->hwq.max_elements ||
	    nq->hwq.max_elements > BNXT_QPLIB_NQE_MAX_CNT)
		nq->hwq.max_elements = BNXT_QPLIB_NQE_MAX_CNT;

	if (bnxt_qplib_alloc_init_hwq(nq->pdev, &nq->hwq, NULL, 0,
				      &nq->hwq.max_elements,
				      BNXT_QPLIB_MAX_NQE_ENTRY_SIZE, 0,
				      PAGE_SIZE, HWQ_TYPE_L2_CMPL))
		return -ENOMEM;

	nq->budget = 8;
	return 0;
}

/* QP */
int bnxt_qplib_create_qp1(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_create_qp1 req;
	struct creq_create_qp1_resp *resp;
	struct bnxt_qplib_pbl *pbl;
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_q *rq = &qp->rq;
	int rc;
	u16 cmd_flags = 0;
	u32 qp_flags = 0;

	RCFW_CMD_PREP(req, CREATE_QP1, cmd_flags);

	/* General */
	req.type = qp->type;
	req.dpi = cpu_to_le32(qp->dpi->dpi);
	req.qp_handle = cpu_to_le64(qp->qp_handle);

	/* SQ */
	sq->hwq.max_elements = sq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &sq->hwq, NULL, 0,
				       &sq->hwq.max_elements,
				       BNXT_QPLIB_MAX_SQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	sq->swq = kcalloc(sq->hwq.max_elements, sizeof(*sq->swq), GFP_KERNEL);
	if (!sq->swq) {
		rc = -ENOMEM;
		goto fail_sq;
	}
	pbl = &sq->hwq.pbl[PBL_LVL_0];
	req.sq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
	req.sq_pg_size_sq_lvl =
		((sq->hwq.level & CMDQ_CREATE_QP1_SQ_LVL_MASK)
				<<  CMDQ_CREATE_QP1_SQ_LVL_SFT) |
		(pbl->pg_size == ROCE_PG_SIZE_4K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_4K :
		 pbl->pg_size == ROCE_PG_SIZE_8K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_8K :
		 pbl->pg_size == ROCE_PG_SIZE_64K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_64K :
		 pbl->pg_size == ROCE_PG_SIZE_2M ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_2M :
		 pbl->pg_size == ROCE_PG_SIZE_8M ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_8M :
		 pbl->pg_size == ROCE_PG_SIZE_1G ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_1G :
		 CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_4K);

	if (qp->scq)
		req.scq_cid = cpu_to_le32(qp->scq->id);

	qp_flags |= CMDQ_CREATE_QP1_QP_FLAGS_RESERVED_LKEY_ENABLE;

	/* RQ */
	if (rq->max_wqe) {
		rq->hwq.max_elements = qp->rq.max_wqe;
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, &rq->hwq, NULL, 0,
					       &rq->hwq.max_elements,
					       BNXT_QPLIB_MAX_RQE_ENTRY_SIZE, 0,
					       PAGE_SIZE, HWQ_TYPE_QUEUE);
		if (rc)
			goto fail_sq;

		rq->swq = kcalloc(rq->hwq.max_elements, sizeof(*rq->swq),
				  GFP_KERNEL);
		if (!rq->swq) {
			rc = -ENOMEM;
			goto fail_rq;
		}
		pbl = &rq->hwq.pbl[PBL_LVL_0];
		req.rq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
		req.rq_pg_size_rq_lvl =
			((rq->hwq.level & CMDQ_CREATE_QP1_RQ_LVL_MASK) <<
			 CMDQ_CREATE_QP1_RQ_LVL_SFT) |
				(pbl->pg_size == ROCE_PG_SIZE_4K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_4K :
				 pbl->pg_size == ROCE_PG_SIZE_8K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_8K :
				 pbl->pg_size == ROCE_PG_SIZE_64K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_64K :
				 pbl->pg_size == ROCE_PG_SIZE_2M ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_2M :
				 pbl->pg_size == ROCE_PG_SIZE_8M ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_8M :
				 pbl->pg_size == ROCE_PG_SIZE_1G ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_1G :
				 CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_4K);
		if (qp->rcq)
			req.rcq_cid = cpu_to_le32(qp->rcq->id);
	}

	/* Header buffer - allow hdr_buf pass in */
	rc = bnxt_qplib_alloc_qp_hdr_buf(res, qp);
	if (rc) {
		rc = -ENOMEM;
		goto fail;
	}
	req.qp_flags = cpu_to_le32(qp_flags);
	req.sq_size = cpu_to_le32(sq->hwq.max_elements);
	req.rq_size = cpu_to_le32(rq->hwq.max_elements);

	req.sq_fwo_sq_sge =
		cpu_to_le16((sq->max_sge & CMDQ_CREATE_QP1_SQ_SGE_MASK) <<
			    CMDQ_CREATE_QP1_SQ_SGE_SFT);
	req.rq_fwo_rq_sge =
		cpu_to_le16((rq->max_sge & CMDQ_CREATE_QP1_RQ_SGE_MASK) <<
			    CMDQ_CREATE_QP1_RQ_SGE_SFT);

	req.pd_id = cpu_to_le32(qp->pd->id);

	resp = (struct creq_create_qp1_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&res->pdev->dev, "QPLIB: FP: CREATE_QP1 send failed");
		rc = -EINVAL;
		goto fail;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_QP1 timed out");
		rc = -ETIMEDOUT;
		goto fail;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_QP1 failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		rc = -EINVAL;
		goto fail;
	}
	qp->id = le32_to_cpu(resp->xid);
	qp->cur_qp_state = CMDQ_MODIFY_QP_NEW_STATE_RESET;
	sq->flush_in_progress = false;
	rq->flush_in_progress = false;

	return 0;

fail:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
fail_rq:
	bnxt_qplib_free_hwq(res->pdev, &rq->hwq);
	kfree(rq->swq);
fail_sq:
	bnxt_qplib_free_hwq(res->pdev, &sq->hwq);
	kfree(sq->swq);
exit:
	return rc;
}

int bnxt_qplib_create_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct sq_send *hw_sq_send_hdr, **hw_sq_send_ptr;
	struct cmdq_create_qp req;
	struct creq_create_qp_resp *resp;
	struct bnxt_qplib_pbl *pbl;
	struct sq_psn_search **psn_search_ptr;
	unsigned long int psn_search, poff = 0;
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_hwq *xrrq;
	int i, rc, req_size, psn_sz;
	u16 cmd_flags = 0, max_ssge;
	u32 sw_prod, qp_flags = 0;

	RCFW_CMD_PREP(req, CREATE_QP, cmd_flags);

	/* General */
	req.type = qp->type;
	req.dpi = cpu_to_le32(qp->dpi->dpi);
	req.qp_handle = cpu_to_le64(qp->qp_handle);

	/* SQ */
	psn_sz = (qp->type == CMDQ_CREATE_QP_TYPE_RC) ?
		 sizeof(struct sq_psn_search) : 0;
	sq->hwq.max_elements = sq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &sq->hwq, sq->sglist,
				       sq->nmap, &sq->hwq.max_elements,
				       BNXT_QPLIB_MAX_SQE_ENTRY_SIZE,
				       psn_sz,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	sq->swq = kcalloc(sq->hwq.max_elements, sizeof(*sq->swq), GFP_KERNEL);
	if (!sq->swq) {
		rc = -ENOMEM;
		goto fail_sq;
	}
	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	if (psn_sz) {
		psn_search_ptr = (struct sq_psn_search **)
				  &hw_sq_send_ptr[get_sqe_pg
					(sq->hwq.max_elements)];
		psn_search = (unsigned long int)
			      &hw_sq_send_ptr[get_sqe_pg(sq->hwq.max_elements)]
			      [get_sqe_idx(sq->hwq.max_elements)];
		if (psn_search & ~PAGE_MASK) {
			/* If the psn_search does not start on a page boundary,
			 * then calculate the offset
			 */
			poff = (psn_search & ~PAGE_MASK) /
				BNXT_QPLIB_MAX_PSNE_ENTRY_SIZE;
		}
		for (i = 0; i < sq->hwq.max_elements; i++)
			sq->swq[i].psn_search =
				&psn_search_ptr[get_psne_pg(i + poff)]
					       [get_psne_idx(i + poff)];
	}
	pbl = &sq->hwq.pbl[PBL_LVL_0];
	req.sq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
	req.sq_pg_size_sq_lvl =
		((sq->hwq.level & CMDQ_CREATE_QP_SQ_LVL_MASK)
				 <<  CMDQ_CREATE_QP_SQ_LVL_SFT) |
		(pbl->pg_size == ROCE_PG_SIZE_4K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_4K :
		 pbl->pg_size == ROCE_PG_SIZE_8K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_8K :
		 pbl->pg_size == ROCE_PG_SIZE_64K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_64K :
		 pbl->pg_size == ROCE_PG_SIZE_2M ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_2M :
		 pbl->pg_size == ROCE_PG_SIZE_8M ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_8M :
		 pbl->pg_size == ROCE_PG_SIZE_1G ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_1G :
		 CMDQ_CREATE_QP_SQ_PG_SIZE_PG_4K);

	/* initialize all SQ WQEs to LOCAL_INVALID (sq prep for hw fetch) */
	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	for (sw_prod = 0; sw_prod < sq->hwq.max_elements; sw_prod++) {
		hw_sq_send_hdr = &hw_sq_send_ptr[get_sqe_pg(sw_prod)]
						[get_sqe_idx(sw_prod)];
		hw_sq_send_hdr->wqe_type = SQ_BASE_WQE_TYPE_LOCAL_INVALID;
	}

	if (qp->scq)
		req.scq_cid = cpu_to_le32(qp->scq->id);

	qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_RESERVED_LKEY_ENABLE;
	qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_FR_PMR_ENABLED;
	if (qp->sig_type)
		qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_FORCE_COMPLETION;

	/* RQ */
	if (rq->max_wqe) {
		rq->hwq.max_elements = rq->max_wqe;
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, &rq->hwq, rq->sglist,
					       rq->nmap, &rq->hwq.max_elements,
					       BNXT_QPLIB_MAX_RQE_ENTRY_SIZE, 0,
					       PAGE_SIZE, HWQ_TYPE_QUEUE);
		if (rc)
			goto fail_sq;

		rq->swq = kcalloc(rq->hwq.max_elements, sizeof(*rq->swq),
				  GFP_KERNEL);
		if (!rq->swq) {
			rc = -ENOMEM;
			goto fail_rq;
		}
		pbl = &rq->hwq.pbl[PBL_LVL_0];
		req.rq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
		req.rq_pg_size_rq_lvl =
			((rq->hwq.level & CMDQ_CREATE_QP_RQ_LVL_MASK) <<
			 CMDQ_CREATE_QP_RQ_LVL_SFT) |
				(pbl->pg_size == ROCE_PG_SIZE_4K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_4K :
				 pbl->pg_size == ROCE_PG_SIZE_8K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_8K :
				 pbl->pg_size == ROCE_PG_SIZE_64K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_64K :
				 pbl->pg_size == ROCE_PG_SIZE_2M ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_2M :
				 pbl->pg_size == ROCE_PG_SIZE_8M ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_8M :
				 pbl->pg_size == ROCE_PG_SIZE_1G ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_1G :
				 CMDQ_CREATE_QP_RQ_PG_SIZE_PG_4K);
	}

	if (qp->rcq)
		req.rcq_cid = cpu_to_le32(qp->rcq->id);
	req.qp_flags = cpu_to_le32(qp_flags);
	req.sq_size = cpu_to_le32(sq->hwq.max_elements);
	req.rq_size = cpu_to_le32(rq->hwq.max_elements);
	qp->sq_hdr_buf = NULL;
	qp->rq_hdr_buf = NULL;

	rc = bnxt_qplib_alloc_qp_hdr_buf(res, qp);
	if (rc)
		goto fail_rq;

	/* CTRL-22434: Irrespective of the requested SGE count on the SQ
	 * always create the QP with max send sges possible if the requested
	 * inline size is greater than 0.
	 */
	max_ssge = qp->max_inline_data ? 6 : sq->max_sge;
	req.sq_fwo_sq_sge = cpu_to_le16(
				((max_ssge & CMDQ_CREATE_QP_SQ_SGE_MASK)
				 << CMDQ_CREATE_QP_SQ_SGE_SFT) | 0);
	req.rq_fwo_rq_sge = cpu_to_le16(
				((rq->max_sge & CMDQ_CREATE_QP_RQ_SGE_MASK)
				 << CMDQ_CREATE_QP_RQ_SGE_SFT) | 0);
	/* ORRQ and IRRQ */
	if (psn_sz) {
		xrrq = &qp->orrq;
		xrrq->max_elements =
			ORD_LIMIT_TO_ORRQ_SLOTS(qp->max_rd_atomic);
		req_size = xrrq->max_elements *
			   BNXT_QPLIB_MAX_ORRQE_ENTRY_SIZE + PAGE_SIZE - 1;
		req_size &= ~(PAGE_SIZE - 1);
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, xrrq, NULL, 0,
					       &xrrq->max_elements,
					       BNXT_QPLIB_MAX_ORRQE_ENTRY_SIZE,
					       0, req_size, HWQ_TYPE_CTX);
		if (rc)
			goto fail_buf_free;
		pbl = &xrrq->pbl[PBL_LVL_0];
		req.orrq_addr = cpu_to_le64(pbl->pg_map_arr[0]);

		xrrq = &qp->irrq;
		xrrq->max_elements = IRD_LIMIT_TO_IRRQ_SLOTS(
						qp->max_dest_rd_atomic);
		req_size = xrrq->max_elements *
			   BNXT_QPLIB_MAX_IRRQE_ENTRY_SIZE + PAGE_SIZE - 1;
		req_size &= ~(PAGE_SIZE - 1);

		rc = bnxt_qplib_alloc_init_hwq(res->pdev, xrrq, NULL, 0,
					       &xrrq->max_elements,
					       BNXT_QPLIB_MAX_IRRQE_ENTRY_SIZE,
					       0, req_size, HWQ_TYPE_CTX);
		if (rc)
			goto fail_orrq;

		pbl = &xrrq->pbl[PBL_LVL_0];
		req.irrq_addr = cpu_to_le64(pbl->pg_map_arr[0]);
	}
	req.pd_id = cpu_to_le32(qp->pd->id);

	resp = (struct creq_create_qp_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_QP send failed");
		rc = -EINVAL;
		goto fail;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_QP timed out");
		rc = -ETIMEDOUT;
		goto fail;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_QP failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		rc = -EINVAL;
		goto fail;
	}
	qp->id = le32_to_cpu(resp->xid);
	qp->cur_qp_state = CMDQ_MODIFY_QP_NEW_STATE_RESET;
	sq->flush_in_progress = false;
	rq->flush_in_progress = false;

	return 0;

fail:
	if (qp->irrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->irrq);
fail_orrq:
	if (qp->orrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->orrq);
fail_buf_free:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
fail_rq:
	bnxt_qplib_free_hwq(res->pdev, &rq->hwq);
	kfree(rq->swq);
fail_sq:
	bnxt_qplib_free_hwq(res->pdev, &sq->hwq);
	kfree(sq->swq);
exit:
	return rc;
}

static void __modify_flags_from_init_state(struct bnxt_qplib_qp *qp)
{
	switch (qp->state) {
	case CMDQ_MODIFY_QP_NEW_STATE_RTR:
		/* INIT->RTR, configure the path_mtu to the default
		 * 2048 if not being requested
		 */
		if (!(qp->modify_flags &
		    CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU)) {
			qp->modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU;
			qp->path_mtu =
				CMDQ_MODIFY_QP_PATH_MTU_MTU_2048;
		}
		qp->modify_flags &=
			~CMDQ_MODIFY_QP_MODIFY_MASK_VLAN_ID;
		/* Bono FW require the max_dest_rd_atomic to be >= 1 */
		if (qp->max_dest_rd_atomic < 1)
			qp->max_dest_rd_atomic = 1;
		qp->modify_flags &= ~CMDQ_MODIFY_QP_MODIFY_MASK_SRC_MAC;
		/* Bono FW 20.6.5 requires SGID_INDEX configuration */
		if (!(qp->modify_flags &
		    CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX)) {
			qp->modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX;
			qp->ah.sgid_index = 0;
		}
		break;
	default:
		break;
	}
}

static void __modify_flags_from_rtr_state(struct bnxt_qplib_qp *qp)
{
	switch (qp->state) {
	case CMDQ_MODIFY_QP_NEW_STATE_RTS:
		/* Bono FW requires the max_rd_atomic to be >= 1 */
		if (qp->max_rd_atomic < 1)
			qp->max_rd_atomic = 1;
		/* Bono FW does not allow PKEY_INDEX,
		 * DGID, FLOW_LABEL, SGID_INDEX, HOP_LIMIT,
		 * TRAFFIC_CLASS, DEST_MAC, PATH_MTU, RQ_PSN,
		 * MIN_RNR_TIMER, MAX_DEST_RD_ATOMIC, DEST_QP_ID
		 * modification
		 */
		qp->modify_flags &=
			~(CMDQ_MODIFY_QP_MODIFY_MASK_PKEY |
			  CMDQ_MODIFY_QP_MODIFY_MASK_DGID |
			  CMDQ_MODIFY_QP_MODIFY_MASK_FLOW_LABEL |
			  CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX |
			  CMDQ_MODIFY_QP_MODIFY_MASK_HOP_LIMIT |
			  CMDQ_MODIFY_QP_MODIFY_MASK_TRAFFIC_CLASS |
			  CMDQ_MODIFY_QP_MODIFY_MASK_DEST_MAC |
			  CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU |
			  CMDQ_MODIFY_QP_MODIFY_MASK_RQ_PSN |
			  CMDQ_MODIFY_QP_MODIFY_MASK_MIN_RNR_TIMER |
			  CMDQ_MODIFY_QP_MODIFY_MASK_MAX_DEST_RD_ATOMIC |
			  CMDQ_MODIFY_QP_MODIFY_MASK_DEST_QP_ID);
		break;
	default:
		break;
	}
}

static void __filter_modify_flags(struct bnxt_qplib_qp *qp)
{
	switch (qp->cur_qp_state) {
	case CMDQ_MODIFY_QP_NEW_STATE_RESET:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_INIT:
		__modify_flags_from_init_state(qp);
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_RTR:
		__modify_flags_from_rtr_state(qp);
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_RTS:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_SQD:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_SQE:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_ERR:
		break;
	default:
		break;
	}
}

int bnxt_qplib_modify_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_modify_qp req;
	struct creq_modify_qp_resp *resp;
	u16 cmd_flags = 0, pkey;
	u32 temp32[4];
	u32 bmask;

	RCFW_CMD_PREP(req, MODIFY_QP, cmd_flags);

	/* Filter out the qp_attr_mask based on the state->new transition */
	__filter_modify_flags(qp);
	bmask = qp->modify_flags;
	req.modify_mask = cpu_to_le32(qp->modify_flags);
	req.qp_cid = cpu_to_le32(qp->id);
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_STATE) {
		req.network_type_en_sqd_async_notify_new_state =
				(qp->state & CMDQ_MODIFY_QP_NEW_STATE_MASK) |
				(qp->en_sqd_async_notify ?
					CMDQ_MODIFY_QP_EN_SQD_ASYNC_NOTIFY : 0);
	}
	req.network_type_en_sqd_async_notify_new_state |= qp->nw_type;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_ACCESS)
		req.access = qp->access;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_PKEY) {
		if (!bnxt_qplib_get_pkey(res, &res->pkey_tbl,
					 qp->pkey_index, &pkey))
			req.pkey = cpu_to_le16(pkey);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_QKEY)
		req.qkey = cpu_to_le32(qp->qkey);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DGID) {
		memcpy(temp32, qp->ah.dgid.data, sizeof(struct bnxt_qplib_gid));
		req.dgid[0] = cpu_to_le32(temp32[0]);
		req.dgid[1] = cpu_to_le32(temp32[1]);
		req.dgid[2] = cpu_to_le32(temp32[2]);
		req.dgid[3] = cpu_to_le32(temp32[3]);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_FLOW_LABEL)
		req.flow_label = cpu_to_le32(qp->ah.flow_label);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX)
		req.sgid_index = cpu_to_le16(res->sgid_tbl.hw_id
					     [qp->ah.sgid_index]);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_HOP_LIMIT)
		req.hop_limit = qp->ah.hop_limit;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TRAFFIC_CLASS)
		req.traffic_class = qp->ah.traffic_class;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DEST_MAC)
		memcpy(req.dest_mac, qp->ah.dmac, 6);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU)
		req.path_mtu = qp->path_mtu;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TIMEOUT)
		req.timeout = qp->timeout;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RETRY_CNT)
		req.retry_cnt = qp->retry_cnt;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RNR_RETRY)
		req.rnr_retry = qp->rnr_retry;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MIN_RNR_TIMER)
		req.min_rnr_timer = qp->min_rnr_timer;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RQ_PSN)
		req.rq_psn = cpu_to_le32(qp->rq.psn);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_SQ_PSN)
		req.sq_psn = cpu_to_le32(qp->sq.psn);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MAX_RD_ATOMIC)
		req.max_rd_atomic =
			ORD_LIMIT_TO_ORRQ_SLOTS(qp->max_rd_atomic);

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MAX_DEST_RD_ATOMIC)
		req.max_dest_rd_atomic =
			IRD_LIMIT_TO_IRRQ_SLOTS(qp->max_dest_rd_atomic);

	req.sq_size = cpu_to_le32(qp->sq.hwq.max_elements);
	req.rq_size = cpu_to_le32(qp->rq.hwq.max_elements);
	req.sq_sge = cpu_to_le16(qp->sq.max_sge);
	req.rq_sge = cpu_to_le16(qp->rq.max_sge);
	req.max_inline_data = cpu_to_le32(qp->max_inline_data);
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DEST_QP_ID)
		req.dest_qp_id = cpu_to_le32(qp->dest_qpn);

	req.vlan_pcp_vlan_dei_vlan_id = cpu_to_le16(qp->vlan_id);

	resp = (struct creq_modify_qp_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: MODIFY_QP send failed");
		return -EINVAL;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: MODIFY_QP timed out");
		return -ETIMEDOUT;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: MODIFY_QP failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		return -EINVAL;
	}
	qp->cur_qp_state = qp->state;
	return 0;
}

int bnxt_qplib_query_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_query_qp req;
	struct creq_query_qp_resp *resp;
	struct creq_query_qp_resp_sb *sb;
	u16 cmd_flags = 0;
	u32 temp32[4];
	int i;

	RCFW_CMD_PREP(req, QUERY_QP, cmd_flags);

	req.qp_cid = cpu_to_le32(qp->id);
	req.resp_size = sizeof(*sb) / BNXT_QPLIB_CMDQE_UNITS;
	resp = (struct creq_query_qp_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     (void **)&sb, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: QUERY_QP send failed");
		return -EINVAL;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: QUERY_QP timed out");
		return -ETIMEDOUT;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: QUERY_QP failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		return -EINVAL;
	}
	/* Extract the context from the side buffer */
	qp->state = sb->en_sqd_async_notify_state &
			CREQ_QUERY_QP_RESP_SB_STATE_MASK;
	qp->en_sqd_async_notify = sb->en_sqd_async_notify_state &
				  CREQ_QUERY_QP_RESP_SB_EN_SQD_ASYNC_NOTIFY ?
				  true : false;
	qp->access = sb->access;
	qp->pkey_index = le16_to_cpu(sb->pkey);
	qp->qkey = le32_to_cpu(sb->qkey);

	temp32[0] = le32_to_cpu(sb->dgid[0]);
	temp32[1] = le32_to_cpu(sb->dgid[1]);
	temp32[2] = le32_to_cpu(sb->dgid[2]);
	temp32[3] = le32_to_cpu(sb->dgid[3]);
	memcpy(qp->ah.dgid.data, temp32, sizeof(qp->ah.dgid.data));

	qp->ah.flow_label = le32_to_cpu(sb->flow_label);

	qp->ah.sgid_index = 0;
	for (i = 0; i < res->sgid_tbl.max; i++) {
		if (res->sgid_tbl.hw_id[i] == le16_to_cpu(sb->sgid_index)) {
			qp->ah.sgid_index = i;
			break;
		}
	}
	if (i == res->sgid_tbl.max)
		dev_warn(&res->pdev->dev, "QPLIB: SGID not found??");

	qp->ah.hop_limit = sb->hop_limit;
	qp->ah.traffic_class = sb->traffic_class;
	memcpy(qp->ah.dmac, sb->dest_mac, 6);
	qp->ah.vlan_id = (le16_to_cpu(sb->path_mtu_dest_vlan_id) &
				CREQ_QUERY_QP_RESP_SB_VLAN_ID_MASK) >>
				CREQ_QUERY_QP_RESP_SB_VLAN_ID_SFT;
	qp->path_mtu = (le16_to_cpu(sb->path_mtu_dest_vlan_id) &
				    CREQ_QUERY_QP_RESP_SB_PATH_MTU_MASK) >>
				    CREQ_QUERY_QP_RESP_SB_PATH_MTU_SFT;
	qp->timeout = sb->timeout;
	qp->retry_cnt = sb->retry_cnt;
	qp->rnr_retry = sb->rnr_retry;
	qp->min_rnr_timer = sb->min_rnr_timer;
	qp->rq.psn = le32_to_cpu(sb->rq_psn);
	qp->max_rd_atomic = ORRQ_SLOTS_TO_ORD_LIMIT(sb->max_rd_atomic);
	qp->sq.psn = le32_to_cpu(sb->sq_psn);
	qp->max_dest_rd_atomic =
			IRRQ_SLOTS_TO_IRD_LIMIT(sb->max_dest_rd_atomic);
	qp->sq.max_wqe = qp->sq.hwq.max_elements;
	qp->rq.max_wqe = qp->rq.hwq.max_elements;
	qp->sq.max_sge = le16_to_cpu(sb->sq_sge);
	qp->rq.max_sge = le16_to_cpu(sb->rq_sge);
	qp->max_inline_data = le32_to_cpu(sb->max_inline_data);
	qp->dest_qpn = le32_to_cpu(sb->dest_qp_id);
	memcpy(qp->smac, sb->src_mac, 6);
	qp->vlan_id = le16_to_cpu(sb->vlan_pcp_vlan_dei_vlan_id);
	return 0;
}

static void __clean_cq(struct bnxt_qplib_cq *cq, u64 qp)
{
	struct bnxt_qplib_hwq *cq_hwq = &cq->hwq;
	struct cq_base *hw_cqe, **hw_cqe_ptr;
	int i;

	for (i = 0; i < cq_hwq->max_elements; i++) {
		hw_cqe_ptr = (struct cq_base **)cq_hwq->pbl_ptr;
		hw_cqe = &hw_cqe_ptr[CQE_PG(i)][CQE_IDX(i)];
		if (!CQE_CMP_VALID(hw_cqe, i, cq_hwq->max_elements))
			continue;
		switch (hw_cqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK) {
		case CQ_BASE_CQE_TYPE_REQ:
		case CQ_BASE_CQE_TYPE_TERMINAL:
		{
			struct cq_req *cqe = (struct cq_req *)hw_cqe;

			if (qp == le64_to_cpu(cqe->qp_handle))
				cqe->qp_handle = 0;
			break;
		}
		case CQ_BASE_CQE_TYPE_RES_RC:
		case CQ_BASE_CQE_TYPE_RES_UD:
		case CQ_BASE_CQE_TYPE_RES_RAWETH_QP1:
		{
			struct cq_res_rc *cqe = (struct cq_res_rc *)hw_cqe;

			if (qp == le64_to_cpu(cqe->qp_handle))
				cqe->qp_handle = 0;
			break;
		}
		default:
			break;
		}
	}
}

int bnxt_qplib_destroy_qp(struct bnxt_qplib_res *res,
			  struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_destroy_qp req;
	struct creq_destroy_qp_resp *resp;
	unsigned long flags;
	u16 cmd_flags = 0;

	RCFW_CMD_PREP(req, DESTROY_QP, cmd_flags);

	req.qp_cid = cpu_to_le32(qp->id);
	resp = (struct creq_destroy_qp_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_QP send failed");
		return -EINVAL;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_QP timed out");
		return -ETIMEDOUT;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_QP failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		return -EINVAL;
	}

	/* Must walk the associated CQs to nullified the QP ptr */
	spin_lock_irqsave(&qp->scq->hwq.lock, flags);

	__clean_cq(qp->scq, (u64)(unsigned long)qp);

	if (qp->rcq && qp->rcq != qp->scq) {
		spin_lock(&qp->rcq->hwq.lock);
		__clean_cq(qp->rcq, (u64)(unsigned long)qp);
		spin_unlock(&qp->rcq->hwq.lock);
	}

	spin_unlock_irqrestore(&qp->scq->hwq.lock, flags);

	bnxt_qplib_free_qp_hdr_buf(res, qp);
	bnxt_qplib_free_hwq(res->pdev, &qp->sq.hwq);
	kfree(qp->sq.swq);

	bnxt_qplib_free_hwq(res->pdev, &qp->rq.hwq);
	kfree(qp->rq.swq);

	if (qp->irrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->irrq);
	if (qp->orrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->orrq);

	return 0;
}

void *bnxt_qplib_get_qp1_sq_buf(struct bnxt_qplib_qp *qp,
				struct bnxt_qplib_sge *sge)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	u32 sw_prod;

	memset(sge, 0, sizeof(*sge));

	if (qp->sq_hdr_buf) {
		sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
		sge->addr = (dma_addr_t)(qp->sq_hdr_buf_map +
					 sw_prod * qp->sq_hdr_buf_size);
		sge->lkey = 0xFFFFFFFF;
		sge->size = qp->sq_hdr_buf_size;
		return qp->sq_hdr_buf + sw_prod * sge->size;
	}
	return NULL;
}

u32 bnxt_qplib_get_rq_prod_index(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;

	return HWQ_CMP(rq->hwq.prod, &rq->hwq);
}

dma_addr_t bnxt_qplib_get_qp_buf_from_index(struct bnxt_qplib_qp *qp, u32 index)
{
	return (qp->rq_hdr_buf_map + index * qp->rq_hdr_buf_size);
}

void *bnxt_qplib_get_qp1_rq_buf(struct bnxt_qplib_qp *qp,
				struct bnxt_qplib_sge *sge)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	u32 sw_prod;

	memset(sge, 0, sizeof(*sge));

	if (qp->rq_hdr_buf) {
		sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
		sge->addr = (dma_addr_t)(qp->rq_hdr_buf_map +
					 sw_prod * qp->rq_hdr_buf_size);
		sge->lkey = 0xFFFFFFFF;
		sge->size = qp->rq_hdr_buf_size;
		return qp->rq_hdr_buf + sw_prod * sge->size;
	}
	return NULL;
}

void bnxt_qplib_post_send_db(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_prod;

	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);

	db_msg.index = cpu_to_le32((sw_prod << DBR_DBR_INDEX_SFT) &
				   DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((qp->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_SQ);
	/* Flush all the WQE writes to HW */
	wmb();
	__iowrite64_copy(qp->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_post_send(struct bnxt_qplib_qp *qp,
			 struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_swq *swq;
	struct sq_send *hw_sq_send_hdr, **hw_sq_send_ptr;
	struct sq_sge *hw_sge;
	u32 sw_prod;
	u8 wqe_size16;
	int i, rc = 0, data_len = 0, pkt_num = 0;
	__le32 temp32;

	if (qp->state != CMDQ_MODIFY_QP_NEW_STATE_RTS) {
		rc = -EINVAL;
		goto done;
	}
	if (HWQ_CMP((sq->hwq.prod + 1), &sq->hwq) ==
	    HWQ_CMP(sq->hwq.cons, &sq->hwq)) {
		rc = -ENOMEM;
		goto done;
	}
	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
	swq = &sq->swq[sw_prod];
	swq->wr_id = wqe->wr_id;
	swq->type = wqe->type;
	swq->flags = wqe->flags;
	if (qp->sig_type)
		swq->flags |= SQ_SEND_FLAGS_SIGNAL_COMP;
	swq->start_psn = sq->psn & BTH_PSN_MASK;

	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	hw_sq_send_hdr = &hw_sq_send_ptr[get_sqe_pg(sw_prod)]
					[get_sqe_idx(sw_prod)];

	memset(hw_sq_send_hdr, 0, BNXT_QPLIB_MAX_SQE_ENTRY_SIZE);

	if (wqe->flags & BNXT_QPLIB_SWQE_FLAGS_INLINE) {
		/* Copy the inline data */
		if (wqe->inline_len > BNXT_QPLIB_SWQE_MAX_INLINE_LENGTH) {
			dev_warn(&sq->hwq.pdev->dev,
				 "QPLIB: Inline data length > 96 detected");
			data_len = BNXT_QPLIB_SWQE_MAX_INLINE_LENGTH;
		} else {
			data_len = wqe->inline_len;
		}
		memcpy(hw_sq_send_hdr->data, wqe->inline_data, data_len);
		wqe_size16 = (data_len + 15) >> 4;
	} else {
		for (i = 0, hw_sge = (struct sq_sge *)hw_sq_send_hdr->data;
		     i < wqe->num_sge; i++, hw_sge++) {
			hw_sge->va_or_pa = cpu_to_le64(wqe->sg_list[i].addr);
			hw_sge->l_key = cpu_to_le32(wqe->sg_list[i].lkey);
			hw_sge->size = cpu_to_le32(wqe->sg_list[i].size);
			data_len += wqe->sg_list[i].size;
		}
		/* Each SGE entry = 1 WQE size16 */
		wqe_size16 = wqe->num_sge;
	}

	/* Specifics */
	switch (wqe->type) {
	case BNXT_QPLIB_SWQE_TYPE_SEND:
		if (qp->type == CMDQ_CREATE_QP1_TYPE_GSI) {
			/* Assemble info for Raw Ethertype QPs */
			struct sq_send_raweth_qp1 *sqe =
				(struct sq_send_raweth_qp1 *)hw_sq_send_hdr;

			sqe->wqe_type = wqe->type;
			sqe->flags = wqe->flags;
			sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
			sqe->cfa_action = cpu_to_le16(wqe->rawqp1.cfa_action);
			sqe->lflags = cpu_to_le16(wqe->rawqp1.lflags);
			sqe->length = cpu_to_le32(data_len);
			sqe->cfa_meta = cpu_to_le32((wqe->rawqp1.cfa_meta &
				SQ_SEND_RAWETH_QP1_CFA_META_VLAN_VID_MASK) <<
				SQ_SEND_RAWETH_QP1_CFA_META_VLAN_VID_SFT);

			break;
		}
		/* else, just fall thru */
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_IMM:
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_INV:
	{
		struct sq_send *sqe = (struct sq_send *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
		sqe->inv_key_or_imm_data = cpu_to_le32(
						wqe->send.inv_key);
		if (qp->type == CMDQ_CREATE_QP_TYPE_UD) {
			sqe->q_key = cpu_to_le32(wqe->send.q_key);
			sqe->dst_qp = cpu_to_le32(
					wqe->send.dst_qp & SQ_SEND_DST_QP_MASK);
			sqe->length = cpu_to_le32(data_len);
			sqe->avid = cpu_to_le32(wqe->send.avid &
						SQ_SEND_AVID_MASK);
			sq->psn = (sq->psn + 1) & BTH_PSN_MASK;
		} else {
			sqe->length = cpu_to_le32(data_len);
			sqe->dst_qp = 0;
			sqe->avid = 0;
			if (qp->mtu)
				pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
			if (!pkt_num)
				pkt_num = 1;
			sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;
		}
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE:
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE_WITH_IMM:
	case BNXT_QPLIB_SWQE_TYPE_RDMA_READ:
	{
		struct sq_rdma *sqe = (struct sq_rdma *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
		sqe->imm_data = cpu_to_le32(wqe->rdma.inv_key);
		sqe->length = cpu_to_le32((u32)data_len);
		sqe->remote_va = cpu_to_le64(wqe->rdma.remote_va);
		sqe->remote_key = cpu_to_le32(wqe->rdma.r_key);
		if (qp->mtu)
			pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
		if (!pkt_num)
			pkt_num = 1;
		sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_CMP_AND_SWP:
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_FETCH_AND_ADD:
	{
		struct sq_atomic *sqe = (struct sq_atomic *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->remote_key = cpu_to_le32(wqe->atomic.r_key);
		sqe->remote_va = cpu_to_le64(wqe->atomic.remote_va);
		sqe->swap_data = cpu_to_le64(wqe->atomic.swap_data);
		sqe->cmp_data = cpu_to_le64(wqe->atomic.cmp_data);
		if (qp->mtu)
			pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
		if (!pkt_num)
			pkt_num = 1;
		sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_LOCAL_INV:
	{
		struct sq_localinvalidate *sqe =
				(struct sq_localinvalidate *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->inv_l_key = cpu_to_le32(wqe->local_inv.inv_l_key);

		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_FAST_REG_MR:
	{
		struct sq_fr_pmr *sqe = (struct sq_fr_pmr *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->access_cntl = wqe->frmr.access_cntl |
				   SQ_FR_PMR_ACCESS_CNTL_LOCAL_WRITE;
		sqe->zero_based_page_size_log =
			(wqe->frmr.pg_sz_log & SQ_FR_PMR_PAGE_SIZE_LOG_MASK) <<
			SQ_FR_PMR_PAGE_SIZE_LOG_SFT |
			(wqe->frmr.zero_based ? SQ_FR_PMR_ZERO_BASED : 0);
		sqe->l_key = cpu_to_le32(wqe->frmr.l_key);
		temp32 = cpu_to_le32(wqe->frmr.length);
		memcpy(sqe->length, &temp32, sizeof(wqe->frmr.length));
		sqe->numlevels_pbl_page_size_log =
			((wqe->frmr.pbl_pg_sz_log <<
					SQ_FR_PMR_PBL_PAGE_SIZE_LOG_SFT) &
					SQ_FR_PMR_PBL_PAGE_SIZE_LOG_MASK) |
			((wqe->frmr.levels << SQ_FR_PMR_NUMLEVELS_SFT) &
					SQ_FR_PMR_NUMLEVELS_MASK);

		for (i = 0; i < wqe->frmr.page_list_len; i++)
			wqe->frmr.pbl_ptr[i] = cpu_to_le64(
						wqe->frmr.page_list[i] |
						PTU_PTE_VALID);
		sqe->pblptr = cpu_to_le64(wqe->frmr.pbl_dma_ptr);
		sqe->va = cpu_to_le64(wqe->frmr.va);

		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_BIND_MW:
	{
		struct sq_bind *sqe = (struct sq_bind *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->access_cntl = wqe->bind.access_cntl;
		sqe->mw_type_zero_based = wqe->bind.mw_type |
			(wqe->bind.zero_based ? SQ_BIND_ZERO_BASED : 0);
		sqe->parent_l_key = cpu_to_le32(wqe->bind.parent_l_key);
		sqe->l_key = cpu_to_le32(wqe->bind.r_key);
		sqe->va = cpu_to_le64(wqe->bind.va);
		temp32 = cpu_to_le32(wqe->bind.length);
		memcpy(&sqe->length, &temp32, sizeof(wqe->bind.length));
		break;
	}
	default:
		/* Bad wqe, return error */
		rc = -EINVAL;
		goto done;
	}
	swq->next_psn = sq->psn & BTH_PSN_MASK;
	if (swq->psn_search) {
		swq->psn_search->opcode_start_psn = cpu_to_le32(
			((swq->start_psn << SQ_PSN_SEARCH_START_PSN_SFT) &
			 SQ_PSN_SEARCH_START_PSN_MASK) |
			((wqe->type << SQ_PSN_SEARCH_OPCODE_SFT) &
			 SQ_PSN_SEARCH_OPCODE_MASK));
		swq->psn_search->flags_next_psn = cpu_to_le32(
			((swq->next_psn << SQ_PSN_SEARCH_NEXT_PSN_SFT) &
			 SQ_PSN_SEARCH_NEXT_PSN_MASK));
	}

	sq->hwq.prod++;
done:
	return rc;
}

void bnxt_qplib_post_recv_db(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_prod;

	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	db_msg.index = cpu_to_le32((sw_prod << DBR_DBR_INDEX_SFT) &
				   DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((qp->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_RQ);

	/* Flush the writes to HW Rx WQE before the ringing Rx DB */
	wmb();
	__iowrite64_copy(qp->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_post_recv(struct bnxt_qplib_qp *qp,
			 struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct rq_wqe *rqe, **rqe_ptr;
	struct sq_sge *hw_sge;
	u32 sw_prod;
	int i, rc = 0;

	if (qp->state == CMDQ_MODIFY_QP_NEW_STATE_ERR) {
		dev_err(&rq->hwq.pdev->dev,
			"QPLIB: FP: QP (0x%x) is in the 0x%x state",
			qp->id, qp->state);
		rc = -EINVAL;
		goto done;
	}
	if (HWQ_CMP((rq->hwq.prod + 1), &rq->hwq) ==
	    HWQ_CMP(rq->hwq.cons, &rq->hwq)) {
		dev_err(&rq->hwq.pdev->dev,
			"QPLIB: FP: QP (0x%x) RQ is full!", qp->id);
		rc = -EINVAL;
		goto done;
	}
	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	rq->swq[sw_prod].wr_id = wqe->wr_id;

	rqe_ptr = (struct rq_wqe **)rq->hwq.pbl_ptr;
	rqe = &rqe_ptr[RQE_PG(sw_prod)][RQE_IDX(sw_prod)];

	memset(rqe, 0, BNXT_QPLIB_MAX_RQE_ENTRY_SIZE);

	/* Calculate wqe_size16 and data_len */
	for (i = 0, hw_sge = (struct sq_sge *)rqe->data;
	     i < wqe->num_sge; i++, hw_sge++) {
		hw_sge->va_or_pa = cpu_to_le64(wqe->sg_list[i].addr);
		hw_sge->l_key = cpu_to_le32(wqe->sg_list[i].lkey);
		hw_sge->size = cpu_to_le32(wqe->sg_list[i].size);
	}
	rqe->wqe_type = wqe->type;
	rqe->flags = wqe->flags;
	rqe->wqe_size = wqe->num_sge +
			((offsetof(typeof(*rqe), data) + 15) >> 4);

	/* Supply the rqe->wr_id index to the wr_id_tbl for now */
	rqe->wr_id[0] = cpu_to_le32(sw_prod);

	rq->hwq.prod++;
done:
	return rc;
}

/* CQ */

/* Spinlock must be held */
static void bnxt_qplib_arm_cq_enable(struct bnxt_qplib_cq *cq)
{
	struct dbr_dbr db_msg = { 0 };

	db_msg.type_xid =
		cpu_to_le32(((cq->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_CQ_ARMENA);
	/* Flush memory writes before enabling the CQ */
	wmb();
	__iowrite64_copy(cq->dbr_base, &db_msg, sizeof(db_msg) / sizeof(u64));
}

static void bnxt_qplib_arm_cq(struct bnxt_qplib_cq *cq, u32 arm_type)
{
	struct bnxt_qplib_hwq *cq_hwq = &cq->hwq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_cons;

	/* Ring DB */
	sw_cons = HWQ_CMP(cq_hwq->cons, cq_hwq);
	db_msg.index = cpu_to_le32((sw_cons << DBR_DBR_INDEX_SFT) &
				    DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((cq->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    arm_type);
	/* flush memory writes before arming the CQ */
	wmb();
	__iowrite64_copy(cq->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_create_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_create_cq req;
	struct creq_create_cq_resp *resp;
	struct bnxt_qplib_pbl *pbl;
	u16 cmd_flags = 0;
	int rc;

	cq->hwq.max_elements = cq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &cq->hwq, cq->sghead,
				       cq->nmap, &cq->hwq.max_elements,
				       BNXT_QPLIB_MAX_CQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	RCFW_CMD_PREP(req, CREATE_CQ, cmd_flags);

	if (!cq->dpi) {
		dev_err(&rcfw->pdev->dev,
			"QPLIB: FP: CREATE_CQ failed due to NULL DPI");
		return -EINVAL;
	}
	req.dpi = cpu_to_le32(cq->dpi->dpi);
	req.cq_handle = cpu_to_le64(cq->cq_handle);

	req.cq_size = cpu_to_le32(cq->hwq.max_elements);
	pbl = &cq->hwq.pbl[PBL_LVL_0];
	req.pg_size_lvl = cpu_to_le32(
	    ((cq->hwq.level & CMDQ_CREATE_CQ_LVL_MASK) <<
						CMDQ_CREATE_CQ_LVL_SFT) |
	    (pbl->pg_size == ROCE_PG_SIZE_4K ? CMDQ_CREATE_CQ_PG_SIZE_PG_4K :
	     pbl->pg_size == ROCE_PG_SIZE_8K ? CMDQ_CREATE_CQ_PG_SIZE_PG_8K :
	     pbl->pg_size == ROCE_PG_SIZE_64K ? CMDQ_CREATE_CQ_PG_SIZE_PG_64K :
	     pbl->pg_size == ROCE_PG_SIZE_2M ? CMDQ_CREATE_CQ_PG_SIZE_PG_2M :
	     pbl->pg_size == ROCE_PG_SIZE_8M ? CMDQ_CREATE_CQ_PG_SIZE_PG_8M :
	     pbl->pg_size == ROCE_PG_SIZE_1G ? CMDQ_CREATE_CQ_PG_SIZE_PG_1G :
	     CMDQ_CREATE_CQ_PG_SIZE_PG_4K));

	req.pbl = cpu_to_le64(pbl->pg_map_arr[0]);

	req.cq_fco_cnq_id = cpu_to_le32(
			(cq->cnq_hw_ring_id & CMDQ_CREATE_CQ_CNQ_ID_MASK) <<
			 CMDQ_CREATE_CQ_CNQ_ID_SFT);

	resp = (struct creq_create_cq_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_CQ send failed");
		return -EINVAL;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_CQ timed out");
		rc = -ETIMEDOUT;
		goto fail;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: CREATE_CQ failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		rc = -EINVAL;
		goto fail;
	}
	cq->id = le32_to_cpu(resp->xid);
	cq->dbr_base = res->dpi_tbl.dbr_bar_reg_iomem;
	cq->period = BNXT_QPLIB_QUEUE_START_PERIOD;
	init_waitqueue_head(&cq->waitq);

	bnxt_qplib_arm_cq_enable(cq);
	return 0;

fail:
	bnxt_qplib_free_hwq(res->pdev, &cq->hwq);
exit:
	return rc;
}

int bnxt_qplib_destroy_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_destroy_cq req;
	struct creq_destroy_cq_resp *resp;
	u16 cmd_flags = 0;

	RCFW_CMD_PREP(req, DESTROY_CQ, cmd_flags);

	req.cq_cid = cpu_to_le32(cq->id);
	resp = (struct creq_destroy_cq_resp *)
			bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
						     NULL, 0);
	if (!resp) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_CQ send failed");
		return -EINVAL;
	}
	if (!bnxt_qplib_rcfw_wait_for_resp(rcfw, le16_to_cpu(req.cookie))) {
		/* Cmd timed out */
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_CQ timed out");
		return -ETIMEDOUT;
	}
	if (resp->status ||
	    le16_to_cpu(resp->cookie) != le16_to_cpu(req.cookie)) {
		dev_err(&rcfw->pdev->dev, "QPLIB: FP: DESTROY_CQ failed ");
		dev_err(&rcfw->pdev->dev,
			"QPLIB: with status 0x%x cmdq 0x%x resp 0x%x",
			resp->status, le16_to_cpu(req.cookie),
			le16_to_cpu(resp->cookie));
		return -EINVAL;
	}
	bnxt_qplib_free_hwq(res->pdev, &cq->hwq);
	return 0;
}

static int __flush_sq(struct bnxt_qplib_q *sq, struct bnxt_qplib_qp *qp,
		      struct bnxt_qplib_cqe **pcqe, int *budget)
{
	u32 sw_prod, sw_cons;
	struct bnxt_qplib_cqe *cqe;
	int rc = 0;

	/* Now complete all outstanding SQEs with FLUSHED_ERR */
	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_cons == sw_prod) {
			sq->flush_in_progress = false;
			break;
		}
		memset(cqe, 0, sizeof(*cqe));
		cqe->status = CQ_REQ_STATUS_WORK_REQUEST_FLUSHED_ERR;
		cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
		cqe->qp_handle = (u64)(unsigned long)qp;
		cqe->wr_id = sq->swq[sw_cons].wr_id;
		cqe->src_qp = qp->id;
		cqe->type = sq->swq[sw_cons].type;
		cqe++;
		(*budget)--;
		sq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!(*budget) && HWQ_CMP(sq->hwq.cons, &sq->hwq) != sw_prod)
		/* Out of budget */
		rc = -EAGAIN;

	return rc;
}

static int __flush_rq(struct bnxt_qplib_q *rq, struct bnxt_qplib_qp *qp,
		      int opcode, struct bnxt_qplib_cqe **pcqe, int *budget)
{
	struct bnxt_qplib_cqe *cqe;
	u32 sw_prod, sw_cons;
	int rc = 0;

	/* Flush the rest of the RQ */
	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(rq->hwq.cons, &rq->hwq);
		if (sw_cons == sw_prod)
			break;
		memset(cqe, 0, sizeof(*cqe));
		cqe->status =
		    CQ_RES_RC_STATUS_WORK_REQUEST_FLUSHED_ERR;
		cqe->opcode = opcode;
		cqe->qp_handle = (unsigned long)qp;
		cqe->wr_id = rq->swq[sw_cons].wr_id;
		cqe++;
		(*budget)--;
		rq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!*budget && HWQ_CMP(rq->hwq.cons, &rq->hwq) != sw_prod)
		/* Out of budget */
		rc = -EAGAIN;

	return rc;
}

static int bnxt_qplib_cq_process_req(struct bnxt_qplib_cq *cq,
				     struct cq_req *hwcqe,
				     struct bnxt_qplib_cqe **pcqe, int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *sq;
	struct bnxt_qplib_cqe *cqe;
	u32 sw_cons, cqe_cons;
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)((unsigned long)
				      le64_to_cpu(hwcqe->qp_handle));
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: Process Req qp is NULL");
		return -EINVAL;
	}
	sq = &qp->sq;

	cqe_cons = HWQ_CMP(le16_to_cpu(hwcqe->sq_cons_idx), &sq->hwq);
	if (cqe_cons > sq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process req reported ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: sq_cons_idx 0x%x which exceeded max 0x%x",
			cqe_cons, sq->hwq.max_elements);
		return -EINVAL;
	}
	/* If we were in the middle of flushing the SQ, continue */
	if (sq->flush_in_progress)
		goto flush;

	/* Require to walk the sq's swq to fabricate CQEs for all previously
	 * signaled SWQEs due to CQE aggregation from the current sq cons
	 * to the cqe_cons
	 */
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_cons == cqe_cons)
			break;
		memset(cqe, 0, sizeof(*cqe));
		cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
		cqe->qp_handle = (u64)(unsigned long)qp;
		cqe->src_qp = qp->id;
		cqe->wr_id = sq->swq[sw_cons].wr_id;
		cqe->type = sq->swq[sw_cons].type;

		/* For the last CQE, check for status.  For errors, regardless
		 * of the request being signaled or not, it must complete with
		 * the hwcqe error status
		 */
		if (HWQ_CMP((sw_cons + 1), &sq->hwq) == cqe_cons &&
		    hwcqe->status != CQ_REQ_STATUS_OK) {
			cqe->status = hwcqe->status;
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Processed Req ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id[%d] = 0x%llx with status 0x%x",
				sw_cons, cqe->wr_id, cqe->status);
			cqe++;
			(*budget)--;
			sq->flush_in_progress = true;
			/* Must block new posting of SQ and RQ */
			qp->state = CMDQ_MODIFY_QP_NEW_STATE_ERR;
		} else {
			if (sq->swq[sw_cons].flags &
			    SQ_SEND_FLAGS_SIGNAL_COMP) {
				cqe->status = CQ_REQ_STATUS_OK;
				cqe++;
				(*budget)--;
			}
		}
		sq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!*budget && HWQ_CMP(sq->hwq.cons, &sq->hwq) != cqe_cons) {
		/* Out of budget */
		rc = -EAGAIN;
		goto done;
	}
	if (!sq->flush_in_progress)
		goto done;
flush:
	/* Require to walk the sq's swq to fabricate CQEs for all
	 * previously posted SWQEs due to the error CQE received
	 */
	rc = __flush_sq(sq, qp, pcqe, budget);
	if (!rc)
		sq->flush_in_progress = false;
done:
	return rc;
}

static int bnxt_qplib_cq_process_res_rc(struct bnxt_qplib_cq *cq,
					struct cq_res_rc *hwcqe,
					struct bnxt_qplib_cqe **pcqe,
					int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_cqe *cqe;
	u32 wr_id_idx;
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)((unsigned long)
				      le64_to_cpu(hwcqe->qp_handle));
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: process_cq RC qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->length = le32_to_cpu(hwcqe->length);
	cqe->invrkey = le32_to_cpu(hwcqe->imm_data_or_inv_r_key);
	cqe->mr_handle = le64_to_cpu(hwcqe->mr_handle);
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->status = hwcqe->status;
	cqe->qp_handle = (u64)(unsigned long)qp;

	wr_id_idx = le32_to_cpu(hwcqe->srq_or_rq_wr_id) &
				CQ_RES_RC_SRQ_OR_RQ_WR_ID_MASK;
	rq = &qp->rq;
	if (wr_id_idx > rq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: FP: CQ Process RC ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: wr_id idx 0x%x exceeded RQ max 0x%x",
			wr_id_idx, rq->hwq.max_elements);
		return -EINVAL;
	}
	if (rq->flush_in_progress)
		goto flush_rq;

	cqe->wr_id = rq->swq[wr_id_idx].wr_id;
	cqe++;
	(*budget)--;
	rq->hwq.cons++;
	*pcqe = cqe;

	if (hwcqe->status != CQ_RES_RC_STATUS_OK) {
		rq->flush_in_progress = true;
flush_rq:
		rc = __flush_rq(rq, qp, CQ_BASE_CQE_TYPE_RES_RC, pcqe, budget);
		if (!rc)
			rq->flush_in_progress = false;
	}
	return rc;
}

static int bnxt_qplib_cq_process_res_ud(struct bnxt_qplib_cq *cq,
					struct cq_res_ud *hwcqe,
					struct bnxt_qplib_cqe **pcqe,
					int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_cqe *cqe;
	u32 wr_id_idx;
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)((unsigned long)
				      le64_to_cpu(hwcqe->qp_handle));
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: process_cq UD qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->length = le32_to_cpu(hwcqe->length);
	cqe->invrkey = le32_to_cpu(hwcqe->imm_data);
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->status = hwcqe->status;
	cqe->qp_handle = (u64)(unsigned long)qp;
	memcpy(cqe->smac, hwcqe->src_mac, 6);
	wr_id_idx = le32_to_cpu(hwcqe->src_qp_high_srq_or_rq_wr_id)
				& CQ_RES_UD_SRQ_OR_RQ_WR_ID_MASK;
	cqe->src_qp = le16_to_cpu(hwcqe->src_qp_low) |
				  ((le32_to_cpu(
				  hwcqe->src_qp_high_srq_or_rq_wr_id) &
				 CQ_RES_UD_SRC_QP_HIGH_MASK) >> 8);

	rq = &qp->rq;
	if (wr_id_idx > rq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: FP: CQ Process UD ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: wr_id idx %#x exceeded RQ max %#x",
			wr_id_idx, rq->hwq.max_elements);
		return -EINVAL;
	}
	if (rq->flush_in_progress)
		goto flush_rq;

	cqe->wr_id = rq->swq[wr_id_idx].wr_id;
	cqe++;
	(*budget)--;
	rq->hwq.cons++;
	*pcqe = cqe;

	if (hwcqe->status != CQ_RES_RC_STATUS_OK) {
		rq->flush_in_progress = true;
flush_rq:
		rc = __flush_rq(rq, qp, CQ_BASE_CQE_TYPE_RES_UD, pcqe, budget);
		if (!rc)
			rq->flush_in_progress = false;
	}
	return rc;
}

static int bnxt_qplib_cq_process_res_raweth_qp1(struct bnxt_qplib_cq *cq,
						struct cq_res_raweth_qp1 *hwcqe,
						struct bnxt_qplib_cqe **pcqe,
						int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_cqe *cqe;
	u32 wr_id_idx;
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)((unsigned long)
				      le64_to_cpu(hwcqe->qp_handle));
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: process_cq Raw/QP1 qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->qp_handle = (u64)(unsigned long)qp;

	wr_id_idx =
		le32_to_cpu(hwcqe->raweth_qp1_payload_offset_srq_or_rq_wr_id)
				& CQ_RES_RAWETH_QP1_SRQ_OR_RQ_WR_ID_MASK;
	cqe->src_qp = qp->id;
	if (qp->id == 1 && !cqe->length) {
		/* Add workaround for the length misdetection */
		cqe->length = 296;
	} else {
		cqe->length = le16_to_cpu(hwcqe->length);
	}
	cqe->pkey_index = qp->pkey_index;
	memcpy(cqe->smac, qp->smac, 6);

	cqe->raweth_qp1_flags = le16_to_cpu(hwcqe->raweth_qp1_flags);
	cqe->raweth_qp1_flags2 = le32_to_cpu(hwcqe->raweth_qp1_flags2);

	rq = &qp->rq;
	if (wr_id_idx > rq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: FP: CQ Process Raw/QP1 RQ wr_id ");
		dev_err(&cq->hwq.pdev->dev, "QPLIB: ix 0x%x exceeded RQ max 0x%x",
			wr_id_idx, rq->hwq.max_elements);
		return -EINVAL;
	}
	if (rq->flush_in_progress)
		goto flush_rq;

	cqe->wr_id = rq->swq[wr_id_idx].wr_id;
	cqe++;
	(*budget)--;
	rq->hwq.cons++;
	*pcqe = cqe;

	if (hwcqe->status != CQ_RES_RC_STATUS_OK) {
		rq->flush_in_progress = true;
flush_rq:
		rc = __flush_rq(rq, qp, CQ_BASE_CQE_TYPE_RES_RAWETH_QP1, pcqe,
				budget);
		if (!rc)
			rq->flush_in_progress = false;
	}
	return rc;
}

static int bnxt_qplib_cq_process_terminal(struct bnxt_qplib_cq *cq,
					  struct cq_terminal *hwcqe,
					  struct bnxt_qplib_cqe **pcqe,
					  int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *sq, *rq;
	struct bnxt_qplib_cqe *cqe;
	u32 sw_cons = 0, cqe_cons;
	int rc = 0;
	u8 opcode = 0;

	/* Check the Status */
	if (hwcqe->status != CQ_TERMINAL_STATUS_OK)
		dev_warn(&cq->hwq.pdev->dev,
			 "QPLIB: FP: CQ Process Terminal Error status = 0x%x",
			 hwcqe->status);

	qp = (struct bnxt_qplib_qp *)((unsigned long)
				      le64_to_cpu(hwcqe->qp_handle));
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process terminal qp is NULL");
		return -EINVAL;
	}
	/* Must block new posting of SQ and RQ */
	qp->state = CMDQ_MODIFY_QP_NEW_STATE_ERR;

	sq = &qp->sq;
	rq = &qp->rq;

	cqe_cons = le16_to_cpu(hwcqe->sq_cons_idx);
	if (cqe_cons == 0xFFFF)
		goto do_rq;

	if (cqe_cons > sq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process terminal reported ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: sq_cons_idx 0x%x which exceeded max 0x%x",
			cqe_cons, sq->hwq.max_elements);
		goto do_rq;
	}
	/* If we were in the middle of flushing, continue */
	if (sq->flush_in_progress)
		goto flush_sq;

	/* Terminal CQE can also include aggregated successful CQEs prior.
	 * So we must complete all CQEs from the current sq's cons to the
	 * cq_cons with status OK
	 */
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_cons == cqe_cons)
			break;
		if (sq->swq[sw_cons].flags & SQ_SEND_FLAGS_SIGNAL_COMP) {
			memset(cqe, 0, sizeof(*cqe));
			cqe->status = CQ_REQ_STATUS_OK;
			cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
			cqe->qp_handle = (u64)(unsigned long)qp;
			cqe->src_qp = qp->id;
			cqe->wr_id = sq->swq[sw_cons].wr_id;
			cqe->type = sq->swq[sw_cons].type;
			cqe++;
			(*budget)--;
		}
		sq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!(*budget) && sw_cons != cqe_cons) {
		/* Out of budget */
		rc = -EAGAIN;
		goto sq_done;
	}
	sq->flush_in_progress = true;
flush_sq:
	rc = __flush_sq(sq, qp, pcqe, budget);
	if (!rc)
		sq->flush_in_progress = false;
sq_done:
	if (rc)
		return rc;
do_rq:
	cqe_cons = le16_to_cpu(hwcqe->rq_cons_idx);
	if (cqe_cons == 0xFFFF) {
		goto done;
	} else if (cqe_cons > rq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed terminal ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: reported rq_cons_idx 0x%x exceeds max 0x%x",
			cqe_cons, rq->hwq.max_elements);
		goto done;
	}
	/* Terminal CQE requires all posted RQEs to complete with FLUSHED_ERR
	 * from the current rq->cons to the rq->prod regardless what the
	 * rq->cons the terminal CQE indicates
	 */
	rq->flush_in_progress = true;
	switch (qp->type) {
	case CMDQ_CREATE_QP1_TYPE_GSI:
		opcode = CQ_BASE_CQE_TYPE_RES_RAWETH_QP1;
		break;
	case CMDQ_CREATE_QP_TYPE_RC:
		opcode = CQ_BASE_CQE_TYPE_RES_RC;
		break;
	case CMDQ_CREATE_QP_TYPE_UD:
		opcode = CQ_BASE_CQE_TYPE_RES_UD;
		break;
	}

	rc = __flush_rq(rq, qp, opcode, pcqe, budget);
	if (!rc)
		rq->flush_in_progress = false;
done:
	return rc;
}

static int bnxt_qplib_cq_process_cutoff(struct bnxt_qplib_cq *cq,
					struct cq_cutoff *hwcqe)
{
	/* Check the Status */
	if (hwcqe->status != CQ_CUTOFF_STATUS_OK) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process Cutoff Error status = 0x%x",
			hwcqe->status);
		return -EINVAL;
	}
	clear_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags);
	wake_up_interruptible(&cq->waitq);

	return 0;
}

int bnxt_qplib_poll_cq(struct bnxt_qplib_cq *cq, struct bnxt_qplib_cqe *cqe,
		       int num_cqes)
{
	struct cq_base *hw_cqe, **hw_cqe_ptr;
	unsigned long flags;
	u32 sw_cons, raw_cons;
	int budget, rc = 0;

	spin_lock_irqsave(&cq->hwq.lock, flags);
	raw_cons = cq->hwq.cons;
	budget = num_cqes;

	while (budget) {
		sw_cons = HWQ_CMP(raw_cons, &cq->hwq);
		hw_cqe_ptr = (struct cq_base **)cq->hwq.pbl_ptr;
		hw_cqe = &hw_cqe_ptr[CQE_PG(sw_cons)][CQE_IDX(sw_cons)];

		/* Check for Valid bit */
		if (!CQE_CMP_VALID(hw_cqe, raw_cons, cq->hwq.max_elements))
			break;

		/* From the device's respective CQE format to qplib_wc*/
		switch (hw_cqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK) {
		case CQ_BASE_CQE_TYPE_REQ:
			rc = bnxt_qplib_cq_process_req(cq,
						       (struct cq_req *)hw_cqe,
						       &cqe, &budget);
			break;
		case CQ_BASE_CQE_TYPE_RES_RC:
			rc = bnxt_qplib_cq_process_res_rc(cq,
							  (struct cq_res_rc *)
							  hw_cqe, &cqe,
							  &budget);
			break;
		case CQ_BASE_CQE_TYPE_RES_UD:
			rc = bnxt_qplib_cq_process_res_ud
					(cq, (struct cq_res_ud *)hw_cqe, &cqe,
					 &budget);
			break;
		case CQ_BASE_CQE_TYPE_RES_RAWETH_QP1:
			rc = bnxt_qplib_cq_process_res_raweth_qp1
					(cq, (struct cq_res_raweth_qp1 *)
					 hw_cqe, &cqe, &budget);
			break;
		case CQ_BASE_CQE_TYPE_TERMINAL:
			rc = bnxt_qplib_cq_process_terminal
					(cq, (struct cq_terminal *)hw_cqe,
					 &cqe, &budget);
			break;
		case CQ_BASE_CQE_TYPE_CUT_OFF:
			bnxt_qplib_cq_process_cutoff
					(cq, (struct cq_cutoff *)hw_cqe);
			/* Done processing this CQ */
			goto exit;
		default:
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: process_cq unknown type 0x%lx",
				hw_cqe->cqe_type_toggle &
				CQ_BASE_CQE_TYPE_MASK);
			rc = -EINVAL;
			break;
		}
		if (rc < 0) {
			if (rc == -EAGAIN)
				break;
			/* Error while processing the CQE, just skip to the
			 * next one
			 */
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: process_cqe error rc = 0x%x", rc);
		}
		raw_cons++;
	}
	if (cq->hwq.cons != raw_cons) {
		cq->hwq.cons = raw_cons;
		bnxt_qplib_arm_cq(cq, DBR_DBR_TYPE_CQ);
	}
exit:
	spin_unlock_irqrestore(&cq->hwq.lock, flags);
	return num_cqes - budget;
}

void bnxt_qplib_req_notify_cq(struct bnxt_qplib_cq *cq, u32 arm_type)
{
	unsigned long flags;

	spin_lock_irqsave(&cq->hwq.lock, flags);
	if (arm_type)
		bnxt_qplib_arm_cq(cq, arm_type);

	spin_unlock_irqrestore(&cq->hwq.lock, flags);
}

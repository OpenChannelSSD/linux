/* SCTP kernel implementation
 * (C) Copyright IBM Corp. 2001, 2004
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001 Intel Corp.
 *
 * This file is part of the SCTP kernel implementation
 *
 * These functions manipulate sctp tsn mapping array.
 *
 * This SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This SCTP implementation is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <linux-sctp@vger.kernel.org>
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>

int sctp_stream_new(struct sctp_association *asoc, gfp_t gfp)
{
	struct sctp_stream *stream;
	int i;

	stream = kzalloc(sizeof(*stream), gfp);
	if (!stream)
		return -ENOMEM;

	stream->outcnt = asoc->c.sinit_num_ostreams;
	stream->out = kcalloc(stream->outcnt, sizeof(*stream->out), gfp);
	if (!stream->out) {
		kfree(stream);
		return -ENOMEM;
	}
	for (i = 0; i < stream->outcnt; i++)
		stream->out[i].state = SCTP_STREAM_OPEN;

	asoc->stream = stream;

	return 0;
}

int sctp_stream_init(struct sctp_association *asoc, gfp_t gfp)
{
	struct sctp_stream *stream = asoc->stream;
	int i;

	/* Initial stream->out size may be very big, so free it and alloc
	 * a new one with new outcnt to save memory.
	 */
	kfree(stream->out);
	stream->outcnt = asoc->c.sinit_num_ostreams;
	stream->out = kcalloc(stream->outcnt, sizeof(*stream->out), gfp);
	if (!stream->out)
		goto nomem;

	for (i = 0; i < stream->outcnt; i++)
		stream->out[i].state = SCTP_STREAM_OPEN;

	stream->incnt = asoc->c.sinit_max_instreams;
	stream->in = kcalloc(stream->incnt, sizeof(*stream->in), gfp);
	if (!stream->in) {
		kfree(stream->out);
		goto nomem;
	}

	return 0;

nomem:
	asoc->stream = NULL;
	kfree(stream);

	return -ENOMEM;
}

void sctp_stream_free(struct sctp_stream *stream)
{
	if (unlikely(!stream))
		return;

	kfree(stream->out);
	kfree(stream->in);
	kfree(stream);
}

void sctp_stream_clear(struct sctp_stream *stream)
{
	int i;

	for (i = 0; i < stream->outcnt; i++)
		stream->out[i].ssn = 0;

	for (i = 0; i < stream->incnt; i++)
		stream->in[i].ssn = 0;
}

static int sctp_send_reconf(struct sctp_association *asoc,
			    struct sctp_chunk *chunk)
{
	struct net *net = sock_net(asoc->base.sk);
	int retval = 0;

	retval = sctp_primitive_RECONF(net, asoc, chunk);
	if (retval)
		sctp_chunk_free(chunk);

	return retval;
}

int sctp_send_reset_streams(struct sctp_association *asoc,
			    struct sctp_reset_streams *params)
{
	struct sctp_stream *stream = asoc->stream;
	__u16 i, str_nums, *str_list;
	struct sctp_chunk *chunk;
	int retval = -EINVAL;
	bool out, in;

	if (!asoc->peer.reconf_capable ||
	    !(asoc->strreset_enable & SCTP_ENABLE_RESET_STREAM_REQ)) {
		retval = -ENOPROTOOPT;
		goto out;
	}

	if (asoc->strreset_outstanding) {
		retval = -EINPROGRESS;
		goto out;
	}

	out = params->srs_flags & SCTP_STREAM_RESET_OUTGOING;
	in  = params->srs_flags & SCTP_STREAM_RESET_INCOMING;
	if (!out && !in)
		goto out;

	str_nums = params->srs_number_streams;
	str_list = params->srs_stream_list;
	if (out && str_nums)
		for (i = 0; i < str_nums; i++)
			if (str_list[i] >= stream->outcnt)
				goto out;

	if (in && str_nums)
		for (i = 0; i < str_nums; i++)
			if (str_list[i] >= stream->incnt)
				goto out;

	for (i = 0; i < str_nums; i++)
		str_list[i] = htons(str_list[i]);

	chunk = sctp_make_strreset_req(asoc, str_nums, str_list, out, in);

	for (i = 0; i < str_nums; i++)
		str_list[i] = ntohs(str_list[i]);

	if (!chunk) {
		retval = -ENOMEM;
		goto out;
	}

	if (out) {
		if (str_nums)
			for (i = 0; i < str_nums; i++)
				stream->out[str_list[i]].state =
						       SCTP_STREAM_CLOSED;
		else
			for (i = 0; i < stream->outcnt; i++)
				stream->out[i].state = SCTP_STREAM_CLOSED;
	}

	asoc->strreset_chunk = chunk;
	sctp_chunk_hold(asoc->strreset_chunk);

	retval = sctp_send_reconf(asoc, chunk);
	if (retval) {
		sctp_chunk_put(asoc->strreset_chunk);
		asoc->strreset_chunk = NULL;
		if (!out)
			goto out;

		if (str_nums)
			for (i = 0; i < str_nums; i++)
				stream->out[str_list[i]].state =
						       SCTP_STREAM_OPEN;
		else
			for (i = 0; i < stream->outcnt; i++)
				stream->out[i].state = SCTP_STREAM_OPEN;

		goto out;
	}

	asoc->strreset_outstanding = out + in;

out:
	return retval;
}

int sctp_send_reset_assoc(struct sctp_association *asoc)
{
	struct sctp_chunk *chunk = NULL;
	int retval;
	__u16 i;

	if (!asoc->peer.reconf_capable ||
	    !(asoc->strreset_enable & SCTP_ENABLE_RESET_ASSOC_REQ))
		return -ENOPROTOOPT;

	if (asoc->strreset_outstanding)
		return -EINPROGRESS;

	chunk = sctp_make_strreset_tsnreq(asoc);
	if (!chunk)
		return -ENOMEM;

	/* Block further xmit of data until this request is completed */
	for (i = 0; i < asoc->stream->outcnt; i++)
		asoc->stream->out[i].state = SCTP_STREAM_CLOSED;

	asoc->strreset_chunk = chunk;
	sctp_chunk_hold(asoc->strreset_chunk);

	retval = sctp_send_reconf(asoc, chunk);
	if (retval) {
		sctp_chunk_put(asoc->strreset_chunk);
		asoc->strreset_chunk = NULL;

		for (i = 0; i < asoc->stream->outcnt; i++)
			asoc->stream->out[i].state = SCTP_STREAM_OPEN;

		return retval;
	}

	asoc->strreset_outstanding = 1;

	return 0;
}

int sctp_send_add_streams(struct sctp_association *asoc,
			  struct sctp_add_streams *params)
{
	struct sctp_stream *stream = asoc->stream;
	struct sctp_chunk *chunk = NULL;
	int retval = -ENOMEM;
	__u32 outcnt, incnt;
	__u16 out, in;

	if (!asoc->peer.reconf_capable ||
	    !(asoc->strreset_enable & SCTP_ENABLE_CHANGE_ASSOC_REQ)) {
		retval = -ENOPROTOOPT;
		goto out;
	}

	if (asoc->strreset_outstanding) {
		retval = -EINPROGRESS;
		goto out;
	}

	out = params->sas_outstrms;
	in  = params->sas_instrms;
	outcnt = stream->outcnt + out;
	incnt = stream->incnt + in;
	if (outcnt > SCTP_MAX_STREAM || incnt > SCTP_MAX_STREAM ||
	    (!out && !in)) {
		retval = -EINVAL;
		goto out;
	}

	if (out) {
		struct sctp_stream_out *streamout;

		streamout = krealloc(stream->out, outcnt * sizeof(*streamout),
				     GFP_KERNEL);
		if (!streamout)
			goto out;

		memset(streamout + stream->outcnt, 0, out * sizeof(*streamout));
		stream->out = streamout;
	}

	if (in) {
		struct sctp_stream_in *streamin;

		streamin = krealloc(stream->in, incnt * sizeof(*streamin),
				    GFP_KERNEL);
		if (!streamin)
			goto out;

		memset(streamin + stream->incnt, 0, in * sizeof(*streamin));
		stream->in = streamin;
	}

	chunk = sctp_make_strreset_addstrm(asoc, out, in);
	if (!chunk)
		goto out;

	asoc->strreset_chunk = chunk;
	sctp_chunk_hold(asoc->strreset_chunk);

	retval = sctp_send_reconf(asoc, chunk);
	if (retval) {
		sctp_chunk_put(asoc->strreset_chunk);
		asoc->strreset_chunk = NULL;
		goto out;
	}

	stream->incnt = incnt;
	stream->outcnt = outcnt;

	asoc->strreset_outstanding = !!out + !!in;

out:
	return retval;
}

static sctp_paramhdr_t *sctp_chunk_lookup_strreset_param(
			struct sctp_association *asoc, __u32 resp_seq)
{
	struct sctp_chunk *chunk = asoc->strreset_chunk;
	struct sctp_reconf_chunk *hdr;
	union sctp_params param;

	if (ntohl(resp_seq) != asoc->strreset_outseq || !chunk)
		return NULL;

	hdr = (struct sctp_reconf_chunk *)chunk->chunk_hdr;
	sctp_walk_params(param, hdr, params) {
		/* sctp_strreset_tsnreq is actually the basic structure
		 * of all stream reconf params, so it's safe to use it
		 * to access request_seq.
		 */
		struct sctp_strreset_tsnreq *req = param.v;

		if (req->request_seq == resp_seq)
			return param.v;
	}

	return NULL;
}

struct sctp_chunk *sctp_process_strreset_outreq(
				struct sctp_association *asoc,
				union sctp_params param,
				struct sctp_ulpevent **evp)
{
	struct sctp_strreset_outreq *outreq = param.v;
	struct sctp_stream *stream = asoc->stream;
	__u16 i, nums, flags = 0, *str_p = NULL;
	__u32 result = SCTP_STRRESET_DENIED;
	__u32 request_seq;

	request_seq = ntohl(outreq->request_seq);

	if (ntohl(outreq->send_reset_at_tsn) >
	    sctp_tsnmap_get_ctsn(&asoc->peer.tsn_map)) {
		result = SCTP_STRRESET_IN_PROGRESS;
		goto out;
	}

	if (request_seq > asoc->strreset_inseq) {
		result = SCTP_STRRESET_ERR_BAD_SEQNO;
		goto out;
	} else if (request_seq == asoc->strreset_inseq) {
		asoc->strreset_inseq++;
	}

	/* Check strreset_enable after inseq inc, as sender cannot tell
	 * the peer doesn't enable strreset after receiving response with
	 * result denied, as well as to keep consistent with bsd.
	 */
	if (!(asoc->strreset_enable & SCTP_ENABLE_RESET_STREAM_REQ))
		goto out;

	if (asoc->strreset_chunk) {
		sctp_paramhdr_t *param_hdr;
		struct sctp_transport *t;

		param_hdr = sctp_chunk_lookup_strreset_param(
					asoc, outreq->response_seq);
		if (!param_hdr || param_hdr->type !=
					SCTP_PARAM_RESET_IN_REQUEST) {
			/* same process with outstanding isn't 0 */
			result = SCTP_STRRESET_ERR_IN_PROGRESS;
			goto out;
		}

		asoc->strreset_outstanding--;
		asoc->strreset_outseq++;

		if (!asoc->strreset_outstanding) {
			t = asoc->strreset_chunk->transport;
			if (del_timer(&t->reconf_timer))
				sctp_transport_put(t);

			sctp_chunk_put(asoc->strreset_chunk);
			asoc->strreset_chunk = NULL;
		}

		flags = SCTP_STREAM_RESET_INCOMING_SSN;
	}

	nums = (ntohs(param.p->length) - sizeof(*outreq)) / 2;
	if (nums) {
		str_p = outreq->list_of_streams;
		for (i = 0; i < nums; i++) {
			if (ntohs(str_p[i]) >= stream->incnt) {
				result = SCTP_STRRESET_ERR_WRONG_SSN;
				goto out;
			}
		}

		for (i = 0; i < nums; i++)
			stream->in[ntohs(str_p[i])].ssn = 0;
	} else {
		for (i = 0; i < stream->incnt; i++)
			stream->in[i].ssn = 0;
	}

	result = SCTP_STRRESET_PERFORMED;

	*evp = sctp_ulpevent_make_stream_reset_event(asoc,
		flags | SCTP_STREAM_RESET_OUTGOING_SSN, nums, str_p,
		GFP_ATOMIC);

out:
	return sctp_make_strreset_resp(asoc, result, request_seq);
}

struct sctp_chunk *sctp_process_strreset_inreq(
				struct sctp_association *asoc,
				union sctp_params param,
				struct sctp_ulpevent **evp)
{
	struct sctp_strreset_inreq *inreq = param.v;
	struct sctp_stream *stream = asoc->stream;
	__u32 result = SCTP_STRRESET_DENIED;
	struct sctp_chunk *chunk = NULL;
	__u16 i, nums, *str_p;
	__u32 request_seq;

	request_seq = ntohl(inreq->request_seq);
	if (request_seq > asoc->strreset_inseq) {
		result = SCTP_STRRESET_ERR_BAD_SEQNO;
		goto out;
	} else if (request_seq == asoc->strreset_inseq) {
		asoc->strreset_inseq++;
	}

	if (!(asoc->strreset_enable & SCTP_ENABLE_RESET_STREAM_REQ))
		goto out;

	if (asoc->strreset_outstanding) {
		result = SCTP_STRRESET_ERR_IN_PROGRESS;
		goto out;
	}

	nums = (ntohs(param.p->length) - sizeof(*inreq)) / 2;
	str_p = inreq->list_of_streams;
	for (i = 0; i < nums; i++) {
		if (ntohs(str_p[i]) >= stream->outcnt) {
			result = SCTP_STRRESET_ERR_WRONG_SSN;
			goto out;
		}
	}

	chunk = sctp_make_strreset_req(asoc, nums, str_p, 1, 0);
	if (!chunk)
		goto out;

	if (nums)
		for (i = 0; i < nums; i++)
			stream->out[ntohs(str_p[i])].state =
					       SCTP_STREAM_CLOSED;
	else
		for (i = 0; i < stream->outcnt; i++)
			stream->out[i].state = SCTP_STREAM_CLOSED;

	asoc->strreset_chunk = chunk;
	asoc->strreset_outstanding = 1;
	sctp_chunk_hold(asoc->strreset_chunk);

	*evp = sctp_ulpevent_make_stream_reset_event(asoc,
		SCTP_STREAM_RESET_INCOMING_SSN, nums, str_p, GFP_ATOMIC);

out:
	if (!chunk)
		chunk =  sctp_make_strreset_resp(asoc, result, request_seq);

	return chunk;
}

/*
 * Definitions for the LightNVM interface
 * Copyright (c) 2015, IT University of Copenhagen
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _UAPI_LINUX_LIGHTNVM_H
#define _UAPI_LINUX_LIGHTNVM_H

#include <linux/types.h>

enum {
	/* HW Responsibilities */
	NVM_RSP_L2P	= 0x00,
	NVM_RSP_GC	= 0x01,
	NVM_RSP_ECC	= 0x02,

	/* Physical NVM Type */
	NVM_NVMT_BLK	= 0,
	NVM_NVMT_BYTE	= 1,

	/* Internal IO Scheduling algorithm */
	NVM_IOSCHED_CHANNEL	= 0,
	NVM_IOSCHED_CHIP	= 1,

	/* Status codes */
	NVM_SUCCESS		= 0,
	NVM_RSP_NOT_CHANGEABLE	= 1,
};

struct nvm_id_chnl {
	u64	laddr_begin;
	u64	laddr_end;
	u32	oob_size;
	u32	queue_size;
	u32	gran_read;
	u32	gran_write;
	u32	gran_erase;
	u32	t_r;
	u32	t_sqr;
	u32	t_w;
	u32	t_sqw;
	u32	t_e;
	u16	chnl_parallelism;
	u8	io_sched;
	u8	res[133];
};

struct nvm_id {
	u8	ver_id;
	u8	nvm_type;
	u16	nchannels;
	struct nvm_id_chnl *chnls;
};

struct nvm_get_features {
	u64	rsp;
	u64	ext;
};

#endif /* _UAPI_LINUX_LIGHTNVM_H */


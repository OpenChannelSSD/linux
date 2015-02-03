#ifndef LIGHTNVM_H
#define LIGHTNVM_H

#include <linux/types.h>
#include <linux/blk-mq.h>
#include <linux/genhd.h>

enum {
	/* HW Responsibilities */
	NVM_RSP_L2P	= 0x00,
	NVM_RSP_P2L	= 0x01,
	NVM_RSP_GC	= 0x02,
	NVM_RSP_ECC	= 0x03,

	/* Physical NVM Type */
	NVM_NVMT_BLK	= 0,
	NVM_NVMT_BYTE	= 1,

	/* Internal IO Scheduling algorithm */
	NVM_IOSCHED_CHANNEL	= 0,
	NVM_IOSCHED_CHIP	= 1,

	/* Status codes */
	NVM_SUCCESS		= 0x0000,
	NVM_RID_NOT_CHANGEABLE	= 0x010e,
	NVM_DNR			= 0x4000,
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
	u64	rsp[4];
	u64	ext[4];
};

typedef int (nvm_l2p_tbl_init_fn)(struct request_queue *, u64, u64, __le64 *);
typedef int (nvm_id_fn)(struct request_queue *, struct nvm_id *);
typedef int (nvm_get_features_fn)(struct request_queue *,
				  struct nvm_get_features *);
typedef int (nvm_set_rsp_fn)(struct request_queue *, u8 rsp, u8 val);
typedef int (nvm_get_l2p_tbl_fn)(struct request_queue *, u64, u64,
				 nvm_l2p_tbl_init_fn *);
typedef int (nvm_erase_blk_fn)(struct request_queue *, sector_t);

struct lightnvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;

	nvm_erase_blk_fn	*erase_block;
};

struct nvm_dev {
	struct lightnvm_dev_ops *ops;
	struct gendisk *disk;
	struct request_queue *q;

	/* LightNVM stores extra data after the private driver data */
	unsigned int drv_cmd_size;

	void *stor;
};

/* LightNVM configuration */
unsigned int nvm_cmd_size(void);

int nvm_init(struct nvm_dev *);
void nvm_exit(struct nvm_dev *);
int nvm_map_rq(struct nvm_dev *, struct request *);
void nvm_complete_request(struct nvm_dev *, struct request *, int err);

int nvm_add_sysfs(struct device *);
void nvm_remove_sysfs(struct device *);

#endif

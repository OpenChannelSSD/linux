#ifndef LIGHTNVM_H
#define LIGHTNVM_H

#include <uapi/linux/lightnvm.h>
#include <linux/types.h>
#include <linux/blk-mq.h>
#include <linux/genhd.h>

/* HW Responsibilities */
enum {
	NVM_RSP_L2P	= 0x00,
	NVM_RSP_P2L	= 0x01,
	NVM_RSP_GC	= 0x02,
	NVM_RSP_ECC	= 0x03,
};

/* Physical NVM Type */
enum {
	NVM_NVMT_BLK	= 0,
	NVM_NVMT_BYTE	= 1,
};

/* Internal IO Scheduling algorithm */
enum {
	NVM_IOSCHED_CHANNEL	= 0,
	NVM_IOSCHED_CHIP	= 1,
};

/* Status codes */
enum {
	NVM_SUCCESS		= 0x0000,
	NVM_INVALID_OPCODE	= 0x0001,
	NVM_INVALID_FIELD	= 0x0002,
	NVM_INTERNAL_DEV_ERROR	= 0x0006,
	NVM_INVALID_CHNLID	= 0x000b,
	NVM_LBA_RANGE		= 0x0080,
	NVM_MAX_QSIZE_EXCEEDED	= 0x0102,
	NVM_RESERVED		= 0x0104,
	NVM_CONFLICTING_ATTRS	= 0x0180,
	NVM_RID_NOT_SAVEABLE	= 0x010d,
	NVM_RID_NOT_CHANGEABLE	= 0x010e,
	NVM_ACCESS_DENIED	= 0x0286,
	NVM_MORE		= 0x2000,
	NVM_DNR			= 0x4000,
	NVM_NO_COMPLETE		= 0xffff,
};

/* LightNVM request return values */
enum {
	__NVM_RQ_OK,		/* not set, check errors, set, all OK */
	__NVM_RQ_PROCESSED,	/* not set, continue, set, don't send to dev */
	__NVM_RQ_ERR_BUSY,	/* cannot satisfy rq now */
	__NVM_RQ_ERR_MAPPED,	/* already mapped */
};

#define NVM_RQ_OK		(__NVM_RQ_OK)
#define NVM_RQ_PROCESSED	(1U << __NVM_RQ_PROCESSED)
#define NVM_RQ_ERR_BUSY		(1U << __NVM_RQ_ERR_BUSY)
#define NVM_RQ_ERR_MAPPED	(1U << __NVM_RQ_ERR_MAPPED)

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

struct nvm_dev;
struct nvm_stor;

typedef int (nvm_l2p_tbl_init_fn)(struct nvm_stor *s, u64 slba, u64 nlb,
							__le64 *tbl_segment);
typedef int (nvm_id_fn)(struct request_queue *q, struct nvm_id *id);
typedef int (nvm_get_features_fn)(struct request_queue *q, struct nvm_get_features *);
typedef int (nvm_set_rsp_fn)(struct request_queue *q, u8 rsp, u8 val);
typedef int (nvm_get_l2p_tbl_fn)(struct request_queue *q, u64 slba, u64 nlb,
						nvm_l2p_tbl_init_fn *init_cb,
						struct nvm_stor *s);
typedef int (nvm_erase_blk_fn)(struct nvm_dev *, sector_t);

struct lightnvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_get_features_fn 	*get_features;
	nvm_set_rsp_fn		*set_responsibility;
	nvm_get_l2p_tbl_fn	*get_l2p_tbl;

	nvm_erase_blk_fn	*nvm_erase_block;
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

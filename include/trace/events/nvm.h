#undef TRACE_SYSTEM
#define TRACE_SYSTEM nvm

#if !defined(_TRACE_NVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NVM_H

#include <linux/blkdev.h>
#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(nvm__rq_map,
	TP_PROTO(struct request *rq),
	TP_ARGS(rq),

	TP_STRUCT__entry(
		__field(	sector_t,	sector		)
		__field(	sector_t,	phys_sector	)
		__field(	unsigned int,	data_len	)
		__field(	u64,		flags		)
	),

	TP_fast_assign(
		__entry->sector = rq->__sector;
		__entry->phys_sector = rq->phys_sector;
		__entry->data_len = rq->__data_len;
		__entry->flags = rq->cmd_flags;
	),

	TP_printk("sector %llu phys_sector %llu data_len %u flags: %s",
		(unsigned long long)__entry->sector,
		(unsigned long long)__entry->phys_sector,
		__entry->data_len,
		__print_flags(__entry->flags, " ",
			{REQ_NVM, "N"},
			{REQ_NVM_MAPPED, "M"}
		)
	)
);

/**
 * nvm_rq_map_begin - NVM mapping logic entered
 * @rq: block IO request
 *
 * Called immediately after entering the NVM mapping function.
 */
DEFINE_EVENT(nvm__rq_map, nvm_rq_map_begin,

	TP_PROTO(struct request *rq),

	TP_ARGS(rq)
);

/**
 * nvm_rq_map_end - NVM mapping logic exited
 * @rq: block IO request
 *
 * Called immediately before the NVM mapping function exits. The flags of
 * the request marks whether it has been treated as an actual NVM request
 * and/or mapped or passed down directly.
 */
DEFINE_EVENT(nvm__rq_map, nvm_rq_map_end,

	TP_PROTO(struct request *rq),

	TP_ARGS(rq)
);

#endif /* _TRACE_NVM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

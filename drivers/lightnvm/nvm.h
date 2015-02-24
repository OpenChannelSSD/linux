/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef NVM_H_
#define NVM_H_

#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/mempool.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/hashtable.h>
#include <linux/lightnvm.h>
#include <linux/blk-mq.h>
#include <linux/slab.h>

/*
 * For now we hardcode some of the configuration for the LightNVM device that we
 * have. In the future this should be made configurable.
 *
 * Configuration:
 * EXPOSED_PAGE_SIZE - the page size of which we tell the layers above the
 * driver to issue. This usually is 512 bytes for 4K for simplivity.
 */

#endif /* NVM_H_ */


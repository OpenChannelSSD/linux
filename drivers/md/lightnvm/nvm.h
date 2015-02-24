/*
 * nvm.h - LightNVM Open-channel SSD integration
 *
 * Copyright (C) 2015 IT University of Copenhagen
 * Initial release: Matias Bjorling <mabj@itu.dk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#ifndef NVM_H
#define NVM_H

#include <linux/blkdev.h>


int nvm_create_disk(struct request_queue *, char *, int, int);

#endif /* NVM_H */

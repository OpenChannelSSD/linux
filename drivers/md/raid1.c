/*
 * raid1.c : Multiple Devices driver for Linux
 *
 * Copyright (C) 1999, 2000, 2001 Ingo Molnar, Red Hat
 *
 * Copyright (C) 1996, 1997, 1998 Ingo Molnar, Miguel de Icaza, Gadi Oxman
 *
 * RAID-1 management functions.
 *
 * Better read-balancing code written by Mika Kuoppala <miku@iki.fi>, 2000
 *
 * Fixes to reconstruction by Jakob Østergaard" <jakob@ostenfeld.dk>
 * Various fixes by Neil Brown <neilb@cse.unsw.edu.au>
 *
 * Changes by Peter T. Breuer <ptb@it.uc3m.es> 31/1/2003 to support
 * bitmapped intelligence in resync:
 *
 *      - bitmap marked during normal i/o
 *      - bitmap used to skip nondirty blocks during sync
 *
 * Additions to bitmap code, (C) 2003-2004 Paul Clements, SteelEye Technology:
 * - persistent bitmap code
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * You should have received a copy of the GNU General Public License
 * (for example /usr/src/linux/COPYING); if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>

#include <trace/events/block.h>

#include "md.h"
#include "raid1.h"
#include "bitmap.h"

#define UNSUPPORTED_MDDEV_FLAGS		\
	((1L << MD_HAS_JOURNAL) |	\
	 (1L << MD_JOURNAL_CLEAN))

/*
 * Number of guaranteed r1bios in case of extreme VM load:
 */
#define	NR_RAID1_BIOS 256

/* when we get a read error on a read-only array, we redirect to another
 * device without failing the first device, or trying to over-write to
 * correct the read error.  To keep track of bad blocks on a per-bio
 * level, we store IO_BLOCKED in the appropriate 'bios' pointer
 */
#define IO_BLOCKED ((struct bio *)1)
/* When we successfully write to a known bad-block, we need to remove the
 * bad-block marking which must be done from process context.  So we record
 * the success by setting devs[n].bio to IO_MADE_GOOD
 */
#define IO_MADE_GOOD ((struct bio *)2)

#define BIO_SPECIAL(bio) ((unsigned long)bio <= 2)

/* When there are this many requests queue to be written by
 * the raid1 thread, we become 'congested' to provide back-pressure
 * for writeback.
 */
static int max_queued_requests = 1024;

static void allow_barrier(struct r1conf *conf, sector_t sector_nr);
static void lower_barrier(struct r1conf *conf, sector_t sector_nr);

#define raid1_log(md, fmt, args...)				\
	do { if ((md)->queue) blk_add_trace_msg((md)->queue, "raid1 " fmt, ##args); } while (0)

static void * r1bio_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct pool_info *pi = data;
	int size = offsetof(struct r1bio, bios[pi->raid_disks]);

	/* allocate a r1bio with room for raid_disks entries in the bios array */
	return kzalloc(size, gfp_flags);
}

static void r1bio_pool_free(void *r1_bio, void *data)
{
	kfree(r1_bio);
}

#define RESYNC_BLOCK_SIZE (64*1024)
#define RESYNC_DEPTH 32
#define RESYNC_SECTORS (RESYNC_BLOCK_SIZE >> 9)
#define RESYNC_PAGES ((RESYNC_BLOCK_SIZE + PAGE_SIZE-1) / PAGE_SIZE)
#define RESYNC_WINDOW (RESYNC_BLOCK_SIZE * RESYNC_DEPTH)
#define RESYNC_WINDOW_SECTORS (RESYNC_WINDOW >> 9)
#define CLUSTER_RESYNC_WINDOW (16 * RESYNC_WINDOW)
#define CLUSTER_RESYNC_WINDOW_SECTORS (CLUSTER_RESYNC_WINDOW >> 9)

static void * r1buf_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct pool_info *pi = data;
	struct r1bio *r1_bio;
	struct bio *bio;
	int need_pages;
	int i, j;

	r1_bio = r1bio_pool_alloc(gfp_flags, pi);
	if (!r1_bio)
		return NULL;

	/*
	 * Allocate bios : 1 for reading, n-1 for writing
	 */
	for (j = pi->raid_disks ; j-- ; ) {
		bio = bio_kmalloc(gfp_flags, RESYNC_PAGES);
		if (!bio)
			goto out_free_bio;
		r1_bio->bios[j] = bio;
	}
	/*
	 * Allocate RESYNC_PAGES data pages and attach them to
	 * the first bio.
	 * If this is a user-requested check/repair, allocate
	 * RESYNC_PAGES for each bio.
	 */
	if (test_bit(MD_RECOVERY_REQUESTED, &pi->mddev->recovery))
		need_pages = pi->raid_disks;
	else
		need_pages = 1;
	for (j = 0; j < need_pages; j++) {
		bio = r1_bio->bios[j];
		bio->bi_vcnt = RESYNC_PAGES;

		if (bio_alloc_pages(bio, gfp_flags))
			goto out_free_pages;
	}
	/* If not user-requests, copy the page pointers to all bios */
	if (!test_bit(MD_RECOVERY_REQUESTED, &pi->mddev->recovery)) {
		for (i=0; i<RESYNC_PAGES ; i++)
			for (j=1; j<pi->raid_disks; j++)
				r1_bio->bios[j]->bi_io_vec[i].bv_page =
					r1_bio->bios[0]->bi_io_vec[i].bv_page;
	}

	r1_bio->master_bio = NULL;

	return r1_bio;

out_free_pages:
	while (--j >= 0)
		bio_free_pages(r1_bio->bios[j]);

out_free_bio:
	while (++j < pi->raid_disks)
		bio_put(r1_bio->bios[j]);
	r1bio_pool_free(r1_bio, data);
	return NULL;
}

static void r1buf_pool_free(void *__r1_bio, void *data)
{
	struct pool_info *pi = data;
	int i,j;
	struct r1bio *r1bio = __r1_bio;

	for (i = 0; i < RESYNC_PAGES; i++)
		for (j = pi->raid_disks; j-- ;) {
			if (j == 0 ||
			    r1bio->bios[j]->bi_io_vec[i].bv_page !=
			    r1bio->bios[0]->bi_io_vec[i].bv_page)
				safe_put_page(r1bio->bios[j]->bi_io_vec[i].bv_page);
		}
	for (i=0 ; i < pi->raid_disks; i++)
		bio_put(r1bio->bios[i]);

	r1bio_pool_free(r1bio, data);
}

static void put_all_bios(struct r1conf *conf, struct r1bio *r1_bio)
{
	int i;

	for (i = 0; i < conf->raid_disks * 2; i++) {
		struct bio **bio = r1_bio->bios + i;
		if (!BIO_SPECIAL(*bio))
			bio_put(*bio);
		*bio = NULL;
	}
}

static void free_r1bio(struct r1bio *r1_bio)
{
	struct r1conf *conf = r1_bio->mddev->private;

	put_all_bios(conf, r1_bio);
	mempool_free(r1_bio, conf->r1bio_pool);
}

static void put_buf(struct r1bio *r1_bio)
{
	struct r1conf *conf = r1_bio->mddev->private;
	sector_t sect = r1_bio->sector;
	int i;

	for (i = 0; i < conf->raid_disks * 2; i++) {
		struct bio *bio = r1_bio->bios[i];
		if (bio->bi_end_io)
			rdev_dec_pending(conf->mirrors[i].rdev, r1_bio->mddev);
	}

	mempool_free(r1_bio, conf->r1buf_pool);

	lower_barrier(conf, sect);
}

static void reschedule_retry(struct r1bio *r1_bio)
{
	unsigned long flags;
	struct mddev *mddev = r1_bio->mddev;
	struct r1conf *conf = mddev->private;
	int idx;

	idx = sector_to_idx(r1_bio->sector);
	spin_lock_irqsave(&conf->device_lock, flags);
	list_add(&r1_bio->retry_list, &conf->retry_list);
	atomic_inc(&conf->nr_queued[idx]);
	spin_unlock_irqrestore(&conf->device_lock, flags);

	wake_up(&conf->wait_barrier);
	md_wakeup_thread(mddev->thread);
}

/*
 * raid_end_bio_io() is called when we have finished servicing a mirrored
 * operation and are ready to return a success/failure code to the buffer
 * cache layer.
 */
static void call_bio_endio(struct r1bio *r1_bio)
{
	struct bio *bio = r1_bio->master_bio;
	int done;
	struct r1conf *conf = r1_bio->mddev->private;
	sector_t bi_sector = bio->bi_iter.bi_sector;

	if (bio->bi_phys_segments) {
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		bio->bi_phys_segments--;
		done = (bio->bi_phys_segments == 0);
		spin_unlock_irqrestore(&conf->device_lock, flags);
		/*
		 * make_request() might be waiting for
		 * bi_phys_segments to decrease
		 */
		wake_up(&conf->wait_barrier);
	} else
		done = 1;

	if (!test_bit(R1BIO_Uptodate, &r1_bio->state))
		bio->bi_error = -EIO;

	if (done) {
		bio_endio(bio);
		/*
		 * Wake up any possible resync thread that waits for the device
		 * to go idle.
		 */
		allow_barrier(conf, bi_sector);
	}
}

static void raid_end_bio_io(struct r1bio *r1_bio)
{
	struct bio *bio = r1_bio->master_bio;

	/* if nobody has done the final endio yet, do it now */
	if (!test_and_set_bit(R1BIO_Returned, &r1_bio->state)) {
		pr_debug("raid1: sync end %s on sectors %llu-%llu\n",
			 (bio_data_dir(bio) == WRITE) ? "write" : "read",
			 (unsigned long long) bio->bi_iter.bi_sector,
			 (unsigned long long) bio_end_sector(bio) - 1);

		call_bio_endio(r1_bio);
	}
	free_r1bio(r1_bio);
}

/*
 * Update disk head position estimator based on IRQ completion info.
 */
static inline void update_head_pos(int disk, struct r1bio *r1_bio)
{
	struct r1conf *conf = r1_bio->mddev->private;

	conf->mirrors[disk].head_position =
		r1_bio->sector + (r1_bio->sectors);
}

/*
 * Find the disk number which triggered given bio
 */
static int find_bio_disk(struct r1bio *r1_bio, struct bio *bio)
{
	int mirror;
	struct r1conf *conf = r1_bio->mddev->private;
	int raid_disks = conf->raid_disks;

	for (mirror = 0; mirror < raid_disks * 2; mirror++)
		if (r1_bio->bios[mirror] == bio)
			break;

	BUG_ON(mirror == raid_disks * 2);
	update_head_pos(mirror, r1_bio);

	return mirror;
}

static void raid1_end_read_request(struct bio *bio)
{
	int uptodate = !bio->bi_error;
	struct r1bio *r1_bio = bio->bi_private;
	struct r1conf *conf = r1_bio->mddev->private;
	struct md_rdev *rdev = conf->mirrors[r1_bio->read_disk].rdev;

	/*
	 * this branch is our 'one mirror IO has finished' event handler:
	 */
	update_head_pos(r1_bio->read_disk, r1_bio);

	if (uptodate)
		set_bit(R1BIO_Uptodate, &r1_bio->state);
	else if (test_bit(FailFast, &rdev->flags) &&
		 test_bit(R1BIO_FailFast, &r1_bio->state))
		/* This was a fail-fast read so we definitely
		 * want to retry */
		;
	else {
		/* If all other devices have failed, we want to return
		 * the error upwards rather than fail the last device.
		 * Here we redefine "uptodate" to mean "Don't want to retry"
		 */
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		if (r1_bio->mddev->degraded == conf->raid_disks ||
		    (r1_bio->mddev->degraded == conf->raid_disks-1 &&
		     test_bit(In_sync, &rdev->flags)))
			uptodate = 1;
		spin_unlock_irqrestore(&conf->device_lock, flags);
	}

	if (uptodate) {
		raid_end_bio_io(r1_bio);
		rdev_dec_pending(rdev, conf->mddev);
	} else {
		/*
		 * oops, read error:
		 */
		char b[BDEVNAME_SIZE];
		pr_err_ratelimited("md/raid1:%s: %s: rescheduling sector %llu\n",
				   mdname(conf->mddev),
				   bdevname(rdev->bdev, b),
				   (unsigned long long)r1_bio->sector);
		set_bit(R1BIO_ReadError, &r1_bio->state);
		reschedule_retry(r1_bio);
		/* don't drop the reference on read_disk yet */
	}
}

static void close_write(struct r1bio *r1_bio)
{
	/* it really is the end of this request */
	if (test_bit(R1BIO_BehindIO, &r1_bio->state)) {
		/* free extra copy of the data pages */
		int i = r1_bio->behind_page_count;
		while (i--)
			safe_put_page(r1_bio->behind_bvecs[i].bv_page);
		kfree(r1_bio->behind_bvecs);
		r1_bio->behind_bvecs = NULL;
	}
	/* clear the bitmap if all writes complete successfully */
	bitmap_endwrite(r1_bio->mddev->bitmap, r1_bio->sector,
			r1_bio->sectors,
			!test_bit(R1BIO_Degraded, &r1_bio->state),
			test_bit(R1BIO_BehindIO, &r1_bio->state));
	md_write_end(r1_bio->mddev);
}

static void r1_bio_write_done(struct r1bio *r1_bio)
{
	if (!atomic_dec_and_test(&r1_bio->remaining))
		return;

	if (test_bit(R1BIO_WriteError, &r1_bio->state))
		reschedule_retry(r1_bio);
	else {
		close_write(r1_bio);
		if (test_bit(R1BIO_MadeGood, &r1_bio->state))
			reschedule_retry(r1_bio);
		else
			raid_end_bio_io(r1_bio);
	}
}

static void raid1_end_write_request(struct bio *bio)
{
	struct r1bio *r1_bio = bio->bi_private;
	int behind = test_bit(R1BIO_BehindIO, &r1_bio->state);
	struct r1conf *conf = r1_bio->mddev->private;
	struct bio *to_put = NULL;
	int mirror = find_bio_disk(r1_bio, bio);
	struct md_rdev *rdev = conf->mirrors[mirror].rdev;
	bool discard_error;

	discard_error = bio->bi_error && bio_op(bio) == REQ_OP_DISCARD;

	/*
	 * 'one mirror IO has finished' event handler:
	 */
	if (bio->bi_error && !discard_error) {
		set_bit(WriteErrorSeen,	&rdev->flags);
		if (!test_and_set_bit(WantReplacement, &rdev->flags))
			set_bit(MD_RECOVERY_NEEDED, &
				conf->mddev->recovery);

		if (test_bit(FailFast, &rdev->flags) &&
		    (bio->bi_opf & MD_FAILFAST) &&
		    /* We never try FailFast to WriteMostly devices */
		    !test_bit(WriteMostly, &rdev->flags)) {
			md_error(r1_bio->mddev, rdev);
			if (!test_bit(Faulty, &rdev->flags))
				/* This is the only remaining device,
				 * We need to retry the write without
				 * FailFast
				 */
				set_bit(R1BIO_WriteError, &r1_bio->state);
			else {
				/* Finished with this branch */
				r1_bio->bios[mirror] = NULL;
				to_put = bio;
			}
		} else
			set_bit(R1BIO_WriteError, &r1_bio->state);
	} else {
		/*
		 * Set R1BIO_Uptodate in our master bio, so that we
		 * will return a good error code for to the higher
		 * levels even if IO on some other mirrored buffer
		 * fails.
		 *
		 * The 'master' represents the composite IO operation
		 * to user-side. So if something waits for IO, then it
		 * will wait for the 'master' bio.
		 */
		sector_t first_bad;
		int bad_sectors;

		r1_bio->bios[mirror] = NULL;
		to_put = bio;
		/*
		 * Do not set R1BIO_Uptodate if the current device is
		 * rebuilding or Faulty. This is because we cannot use
		 * such device for properly reading the data back (we could
		 * potentially use it, if the current write would have felt
		 * before rdev->recovery_offset, but for simplicity we don't
		 * check this here.
		 */
		if (test_bit(In_sync, &rdev->flags) &&
		    !test_bit(Faulty, &rdev->flags))
			set_bit(R1BIO_Uptodate, &r1_bio->state);

		/* Maybe we can clear some bad blocks. */
		if (is_badblock(rdev, r1_bio->sector, r1_bio->sectors,
				&first_bad, &bad_sectors) && !discard_error) {
			r1_bio->bios[mirror] = IO_MADE_GOOD;
			set_bit(R1BIO_MadeGood, &r1_bio->state);
		}
	}

	if (behind) {
		if (test_bit(WriteMostly, &rdev->flags))
			atomic_dec(&r1_bio->behind_remaining);

		/*
		 * In behind mode, we ACK the master bio once the I/O
		 * has safely reached all non-writemostly
		 * disks. Setting the Returned bit ensures that this
		 * gets done only once -- we don't ever want to return
		 * -EIO here, instead we'll wait
		 */
		if (atomic_read(&r1_bio->behind_remaining) >= (atomic_read(&r1_bio->remaining)-1) &&
		    test_bit(R1BIO_Uptodate, &r1_bio->state)) {
			/* Maybe we can return now */
			if (!test_and_set_bit(R1BIO_Returned, &r1_bio->state)) {
				struct bio *mbio = r1_bio->master_bio;
				pr_debug("raid1: behind end write sectors"
					 " %llu-%llu\n",
					 (unsigned long long) mbio->bi_iter.bi_sector,
					 (unsigned long long) bio_end_sector(mbio) - 1);
				call_bio_endio(r1_bio);
			}
		}
	}
	if (r1_bio->bios[mirror] == NULL)
		rdev_dec_pending(rdev, conf->mddev);

	/*
	 * Let's see if all mirrored write operations have finished
	 * already.
	 */
	r1_bio_write_done(r1_bio);

	if (to_put)
		bio_put(to_put);
}

static sector_t align_to_barrier_unit_end(sector_t start_sector,
					  sector_t sectors)
{
	sector_t len;

	WARN_ON(sectors == 0);
	/*
	 * len is the number of sectors from start_sector to end of the
	 * barrier unit which start_sector belongs to.
	 */
	len = round_up(start_sector + 1, BARRIER_UNIT_SECTOR_SIZE) -
	      start_sector;

	if (len > sectors)
		len = sectors;

	return len;
}

/*
 * This routine returns the disk from which the requested read should
 * be done. There is a per-array 'next expected sequential IO' sector
 * number - if this matches on the next IO then we use the last disk.
 * There is also a per-disk 'last know head position' sector that is
 * maintained from IRQ contexts, both the normal and the resync IO
 * completion handlers update this position correctly. If there is no
 * perfect sequential match then we pick the disk whose head is closest.
 *
 * If there are 2 mirrors in the same 2 devices, performance degrades
 * because position is mirror, not device based.
 *
 * The rdev for the device selected will have nr_pending incremented.
 */
static int read_balance(struct r1conf *conf, struct r1bio *r1_bio, int *max_sectors)
{
	const sector_t this_sector = r1_bio->sector;
	int sectors;
	int best_good_sectors;
	int best_disk, best_dist_disk, best_pending_disk;
	int has_nonrot_disk;
	int disk;
	sector_t best_dist;
	unsigned int min_pending;
	struct md_rdev *rdev;
	int choose_first;
	int choose_next_idle;

	rcu_read_lock();
	/*
	 * Check if we can balance. We can balance on the whole
	 * device if no resync is going on, or below the resync window.
	 * We take the first readable disk when above the resync window.
	 */
 retry:
	sectors = r1_bio->sectors;
	best_disk = -1;
	best_dist_disk = -1;
	best_dist = MaxSector;
	best_pending_disk = -1;
	min_pending = UINT_MAX;
	best_good_sectors = 0;
	has_nonrot_disk = 0;
	choose_next_idle = 0;
	clear_bit(R1BIO_FailFast, &r1_bio->state);

	if ((conf->mddev->recovery_cp < this_sector + sectors) ||
	    (mddev_is_clustered(conf->mddev) &&
	    md_cluster_ops->area_resyncing(conf->mddev, READ, this_sector,
		    this_sector + sectors)))
		choose_first = 1;
	else
		choose_first = 0;

	for (disk = 0 ; disk < conf->raid_disks * 2 ; disk++) {
		sector_t dist;
		sector_t first_bad;
		int bad_sectors;
		unsigned int pending;
		bool nonrot;

		rdev = rcu_dereference(conf->mirrors[disk].rdev);
		if (r1_bio->bios[disk] == IO_BLOCKED
		    || rdev == NULL
		    || test_bit(Faulty, &rdev->flags))
			continue;
		if (!test_bit(In_sync, &rdev->flags) &&
		    rdev->recovery_offset < this_sector + sectors)
			continue;
		if (test_bit(WriteMostly, &rdev->flags)) {
			/* Don't balance among write-mostly, just
			 * use the first as a last resort */
			if (best_dist_disk < 0) {
				if (is_badblock(rdev, this_sector, sectors,
						&first_bad, &bad_sectors)) {
					if (first_bad <= this_sector)
						/* Cannot use this */
						continue;
					best_good_sectors = first_bad - this_sector;
				} else
					best_good_sectors = sectors;
				best_dist_disk = disk;
				best_pending_disk = disk;
			}
			continue;
		}
		/* This is a reasonable device to use.  It might
		 * even be best.
		 */
		if (is_badblock(rdev, this_sector, sectors,
				&first_bad, &bad_sectors)) {
			if (best_dist < MaxSector)
				/* already have a better device */
				continue;
			if (first_bad <= this_sector) {
				/* cannot read here. If this is the 'primary'
				 * device, then we must not read beyond
				 * bad_sectors from another device..
				 */
				bad_sectors -= (this_sector - first_bad);
				if (choose_first && sectors > bad_sectors)
					sectors = bad_sectors;
				if (best_good_sectors > sectors)
					best_good_sectors = sectors;

			} else {
				sector_t good_sectors = first_bad - this_sector;
				if (good_sectors > best_good_sectors) {
					best_good_sectors = good_sectors;
					best_disk = disk;
				}
				if (choose_first)
					break;
			}
			continue;
		} else
			best_good_sectors = sectors;

		if (best_disk >= 0)
			/* At least two disks to choose from so failfast is OK */
			set_bit(R1BIO_FailFast, &r1_bio->state);

		nonrot = blk_queue_nonrot(bdev_get_queue(rdev->bdev));
		has_nonrot_disk |= nonrot;
		pending = atomic_read(&rdev->nr_pending);
		dist = abs(this_sector - conf->mirrors[disk].head_position);
		if (choose_first) {
			best_disk = disk;
			break;
		}
		/* Don't change to another disk for sequential reads */
		if (conf->mirrors[disk].next_seq_sect == this_sector
		    || dist == 0) {
			int opt_iosize = bdev_io_opt(rdev->bdev) >> 9;
			struct raid1_info *mirror = &conf->mirrors[disk];

			best_disk = disk;
			/*
			 * If buffered sequential IO size exceeds optimal
			 * iosize, check if there is idle disk. If yes, choose
			 * the idle disk. read_balance could already choose an
			 * idle disk before noticing it's a sequential IO in
			 * this disk. This doesn't matter because this disk
			 * will idle, next time it will be utilized after the
			 * first disk has IO size exceeds optimal iosize. In
			 * this way, iosize of the first disk will be optimal
			 * iosize at least. iosize of the second disk might be
			 * small, but not a big deal since when the second disk
			 * starts IO, the first disk is likely still busy.
			 */
			if (nonrot && opt_iosize > 0 &&
			    mirror->seq_start != MaxSector &&
			    mirror->next_seq_sect > opt_iosize &&
			    mirror->next_seq_sect - opt_iosize >=
			    mirror->seq_start) {
				choose_next_idle = 1;
				continue;
			}
			break;
		}

		if (choose_next_idle)
			continue;

		if (min_pending > pending) {
			min_pending = pending;
			best_pending_disk = disk;
		}

		if (dist < best_dist) {
			best_dist = dist;
			best_dist_disk = disk;
		}
	}

	/*
	 * If all disks are rotational, choose the closest disk. If any disk is
	 * non-rotational, choose the disk with less pending request even the
	 * disk is rotational, which might/might not be optimal for raids with
	 * mixed ratation/non-rotational disks depending on workload.
	 */
	if (best_disk == -1) {
		if (has_nonrot_disk || min_pending == 0)
			best_disk = best_pending_disk;
		else
			best_disk = best_dist_disk;
	}

	if (best_disk >= 0) {
		rdev = rcu_dereference(conf->mirrors[best_disk].rdev);
		if (!rdev)
			goto retry;
		atomic_inc(&rdev->nr_pending);
		sectors = best_good_sectors;

		if (conf->mirrors[best_disk].next_seq_sect != this_sector)
			conf->mirrors[best_disk].seq_start = this_sector;

		conf->mirrors[best_disk].next_seq_sect = this_sector + sectors;
	}
	rcu_read_unlock();
	*max_sectors = sectors;

	return best_disk;
}

static int raid1_congested(struct mddev *mddev, int bits)
{
	struct r1conf *conf = mddev->private;
	int i, ret = 0;

	if ((bits & (1 << WB_async_congested)) &&
	    conf->pending_count >= max_queued_requests)
		return 1;

	rcu_read_lock();
	for (i = 0; i < conf->raid_disks * 2; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && !test_bit(Faulty, &rdev->flags)) {
			struct request_queue *q = bdev_get_queue(rdev->bdev);

			BUG_ON(!q);

			/* Note the '|| 1' - when read_balance prefers
			 * non-congested targets, it can be removed
			 */
			if ((bits & (1 << WB_async_congested)) || 1)
				ret |= bdi_congested(q->backing_dev_info, bits);
			else
				ret &= bdi_congested(q->backing_dev_info, bits);
		}
	}
	rcu_read_unlock();
	return ret;
}

static void flush_pending_writes(struct r1conf *conf)
{
	/* Any writes that have been queued but are awaiting
	 * bitmap updates get flushed here.
	 */
	spin_lock_irq(&conf->device_lock);

	if (conf->pending_bio_list.head) {
		struct bio *bio;
		bio = bio_list_get(&conf->pending_bio_list);
		conf->pending_count = 0;
		spin_unlock_irq(&conf->device_lock);
		/* flush any pending bitmap writes to
		 * disk before proceeding w/ I/O */
		bitmap_unplug(conf->mddev->bitmap);
		wake_up(&conf->wait_barrier);

		while (bio) { /* submit pending writes */
			struct bio *next = bio->bi_next;
			struct md_rdev *rdev = (void*)bio->bi_bdev;
			bio->bi_next = NULL;
			bio->bi_bdev = rdev->bdev;
			if (test_bit(Faulty, &rdev->flags)) {
				bio->bi_error = -EIO;
				bio_endio(bio);
			} else if (unlikely((bio_op(bio) == REQ_OP_DISCARD) &&
					    !blk_queue_discard(bdev_get_queue(bio->bi_bdev))))
				/* Just ignore it */
				bio_endio(bio);
			else
				generic_make_request(bio);
			bio = next;
		}
	} else
		spin_unlock_irq(&conf->device_lock);
}

/* Barriers....
 * Sometimes we need to suspend IO while we do something else,
 * either some resync/recovery, or reconfigure the array.
 * To do this we raise a 'barrier'.
 * The 'barrier' is a counter that can be raised multiple times
 * to count how many activities are happening which preclude
 * normal IO.
 * We can only raise the barrier if there is no pending IO.
 * i.e. if nr_pending == 0.
 * We choose only to raise the barrier if no-one is waiting for the
 * barrier to go down.  This means that as soon as an IO request
 * is ready, no other operations which require a barrier will start
 * until the IO request has had a chance.
 *
 * So: regular IO calls 'wait_barrier'.  When that returns there
 *    is no backgroup IO happening,  It must arrange to call
 *    allow_barrier when it has finished its IO.
 * backgroup IO calls must call raise_barrier.  Once that returns
 *    there is no normal IO happeing.  It must arrange to call
 *    lower_barrier when the particular background IO completes.
 */
static void raise_barrier(struct r1conf *conf, sector_t sector_nr)
{
	int idx = sector_to_idx(sector_nr);

	spin_lock_irq(&conf->resync_lock);

	/* Wait until no block IO is waiting */
	wait_event_lock_irq(conf->wait_barrier,
			    !atomic_read(&conf->nr_waiting[idx]),
			    conf->resync_lock);

	/* block any new IO from starting */
	atomic_inc(&conf->barrier[idx]);
	/*
	 * In raise_barrier() we firstly increase conf->barrier[idx] then
	 * check conf->nr_pending[idx]. In _wait_barrier() we firstly
	 * increase conf->nr_pending[idx] then check conf->barrier[idx].
	 * A memory barrier here to make sure conf->nr_pending[idx] won't
	 * be fetched before conf->barrier[idx] is increased. Otherwise
	 * there will be a race between raise_barrier() and _wait_barrier().
	 */
	smp_mb__after_atomic();

	/* For these conditions we must wait:
	 * A: while the array is in frozen state
	 * B: while conf->nr_pending[idx] is not 0, meaning regular I/O
	 *    existing in corresponding I/O barrier bucket.
	 * C: while conf->barrier[idx] >= RESYNC_DEPTH, meaning reaches
	 *    max resync count which allowed on current I/O barrier bucket.
	 */
	wait_event_lock_irq(conf->wait_barrier,
			    !conf->array_frozen &&
			     !atomic_read(&conf->nr_pending[idx]) &&
			     atomic_read(&conf->barrier[idx]) < RESYNC_DEPTH,
			    conf->resync_lock);

	atomic_inc(&conf->nr_pending[idx]);
	spin_unlock_irq(&conf->resync_lock);
}

static void lower_barrier(struct r1conf *conf, sector_t sector_nr)
{
	int idx = sector_to_idx(sector_nr);

	BUG_ON(atomic_read(&conf->barrier[idx]) <= 0);

	atomic_dec(&conf->barrier[idx]);
	atomic_dec(&conf->nr_pending[idx]);
	wake_up(&conf->wait_barrier);
}

static void _wait_barrier(struct r1conf *conf, int idx)
{
	/*
	 * We need to increase conf->nr_pending[idx] very early here,
	 * then raise_barrier() can be blocked when it waits for
	 * conf->nr_pending[idx] to be 0. Then we can avoid holding
	 * conf->resync_lock when there is no barrier raised in same
	 * barrier unit bucket. Also if the array is frozen, I/O
	 * should be blocked until array is unfrozen.
	 */
	atomic_inc(&conf->nr_pending[idx]);
	/*
	 * In _wait_barrier() we firstly increase conf->nr_pending[idx], then
	 * check conf->barrier[idx]. In raise_barrier() we firstly increase
	 * conf->barrier[idx], then check conf->nr_pending[idx]. A memory
	 * barrier is necessary here to make sure conf->barrier[idx] won't be
	 * fetched before conf->nr_pending[idx] is increased. Otherwise there
	 * will be a race between _wait_barrier() and raise_barrier().
	 */
	smp_mb__after_atomic();

	/*
	 * Don't worry about checking two atomic_t variables at same time
	 * here. If during we check conf->barrier[idx], the array is
	 * frozen (conf->array_frozen is 1), and chonf->barrier[idx] is
	 * 0, it is safe to return and make the I/O continue. Because the
	 * array is frozen, all I/O returned here will eventually complete
	 * or be queued, no race will happen. See code comment in
	 * frozen_array().
	 */
	if (!READ_ONCE(conf->array_frozen) &&
	    !atomic_read(&conf->barrier[idx]))
		return;

	/*
	 * After holding conf->resync_lock, conf->nr_pending[idx]
	 * should be decreased before waiting for barrier to drop.
	 * Otherwise, we may encounter a race condition because
	 * raise_barrer() might be waiting for conf->nr_pending[idx]
	 * to be 0 at same time.
	 */
	spin_lock_irq(&conf->resync_lock);
	atomic_inc(&conf->nr_waiting[idx]);
	atomic_dec(&conf->nr_pending[idx]);
	/*
	 * In case freeze_array() is waiting for
	 * get_unqueued_pending() == extra
	 */
	wake_up(&conf->wait_barrier);
	/* Wait for the barrier in same barrier unit bucket to drop. */
	wait_event_lock_irq(conf->wait_barrier,
			    !conf->array_frozen &&
			     !atomic_read(&conf->barrier[idx]),
			    conf->resync_lock);
	atomic_inc(&conf->nr_pending[idx]);
	atomic_dec(&conf->nr_waiting[idx]);
	spin_unlock_irq(&conf->resync_lock);
}

static void wait_read_barrier(struct r1conf *conf, sector_t sector_nr)
{
	int idx = sector_to_idx(sector_nr);

	/*
	 * Very similar to _wait_barrier(). The difference is, for read
	 * I/O we don't need wait for sync I/O, but if the whole array
	 * is frozen, the read I/O still has to wait until the array is
	 * unfrozen. Since there is no ordering requirement with
	 * conf->barrier[idx] here, memory barrier is unnecessary as well.
	 */
	atomic_inc(&conf->nr_pending[idx]);

	if (!READ_ONCE(conf->array_frozen))
		return;

	spin_lock_irq(&conf->resync_lock);
	atomic_inc(&conf->nr_waiting[idx]);
	atomic_dec(&conf->nr_pending[idx]);
	/*
	 * In case freeze_array() is waiting for
	 * get_unqueued_pending() == extra
	 */
	wake_up(&conf->wait_barrier);
	/* Wait for array to be unfrozen */
	wait_event_lock_irq(conf->wait_barrier,
			    !conf->array_frozen,
			    conf->resync_lock);
	atomic_inc(&conf->nr_pending[idx]);
	atomic_dec(&conf->nr_waiting[idx]);
	spin_unlock_irq(&conf->resync_lock);
}

static void wait_barrier(struct r1conf *conf, sector_t sector_nr)
{
	int idx = sector_to_idx(sector_nr);

	_wait_barrier(conf, idx);
}

static void wait_all_barriers(struct r1conf *conf)
{
	int idx;

	for (idx = 0; idx < BARRIER_BUCKETS_NR; idx++)
		_wait_barrier(conf, idx);
}

static void _allow_barrier(struct r1conf *conf, int idx)
{
	atomic_dec(&conf->nr_pending[idx]);
	wake_up(&conf->wait_barrier);
}

static void allow_barrier(struct r1conf *conf, sector_t sector_nr)
{
	int idx = sector_to_idx(sector_nr);

	_allow_barrier(conf, idx);
}

static void allow_all_barriers(struct r1conf *conf)
{
	int idx;

	for (idx = 0; idx < BARRIER_BUCKETS_NR; idx++)
		_allow_barrier(conf, idx);
}

/* conf->resync_lock should be held */
static int get_unqueued_pending(struct r1conf *conf)
{
	int idx, ret;

	for (ret = 0, idx = 0; idx < BARRIER_BUCKETS_NR; idx++)
		ret += atomic_read(&conf->nr_pending[idx]) -
			atomic_read(&conf->nr_queued[idx]);

	return ret;
}

static void freeze_array(struct r1conf *conf, int extra)
{
	/* Stop sync I/O and normal I/O and wait for everything to
	 * go quiet.
	 * This is called in two situations:
	 * 1) management command handlers (reshape, remove disk, quiesce).
	 * 2) one normal I/O request failed.

	 * After array_frozen is set to 1, new sync IO will be blocked at
	 * raise_barrier(), and new normal I/O will blocked at _wait_barrier()
	 * or wait_read_barrier(). The flying I/Os will either complete or be
	 * queued. When everything goes quite, there are only queued I/Os left.

	 * Every flying I/O contributes to a conf->nr_pending[idx], idx is the
	 * barrier bucket index which this I/O request hits. When all sync and
	 * normal I/O are queued, sum of all conf->nr_pending[] will match sum
	 * of all conf->nr_queued[]. But normal I/O failure is an exception,
	 * in handle_read_error(), we may call freeze_array() before trying to
	 * fix the read error. In this case, the error read I/O is not queued,
	 * so get_unqueued_pending() == 1.
	 *
	 * Therefore before this function returns, we need to wait until
	 * get_unqueued_pendings(conf) gets equal to extra. For
	 * normal I/O context, extra is 1, in rested situations extra is 0.
	 */
	spin_lock_irq(&conf->resync_lock);
	conf->array_frozen = 1;
	raid1_log(conf->mddev, "wait freeze");
	wait_event_lock_irq_cmd(
		conf->wait_barrier,
		get_unqueued_pending(conf) == extra,
		conf->resync_lock,
		flush_pending_writes(conf));
	spin_unlock_irq(&conf->resync_lock);
}
static void unfreeze_array(struct r1conf *conf)
{
	/* reverse the effect of the freeze */
	spin_lock_irq(&conf->resync_lock);
	conf->array_frozen = 0;
	spin_unlock_irq(&conf->resync_lock);
	wake_up(&conf->wait_barrier);
}

/* duplicate the data pages for behind I/O
 */
static void alloc_behind_pages(struct bio *bio, struct r1bio *r1_bio)
{
	int i;
	struct bio_vec *bvec;
	struct bio_vec *bvecs = kzalloc(bio->bi_vcnt * sizeof(struct bio_vec),
					GFP_NOIO);
	if (unlikely(!bvecs))
		return;

	bio_for_each_segment_all(bvec, bio, i) {
		bvecs[i] = *bvec;
		bvecs[i].bv_page = alloc_page(GFP_NOIO);
		if (unlikely(!bvecs[i].bv_page))
			goto do_sync_io;
		memcpy(kmap(bvecs[i].bv_page) + bvec->bv_offset,
		       kmap(bvec->bv_page) + bvec->bv_offset, bvec->bv_len);
		kunmap(bvecs[i].bv_page);
		kunmap(bvec->bv_page);
	}
	r1_bio->behind_bvecs = bvecs;
	r1_bio->behind_page_count = bio->bi_vcnt;
	set_bit(R1BIO_BehindIO, &r1_bio->state);
	return;

do_sync_io:
	for (i = 0; i < bio->bi_vcnt; i++)
		if (bvecs[i].bv_page)
			put_page(bvecs[i].bv_page);
	kfree(bvecs);
	pr_debug("%dB behind alloc failed, doing sync I/O\n",
		 bio->bi_iter.bi_size);
}

struct raid1_plug_cb {
	struct blk_plug_cb	cb;
	struct bio_list		pending;
	int			pending_cnt;
};

static void raid1_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	struct raid1_plug_cb *plug = container_of(cb, struct raid1_plug_cb,
						  cb);
	struct mddev *mddev = plug->cb.data;
	struct r1conf *conf = mddev->private;
	struct bio *bio;

	if (from_schedule || current->bio_list) {
		spin_lock_irq(&conf->device_lock);
		bio_list_merge(&conf->pending_bio_list, &plug->pending);
		conf->pending_count += plug->pending_cnt;
		spin_unlock_irq(&conf->device_lock);
		wake_up(&conf->wait_barrier);
		md_wakeup_thread(mddev->thread);
		kfree(plug);
		return;
	}

	/* we aren't scheduling, so we can do the write-out directly. */
	bio = bio_list_get(&plug->pending);
	bitmap_unplug(mddev->bitmap);
	wake_up(&conf->wait_barrier);

	while (bio) { /* submit pending writes */
		struct bio *next = bio->bi_next;
		struct md_rdev *rdev = (void*)bio->bi_bdev;
		bio->bi_next = NULL;
		bio->bi_bdev = rdev->bdev;
		if (test_bit(Faulty, &rdev->flags)) {
			bio->bi_error = -EIO;
			bio_endio(bio);
		} else if (unlikely((bio_op(bio) == REQ_OP_DISCARD) &&
				    !blk_queue_discard(bdev_get_queue(bio->bi_bdev))))
			/* Just ignore it */
			bio_endio(bio);
		else
			generic_make_request(bio);
		bio = next;
	}
	kfree(plug);
}

static inline struct r1bio *
alloc_r1bio(struct mddev *mddev, struct bio *bio, sector_t sectors_handled)
{
	struct r1conf *conf = mddev->private;
	struct r1bio *r1_bio;

	r1_bio = mempool_alloc(conf->r1bio_pool, GFP_NOIO);

	r1_bio->master_bio = bio;
	r1_bio->sectors = bio_sectors(bio) - sectors_handled;
	r1_bio->state = 0;
	r1_bio->mddev = mddev;
	r1_bio->sector = bio->bi_iter.bi_sector + sectors_handled;

	return r1_bio;
}

static void raid1_read_request(struct mddev *mddev, struct bio *bio)
{
	struct r1conf *conf = mddev->private;
	struct raid1_info *mirror;
	struct r1bio *r1_bio;
	struct bio *read_bio;
	struct bitmap *bitmap = mddev->bitmap;
	const int op = bio_op(bio);
	const unsigned long do_sync = (bio->bi_opf & REQ_SYNC);
	int sectors_handled;
	int max_sectors;
	int rdisk;

	/*
	 * Still need barrier for READ in case that whole
	 * array is frozen.
	 */
	wait_read_barrier(conf, bio->bi_iter.bi_sector);

	r1_bio = alloc_r1bio(mddev, bio, 0);

	/*
	 * We might need to issue multiple reads to different
	 * devices if there are bad blocks around, so we keep
	 * track of the number of reads in bio->bi_phys_segments.
	 * If this is 0, there is only one r1_bio and no locking
	 * will be needed when requests complete.  If it is
	 * non-zero, then it is the number of not-completed requests.
	 */
	bio->bi_phys_segments = 0;
	bio_clear_flag(bio, BIO_SEG_VALID);

	/*
	 * make_request() can abort the operation when read-ahead is being
	 * used and no empty request is available.
	 */
read_again:
	rdisk = read_balance(conf, r1_bio, &max_sectors);

	if (rdisk < 0) {
		/* couldn't find anywhere to read from */
		raid_end_bio_io(r1_bio);
		return;
	}
	mirror = conf->mirrors + rdisk;

	if (test_bit(WriteMostly, &mirror->rdev->flags) &&
	    bitmap) {
		/*
		 * Reading from a write-mostly device must take care not to
		 * over-take any writes that are 'behind'
		 */
		raid1_log(mddev, "wait behind writes");
		wait_event(bitmap->behind_wait,
			   atomic_read(&bitmap->behind_writes) == 0);
	}
	r1_bio->read_disk = rdisk;

	read_bio = bio_clone_fast(bio, GFP_NOIO, mddev->bio_set);
	bio_trim(read_bio, r1_bio->sector - bio->bi_iter.bi_sector,
		 max_sectors);

	r1_bio->bios[rdisk] = read_bio;

	read_bio->bi_iter.bi_sector = r1_bio->sector +
		mirror->rdev->data_offset;
	read_bio->bi_bdev = mirror->rdev->bdev;
	read_bio->bi_end_io = raid1_end_read_request;
	bio_set_op_attrs(read_bio, op, do_sync);
	if (test_bit(FailFast, &mirror->rdev->flags) &&
	    test_bit(R1BIO_FailFast, &r1_bio->state))
	        read_bio->bi_opf |= MD_FAILFAST;
	read_bio->bi_private = r1_bio;

	if (mddev->gendisk)
	        trace_block_bio_remap(bdev_get_queue(read_bio->bi_bdev),
	                              read_bio, disk_devt(mddev->gendisk),
	                              r1_bio->sector);

	if (max_sectors < r1_bio->sectors) {
		/*
		 * could not read all from this device, so we will need another
		 * r1_bio.
		 */
		sectors_handled = (r1_bio->sector + max_sectors
				   - bio->bi_iter.bi_sector);
		r1_bio->sectors = max_sectors;
		spin_lock_irq(&conf->device_lock);
		if (bio->bi_phys_segments == 0)
			bio->bi_phys_segments = 2;
		else
			bio->bi_phys_segments++;
		spin_unlock_irq(&conf->device_lock);

		/*
		 * Cannot call generic_make_request directly as that will be
		 * queued in __make_request and subsequent mempool_alloc might
		 * block waiting for it.  So hand bio over to raid1d.
		 */
		reschedule_retry(r1_bio);

		r1_bio = alloc_r1bio(mddev, bio, sectors_handled);
		goto read_again;
	} else
		generic_make_request(read_bio);
}

static void raid1_write_request(struct mddev *mddev, struct bio *bio)
{
	struct r1conf *conf = mddev->private;
	struct r1bio *r1_bio;
	int i, disks;
	struct bitmap *bitmap = mddev->bitmap;
	unsigned long flags;
	struct md_rdev *blocked_rdev;
	struct blk_plug_cb *cb;
	struct raid1_plug_cb *plug = NULL;
	int first_clone;
	int sectors_handled;
	int max_sectors;

	/*
	 * Register the new request and wait if the reconstruction
	 * thread has put up a bar for new requests.
	 * Continue immediately if no resync is active currently.
	 */

	md_write_start(mddev, bio); /* wait on superblock update early */

	if ((bio_end_sector(bio) > mddev->suspend_lo &&
	    bio->bi_iter.bi_sector < mddev->suspend_hi) ||
	    (mddev_is_clustered(mddev) &&
	     md_cluster_ops->area_resyncing(mddev, WRITE,
		     bio->bi_iter.bi_sector, bio_end_sector(bio)))) {

		/*
		 * As the suspend_* range is controlled by userspace, we want
		 * an interruptible wait.
		 */
		DEFINE_WAIT(w);
		for (;;) {
			flush_signals(current);
			prepare_to_wait(&conf->wait_barrier,
					&w, TASK_INTERRUPTIBLE);
			if (bio_end_sector(bio) <= mddev->suspend_lo ||
			    bio->bi_iter.bi_sector >= mddev->suspend_hi ||
			    (mddev_is_clustered(mddev) &&
			     !md_cluster_ops->area_resyncing(mddev, WRITE,
				     bio->bi_iter.bi_sector,
				     bio_end_sector(bio))))
				break;
			schedule();
		}
		finish_wait(&conf->wait_barrier, &w);
	}
	wait_barrier(conf, bio->bi_iter.bi_sector);

	r1_bio = alloc_r1bio(mddev, bio, 0);

	/* We might need to issue multiple writes to different
	 * devices if there are bad blocks around, so we keep
	 * track of the number of writes in bio->bi_phys_segments.
	 * If this is 0, there is only one r1_bio and no locking
	 * will be needed when requests complete.  If it is
	 * non-zero, then it is the number of not-completed requests.
	 */
	bio->bi_phys_segments = 0;
	bio_clear_flag(bio, BIO_SEG_VALID);

	if (conf->pending_count >= max_queued_requests) {
		md_wakeup_thread(mddev->thread);
		raid1_log(mddev, "wait queued");
		wait_event(conf->wait_barrier,
			   conf->pending_count < max_queued_requests);
	}
	/* first select target devices under rcu_lock and
	 * inc refcount on their rdev.  Record them by setting
	 * bios[x] to bio
	 * If there are known/acknowledged bad blocks on any device on
	 * which we have seen a write error, we want to avoid writing those
	 * blocks.
	 * This potentially requires several writes to write around
	 * the bad blocks.  Each set of writes gets it's own r1bio
	 * with a set of bios attached.
	 */

	disks = conf->raid_disks * 2;
 retry_write:
	blocked_rdev = NULL;
	rcu_read_lock();
	max_sectors = r1_bio->sectors;
	for (i = 0;  i < disks; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && unlikely(test_bit(Blocked, &rdev->flags))) {
			atomic_inc(&rdev->nr_pending);
			blocked_rdev = rdev;
			break;
		}
		r1_bio->bios[i] = NULL;
		if (!rdev || test_bit(Faulty, &rdev->flags)) {
			if (i < conf->raid_disks)
				set_bit(R1BIO_Degraded, &r1_bio->state);
			continue;
		}

		atomic_inc(&rdev->nr_pending);
		if (test_bit(WriteErrorSeen, &rdev->flags)) {
			sector_t first_bad;
			int bad_sectors;
			int is_bad;

			is_bad = is_badblock(rdev, r1_bio->sector, max_sectors,
					     &first_bad, &bad_sectors);
			if (is_bad < 0) {
				/* mustn't write here until the bad block is
				 * acknowledged*/
				set_bit(BlockedBadBlocks, &rdev->flags);
				blocked_rdev = rdev;
				break;
			}
			if (is_bad && first_bad <= r1_bio->sector) {
				/* Cannot write here at all */
				bad_sectors -= (r1_bio->sector - first_bad);
				if (bad_sectors < max_sectors)
					/* mustn't write more than bad_sectors
					 * to other devices yet
					 */
					max_sectors = bad_sectors;
				rdev_dec_pending(rdev, mddev);
				/* We don't set R1BIO_Degraded as that
				 * only applies if the disk is
				 * missing, so it might be re-added,
				 * and we want to know to recover this
				 * chunk.
				 * In this case the device is here,
				 * and the fact that this chunk is not
				 * in-sync is recorded in the bad
				 * block log
				 */
				continue;
			}
			if (is_bad) {
				int good_sectors = first_bad - r1_bio->sector;
				if (good_sectors < max_sectors)
					max_sectors = good_sectors;
			}
		}
		r1_bio->bios[i] = bio;
	}
	rcu_read_unlock();

	if (unlikely(blocked_rdev)) {
		/* Wait for this device to become unblocked */
		int j;

		for (j = 0; j < i; j++)
			if (r1_bio->bios[j])
				rdev_dec_pending(conf->mirrors[j].rdev, mddev);
		r1_bio->state = 0;
		allow_barrier(conf, bio->bi_iter.bi_sector);
		raid1_log(mddev, "wait rdev %d blocked", blocked_rdev->raid_disk);
		md_wait_for_blocked_rdev(blocked_rdev, mddev);
		wait_barrier(conf, bio->bi_iter.bi_sector);
		goto retry_write;
	}

	if (max_sectors < r1_bio->sectors) {
		/* We are splitting this write into multiple parts, so
		 * we need to prepare for allocating another r1_bio.
		 */
		r1_bio->sectors = max_sectors;
		spin_lock_irq(&conf->device_lock);
		if (bio->bi_phys_segments == 0)
			bio->bi_phys_segments = 2;
		else
			bio->bi_phys_segments++;
		spin_unlock_irq(&conf->device_lock);
	}
	sectors_handled = r1_bio->sector + max_sectors - bio->bi_iter.bi_sector;

	atomic_set(&r1_bio->remaining, 1);
	atomic_set(&r1_bio->behind_remaining, 0);

	first_clone = 1;
	for (i = 0; i < disks; i++) {
		struct bio *mbio = NULL;
		sector_t offset;
		if (!r1_bio->bios[i])
			continue;

		offset = r1_bio->sector - bio->bi_iter.bi_sector;

		if (first_clone) {
			/* do behind I/O ?
			 * Not if there are too many, or cannot
			 * allocate memory, or a reader on WriteMostly
			 * is waiting for behind writes to flush */
			if (bitmap &&
			    (atomic_read(&bitmap->behind_writes)
			     < mddev->bitmap_info.max_write_behind) &&
			    !waitqueue_active(&bitmap->behind_wait)) {
				mbio = bio_clone_bioset_partial(bio, GFP_NOIO,
								mddev->bio_set,
								offset << 9,
								max_sectors << 9);
				alloc_behind_pages(mbio, r1_bio);
			}

			bitmap_startwrite(bitmap, r1_bio->sector,
					  r1_bio->sectors,
					  test_bit(R1BIO_BehindIO,
						   &r1_bio->state));
			first_clone = 0;
		}

		if (!mbio) {
			if (r1_bio->behind_bvecs)
				mbio = bio_clone_bioset_partial(bio, GFP_NOIO,
								mddev->bio_set,
								offset << 9,
								max_sectors << 9);
			else {
				mbio = bio_clone_fast(bio, GFP_NOIO, mddev->bio_set);
				bio_trim(mbio, offset, max_sectors);
			}
		}

		if (r1_bio->behind_bvecs) {
			struct bio_vec *bvec;
			int j;

			/*
			 * We trimmed the bio, so _all is legit
			 */
			bio_for_each_segment_all(bvec, mbio, j)
				bvec->bv_page = r1_bio->behind_bvecs[j].bv_page;
			if (test_bit(WriteMostly, &conf->mirrors[i].rdev->flags))
				atomic_inc(&r1_bio->behind_remaining);
		}

		r1_bio->bios[i] = mbio;

		mbio->bi_iter.bi_sector	= (r1_bio->sector +
				   conf->mirrors[i].rdev->data_offset);
		mbio->bi_bdev = conf->mirrors[i].rdev->bdev;
		mbio->bi_end_io	= raid1_end_write_request;
		mbio->bi_opf = bio_op(bio) | (bio->bi_opf & (REQ_SYNC | REQ_FUA));
		if (test_bit(FailFast, &conf->mirrors[i].rdev->flags) &&
		    !test_bit(WriteMostly, &conf->mirrors[i].rdev->flags) &&
		    conf->raid_disks - mddev->degraded > 1)
			mbio->bi_opf |= MD_FAILFAST;
		mbio->bi_private = r1_bio;

		atomic_inc(&r1_bio->remaining);

		if (mddev->gendisk)
			trace_block_bio_remap(bdev_get_queue(mbio->bi_bdev),
					      mbio, disk_devt(mddev->gendisk),
					      r1_bio->sector);
		/* flush_pending_writes() needs access to the rdev so...*/
		mbio->bi_bdev = (void*)conf->mirrors[i].rdev;

		cb = blk_check_plugged(raid1_unplug, mddev, sizeof(*plug));
		if (cb)
			plug = container_of(cb, struct raid1_plug_cb, cb);
		else
			plug = NULL;
		spin_lock_irqsave(&conf->device_lock, flags);
		if (plug) {
			bio_list_add(&plug->pending, mbio);
			plug->pending_cnt++;
		} else {
			bio_list_add(&conf->pending_bio_list, mbio);
			conf->pending_count++;
		}
		spin_unlock_irqrestore(&conf->device_lock, flags);
		if (!plug)
			md_wakeup_thread(mddev->thread);
	}
	/* Mustn't call r1_bio_write_done before this next test,
	 * as it could result in the bio being freed.
	 */
	if (sectors_handled < bio_sectors(bio)) {
		r1_bio_write_done(r1_bio);
		/* We need another r1_bio.  It has already been counted
		 * in bio->bi_phys_segments
		 */
		r1_bio = alloc_r1bio(mddev, bio, sectors_handled);
		goto retry_write;
	}

	r1_bio_write_done(r1_bio);

	/* In case raid1d snuck in to freeze_array */
	wake_up(&conf->wait_barrier);
}

static void raid1_make_request(struct mddev *mddev, struct bio *bio)
{
	struct bio *split;
	sector_t sectors;

	if (unlikely(bio->bi_opf & REQ_PREFLUSH)) {
		md_flush_request(mddev, bio);
		return;
	}

	/* if bio exceeds barrier unit boundary, split it */
	do {
		sectors = align_to_barrier_unit_end(
				bio->bi_iter.bi_sector, bio_sectors(bio));
		if (sectors < bio_sectors(bio)) {
			split = bio_split(bio, sectors, GFP_NOIO, fs_bio_set);
			bio_chain(split, bio);
		} else {
			split = bio;
		}

		if (bio_data_dir(split) == READ) {
			raid1_read_request(mddev, split);

			/*
			 * If a bio is splitted, the first part of bio will
			 * pass barrier but the bio is queued in
			 * current->bio_list (see generic_make_request). If
			 * there is a raise_barrier() called here, the second
			 * part of bio can't pass barrier. But since the first
			 * part bio isn't dispatched to underlaying disks yet,
			 * the barrier is never released, hence raise_barrier
			 * will alays wait. We have a deadlock.
			 * Note, this only happens in read path. For write
			 * path, the first part of bio is dispatched in a
			 * schedule() call (because of blk plug) or offloaded
			 * to raid10d.
			 * Quitting from the function immediately can change
			 * the bio order queued in bio_list and avoid the deadlock.
			 */
			if (split != bio) {
				generic_make_request(bio);
				break;
			}
		} else
			raid1_write_request(mddev, split);
	} while (split != bio);
}

static void raid1_status(struct seq_file *seq, struct mddev *mddev)
{
	struct r1conf *conf = mddev->private;
	int i;

	seq_printf(seq, " [%d/%d] [", conf->raid_disks,
		   conf->raid_disks - mddev->degraded);
	rcu_read_lock();
	for (i = 0; i < conf->raid_disks; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		seq_printf(seq, "%s",
			   rdev && test_bit(In_sync, &rdev->flags) ? "U" : "_");
	}
	rcu_read_unlock();
	seq_printf(seq, "]");
}

static void raid1_error(struct mddev *mddev, struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];
	struct r1conf *conf = mddev->private;
	unsigned long flags;

	/*
	 * If it is not operational, then we have already marked it as dead
	 * else if it is the last working disks, ignore the error, let the
	 * next level up know.
	 * else mark the drive as failed
	 */
	spin_lock_irqsave(&conf->device_lock, flags);
	if (test_bit(In_sync, &rdev->flags)
	    && (conf->raid_disks - mddev->degraded) == 1) {
		/*
		 * Don't fail the drive, act as though we were just a
		 * normal single drive.
		 * However don't try a recovery from this drive as
		 * it is very likely to fail.
		 */
		conf->recovery_disabled = mddev->recovery_disabled;
		spin_unlock_irqrestore(&conf->device_lock, flags);
		return;
	}
	set_bit(Blocked, &rdev->flags);
	if (test_and_clear_bit(In_sync, &rdev->flags)) {
		mddev->degraded++;
		set_bit(Faulty, &rdev->flags);
	} else
		set_bit(Faulty, &rdev->flags);
	spin_unlock_irqrestore(&conf->device_lock, flags);
	/*
	 * if recovery is running, make sure it aborts.
	 */
	set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	set_mask_bits(&mddev->sb_flags, 0,
		      BIT(MD_SB_CHANGE_DEVS) | BIT(MD_SB_CHANGE_PENDING));
	pr_crit("md/raid1:%s: Disk failure on %s, disabling device.\n"
		"md/raid1:%s: Operation continuing on %d devices.\n",
		mdname(mddev), bdevname(rdev->bdev, b),
		mdname(mddev), conf->raid_disks - mddev->degraded);
}

static void print_conf(struct r1conf *conf)
{
	int i;

	pr_debug("RAID1 conf printout:\n");
	if (!conf) {
		pr_debug("(!conf)\n");
		return;
	}
	pr_debug(" --- wd:%d rd:%d\n", conf->raid_disks - conf->mddev->degraded,
		 conf->raid_disks);

	rcu_read_lock();
	for (i = 0; i < conf->raid_disks; i++) {
		char b[BDEVNAME_SIZE];
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev)
			pr_debug(" disk %d, wo:%d, o:%d, dev:%s\n",
				 i, !test_bit(In_sync, &rdev->flags),
				 !test_bit(Faulty, &rdev->flags),
				 bdevname(rdev->bdev,b));
	}
	rcu_read_unlock();
}

static void close_sync(struct r1conf *conf)
{
	wait_all_barriers(conf);
	allow_all_barriers(conf);

	mempool_destroy(conf->r1buf_pool);
	conf->r1buf_pool = NULL;
}

static int raid1_spare_active(struct mddev *mddev)
{
	int i;
	struct r1conf *conf = mddev->private;
	int count = 0;
	unsigned long flags;

	/*
	 * Find all failed disks within the RAID1 configuration
	 * and mark them readable.
	 * Called under mddev lock, so rcu protection not needed.
	 * device_lock used to avoid races with raid1_end_read_request
	 * which expects 'In_sync' flags and ->degraded to be consistent.
	 */
	spin_lock_irqsave(&conf->device_lock, flags);
	for (i = 0; i < conf->raid_disks; i++) {
		struct md_rdev *rdev = conf->mirrors[i].rdev;
		struct md_rdev *repl = conf->mirrors[conf->raid_disks + i].rdev;
		if (repl
		    && !test_bit(Candidate, &repl->flags)
		    && repl->recovery_offset == MaxSector
		    && !test_bit(Faulty, &repl->flags)
		    && !test_and_set_bit(In_sync, &repl->flags)) {
			/* replacement has just become active */
			if (!rdev ||
			    !test_and_clear_bit(In_sync, &rdev->flags))
				count++;
			if (rdev) {
				/* Replaced device not technically
				 * faulty, but we need to be sure
				 * it gets removed and never re-added
				 */
				set_bit(Faulty, &rdev->flags);
				sysfs_notify_dirent_safe(
					rdev->sysfs_state);
			}
		}
		if (rdev
		    && rdev->recovery_offset == MaxSector
		    && !test_bit(Faulty, &rdev->flags)
		    && !test_and_set_bit(In_sync, &rdev->flags)) {
			count++;
			sysfs_notify_dirent_safe(rdev->sysfs_state);
		}
	}
	mddev->degraded -= count;
	spin_unlock_irqrestore(&conf->device_lock, flags);

	print_conf(conf);
	return count;
}

static int raid1_add_disk(struct mddev *mddev, struct md_rdev *rdev)
{
	struct r1conf *conf = mddev->private;
	int err = -EEXIST;
	int mirror = 0;
	struct raid1_info *p;
	int first = 0;
	int last = conf->raid_disks - 1;

	if (mddev->recovery_disabled == conf->recovery_disabled)
		return -EBUSY;

	if (md_integrity_add_rdev(rdev, mddev))
		return -ENXIO;

	if (rdev->raid_disk >= 0)
		first = last = rdev->raid_disk;

	/*
	 * find the disk ... but prefer rdev->saved_raid_disk
	 * if possible.
	 */
	if (rdev->saved_raid_disk >= 0 &&
	    rdev->saved_raid_disk >= first &&
	    conf->mirrors[rdev->saved_raid_disk].rdev == NULL)
		first = last = rdev->saved_raid_disk;

	for (mirror = first; mirror <= last; mirror++) {
		p = conf->mirrors+mirror;
		if (!p->rdev) {

			if (mddev->gendisk)
				disk_stack_limits(mddev->gendisk, rdev->bdev,
						  rdev->data_offset << 9);

			p->head_position = 0;
			rdev->raid_disk = mirror;
			err = 0;
			/* As all devices are equivalent, we don't need a full recovery
			 * if this was recently any drive of the array
			 */
			if (rdev->saved_raid_disk < 0)
				conf->fullsync = 1;
			rcu_assign_pointer(p->rdev, rdev);
			break;
		}
		if (test_bit(WantReplacement, &p->rdev->flags) &&
		    p[conf->raid_disks].rdev == NULL) {
			/* Add this device as a replacement */
			clear_bit(In_sync, &rdev->flags);
			set_bit(Replacement, &rdev->flags);
			rdev->raid_disk = mirror;
			err = 0;
			conf->fullsync = 1;
			rcu_assign_pointer(p[conf->raid_disks].rdev, rdev);
			break;
		}
	}
	if (mddev->queue && blk_queue_discard(bdev_get_queue(rdev->bdev)))
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);
	print_conf(conf);
	return err;
}

static int raid1_remove_disk(struct mddev *mddev, struct md_rdev *rdev)
{
	struct r1conf *conf = mddev->private;
	int err = 0;
	int number = rdev->raid_disk;
	struct raid1_info *p = conf->mirrors + number;

	if (rdev != p->rdev)
		p = conf->mirrors + conf->raid_disks + number;

	print_conf(conf);
	if (rdev == p->rdev) {
		if (test_bit(In_sync, &rdev->flags) ||
		    atomic_read(&rdev->nr_pending)) {
			err = -EBUSY;
			goto abort;
		}
		/* Only remove non-faulty devices if recovery
		 * is not possible.
		 */
		if (!test_bit(Faulty, &rdev->flags) &&
		    mddev->recovery_disabled != conf->recovery_disabled &&
		    mddev->degraded < conf->raid_disks) {
			err = -EBUSY;
			goto abort;
		}
		p->rdev = NULL;
		if (!test_bit(RemoveSynchronized, &rdev->flags)) {
			synchronize_rcu();
			if (atomic_read(&rdev->nr_pending)) {
				/* lost the race, try later */
				err = -EBUSY;
				p->rdev = rdev;
				goto abort;
			}
		}
		if (conf->mirrors[conf->raid_disks + number].rdev) {
			/* We just removed a device that is being replaced.
			 * Move down the replacement.  We drain all IO before
			 * doing this to avoid confusion.
			 */
			struct md_rdev *repl =
				conf->mirrors[conf->raid_disks + number].rdev;
			freeze_array(conf, 0);
			clear_bit(Replacement, &repl->flags);
			p->rdev = repl;
			conf->mirrors[conf->raid_disks + number].rdev = NULL;
			unfreeze_array(conf);
			clear_bit(WantReplacement, &rdev->flags);
		} else
			clear_bit(WantReplacement, &rdev->flags);
		err = md_integrity_register(mddev);
	}
abort:

	print_conf(conf);
	return err;
}

static void end_sync_read(struct bio *bio)
{
	struct r1bio *r1_bio = bio->bi_private;

	update_head_pos(r1_bio->read_disk, r1_bio);

	/*
	 * we have read a block, now it needs to be re-written,
	 * or re-read if the read failed.
	 * We don't do much here, just schedule handling by raid1d
	 */
	if (!bio->bi_error)
		set_bit(R1BIO_Uptodate, &r1_bio->state);

	if (atomic_dec_and_test(&r1_bio->remaining))
		reschedule_retry(r1_bio);
}

static void end_sync_write(struct bio *bio)
{
	int uptodate = !bio->bi_error;
	struct r1bio *r1_bio = bio->bi_private;
	struct mddev *mddev = r1_bio->mddev;
	struct r1conf *conf = mddev->private;
	sector_t first_bad;
	int bad_sectors;
	struct md_rdev *rdev = conf->mirrors[find_bio_disk(r1_bio, bio)].rdev;

	if (!uptodate) {
		sector_t sync_blocks = 0;
		sector_t s = r1_bio->sector;
		long sectors_to_go = r1_bio->sectors;
		/* make sure these bits doesn't get cleared. */
		do {
			bitmap_end_sync(mddev->bitmap, s,
					&sync_blocks, 1);
			s += sync_blocks;
			sectors_to_go -= sync_blocks;
		} while (sectors_to_go > 0);
		set_bit(WriteErrorSeen, &rdev->flags);
		if (!test_and_set_bit(WantReplacement, &rdev->flags))
			set_bit(MD_RECOVERY_NEEDED, &
				mddev->recovery);
		set_bit(R1BIO_WriteError, &r1_bio->state);
	} else if (is_badblock(rdev, r1_bio->sector, r1_bio->sectors,
			       &first_bad, &bad_sectors) &&
		   !is_badblock(conf->mirrors[r1_bio->read_disk].rdev,
				r1_bio->sector,
				r1_bio->sectors,
				&first_bad, &bad_sectors)
		)
		set_bit(R1BIO_MadeGood, &r1_bio->state);

	if (atomic_dec_and_test(&r1_bio->remaining)) {
		int s = r1_bio->sectors;
		if (test_bit(R1BIO_MadeGood, &r1_bio->state) ||
		    test_bit(R1BIO_WriteError, &r1_bio->state))
			reschedule_retry(r1_bio);
		else {
			put_buf(r1_bio);
			md_done_sync(mddev, s, uptodate);
		}
	}
}

static int r1_sync_page_io(struct md_rdev *rdev, sector_t sector,
			    int sectors, struct page *page, int rw)
{
	if (sync_page_io(rdev, sector, sectors << 9, page, rw, 0, false))
		/* success */
		return 1;
	if (rw == WRITE) {
		set_bit(WriteErrorSeen, &rdev->flags);
		if (!test_and_set_bit(WantReplacement,
				      &rdev->flags))
			set_bit(MD_RECOVERY_NEEDED, &
				rdev->mddev->recovery);
	}
	/* need to record an error - either for the block or the device */
	if (!rdev_set_badblocks(rdev, sector, sectors, 0))
		md_error(rdev->mddev, rdev);
	return 0;
}

static int fix_sync_read_error(struct r1bio *r1_bio)
{
	/* Try some synchronous reads of other devices to get
	 * good data, much like with normal read errors.  Only
	 * read into the pages we already have so we don't
	 * need to re-issue the read request.
	 * We don't need to freeze the array, because being in an
	 * active sync request, there is no normal IO, and
	 * no overlapping syncs.
	 * We don't need to check is_badblock() again as we
	 * made sure that anything with a bad block in range
	 * will have bi_end_io clear.
	 */
	struct mddev *mddev = r1_bio->mddev;
	struct r1conf *conf = mddev->private;
	struct bio *bio = r1_bio->bios[r1_bio->read_disk];
	sector_t sect = r1_bio->sector;
	int sectors = r1_bio->sectors;
	int idx = 0;
	struct md_rdev *rdev;

	rdev = conf->mirrors[r1_bio->read_disk].rdev;
	if (test_bit(FailFast, &rdev->flags)) {
		/* Don't try recovering from here - just fail it
		 * ... unless it is the last working device of course */
		md_error(mddev, rdev);
		if (test_bit(Faulty, &rdev->flags))
			/* Don't try to read from here, but make sure
			 * put_buf does it's thing
			 */
			bio->bi_end_io = end_sync_write;
	}

	while(sectors) {
		int s = sectors;
		int d = r1_bio->read_disk;
		int success = 0;
		int start;

		if (s > (PAGE_SIZE>>9))
			s = PAGE_SIZE >> 9;
		do {
			if (r1_bio->bios[d]->bi_end_io == end_sync_read) {
				/* No rcu protection needed here devices
				 * can only be removed when no resync is
				 * active, and resync is currently active
				 */
				rdev = conf->mirrors[d].rdev;
				if (sync_page_io(rdev, sect, s<<9,
						 bio->bi_io_vec[idx].bv_page,
						 REQ_OP_READ, 0, false)) {
					success = 1;
					break;
				}
			}
			d++;
			if (d == conf->raid_disks * 2)
				d = 0;
		} while (!success && d != r1_bio->read_disk);

		if (!success) {
			char b[BDEVNAME_SIZE];
			int abort = 0;
			/* Cannot read from anywhere, this block is lost.
			 * Record a bad block on each device.  If that doesn't
			 * work just disable and interrupt the recovery.
			 * Don't fail devices as that won't really help.
			 */
			pr_crit_ratelimited("md/raid1:%s: %s: unrecoverable I/O read error for block %llu\n",
					    mdname(mddev),
					    bdevname(bio->bi_bdev, b),
					    (unsigned long long)r1_bio->sector);
			for (d = 0; d < conf->raid_disks * 2; d++) {
				rdev = conf->mirrors[d].rdev;
				if (!rdev || test_bit(Faulty, &rdev->flags))
					continue;
				if (!rdev_set_badblocks(rdev, sect, s, 0))
					abort = 1;
			}
			if (abort) {
				conf->recovery_disabled =
					mddev->recovery_disabled;
				set_bit(MD_RECOVERY_INTR, &mddev->recovery);
				md_done_sync(mddev, r1_bio->sectors, 0);
				put_buf(r1_bio);
				return 0;
			}
			/* Try next page */
			sectors -= s;
			sect += s;
			idx++;
			continue;
		}

		start = d;
		/* write it back and re-read */
		while (d != r1_bio->read_disk) {
			if (d == 0)
				d = conf->raid_disks * 2;
			d--;
			if (r1_bio->bios[d]->bi_end_io != end_sync_read)
				continue;
			rdev = conf->mirrors[d].rdev;
			if (r1_sync_page_io(rdev, sect, s,
					    bio->bi_io_vec[idx].bv_page,
					    WRITE) == 0) {
				r1_bio->bios[d]->bi_end_io = NULL;
				rdev_dec_pending(rdev, mddev);
			}
		}
		d = start;
		while (d != r1_bio->read_disk) {
			if (d == 0)
				d = conf->raid_disks * 2;
			d--;
			if (r1_bio->bios[d]->bi_end_io != end_sync_read)
				continue;
			rdev = conf->mirrors[d].rdev;
			if (r1_sync_page_io(rdev, sect, s,
					    bio->bi_io_vec[idx].bv_page,
					    READ) != 0)
				atomic_add(s, &rdev->corrected_errors);
		}
		sectors -= s;
		sect += s;
		idx ++;
	}
	set_bit(R1BIO_Uptodate, &r1_bio->state);
	bio->bi_error = 0;
	return 1;
}

static void process_checks(struct r1bio *r1_bio)
{
	/* We have read all readable devices.  If we haven't
	 * got the block, then there is no hope left.
	 * If we have, then we want to do a comparison
	 * and skip the write if everything is the same.
	 * If any blocks failed to read, then we need to
	 * attempt an over-write
	 */
	struct mddev *mddev = r1_bio->mddev;
	struct r1conf *conf = mddev->private;
	int primary;
	int i;
	int vcnt;

	/* Fix variable parts of all bios */
	vcnt = (r1_bio->sectors + PAGE_SIZE / 512 - 1) >> (PAGE_SHIFT - 9);
	for (i = 0; i < conf->raid_disks * 2; i++) {
		int j;
		int size;
		int error;
		struct bio *b = r1_bio->bios[i];
		if (b->bi_end_io != end_sync_read)
			continue;
		/* fixup the bio for reuse, but preserve errno */
		error = b->bi_error;
		bio_reset(b);
		b->bi_error = error;
		b->bi_vcnt = vcnt;
		b->bi_iter.bi_size = r1_bio->sectors << 9;
		b->bi_iter.bi_sector = r1_bio->sector +
			conf->mirrors[i].rdev->data_offset;
		b->bi_bdev = conf->mirrors[i].rdev->bdev;
		b->bi_end_io = end_sync_read;
		b->bi_private = r1_bio;

		size = b->bi_iter.bi_size;
		for (j = 0; j < vcnt ; j++) {
			struct bio_vec *bi;
			bi = &b->bi_io_vec[j];
			bi->bv_offset = 0;
			if (size > PAGE_SIZE)
				bi->bv_len = PAGE_SIZE;
			else
				bi->bv_len = size;
			size -= PAGE_SIZE;
		}
	}
	for (primary = 0; primary < conf->raid_disks * 2; primary++)
		if (r1_bio->bios[primary]->bi_end_io == end_sync_read &&
		    !r1_bio->bios[primary]->bi_error) {
			r1_bio->bios[primary]->bi_end_io = NULL;
			rdev_dec_pending(conf->mirrors[primary].rdev, mddev);
			break;
		}
	r1_bio->read_disk = primary;
	for (i = 0; i < conf->raid_disks * 2; i++) {
		int j;
		struct bio *pbio = r1_bio->bios[primary];
		struct bio *sbio = r1_bio->bios[i];
		int error = sbio->bi_error;

		if (sbio->bi_end_io != end_sync_read)
			continue;
		/* Now we can 'fixup' the error value */
		sbio->bi_error = 0;

		if (!error) {
			for (j = vcnt; j-- ; ) {
				struct page *p, *s;
				p = pbio->bi_io_vec[j].bv_page;
				s = sbio->bi_io_vec[j].bv_page;
				if (memcmp(page_address(p),
					   page_address(s),
					   sbio->bi_io_vec[j].bv_len))
					break;
			}
		} else
			j = 0;
		if (j >= 0)
			atomic64_add(r1_bio->sectors, &mddev->resync_mismatches);
		if (j < 0 || (test_bit(MD_RECOVERY_CHECK, &mddev->recovery)
			      && !error)) {
			/* No need to write to this device. */
			sbio->bi_end_io = NULL;
			rdev_dec_pending(conf->mirrors[i].rdev, mddev);
			continue;
		}

		bio_copy_data(sbio, pbio);
	}
}

static void sync_request_write(struct mddev *mddev, struct r1bio *r1_bio)
{
	struct r1conf *conf = mddev->private;
	int i;
	int disks = conf->raid_disks * 2;
	struct bio *bio, *wbio;

	bio = r1_bio->bios[r1_bio->read_disk];

	if (!test_bit(R1BIO_Uptodate, &r1_bio->state))
		/* ouch - failed to read all of that. */
		if (!fix_sync_read_error(r1_bio))
			return;

	if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
		process_checks(r1_bio);

	/*
	 * schedule writes
	 */
	atomic_set(&r1_bio->remaining, 1);
	for (i = 0; i < disks ; i++) {
		wbio = r1_bio->bios[i];
		if (wbio->bi_end_io == NULL ||
		    (wbio->bi_end_io == end_sync_read &&
		     (i == r1_bio->read_disk ||
		      !test_bit(MD_RECOVERY_SYNC, &mddev->recovery))))
			continue;

		bio_set_op_attrs(wbio, REQ_OP_WRITE, 0);
		if (test_bit(FailFast, &conf->mirrors[i].rdev->flags))
			wbio->bi_opf |= MD_FAILFAST;

		wbio->bi_end_io = end_sync_write;
		atomic_inc(&r1_bio->remaining);
		md_sync_acct(conf->mirrors[i].rdev->bdev, bio_sectors(wbio));

		generic_make_request(wbio);
	}

	if (atomic_dec_and_test(&r1_bio->remaining)) {
		/* if we're here, all write(s) have completed, so clean up */
		int s = r1_bio->sectors;
		if (test_bit(R1BIO_MadeGood, &r1_bio->state) ||
		    test_bit(R1BIO_WriteError, &r1_bio->state))
			reschedule_retry(r1_bio);
		else {
			put_buf(r1_bio);
			md_done_sync(mddev, s, 1);
		}
	}
}

/*
 * This is a kernel thread which:
 *
 *	1.	Retries failed read operations on working mirrors.
 *	2.	Updates the raid superblock when problems encounter.
 *	3.	Performs writes following reads for array synchronising.
 */

static void fix_read_error(struct r1conf *conf, int read_disk,
			   sector_t sect, int sectors)
{
	struct mddev *mddev = conf->mddev;
	while(sectors) {
		int s = sectors;
		int d = read_disk;
		int success = 0;
		int start;
		struct md_rdev *rdev;

		if (s > (PAGE_SIZE>>9))
			s = PAGE_SIZE >> 9;

		do {
			sector_t first_bad;
			int bad_sectors;

			rcu_read_lock();
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (rdev &&
			    (test_bit(In_sync, &rdev->flags) ||
			     (!test_bit(Faulty, &rdev->flags) &&
			      rdev->recovery_offset >= sect + s)) &&
			    is_badblock(rdev, sect, s,
					&first_bad, &bad_sectors) == 0) {
				atomic_inc(&rdev->nr_pending);
				rcu_read_unlock();
				if (sync_page_io(rdev, sect, s<<9,
					 conf->tmppage, REQ_OP_READ, 0, false))
					success = 1;
				rdev_dec_pending(rdev, mddev);
				if (success)
					break;
			} else
				rcu_read_unlock();
			d++;
			if (d == conf->raid_disks * 2)
				d = 0;
		} while (!success && d != read_disk);

		if (!success) {
			/* Cannot read from anywhere - mark it bad */
			struct md_rdev *rdev = conf->mirrors[read_disk].rdev;
			if (!rdev_set_badblocks(rdev, sect, s, 0))
				md_error(mddev, rdev);
			break;
		}
		/* write it back and re-read */
		start = d;
		while (d != read_disk) {
			if (d==0)
				d = conf->raid_disks * 2;
			d--;
			rcu_read_lock();
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (rdev &&
			    !test_bit(Faulty, &rdev->flags)) {
				atomic_inc(&rdev->nr_pending);
				rcu_read_unlock();
				r1_sync_page_io(rdev, sect, s,
						conf->tmppage, WRITE);
				rdev_dec_pending(rdev, mddev);
			} else
				rcu_read_unlock();
		}
		d = start;
		while (d != read_disk) {
			char b[BDEVNAME_SIZE];
			if (d==0)
				d = conf->raid_disks * 2;
			d--;
			rcu_read_lock();
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (rdev &&
			    !test_bit(Faulty, &rdev->flags)) {
				atomic_inc(&rdev->nr_pending);
				rcu_read_unlock();
				if (r1_sync_page_io(rdev, sect, s,
						    conf->tmppage, READ)) {
					atomic_add(s, &rdev->corrected_errors);
					pr_info("md/raid1:%s: read error corrected (%d sectors at %llu on %s)\n",
						mdname(mddev), s,
						(unsigned long long)(sect +
								     rdev->data_offset),
						bdevname(rdev->bdev, b));
				}
				rdev_dec_pending(rdev, mddev);
			} else
				rcu_read_unlock();
		}
		sectors -= s;
		sect += s;
	}
}

static int narrow_write_error(struct r1bio *r1_bio, int i)
{
	struct mddev *mddev = r1_bio->mddev;
	struct r1conf *conf = mddev->private;
	struct md_rdev *rdev = conf->mirrors[i].rdev;

	/* bio has the data to be written to device 'i' where
	 * we just recently had a write error.
	 * We repeatedly clone the bio and trim down to one block,
	 * then try the write.  Where the write fails we record
	 * a bad block.
	 * It is conceivable that the bio doesn't exactly align with
	 * blocks.  We must handle this somehow.
	 *
	 * We currently own a reference on the rdev.
	 */

	int block_sectors;
	sector_t sector;
	int sectors;
	int sect_to_write = r1_bio->sectors;
	int ok = 1;

	if (rdev->badblocks.shift < 0)
		return 0;

	block_sectors = roundup(1 << rdev->badblocks.shift,
				bdev_logical_block_size(rdev->bdev) >> 9);
	sector = r1_bio->sector;
	sectors = ((sector + block_sectors)
		   & ~(sector_t)(block_sectors - 1))
		- sector;

	while (sect_to_write) {
		struct bio *wbio;
		if (sectors > sect_to_write)
			sectors = sect_to_write;
		/* Write at 'sector' for 'sectors'*/

		if (test_bit(R1BIO_BehindIO, &r1_bio->state)) {
			unsigned vcnt = r1_bio->behind_page_count;
			struct bio_vec *vec = r1_bio->behind_bvecs;

			while (!vec->bv_page) {
				vec++;
				vcnt--;
			}

			wbio = bio_alloc_mddev(GFP_NOIO, vcnt, mddev);
			memcpy(wbio->bi_io_vec, vec, vcnt * sizeof(struct bio_vec));

			wbio->bi_vcnt = vcnt;
		} else {
			wbio = bio_clone_fast(r1_bio->master_bio, GFP_NOIO,
					      mddev->bio_set);
		}

		bio_set_op_attrs(wbio, REQ_OP_WRITE, 0);
		wbio->bi_iter.bi_sector = r1_bio->sector;
		wbio->bi_iter.bi_size = r1_bio->sectors << 9;

		bio_trim(wbio, sector - r1_bio->sector, sectors);
		wbio->bi_iter.bi_sector += rdev->data_offset;
		wbio->bi_bdev = rdev->bdev;

		if (submit_bio_wait(wbio) < 0)
			/* failure! */
			ok = rdev_set_badblocks(rdev, sector,
						sectors, 0)
				&& ok;

		bio_put(wbio);
		sect_to_write -= sectors;
		sector += sectors;
		sectors = block_sectors;
	}
	return ok;
}

static void handle_sync_write_finished(struct r1conf *conf, struct r1bio *r1_bio)
{
	int m;
	int s = r1_bio->sectors;
	for (m = 0; m < conf->raid_disks * 2 ; m++) {
		struct md_rdev *rdev = conf->mirrors[m].rdev;
		struct bio *bio = r1_bio->bios[m];
		if (bio->bi_end_io == NULL)
			continue;
		if (!bio->bi_error &&
		    test_bit(R1BIO_MadeGood, &r1_bio->state)) {
			rdev_clear_badblocks(rdev, r1_bio->sector, s, 0);
		}
		if (bio->bi_error &&
		    test_bit(R1BIO_WriteError, &r1_bio->state)) {
			if (!rdev_set_badblocks(rdev, r1_bio->sector, s, 0))
				md_error(conf->mddev, rdev);
		}
	}
	put_buf(r1_bio);
	md_done_sync(conf->mddev, s, 1);
}

static void handle_write_finished(struct r1conf *conf, struct r1bio *r1_bio)
{
	int m, idx;
	bool fail = false;

	for (m = 0; m < conf->raid_disks * 2 ; m++)
		if (r1_bio->bios[m] == IO_MADE_GOOD) {
			struct md_rdev *rdev = conf->mirrors[m].rdev;
			rdev_clear_badblocks(rdev,
					     r1_bio->sector,
					     r1_bio->sectors, 0);
			rdev_dec_pending(rdev, conf->mddev);
		} else if (r1_bio->bios[m] != NULL) {
			/* This drive got a write error.  We need to
			 * narrow down and record precise write
			 * errors.
			 */
			fail = true;
			if (!narrow_write_error(r1_bio, m)) {
				md_error(conf->mddev,
					 conf->mirrors[m].rdev);
				/* an I/O failed, we can't clear the bitmap */
				set_bit(R1BIO_Degraded, &r1_bio->state);
			}
			rdev_dec_pending(conf->mirrors[m].rdev,
					 conf->mddev);
		}
	if (fail) {
		spin_lock_irq(&conf->device_lock);
		list_add(&r1_bio->retry_list, &conf->bio_end_io_list);
		idx = sector_to_idx(r1_bio->sector);
		atomic_inc(&conf->nr_queued[idx]);
		spin_unlock_irq(&conf->device_lock);
		/*
		 * In case freeze_array() is waiting for condition
		 * get_unqueued_pending() == extra to be true.
		 */
		wake_up(&conf->wait_barrier);
		md_wakeup_thread(conf->mddev->thread);
	} else {
		if (test_bit(R1BIO_WriteError, &r1_bio->state))
			close_write(r1_bio);
		raid_end_bio_io(r1_bio);
	}
}

static void handle_read_error(struct r1conf *conf, struct r1bio *r1_bio)
{
	int disk;
	int max_sectors;
	struct mddev *mddev = conf->mddev;
	struct bio *bio;
	char b[BDEVNAME_SIZE];
	struct md_rdev *rdev;
	dev_t bio_dev;
	sector_t bio_sector;

	clear_bit(R1BIO_ReadError, &r1_bio->state);
	/* we got a read error. Maybe the drive is bad.  Maybe just
	 * the block and we can fix it.
	 * We freeze all other IO, and try reading the block from
	 * other devices.  When we find one, we re-write
	 * and check it that fixes the read error.
	 * This is all done synchronously while the array is
	 * frozen
	 */

	bio = r1_bio->bios[r1_bio->read_disk];
	bdevname(bio->bi_bdev, b);
	bio_dev = bio->bi_bdev->bd_dev;
	bio_sector = conf->mirrors[r1_bio->read_disk].rdev->data_offset + r1_bio->sector;
	bio_put(bio);
	r1_bio->bios[r1_bio->read_disk] = NULL;

	rdev = conf->mirrors[r1_bio->read_disk].rdev;
	if (mddev->ro == 0
	    && !test_bit(FailFast, &rdev->flags)) {
		freeze_array(conf, 1);
		fix_read_error(conf, r1_bio->read_disk,
			       r1_bio->sector, r1_bio->sectors);
		unfreeze_array(conf);
	} else {
		r1_bio->bios[r1_bio->read_disk] = IO_BLOCKED;
	}

	rdev_dec_pending(rdev, conf->mddev);

read_more:
	disk = read_balance(conf, r1_bio, &max_sectors);
	if (disk == -1) {
		pr_crit_ratelimited("md/raid1:%s: %s: unrecoverable I/O read error for block %llu\n",
				    mdname(mddev), b, (unsigned long long)r1_bio->sector);
		raid_end_bio_io(r1_bio);
	} else {
		const unsigned long do_sync
			= r1_bio->master_bio->bi_opf & REQ_SYNC;
		r1_bio->read_disk = disk;
		bio = bio_clone_fast(r1_bio->master_bio, GFP_NOIO,
				     mddev->bio_set);
		bio_trim(bio, r1_bio->sector - bio->bi_iter.bi_sector,
			 max_sectors);
		r1_bio->bios[r1_bio->read_disk] = bio;
		rdev = conf->mirrors[disk].rdev;
		pr_info_ratelimited("md/raid1:%s: redirecting sector %llu to other mirror: %s\n",
				    mdname(mddev),
				    (unsigned long long)r1_bio->sector,
				    bdevname(rdev->bdev, b));
		bio->bi_iter.bi_sector = r1_bio->sector + rdev->data_offset;
		bio->bi_bdev = rdev->bdev;
		bio->bi_end_io = raid1_end_read_request;
		bio_set_op_attrs(bio, REQ_OP_READ, do_sync);
		if (test_bit(FailFast, &rdev->flags) &&
		    test_bit(R1BIO_FailFast, &r1_bio->state))
			bio->bi_opf |= MD_FAILFAST;
		bio->bi_private = r1_bio;
		if (max_sectors < r1_bio->sectors) {
			/* Drat - have to split this up more */
			struct bio *mbio = r1_bio->master_bio;
			int sectors_handled = (r1_bio->sector + max_sectors
					       - mbio->bi_iter.bi_sector);
			r1_bio->sectors = max_sectors;
			spin_lock_irq(&conf->device_lock);
			if (mbio->bi_phys_segments == 0)
				mbio->bi_phys_segments = 2;
			else
				mbio->bi_phys_segments++;
			spin_unlock_irq(&conf->device_lock);
			trace_block_bio_remap(bdev_get_queue(bio->bi_bdev),
					      bio, bio_dev, bio_sector);
			generic_make_request(bio);
			bio = NULL;

			r1_bio = alloc_r1bio(mddev, mbio, sectors_handled);
			set_bit(R1BIO_ReadError, &r1_bio->state);

			goto read_more;
		} else {
			trace_block_bio_remap(bdev_get_queue(bio->bi_bdev),
					      bio, bio_dev, bio_sector);
			generic_make_request(bio);
		}
	}
}

static void raid1d(struct md_thread *thread)
{
	struct mddev *mddev = thread->mddev;
	struct r1bio *r1_bio;
	unsigned long flags;
	struct r1conf *conf = mddev->private;
	struct list_head *head = &conf->retry_list;
	struct blk_plug plug;
	int idx;

	md_check_recovery(mddev);

	if (!list_empty_careful(&conf->bio_end_io_list) &&
	    !test_bit(MD_SB_CHANGE_PENDING, &mddev->sb_flags)) {
		LIST_HEAD(tmp);
		spin_lock_irqsave(&conf->device_lock, flags);
		if (!test_bit(MD_SB_CHANGE_PENDING, &mddev->sb_flags))
			list_splice_init(&conf->bio_end_io_list, &tmp);
		spin_unlock_irqrestore(&conf->device_lock, flags);
		while (!list_empty(&tmp)) {
			r1_bio = list_first_entry(&tmp, struct r1bio,
						  retry_list);
			list_del(&r1_bio->retry_list);
			idx = sector_to_idx(r1_bio->sector);
			atomic_dec(&conf->nr_queued[idx]);
			if (mddev->degraded)
				set_bit(R1BIO_Degraded, &r1_bio->state);
			if (test_bit(R1BIO_WriteError, &r1_bio->state))
				close_write(r1_bio);
			raid_end_bio_io(r1_bio);
		}
	}

	blk_start_plug(&plug);
	for (;;) {

		flush_pending_writes(conf);

		spin_lock_irqsave(&conf->device_lock, flags);
		if (list_empty(head)) {
			spin_unlock_irqrestore(&conf->device_lock, flags);
			break;
		}
		r1_bio = list_entry(head->prev, struct r1bio, retry_list);
		list_del(head->prev);
		idx = sector_to_idx(r1_bio->sector);
		atomic_dec(&conf->nr_queued[idx]);
		spin_unlock_irqrestore(&conf->device_lock, flags);

		mddev = r1_bio->mddev;
		conf = mddev->private;
		if (test_bit(R1BIO_IsSync, &r1_bio->state)) {
			if (test_bit(R1BIO_MadeGood, &r1_bio->state) ||
			    test_bit(R1BIO_WriteError, &r1_bio->state))
				handle_sync_write_finished(conf, r1_bio);
			else
				sync_request_write(mddev, r1_bio);
		} else if (test_bit(R1BIO_MadeGood, &r1_bio->state) ||
			   test_bit(R1BIO_WriteError, &r1_bio->state))
			handle_write_finished(conf, r1_bio);
		else if (test_bit(R1BIO_ReadError, &r1_bio->state))
			handle_read_error(conf, r1_bio);
		else
			/* just a partial read to be scheduled from separate
			 * context
			 */
			generic_make_request(r1_bio->bios[r1_bio->read_disk]);

		cond_resched();
		if (mddev->sb_flags & ~(1<<MD_SB_CHANGE_PENDING))
			md_check_recovery(mddev);
	}
	blk_finish_plug(&plug);
}

static int init_resync(struct r1conf *conf)
{
	int buffs;

	buffs = RESYNC_WINDOW / RESYNC_BLOCK_SIZE;
	BUG_ON(conf->r1buf_pool);
	conf->r1buf_pool = mempool_create(buffs, r1buf_pool_alloc, r1buf_pool_free,
					  conf->poolinfo);
	if (!conf->r1buf_pool)
		return -ENOMEM;
	return 0;
}

/*
 * perform a "sync" on one "block"
 *
 * We need to make sure that no normal I/O request - particularly write
 * requests - conflict with active sync requests.
 *
 * This is achieved by tracking pending requests and a 'barrier' concept
 * that can be installed to exclude normal IO requests.
 */

static sector_t raid1_sync_request(struct mddev *mddev, sector_t sector_nr,
				   int *skipped)
{
	struct r1conf *conf = mddev->private;
	struct r1bio *r1_bio;
	struct bio *bio;
	sector_t max_sector, nr_sectors;
	int disk = -1;
	int i;
	int wonly = -1;
	int write_targets = 0, read_targets = 0;
	sector_t sync_blocks;
	int still_degraded = 0;
	int good_sectors = RESYNC_SECTORS;
	int min_bad = 0; /* number of sectors that are bad in all devices */
	int idx = sector_to_idx(sector_nr);

	if (!conf->r1buf_pool)
		if (init_resync(conf))
			return 0;

	max_sector = mddev->dev_sectors;
	if (sector_nr >= max_sector) {
		/* If we aborted, we need to abort the
		 * sync on the 'current' bitmap chunk (there will
		 * only be one in raid1 resync.
		 * We can find the current addess in mddev->curr_resync
		 */
		if (mddev->curr_resync < max_sector) /* aborted */
			bitmap_end_sync(mddev->bitmap, mddev->curr_resync,
						&sync_blocks, 1);
		else /* completed sync */
			conf->fullsync = 0;

		bitmap_close_sync(mddev->bitmap);
		close_sync(conf);

		if (mddev_is_clustered(mddev)) {
			conf->cluster_sync_low = 0;
			conf->cluster_sync_high = 0;
		}
		return 0;
	}

	if (mddev->bitmap == NULL &&
	    mddev->recovery_cp == MaxSector &&
	    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery) &&
	    conf->fullsync == 0) {
		*skipped = 1;
		return max_sector - sector_nr;
	}
	/* before building a request, check if we can skip these blocks..
	 * This call the bitmap_start_sync doesn't actually record anything
	 */
	if (!bitmap_start_sync(mddev->bitmap, sector_nr, &sync_blocks, 1) &&
	    !conf->fullsync && !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		/* We can skip this block, and probably several more */
		*skipped = 1;
		return sync_blocks;
	}

	/*
	 * If there is non-resync activity waiting for a turn, then let it
	 * though before starting on this new sync request.
	 */
	if (atomic_read(&conf->nr_waiting[idx]))
		schedule_timeout_uninterruptible(1);

	/* we are incrementing sector_nr below. To be safe, we check against
	 * sector_nr + two times RESYNC_SECTORS
	 */

	bitmap_cond_end_sync(mddev->bitmap, sector_nr,
		mddev_is_clustered(mddev) && (sector_nr + 2 * RESYNC_SECTORS > conf->cluster_sync_high));
	r1_bio = mempool_alloc(conf->r1buf_pool, GFP_NOIO);

	raise_barrier(conf, sector_nr);

	rcu_read_lock();
	/*
	 * If we get a correctably read error during resync or recovery,
	 * we might want to read from a different device.  So we
	 * flag all drives that could conceivably be read from for READ,
	 * and any others (which will be non-In_sync devices) for WRITE.
	 * If a read fails, we try reading from something else for which READ
	 * is OK.
	 */

	r1_bio->mddev = mddev;
	r1_bio->sector = sector_nr;
	r1_bio->state = 0;
	set_bit(R1BIO_IsSync, &r1_bio->state);
	/* make sure good_sectors won't go across barrier unit boundary */
	good_sectors = align_to_barrier_unit_end(sector_nr, good_sectors);

	for (i = 0; i < conf->raid_disks * 2; i++) {
		struct md_rdev *rdev;
		bio = r1_bio->bios[i];
		bio_reset(bio);

		rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev == NULL ||
		    test_bit(Faulty, &rdev->flags)) {
			if (i < conf->raid_disks)
				still_degraded = 1;
		} else if (!test_bit(In_sync, &rdev->flags)) {
			bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
			bio->bi_end_io = end_sync_write;
			write_targets ++;
		} else {
			/* may need to read from here */
			sector_t first_bad = MaxSector;
			int bad_sectors;

			if (is_badblock(rdev, sector_nr, good_sectors,
					&first_bad, &bad_sectors)) {
				if (first_bad > sector_nr)
					good_sectors = first_bad - sector_nr;
				else {
					bad_sectors -= (sector_nr - first_bad);
					if (min_bad == 0 ||
					    min_bad > bad_sectors)
						min_bad = bad_sectors;
				}
			}
			if (sector_nr < first_bad) {
				if (test_bit(WriteMostly, &rdev->flags)) {
					if (wonly < 0)
						wonly = i;
				} else {
					if (disk < 0)
						disk = i;
				}
				bio_set_op_attrs(bio, REQ_OP_READ, 0);
				bio->bi_end_io = end_sync_read;
				read_targets++;
			} else if (!test_bit(WriteErrorSeen, &rdev->flags) &&
				test_bit(MD_RECOVERY_SYNC, &mddev->recovery) &&
				!test_bit(MD_RECOVERY_CHECK, &mddev->recovery)) {
				/*
				 * The device is suitable for reading (InSync),
				 * but has bad block(s) here. Let's try to correct them,
				 * if we are doing resync or repair. Otherwise, leave
				 * this device alone for this sync request.
				 */
				bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
				bio->bi_end_io = end_sync_write;
				write_targets++;
			}
		}
		if (bio->bi_end_io) {
			atomic_inc(&rdev->nr_pending);
			bio->bi_iter.bi_sector = sector_nr + rdev->data_offset;
			bio->bi_bdev = rdev->bdev;
			bio->bi_private = r1_bio;
			if (test_bit(FailFast, &rdev->flags))
				bio->bi_opf |= MD_FAILFAST;
		}
	}
	rcu_read_unlock();
	if (disk < 0)
		disk = wonly;
	r1_bio->read_disk = disk;

	if (read_targets == 0 && min_bad > 0) {
		/* These sectors are bad on all InSync devices, so we
		 * need to mark them bad on all write targets
		 */
		int ok = 1;
		for (i = 0 ; i < conf->raid_disks * 2 ; i++)
			if (r1_bio->bios[i]->bi_end_io == end_sync_write) {
				struct md_rdev *rdev = conf->mirrors[i].rdev;
				ok = rdev_set_badblocks(rdev, sector_nr,
							min_bad, 0
					) && ok;
			}
		set_bit(MD_SB_CHANGE_DEVS, &mddev->sb_flags);
		*skipped = 1;
		put_buf(r1_bio);

		if (!ok) {
			/* Cannot record the badblocks, so need to
			 * abort the resync.
			 * If there are multiple read targets, could just
			 * fail the really bad ones ???
			 */
			conf->recovery_disabled = mddev->recovery_disabled;
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
			return 0;
		} else
			return min_bad;

	}
	if (min_bad > 0 && min_bad < good_sectors) {
		/* only resync enough to reach the next bad->good
		 * transition */
		good_sectors = min_bad;
	}

	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) && read_targets > 0)
		/* extra read targets are also write targets */
		write_targets += read_targets-1;

	if (write_targets == 0 || read_targets == 0) {
		/* There is nowhere to write, so all non-sync
		 * drives must be failed - so we are finished
		 */
		sector_t rv;
		if (min_bad > 0)
			max_sector = sector_nr + min_bad;
		rv = max_sector - sector_nr;
		*skipped = 1;
		put_buf(r1_bio);
		return rv;
	}

	if (max_sector > mddev->resync_max)
		max_sector = mddev->resync_max; /* Don't do IO beyond here */
	if (max_sector > sector_nr + good_sectors)
		max_sector = sector_nr + good_sectors;
	nr_sectors = 0;
	sync_blocks = 0;
	do {
		struct page *page;
		int len = PAGE_SIZE;
		if (sector_nr + (len>>9) > max_sector)
			len = (max_sector - sector_nr) << 9;
		if (len == 0)
			break;
		if (sync_blocks == 0) {
			if (!bitmap_start_sync(mddev->bitmap, sector_nr,
					       &sync_blocks, still_degraded) &&
			    !conf->fullsync &&
			    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
				break;
			if ((len >> 9) > sync_blocks)
				len = sync_blocks<<9;
		}

		for (i = 0 ; i < conf->raid_disks * 2; i++) {
			bio = r1_bio->bios[i];
			if (bio->bi_end_io) {
				page = bio->bi_io_vec[bio->bi_vcnt].bv_page;
				if (bio_add_page(bio, page, len, 0) == 0) {
					/* stop here */
					bio->bi_io_vec[bio->bi_vcnt].bv_page = page;
					while (i > 0) {
						i--;
						bio = r1_bio->bios[i];
						if (bio->bi_end_io==NULL)
							continue;
						/* remove last page from this bio */
						bio->bi_vcnt--;
						bio->bi_iter.bi_size -= len;
						bio_clear_flag(bio, BIO_SEG_VALID);
					}
					goto bio_full;
				}
			}
		}
		nr_sectors += len>>9;
		sector_nr += len>>9;
		sync_blocks -= (len>>9);
	} while (r1_bio->bios[disk]->bi_vcnt < RESYNC_PAGES);
 bio_full:
	r1_bio->sectors = nr_sectors;

	if (mddev_is_clustered(mddev) &&
			conf->cluster_sync_high < sector_nr + nr_sectors) {
		conf->cluster_sync_low = mddev->curr_resync_completed;
		conf->cluster_sync_high = conf->cluster_sync_low + CLUSTER_RESYNC_WINDOW_SECTORS;
		/* Send resync message */
		md_cluster_ops->resync_info_update(mddev,
				conf->cluster_sync_low,
				conf->cluster_sync_high);
	}

	/* For a user-requested sync, we read all readable devices and do a
	 * compare
	 */
	if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		atomic_set(&r1_bio->remaining, read_targets);
		for (i = 0; i < conf->raid_disks * 2 && read_targets; i++) {
			bio = r1_bio->bios[i];
			if (bio->bi_end_io == end_sync_read) {
				read_targets--;
				md_sync_acct(bio->bi_bdev, nr_sectors);
				if (read_targets == 1)
					bio->bi_opf &= ~MD_FAILFAST;
				generic_make_request(bio);
			}
		}
	} else {
		atomic_set(&r1_bio->remaining, 1);
		bio = r1_bio->bios[r1_bio->read_disk];
		md_sync_acct(bio->bi_bdev, nr_sectors);
		if (read_targets == 1)
			bio->bi_opf &= ~MD_FAILFAST;
		generic_make_request(bio);

	}
	return nr_sectors;
}

static sector_t raid1_size(struct mddev *mddev, sector_t sectors, int raid_disks)
{
	if (sectors)
		return sectors;

	return mddev->dev_sectors;
}

static struct r1conf *setup_conf(struct mddev *mddev)
{
	struct r1conf *conf;
	int i;
	struct raid1_info *disk;
	struct md_rdev *rdev;
	int err = -ENOMEM;

	conf = kzalloc(sizeof(struct r1conf), GFP_KERNEL);
	if (!conf)
		goto abort;

	conf->nr_pending = kcalloc(BARRIER_BUCKETS_NR,
				   sizeof(atomic_t), GFP_KERNEL);
	if (!conf->nr_pending)
		goto abort;

	conf->nr_waiting = kcalloc(BARRIER_BUCKETS_NR,
				   sizeof(atomic_t), GFP_KERNEL);
	if (!conf->nr_waiting)
		goto abort;

	conf->nr_queued = kcalloc(BARRIER_BUCKETS_NR,
				  sizeof(atomic_t), GFP_KERNEL);
	if (!conf->nr_queued)
		goto abort;

	conf->barrier = kcalloc(BARRIER_BUCKETS_NR,
				sizeof(atomic_t), GFP_KERNEL);
	if (!conf->barrier)
		goto abort;

	conf->mirrors = kzalloc(sizeof(struct raid1_info)
				* mddev->raid_disks * 2,
				 GFP_KERNEL);
	if (!conf->mirrors)
		goto abort;

	conf->tmppage = alloc_page(GFP_KERNEL);
	if (!conf->tmppage)
		goto abort;

	conf->poolinfo = kzalloc(sizeof(*conf->poolinfo), GFP_KERNEL);
	if (!conf->poolinfo)
		goto abort;
	conf->poolinfo->raid_disks = mddev->raid_disks * 2;
	conf->r1bio_pool = mempool_create(NR_RAID1_BIOS, r1bio_pool_alloc,
					  r1bio_pool_free,
					  conf->poolinfo);
	if (!conf->r1bio_pool)
		goto abort;

	conf->poolinfo->mddev = mddev;

	err = -EINVAL;
	spin_lock_init(&conf->device_lock);
	rdev_for_each(rdev, mddev) {
		struct request_queue *q;
		int disk_idx = rdev->raid_disk;
		if (disk_idx >= mddev->raid_disks
		    || disk_idx < 0)
			continue;
		if (test_bit(Replacement, &rdev->flags))
			disk = conf->mirrors + mddev->raid_disks + disk_idx;
		else
			disk = conf->mirrors + disk_idx;

		if (disk->rdev)
			goto abort;
		disk->rdev = rdev;
		q = bdev_get_queue(rdev->bdev);

		disk->head_position = 0;
		disk->seq_start = MaxSector;
	}
	conf->raid_disks = mddev->raid_disks;
	conf->mddev = mddev;
	INIT_LIST_HEAD(&conf->retry_list);
	INIT_LIST_HEAD(&conf->bio_end_io_list);

	spin_lock_init(&conf->resync_lock);
	init_waitqueue_head(&conf->wait_barrier);

	bio_list_init(&conf->pending_bio_list);
	conf->pending_count = 0;
	conf->recovery_disabled = mddev->recovery_disabled - 1;

	err = -EIO;
	for (i = 0; i < conf->raid_disks * 2; i++) {

		disk = conf->mirrors + i;

		if (i < conf->raid_disks &&
		    disk[conf->raid_disks].rdev) {
			/* This slot has a replacement. */
			if (!disk->rdev) {
				/* No original, just make the replacement
				 * a recovering spare
				 */
				disk->rdev =
					disk[conf->raid_disks].rdev;
				disk[conf->raid_disks].rdev = NULL;
			} else if (!test_bit(In_sync, &disk->rdev->flags))
				/* Original is not in_sync - bad */
				goto abort;
		}

		if (!disk->rdev ||
		    !test_bit(In_sync, &disk->rdev->flags)) {
			disk->head_position = 0;
			if (disk->rdev &&
			    (disk->rdev->saved_raid_disk < 0))
				conf->fullsync = 1;
		}
	}

	err = -ENOMEM;
	conf->thread = md_register_thread(raid1d, mddev, "raid1");
	if (!conf->thread)
		goto abort;

	return conf;

 abort:
	if (conf) {
		mempool_destroy(conf->r1bio_pool);
		kfree(conf->mirrors);
		safe_put_page(conf->tmppage);
		kfree(conf->poolinfo);
		kfree(conf->nr_pending);
		kfree(conf->nr_waiting);
		kfree(conf->nr_queued);
		kfree(conf->barrier);
		kfree(conf);
	}
	return ERR_PTR(err);
}

static void raid1_free(struct mddev *mddev, void *priv);
static int raid1_run(struct mddev *mddev)
{
	struct r1conf *conf;
	int i;
	struct md_rdev *rdev;
	int ret;
	bool discard_supported = false;

	if (mddev->level != 1) {
		pr_warn("md/raid1:%s: raid level not set to mirroring (%d)\n",
			mdname(mddev), mddev->level);
		return -EIO;
	}
	if (mddev->reshape_position != MaxSector) {
		pr_warn("md/raid1:%s: reshape_position set but not supported\n",
			mdname(mddev));
		return -EIO;
	}
	/*
	 * copy the already verified devices into our private RAID1
	 * bookkeeping area. [whatever we allocate in run(),
	 * should be freed in raid1_free()]
	 */
	if (mddev->private == NULL)
		conf = setup_conf(mddev);
	else
		conf = mddev->private;

	if (IS_ERR(conf))
		return PTR_ERR(conf);

	if (mddev->queue) {
		blk_queue_max_write_same_sectors(mddev->queue, 0);
		blk_queue_max_write_zeroes_sectors(mddev->queue, 0);
	}

	rdev_for_each(rdev, mddev) {
		if (!mddev->gendisk)
			continue;
		disk_stack_limits(mddev->gendisk, rdev->bdev,
				  rdev->data_offset << 9);
		if (blk_queue_discard(bdev_get_queue(rdev->bdev)))
			discard_supported = true;
	}

	mddev->degraded = 0;
	for (i=0; i < conf->raid_disks; i++)
		if (conf->mirrors[i].rdev == NULL ||
		    !test_bit(In_sync, &conf->mirrors[i].rdev->flags) ||
		    test_bit(Faulty, &conf->mirrors[i].rdev->flags))
			mddev->degraded++;

	if (conf->raid_disks - mddev->degraded == 1)
		mddev->recovery_cp = MaxSector;

	if (mddev->recovery_cp != MaxSector)
		pr_info("md/raid1:%s: not clean -- starting background reconstruction\n",
			mdname(mddev));
	pr_info("md/raid1:%s: active with %d out of %d mirrors\n",
		mdname(mddev), mddev->raid_disks - mddev->degraded,
		mddev->raid_disks);

	/*
	 * Ok, everything is just fine now
	 */
	mddev->thread = conf->thread;
	conf->thread = NULL;
	mddev->private = conf;
	set_bit(MD_FAILFAST_SUPPORTED, &mddev->flags);

	md_set_array_sectors(mddev, raid1_size(mddev, 0, 0));

	if (mddev->queue) {
		if (discard_supported)
			queue_flag_set_unlocked(QUEUE_FLAG_DISCARD,
						mddev->queue);
		else
			queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD,
						  mddev->queue);
	}

	ret =  md_integrity_register(mddev);
	if (ret) {
		md_unregister_thread(&mddev->thread);
		raid1_free(mddev, conf);
	}
	return ret;
}

static void raid1_free(struct mddev *mddev, void *priv)
{
	struct r1conf *conf = priv;

	mempool_destroy(conf->r1bio_pool);
	kfree(conf->mirrors);
	safe_put_page(conf->tmppage);
	kfree(conf->poolinfo);
	kfree(conf->nr_pending);
	kfree(conf->nr_waiting);
	kfree(conf->nr_queued);
	kfree(conf->barrier);
	kfree(conf);
}

static int raid1_resize(struct mddev *mddev, sector_t sectors)
{
	/* no resync is happening, and there is enough space
	 * on all devices, so we can resize.
	 * We need to make sure resync covers any new space.
	 * If the array is shrinking we should possibly wait until
	 * any io in the removed space completes, but it hardly seems
	 * worth it.
	 */
	sector_t newsize = raid1_size(mddev, sectors, 0);
	if (mddev->external_size &&
	    mddev->array_sectors > newsize)
		return -EINVAL;
	if (mddev->bitmap) {
		int ret = bitmap_resize(mddev->bitmap, newsize, 0, 0);
		if (ret)
			return ret;
	}
	md_set_array_sectors(mddev, newsize);
	if (sectors > mddev->dev_sectors &&
	    mddev->recovery_cp > mddev->dev_sectors) {
		mddev->recovery_cp = mddev->dev_sectors;
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}
	mddev->dev_sectors = sectors;
	mddev->resync_max_sectors = sectors;
	return 0;
}

static int raid1_reshape(struct mddev *mddev)
{
	/* We need to:
	 * 1/ resize the r1bio_pool
	 * 2/ resize conf->mirrors
	 *
	 * We allocate a new r1bio_pool if we can.
	 * Then raise a device barrier and wait until all IO stops.
	 * Then resize conf->mirrors and swap in the new r1bio pool.
	 *
	 * At the same time, we "pack" the devices so that all the missing
	 * devices have the higher raid_disk numbers.
	 */
	mempool_t *newpool, *oldpool;
	struct pool_info *newpoolinfo;
	struct raid1_info *newmirrors;
	struct r1conf *conf = mddev->private;
	int cnt, raid_disks;
	unsigned long flags;
	int d, d2, err;

	/* Cannot change chunk_size, layout, or level */
	if (mddev->chunk_sectors != mddev->new_chunk_sectors ||
	    mddev->layout != mddev->new_layout ||
	    mddev->level != mddev->new_level) {
		mddev->new_chunk_sectors = mddev->chunk_sectors;
		mddev->new_layout = mddev->layout;
		mddev->new_level = mddev->level;
		return -EINVAL;
	}

	if (!mddev_is_clustered(mddev)) {
		err = md_allow_write(mddev);
		if (err)
			return err;
	}

	raid_disks = mddev->raid_disks + mddev->delta_disks;

	if (raid_disks < conf->raid_disks) {
		cnt=0;
		for (d= 0; d < conf->raid_disks; d++)
			if (conf->mirrors[d].rdev)
				cnt++;
		if (cnt > raid_disks)
			return -EBUSY;
	}

	newpoolinfo = kmalloc(sizeof(*newpoolinfo), GFP_KERNEL);
	if (!newpoolinfo)
		return -ENOMEM;
	newpoolinfo->mddev = mddev;
	newpoolinfo->raid_disks = raid_disks * 2;

	newpool = mempool_create(NR_RAID1_BIOS, r1bio_pool_alloc,
				 r1bio_pool_free, newpoolinfo);
	if (!newpool) {
		kfree(newpoolinfo);
		return -ENOMEM;
	}
	newmirrors = kzalloc(sizeof(struct raid1_info) * raid_disks * 2,
			     GFP_KERNEL);
	if (!newmirrors) {
		kfree(newpoolinfo);
		mempool_destroy(newpool);
		return -ENOMEM;
	}

	freeze_array(conf, 0);

	/* ok, everything is stopped */
	oldpool = conf->r1bio_pool;
	conf->r1bio_pool = newpool;

	for (d = d2 = 0; d < conf->raid_disks; d++) {
		struct md_rdev *rdev = conf->mirrors[d].rdev;
		if (rdev && rdev->raid_disk != d2) {
			sysfs_unlink_rdev(mddev, rdev);
			rdev->raid_disk = d2;
			sysfs_unlink_rdev(mddev, rdev);
			if (sysfs_link_rdev(mddev, rdev))
				pr_warn("md/raid1:%s: cannot register rd%d\n",
					mdname(mddev), rdev->raid_disk);
		}
		if (rdev)
			newmirrors[d2++].rdev = rdev;
	}
	kfree(conf->mirrors);
	conf->mirrors = newmirrors;
	kfree(conf->poolinfo);
	conf->poolinfo = newpoolinfo;

	spin_lock_irqsave(&conf->device_lock, flags);
	mddev->degraded += (raid_disks - conf->raid_disks);
	spin_unlock_irqrestore(&conf->device_lock, flags);
	conf->raid_disks = mddev->raid_disks = raid_disks;
	mddev->delta_disks = 0;

	unfreeze_array(conf);

	set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);

	mempool_destroy(oldpool);
	return 0;
}

static void raid1_quiesce(struct mddev *mddev, int state)
{
	struct r1conf *conf = mddev->private;

	switch(state) {
	case 2: /* wake for suspend */
		wake_up(&conf->wait_barrier);
		break;
	case 1:
		freeze_array(conf, 0);
		break;
	case 0:
		unfreeze_array(conf);
		break;
	}
}

static void *raid1_takeover(struct mddev *mddev)
{
	/* raid1 can take over:
	 *  raid5 with 2 devices, any layout or chunk size
	 */
	if (mddev->level == 5 && mddev->raid_disks == 2) {
		struct r1conf *conf;
		mddev->new_level = 1;
		mddev->new_layout = 0;
		mddev->new_chunk_sectors = 0;
		conf = setup_conf(mddev);
		if (!IS_ERR(conf)) {
			/* Array must appear to be quiesced */
			conf->array_frozen = 1;
			mddev_clear_unsupported_flags(mddev,
				UNSUPPORTED_MDDEV_FLAGS);
		}
		return conf;
	}
	return ERR_PTR(-EINVAL);
}

static struct md_personality raid1_personality =
{
	.name		= "raid1",
	.level		= 1,
	.owner		= THIS_MODULE,
	.make_request	= raid1_make_request,
	.run		= raid1_run,
	.free		= raid1_free,
	.status		= raid1_status,
	.error_handler	= raid1_error,
	.hot_add_disk	= raid1_add_disk,
	.hot_remove_disk= raid1_remove_disk,
	.spare_active	= raid1_spare_active,
	.sync_request	= raid1_sync_request,
	.resize		= raid1_resize,
	.size		= raid1_size,
	.check_reshape	= raid1_reshape,
	.quiesce	= raid1_quiesce,
	.takeover	= raid1_takeover,
	.congested	= raid1_congested,
};

static int __init raid_init(void)
{
	return register_md_personality(&raid1_personality);
}

static void raid_exit(void)
{
	unregister_md_personality(&raid1_personality);
}

module_init(raid_init);
module_exit(raid_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID1 (mirroring) personality for MD");
MODULE_ALIAS("md-personality-3"); /* RAID1 */
MODULE_ALIAS("md-raid1");
MODULE_ALIAS("md-level-1");

module_param(max_queued_requests, int, S_IRUGO|S_IWUSR);

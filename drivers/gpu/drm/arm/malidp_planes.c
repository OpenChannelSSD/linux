/*
 * (C) COPYRIGHT 2016 ARM Limited. All rights reserved.
 * Author: Liviu Dudau <Liviu.Dudau@arm.com>
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * ARM Mali DP plane manipulation routines.
 */

#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_plane_helper.h>

#include "malidp_hw.h"
#include "malidp_drv.h"

/* Layer specific register offsets */
#define MALIDP_LAYER_FORMAT		0x000
#define MALIDP_LAYER_CONTROL		0x004
#define   LAYER_ENABLE			(1 << 0)
#define   LAYER_ROT_OFFSET		8
#define   LAYER_H_FLIP			(1 << 10)
#define   LAYER_V_FLIP			(1 << 11)
#define   LAYER_ROT_MASK		(0xf << 8)
#define   LAYER_COMP_MASK		(0x3 << 12)
#define   LAYER_COMP_PIXEL		(0x3 << 12)
#define   LAYER_COMP_PLANE		(0x2 << 12)
#define MALIDP_LAYER_COMPOSE		0x008
#define MALIDP_LAYER_SIZE		0x00c
#define   LAYER_H_VAL(x)		(((x) & 0x1fff) << 0)
#define   LAYER_V_VAL(x)		(((x) & 0x1fff) << 16)
#define MALIDP_LAYER_COMP_SIZE		0x010
#define MALIDP_LAYER_OFFSET		0x014
#define MALIDP550_LS_ENABLE		0x01c
#define MALIDP550_LS_R1_IN_SIZE		0x020

/*
 * This 4-entry look-up-table is used to determine the full 8-bit alpha value
 * for formats with 1- or 2-bit alpha channels.
 * We set it to give 100%/0% opacity for 1-bit formats and 100%/66%/33%/0%
 * opacity for 2-bit formats.
 */
#define MALIDP_ALPHA_LUT 0xffaa5500

static void malidp_de_plane_destroy(struct drm_plane *plane)
{
	struct malidp_plane *mp = to_malidp_plane(plane);

	if (mp->base.fb)
		drm_framebuffer_unreference(mp->base.fb);

	drm_plane_helper_disable(plane);
	drm_plane_cleanup(plane);
	devm_kfree(plane->dev->dev, mp);
}

static struct
drm_plane_state *malidp_duplicate_plane_state(struct drm_plane *plane)
{
	struct malidp_plane_state *state, *m_state;

	if (!plane->state)
		return NULL;

	state = kmalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	m_state = to_malidp_plane_state(plane->state);
	__drm_atomic_helper_plane_duplicate_state(plane, &state->base);
	state->rotmem_size = m_state->rotmem_size;
	state->format = m_state->format;
	state->n_planes = m_state->n_planes;

	return &state->base;
}

static void malidp_destroy_plane_state(struct drm_plane *plane,
				       struct drm_plane_state *state)
{
	struct malidp_plane_state *m_state = to_malidp_plane_state(state);

	__drm_atomic_helper_plane_destroy_state(state);
	kfree(m_state);
}

static const struct drm_plane_funcs malidp_de_plane_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.set_property = drm_atomic_helper_plane_set_property,
	.destroy = malidp_de_plane_destroy,
	.reset = drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = malidp_duplicate_plane_state,
	.atomic_destroy_state = malidp_destroy_plane_state,
};

static int malidp_de_plane_check(struct drm_plane *plane,
				 struct drm_plane_state *state)
{
	struct malidp_plane *mp = to_malidp_plane(plane);
	struct malidp_plane_state *ms = to_malidp_plane_state(state);
	struct drm_crtc_state *crtc_state;
	struct drm_framebuffer *fb;
	struct drm_rect clip = { 0 };
	int i, ret;
	u32 src_w, src_h;

	if (!state->crtc || !state->fb)
		return 0;

	fb = state->fb;

	ms->format = malidp_hw_get_format_id(&mp->hwdev->map, mp->layer->id,
					    fb->format->format);
	if (ms->format == MALIDP_INVALID_FORMAT_ID)
		return -EINVAL;

	ms->n_planes = fb->format->num_planes;
	for (i = 0; i < ms->n_planes; i++) {
		if (!malidp_hw_pitch_valid(mp->hwdev, fb->pitches[i])) {
			DRM_DEBUG_KMS("Invalid pitch %u for plane %d\n",
				      fb->pitches[i], i);
			return -EINVAL;
		}
	}

	src_w = state->src_w >> 16;
	src_h = state->src_h >> 16;

	if ((state->crtc_w > mp->hwdev->max_line_size) ||
	    (state->crtc_h > mp->hwdev->max_line_size) ||
	    (state->crtc_w < mp->hwdev->min_line_size) ||
	    (state->crtc_h < mp->hwdev->min_line_size))
		return -EINVAL;

	/*
	 * DP550/650 video layers can accept 3 plane formats only if
	 * fb->pitches[1] == fb->pitches[2] since they don't have a
	 * third plane stride register.
	 */
	if (ms->n_planes == 3 &&
	    !(mp->hwdev->features & MALIDP_DEVICE_LV_HAS_3_STRIDES) &&
	    (state->fb->pitches[1] != state->fb->pitches[2]))
		return -EINVAL;

	/* packed RGB888 / BGR888 can't be rotated or flipped */
	if (state->rotation != DRM_ROTATE_0 &&
	    (fb->format->format == DRM_FORMAT_RGB888 ||
	     fb->format->format == DRM_FORMAT_BGR888))
		return -EINVAL;

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, state->crtc);
	clip.x2 = crtc_state->adjusted_mode.hdisplay;
	clip.y2 = crtc_state->adjusted_mode.vdisplay;
	ret = drm_plane_helper_check_state(state, &clip,
					   DRM_PLANE_HELPER_NO_SCALING,
					   DRM_PLANE_HELPER_NO_SCALING,
					   true, true);
	if (ret)
		return ret;

	ms->rotmem_size = 0;
	if (state->rotation & MALIDP_ROTATED_MASK) {
		int val;

		val = mp->hwdev->rotmem_required(mp->hwdev, state->crtc_h,
						 state->crtc_w,
						 fb->format->format);
		if (val < 0)
			return val;

		ms->rotmem_size = val;
	}

	return 0;
}

static void malidp_de_set_plane_pitches(struct malidp_plane *mp,
					int num_planes, unsigned int pitches[3])
{
	int i;
	int num_strides = num_planes;

	if (!mp->layer->stride_offset)
		return;

	if (num_planes == 3)
		num_strides = (mp->hwdev->features &
			       MALIDP_DEVICE_LV_HAS_3_STRIDES) ? 3 : 2;

	for (i = 0; i < num_strides; ++i)
		malidp_hw_write(mp->hwdev, pitches[i],
				mp->layer->base +
				mp->layer->stride_offset + i * 4);
}

static void malidp_de_plane_update(struct drm_plane *plane,
				   struct drm_plane_state *old_state)
{
	struct drm_gem_cma_object *obj;
	struct malidp_plane *mp;
	const struct malidp_hw_regmap *map;
	struct malidp_plane_state *ms = to_malidp_plane_state(plane->state);
	u16 ptr;
	u32 src_w, src_h, dest_w, dest_h, val;
	int i;

	mp = to_malidp_plane(plane);
	map = &mp->hwdev->map;

	/* convert src values from Q16 fixed point to integer */
	src_w = plane->state->src_w >> 16;
	src_h = plane->state->src_h >> 16;
	dest_w = plane->state->crtc_w;
	dest_h = plane->state->crtc_h;

	malidp_hw_write(mp->hwdev, ms->format, mp->layer->base);

	for (i = 0; i < ms->n_planes; i++) {
		/* calculate the offset for the layer's plane registers */
		ptr = mp->layer->ptr + (i << 4);

		obj = drm_fb_cma_get_gem_obj(plane->state->fb, i);
		obj->paddr += plane->state->fb->offsets[i];
		malidp_hw_write(mp->hwdev, lower_32_bits(obj->paddr), ptr);
		malidp_hw_write(mp->hwdev, upper_32_bits(obj->paddr), ptr + 4);
	}
	malidp_de_set_plane_pitches(mp, ms->n_planes,
				    plane->state->fb->pitches);

	malidp_hw_write(mp->hwdev, LAYER_H_VAL(src_w) | LAYER_V_VAL(src_h),
			mp->layer->base + MALIDP_LAYER_SIZE);

	malidp_hw_write(mp->hwdev, LAYER_H_VAL(dest_w) | LAYER_V_VAL(dest_h),
			mp->layer->base + MALIDP_LAYER_COMP_SIZE);

	malidp_hw_write(mp->hwdev, LAYER_H_VAL(plane->state->crtc_x) |
			LAYER_V_VAL(plane->state->crtc_y),
			mp->layer->base + MALIDP_LAYER_OFFSET);

	if (mp->layer->id == DE_SMART)
		malidp_hw_write(mp->hwdev,
				LAYER_H_VAL(src_w) | LAYER_V_VAL(src_h),
				mp->layer->base + MALIDP550_LS_R1_IN_SIZE);

	/* first clear the rotation bits */
	val = malidp_hw_read(mp->hwdev, mp->layer->base + MALIDP_LAYER_CONTROL);
	val &= ~LAYER_ROT_MASK;

	/* setup the rotation and axis flip bits */
	if (plane->state->rotation & DRM_ROTATE_MASK)
		val |= ilog2(plane->state->rotation & DRM_ROTATE_MASK) <<
		       LAYER_ROT_OFFSET;
	if (plane->state->rotation & DRM_REFLECT_X)
		val |= LAYER_H_FLIP;
	if (plane->state->rotation & DRM_REFLECT_Y)
		val |= LAYER_V_FLIP;

	/*
	 * always enable pixel alpha blending until we have a way to change
	 * blend modes
	 */
	val &= ~LAYER_COMP_MASK;
	val |= LAYER_COMP_PIXEL;

	/* set the 'enable layer' bit */
	val |= LAYER_ENABLE;

	malidp_hw_write(mp->hwdev, val,
			mp->layer->base + MALIDP_LAYER_CONTROL);
}

static void malidp_de_plane_disable(struct drm_plane *plane,
				    struct drm_plane_state *state)
{
	struct malidp_plane *mp = to_malidp_plane(plane);

	malidp_hw_clearbits(mp->hwdev, LAYER_ENABLE,
			    mp->layer->base + MALIDP_LAYER_CONTROL);
}

static const struct drm_plane_helper_funcs malidp_de_plane_helper_funcs = {
	.atomic_check = malidp_de_plane_check,
	.atomic_update = malidp_de_plane_update,
	.atomic_disable = malidp_de_plane_disable,
};

int malidp_de_planes_init(struct drm_device *drm)
{
	struct malidp_drm *malidp = drm->dev_private;
	const struct malidp_hw_regmap *map = &malidp->dev->map;
	struct malidp_plane *plane = NULL;
	enum drm_plane_type plane_type;
	unsigned long crtcs = 1 << drm->mode_config.num_crtc;
	unsigned long flags = DRM_ROTATE_0 | DRM_ROTATE_90 | DRM_ROTATE_180 |
			      DRM_ROTATE_270 | DRM_REFLECT_X | DRM_REFLECT_Y;
	u32 *formats;
	int ret, i, j, n;

	formats = kcalloc(map->n_pixel_formats, sizeof(*formats), GFP_KERNEL);
	if (!formats) {
		ret = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < map->n_layers; i++) {
		u8 id = map->layers[i].id;

		plane = kzalloc(sizeof(*plane), GFP_KERNEL);
		if (!plane) {
			ret = -ENOMEM;
			goto cleanup;
		}

		/* build the list of DRM supported formats based on the map */
		for (n = 0, j = 0;  j < map->n_pixel_formats; j++) {
			if ((map->pixel_formats[j].layer & id) == id)
				formats[n++] = map->pixel_formats[j].format;
		}

		plane_type = (i == 0) ? DRM_PLANE_TYPE_PRIMARY :
					DRM_PLANE_TYPE_OVERLAY;
		ret = drm_universal_plane_init(drm, &plane->base, crtcs,
					       &malidp_de_plane_funcs, formats,
					       n, plane_type, NULL);
		if (ret < 0)
			goto cleanup;

		drm_plane_helper_add(&plane->base,
				     &malidp_de_plane_helper_funcs);
		plane->hwdev = malidp->dev;
		plane->layer = &map->layers[i];

		if (id == DE_SMART) {
			/*
			 * Enable the first rectangle in the SMART layer to be
			 * able to use it as a drm plane.
			 */
			malidp_hw_write(malidp->dev, 1,
					plane->layer->base + MALIDP550_LS_ENABLE);
			/* Skip the features which the SMART layer doesn't have. */
			continue;
		}

		drm_plane_create_rotation_property(&plane->base, DRM_ROTATE_0, flags);
		malidp_hw_write(malidp->dev, MALIDP_ALPHA_LUT,
				plane->layer->base + MALIDP_LAYER_COMPOSE);
	}

	kfree(formats);

	return 0;

cleanup:
	malidp_de_planes_destroy(drm);
	kfree(formats);

	return ret;
}

void malidp_de_planes_destroy(struct drm_device *drm)
{
	struct drm_plane *p, *pt;

	list_for_each_entry_safe(p, pt, &drm->mode_config.plane_list, head) {
		drm_plane_cleanup(p);
		kfree(p);
	}
}

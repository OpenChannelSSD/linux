/*
 * drivers/gpu/drm/omapdrm/omap_plane.c
 *
 * Copyright (C) 2011 Texas Instruments
 * Author: Rob Clark <rob.clark@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_plane_helper.h>

#include "omap_dmm_tiler.h"
#include "omap_drv.h"

/* some hackery because omapdss has an 'enum omap_plane' (which would be
 * better named omap_plane_id).. and compiler seems unhappy about having
 * both a 'struct omap_plane' and 'enum omap_plane'
 */
#define omap_plane _omap_plane

/*
 * plane funcs
 */

#define to_omap_plane(x) container_of(x, struct omap_plane, base)

struct omap_plane {
	struct drm_plane base;
	int id;  /* TODO rename omap_plane -> omap_plane_id in omapdss so I can use the enum */
	const char *name;

	uint32_t nformats;
	uint32_t formats[32];
};

struct omap_plane_state {
	struct drm_plane_state base;

	unsigned int zorder;
};

static inline struct omap_plane_state *
to_omap_plane_state(struct drm_plane_state *state)
{
	return container_of(state, struct omap_plane_state, base);
}

static int omap_plane_prepare_fb(struct drm_plane *plane,
				 struct drm_plane_state *new_state)
{
	if (!new_state->fb)
		return 0;

	return omap_framebuffer_pin(new_state->fb);
}

static void omap_plane_cleanup_fb(struct drm_plane *plane,
				  struct drm_plane_state *old_state)
{
	if (old_state->fb)
		omap_framebuffer_unpin(old_state->fb);
}

static void omap_plane_atomic_update(struct drm_plane *plane,
				     struct drm_plane_state *old_state)
{
	struct omap_plane *omap_plane = to_omap_plane(plane);
	struct drm_plane_state *state = plane->state;
	struct omap_plane_state *omap_state = to_omap_plane_state(state);
	struct omap_overlay_info info;
	struct omap_drm_window win;
	int ret;

	DBG("%s, crtc=%p fb=%p", omap_plane->name, state->crtc, state->fb);

	memset(&info, 0, sizeof(info));
	info.rotation_type = OMAP_DSS_ROT_DMA;
	info.rotation = OMAP_DSS_ROT_0;
	info.global_alpha = 0xff;
	info.mirror = 0;
	info.zorder = omap_state->zorder;

	memset(&win, 0, sizeof(win));
	win.rotation = state->rotation;
	win.crtc_x = state->crtc_x;
	win.crtc_y = state->crtc_y;
	win.crtc_w = state->crtc_w;
	win.crtc_h = state->crtc_h;

	/*
	 * src values are in Q16 fixed point, convert to integer.
	 * omap_framebuffer_update_scanout() takes adjusted src.
	 */
	win.src_x = state->src_x >> 16;
	win.src_y = state->src_y >> 16;

	if (drm_rotation_90_or_270(state->rotation)) {
		win.src_w = state->src_h >> 16;
		win.src_h = state->src_w >> 16;
	} else {
		win.src_w = state->src_w >> 16;
		win.src_h = state->src_h >> 16;
	}

	/* update scanout: */
	omap_framebuffer_update_scanout(state->fb, &win, &info);

	DBG("%dx%d -> %dx%d (%d)", info.width, info.height,
			info.out_width, info.out_height,
			info.screen_width);
	DBG("%d,%d %pad %pad", info.pos_x, info.pos_y,
			&info.paddr, &info.p_uv_addr);

	dispc_ovl_set_channel_out(omap_plane->id,
				  omap_crtc_channel(state->crtc));

	/* and finally, update omapdss: */
	ret = dispc_ovl_setup(omap_plane->id, &info, false,
			      omap_crtc_timings(state->crtc), false);
	if (ret) {
		dev_err(plane->dev->dev, "Failed to setup plane %s\n",
			omap_plane->name);
		dispc_ovl_enable(omap_plane->id, false);
		return;
	}

	dispc_ovl_enable(omap_plane->id, true);
}

static void omap_plane_atomic_disable(struct drm_plane *plane,
				      struct drm_plane_state *old_state)
{
	struct omap_plane_state *omap_state = to_omap_plane_state(plane->state);
	struct omap_plane *omap_plane = to_omap_plane(plane);

	plane->state->rotation = DRM_ROTATE_0;
	omap_state->zorder = plane->type == DRM_PLANE_TYPE_PRIMARY
			   ? 0 : omap_plane->id;

	dispc_ovl_enable(omap_plane->id, false);
}

static int omap_plane_atomic_check(struct drm_plane *plane,
				   struct drm_plane_state *state)
{
	struct drm_crtc_state *crtc_state;

	if (!state->fb)
		return 0;

	/* crtc should only be NULL when disabling (i.e., !state->fb) */
	if (WARN_ON(!state->crtc))
		return 0;

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, state->crtc);
	/* we should have a crtc state if the plane is attached to a crtc */
	if (WARN_ON(!crtc_state))
		return 0;

	if (!crtc_state->enable)
		return 0;

	if (state->crtc_x < 0 || state->crtc_y < 0)
		return -EINVAL;

	if (state->crtc_x + state->crtc_w > crtc_state->adjusted_mode.hdisplay)
		return -EINVAL;

	if (state->crtc_y + state->crtc_h > crtc_state->adjusted_mode.vdisplay)
		return -EINVAL;

	if (state->rotation != DRM_ROTATE_0 &&
	    !omap_framebuffer_supports_rotation(state->fb))
		return -EINVAL;

	return 0;
}

static const struct drm_plane_helper_funcs omap_plane_helper_funcs = {
	.prepare_fb = omap_plane_prepare_fb,
	.cleanup_fb = omap_plane_cleanup_fb,
	.atomic_check = omap_plane_atomic_check,
	.atomic_update = omap_plane_atomic_update,
	.atomic_disable = omap_plane_atomic_disable,
};

static void omap_plane_destroy(struct drm_plane *plane)
{
	struct omap_plane *omap_plane = to_omap_plane(plane);

	DBG("%s", omap_plane->name);

	drm_plane_cleanup(plane);

	kfree(omap_plane);
}

/* helper to install properties which are common to planes and crtcs */
void omap_plane_install_properties(struct drm_plane *plane,
		struct drm_mode_object *obj)
{
	struct drm_device *dev = plane->dev;
	struct omap_drm_private *priv = dev->dev_private;

	if (priv->has_dmm) {
		if (!plane->rotation_property)
			drm_plane_create_rotation_property(plane,
							   DRM_ROTATE_0,
							   DRM_ROTATE_0 | DRM_ROTATE_90 |
							   DRM_ROTATE_180 | DRM_ROTATE_270 |
							   DRM_REFLECT_X | DRM_REFLECT_Y);

		/* Attach the rotation property also to the crtc object */
		if (plane->rotation_property && obj != &plane->base)
			drm_object_attach_property(obj, plane->rotation_property,
						   DRM_ROTATE_0);
	}

	drm_object_attach_property(obj, priv->zorder_prop, 0);
}

static struct drm_plane_state *
omap_plane_atomic_duplicate_state(struct drm_plane *plane)
{
	struct omap_plane_state *state;
	struct omap_plane_state *copy;

	if (WARN_ON(!plane->state))
		return NULL;

	state = to_omap_plane_state(plane->state);
	copy = kmemdup(state, sizeof(*state), GFP_KERNEL);
	if (copy == NULL)
		return NULL;

	__drm_atomic_helper_plane_duplicate_state(plane, &copy->base);

	return &copy->base;
}

static void omap_plane_atomic_destroy_state(struct drm_plane *plane,
					    struct drm_plane_state *state)
{
	__drm_atomic_helper_plane_destroy_state(state);
	kfree(to_omap_plane_state(state));
}

static void omap_plane_reset(struct drm_plane *plane)
{
	struct omap_plane *omap_plane = to_omap_plane(plane);
	struct omap_plane_state *omap_state;

	if (plane->state) {
		omap_plane_atomic_destroy_state(plane, plane->state);
		plane->state = NULL;
	}

	omap_state = kzalloc(sizeof(*omap_state), GFP_KERNEL);
	if (omap_state == NULL)
		return;

	/*
	 * Set defaults depending on whether we are a primary or overlay
	 * plane.
	 */
	omap_state->zorder = plane->type == DRM_PLANE_TYPE_PRIMARY
			   ? 0 : omap_plane->id;
	omap_state->base.rotation = DRM_ROTATE_0;

	plane->state = &omap_state->base;
	plane->state->plane = plane;
}

static int omap_plane_atomic_set_property(struct drm_plane *plane,
					  struct drm_plane_state *state,
					  struct drm_property *property,
					  uint64_t val)
{
	struct omap_drm_private *priv = plane->dev->dev_private;
	struct omap_plane_state *omap_state = to_omap_plane_state(state);

	if (property == priv->zorder_prop)
		omap_state->zorder = val;
	else
		return -EINVAL;

	return 0;
}

static int omap_plane_atomic_get_property(struct drm_plane *plane,
					  const struct drm_plane_state *state,
					  struct drm_property *property,
					  uint64_t *val)
{
	struct omap_drm_private *priv = plane->dev->dev_private;
	const struct omap_plane_state *omap_state =
		container_of(state, const struct omap_plane_state, base);

	if (property == priv->zorder_prop)
		*val = omap_state->zorder;
	else
		return -EINVAL;

	return 0;
}

static const struct drm_plane_funcs omap_plane_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.reset = omap_plane_reset,
	.destroy = omap_plane_destroy,
	.set_property = drm_atomic_helper_plane_set_property,
	.atomic_duplicate_state = omap_plane_atomic_duplicate_state,
	.atomic_destroy_state = omap_plane_atomic_destroy_state,
	.atomic_set_property = omap_plane_atomic_set_property,
	.atomic_get_property = omap_plane_atomic_get_property,
};

static const char *plane_names[] = {
	[OMAP_DSS_GFX] = "gfx",
	[OMAP_DSS_VIDEO1] = "vid1",
	[OMAP_DSS_VIDEO2] = "vid2",
	[OMAP_DSS_VIDEO3] = "vid3",
};

/* initialize plane */
struct drm_plane *omap_plane_init(struct drm_device *dev,
		int id, enum drm_plane_type type,
		u32 possible_crtcs)
{
	struct drm_plane *plane;
	struct omap_plane *omap_plane;
	int ret;

	DBG("%s: type=%d", plane_names[id], type);

	omap_plane = kzalloc(sizeof(*omap_plane), GFP_KERNEL);
	if (!omap_plane)
		return ERR_PTR(-ENOMEM);

	omap_plane->nformats = omap_framebuffer_get_formats(
			omap_plane->formats, ARRAY_SIZE(omap_plane->formats),
			dss_feat_get_supported_color_modes(id));
	omap_plane->id = id;
	omap_plane->name = plane_names[id];

	plane = &omap_plane->base;

	ret = drm_universal_plane_init(dev, plane, possible_crtcs,
				       &omap_plane_funcs, omap_plane->formats,
				       omap_plane->nformats, type, NULL);
	if (ret < 0)
		goto error;

	drm_plane_helper_add(plane, &omap_plane_helper_funcs);

	omap_plane_install_properties(plane, &plane->base);

	return plane;

error:
	kfree(omap_plane);
	return NULL;
}

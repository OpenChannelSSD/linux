/*
 * Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __GVT_DEBUG_H__
#define __GVT_DEBUG_H__

#define gvt_err(fmt, args...) \
	DRM_ERROR("gvt: "fmt, ##args)

#define gvt_vgpu_err(fmt, args...)					\
do {									\
	if (IS_ERR_OR_NULL(vgpu))					\
		DRM_DEBUG_DRIVER("gvt: "fmt, ##args);			\
	else								\
		DRM_DEBUG_DRIVER("gvt: vgpu %d: "fmt, vgpu->id, ##args);\
} while (0)

#define gvt_dbg_core(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: core: "fmt, ##args)

#define gvt_dbg_irq(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: irq: "fmt, ##args)

#define gvt_dbg_mm(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: mm: "fmt, ##args)

#define gvt_dbg_mmio(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: mmio: "fmt, ##args)

#define gvt_dbg_dpy(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: dpy: "fmt, ##args)

#define gvt_dbg_el(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: el: "fmt, ##args)

#define gvt_dbg_sched(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: sched: "fmt, ##args)

#define gvt_dbg_render(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: render: "fmt, ##args)

#define gvt_dbg_cmd(fmt, args...) \
	DRM_DEBUG_DRIVER("gvt: cmd: "fmt, ##args)

#endif

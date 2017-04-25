/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include "pp_debug.h"
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include "amd_shared.h"
#include "amd_powerplay.h"
#include "pp_instance.h"
#include "power_state.h"
#include "eventmanager.h"


static inline int pp_check(struct pp_instance *handle)
{
	if (handle == NULL || handle->pp_valid != PP_VALID)
		return -EINVAL;

	if (handle->smu_mgr == NULL || handle->smu_mgr->smumgr_funcs == NULL)
		return -EINVAL;

	if (handle->pm_en == 0)
		return PP_DPM_DISABLED;

	if (handle->hwmgr == NULL || handle->hwmgr->hwmgr_func == NULL
		|| handle->eventmgr == NULL)
		return PP_DPM_DISABLED;

	return 0;
}

static int pp_early_init(void *handle)
{
	int ret;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret = smum_early_init(pp_handle);
	if (ret)
		return ret;

	if ((pp_handle->pm_en == 0)
		|| cgs_is_virtualization_enabled(pp_handle->device))
		return PP_DPM_DISABLED;

	ret = hwmgr_early_init(pp_handle);
	if (ret) {
		pp_handle->pm_en = 0;
		return PP_DPM_DISABLED;
	}

	ret = eventmgr_early_init(pp_handle);
	if (ret) {
		kfree(pp_handle->hwmgr);
		pp_handle->hwmgr = NULL;
		pp_handle->pm_en = 0;
		return PP_DPM_DISABLED;
	}

	return 0;
}

static int pp_sw_init(void *handle)
{
	struct pp_smumgr *smumgr;
	int ret = 0;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret = pp_check(pp_handle);

	if (ret == 0 || ret == PP_DPM_DISABLED) {
		smumgr = pp_handle->smu_mgr;

		if (smumgr->smumgr_funcs->smu_init == NULL)
			return -EINVAL;

		ret = smumgr->smumgr_funcs->smu_init(smumgr);

		pr_info("amdgpu: powerplay sw initialized\n");
	}
	return ret;
}

static int pp_sw_fini(void *handle)
{
	struct pp_smumgr *smumgr;
	int ret = 0;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret = pp_check(pp_handle);
	if (ret == 0 || ret == PP_DPM_DISABLED) {
		smumgr = pp_handle->smu_mgr;

		if (smumgr->smumgr_funcs->smu_fini == NULL)
			return -EINVAL;

		ret = smumgr->smumgr_funcs->smu_fini(smumgr);
	}
	return ret;
}

static int pp_hw_init(void *handle)
{
	struct pp_smumgr *smumgr;
	struct pp_eventmgr *eventmgr;
	int ret = 0;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret = pp_check(pp_handle);

	if (ret == 0 || ret == PP_DPM_DISABLED) {
		smumgr = pp_handle->smu_mgr;

		if (smumgr->smumgr_funcs->start_smu == NULL)
			return -EINVAL;

		if(smumgr->smumgr_funcs->start_smu(smumgr)) {
			pr_err("smc start failed\n");
			smumgr->smumgr_funcs->smu_fini(smumgr);
			return -EINVAL;;
		}
		if (ret == PP_DPM_DISABLED)
			return PP_DPM_DISABLED;
	}

	ret = hwmgr_hw_init(pp_handle);
	if (ret)
		goto err;

	eventmgr = pp_handle->eventmgr;
	if (eventmgr->pp_eventmgr_init == NULL ||
		eventmgr->pp_eventmgr_init(eventmgr))
		goto err;

	return 0;
err:
	pp_handle->pm_en = 0;
	kfree(pp_handle->eventmgr);
	kfree(pp_handle->hwmgr);
	pp_handle->hwmgr = NULL;
	pp_handle->eventmgr = NULL;
	return PP_DPM_DISABLED;
}

static int pp_hw_fini(void *handle)
{
	struct pp_eventmgr *eventmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret == 0) {
		eventmgr = pp_handle->eventmgr;

		if (eventmgr->pp_eventmgr_fini != NULL)
			eventmgr->pp_eventmgr_fini(eventmgr);

		hwmgr_hw_fini(pp_handle);
	}
	return 0;
}

static bool pp_is_idle(void *handle)
{
	return false;
}

static int pp_wait_for_idle(void *handle)
{
	return 0;
}

static int pp_sw_reset(void *handle)
{
	return 0;
}


int amd_set_clockgating_by_smu(void *handle, uint32_t msg_id)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->update_clock_gatings == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->update_clock_gatings(hwmgr, &msg_id);
}

static int pp_set_powergating_state(void *handle,
				    enum amd_powergating_state state)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->enable_per_cu_power_gating == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	/* Enable/disable GFX per cu powergating through SMU */
	return hwmgr->hwmgr_func->enable_per_cu_power_gating(hwmgr,
			state == AMD_PG_STATE_GATE ? true : false);
}

static int pp_suspend(void *handle)
{
	struct pp_eventmgr *eventmgr;
	struct pem_event_data event_data = { {0} };
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	eventmgr = pp_handle->eventmgr;
	pem_handle_event(eventmgr, AMD_PP_EVENT_SUSPEND, &event_data);

	return 0;
}

static int pp_resume(void *handle)
{
	struct pp_eventmgr *eventmgr;
	struct pem_event_data event_data = { {0} };
	struct pp_smumgr *smumgr;
	int ret, ret1;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret1 = pp_check(pp_handle);

	if (ret1 != 0 && ret1 != PP_DPM_DISABLED)
		return ret1;

	smumgr = pp_handle->smu_mgr;

	if (smumgr->smumgr_funcs->start_smu == NULL)
		return -EINVAL;

	ret = smumgr->smumgr_funcs->start_smu(smumgr);
	if (ret) {
		pr_err("smc start failed\n");
		smumgr->smumgr_funcs->smu_fini(smumgr);
		return ret;
	}

	if (ret1 == PP_DPM_DISABLED)
		return ret1;

	eventmgr = pp_handle->eventmgr;

	pem_handle_event(eventmgr, AMD_PP_EVENT_RESUME, &event_data);

	return 0;
}

const struct amd_ip_funcs pp_ip_funcs = {
	.name = "powerplay",
	.early_init = pp_early_init,
	.late_init = NULL,
	.sw_init = pp_sw_init,
	.sw_fini = pp_sw_fini,
	.hw_init = pp_hw_init,
	.hw_fini = pp_hw_fini,
	.suspend = pp_suspend,
	.resume = pp_resume,
	.is_idle = pp_is_idle,
	.wait_for_idle = pp_wait_for_idle,
	.soft_reset = pp_sw_reset,
	.set_clockgating_state = NULL,
	.set_powergating_state = pp_set_powergating_state,
};

static int pp_dpm_load_fw(void *handle)
{
	return 0;
}

static int pp_dpm_fw_loading_complete(void *handle)
{
	return 0;
}

static int pp_dpm_force_performance_level(void *handle,
					enum amd_dpm_forced_level level)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->force_dpm_level == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	hwmgr->hwmgr_func->force_dpm_level(hwmgr, level);

	return 0;
}

static enum amd_dpm_forced_level pp_dpm_get_performance_level(
								void *handle)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	return hwmgr->dpm_level;
}

static int pp_dpm_get_sclk(void *handle, bool low)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_sclk == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_sclk(hwmgr, low);
}

static int pp_dpm_get_mclk(void *handle, bool low)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_mclk == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_mclk(hwmgr, low);
}

static int pp_dpm_powergate_vce(void *handle, bool gate)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->powergate_vce == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->powergate_vce(hwmgr, gate);
}

static int pp_dpm_powergate_uvd(void *handle, bool gate)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->powergate_uvd == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->powergate_uvd(hwmgr, gate);
}

static enum PP_StateUILabel power_state_convert(enum amd_pm_state_type  state)
{
	switch (state) {
	case POWER_STATE_TYPE_BATTERY:
		return PP_StateUILabel_Battery;
	case POWER_STATE_TYPE_BALANCED:
		return PP_StateUILabel_Balanced;
	case POWER_STATE_TYPE_PERFORMANCE:
		return PP_StateUILabel_Performance;
	default:
		return PP_StateUILabel_None;
	}
}

static int pp_dpm_dispatch_tasks(void *handle, enum amd_pp_event event_id,
		void *input, void *output)
{
	int ret = 0;
	struct pem_event_data data = { {0} };
	struct pp_instance *pp_handle = (struct pp_instance *)handle;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	switch (event_id) {
	case AMD_PP_EVENT_DISPLAY_CONFIG_CHANGE:
		ret = pem_handle_event(pp_handle->eventmgr, event_id, &data);
		break;
	case AMD_PP_EVENT_ENABLE_USER_STATE:
	{
		enum amd_pm_state_type  ps;

		if (input == NULL)
			return -EINVAL;
		ps = *(unsigned long *)input;

		data.requested_ui_label = power_state_convert(ps);
		ret = pem_handle_event(pp_handle->eventmgr, event_id, &data);
		break;
	}
	case AMD_PP_EVENT_COMPLETE_INIT:
		ret = pem_handle_event(pp_handle->eventmgr, event_id, &data);
		break;
	case AMD_PP_EVENT_READJUST_POWER_STATE:
		ret = pem_handle_event(pp_handle->eventmgr, event_id, &data);
		break;
	default:
		break;
	}
	return ret;
}

static enum amd_pm_state_type pp_dpm_get_current_power_state(void *handle)
{
	struct pp_hwmgr *hwmgr;
	struct pp_power_state *state;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->current_ps == NULL)
		return -EINVAL;

	state = hwmgr->current_ps;

	switch (state->classification.ui_label) {
	case PP_StateUILabel_Battery:
		return POWER_STATE_TYPE_BATTERY;
	case PP_StateUILabel_Balanced:
		return POWER_STATE_TYPE_BALANCED;
	case PP_StateUILabel_Performance:
		return POWER_STATE_TYPE_PERFORMANCE;
	default:
		if (state->classification.flags & PP_StateClassificationFlag_Boot)
			return  POWER_STATE_TYPE_INTERNAL_BOOT;
		else
			return POWER_STATE_TYPE_DEFAULT;
	}
}

static int pp_dpm_set_fan_control_mode(void *handle, uint32_t mode)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->set_fan_control_mode == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->set_fan_control_mode(hwmgr, mode);
}

static int pp_dpm_get_fan_control_mode(void *handle)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_fan_control_mode == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_fan_control_mode(hwmgr);
}

static int pp_dpm_set_fan_speed_percent(void *handle, uint32_t percent)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->set_fan_speed_percent == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->set_fan_speed_percent(hwmgr, percent);
}

static int pp_dpm_get_fan_speed_percent(void *handle, uint32_t *speed)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_fan_speed_percent == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_fan_speed_percent(hwmgr, speed);
}

static int pp_dpm_get_fan_speed_rpm(void *handle, uint32_t *rpm)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_fan_speed_rpm == NULL)
		return -EINVAL;

	return hwmgr->hwmgr_func->get_fan_speed_rpm(hwmgr, rpm);
}

static int pp_dpm_get_temperature(void *handle)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_temperature == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_temperature(hwmgr);
}

static int pp_dpm_get_pp_num_states(void *handle,
		struct pp_states_info *data)
{
	struct pp_hwmgr *hwmgr;
	int i;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->ps == NULL)
		return -EINVAL;

	data->nums = hwmgr->num_ps;

	for (i = 0; i < hwmgr->num_ps; i++) {
		struct pp_power_state *state = (struct pp_power_state *)
				((unsigned long)hwmgr->ps + i * hwmgr->ps_size);
		switch (state->classification.ui_label) {
		case PP_StateUILabel_Battery:
			data->states[i] = POWER_STATE_TYPE_BATTERY;
			break;
		case PP_StateUILabel_Balanced:
			data->states[i] = POWER_STATE_TYPE_BALANCED;
			break;
		case PP_StateUILabel_Performance:
			data->states[i] = POWER_STATE_TYPE_PERFORMANCE;
			break;
		default:
			if (state->classification.flags & PP_StateClassificationFlag_Boot)
				data->states[i] = POWER_STATE_TYPE_INTERNAL_BOOT;
			else
				data->states[i] = POWER_STATE_TYPE_DEFAULT;
		}
	}

	return 0;
}

static int pp_dpm_get_pp_table(void *handle, char **table)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (!hwmgr->soft_pp_table)
		return -EINVAL;

	*table = (char *)hwmgr->soft_pp_table;

	return hwmgr->soft_pp_table_size;
}

static int pp_dpm_set_pp_table(void *handle, const char *buf, size_t size)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (!hwmgr->hardcode_pp_table) {
		hwmgr->hardcode_pp_table = kmemdup(hwmgr->soft_pp_table,
						   hwmgr->soft_pp_table_size,
						   GFP_KERNEL);

		if (!hwmgr->hardcode_pp_table)
			return -ENOMEM;
	}

	memcpy(hwmgr->hardcode_pp_table, buf, size);

	hwmgr->soft_pp_table = hwmgr->hardcode_pp_table;

	return amd_powerplay_reset(handle);
}

static int pp_dpm_force_clock_level(void *handle,
		enum pp_clock_type type, uint32_t mask)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->force_clock_level == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->force_clock_level(hwmgr, type, mask);
}

static int pp_dpm_print_clock_levels(void *handle,
		enum pp_clock_type type, char *buf)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->print_clock_levels == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}
	return hwmgr->hwmgr_func->print_clock_levels(hwmgr, type, buf);
}

static int pp_dpm_get_sclk_od(void *handle)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_sclk_od == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_sclk_od(hwmgr);
}

static int pp_dpm_set_sclk_od(void *handle, uint32_t value)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->set_sclk_od == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->set_sclk_od(hwmgr, value);
}

static int pp_dpm_get_mclk_od(void *handle)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->get_mclk_od == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->get_mclk_od(hwmgr);
}

static int pp_dpm_set_mclk_od(void *handle, uint32_t value)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->set_mclk_od == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->set_mclk_od(hwmgr, value);
}

static int pp_dpm_read_sensor(void *handle, int idx, int32_t *value)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr->hwmgr_func->read_sensor == NULL) {
		pr_info("%s was not implemented.\n", __func__);
		return 0;
	}

	return hwmgr->hwmgr_func->read_sensor(hwmgr, idx, value);
}

static struct amd_vce_state*
pp_dpm_get_vce_clock_state(void *handle, unsigned idx)
{
	struct pp_hwmgr *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return NULL;

	hwmgr = pp_handle->hwmgr;

	if (hwmgr && idx < hwmgr->num_vce_state_tables)
		return &hwmgr->vce_states[idx];

	return NULL;
}

const struct amd_powerplay_funcs pp_dpm_funcs = {
	.get_temperature = pp_dpm_get_temperature,
	.load_firmware = pp_dpm_load_fw,
	.wait_for_fw_loading_complete = pp_dpm_fw_loading_complete,
	.force_performance_level = pp_dpm_force_performance_level,
	.get_performance_level = pp_dpm_get_performance_level,
	.get_current_power_state = pp_dpm_get_current_power_state,
	.get_sclk = pp_dpm_get_sclk,
	.get_mclk = pp_dpm_get_mclk,
	.powergate_vce = pp_dpm_powergate_vce,
	.powergate_uvd = pp_dpm_powergate_uvd,
	.dispatch_tasks = pp_dpm_dispatch_tasks,
	.set_fan_control_mode = pp_dpm_set_fan_control_mode,
	.get_fan_control_mode = pp_dpm_get_fan_control_mode,
	.set_fan_speed_percent = pp_dpm_set_fan_speed_percent,
	.get_fan_speed_percent = pp_dpm_get_fan_speed_percent,
	.get_fan_speed_rpm = pp_dpm_get_fan_speed_rpm,
	.get_pp_num_states = pp_dpm_get_pp_num_states,
	.get_pp_table = pp_dpm_get_pp_table,
	.set_pp_table = pp_dpm_set_pp_table,
	.force_clock_level = pp_dpm_force_clock_level,
	.print_clock_levels = pp_dpm_print_clock_levels,
	.get_sclk_od = pp_dpm_get_sclk_od,
	.set_sclk_od = pp_dpm_set_sclk_od,
	.get_mclk_od = pp_dpm_get_mclk_od,
	.set_mclk_od = pp_dpm_set_mclk_od,
	.read_sensor = pp_dpm_read_sensor,
	.get_vce_clock_state = pp_dpm_get_vce_clock_state,
};

int amd_powerplay_create(struct amd_pp_init *pp_init,
				void **handle)
{
	struct pp_instance *instance;

	if (pp_init == NULL || handle == NULL)
		return -EINVAL;

	instance = kzalloc(sizeof(struct pp_instance), GFP_KERNEL);
	if (instance == NULL)
		return -ENOMEM;

	instance->pp_valid = PP_VALID;
	instance->chip_family = pp_init->chip_family;
	instance->chip_id = pp_init->chip_id;
	instance->pm_en = pp_init->pm_en;
	instance->feature_mask = pp_init->feature_mask;
	instance->device = pp_init->device;
	*handle = instance;

	return 0;
}

int amd_powerplay_destroy(void *handle)
{
	struct pp_instance *instance = (struct pp_instance *)handle;

	if (instance->pm_en) {
		kfree(instance->eventmgr);
		kfree(instance->hwmgr);
		instance->hwmgr = NULL;
		instance->eventmgr = NULL;
	}

	kfree(instance->smu_mgr);
	instance->smu_mgr = NULL;
	kfree(instance);
	instance = NULL;
	return 0;
}

int amd_powerplay_reset(void *handle)
{
	struct pp_instance *instance = (struct pp_instance *)handle;
	struct pp_eventmgr *eventmgr;
	struct pem_event_data event_data = { {0} };
	int ret;

	if (cgs_is_virtualization_enabled(instance->smu_mgr->device))
		return PP_DPM_DISABLED;

	ret = pp_check(instance);
	if (ret != 0)
		return ret;

	ret = pp_hw_fini(handle);
	if (ret)
		return ret;

	ret = hwmgr_hw_init(instance);
	if (ret)
		return PP_DPM_DISABLED;

	eventmgr = instance->eventmgr;

	if (eventmgr->pp_eventmgr_init == NULL)
		return PP_DPM_DISABLED;

	ret = eventmgr->pp_eventmgr_init(eventmgr);
	if (ret)
		return ret;

	return pem_handle_event(eventmgr, AMD_PP_EVENT_COMPLETE_INIT, &event_data);
}

/* export this function to DAL */

int amd_powerplay_display_configuration_change(void *handle,
	const struct amd_pp_display_configuration *display_config)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	phm_store_dal_configuration_data(hwmgr, display_config);

	return 0;
}

int amd_powerplay_get_display_power_level(void *handle,
		struct amd_pp_simple_clock_info *output)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (output == NULL)
		return -EINVAL;

	return phm_get_dal_power_level(hwmgr, output);
}

int amd_powerplay_get_current_clocks(void *handle,
		struct amd_pp_clock_info *clocks)
{
	struct amd_pp_simple_clock_info simple_clocks;
	struct pp_clock_info hw_clocks;
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	phm_get_dal_power_level(hwmgr, &simple_clocks);

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps, PHM_PlatformCaps_PowerContainment)) {
		if (0 != phm_get_clock_info(hwmgr, &hwmgr->current_ps->hardware, &hw_clocks, PHM_PerformanceLevelDesignation_PowerContainment))
			PP_ASSERT_WITH_CODE(0, "Error in PHM_GetPowerContainmentClockInfo", return -1);
	} else {
		if (0 != phm_get_clock_info(hwmgr, &hwmgr->current_ps->hardware, &hw_clocks, PHM_PerformanceLevelDesignation_Activity))
			PP_ASSERT_WITH_CODE(0, "Error in PHM_GetClockInfo", return -1);
	}

	clocks->min_engine_clock = hw_clocks.min_eng_clk;
	clocks->max_engine_clock = hw_clocks.max_eng_clk;
	clocks->min_memory_clock = hw_clocks.min_mem_clk;
	clocks->max_memory_clock = hw_clocks.max_mem_clk;
	clocks->min_bus_bandwidth = hw_clocks.min_bus_bandwidth;
	clocks->max_bus_bandwidth = hw_clocks.max_bus_bandwidth;

	clocks->max_engine_clock_in_sr = hw_clocks.max_eng_clk;
	clocks->min_engine_clock_in_sr = hw_clocks.min_eng_clk;

	clocks->max_clocks_state = simple_clocks.level;

	if (0 == phm_get_current_shallow_sleep_clocks(hwmgr, &hwmgr->current_ps->hardware, &hw_clocks)) {
		clocks->max_engine_clock_in_sr = hw_clocks.max_eng_clk;
		clocks->min_engine_clock_in_sr = hw_clocks.min_eng_clk;
	}

	return 0;

}

int amd_powerplay_get_clock_by_type(void *handle, enum amd_pp_clock_type type, struct amd_pp_clocks *clocks)
{
	int result = -1;
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;

	if (clocks == NULL)
		return -EINVAL;

	result = phm_get_clock_by_type(hwmgr, type, clocks);

	return result;
}

int amd_powerplay_get_display_mode_validation_clocks(void *handle,
		struct amd_pp_simple_clock_info *clocks)
{
	struct pp_hwmgr  *hwmgr;
	struct pp_instance *pp_handle = (struct pp_instance *)handle;
	int ret = 0;

	ret = pp_check(pp_handle);

	if (ret != 0)
		return ret;

	hwmgr = pp_handle->hwmgr;


	if (clocks == NULL)
		return -EINVAL;

	if (phm_cap_enabled(hwmgr->platform_descriptor.platformCaps, PHM_PlatformCaps_DynamicPatchPowerState))
		ret = phm_get_max_high_clocks(hwmgr, clocks);

	return ret;
}


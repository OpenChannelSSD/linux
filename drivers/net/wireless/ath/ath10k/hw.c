/*
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/types.h>
#include "core.h"
#include "hw.h"
#include "hif.h"
#include "wmi-ops.h"

const struct ath10k_hw_regs qca988x_regs = {
	.rtc_soc_base_address		= 0x00004000,
	.rtc_wmac_base_address		= 0x00005000,
	.soc_core_base_address		= 0x00009000,
	.wlan_mac_base_address		= 0x00020000,
	.ce_wrapper_base_address	= 0x00057000,
	.ce0_base_address		= 0x00057400,
	.ce1_base_address		= 0x00057800,
	.ce2_base_address		= 0x00057c00,
	.ce3_base_address		= 0x00058000,
	.ce4_base_address		= 0x00058400,
	.ce5_base_address		= 0x00058800,
	.ce6_base_address		= 0x00058c00,
	.ce7_base_address		= 0x00059000,
	.soc_reset_control_si0_rst_mask	= 0x00000001,
	.soc_reset_control_ce_rst_mask	= 0x00040000,
	.soc_chip_id_address		= 0x000000ec,
	.scratch_3_address		= 0x00000030,
	.fw_indicator_address		= 0x00009030,
	.pcie_local_base_address	= 0x00080000,
	.ce_wrap_intr_sum_host_msi_lsb	= 0x00000008,
	.ce_wrap_intr_sum_host_msi_mask	= 0x0000ff00,
	.pcie_intr_fw_mask		= 0x00000400,
	.pcie_intr_ce_mask_all		= 0x0007f800,
	.pcie_intr_clr_address		= 0x00000014,
};

const struct ath10k_hw_regs qca6174_regs = {
	.rtc_soc_base_address			= 0x00000800,
	.rtc_wmac_base_address			= 0x00001000,
	.soc_core_base_address			= 0x0003a000,
	.wlan_mac_base_address			= 0x00010000,
	.ce_wrapper_base_address		= 0x00034000,
	.ce0_base_address			= 0x00034400,
	.ce1_base_address			= 0x00034800,
	.ce2_base_address			= 0x00034c00,
	.ce3_base_address			= 0x00035000,
	.ce4_base_address			= 0x00035400,
	.ce5_base_address			= 0x00035800,
	.ce6_base_address			= 0x00035c00,
	.ce7_base_address			= 0x00036000,
	.soc_reset_control_si0_rst_mask		= 0x00000000,
	.soc_reset_control_ce_rst_mask		= 0x00000001,
	.soc_chip_id_address			= 0x000000f0,
	.scratch_3_address			= 0x00000028,
	.fw_indicator_address			= 0x0003a028,
	.pcie_local_base_address		= 0x00080000,
	.ce_wrap_intr_sum_host_msi_lsb		= 0x00000008,
	.ce_wrap_intr_sum_host_msi_mask		= 0x0000ff00,
	.pcie_intr_fw_mask			= 0x00000400,
	.pcie_intr_ce_mask_all			= 0x0007f800,
	.pcie_intr_clr_address			= 0x00000014,
};

const struct ath10k_hw_regs qca99x0_regs = {
	.rtc_soc_base_address			= 0x00080000,
	.rtc_wmac_base_address			= 0x00000000,
	.soc_core_base_address			= 0x00082000,
	.wlan_mac_base_address			= 0x00030000,
	.ce_wrapper_base_address		= 0x0004d000,
	.ce0_base_address			= 0x0004a000,
	.ce1_base_address			= 0x0004a400,
	.ce2_base_address			= 0x0004a800,
	.ce3_base_address			= 0x0004ac00,
	.ce4_base_address			= 0x0004b000,
	.ce5_base_address			= 0x0004b400,
	.ce6_base_address			= 0x0004b800,
	.ce7_base_address			= 0x0004bc00,
	/* Note: qca99x0 supports upto 12 Copy Engines. Other than address of
	 * CE0 and CE1 no other copy engine is directly referred in the code.
	 * It is not really necessary to assign address for newly supported
	 * CEs in this address table.
	 *	Copy Engine		Address
	 *	CE8			0x0004c000
	 *	CE9			0x0004c400
	 *	CE10			0x0004c800
	 *	CE11			0x0004cc00
	 */
	.soc_reset_control_si0_rst_mask		= 0x00000001,
	.soc_reset_control_ce_rst_mask		= 0x00000100,
	.soc_chip_id_address			= 0x000000ec,
	.scratch_3_address			= 0x00040050,
	.fw_indicator_address			= 0x00040050,
	.pcie_local_base_address		= 0x00000000,
	.ce_wrap_intr_sum_host_msi_lsb		= 0x0000000c,
	.ce_wrap_intr_sum_host_msi_mask		= 0x00fff000,
	.pcie_intr_fw_mask			= 0x00100000,
	.pcie_intr_ce_mask_all			= 0x000fff00,
	.pcie_intr_clr_address			= 0x00000010,
};

const struct ath10k_hw_regs qca4019_regs = {
	.rtc_soc_base_address                   = 0x00080000,
	.soc_core_base_address                  = 0x00082000,
	.wlan_mac_base_address                  = 0x00030000,
	.ce_wrapper_base_address                = 0x0004d000,
	.ce0_base_address                       = 0x0004a000,
	.ce1_base_address                       = 0x0004a400,
	.ce2_base_address                       = 0x0004a800,
	.ce3_base_address                       = 0x0004ac00,
	.ce4_base_address                       = 0x0004b000,
	.ce5_base_address                       = 0x0004b400,
	.ce6_base_address                       = 0x0004b800,
	.ce7_base_address                       = 0x0004bc00,
	/* qca4019 supports upto 12 copy engines. Since base address
	 * of ce8 to ce11 are not directly referred in the code,
	 * no need have them in separate members in this table.
	 *      Copy Engine             Address
	 *      CE8                     0x0004c000
	 *      CE9                     0x0004c400
	 *      CE10                    0x0004c800
	 *      CE11                    0x0004cc00
	 */
	.soc_reset_control_si0_rst_mask         = 0x00000001,
	.soc_reset_control_ce_rst_mask          = 0x00000100,
	.soc_chip_id_address                    = 0x000000ec,
	.fw_indicator_address                   = 0x0004f00c,
	.ce_wrap_intr_sum_host_msi_lsb          = 0x0000000c,
	.ce_wrap_intr_sum_host_msi_mask         = 0x00fff000,
	.pcie_intr_fw_mask                      = 0x00100000,
	.pcie_intr_ce_mask_all                  = 0x000fff00,
	.pcie_intr_clr_address                  = 0x00000010,
};

const struct ath10k_hw_values qca988x_values = {
	.rtc_state_val_on		= 3,
	.ce_count			= 8,
	.msi_assign_ce_max		= 7,
	.num_target_ce_config_wlan	= 7,
	.ce_desc_meta_data_mask		= 0xFFFC,
	.ce_desc_meta_data_lsb		= 2,
};

const struct ath10k_hw_values qca6174_values = {
	.rtc_state_val_on		= 3,
	.ce_count			= 8,
	.msi_assign_ce_max		= 7,
	.num_target_ce_config_wlan	= 7,
	.ce_desc_meta_data_mask		= 0xFFFC,
	.ce_desc_meta_data_lsb		= 2,
};

const struct ath10k_hw_values qca99x0_values = {
	.rtc_state_val_on		= 5,
	.ce_count			= 12,
	.msi_assign_ce_max		= 12,
	.num_target_ce_config_wlan	= 10,
	.ce_desc_meta_data_mask		= 0xFFF0,
	.ce_desc_meta_data_lsb		= 4,
};

const struct ath10k_hw_values qca9888_values = {
	.rtc_state_val_on		= 3,
	.ce_count			= 12,
	.msi_assign_ce_max		= 12,
	.num_target_ce_config_wlan	= 10,
	.ce_desc_meta_data_mask		= 0xFFF0,
	.ce_desc_meta_data_lsb		= 4,
};

const struct ath10k_hw_values qca4019_values = {
	.ce_count                       = 12,
	.num_target_ce_config_wlan      = 10,
	.ce_desc_meta_data_mask         = 0xFFF0,
	.ce_desc_meta_data_lsb          = 4,
};

void ath10k_hw_fill_survey_time(struct ath10k *ar, struct survey_info *survey,
				u32 cc, u32 rcc, u32 cc_prev, u32 rcc_prev)
{
	u32 cc_fix = 0;
	u32 rcc_fix = 0;
	enum ath10k_hw_cc_wraparound_type wraparound_type;

	survey->filled |= SURVEY_INFO_TIME |
			  SURVEY_INFO_TIME_BUSY;

	wraparound_type = ar->hw_params.cc_wraparound_type;

	if (cc < cc_prev || rcc < rcc_prev) {
		switch (wraparound_type) {
		case ATH10K_HW_CC_WRAP_SHIFTED_ALL:
			if (cc < cc_prev) {
				cc_fix = 0x7fffffff;
				survey->filled &= ~SURVEY_INFO_TIME_BUSY;
			}
			break;
		case ATH10K_HW_CC_WRAP_SHIFTED_EACH:
			if (cc < cc_prev)
				cc_fix = 0x7fffffff;

			if (rcc < rcc_prev)
				rcc_fix = 0x7fffffff;
			break;
		case ATH10K_HW_CC_WRAP_DISABLED:
			break;
		}
	}

	cc -= cc_prev - cc_fix;
	rcc -= rcc_prev - rcc_fix;

	survey->time = CCNT_TO_MSEC(ar, cc);
	survey->time_busy = CCNT_TO_MSEC(ar, rcc);
}

/* The firmware does not support setting the coverage class. Instead this
 * function monitors and modifies the corresponding MAC registers.
 */
static void ath10k_hw_qca988x_set_coverage_class(struct ath10k *ar,
						 s16 value)
{
	u32 slottime_reg;
	u32 slottime;
	u32 timeout_reg;
	u32 ack_timeout;
	u32 cts_timeout;
	u32 phyclk_reg;
	u32 phyclk;
	u64 fw_dbglog_mask;
	u32 fw_dbglog_level;

	mutex_lock(&ar->conf_mutex);

	/* Only modify registers if the core is started. */
	if ((ar->state != ATH10K_STATE_ON) &&
	    (ar->state != ATH10K_STATE_RESTARTED))
		goto unlock;

	/* Retrieve the current values of the two registers that need to be
	 * adjusted.
	 */
	slottime_reg = ath10k_hif_read32(ar, WLAN_MAC_BASE_ADDRESS +
					     WAVE1_PCU_GBL_IFS_SLOT);
	timeout_reg = ath10k_hif_read32(ar, WLAN_MAC_BASE_ADDRESS +
					    WAVE1_PCU_ACK_CTS_TIMEOUT);
	phyclk_reg = ath10k_hif_read32(ar, WLAN_MAC_BASE_ADDRESS +
					   WAVE1_PHYCLK);
	phyclk = MS(phyclk_reg, WAVE1_PHYCLK_USEC) + 1;

	if (value < 0)
		value = ar->fw_coverage.coverage_class;

	/* Break out if the coverage class and registers have the expected
	 * value.
	 */
	if (value == ar->fw_coverage.coverage_class &&
	    slottime_reg == ar->fw_coverage.reg_slottime_conf &&
	    timeout_reg == ar->fw_coverage.reg_ack_cts_timeout_conf &&
	    phyclk_reg == ar->fw_coverage.reg_phyclk)
		goto unlock;

	/* Store new initial register values from the firmware. */
	if (slottime_reg != ar->fw_coverage.reg_slottime_conf)
		ar->fw_coverage.reg_slottime_orig = slottime_reg;
	if (timeout_reg != ar->fw_coverage.reg_ack_cts_timeout_conf)
		ar->fw_coverage.reg_ack_cts_timeout_orig = timeout_reg;
	ar->fw_coverage.reg_phyclk = phyclk_reg;

	/* Calculat new value based on the (original) firmware calculation. */
	slottime_reg = ar->fw_coverage.reg_slottime_orig;
	timeout_reg = ar->fw_coverage.reg_ack_cts_timeout_orig;

	/* Do some sanity checks on the slottime register. */
	if (slottime_reg % phyclk) {
		ath10k_warn(ar,
			    "failed to set coverage class: expected integer microsecond value in register\n");

		goto store_regs;
	}

	slottime = MS(slottime_reg, WAVE1_PCU_GBL_IFS_SLOT);
	slottime = slottime / phyclk;
	if (slottime != 9 && slottime != 20) {
		ath10k_warn(ar,
			    "failed to set coverage class: expected slot time of 9 or 20us in HW register. It is %uus.\n",
			    slottime);

		goto store_regs;
	}

	/* Recalculate the register values by adding the additional propagation
	 * delay (3us per coverage class).
	 */

	slottime = MS(slottime_reg, WAVE1_PCU_GBL_IFS_SLOT);
	slottime += value * 3 * phyclk;
	slottime = min_t(u32, slottime, WAVE1_PCU_GBL_IFS_SLOT_MAX);
	slottime = SM(slottime, WAVE1_PCU_GBL_IFS_SLOT);
	slottime_reg = (slottime_reg & ~WAVE1_PCU_GBL_IFS_SLOT_MASK) | slottime;

	/* Update ack timeout (lower halfword). */
	ack_timeout = MS(timeout_reg, WAVE1_PCU_ACK_CTS_TIMEOUT_ACK);
	ack_timeout += 3 * value * phyclk;
	ack_timeout = min_t(u32, ack_timeout, WAVE1_PCU_ACK_CTS_TIMEOUT_MAX);
	ack_timeout = SM(ack_timeout, WAVE1_PCU_ACK_CTS_TIMEOUT_ACK);

	/* Update cts timeout (upper halfword). */
	cts_timeout = MS(timeout_reg, WAVE1_PCU_ACK_CTS_TIMEOUT_CTS);
	cts_timeout += 3 * value * phyclk;
	cts_timeout = min_t(u32, cts_timeout, WAVE1_PCU_ACK_CTS_TIMEOUT_MAX);
	cts_timeout = SM(cts_timeout, WAVE1_PCU_ACK_CTS_TIMEOUT_CTS);

	timeout_reg = ack_timeout | cts_timeout;

	ath10k_hif_write32(ar,
			   WLAN_MAC_BASE_ADDRESS + WAVE1_PCU_GBL_IFS_SLOT,
			   slottime_reg);
	ath10k_hif_write32(ar,
			   WLAN_MAC_BASE_ADDRESS + WAVE1_PCU_ACK_CTS_TIMEOUT,
			   timeout_reg);

	/* Ensure we have a debug level of WARN set for the case that the
	 * coverage class is larger than 0. This is important as we need to
	 * set the registers again if the firmware does an internal reset and
	 * this way we will be notified of the event.
	 */
	fw_dbglog_mask = ath10k_debug_get_fw_dbglog_mask(ar);
	fw_dbglog_level = ath10k_debug_get_fw_dbglog_level(ar);

	if (value > 0) {
		if (fw_dbglog_level > ATH10K_DBGLOG_LEVEL_WARN)
			fw_dbglog_level = ATH10K_DBGLOG_LEVEL_WARN;
		fw_dbglog_mask = ~0;
	}

	ath10k_wmi_dbglog_cfg(ar, fw_dbglog_mask, fw_dbglog_level);

store_regs:
	/* After an error we will not retry setting the coverage class. */
	spin_lock_bh(&ar->data_lock);
	ar->fw_coverage.coverage_class = value;
	spin_unlock_bh(&ar->data_lock);

	ar->fw_coverage.reg_slottime_conf = slottime_reg;
	ar->fw_coverage.reg_ack_cts_timeout_conf = timeout_reg;

unlock:
	mutex_unlock(&ar->conf_mutex);
}

const struct ath10k_hw_ops qca988x_ops = {
	.set_coverage_class = ath10k_hw_qca988x_set_coverage_class,
};

static int ath10k_qca99x0_rx_desc_get_l3_pad_bytes(struct htt_rx_desc *rxd)
{
	return MS(__le32_to_cpu(rxd->msdu_end.qca99x0.info1),
		  RX_MSDU_END_INFO1_L3_HDR_PAD);
}

const struct ath10k_hw_ops qca99x0_ops = {
	.rx_desc_get_l3_pad_bytes = ath10k_qca99x0_rx_desc_get_l3_pad_bytes,
};

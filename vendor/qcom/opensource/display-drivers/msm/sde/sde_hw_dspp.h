/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2015-2021, The Linux Foundation. All rights reserved.
 */

#ifndef _SDE_HW_DSPP_H
#define _SDE_HW_DSPP_H

#include <drm/msm_drm_pp.h>
#include "msm_drv.h"

struct sde_hw_dspp;

/**
 * struct sde_hw_dspp_ops - interface to the dspp hardware driver functions
 * Caller must call the init function to get the dspp context for each dspp
 * Assumption is these functions will be called after clocks are enabled
 */
struct sde_hw_dspp_ops {
	/**
	 * setup_histogram - setup dspp histogram
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_histogram)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * read_histogram - read dspp histogram
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*read_histogram)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * lock_histogram - lock dspp histogram buffer
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*lock_histogram)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_igc - update dspp igc
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_igc)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_hsic - setup dspp pa hsic
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_hsic)(struct sde_hw_dspp *dspp, void *cfg);

	/**
	 * setup_pcc - setup dspp pcc
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pcc)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_sharpening - setup dspp sharpening
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_sharpening)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_memcol_skin - setup dspp memcolor skin
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_memcol_skin)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_memcol_sky - setup dspp memcolor sky
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_memcol_sky)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_memcol_foliage - setup dspp memcolor foliage
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_memcol_foliage)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_memcol_prot - setup dspp memcolor protection
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_memcol_prot)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_sixzone - setup dspp six zone
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_sixzone)(struct sde_hw_dspp *dspp, void *cfg);

	/**
	 * setup_danger_safe - setup danger safe LUTS
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_danger_safe)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_pa_dither - setup dspp PA dither
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_pa_dither)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_vlut - setup dspp PA VLUT
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_vlut)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_gc - update dspp gc
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_gc)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_gamut - update dspp gamut
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_gamut)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * validate_ad - check if ad property can be set
	 * @ctx: Pointer to dspp context
	 * @prop: Pointer to ad property being validated
	 */
	int (*validate_ad)(struct sde_hw_dspp *ctx, u32 *prop);

	/**
	 * setup_ad - update the ad property
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to ad configuration
	 */
	void (*setup_ad)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * ad_read_intr_resp - function to get interrupt response for ad
	 * @event: Event for which response needs to be read
	 * @resp_in: Pointer to u32 where resp ad4 input value is dumped.
	 * @resp_out: Pointer to u32 where resp ad4 output value is dumped.
	 */
	void (*ad_read_intr_resp)(struct sde_hw_dspp *ctx, u32 event,
			u32 *resp_in, u32 *resp_out);

	/**
	 * setup_ltm_init - setup LTM INIT
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_ltm_init)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_ltm_roi - setup LTM ROI
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_ltm_roi)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_ltm_vlut - setup LTM VLUT
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_ltm_vlut)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_ltm_hist_ctrl - setup LTM histogram control
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 * @enable: feature enable/disable value
	 * @iova: aligned hist buffer address
	 */
	void (*setup_ltm_hist_ctrl)(struct sde_hw_dspp *ctx, void *cfg,
				    bool enable, u64 iova);

	/**
	 * setup_ltm_hist_buffer - setup LTM histogram buffer
	 * @ctx: Pointer to dspp context
	 * @iova: aligned hist buffer address
	 */
	void (*setup_ltm_hist_buffer)(struct sde_hw_dspp *ctx, u64 iova);

	/**
	 * setup_ltm_thresh - setup LTM histogram thresh
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_ltm_thresh)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * ltm_read_intr_status - function to read ltm interrupt status
	 * @ctx: Pointer to dspp context
	 * @status: Pointer to u32 where ltm status value is dumped.
	 */
	void (*ltm_read_intr_status)(struct sde_hw_dspp *ctx, u32 *status);

	/**
	 * clear_ltm_merge_mode - clear LTM merge_mode bit
	 * @ctx: Pointer to dspp context
	 */
	void (*clear_ltm_merge_mode)(struct sde_hw_dspp *ctx);

	/**
	 * validate_rc_mask -  Validate RC mask configuration
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*validate_rc_mask)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_rc_mask -  Setup RC mask configuration
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*setup_rc_mask)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * validate_rc_pu_roi -  Validate RC regions in during partial update.
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*validate_rc_pu_roi)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_rc_pu_roi -  Setup RC regions in during partial update.
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*setup_rc_pu_roi)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * validate_spr_init_config -  Validate SPR configuration
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*validate_spr_init_config)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * validate_spr_udc_config -  Validate SPR configuration
	 * @ctx: Pointer to dspp context.
	 * @cfg: Pointer to configuration.
	 * Return: 0 on success, non-zero otherwise.
	 */
	int (*validate_spr_udc_config)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_spr_init_config - function to configure spr hw block
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_spr_init_config)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_spr_udc_config - function to configure spr hw block
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_spr_udc_config)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_spr_pu_config - function to configure spr hw block pu offsets
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_spr_pu_config)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * read_spr_opr_value - function to read spr opr value
	 * @ctx: Pointer to dspp context
	 * @opr_value: Pointer to opr value
	 */
	int (*read_spr_opr_value)(struct sde_hw_dspp *ctx, u32 *opr_value);

	/**
	 * setup_demura_cfg - function to program demura cfg
	 * @ctx: Pointer to dspp context
	 * @status: Pointer to configuration.
	 */
	void (*setup_demura_cfg)(struct sde_hw_dspp *ctx, void *cfg);

	/**
	 * setup_demura_backlight_cfg - function to program demura backlight
	 * @ctx: Pointer to dspp context
	 * @status: Pointer to configuration.
	 */
	void (*setup_demura_backlight_cfg)(struct sde_hw_dspp *ctx, u64 val);

	/**
	 * demura_read_plane_status - Query demura plane status
	 * @ctx: Pointer to dspp context
	 * @status: Demura plane used by DSPP. demura_fetch_planes enum value.
	 */
	void (*demura_read_plane_status)(struct sde_hw_dspp *ctx, u32 *status);
	/**
	 * setup_demura_pu_config - function to configure demura hw block pu offsets
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_demura_pu_config)(struct sde_hw_dspp *ctx, void *cfg);
	/**
	 * setup_demura_cfg0_param2 - function to configure demura cfg0_param2 params
	 * @ctx: Pointer to dspp context
	 * @cfg: Pointer to configuration
	 */
	void (*setup_demura_cfg0_param2)(struct sde_hw_dspp *ctx, void *cfg);
};

/**
 * struct sde_hw_rc_state - rounded corner cached state per RC instance
 * @last_rc_mask_cfg: cached value of most recent programmed mask.
 * @last_roi_list: cached value of most recent processed list of ROIs.
 */
struct sde_hw_rc_state {
	struct drm_msm_rc_mask_cfg *last_rc_mask_cfg;
	struct msm_roi_list *last_roi_list;
};

/**
 * struct sde_hw_dspp - dspp description
 * @base: Hardware block base structure
 * @hw: Block hardware details
 * @hw_top: Block hardware top details
 * @idx: DSPP index
 * @cap: Pointer to layer_cfg
 * @sb_dma_in_use: hint indicating if sb dma is being used for this dspp
 * @ops: Pointer to operations possible for this DSPP
 * @ltm_checksum_support: flag to check if checksum present
 * @spr_cfg_18_default: Default SPR cfg 18 HW details. Needed for PU handling
 * @rc_state: Structure for RC state
 */
struct sde_hw_dspp {
	struct sde_hw_blk_reg_map hw;

	/* dspp top */
	struct sde_hw_blk_reg_map hw_top;

	/* dspp */
	enum sde_dspp idx;
	const struct sde_dspp_cfg *cap;
	bool sb_dma_in_use;
	bool ltm_checksum_support;
	u32 spr_cfg_18_default;

	/* Ops */
	struct sde_hw_dspp_ops ops;

	/* rc state */
	struct sde_hw_rc_state rc_state;
};

/**
 * to_sde_hw_dspp - convert base hw object to sde_hw_dspp container
 * @hw: Pointer to hardware block register map object
 * return: Pointer to hardware block container
 */
static inline struct sde_hw_dspp *to_sde_hw_dspp(struct sde_hw_blk_reg_map *hw)
{
	return container_of(hw, struct sde_hw_dspp, hw);
}

/**
 * sde_hw_dspp_init - initializes the dspp hw driver object.
 * should be called once before accessing every dspp.
 * @idx:  DSPP index for which driver object is required
 * @addr: Mapped register io address of MDP
 * @Return: pointer to structure or ERR_PTR
 */
struct sde_hw_blk_reg_map *sde_hw_dspp_init(enum sde_dspp idx,
			void __iomem *addr,
			struct sde_mdss_cfg *m);

/**
 * sde_hw_dspp_destroy(): Destroys DSPP driver context
 * @hw: Pointer to hardware block register map object
 */
void sde_hw_dspp_destroy(struct sde_hw_blk_reg_map *hw);

#endif /*_SDE_HW_DSPP_H */

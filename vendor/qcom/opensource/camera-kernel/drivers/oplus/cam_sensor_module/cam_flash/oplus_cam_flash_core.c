// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>

#include "cam_sensor_cmn_header.h"
#include "oplus_cam_flash_core.h"
#include "cam_res_mgr_api.h"
#include "cam_common_util.h"
#include "cam_packet_util.h"

bool oplus_cam_flash_is_new_ma(
	struct cam_flash_ctrl *flash_ctrl,
	struct cam_flash_frame_setting *flash_data)
{
    int i = 0;
    for (i = 0; i < flash_ctrl->torch_num_sources; i++) {
        if (flash_ctrl->torch_trigger[i]) {
            if (flash_data->led_current_ma[i] !=
                oplus_curr_ma)
            {
                oplus_curr_ma = flash_data->led_current_ma[i];
                return true;
            }
        }
    }
    return false;
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2020, The Linux Foundation. All rights reserved.
 */

#ifndef _OPLUS_CAM_FLASH_CORE_H_
#define _OPLUS_CAM_FLASH_CORE_H_

#include <media/cam_sensor.h>
#include "cam_flash_dev.h"
static uint32_t oplus_curr_ma = 0;

bool oplus_cam_flash_is_new_ma(
	struct cam_flash_ctrl *flash_ctrl,
	struct cam_flash_frame_setting *flash_data);

#endif /*_OPLUS_CAM_FLASH_CORE_H_*/

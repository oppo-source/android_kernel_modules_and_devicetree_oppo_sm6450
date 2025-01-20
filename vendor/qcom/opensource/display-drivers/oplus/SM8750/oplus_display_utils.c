/***************************************************************
** Copyright (C), 2024, OPLUS Mobile Comm Corp., Ltd
**
** File : oplus_display_utils.c
** Description : display driver private utils
** Version : 1.1
** Date : 2024/05/09
** Author : Display
******************************************************************/
#include "oplus_display_utils.h"
#include <soc/oplus/system/boot_mode.h>
#include <soc/oplus/system/oplus_project.h>
#include <soc/oplus/device_info.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include "dsi_display.h"
#include "oplus_debug.h"
#include "oplus_display_panel_cmd.h"

#ifdef OPLUS_FEATURE_DISPLAY_ADFR
#include "oplus_adfr.h"
#endif /* OPLUS_FEATURE_DISPLAY_ADFR */

#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
#include "oplus_onscreenfingerprint.h"
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */

#define GAMMA_COMPENSATION_READ_RETRY_MAX 5
#define GAMMA_COMPENSATION_PERCENTAGE1 82/100
#define GAMMA_COMPENSATION_PERCENTAGE2 87/100
#define REG_SIZE 256
#define OPLUS_DSI_CMD_PRINT_BUF_SIZE 1024
#define GAMMA_COMPENSATION_READ_LENGTH 6
#define GAMMA_COMPENSATION_READ_REG 0x81
#define GAMMA_COMPENSATION_BAND_REG 0x99
#define GAMMA_COMPENSATION_BAND_VALUE1 0x81
#define GAMMA_COMPENSATION_BAND_VALUE2 0xB1
#define GAMMA_COMPENSATION_BAND_VALUE3 0x8D
#define GAMMA_COMPENSATION_BAND_VALUE4 0xBD

bool g_gamma_regs_read_done = false;
EXPORT_SYMBOL(g_gamma_regs_read_done);

/* log level config */
unsigned int oplus_display_log_level = OPLUS_LOG_LEVEL_INFO;
unsigned int oplus_display_trace_enable = OPLUS_DISPLAY_DISABLE_TRACE;
unsigned int oplus_display_log_type = OPLUS_DEBUG_LOG_DISABLED;

static enum oplus_display_support_list  oplus_display_vendor =
		OPLUS_DISPLAY_UNKNOW;
static enum oplus_display_power_status oplus_display_status =
		OPLUS_DISPLAY_POWER_OFF;
static BLOCKING_NOTIFIER_HEAD(oplus_display_notifier_list);

static struct dsi_display *primary_display;
static struct dsi_display *secondary_display;
/* add for dual panel */
static struct dsi_display *current_display = NULL;

bool refresh_rate_change = false;

struct dsi_display *get_main_display(void) {
		return primary_display;
}
EXPORT_SYMBOL(get_main_display);

struct dsi_display *get_sec_display(void) {
		return secondary_display;
}
EXPORT_SYMBOL(get_sec_display);

struct dsi_display *oplus_display_get_current_display(void)
{
	return current_display;
}

int oplus_display_register_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&oplus_display_notifier_list, nb);
}
EXPORT_SYMBOL(oplus_display_register_client);


int oplus_display_unregister_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&oplus_display_notifier_list,
			nb);
}
EXPORT_SYMBOL(oplus_display_unregister_client);

static int oplus_display_notifier_call_chain(unsigned long val, void *v)
{
	return blocking_notifier_call_chain(&oplus_display_notifier_list, val, v);
}

bool oplus_is_correct_display(enum oplus_display_support_list lcd_name)
{
	return (oplus_display_vendor == lcd_name ? true : false);
}

bool oplus_is_silence_reboot(void)
{
	OPLUS_DSI_INFO("get_boot_mode = %d\n", get_boot_mode());
	if ((MSM_BOOT_MODE__SILENCE == get_boot_mode())
			|| (MSM_BOOT_MODE__SAU == get_boot_mode())) {
		return true;

	} else {
		return false;
	}
	return false;
}
EXPORT_SYMBOL(oplus_is_silence_reboot);

bool oplus_is_factory_boot(void)
{
	OPLUS_DSI_INFO("get_boot_mode = %d\n", get_boot_mode());
	if ((MSM_BOOT_MODE__FACTORY == get_boot_mode())
			|| (MSM_BOOT_MODE__RF == get_boot_mode())
			|| (MSM_BOOT_MODE__WLAN == get_boot_mode())
			|| (MSM_BOOT_MODE__MOS == get_boot_mode())) {
		return true;
	} else {
		return false;
	}
	return false;
}
EXPORT_SYMBOL(oplus_is_factory_boot);

void oplus_display_notifier_early_status(enum oplus_display_power_status
					power_status)
{
	int blank;
	OPLUS_DISPLAY_NOTIFIER_EVENT oplus_notifier_data;

	switch (power_status) {
	case OPLUS_DISPLAY_POWER_ON:
		blank = OPLUS_DISPLAY_POWER_ON;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_ON;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE:
		blank = OPLUS_DISPLAY_POWER_DOZE;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE_SUSPEND:
		blank = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_OFF:
		blank = OPLUS_DISPLAY_POWER_OFF;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_OFF;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EARLY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	default:
		break;
	}
}

void oplus_display_notifier_status(enum oplus_display_power_status power_status)
{
	int blank;
	OPLUS_DISPLAY_NOTIFIER_EVENT oplus_notifier_data;

	switch (power_status) {
	case OPLUS_DISPLAY_POWER_ON:
		blank = OPLUS_DISPLAY_POWER_ON;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_ON;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE:
		blank = OPLUS_DISPLAY_POWER_DOZE;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_DOZE_SUSPEND:
		blank = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_DOZE_SUSPEND;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	case OPLUS_DISPLAY_POWER_OFF:
		blank = OPLUS_DISPLAY_POWER_OFF;
		oplus_notifier_data.data = &blank;
		oplus_notifier_data.status = OPLUS_DISPLAY_POWER_OFF;
		oplus_display_notifier_call_chain(OPLUS_DISPLAY_EVENT_BLANK,
				&oplus_notifier_data);
		break;
	default:
		break;
	}
}

void __oplus_set_power_status(enum oplus_display_power_status power_status)
{
	oplus_display_status = power_status;
}
EXPORT_SYMBOL(__oplus_set_power_status);

enum oplus_display_power_status __oplus_get_power_status(void)
{
	return oplus_display_status;
}
EXPORT_SYMBOL(__oplus_get_power_status);

int oplus_panel_event_data_notifier_trigger(struct dsi_panel *panel,
		enum panel_event_notification_type notif_type,
		u32 data,
		bool early_trigger)
{
	struct panel_event_notification notifier;
	enum panel_event_notifier_tag panel_type;
	char tag_name[256];

	if (!panel) {
		OPLUS_DSI_ERR("Oplus Features config No panel device\n");
		return -ENODEV;
	}

	if (!strcmp(panel->type, "secondary")) {
		panel_type = PANEL_EVENT_NOTIFICATION_SECONDARY;
	} else {
		panel_type = PANEL_EVENT_NOTIFICATION_PRIMARY;
	}

	snprintf(tag_name, sizeof(tag_name),
		"oplus_panel_event_data_notifier_trigger : [%s] type=0x%X, data=%d, early_trigger=%d",
		panel->type, notif_type, data, early_trigger);
	OPLUS_DSI_TRACE_BEGIN(tag_name);

	OPLUS_DSI_DEBUG("[%s] type=0x%X, data=%d, early_trigger=%d\n",
			panel->type, notif_type, data, early_trigger);

	memset(&notifier, 0, sizeof(notifier));

	notifier.panel = &panel->drm_panel;
	notifier.notif_type = notif_type;
	notifier.notif_data.data = data;
	notifier.notif_data.early_trigger = early_trigger;

	panel_event_notification_trigger(panel_type, &notifier);

	OPLUS_DSI_TRACE_END(tag_name);
	return 0;
}
EXPORT_SYMBOL(oplus_panel_event_data_notifier_trigger);

int oplus_event_data_notifier_trigger(
		enum panel_event_notification_type notif_type,
		u32 data,
		bool early_trigger)
{
	struct dsi_display *display = oplus_display_get_current_display();

	if (!display || !display->panel) {
		OPLUS_DSI_ERR("Oplus Features config No display device\n");
		return -ENODEV;
	}

	oplus_panel_event_data_notifier_trigger(display->panel,
			notif_type, data, early_trigger);

	return 0;
}
EXPORT_SYMBOL(oplus_event_data_notifier_trigger);

int oplus_panel_backlight_notifier(struct dsi_panel *panel, u32 bl_lvl)
{
	u32 threshold = panel->oplus_panel.bl_cfg.dc_backlight_threshold;
	bool dc_mode = panel->oplus_panel.bl_cfg.oplus_dc_mode;

	if (dc_mode && (bl_lvl > 1 && bl_lvl < threshold)) {
		dc_mode = false;
		oplus_panel_event_data_notifier_trigger(panel,
				DRM_PANEL_EVENT_DC_MODE, dc_mode, true);
	} else if (!dc_mode && bl_lvl >= threshold) {
		dc_mode = true;
		oplus_panel_event_data_notifier_trigger(panel,
				DRM_PANEL_EVENT_DC_MODE, dc_mode, true);
	}

	oplus_panel_event_data_notifier_trigger(panel,
			DRM_PANEL_EVENT_BACKLIGHT, bl_lvl, true);

	return 0;
}
EXPORT_SYMBOL(oplus_panel_backlight_notifier);

/* add for dual panel */
void oplus_display_set_current_display(void *dsi_display)
{
	struct dsi_display *display = dsi_display;
	current_display = display;
}

/* update current display when panel is enabled and disabled */
void oplus_display_update_current_display(void)
{
	struct dsi_display *primary_display = get_main_display();
	struct dsi_display *secondary_display = get_sec_display();

	OPLUS_DSI_DEBUG("start\n");

	if ((!primary_display && !secondary_display) || (!primary_display->panel && !secondary_display->panel)) {
		current_display = NULL;
	} else if ((primary_display && !secondary_display) || (primary_display->panel && !secondary_display->panel)) {
		current_display = primary_display;
	} else if ((!primary_display && secondary_display) || (!primary_display->panel && secondary_display->panel)) {
		current_display = secondary_display;
	} else if (primary_display->panel->panel_initialized && !secondary_display->panel->panel_initialized) {
		current_display = primary_display;
	} else if (!primary_display->panel->panel_initialized && secondary_display->panel->panel_initialized) {
		current_display = secondary_display;
	} else if (primary_display->panel->panel_initialized && secondary_display->panel->panel_initialized) {
		current_display = primary_display;
	}

#ifdef OPLUS_FEATURE_DISPLAY_ADFR
	oplus_adfr_update_display_id();
#endif /* OPLUS_FEATURE_DISPLAY_ADFR */

#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
	if (oplus_ofp_is_supported()) {
		oplus_ofp_update_display_id();
	}
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */

	OPLUS_DSI_DEBUG("end\n");

	return;
}

void oplus_check_refresh_rate(const int old_rate, const int new_rate)
{
	if (old_rate != new_rate)
		refresh_rate_change = true;
	else
		refresh_rate_change = false;
}

int oplus_display_set_power(struct drm_connector *connector,
		int power_mode, void *disp)
{
	struct dsi_display *display = disp;
	int rc = 0;

	if (!display || !display->panel) {
		OPLUS_DSI_ERR("display is null\n");
		return -EINVAL;
	}

	if (power_mode == SDE_MODE_DPMS_OFF)
		atomic_set(&display->panel->oplus_panel.esd_pending, 1);

	switch (power_mode) {
	case SDE_MODE_DPMS_LP1:
	case SDE_MODE_DPMS_LP2:
		OPLUS_DSI_INFO("SDE_MODE_DPMS_LP%d\n", power_mode == SDE_MODE_DPMS_LP1 ? 1 : 2);

#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
		if (oplus_ofp_is_supported()) {
			oplus_ofp_power_mode_handle(display, power_mode);
		}
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */
		__oplus_set_power_status(OPLUS_DISPLAY_POWER_DOZE_SUSPEND);
		break;

	case SDE_MODE_DPMS_ON:
		OPLUS_DSI_INFO("SDE_MODE_DPMS_ON\n");
#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
		if (oplus_ofp_is_supported()) {
			oplus_ofp_power_mode_handle(display, SDE_MODE_DPMS_ON);
		}
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */
		__oplus_set_power_status(OPLUS_DISPLAY_POWER_ON);
		break;

	case SDE_MODE_DPMS_OFF:
		OPLUS_DSI_INFO("SDE_MODE_DPMS_OFF\n");
#ifdef OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT
		if (oplus_ofp_is_supported()) {
			oplus_ofp_power_mode_handle(display, SDE_MODE_DPMS_OFF);
		}
#endif /* OPLUS_FEATURE_DISPLAY_ONSCREENFINGERPRINT */
		break;

	default:
		return rc;
	}

	OPLUS_DSI_DEBUG("Power mode transition from %d to %d %s\n",
			display->panel->power_mode, power_mode,
			rc ? "failed" : "successful");

	if (!rc) {
		display->panel->power_mode = power_mode;
	}

	return rc;
}
EXPORT_SYMBOL(oplus_display_set_power);

void oplus_display_set_display(void *display)
{
	struct dsi_display *dsi_display = display;

	if (!strcmp(dsi_display->display_type, "primary")) {
		primary_display = dsi_display;
		oplus_display_set_current_display(primary_display);
	} else {
		secondary_display = dsi_display;
	}

	return;
}

static int oplus_panel_gamma_compensation_read_reg(struct dsi_panel *panel, struct dsi_display_ctrl *m_ctrl, char *regs, u8 value)
{
	int rc = 0;
	u32 cnt = 0;
	int index = 0;
	u8 cmd = GAMMA_COMPENSATION_BAND_REG;
	size_t replace_reg_len = 1;
	char replace_reg[REG_SIZE] = {0};
	char print_buf[OPLUS_DSI_CMD_PRINT_BUF_SIZE] = {0};

	memset(replace_reg, 0, sizeof(replace_reg));
	replace_reg[0] = value;
	rc = oplus_panel_cmd_reg_replace(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE1, cmd, replace_reg, replace_reg_len);
	if (rc) {
		OPLUS_DSI_ERR("oplus panel cmd reg replace failed, retry\n");
		return rc;
	}
	rc = dsi_panel_tx_cmd_set(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE1, false);
	if (rc) {
		OPLUS_DSI_ERR("send DSI_CMD_GAMMA_COMPENSATION_PAGE1 failed, retry\n");
		return rc;
	}

	rc = dsi_panel_read_panel_reg_unlock(m_ctrl, panel, GAMMA_COMPENSATION_READ_REG,
			regs, GAMMA_COMPENSATION_READ_LENGTH);
	if (rc < 0) {
		OPLUS_DSI_ERR("failed to read GAMMA_COMPENSATION_READ_REG rc=%d\n", rc);
		return rc;
	}
	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs[index]);
	}
	OPLUS_DSI_INFO("read regs0x%02X len=%d, buf=[%s]\n", value, GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	return 0;
}

int oplus_display_panel_gamma_compensation(struct dsi_display *display)
{
	u32 retry_count = 0;
	u32 index = 0;
	int rc = 0;
	u32 cnt = 0;
	u32 reg_tmp = 0;
	struct dsi_display_mode *mode = NULL;
	char print_buf[OPLUS_DSI_CMD_PRINT_BUF_SIZE] = {0};
	struct dsi_display_ctrl *m_ctrl = NULL;
	struct dsi_panel *panel = display->panel;
	char regs1[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs2[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs3[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs4[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs1_last[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs2_last[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs3_last[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	char regs4_last[GAMMA_COMPENSATION_READ_LENGTH] = {0};
	const char reg_base[GAMMA_COMPENSATION_READ_LENGTH] = {0};

	if (!panel) {
		OPLUS_DSI_ERR("panel is null\n");
		return  -EINVAL;
	}

	m_ctrl = &display->ctrl[display->cmd_master_idx];

	if (!m_ctrl) {
		OPLUS_DSI_ERR("ctrl is null\n");
		return -EINVAL;
	}

	if (!panel->oplus_panel.gamma_compensation_support) {
		OPLUS_DSI_INFO("panel gamma compensation isn't supported\n");
		return rc;
	}

	if (display->panel->power_mode != SDE_MODE_DPMS_ON) {
		OPLUS_DSI_ERR("display panel in off status\n");
		return -EINVAL;
	}
	if (!display->panel->panel_initialized) {
		OPLUS_DSI_ERR("panel initialized = false\n");
		return -EINVAL;
	}

	mutex_lock(&display->display_lock);
	mutex_lock(&display->panel->panel_lock);
	while(!g_gamma_regs_read_done && retry_count < GAMMA_COMPENSATION_READ_RETRY_MAX) {
		OPLUS_DSI_INFO("read gamma compensation regs, retry_count=%d\n", retry_count);
		memset(regs1, 0, GAMMA_COMPENSATION_READ_LENGTH);
		memset(regs2, 0, GAMMA_COMPENSATION_READ_LENGTH);
		memset(regs3, 0, GAMMA_COMPENSATION_READ_LENGTH);
		memset(regs4, 0, GAMMA_COMPENSATION_READ_LENGTH);

		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs1, GAMMA_COMPENSATION_BAND_VALUE1);
		if (rc) {
			OPLUS_DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}
		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs2, GAMMA_COMPENSATION_BAND_VALUE2);
		if (rc) {
			OPLUS_DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}
		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs3, GAMMA_COMPENSATION_BAND_VALUE3);
		if (rc) {
			OPLUS_DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}
		rc = oplus_panel_gamma_compensation_read_reg(panel, m_ctrl, regs4, GAMMA_COMPENSATION_BAND_VALUE4);
		if (rc) {
			OPLUS_DSI_ERR("panel read reg1 failed\n");
			retry_count++;
			continue;
		}

		if (!memcmp(regs1, reg_base, sizeof(reg_base)) || !memcmp(regs2, reg_base, sizeof(reg_base)) ||
				!memcmp(regs3, reg_base, sizeof(reg_base)) || !memcmp(regs4, reg_base, sizeof(reg_base)) ||
				memcmp(regs1, regs1_last, sizeof(regs1_last)) || memcmp(regs2, regs2_last, sizeof(regs2_last)) ||
				memcmp(regs3, regs3_last, sizeof(regs1_last)) || memcmp(regs4, regs4_last, sizeof(regs2_last))) {
			OPLUS_DSI_WARN("gamma compensation regs is invalid, retry\n");
			memcpy(regs1_last, regs1, GAMMA_COMPENSATION_READ_LENGTH);
			memcpy(regs2_last, regs2, GAMMA_COMPENSATION_READ_LENGTH);
			memcpy(regs3_last, regs3, GAMMA_COMPENSATION_READ_LENGTH);
			memcpy(regs4_last, regs4, GAMMA_COMPENSATION_READ_LENGTH);
			retry_count++;
			continue;
		}

		rc = dsi_panel_tx_cmd_set(panel, DSI_CMD_GAMMA_COMPENSATION_PAGE0, false);
		if (rc) {
			OPLUS_DSI_ERR("send DSI_CMD_GAMMA_COMPENSATION_PAGE0 failed\n");
		}

		g_gamma_regs_read_done = true;
		OPLUS_DSI_INFO("gamma compensation read success");
		break;
	}
	mutex_unlock(&display->panel->panel_lock);
	mutex_unlock(&display->display_lock);

	if (!g_gamma_regs_read_done) {
		return -EFAULT;
	}

	for (index = 0; index < (GAMMA_COMPENSATION_READ_LENGTH - 1); index = index+2) {
		reg_tmp = regs1[index] << 8 | regs1[index+1];
		regs1[index] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE1) >> 8 & 0xFF;
		regs1[index+1] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE1) & 0xFF;

		reg_tmp = regs2[index] << 8 | regs2[index+1];
		regs2[index] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE1) >> 8 & 0xFF;
		regs2[index+1] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE1) & 0xFF;

		reg_tmp = regs3[index] << 8 | regs3[index+1];
		regs3[index] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE2) >> 8 & 0xFF;
		regs3[index+1] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE2) & 0xFF;

		reg_tmp = regs4[index] << 8 | regs4[index+1];
		regs4[index] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE2) >> 8 & 0xFF;
		regs4[index+1] = (reg_tmp*GAMMA_COMPENSATION_PERCENTAGE2) & 0xFF;
	}

	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs1[index]);
	}
	OPLUS_DSI_INFO("compensation regs0x%02X len=%d, buf=[%s]\n", GAMMA_COMPENSATION_BAND_VALUE1,
			GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs2[index]);
	}
	OPLUS_DSI_INFO("compensation regs0x%02X len=%d, buf=[%s]\n", GAMMA_COMPENSATION_BAND_VALUE2,
			GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs3[index]);
	}
	OPLUS_DSI_INFO("compensation regs0x%02X len=%d, buf=[%s]\n", GAMMA_COMPENSATION_BAND_VALUE3,
			GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	cnt = 0;
	memset(print_buf, 0, OPLUS_DSI_CMD_PRINT_BUF_SIZE);
	for (index = 0; index < GAMMA_COMPENSATION_READ_LENGTH; index++) {
		cnt += snprintf(print_buf + cnt, OPLUS_DSI_CMD_PRINT_BUF_SIZE - cnt, "%02X ", regs4[index]);
	}
	OPLUS_DSI_INFO("compensation regs0x%02X len=%d, buf=[%s]\n", GAMMA_COMPENSATION_BAND_VALUE4,
			GAMMA_COMPENSATION_READ_LENGTH, print_buf);

	mutex_lock(&display->display_lock);
	mutex_lock(&display->panel->panel_lock);
	for (index = 0; index < display->panel->num_display_modes; index++) {
		mode = &display->modes[index];
		if (!mode) {
			OPLUS_DSI_INFO("mode is null\n");
			continue;
		}
		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs1,
			GAMMA_COMPENSATION_READ_LENGTH, 5/* rows of cmd */);
		if (rc) {
			OPLUS_DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg1 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}
		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs2,
				GAMMA_COMPENSATION_READ_LENGTH, 7/* rows of cmd */);
		if (rc) {
			OPLUS_DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg2 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}
		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs3,
				GAMMA_COMPENSATION_READ_LENGTH, 9/* rows of cmd */);
		if (rc) {
			OPLUS_DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg3 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}
		rc = oplus_panel_cmd_reg_replace_specific_row(panel, mode, DSI_CMD_GAMMA_COMPENSATION, regs4,
				GAMMA_COMPENSATION_READ_LENGTH, 11/* rows of cmd */);
		if (rc) {
			OPLUS_DSI_ERR("DSI_CMD_GAMMA_COMPENSATION reg4 replace failed\n");
			g_gamma_regs_read_done = false;
			return -EFAULT;
		}
		OPLUS_DSI_INFO("display mode%d had completed gamma compensation\n", index);
	}
	mutex_unlock(&display->panel->panel_lock);
	mutex_unlock(&display->display_lock);

	return rc;
}

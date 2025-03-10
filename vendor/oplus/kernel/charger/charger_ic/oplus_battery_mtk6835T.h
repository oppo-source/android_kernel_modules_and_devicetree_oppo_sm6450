// SPDX-License-Identifier: GPL-2.0-only
/*
* Copyright (C) 2018-2020 Oplus. All rights reserved.
*/

#ifndef __MTK_CHARGER_H
#define __MTK_CHARGER_H

#include <linux/alarmtimer.h>
#include <linux/reboot.h>
#include "../../../../kernel-5.15/drivers/power/supply/charger_class.h"
#include "../../../../kernel-5.15/drivers/power/supply/adapter_class.h"
#include "../../../../kernel-5.15/drivers/power/supply/mtk_charger_algorithm_class.h"
#include <linux/power_supply.h>
#include "../../../../kernel-5.15/drivers/power/supply/mtk_smartcharging.h"

#ifdef CONFIG_OPLUS_MTK_DRM_GKI_NOTIFY_CHG
#include "../../../../kernel-5.15/drivers/gpu/drm/mediatek/mediatek_v2/mtk_panel_ext.h"
#include "../../../../kernel-5.15/drivers/gpu/drm/mediatek/mediatek_v2/mtk_disp_notify.h"
#endif

#include "../../../base/kernelFwUpdate/kernelFwUpdate.h"

#include "../oplus_chg_core.h"
#include "../op_wlchg_v2/hal/oplus_chg_ic.h"
#ifdef CONFIG_OPLUS_CHARGER_MTK
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
#ifdef CONFIG_OPLUS_PD_EXT_SUPPORT
#include "../../../../kernel-5.15/drivers/power/oplus/pd_ext/inc/tcpm.h"
#else
#include "../../../../kernel-5.15/drivers/misc/mediatek/typec/tcpc/inc/tcpm.h"
#endif
#endif
#endif
#define RT9471D 0
#define RT9467 1
#define BQ2589X 2
#define BQ2591X 3
#define SY6970 4
#define SGM4151X 5
#define BQ2560X 6
#define SGM41542 7
#define SGM41512 8
#define SC6607 9
#define CHARGING_INTERVAL 10
#define CHARGING_FULL_INTERVAL 20

#define CHRLOG_ERROR_LEVEL	1
#define CHRLOG_INFO_LEVEL	2
#define CHRLOG_DEBUG_LEVEL	3

#define PORT_ERROR 0
#define PORT_A 1
#define PORT_PD_WITH_USB 2
#define PORT_PD_WITHOUT_USB 3

#define SC_TAG "smartcharging"

extern int chr_get_debug_level(void);

#define chr_err(fmt, args...)					\
do {								\
	if (chr_get_debug_level() >= CHRLOG_ERROR_LEVEL) {	\
		pr_notice(fmt, ##args);				\
	}							\
} while (0)

#define chr_info(fmt, args...)					\
do {								\
	if (chr_get_debug_level() >= CHRLOG_INFO_LEVEL) {	\
		pr_notice_ratelimited(fmt, ##args);		\
	}							\
} while (0)

#define chr_debug(fmt, args...)					\
do {								\
	if (chr_get_debug_level() >= CHRLOG_DEBUG_LEVEL) {	\
		pr_notice(fmt, ##args);				\
	}							\
} while (0)

struct mtk_charger;
struct charger_data;
#define BATTERY_CV 4350000
#define V_CHARGER_MAX 6500000 /* 6.5 V */
#define V_CHARGER_MIN 4600000 /* 4.6 V */

#define USB_CHARGER_CURRENT_SUSPEND		0 /* def CONFIG_USB_IF */
#define USB_CHARGER_CURRENT_UNCONFIGURED	70000 /* 70mA */
#define USB_CHARGER_CURRENT_CONFIGURED		500000 /* 500mA */
#define USB_CHARGER_CURRENT			500000 /* 500mA */
#define AC_CHARGER_CURRENT			2050000
#define AC_CHARGER_INPUT_CURRENT		3200000
#define NON_STD_AC_CHARGER_CURRENT		500000
#define CHARGING_HOST_CHARGER_CURRENT		650000

/* dynamic mivr */
#define V_CHARGER_MIN_1 4400000 /* 4.4 V */
#define V_CHARGER_MIN_2 4200000 /* 4.2 V */
#define MAX_DMIVR_CHARGER_CURRENT 1800000 /* 1.8 A */

/* battery warning */
#ifndef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
#define BATTERY_NOTIFY_CASE_0001_VCHARGER
#define BATTERY_NOTIFY_CASE_0002_VBATTEMP
#endif

/* charging abnormal status */
#define CHG_VBUS_OV_STATUS	(1 << 0)
#define CHG_BAT_OT_STATUS	(1 << 1)
#define CHG_OC_STATUS		(1 << 2)
#define CHG_BAT_OV_STATUS	(1 << 3)
#define CHG_ST_TMO_STATUS	(1 << 4)
#define CHG_BAT_LT_STATUS	(1 << 5)
#define CHG_TYPEC_WD_STATUS	(1 << 6)

/* Battery Temperature Protection */
#define MIN_CHARGE_TEMP  0
#define MIN_CHARGE_TEMP_PLUS_X_DEGREE	6
#define MAX_CHARGE_TEMP  50
#define MAX_CHARGE_TEMP_MINUS_X_DEGREE	47

#define MAX_ALG_NO 10

#ifdef OPLUS_FEATURE_CHG_BASIC
/* Add for ntc temp */
typedef enum {
	NTC_BATTERY,
	NTC_CHARGER_IC,
	NTC_SUB_BOARD,
	NTC_BATTERY_BTB,
	NTC_USB_BTB,
}NTC_TYPE;

struct temp_param {
	__s32 bts_temp;
	__s32 temperature_r;
};

struct ntc_temp{
	NTC_TYPE e_ntc_type;
	int i_tap_over_critical_low;
	int i_rap_pull_up_r;
	int i_rap_pull_up_voltage;
	int i_tap_min;
	int i_tap_max;
	unsigned int i_25c_volt;
	unsigned int ui_dwvolt;
	struct temp_param *pst_temp_table;
	int i_table_size;
};
#endif

struct charger_consumer {
	struct device *dev;
	void *cm;
	struct notifier_block *pnb;
	struct list_head list;
	bool hv_charging_disabled;
	/* add for tscharger 0.1C precision support*/
	bool support_ntc_01c_precision;
	/*end*/
};
enum charger_type {
	CHARGER_UNKNOWN = 0,
	STANDARD_HOST,		/* USB : 450mA */
	CHARGING_HOST,
	NONSTANDARD_CHARGER,	/* AC : 450mA~1A */
	STANDARD_CHARGER,	/* AC : ~1A */
	APPLE_2_1A_CHARGER, /* 2.1A apple charger */
	APPLE_1_0A_CHARGER, /* 1A apple charger */
	APPLE_0_5A_CHARGER, /* 0.5A apple charger */
	WIRELESS_CHARGER,
};
enum bat_temp_state_enum {
	BAT_TEMP_LOW = 0,
	BAT_TEMP_NORMAL,
	BAT_TEMP_HIGH
};

enum chg_dev_notifier_events {
	EVENT_FULL,
	EVENT_RECHARGE,
	EVENT_DISCHARGE,
};

struct battery_thermal_protection_data {
	int sm;
	bool enable_min_charge_temp;
	int min_charge_temp;
	int min_charge_temp_plus_x_degree;
	int max_charge_temp;
	int max_charge_temp_minus_x_degree;
};

/* sw jeita */
#define JEITA_TEMP_ABOVE_T4_CV	4240000
#define JEITA_TEMP_T3_TO_T4_CV	4240000
#define JEITA_TEMP_T2_TO_T3_CV	4340000
#define JEITA_TEMP_T1_TO_T2_CV	4240000
#define JEITA_TEMP_T0_TO_T1_CV	4040000
#define JEITA_TEMP_BELOW_T0_CV	4040000
#define TEMP_T4_THRES  50
#define TEMP_T4_THRES_MINUS_X_DEGREE 47
#define TEMP_T3_THRES  45
#define TEMP_T3_THRES_MINUS_X_DEGREE 39
#define TEMP_T2_THRES  10
#define TEMP_T2_THRES_PLUS_X_DEGREE 16
#define TEMP_T1_THRES  0
#define TEMP_T1_THRES_PLUS_X_DEGREE 6
#define TEMP_T0_THRES  0
#define TEMP_T0_THRES_PLUS_X_DEGREE  0
#define TEMP_NEG_10_THRES 0

/*
 * Software JEITA
 * T0: -10 degree Celsius
 * T1: 0 degree Celsius
 * T2: 10 degree Celsius
 * T3: 45 degree Celsius
 * T4: 50 degree Celsius
 */
enum sw_jeita_state_enum {
	TEMP_BELOW_T0 = 0,
	TEMP_T0_TO_T1,
	TEMP_T1_TO_T2,
	TEMP_T2_TO_T3,
	TEMP_T3_TO_T4,
	TEMP_ABOVE_T4
};

struct sw_jeita_data {
	int sm;
	int pre_sm;
	int cv;
	bool charging;
	bool error_recovery_flag;
};

struct mtk_charger_algorithm {
	int (*do_algorithm)(struct mtk_charger *info);
	int (*enable_charging)(struct mtk_charger *info, bool en);
	int (*do_event)(struct notifier_block *nb, unsigned long ev, void *v);
	int (*do_dvchg1_event)(struct notifier_block *nb, unsigned long ev,
			       void *v);
	int (*do_dvchg2_event)(struct notifier_block *nb, unsigned long ev,
			       void *v);
	int (*change_current_setting)(struct mtk_charger *info);
	void *algo_data;
};

struct charger_custom_data {
	int battery_cv;	/* uv */
	int max_charger_voltage;
	int max_charger_voltage_setting;
	int min_charger_voltage;

	int usb_charger_current;
	int ac_charger_current;
	int ac_charger_input_current;
	int charging_host_charger_current;

	/* sw jeita */
	int jeita_temp_above_t4_cv;
	int jeita_temp_t3_to_t4_cv;
	int jeita_temp_t2_to_t3_cv;
	int jeita_temp_t1_to_t2_cv;
	int jeita_temp_t0_to_t1_cv;
	int jeita_temp_below_t0_cv;
	int temp_t4_thres;
	int temp_t4_thres_minus_x_degree;
	int temp_t3_thres;
	int temp_t3_thres_minus_x_degree;
	int temp_t2_thres;
	int temp_t2_thres_plus_x_degree;
	int temp_t1_thres;
	int temp_t1_thres_plus_x_degree;
	int temp_t0_thres;
	int temp_t0_thres_plus_x_degree;
	int temp_neg_10_thres;

	/* battery temperature protection */
	int mtk_temperature_recharge_support;
	int max_charge_temp;
	int max_charge_temp_minus_x_degree;
	int min_charge_temp;
	int min_charge_temp_plus_x_degree;

	/* dynamic mivr */
	int min_charger_voltage_1;
	int min_charger_voltage_2;
	int max_dmivr_charger_current;

	/* pd 5V 3A*/
	int pd_support_5v3a;
};

struct charger_data {
	int input_current_limit;
	int charging_current_limit;

	int force_charging_current;
	int thermal_input_current_limit;
	int thermal_charging_current_limit;
	int disable_charging_count;
	int input_current_limit_by_aicl;
	int junction_temp_min;
	int junction_temp_max;
};

enum chg_data_idx_enum {
	CHG1_SETTING,
	CHG2_SETTING,
	DVCHG1_SETTING,
	DVCHG2_SETTING,
	CHGS_SETTING_MAX,
};

#ifdef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
struct oplus_custom_gpio_pinctrl {
	int vchg_trig_gpio;
	int ccdetect_gpio;
	struct mutex 		pinctrl_mutex;
	struct pinctrl		*vchg_trig_pinctrl;
	struct pinctrl_state	*vchg_trig_default;
	struct pinctrl		*ccdetect_pinctrl;
	struct pinctrl_state	*ccdetect_active;
	struct pinctrl_state	*ccdetect_sleep;
	struct pinctrl		*usbtemp_l_gpio_pinctrl;
	struct pinctrl_state	*usbtemp_l_gpio_default;
	struct pinctrl		*usbtemp_r_gpio_pinctrl;
	struct pinctrl_state	*usbtemp_r_gpio_default;
};
#endif

struct mtk_charger {
#ifdef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
	struct oplus_chg_ic_dev *ic_dev;
	struct oplus_chg_mod *usb_ocm;
	struct notifier_block usb_event_nb;
	bool wls_boost_soft_start;
	int wls_set_boost_vol;
#endif

	struct platform_device *pdev;
	struct charger_device *chg1_dev;
	struct notifier_block chg1_nb;
	struct charger_device *chg2_dev;
	struct charger_device *dvchg1_dev;
	struct notifier_block dvchg1_nb;
	struct charger_device *dvchg2_dev;
	struct notifier_block dvchg2_nb;

	struct charger_data chg_data[CHGS_SETTING_MAX];
	struct chg_limit_setting setting;
	enum charger_configuration config;

	struct power_supply_desc psy_desc1;
	struct power_supply_config psy_cfg1;
	struct power_supply *psy1;

	struct power_supply_desc psy_desc2;
	struct power_supply_config psy_cfg2;
	struct power_supply *psy2;

	struct power_supply_desc psy_dvchg_desc1;
	struct power_supply_config psy_dvchg_cfg1;
	struct power_supply *psy_dvchg1;

	struct power_supply_desc psy_dvchg_desc2;
	struct power_supply_config psy_dvchg_cfg2;
	struct power_supply *psy_dvchg2;

	struct power_supply  *chg_psy;
	struct power_supply  *bat_psy;
	struct adapter_device *pd_adapter;
	struct notifier_block pd_nb;
	struct mutex pd_lock;
	int pd_type;
	bool pd_reset;

	u32 bootmode;
	u32 boottype;

	int chr_type;
	int usb_type;
	int usb_state;

	struct mutex cable_out_lock;
	int cable_out_cnt;

	/* system lock */
	spinlock_t slock;
	struct wakeup_source *charger_wakelock;
	struct mutex charger_lock;

	/* thread related */
	wait_queue_head_t  wait_que;
	bool charger_thread_timeout;
	unsigned int polling_interval;
	bool charger_thread_polling;

	/* alarm timer */
	struct alarm charger_timer;
	struct timespec64 endtime;
	bool is_suspend;
	struct notifier_block pm_notifier;
	ktime_t timer_cb_duration[8];

	/* notify charger user */
	struct srcu_notifier_head evt_nh;

	/* common info */
	int log_level;
	bool usb_unlimited;
	bool disable_charger;
	int battery_temp;
	bool can_charging;
	bool cmd_discharging;
	bool safety_timeout;
	int safety_timer_cmd;
	bool vbusov_stat;
	bool is_chg_done;
	/* ATM */
	bool atm_enabled;

	const char *algorithm_name;
	struct mtk_charger_algorithm algo;

	/* dtsi custom data */
	struct charger_custom_data data;

	/* battery warning */
	unsigned int notify_code;
	unsigned int notify_test_mode;

	/* sw safety timer */
	bool enable_sw_safety_timer;
	bool sw_safety_timer_setting;
	struct timespec64 charging_begin_time;

	/* vbat monitor, 6pin bat */
	bool batpro_done;
	bool enable_vbat_mon;
	int old_cv;
	bool stop_6pin_re_en;

	/* sw jeita */
	bool enable_sw_jeita;
	struct sw_jeita_data sw_jeita;

	/* battery thermal protection */
	struct battery_thermal_protection_data thermal;

	struct chg_alg_device *alg[MAX_ALG_NO];
	struct notifier_block chg_alg_nb;
	bool enable_hv_charging;

	/* water detection */
	bool water_detected;

	bool enable_dynamic_mivr;

	/* fast charging algo support indicator */
	bool enable_fast_charging_indicator;
	unsigned int fast_charging_indicator;

	/* diasable meta current limit for testing */
	unsigned int enable_meta_current_limit;

	struct smartcharging sc;

	/*daemon related*/
	struct sock *daemo_nl_sk;
	u_int g_scd_pid;
	struct scd_cmd_param_t_1 sc_data;

	/*charger IC charging status*/
	bool is_charging;

#ifdef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
	struct iio_channel      *chargeric_temp_chan;
	struct iio_channel      *charger_id_chan;
	struct iio_channel      *usb_temp_v_l_chan;
	struct iio_channel      *usb_temp_v_r_chan;
	struct iio_channel      *subboard_temp_chan;
	struct iio_channel      *batt_btb_temp_chan;
	struct iio_channel      *usb_btb_temp_chan;

	int ccdetect_gpio;
	int ccdetect_irq;
	struct pinctrl_state *ccdetect_active;
	struct pinctrl_state *ccdetect_sleep;
	struct pinctrl *pinctrl;
	struct oplus_custom_gpio_pinctrl oplus_custom_gpio;

	int wrx_en_gpio;
	int wrx_otg_en_gpio;
	int boost_en_gpio;
	int ext1_otg_en_gpio;
	int ext2_otg_en_gpio;
	struct pinctrl          *wrx_en_pinctrl;
	struct pinctrl_state    *wrx_en_active;
	struct pinctrl_state    *wrx_en_sleep;
	struct pinctrl          *wrx_otg_en_pinctrl;
	struct pinctrl_state    *wrx_otg_en_active;
	struct pinctrl_state    *wrx_otg_en_sleep;
	struct pinctrl          *boost_en_pinctrl;
	struct pinctrl_state    *boost_en_active;
	struct pinctrl_state    *boost_en_sleep;
	struct pinctrl          *ext1_otg_en_pinctrl;
	struct pinctrl_state    *ext1_otg_en_active;
	struct pinctrl_state    *ext1_otg_en_sleep;
	struct pinctrl          *ext2_otg_en_pinctrl;
	struct pinctrl_state    *ext2_otg_en_active;
	struct pinctrl_state    *ext2_otg_en_sleep;

	int chargeric_temp_volt;
	int chargeric_temp;
	bool support_ntc_01c_precision;

	struct tcpc_device *tcpc;
	struct adapter_power_cap srccap;

	bool chrdet_state;
	bool wd0_detect;
	bool wait_hard_reset_complete;
	struct delayed_work status_keep_clean_work;
	struct wakeup_source *status_wake_lock;
	bool status_wake_lock_on;
/*.add for doki disable hvdcp func .*/
	bool hvdcp_disabled;
#endif
};

#ifdef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
struct mtk_pmic {
        struct mtk_charger* oplus_info;
};
#endif
static inline int mtk_chg_alg_notify_call(struct mtk_charger *info,
					  enum chg_alg_notifier_events evt,
					  int value)
{
	int i;
	struct chg_alg_notify notify = {
		.evt = evt,
		.value = value,
	};

	for (i = 0; i < MAX_ALG_NO; i++) {
		if (info->alg[i])
			chg_alg_notifier_call(info->alg[i], &notify);
	}
	return 0;
}

/* functions which framework needs*/
extern int mtk_basic_charger_init(struct mtk_charger *info);
extern int mtk_pulse_charger_init(struct mtk_charger *info);
extern int disable_hw_ovp(struct mtk_charger *info, int en);
extern void _wake_up_charger(struct mtk_charger *info);

/* functions for other */
extern int mtk_chg_enable_vbus_ovp(bool enable);


#ifdef OPLUS_FEATURE_CHG_BASIC
/*add for charge*/
extern int battery_meter_get_charger_voltage(void);
extern bool is_meta_mode(void);
int oplus_get_fast_chg_type(void);
extern int oplus_pdc_setup(int *vbus_mv, int *ibus_ma);
#endif
#endif /* __MTK_CHARGER_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include "hmbird_sched.h"
extern atomic_t ext_module_loaded;
static int __init sched_ext_init(void)
{
	scx_shadow_tick_init();
	hmbird_sysctrl_init();
	hmbird_misc_init();
	atomic_set(&ext_module_loaded, 1);

	pr_err("load sched_ext_init module \n");
	return 0;
}


static void __exit sched_ext_exit(void)
{
}

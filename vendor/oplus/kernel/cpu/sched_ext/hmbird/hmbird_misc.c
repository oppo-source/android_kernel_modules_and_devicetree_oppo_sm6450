// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include "hmbird_sched.h"

static void android_vh_hmbird_update_load_handler(
					void *unused, struct task_struct *p,
					struct rq *rq, int event, u64 wallclock)
{
	scx_update_task_ravg(p, rq, event, wallclock);
}

static void android_vh_hmbird_init_task_handler(
					void *unused, struct task_struct *p)
{
	scx_sched_init_task(p);
}

extern void walt_disable_wait_for_completion(void);
extern void walt_enable_wait_for_completion(void);
static void android_vh_hmbird_update_load_enable_handler(
					void *unused, bool enable)
{
	slim_walt_enable(enable);
	preempt_enable();
	if (enable)
		walt_disable_wait_for_completion();
	else
		walt_enable_wait_for_completion();
	preempt_disable();
}

static void android_vh_get_cpu_util_handler(
			void *unused, int cpu, u64 *util)
{
	*util = scx_cpu_util(cpu);
}

static void register_hooks(void)
{
	int ret;

	REGISTER_TRACE_VH(android_vh_hmbird_update_load,
				android_vh_hmbird_update_load_handler);
	REGISTER_TRACE_VH(android_vh_hmbird_init_task,
				android_vh_hmbird_init_task_handler);
	REGISTER_TRACE_VH(android_vh_hmbird_update_load_enable,
				android_vh_hmbird_update_load_enable_handler);
	REGISTER_TRACE_VH(android_vh_get_cpu_util,
				android_vh_get_cpu_util_handler);
}

void hmbird_misc_init(void)
{
	register_hooks();
}

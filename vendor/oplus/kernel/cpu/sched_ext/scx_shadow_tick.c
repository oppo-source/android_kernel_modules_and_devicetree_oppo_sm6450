// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */
#include <linux/tick.h>
#include <kernel/time/tick-sched.h>
#include <trace/hooks/sched.h>

#include "./hmbird_gki/scx_main.h"

#define HIGHRES_WATCH_CPU       0
static inline bool shadow_tick_enable(void)
{
	return false;
}
static inline bool shadow_tick_dbg_enable(void) {return false;}

#define REGISTER_TRACE_VH(vender_hook, handler) \
{ \
	ret = register_trace_##vender_hook(handler, NULL); \
	if (ret) { \
			pr_err("failed to register_trace_"#vender_hook", ret=%d\n", ret); \
	} \
}

#define NUM_SHADOW_TICK_TIMER (3)
DEFINE_PER_CPU(struct hrtimer[NUM_SHADOW_TICK_TIMER], stt);
#define shadow_tick_timer(cpu, id) (&per_cpu(stt[id], (cpu)))

#define STOP_IDLE_TRIGGER     (1)
#define PERIODIC_TICK_TRIGGER (2)
static DEFINE_PER_CPU(u8, trigger_event);

void sched_switch_handler(void *data, bool preempt, struct task_struct *prev,
		struct task_struct *next, unsigned int prev_state)
{
	int i, cpu = smp_processor_id();

	if (shadow_tick_enable() && (cpu_rq(cpu)->idle == prev)) {
		this_cpu_write(trigger_event, STOP_IDLE_TRIGGER);
		for (i = 0; i < NUM_SHADOW_TICK_TIMER; i++) {
			if (!hrtimer_active(shadow_tick_timer(cpu, i)))
				hrtimer_start(shadow_tick_timer(cpu, i),
					ns_to_ktime(1000000ULL * (i + 1)), HRTIMER_MODE_REL);
		}
		if (shadow_tick_dbg_enable() && cpu == HIGHRES_WATCH_CPU)
			trace_printk("hmbird_sched : enter tick triggered by stop_idle events\n");
	}
}

enum hrtimer_restart scheduler_tick_no_balance(struct hrtimer *timer)
{
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);
	struct task_struct *curr = rq->curr;
	struct rq_flags rf;

	rq_lock(rq, &rf);
	update_rq_clock(rq);
	scx_tick_entry(rq);
	curr->sched_class->task_tick(rq, curr, 0);
	if (shadow_tick_dbg_enable() && cpu == HIGHRES_WATCH_CPU)
		trace_printk("hmbird_sched : enter tick\n");
	rq_unlock(rq, &rf);
	scx_scheduler_tick();
	return HRTIMER_NORESTART;
}

void shadow_tick_timer_init(void)
{
	int i, cpu;

	for_each_possible_cpu(cpu) {
		for (i = 0; i < NUM_SHADOW_TICK_TIMER; i++) {
			hrtimer_init(shadow_tick_timer(cpu, i),
				     CLOCK_MONOTONIC, HRTIMER_MODE_REL);
			shadow_tick_timer(cpu, i)->function = &scheduler_tick_no_balance;
		}
	}
}

void start_shadow_tick_timer(void)
{
	int i, cpu = smp_processor_id();

	if (shadow_tick_enable()) {
		if (this_cpu_read(trigger_event) == STOP_IDLE_TRIGGER) {
			for (i = 0; i < NUM_SHADOW_TICK_TIMER; i++)
				hrtimer_cancel(shadow_tick_timer(cpu, i));
		}

		this_cpu_write(trigger_event, PERIODIC_TICK_TRIGGER);

		for (i = 0; i < NUM_SHADOW_TICK_TIMER; i++) {
			if (!hrtimer_active(shadow_tick_timer(cpu, i)))
				hrtimer_start(shadow_tick_timer(cpu, i),
								ns_to_ktime(1000000ULL * (i + 1)), HRTIMER_MODE_REL);
			if (shadow_tick_dbg_enable() && cpu == HIGHRES_WATCH_CPU)
				trace_printk("hmbird_sched : restart tick\n");
		}
	}
}

static void stop_shadow_tick_timer(void)
{
	int i, cpu = smp_processor_id();

	this_cpu_write(trigger_event, 0);
	for (i = 0; i < NUM_SHADOW_TICK_TIMER; i++)
		hrtimer_cancel(shadow_tick_timer(cpu, i));
	if (shadow_tick_dbg_enable() && cpu == HIGHRES_WATCH_CPU)
		trace_printk("hmbird_sched : stop tick\n");
}

void android_vh_tick_nohz_idle_stop_tick_handler(void *unused, void *data)
{
	stop_shadow_tick_timer();
}

int scx_shadow_tick_init(void)
{
	int ret = 0;
	shadow_tick_timer_init();

	REGISTER_TRACE_VH(android_vh_tick_nohz_idle_stop_tick, android_vh_tick_nohz_idle_stop_tick_handler);
	REGISTER_TRACE_VH(sched_switch, sched_switch_handler);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#include <trace/events/sched.h>
#include <trace/hooks/sched.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/stdarg.h>
#include <linux/kprobes.h>
#if IS_ENABLED(CONFIG_SCHED_WALT)
#include <linux/sched/walt.h>
#endif /* CONFIG_SCHED_WALT */
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
#include <drivers/cpuidle/governors/trace-qcom-lpm.h>
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */

#include <linux/sched/hmbird.h>

#include "game_ctrl.h"
#include "es4g_assist_ogki.h"
#include "es4g_assist_common.h"

#define ES4G_ALLOW_PROC_WR_OPS

static unsigned int es4g_assist_debug = 0;

#define DECLARE_DEBUG_TRACE(name, proto, data)		\
	void __maybe_unused debug_##name(proto) {		\
		if (es4g_assist_debug & DEBUG_SYSTRACE) {	\
			name(data);								\
		}											\
	}
#include "debug_common.h"
#undef DECLARE_DEBUG_TRACE

static struct proc_dir_entry *es4g_dir = NULL;

static struct key_thread_struct {
	pid_t pid;
	struct task_struct *task;
	s32 prio; /* smaller is more critical, range from 0 to 8 */
	u32 slot;
	s32 cpu;
	s32 util;
} critical_thread_list[MAX_KEY_THREAD_RECORD];

static int heavy_task_index = -1;
static int __maybe_unused heavy_task_count = 0;
static int es4g_assist_preempt_policy = 0;

enum hmbird_rq_cpu_type {
	ES4G_SELECT_CPU   = 0,
	ES4G_ISOLATE_CPU  = 1,
	ES4G_LOW_ISOLATE_CPU       = 2,
	INVALIED_CPU,
};
static int select_cpu_list[MAX_NR_CPUS] = {7, 4, 3, 2, 6, 5, -1, -1};
static int sched_prop_to_preempt_prio[ES4G_TASK_PROP_MAX] = {0};

static DEFINE_RWLOCK(critical_task_list_rwlock);
static DEFINE_RWLOCK(select_cpu_list_rwlock);

void es4g_set_hmbird_rq_cpu_by_mask(int cpu_mask, enum hmbird_rq_cpu_type type) {
	int cpu;
	struct rq *rq;
	struct rq_flags rf;
	bool tmp_bool;

	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		rq_lock_irqsave(rq, &rf);
		if (cpu_mask & (1 << cpu)) {
			tmp_bool = true;
		} else {
			tmp_bool = false;
		}

		switch(type) {
		case ES4G_SELECT_CPU:
			get_hmbird_rq(rq)->es4g_select = tmp_bool;
		break;
		case ES4G_ISOLATE_CPU:
			get_hmbird_rq(rq)->es4g_isolate = tmp_bool;
		break;
		case ES4G_LOW_ISOLATE_CPU:
			get_hmbird_rq(rq)->es4g_low_isolate = tmp_bool;
		break;
		default:
			printk("invalid scx rq cpu type:%d", type);
		break;
		}
		rq_unlock_irqrestore(rq, &rf);
	}
}

int es4g_get_hmbird_rq_cpu_mask(enum hmbird_rq_cpu_type type) {
	int cpu;
	int cpu_mask = 0;
	struct rq *rq;
	bool tmp_bool;

	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		switch(type) {
		case ES4G_SELECT_CPU:
			tmp_bool = get_hmbird_rq(rq)->es4g_select;
		break;

		case ES4G_ISOLATE_CPU:
			tmp_bool = get_hmbird_rq(rq)->es4g_isolate;
		break;

		case ES4G_LOW_ISOLATE_CPU:
			tmp_bool = get_hmbird_rq(rq)->es4g_low_isolate;
		break;

		default:
			printk("invalid hmbird rq cpu type:%d", type);
		break;
		}
		if (tmp_bool) {
			cpu_mask |= (1 << cpu);
		}
	}

	return cpu_mask;
}

static inline int prop_to_index(int prop)
{
	return (~prop & TOP_TASK_BITS_MASK);
}

static inline int index_to_prop(int index)
{
	return (~index & TOP_TASK_BITS_MASK);
}

static inline int get_pipeline_sched_prop(struct task_struct *p)
{
	return get_top_task_prop(p) & TOP_TASK_BITS_MASK;
}

static inline int get_pipeline_index(struct task_struct *p)
{
	return prop_to_index(get_pipeline_sched_prop(p));
}

static inline bool sched_ext_pipeline_task(struct task_struct *p)
{
	int index = get_pipeline_index(p);

	if (index >= MAX_KEY_THREAD_RECORD) {
		return false;
	} else {
		return critical_thread_list[index].cpu >= 0;
	}
}

static inline bool task_specific_type(uint32_t prop, enum es4g_task_prop_type type)
{
	return (prop >> TOP_TASK_SHIFT) & (1 << type);
}

static inline void init_sched_prop_to_preempt_prio(void)
{
	/**
	 * prio list: 8 > 7 > 1 > other > 0 > 2
	 *
	 * type 8: 5
	 * type 7: 4
	 * type 1: 3
	 * other: 2
	 * type 0: 1
	 * type 2: 0
	 *
	 */
	for (int i = 1; i < ES4G_TASK_PROP_MAX; i++) {
		switch (i) {
		case ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL:
			sched_prop_to_preempt_prio[i] = 5;
			break;

		case ES4G_TASK_PROP_PERIODIC_AND_CRITICAL:
			sched_prop_to_preempt_prio[i] = 4;
			break;

		case ES4G_TASK_PROP_PIPELINE:
			sched_prop_to_preempt_prio[i] = 3;
			break;

		case ES4G_TASK_PROP_COMMON:
			sched_prop_to_preempt_prio[i] = 1;
			break;

		case ES4G_TASK_PROP_DEBUG_OR_LOG:
			sched_prop_to_preempt_prio[i] = 0;
			break;

		default:
			sched_prop_to_preempt_prio[i] = 2;
			break;
		}
	}
}

static inline enum es4g_task_prop_type es4g_get_task_type(struct task_struct *p)
{
	uint32_t prop = get_pipeline_sched_prop(p);

	if (task_specific_type(prop, ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL)) {
		return ES4G_TASK_PROP_TRANSIENT_AND_CRITICAL;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_PERIODIC_AND_CRITICAL)) {
		return ES4G_TASK_PROP_PERIODIC_AND_CRITICAL;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_PIPELINE) || sched_ext_pipeline_task(p)) {
		return ES4G_TASK_PROP_PIPELINE;
	}
	if (task_specific_type(prop, ES4G_TASK_PROP_COMMON) ||
			!task_specific_type(prop, ES4G_TASK_PROP_DEBUG_OR_LOG)) {
		return ES4G_TASK_PROP_COMMON;
	}
	return ES4G_TASK_PROP_DEBUG_OR_LOG;
}

static inline bool es4g_prio_higher(struct task_struct *a, struct task_struct *b)
{
	int type_a = es4g_get_task_type(a);
	int type_b = es4g_get_task_type(b);

	return sched_prop_to_preempt_prio[type_a] > sched_prop_to_preempt_prio[type_b];
}

static void remove_slot_of_index(struct key_thread_struct *list, size_t index)
{
	rcu_read_lock();
	if (list[index].slot > 0 && likely(list[index].task != NULL)) {
		set_top_task_prop(list[index].task, 0, TOP_TASK_BITS_MASK);
		get_hmbird_ts((list[index].task))->critical_affinity_cpu = -1;
		put_task_struct(list[index].task);
	}
	rcu_read_unlock();
	list[index].pid = -1;
	list[index].task = NULL;
	list[index].prio = -1;
	list[index].slot = 0;
	list[index].cpu = -1;
	list[index].util = -1;
	if (heavy_task_index == index) {
		heavy_task_index = -1;
	}
}

static bool clear_key_thread(struct key_thread_struct *list, size_t len)
{
	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < len; i++) {
		remove_slot_of_index(list, i);
	}
	write_unlock(&critical_task_list_rwlock);
	es4g_set_hmbird_rq_cpu_by_mask(0, ES4G_SELECT_CPU);
	return true;
}

static bool init_key_thread(struct key_thread_struct *list, size_t len)
{
	return clear_key_thread(list, len);
}

static void update_key_thread_cpu(struct key_thread_struct *list, size_t len)
{
	int prio_count[KEY_THREAD_PRIORITY_COUNT + 1] = {0};
	int online_cpumask = (1 << MAX_NR_CPUS) - 1;
	int task_cpumask = online_cpumask;

	/**
	 * clear key task prop if no cpu online
	 */
	if (unlikely(task_cpumask <= 0)) {
		clear_key_thread(list, len);
		return;
	}

	/* boost priority of heavy task */
	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio--;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			prio_count[list[i].prio + 1]++;
		}
	}
	/* 1st and the last slot is not necessary to count */
	for (int i = 2; i < KEY_THREAD_PRIORITY_COUNT; i++) {
		prio_count[i] += prio_count[i - 1];
	}

	read_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < len && task_cpumask > 0; i++) {
		if (list[i].slot <= 0) {
			continue;
		}
		for (int cpu_index = prio_count[list[i].prio]; cpu_index < MAX_NR_CPUS; cpu_index++) {
			if (select_cpu_list[cpu_index] < 0) {
				list[i].cpu = -1;
				get_hmbird_ts((list[i].task))->critical_affinity_cpu = -1;
				break;
			}
			if (1 << select_cpu_list[cpu_index] & task_cpumask) {
				list[i].cpu = select_cpu_list[cpu_index];
				get_hmbird_ts((list[i].task))->critical_affinity_cpu = select_cpu_list[cpu_index];
				task_cpumask &= ~(1 << select_cpu_list[cpu_index]);
				break;
			}
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio++;
	}

	es4g_set_hmbird_rq_cpu_by_mask(online_cpumask & (~task_cpumask), ES4G_SELECT_CPU);
}

static bool add_key_thread(struct key_thread_struct *list, size_t len, pid_t pid, s32 prio)
{
	int first_slot = -1;
	bool update = false;

	if (prio > MIN_KEY_THREAD_PRIORITY) {
		prio = MIN_KEY_THREAD_PRIORITY;
	}
	if (prio < MAX_KEY_THREAD_PRIORITY_US) {
		prio = MAX_KEY_THREAD_PRIORITY_US;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			if (list[i].pid == pid) {
				if (list[i].prio != prio) {
					list[i].prio = prio;
					update = true;
				}
				goto out;
			}
		} else {
			if (first_slot < 0) {
				first_slot = i;
			}
		}
	}
	if (first_slot >= 0) {
		rcu_read_lock();
		list[first_slot].task = find_task_by_vpid(pid);
		if (list[first_slot].task) {
			get_task_struct(list[first_slot].task);
			list[first_slot].pid = pid;
			list[first_slot].prio = prio;
			list[first_slot].slot = 1;
			list[first_slot].util = -1;
			hmbird_set_sched_prop(list[first_slot].task, SCHED_PROP_DEADLINE_LEVEL3);
			set_top_task_prop(list[first_slot].task, 0, TOP_TASK_BITS_MASK);
			set_top_task_prop(list[first_slot].task, index_to_prop(first_slot), 0);
			update = true;
		}
		rcu_read_unlock();
	}

out:
	if (update) {
		heavy_task_index = -1;
	}

	return update;
}

static bool remove_key_thread(struct key_thread_struct *list, size_t len, pid_t pid)
{
	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0 && list[i].pid == pid) {
			remove_slot_of_index(list, i);
			return true;
		}
	}
	return false;
}

#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
static void scx_sched_lpm_disallowed_time_hook(void *unused, int cpu, int *timeout_allowed)
{
	struct rq *rq;
	rq = cpu_rq(cpu);
	*timeout_allowed  = !!(get_hmbird_rq(rq)->es4g_select);
}
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */

/*
 * cpu cycles per instruction may be incomparable because of different cpu microarchitectures where taskload is counted,
 * so that realtime cpu-selecting is abandoned
 *
 */
static void __maybe_unused scx_update_task_scale_time_hook(void *unused, struct task_struct *p, u16 *demand_scale)
{
	/* update selected cpu if tasks with the same priority take on obvious different workload counted by demand_scale */
	int index = get_pipeline_index(p);
#if IS_ENABLED(CONFIG_OPLUS_SYSTEM_KERNEL_QCOM) && IS_ENABLED(CONFIG_SCHED_WALT)
	u64 cpu_cycles;
#endif

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (write_trylock(&critical_task_list_rwlock)) {
		critical_thread_list[index].util = *demand_scale;
		if (unlikely(heavy_task_index < 0) && select_cpu_list[0] >= 0) {
			for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
				if (critical_thread_list[i].slot > 0 && critical_thread_list[i].cpu == select_cpu_list[0]) {
					heavy_task_index = i;
					break;
				}
			}
		}

		debug_trace_pr_val_uint(critical_thread_list[index].pid, critical_thread_list[index].util);

#if IS_ENABLED(CONFIG_OPLUS_SYSTEM_KERNEL_QCOM) && IS_ENABLED(CONFIG_SCHED_WALT)
		cpu_cycles = ((struct walt_task_struct *) critical_thread_list[index].task->android_vendor_data1)->cpu_cycles;
		debug_trace_pr_val_uint(~critical_thread_list[index].pid, cpu_cycles);
#endif

		if (likely(heavy_task_index >= 0) &&
			index != heavy_task_index &&
			critical_thread_list[index].prio == critical_thread_list[heavy_task_index].prio) {
			s32 heavy_task_util = critical_thread_list[heavy_task_index].util;
			if (heavy_task_util > 0) {
				if (*demand_scale <= heavy_task_util) {
					heavy_task_count = 0;
				} else if (*demand_scale <= (heavy_task_util + (heavy_task_util >> 2))) {
					/* pass */
				} else if (heavy_task_count > 0 || *demand_scale > (heavy_task_util + (heavy_task_util >> 1))) {
					heavy_task_count++;
				}
				if (heavy_task_count > 5) {
					heavy_task_index = index;
					update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
					heavy_task_count = 0;
				}
			}
		} else {
			heavy_task_count = 0;
		}

		debug_trace_pr_val_str("count", heavy_task_count);

		write_unlock(&critical_task_list_rwlock);
	}
}

static int es4g_assist_proc_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int es4g_assist_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static void set_es4g_assist_debug(int debug)
{
	es4g_assist_debug = debug < 0 ? 0 : debug;
}

static void set_es4g_assist_preempt_policy(int type)
{
	es4g_assist_preempt_policy = type < 0 ? 0 : type;
}

static void set_es4g_assist_top_task_prop(pid_t pid, int prop)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		set_top_task_prop(task, prop << TOP_TASK_SHIFT, 0);
	}
	rcu_read_unlock();
}

static void unset_es4g_assist_top_task_prop(pid_t pid, int prop)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		set_top_task_prop(task, 0, prop << TOP_TASK_SHIFT);
	}
	rcu_read_unlock();
}

static ssize_t es4g_assist_debug_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret, debug;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d", &debug);
	if (ret < 1) {
		return -EINVAL;
	}

	set_es4g_assist_debug(debug);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_assist_debug_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len;

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d\n", es4g_assist_debug);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_assist_debug_proc_ops = {
	.proc_write		= es4g_assist_debug_proc_write,
	.proc_read		= es4g_assist_debug_proc_read,
	.proc_lseek		= default_llseek,
};

static bool __maybe_unused set_critical_task(int tid, int prio)
{
	bool ret;

	if (tid < 0 && prio < 0) {
		return clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}

	if (tid < 0)
		return false;

	write_lock(&critical_task_list_rwlock);
	if (prio < 0) {
		ret = remove_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid);
	} else {
		ret = add_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid, prio);
	}
	if (ret) {
		update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}
	write_unlock(&critical_task_list_rwlock);

	return ret;
}

static bool batch_set_critical_task(struct es4g_ctrl_info *data, struct key_thread_struct *list, size_t len)
{
	int pair;
	int tid;
	int prio;
	bool update;

	if (data->size <= 0 || (data->size & 1)) {
		return false;
	}

	if (data->data[0] < 0 && data->data[1] < 0) {
		return clear_key_thread(list, len);
	}

	pair = data->size / 2;
	update = false;

	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio >= 0) {
			continue;
		}
		if (remove_key_thread(list, len, tid)) {
			update = true;
		}
	}
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio < 0) {
			continue;
		}
		if (add_key_thread(list, len, tid, prio)) {
			update = true;
		}
	}
	if (update) {
		update_key_thread_cpu(list, len);
	}
	write_unlock(&critical_task_list_rwlock);

	return update;
}

static ssize_t es4g_critical_task_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	int tid, prio;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d %d", &tid, &prio);
	if (ret != 2)
		return -EINVAL;

	if (!set_critical_task(tid, prio)) {
		return -EINVAL;
	}

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_critical_task_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD] = {0};
	int len = 0;

	read_lock(&critical_task_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (critical_thread_list[i].slot > 0) {
			len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"tid=%d, prio=%d, cpu=%d\n",
								critical_thread_list[i].pid, critical_thread_list[i].prio, critical_thread_list[i].cpu);
		}
	}
	if (heavy_task_index >= 0) {
		len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"heavy task is %d\n", critical_thread_list[heavy_task_index].pid);
	}
	read_unlock(&critical_task_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_critical_task_proc_ops = {
	.proc_write		= es4g_critical_task_proc_write,
	.proc_read		= es4g_critical_task_proc_read,
	.proc_lseek		= default_llseek,
};

static void update_select_cpu_list(s64 *data, size_t len)
{
	if (len > MAX_NR_CPUS) {
		len = MAX_NR_CPUS;
	}

	write_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < len; i++) {
		select_cpu_list[i] = data[i];
	}
	for (int i = len; i < MAX_NR_CPUS; i++) {
		select_cpu_list[i] = -1;
	}
	write_unlock(&select_cpu_list_rwlock);

	write_lock(&critical_task_list_rwlock);
	update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	write_unlock(&critical_task_list_rwlock);
}

static ssize_t es4g_select_cpu_list_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	s64 cpu_list[MAX_KEY_THREAD_RECORD] = {0};

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%lld %lld %lld %lld %lld %lld %lld %lld",
					&cpu_list[0],
					&cpu_list[1],
					&cpu_list[2],
					&cpu_list[3],
					&cpu_list[4],
					&cpu_list[5],
					&cpu_list[6],
					&cpu_list[7]);
	if (ret <= 0) {
		return -EINVAL;
	}

	update_select_cpu_list(cpu_list, ret);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_select_cpu_list_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE << 1] = {0};
	int len = 0;

	read_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (select_cpu_list[i] >= 0) {
			len += snprintf(page + len, (ONE_PAGE_SIZE << 1) - len, "%d: %d\n", i, select_cpu_list[i]);
		} else {
			break;
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_select_cpu_list_proc_ops = {
	.proc_write		= es4g_select_cpu_list_proc_write,
	.proc_read		= es4g_select_cpu_list_proc_read,
	.proc_lseek		= default_llseek,
};

static void set_isolate_cpus(int isolate_cpus)
{
	es4g_set_hmbird_rq_cpu_by_mask(isolate_cpus, ES4G_ISOLATE_CPU);
}

static void set_low_isolate_cpus(int isolate_cpus)
{
	es4g_set_hmbird_rq_cpu_by_mask(isolate_cpus, ES4G_LOW_ISOLATE_CPU);
}

static ssize_t es4g_isolate_cpus_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int isolate_cpus, low_isolate_cpus;
	int ret;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d:%d", &isolate_cpus, &low_isolate_cpus);
	if (ret != 2) {
		return -EINVAL;
	}

	set_isolate_cpus(isolate_cpus);
	set_low_isolate_cpus(low_isolate_cpus);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_isolate_cpus_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len = 0;

	int isolate_cpus = es4g_get_hmbird_rq_cpu_mask(ES4G_ISOLATE_CPU);
	int low_isolate_cpus = es4g_get_hmbird_rq_cpu_mask(ES4G_LOW_ISOLATE_CPU);

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d:%d\n", isolate_cpus, low_isolate_cpus);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_isolate_cpus_proc_ops = {
	.proc_write		= es4g_isolate_cpus_proc_write,
	.proc_read		= es4g_isolate_cpus_proc_read,
	.proc_lseek		= default_llseek,
};

static long es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct es4g_ctrl_info data;
	void __user *uarg = (void __user *)arg;
	long ret = 0;

	if ((_IOC_TYPE(cmd) != ES4G_MAGIC) || (_IOC_NR(cmd) >= ES4G_MAX_ID)) {
		return -EINVAL;
	}

	if (copy_from_user(&data, uarg, sizeof(data))) {
		return -EFAULT;
	}

	switch (cmd) {
	case CMD_ID_ES4G_COMMON_CTRL:
		switch (data.data[0]) {
		case ES4G_COMMON_CTRL_DEBUG_LEVEL:
			set_es4g_assist_debug(data.data[1]);
			break;

		case ES4G_COMMON_CTRL_PREEMPT_TYPE:
			set_es4g_assist_preempt_policy(data.data[1]);
			break;

		case ES4G_COMMON_CTRL_SET_SCHED_PROP:
			set_es4g_assist_top_task_prop(data.data[1], data.data[2]);
			break;

		case ES4G_COMMON_CTRL_UNSET_SCHED_PROP:
			unset_es4g_assist_top_task_prop(data.data[1], data.data[2]);
			break;

		default:
			break;
		}
		break;

	case CMD_ID_ES4G_SET_CRITICAL_TASK:
		batch_set_critical_task(&data, critical_thread_list, MAX_KEY_THREAD_RECORD);
		break;

	case CMD_ID_ES4G_SELECT_CPU_LIST:
		update_select_cpu_list(data.data, data.size);
		break;

	case CMD_ID_ES4G_SET_ISOLATE_CPUS:
		if (data.size > 0) {
			set_isolate_cpus(data.data[0]);
		}
		if (data.size > 1) {
			set_low_isolate_cpus(data.data[1]);
		}
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#if IS_ENABLED(CONFIG_COMPAT)
static long compat_es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return es4g_assist_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif /* CONFIG_COMPAT */

static const struct proc_ops es4g_assist_sys_ctrl_proc_ops = {
	.proc_ioctl			= es4g_assist_ioctl,
	.proc_open			= es4g_assist_proc_open,
	.proc_release		= es4g_assist_proc_release,
#if IS_ENABLED(CONFIG_COMPAT)
	.proc_compat_ioctl	= compat_es4g_assist_ioctl,
#endif /* CONFIG_COMPAT */
	.proc_lseek			= default_llseek,
};

static void register_es4g_assist_vendor_hooks(void)
{
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
	register_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */
}

static void unregister_es4g_assist_vendor_hooks(void)
{
#if IS_ENABLED(CONFIG_CPU_IDLE_GOV_QCOM_LPM)
	unregister_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
#endif /* CONFIG_CPU_IDLE_GOV_QCOM_LPM */
}

static void es4g_proc_create(void)
{
	es4g_dir = proc_mkdir("es4g", game_opt_dir);
	proc_create_data("es4ga_ctrl", 0644, es4g_dir, &es4g_assist_sys_ctrl_proc_ops, NULL);
	proc_create_data("es4ga_debug", 0644, es4g_dir, &es4g_assist_debug_proc_ops, NULL);
	proc_create_data("critical_task", 0644, es4g_dir, &es4g_critical_task_proc_ops, NULL);
	proc_create_data("select_cpu_list", 0644, es4g_dir, &es4g_select_cpu_list_proc_ops, NULL);
	proc_create_data("isolate_cpus", 0644, es4g_dir, &es4g_isolate_cpus_proc_ops, NULL);
}

static void es4g_remove_proc_entry(void)
{
	remove_proc_entry("es4ga_ctrl", es4g_dir);
	remove_proc_entry("es4ga_debug", es4g_dir);
	remove_proc_entry("critical_task", es4g_dir);
	remove_proc_entry("select_cpu_list", es4g_dir);
	remove_proc_entry("isolate_cpus", es4g_dir);
	remove_proc_entry("es4g", game_opt_dir);
}

int es4g_assist_ogki_init(void)
{
	if (unlikely(!game_opt_dir))
		return -ENOTDIR;

	register_es4g_assist_vendor_hooks();
	es4g_proc_create();

	init_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
	init_sched_prop_to_preempt_prio();

	return 0;
}

void es4g_assist_ogki_exit(void)
{
	if (unlikely(!game_opt_dir))
		return;

	unregister_es4g_assist_vendor_hooks();
	es4g_remove_proc_entry();

	clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
}

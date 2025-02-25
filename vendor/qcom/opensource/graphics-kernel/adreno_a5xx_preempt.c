// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014-2017,2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "adreno.h"
#include "adreno_a5xx.h"
#include "adreno_pm4types.h"
#include "adreno_trace.h"

#define PREEMPT_RECORD(_field) \
		offsetof(struct a5xx_cp_preemption_record, _field)

#define PREEMPT_SMMU_RECORD(_field) \
		offsetof(struct a5xx_cp_smmu_info, _field)

static void _update_wptr(struct adreno_device *adreno_dev, bool reset_timer)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	struct adreno_ringbuffer *rb = adreno_dev->cur_rb;
	unsigned int wptr;
	unsigned long flags;

	spin_lock_irqsave(&rb->preempt_lock, flags);

	kgsl_regread(device, A5XX_CP_RB_WPTR, &wptr);

	if (wptr != rb->wptr) {
		kgsl_regwrite(device, A5XX_CP_RB_WPTR, rb->wptr);
		/*
		 * In case something got submitted while preemption was on
		 * going, reset the timer.
		 */
		reset_timer = true;
	}

	if (reset_timer)
		rb->dispatch_q.expires = jiffies +
			msecs_to_jiffies(adreno_drawobj_timeout);

	spin_unlock_irqrestore(&rb->preempt_lock, flags);
}

static void _a5xx_preemption_done(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	unsigned int status;

	/*
	 * In the very unlikely case that the power is off, do nothing - the
	 * state will be reset on power up and everybody will be happy
	 */

	if (!kgsl_state_is_awake(device))
		return;

	kgsl_regread(device, A5XX_CP_CONTEXT_SWITCH_CNTL, &status);

	if (status != 0) {
		dev_err(device->dev,
			     "Preemption not complete: status=%X cur=%d R/W=%X/%X next=%d R/W=%X/%X\n",
			     status, adreno_dev->cur_rb->id,
			     adreno_get_rptr(adreno_dev->cur_rb),
			     adreno_dev->cur_rb->wptr,
			     adreno_dev->next_rb->id,
			     adreno_get_rptr(adreno_dev->next_rb),
			     adreno_dev->next_rb->wptr);

		/* Set a fault and restart */
		adreno_scheduler_fault(adreno_dev, ADRENO_PREEMPT_FAULT);

		return;
	}

	del_timer_sync(&adreno_dev->preempt.timer);

	trace_adreno_preempt_done(adreno_dev->cur_rb->id, adreno_dev->next_rb->id, 0, 0);

	/* Clean up all the bits */
	adreno_dev->prev_rb = adreno_dev->cur_rb;
	adreno_dev->cur_rb = adreno_dev->next_rb;
	adreno_dev->next_rb = NULL;

	/* Update the wptr for the new command queue */
	_update_wptr(adreno_dev, true);

	/* Update the dispatcher timer for the new command queue */
	mod_timer(&adreno_dev->dispatcher.timer,
		adreno_dev->cur_rb->dispatch_q.expires);

	/* Clear the preempt state */
	adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_NONE);
}

static void _a5xx_preemption_fault(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	unsigned int status;

	/*
	 * If the power is on check the preemption status one more time - if it
	 * was successful then just transition to the complete state
	 */
	if (kgsl_state_is_awake(device)) {
		kgsl_regread(device, A5XX_CP_CONTEXT_SWITCH_CNTL, &status);

		if (status == 0) {
			adreno_set_preempt_state(adreno_dev,
				ADRENO_PREEMPT_COMPLETE);

			adreno_scheduler_queue(adreno_dev);
			return;
		}
	}

	dev_err(device->dev,
		     "Preemption timed out: cur=%d R/W=%X/%X, next=%d R/W=%X/%X\n",
		     adreno_dev->cur_rb->id,
		     adreno_get_rptr(adreno_dev->cur_rb),
		     adreno_dev->cur_rb->wptr,
		     adreno_dev->next_rb->id,
		     adreno_get_rptr(adreno_dev->next_rb),
		     adreno_dev->next_rb->wptr);

	adreno_scheduler_fault(adreno_dev, ADRENO_PREEMPT_FAULT);
}

static void _a5xx_preemption_worker(struct work_struct *work)
{
	struct adreno_preemption *preempt = container_of(work,
		struct adreno_preemption, work);
	struct adreno_device *adreno_dev = container_of(preempt,
		struct adreno_device, preempt);
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);

	/* Need to take the mutex to make sure that the power stays on */
	mutex_lock(&device->mutex);

	if (adreno_in_preempt_state(adreno_dev, ADRENO_PREEMPT_FAULTED))
		_a5xx_preemption_fault(adreno_dev);

	mutex_unlock(&device->mutex);
}

/* Find the highest priority active ringbuffer */
static struct adreno_ringbuffer *a5xx_next_ringbuffer(
		struct adreno_device *adreno_dev)
{
	struct adreno_ringbuffer *rb;
	unsigned long flags;
	unsigned int i;

	FOR_EACH_RINGBUFFER(adreno_dev, rb, i) {
		bool empty;

		spin_lock_irqsave(&rb->preempt_lock, flags);
		empty = adreno_rb_empty(rb);
		spin_unlock_irqrestore(&rb->preempt_lock, flags);

		if (!empty)
			return rb;
	}

	return NULL;
}

void a5xx_preemption_trigger(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	struct kgsl_iommu *iommu = KGSL_IOMMU(device);
	struct adreno_ringbuffer *next;
	uint64_t ttbr0;
	unsigned int contextidr;
	unsigned long flags;

	/* Put ourselves into a possible trigger state */
	if (!adreno_move_preempt_state(adreno_dev,
		ADRENO_PREEMPT_NONE, ADRENO_PREEMPT_START))
		return;

	/* Get the next ringbuffer to preempt in */
	next = a5xx_next_ringbuffer(adreno_dev);

	/*
	 * Nothing to do if every ringbuffer is empty or if the current
	 * ringbuffer is the only active one
	 */
	if (next == NULL || next == adreno_dev->cur_rb) {
		/*
		 * Update any critical things that might have been skipped while
		 * we were looking for a new ringbuffer
		 */

		if (next != NULL) {
			_update_wptr(adreno_dev, false);

			mod_timer(&adreno_dev->dispatcher.timer,
				adreno_dev->cur_rb->dispatch_q.expires);
		}

		adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_NONE);
		return;
	}

	/* Turn off the dispatcher timer */
	del_timer(&adreno_dev->dispatcher.timer);

	/*
	 * This is the most critical section - we need to take care not to race
	 * until we have programmed the CP for the switch
	 */

	spin_lock_irqsave(&next->preempt_lock, flags);

	/* Get the pagetable from the pagetable info. */
	kgsl_sharedmem_readq(device->scratch, &ttbr0,
		SCRATCH_RB_OFFSET(next->id, ttbr0));
	kgsl_sharedmem_readl(device->scratch, &contextidr,
		SCRATCH_RB_OFFSET(next->id, contextidr));

	kgsl_sharedmem_writel(next->preemption_desc,
		PREEMPT_RECORD(wptr), next->wptr);

	spin_unlock_irqrestore(&next->preempt_lock, flags);

	/* And write it to the smmu info */
	if (kgsl_mmu_is_perprocess(&device->mmu)) {
		kgsl_sharedmem_writeq(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(ttbr0), ttbr0);
		kgsl_sharedmem_writel(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(context_idr), contextidr);
	}

	kgsl_regwrite(device, A5XX_CP_CONTEXT_SWITCH_RESTORE_ADDR_LO,
		lower_32_bits(next->preemption_desc->gpuaddr));
	kgsl_regwrite(device, A5XX_CP_CONTEXT_SWITCH_RESTORE_ADDR_HI,
		upper_32_bits(next->preemption_desc->gpuaddr));

	adreno_dev->next_rb = next;

	/* Start the timer to detect a stuck preemption */
	mod_timer(&adreno_dev->preempt.timer,
		jiffies + msecs_to_jiffies(ADRENO_PREEMPT_TIMEOUT));

	trace_adreno_preempt_trigger(adreno_dev->cur_rb->id, adreno_dev->next_rb->id,
		1, 0);

	adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_TRIGGERED);

	/* Trigger the preemption */
	kgsl_regwrite(device, A5XX_CP_CONTEXT_SWITCH_CNTL, 1);
}

void a5xx_preempt_callback(struct adreno_device *adreno_dev, int bit)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	unsigned int status;

	if (!adreno_move_preempt_state(adreno_dev,
		ADRENO_PREEMPT_TRIGGERED, ADRENO_PREEMPT_PENDING))
		return;

	kgsl_regread(device, A5XX_CP_CONTEXT_SWITCH_CNTL, &status);

	if (status != 0) {
		dev_err(KGSL_DEVICE(adreno_dev)->dev,
			     "preempt interrupt with non-zero status: %X\n",
			     status);

		/*
		 * Under the assumption that this is a race between the
		 * interrupt and the register, schedule the worker to clean up.
		 * If the status still hasn't resolved itself by the time we get
		 * there then we have to assume something bad happened
		 */
		adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_COMPLETE);
		adreno_scheduler_queue(adreno_dev);
		return;
	}

	del_timer(&adreno_dev->preempt.timer);

	trace_adreno_preempt_done(adreno_dev->cur_rb->id, adreno_dev->next_rb->id, 0, 0);

	adreno_dev->prev_rb = adreno_dev->cur_rb;
	adreno_dev->cur_rb = adreno_dev->next_rb;
	adreno_dev->next_rb = NULL;

	/* Update the wptr if it changed while preemption was ongoing */
	_update_wptr(adreno_dev, true);

	/* Update the dispatcher timer for the new command queue */
	mod_timer(&adreno_dev->dispatcher.timer,
		adreno_dev->cur_rb->dispatch_q.expires);

	adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_NONE);

	a5xx_preemption_trigger(adreno_dev);
}

void a5xx_preemption_schedule(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);

	if (!adreno_is_preemption_enabled(adreno_dev))
		return;

	mutex_lock(&device->mutex);

	if (adreno_in_preempt_state(adreno_dev, ADRENO_PREEMPT_COMPLETE))
		_a5xx_preemption_done(adreno_dev);

	a5xx_preemption_trigger(adreno_dev);

	mutex_unlock(&device->mutex);
}

u32 a5xx_preemption_pre_ibsubmit(struct adreno_device *adreno_dev,
			struct adreno_ringbuffer *rb,
			struct adreno_context *drawctxt, u32 *cmds)
{
	unsigned int *cmds_orig = cmds;
	uint64_t gpuaddr = rb->preemption_desc->gpuaddr;
	unsigned int preempt_style = 0;

	if (!adreno_is_preemption_enabled(adreno_dev))
		return 0;

	if (drawctxt) {
		/*
		 * Preemption from secure to unsecure needs Zap shader to be
		 * run to clear all secure content. CP does not know during
		 * preemption if it is switching between secure and unsecure
		 * contexts so restrict Secure contexts to be preempted at
		 * ringbuffer level.
		 */
		if (drawctxt->base.flags & KGSL_CONTEXT_SECURE)
			preempt_style = KGSL_CONTEXT_PREEMPT_STYLE_RINGBUFFER;
		else
			preempt_style = FIELD_GET(KGSL_CONTEXT_PREEMPT_STYLE_MASK,
				drawctxt->base.flags);
	}

	/*
	 * CP_PREEMPT_ENABLE_GLOBAL(global preemption) can only be set by KMD
	 * in ringbuffer.
	 * 1) set global preemption to 0x0 to disable global preemption.
	 *    Only RB level preemption is allowed in this mode
	 * 2) Set global preemption to defer(0x2) for finegrain preemption.
	 *    when global preemption is set to defer(0x2),
	 *    CP_PREEMPT_ENABLE_LOCAL(local preemption) determines the
	 *    preemption point. Local preemption
	 *    can be enabled by both UMD(within IB) and KMD.
	 */
	*cmds++ = cp_type7_packet(CP_PREEMPT_ENABLE_GLOBAL, 1);
	*cmds++ = ((preempt_style == KGSL_CONTEXT_PREEMPT_STYLE_FINEGRAIN)
				? 2 : 0);

	/* Turn CP protection OFF */
	cmds += cp_protected_mode(adreno_dev, cmds, 0);

	/*
	 * CP during context switch will save context switch info to
	 * a5xx_cp_preemption_record pointed by CONTEXT_SWITCH_SAVE_ADDR
	 */
	*cmds++ = cp_type4_packet(A5XX_CP_CONTEXT_SWITCH_SAVE_ADDR_LO, 1);
	*cmds++ = lower_32_bits(gpuaddr);
	*cmds++ = cp_type4_packet(A5XX_CP_CONTEXT_SWITCH_SAVE_ADDR_HI, 1);
	*cmds++ = upper_32_bits(gpuaddr);

	/* Turn CP protection ON */
	cmds += cp_protected_mode(adreno_dev, cmds, 1);

	/*
	 * Enable local preemption for finegrain preemption in case of
	 * a misbehaving IB
	 */
	if (preempt_style == KGSL_CONTEXT_PREEMPT_STYLE_FINEGRAIN) {
		*cmds++ = cp_type7_packet(CP_PREEMPT_ENABLE_LOCAL, 1);
		*cmds++ = 1;
	} else {
		*cmds++ = cp_type7_packet(CP_PREEMPT_ENABLE_LOCAL, 1);
		*cmds++ = 0;
	}

	/* Enable CP_CONTEXT_SWITCH_YIELD packets in the IB2s */
	*cmds++ = cp_type7_packet(CP_YIELD_ENABLE, 1);
	*cmds++ = 2;

	return (unsigned int) (cmds - cmds_orig);
}

unsigned int a5xx_preemption_post_ibsubmit(struct adreno_device *adreno_dev,
	unsigned int *cmds)
{
	int dwords = 0;

	if (!adreno_is_preemption_enabled(adreno_dev))
		return 0;

	cmds[dwords++] = cp_type7_packet(CP_CONTEXT_SWITCH_YIELD, 4);
	/* Write NULL to the address to skip the data write */
	dwords += cp_gpuaddr(adreno_dev, &cmds[dwords], 0x0);
	cmds[dwords++] = 1;
	/* generate interrupt on preemption completion */
	cmds[dwords++] = 1;

	return dwords;
}

void a5xx_preemption_start(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	struct kgsl_iommu *iommu = KGSL_IOMMU(device);
	struct adreno_ringbuffer *rb;
	unsigned int i;

	if (!adreno_is_preemption_enabled(adreno_dev))
		return;

	/* Force the state to be clear */
	adreno_set_preempt_state(adreno_dev, ADRENO_PREEMPT_NONE);

	/* Only set up smmu info when per-process pagetables are enabled */

	if (kgsl_mmu_is_perprocess(&device->mmu)) {
		/* smmu_info is allocated and mapped in a5xx_preemption_iommu_init */
		kgsl_sharedmem_writel(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(magic), A5XX_CP_SMMU_INFO_MAGIC_REF);
		kgsl_sharedmem_writeq(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(ttbr0), MMU_DEFAULT_TTBR0(device));

		/* The CP doesn't use the asid record, so poison it */
		kgsl_sharedmem_writel(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(asid), 0xDECAFBAD);
		kgsl_sharedmem_writel(iommu->smmu_info,
			PREEMPT_SMMU_RECORD(context_idr), 0);

		kgsl_regwrite(device, A5XX_CP_CONTEXT_SWITCH_SMMU_INFO_LO,
			lower_32_bits(iommu->smmu_info->gpuaddr));

		kgsl_regwrite(device, A5XX_CP_CONTEXT_SWITCH_SMMU_INFO_HI,
			upper_32_bits(iommu->smmu_info->gpuaddr));
	}

	FOR_EACH_RINGBUFFER(adreno_dev, rb, i) {
		/*
		 * preemption_desc is allocated and mapped at init time,
		 * so no need to check sharedmem_writel return value
		 */
		kgsl_sharedmem_writel(rb->preemption_desc,
			PREEMPT_RECORD(rptr), 0);
		kgsl_sharedmem_writel(rb->preemption_desc,
			PREEMPT_RECORD(wptr), 0);

		adreno_ringbuffer_set_pagetable(device, rb,
			device->mmu.defaultpagetable);
	}

}

static int a5xx_preemption_ringbuffer_init(struct adreno_device *adreno_dev,
		struct adreno_ringbuffer *rb, uint64_t counteraddr)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);

	if (IS_ERR_OR_NULL(rb->preemption_desc))
		rb->preemption_desc = kgsl_allocate_global(device,
			A5XX_CP_CTXRECORD_SIZE_IN_BYTES, SZ_16K, 0,
			KGSL_MEMDESC_PRIVILEGED, "preemption_desc");

	if (IS_ERR(rb->preemption_desc))
		return PTR_ERR(rb->preemption_desc);

	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(magic), A5XX_CP_CTXRECORD_MAGIC_REF);
	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(info), 0);
	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(data), 0);
	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(cntl), A5XX_CP_RB_CNTL_DEFAULT);
	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(rptr), 0);
	kgsl_sharedmem_writel(rb->preemption_desc,
		PREEMPT_RECORD(wptr), 0);
	kgsl_sharedmem_writeq(rb->preemption_desc,
		PREEMPT_RECORD(rptr_addr), SCRATCH_RB_GPU_ADDR(device,
			rb->id, rptr));
	kgsl_sharedmem_writeq(rb->preemption_desc,
		PREEMPT_RECORD(rbase), rb->buffer_desc->gpuaddr);
	kgsl_sharedmem_writeq(rb->preemption_desc,
		PREEMPT_RECORD(counter), counteraddr);

	return 0;
}

int a5xx_preemption_init(struct adreno_device *adreno_dev)
{
	struct kgsl_device *device = KGSL_DEVICE(adreno_dev);
	struct kgsl_iommu *iommu = KGSL_IOMMU(device);
	struct adreno_preemption *preempt = &adreno_dev->preempt;
	struct adreno_ringbuffer *rb;
	int ret;
	unsigned int i;
	uint64_t addr;

	/* We are dependent on IOMMU to make preemption go on the CP side */
	if (kgsl_mmu_get_mmutype(device) != KGSL_MMU_TYPE_IOMMU)
		return -ENODEV;

	INIT_WORK(&preempt->work, _a5xx_preemption_worker);

	/* Allocate mem for storing preemption counters */
	if (IS_ERR_OR_NULL(preempt->scratch))
		preempt->scratch = kgsl_allocate_global(device,
			adreno_dev->num_ringbuffers *
			A5XX_CP_CTXRECORD_PREEMPTION_COUNTER_SIZE, 0, 0, 0,
			"preemption_counters");

	ret = PTR_ERR_OR_ZERO(preempt->scratch);
	if (ret)
		return ret;

	addr = preempt->scratch->gpuaddr;

	/* Allocate mem for storing preemption switch record */
	FOR_EACH_RINGBUFFER(adreno_dev, rb, i) {
		ret = a5xx_preemption_ringbuffer_init(adreno_dev, rb, addr);
		if (ret)
			return ret;

		addr += A5XX_CP_CTXRECORD_PREEMPTION_COUNTER_SIZE;
	}

	/* Allocate mem for storing preemption smmu record */
	if (kgsl_mmu_is_perprocess(&device->mmu) && IS_ERR_OR_NULL(iommu->smmu_info))
		iommu->smmu_info = kgsl_allocate_global(device, PAGE_SIZE, 0,
			KGSL_MEMFLAGS_GPUREADONLY, KGSL_MEMDESC_PRIVILEGED,
			"smmu_info");

	if (IS_ERR(iommu->smmu_info))
		return PTR_ERR(iommu->smmu_info);

	set_bit(ADRENO_DEVICE_PREEMPTION, &adreno_dev->priv);
	return 0;
}

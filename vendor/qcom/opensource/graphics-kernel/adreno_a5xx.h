/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2017,2019-2020 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022,2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ADRENO_A5XX_H_
#define _ADRENO_A5XX_H_

#include "a5xx_reg.h"

/**
 * struct adreno_a5xx_core - a5xx specific GPU core definitions
 */
struct adreno_a5xx_core {
	/** @base: Container for the generic &struct adreno_gpu_core */
	struct adreno_gpu_core base;
	/** @gpmu_tsens: ID for the temperature sensor used by the GPMU */
	unsigned int gpmu_tsens;
	/** @max_power: Max possible power draw of a core */
	unsigned int max_power;
	/** pm4fw_name: Name of the PM4 microcode file */
	const char *pm4fw_name;
	/** pfpfw_name: Name of the PFP microcode file */
	const char *pfpfw_name;
	/** gpmufw_name: Name of the GPMU microcode file */
	const char *gpmufw_name;
	/** @regfw_name: Filename for the LM registers if applicable */
	const char *regfw_name;
	/** @zap_name: Name of the CPZ zap file */
	const char *zap_name;
	/** @hwcg: List of registers and values to write for HWCG */
	const struct kgsl_regmap_list *hwcg;
	/** @hwcg_count: Number of registers in @hwcg */
	u32 hwcg_count;
	/** @vbif: List of registers and values to write for VBIF */
	const struct kgsl_regmap_list *vbif;
	/** @vbif_count: Number of registers in @vbif */
	u32 vbif_count;
	/** @highest_bank_bit: The bit of the highest DDR bank */
	u32 highest_bank_bit;
};

#define A5XX_CP_CTXRECORD_MAGIC_REF     0x27C4BAFCUL
/* Size of each CP preemption record */
#define A5XX_CP_CTXRECORD_SIZE_IN_BYTES     0x10000
/* Size of the preemption counter block (in bytes) */
#define A5XX_CP_CTXRECORD_PREEMPTION_COUNTER_SIZE   (16 * 4)

/**
 * struct a5xx_cp_preemption_record - CP context record for
 * preemption.
 * @magic: (00) Value at this offset must be equal to
 * A5XX_CP_CTXRECORD_MAGIC_REF.
 * @info: (04) Type of record. Written non-zero (usually) by CP.
 * we must set to zero for all ringbuffers.
 * @data: (08) DATA field in SET_RENDER_MODE or checkpoint packets.
 * Written by CP when switching out. Not used on switch-in.
 * we must initialize to zero.
 * @cntl: (12) RB_CNTL, saved and restored by CP.
 * @rptr: (16) RB_RPTR, saved and restored by CP.
 * @wptr: (20) RB_WPTR, saved and restored by CP.
 * @rptr_addr: (24) RB_RPTR_ADDR_LO|HI saved and restored.
 * rbase: (32) RB_BASE_LO|HI saved and restored.
 * counter: (40) Pointer to preemption counter
 */
struct a5xx_cp_preemption_record {
	uint32_t  magic;
	uint32_t  info;
	uint32_t  data;
	uint32_t  cntl;
	uint32_t  rptr;
	uint32_t  wptr;
	uint64_t  rptr_addr;
	uint64_t  rbase;
	uint64_t  counter;
};

#define A5XX_CP_SMMU_INFO_MAGIC_REF     0x3618CDA3UL

/**
 * struct a5xx_cp_smmu_info - CP preemption SMMU info.
 * @magic: (00) The value at this offset must be equal to
 * A5XX_CP_SMMU_INFO_MAGIC_REF.
 * @_pad4: (04) Reserved/padding
 * @ttbr0: (08) Base address of the page table for the
 * incoming context.
 * @context_idr: (16) Context Identification Register value.
 */
struct a5xx_cp_smmu_info {
	uint32_t  magic;
	uint32_t  _pad4;
	uint64_t  ttbr0;
	uint32_t  asid;
	uint32_t  context_idr;
};

void a5xx_snapshot(struct adreno_device *adreno_dev,
		struct kgsl_snapshot *snapshot);
unsigned int a5xx_num_registers(void);

void a5xx_crashdump_init(struct adreno_device *adreno_dev);

void a5xx_hwcg_set(struct adreno_device *adreno_dev, bool on);

#define A5XX_CP_RB_CNTL_DEFAULT ((1 << 27) | ((ilog2(4) << 8) & 0x1F00) | \
		(ilog2(KGSL_RB_DWORDS >> 1) & 0x3F))
/* GPMU interrupt multiplexor */
#define FW_INTR_INFO			(0)
#define LLM_ACK_ERR_INTR		(1)
#define ISENS_TRIM_ERR_INTR		(2)
#define ISENS_ERR_INTR			(3)
#define ISENS_IDLE_ERR_INTR		(4)
#define ISENS_PWR_ON_ERR_INTR		(5)
#define WDOG_EXPITED			(31)

#define VALID_GPMU_IRQ (\
	BIT(FW_INTR_INFO) | \
	BIT(LLM_ACK_ERR_INTR) | \
	BIT(ISENS_TRIM_ERR_INTR) | \
	BIT(ISENS_ERR_INTR) | \
	BIT(ISENS_IDLE_ERR_INTR) | \
	BIT(ISENS_PWR_ON_ERR_INTR) | \
	BIT(WDOG_EXPITED))

/* A5XX_GPMU_GPMU_LLM_GLM_SLEEP_CTRL */
#define STATE_OF_CHILD			GENMASK(5, 4)
#define STATE_OF_CHILD_01		BIT(4)
#define STATE_OF_CHILD_11		(BIT(4) | BIT(5))
#define IDLE_FULL_LM_SLEEP		BIT(0)

/* A5XX_GPMU_GPMU_LLM_GLM_SLEEP_STATUS */
#define WAKEUP_ACK			BIT(1)
#define IDLE_FULL_ACK			BIT(0)

/* A5XX_GPMU_GPMU_ISENSE_CTRL */
#define	ISENSE_CGC_EN_DISABLE		BIT(0)

/* A5XX_GPMU_TEMP_SENSOR_CONFIG */
#define GPMU_BCL_ENABLED		BIT(4)
#define GPMU_LLM_ENABLED		BIT(9)
#define GPMU_ISENSE_STATUS		GENMASK(3, 0)
#define GPMU_ISENSE_END_POINT_CAL_ERR	BIT(0)

#define AMP_CALIBRATION_RETRY_CNT	3
#define AMP_CALIBRATION_TIMEOUT		6

/* A5XX_GPMU_GPMU_VOLTAGE_INTR_EN_MASK */
#define VOLTAGE_INTR_EN			BIT(0)

/* A5XX_GPMU_GPMU_PWR_THRESHOLD */
#define PWR_THRESHOLD_VALID		0x80000000

/* A5XX_GPMU_GPMU_SP_CLOCK_CONTROL */
#define CNTL_IP_CLK_ENABLE		BIT(0)
/* AGC */
#define AGC_INIT_BASE			A5XX_GPMU_DATA_RAM_BASE
#define AGC_INIT_MSG_MAGIC		(AGC_INIT_BASE + 5)
#define AGC_MSG_BASE			(AGC_INIT_BASE + 7)

#define AGC_MSG_STATE			(AGC_MSG_BASE + 0)
#define AGC_MSG_COMMAND			(AGC_MSG_BASE + 1)
#define AGC_MSG_PAYLOAD_SIZE		(AGC_MSG_BASE + 3)
#define AGC_MSG_PAYLOAD			(AGC_MSG_BASE + 5)

#define AGC_INIT_MSG_VALUE		0xBABEFACE
#define AGC_POWER_CONFIG_PRODUCTION_ID	1

#define AGC_LM_CONFIG			(136/4)
#define AGC_LM_CONFIG_ENABLE_GPMU_ADAPTIVE (1)

#define AGC_LM_CONFIG_ENABLE_ERROR	(3 << 4)
#define AGC_LM_CONFIG_ISENSE_ENABLE     (1 << 4)

#define AGC_THROTTLE_SEL_DCS		(1 << 8)
#define AGC_THROTTLE_DISABLE            (2 << 8)


#define AGC_LLM_ENABLED			(1 << 16)
#define	AGC_GPU_VERSION_MASK		GENMASK(18, 17)
#define AGC_GPU_VERSION_SHIFT		17
#define AGC_BCL_DISABLED		(1 << 24)


#define AGC_LEVEL_CONFIG		(140/4)

#define LM_DCVS_LIMIT			1
/* FW file tages */
#define GPMU_FIRMWARE_ID		2
#define GPMU_SEQUENCE_ID		3
#define GPMU_INST_RAM_SIZE		0xFFF

#define HEADER_MAJOR			1
#define HEADER_MINOR			2
#define HEADER_DATE			3
#define HEADER_TIME			4
#define HEADER_SEQUENCE			5

#define MAX_HEADER_SIZE			10

#define LM_SEQUENCE_ID			1
#define MAX_SEQUENCE_ID			3

#define GPMU_ISENSE_SAVE	(A5XX_GPMU_DATA_RAM_BASE + 200/4)
/* LM defaults */
#define LM_DEFAULT_LIMIT		6000
#define A530_DEFAULT_LEAKAGE		0x004E001A

/**
 * to_a5xx_core - return the a5xx specific GPU core struct
 * @adreno_dev: An Adreno GPU device handle
 *
 * Returns:
 * A pointer to the a5xx specific GPU core struct
 */
static inline const struct adreno_a5xx_core *
to_a5xx_core(struct adreno_device *adreno_dev)
{
	const struct adreno_gpu_core *core = adreno_dev->gpucore;

	return container_of(core, struct adreno_a5xx_core, base);
}

/* Preemption functions */
void a5xx_preemption_trigger(struct adreno_device *adreno_dev);
void a5xx_preemption_schedule(struct adreno_device *adreno_dev);
void a5xx_preemption_start(struct adreno_device *adreno_dev);
int a5xx_preemption_init(struct adreno_device *adreno_dev);

/**
 * a5xx_preemption_post_ibsubmit - Insert commands following a submission
 * @adreno_dev: Adreno GPU handle
 * @cmds: Pointer to the ringbuffer to insert opcodes
 *
 * Return: The number of opcodes written to @cmds
 */
u32 a5xx_preemption_post_ibsubmit(struct adreno_device *adreno_dev, u32 *cmds);

/**
 * a5xx_preemption_post_ibsubmit - Insert opcodes before a submission
 * @adreno_dev: Adreno GPU handle
 * @rb: The ringbuffer being written
 * @drawctxt: The draw context being written
 * @cmds: Pointer to the ringbuffer to insert opcodes
 *
 * Return: The number of opcodes written to @cmds
 */
u32 a5xx_preemption_pre_ibsubmit(struct adreno_device *adreno_dev,
		struct adreno_ringbuffer *rb, struct adreno_context *drawctxt,
		u32 *cmds);

void a5xx_preempt_callback(struct adreno_device *adreno_dev, int bit);

u64 a5xx_read_alwayson(struct adreno_device *adreno_dev);

extern const struct adreno_perfcounters adreno_a5xx_perfcounters;

/**
 * a5xx_ringbuffer_init - Initialize the ringbuffers
 * @adreno_dev: An Adreno GPU handle
 *
 * Initialize the ringbuffer(s) for a5xx.
 * Return: 0 on success or negative on failure
 */
int a5xx_ringbuffer_init(struct adreno_device *adreno_dev);

/**
 * a5xx_ringbuffer_addcmds - Submit a command to the ringbuffer
 * @adreno_dev: An Adreno GPU handle
 * @rb: Pointer to the ringbuffer to submit on
 * @drawctxt: Pointer to the draw context for the submission, or NULL for
 * internal submissions
 * @flags: Flags for the submission
 * @in: Commands to write to the ringbuffer
 * @dwords: Size of @in (in dwords)
 * @timestamp: Timestamp for the submission
 * @time: Optional pointer to a submit time structure
 *
 * Submit a command to the ringbuffer.
 * Return: 0 on success or negative on failure
 */
int a5xx_ringbuffer_addcmds(struct adreno_device *adreno_dev,
		struct adreno_ringbuffer *rb, struct adreno_context *drawctxt,
		u32 flags, u32 *in, u32 dwords, u32 timestamp,
		struct adreno_submit_time *time);

/**
 * a5xx_ringbuffer_submitcmd - Submit a user command to the ringbuffer
 * @adreno_dev: An Adreno GPU handle
 * @cmdobj: Pointer to a user command object
 * @flags: Internal submit flags
 * @time: Optional pointer to a adreno_submit_time container
 *
 * Return: 0 on success or negative on failure
 */
int a5xx_ringbuffer_submitcmd(struct adreno_device *adreno_dev,
		struct kgsl_drawobj_cmd *cmdobj, u32 flags,
		struct adreno_submit_time *time);

int a5xx_ringbuffer_submit(struct adreno_ringbuffer *rb,
		struct adreno_submit_time *time, bool sync);

static inline bool a5xx_has_gpmu(struct adreno_device *adreno_dev)
{
	return (adreno_is_a530(adreno_dev) || adreno_is_a540(adreno_dev));
}

#ifdef CONFIG_QCOM_KGSL_CORESIGHT
void a5xx_coresight_init(struct adreno_device *device);
#else
static inline void a5xx_coresight_init(struct adreno_device *device) { }
#endif

#endif

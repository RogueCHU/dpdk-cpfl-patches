/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _ICPF_ACTIONS_H_
#define _ICPF_ACTIONS_H_

/**
 * TODOs:
 * - Group related actions together, not by action sizes
 * - Share Action definitions between NSL and CPFLib
 * - When the HAS finalizes the order of AUX and base action sets for chained
 *   actions, need to update the icpf_set/add_md[8|16|32]_ext() functions if
 *   required.
 * - The HAS may change the starting index of the MOD_VSI_LIST actions.
 *   (HSD 1409716597)
 */

/*
 * IMPORTANT NOTES:
 * - When transferring action sets to configuration packets, the whole raw value
 *   of each action set must be written in Little Endian format.
 *   if needed.
 * - SET_MD actions are evaluated in each classification block, but they are not
 *   propagated to the next block.  Their corresponding SET_MD action slots will
 *   become NOPs at the beginning of the next classification block.
 */

/* Forwarding to Ports, VSIs, VSI Lists, or Queues */
/* Modify */
/* Mirroring */
/* Hashing */
/* Statistics Counters */
/* Metadata */

/*******************************************************************************
 * FXP/CXP ACTIONS
 *
 * ACTION CONTAINTERS
 * ------------------
 * The FXP/CXP supports the following action containers which support different
 * action sizes, including 1 bit, 8 bits, 16 bits, and 24 bits.  Some actions
 * can be chained to support wider bit sizes or to access more parameters.
 * The FXP/CXP action containers support the action slots listed below.  Action
 * slots are referenced by their indices.  Different action classes or instances
 * of the same action type occupy different action slots in the action
 * containers.
 *  - 8 x 1-bit actions (occupying one action slot/index)
 *    + DROP (Mark a packet to be dropped)
 *    + HEADER_SPLIT (Indicating header split operation requested)
 *    + DIR_CHANGE (Change packet direction, ingress <-> egress, for LOOPBACK
 *      and Port-to-Port direction)
 *    + DEFER_DROP
 *    + ACT_COMMIT (3 bits, action commit options)
 *    + ORIG_MIR_MD
 *
 *  - 13 x 8-bit actions (13 slots/indices)
 *    + MIRROR (8 slots, indices 0-7, select up to 8 different mirror profiles)
 *    + RATE_LIMIT (Index 9, select a rate limiter)
 *    + MOD_META (Index 9, select a Modify profile for modifying metadata)
 *    + SET_HASH_PROFILE (Index 10, select an explicit Hash profile to use)
 *    + COUNT_MODE (Index 11, select statistics counting of pre- or post-modify
 *      packets.
 *    + MIRROR_MODE (Index 12, select pre- or post-modifying mirroring mode)
 *
 *  - 9 x 16-bit actions
 *    + COUNT_SET (Index 0, specifies an assignable counter set to use, and
 *      increment its counters accordingly with packet information)
 *    + SET_MCAST_IDX (Index 1, select which multicast table index to use in
 *      replicating a packet) - SEM only
 *    + SET_VSI (2 slots, indices 2-3, selects a VSI/VSI list/Port to forward a
 *      packet to. SEM uses both slots; others only use the first)
 *    + DEL_MD (Index 4, delete up to 2 metadata structures)
 *    + MOD_VSI_LIST (4 slots, indices 12-15, modify resulting forward-to-VSI
 *      list with pre-configured VSI lists and merge operations) - SEM only
 *
 *  - 23 x 24-bit actions (Group A - 16 slots)
 *    + MOD_ADDR (Index 0, selects a Modify content entry to be used with an
 *      expected Modify profiled specified by the MOD_PROFILE action)
 *    + MIRROR_FIRST (Index 1, select initial state and the Modify profile for
 *      sampling the first packet of a given flow)
 *    + COUNT (6 slots, indices 3-7, select a counter ID to increment with the
 *      matched packet's information)
 *    + SET_Q (Index 8, select a queue or a hashed queue region to forward to)
 *    + MOD_PROFILE (Index 10, select a Modify profile to modify the packet)
 *    + METER (6 slots, indices 10-15, select a Meter index)
 *
 *  - 23 x 24-bit actions (Group B - 7 slots)
 *    + SET_MD (6 slots, indices 0-5, add or set metadata fields)
 *    + RANGE_CHECK (Index 6, specifies a range check table entry to perform
 *      a range check operation)
 *
 * ACTION ENCODING
 * ---------------
 * Each action is encoded in 32-bit action set.  Two 8-bit actions can also be
 * encoded in the same action set.
 * - Bits 31:29 (PREC, or Precedence)
 *   + 000b: Reserved for NOP (Zero-valued action set is an NOP action)
 *   + 001b: Used for Chained/Auxiliary data; PREC is from the base action set
 *   + 010b: Used for Auxiliary Flags (AUX_FLAGS)
 *   + Other values: Indicates the precedence of the action set
 * - Bits 28:24 (Action type, size, and Index)
 *   + 00000b: Reserved for NOP and Chained action
 *   + 1XXXXb: 24-bit actions, Group A (Bits 27:24 select action slots/indices)
 *   + 01XXXb: 24-bit actions, Group B (Bits 26:24 select action slots/indices)
 *   + 001XXb: 16-bit actions (Bits 25:24 are reserved, set to 0's)
 *   + 00010b: 8-bit actions
 *   + 00001b: 1-bit actions
 * - Bits 23:0
 *   + 24-bit Actions (Group A and B):
 *     ~ 24 bits of action-specific data
 *   + 16-bit Actions:
 *     ~ Bits 23:20: Reserved (set to 0's)
 *     ~ Bits 19:16: Action slots/indices
 *     ~ Bits 15:0: 16 bits of action-specific data
 *   + 8-bit Actions: (Encode up to 2 8-bit actions)
 *     ~ Bits 23:20: Action slots/indices for 8-bit action B
 *     ~ Bits 19:16: Action slots/indices for 8-bit action A
 *     ~ Bits 15:8: 8 bits of action-specific data for action B
 *     ~ Bits 7:0: 8 bits of action-specific data for action A
 *   + 1-bit Actions
 *     ~ Bits 23:20: Action slots/indices
 *     ~ Bits 19:10: ENABLE bitmask indicating which 1-bit action is enabled
 *     ~ Bits 9:0: VALUE bitmask providing 1-bit value for enabled 1-bit actions
 *   + Chained/AUX_DATA/AUX_FLAGS
 *     ~ Bits 23:0: 24 bits of parameters for the parent/base action of chained
 *       actions
 *
 * ACTION PRECEDENCE
 * ------------------
 * The FXP/CXP use the action precedence values in the action resolution process
 * which select the final actions to performed when there are conflicts.  Action
 * precedence values come from two sources: most-significant 4 bits from the
 * AUX_PREC field in the profile used for packet classification; the least-
 * significant 3 bits come from the "PREC" field of the action sets. Valid range
 * for the "PREC" field in action sets is 1 to 7, where 7 is the highest
 * precedence.
 *
 * When adding action to rules (flow entries), the Control Plane may or may not
 * utilize different action slots for different classification blocks.  When the
 * same action slots are used in the classification process of a packet, action
 * precedence values are used to select the actions with the higher precedence.
 *
 * ACTION CLASSES
 * --------------
 * Actions are classified in 4 different groups based on when they are typically
 * evaluated or performed.
 *
 *								Subject to
 *					Subject to		Action Commit
 *					Deferred Actions	Mode
 *					----------------	----------------
 * - Early Evaluated Actions			No			No
 *   + SET_MD[0..5]
 *   + DEL_MD
 *   + SET_VSI[0..1]
 *   + MOD_VSI_LIST[0..3]
 *   + SET_MCAST_IDX
 *
 * - Pre-Modify Actions - Always Commit		No			No
 *   + SET_Q
 *   + MOD_PROFILE
 *   + MOD_META
 *   + RANGE_CHECK
 *   + DIR_CHANGE
 *   + ACT_COMMIT
 *   + ORIG_MIR_MD
 *   + SET_HAS_PROFILE
 *
 * - Pre-Modify Actions - Not Always Commit	No			Yes
 *   + Pre-Modify MIRROR[0..7]
 *   + MIRROR_FIRST
 *   + MIRROR_MODE
 *
 * - Post-Modify Actions			Yes			Yes
 *   + COUNT[0..5]
 *   + COUNT_SET
 *   + COUNT_MODE
 *   + Post-Modify MIRROR[0..7]
 *   + METER[0..5]
 *   + RATE_LIMIT
 *   + HEADER_SPLIT
 *   + DROP
 *   + DEFER_DROP
 *
 * Early evaluated actions are evaluated at the end of all lookups for SEM and
 * LEM, and after each group for WCM.  LPM forwards all actions to LEM for
 * action resolutions and evaluations.  SET_VSI[1], MOD_VSI_LIST[0..3], and
 * SET_MCAST_IDX actions can only be emitted by SEM.
 *
 * ACTION COMMIT MODE
 * ------------------
 * The ACT_COMMIT action can specify if certain action classes will be committed
 * in the initial classification pass or a recirculation pass as shown in the
 * table above.
 * Actions that are not committed in the initial classification pass are
 * deferred to recirculation passes.  Depending on the action commit mode for
 * the recirculation pass, some actions may or may not be committed.
 *
 * NOTES:
 * - When SET_VSI[0..] actions select both forward-to-VSI and forward-to-port on
 *   ingress, the forward-to-port action is ignored.
 *
 ******************************************************************************/

#pragma pack(1)

union icpf_action_set {
	u32 data;

	struct {
		u32 val : 24;
		u32 idx : 4;
		u32 tag : 1;
		u32 prec : 3;
	} set_24b_a;

	struct {
		u32 val : 24;
		u32 idx : 3;
		u32 tag : 2;
		u32 prec : 3;
	} set_24b_b;

	struct {
		u32 val : 16;
		u32 idx : 4;
		u32 unused : 6;
		u32 tag : 3;
		u32 prec : 3;
	} set_16b;

	struct {
		u32 val_a : 8;
		u32 val_b : 8;
		u32 idx_a : 4;
		u32 idx_b : 4;
		u32 tag : 5;
		u32 prec : 3;
	} set_8b;

	struct {
		u32 val : 10;
		u32 ena : 10;
		u32 idx : 4;
		u32 tag : 5;
		u32 prec : 3;
	} set_1b;

	struct {
		u32 val : 24;
		u32 tag : 5;
		u32 prec : 3;
	} nop;

	struct {
		u32 val : 24;
		u32 tag : 5;
		u32 prec : 3;
	} chained_24b;

	struct {
		u32 val : 24;
		u32 tag : 5;
		u32 prec : 3;
	} aux_flags;
};

struct icpf_action_set_ext {
#define ICPF_ACTION_SET_EXT_CNT 2
	union icpf_action_set acts[ICPF_ACTION_SET_EXT_CNT];
};

#pragma pack()

/**
 * icpf_act_nop - Encode a NOP action
 */
static inline union icpf_action_set icpf_act_nop(void)
{
	union icpf_action_set act;

	act.data = 0;
	return act;
}

/**
 * icpf_is_nop_action - Indicate if an action set is a NOP
 *
 * @act: action set to check
 */
static inline bool icpf_is_nop_action(union icpf_action_set *act)
{
	return act->data == icpf_act_nop().data;
}

#define ICPF_MAKE_MASK32(b, s)	((((u32)1 << (b)) - 1) << (s))

#define ICPF_ACT_PREC_MAX	7
#define ICPF_ACT_PREC_S		29
#define ICPF_ACT_PREC_M		ICPF_MAKE_MASK32(3, ICPF_ACT_PREC_S)
#define ICPF_ACT_PREC_SET(p)	\
	(((u32)(p) << ICPF_ACT_PREC_S) & ICPF_ACT_PREC_M)
#define ICPF_ACT_PREC_CHECK(p)	((p) > 0 && (p) <= ICPF_ACT_PREC_MAX)

#define ICPF_METADATA_ID_CNT		32	/* Max number of metadata IDs */
#define ICPF_METADATA_STRUCT_MAX_SZ	128	/* Max metadata size per ID */

/*******************************************************************************
 * 1-Bit Actions
 ******************************************************************************/
#define ICPF_ACT_1B_OP_S	24
#define ICPF_ACT_1B_OP_M	ICPF_MAKE_MASK32(5, ICPF_ACT_1B_OP_S)
#define ICPF_ACT_1B_OP		((u32)(0x01) << ICPF_ACT_1B_OP_S)

#define ICPF_ACT_1B_VAL_S	0
#define ICPF_ACT_1B_VAL_M	ICPF_MAKE_MASK32(10, ICPF_ACT_1B_VAL_S)
#define ICPF_ACT_1B_EN_S	10
#define ICPF_ACT_1B_EN_M	ICPF_MAKE_MASK32(10, ICPF_ACT_1B_EN_S)
#define ICPF_ACT_1B_INDEX_S	20
#define ICPF_ACT_1B_INDEX_M	ICPF_MAKE_MASK32(4, ICPF_ACT_1B_INDEX_S)

/* 1-bit actions currently uses only INDEX of 0 */
#define ICPF_ACT_MAKE_1B(prec, en, val) \
	((ICPF_ACT_PREC_SET(prec)) | ICPF_ACT_1B_OP | \
	 ((((u32)0) << ICPF_ACT_1B_INDEX_S) & ICPF_ACT_1B_INDEX_M) | \
	 (((u32)(en) << ICPF_ACT_1B_EN_S) & ICPF_ACT_1B_EN_M) | \
	 (((u32)(val) << ICPF_ACT_1B_VAL_S) & ICPF_ACT_1B_VAL_M))

enum icpf_act_1b_op {
	ICPF_ACT_1B_OP_DROP		= 0x01,
	ICPF_ACT_1B_OP_HDR_SPLIT	= 0x02,
	ICPF_ACT_1B_OP_DIR_CHANGE	= 0x04,
	ICPF_ACT_1B_OP_DEFER_DROP	= 0x08,
	ICPF_ACT_1B_OP_ORIG_MIR_MD	= 0x80
};

#define ICPF_ACT_1B_COMMIT_MODE_S	4
#define ICPF_ACT_1B_COMMIT_MODE_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_1B_COMMIT_MODE_S)

/**
 * icpf_act_commit_mode - action commit mode for certain action classes
 */
enum icpf_act_commit_mode {
	/* Action processing for the initial classification pass */
	ICPF_ACT_COMMIT_ALL		= 0, /* Commit all actions */
	ICPF_ACT_COMMIT_PRE_MOD		= 1, /* Commit only pre-modify actions*/
	ICPF_ACT_COMMIT_NONE		= 2, /* Commit no action */
	/* Action processing for deferred actions in a recirculation pass */
	ICPF_ACT_COMMIT_RECIR_ALL	= 4, /* Commit all actions */
	ICPF_ACT_COMMIT_RECIR_PRE_MOD	= 5, /* Commit only pre-modify actions*/
	ICPF_ACT_COMMIT_RECIR_NONE	= 6  /* Commit no action */
};

/*******************************************************************************
 * 8-Bit Actions
 ******************************************************************************/
#define ICPF_ACT_OP_8B_S	24
#define ICPF_ACT_OP_8B_M	ICPF_MAKE_MASK32(5, ICPF_ACT_OP_8B_S)
#define ICPF_ACT_OP_8B		((u32)(0x02) << ICPF_ACT_OP_8B_S)

#define ICPF_ACT_8B_A_VAL_S	0
#define ICPF_ACT_8B_A_VAL_M	ICPF_MAKE_MASK32(8, ICPF_ACT_8B_A_VAL_S)
#define ICPF_ACT_8B_A_INDEX_S	16
#define ICPF_ACT_8B_A_INDEX_M	ICPF_MAKE_MASK32(4, ICPF_ACT_8B_A_INDEX_S)

#define ICPF_ACT_8B_B_VAL_S	8
#define ICPF_ACT_8B_B_VAL_M	ICPF_MAKE_MASK32(8, ICPF_ACT_8B_B_VAL_S)
#define ICPF_ACT_8B_B_INDEX_S	20
#define ICPF_ACT_8B_B_INDEX_M	ICPF_MAKE_MASK32(4, ICPF_ACT_8B_B_INDEX_S)

/* Unless combining two 8-bit actions into an action set, both A and B fields
 * must be the same,
 */
#define ICPF_ACT_MAKE_8B(prec, idx, val) \
	((ICPF_ACT_PREC_SET(prec)) | ICPF_ACT_OP_8B | \
	 (((idx) << ICPF_ACT_8B_A_INDEX_S) & ICPF_ACT_8B_A_INDEX_M) | \
	 (((idx) << ICPF_ACT_8B_B_INDEX_S) & ICPF_ACT_8B_B_INDEX_M) | \
	 (((val) << ICPF_ACT_8B_A_VAL_S) & ICPF_ACT_8B_A_VAL_M) | \
	 (((val) << ICPF_ACT_8B_B_VAL_S) & ICPF_ACT_8B_B_VAL_M))

/* 8-Bit Action Indices */
#define ICPF_ACT_8B_INDEX_MIRROR		0
#define ICPF_ACT_8B_INDEX_RATE_LIMIT		8
#define ICPF_ACT_8B_INDEX_MOD_META		9
#define ICPF_ACT_8B_INDEX_SET_HASH_PROFILE	10
#define ICPF_ACT_8B_INDEX_COUNT_MODE		11
#define ICPF_ACT_8B_INDEX_MIRROR_MODE		12

/* 8-Bit Action Miscellaneous */
#define ICPF_ACT_8B_MIRROR_SLOTS		8
#define ICPF_ACT_8B_RATE_LIMITER_CNT		128
#define ICPF_ACT_8B_RATE_LIMITER_VALLID		0x80
#define ICPF_ACT_8B_MOD_META_PROF_CNT		16
#define ICPF_ACT_8B_MOD_META_VALID		0x80
#define ICPF_ACT_8B_SET_HASH_PROFILE_CNT	128
#define ICPF_ACT_8B_COUNT_MODE_MASK		0x3f

/*******************************************************************************
 * 16-Bit Actions
 ******************************************************************************/
#define ICPF_ACT_OP_16B_S	26
#define ICPF_ACT_OP_16B_M	ICPF_MAKE_MASK32(3, ICPF_ACT_OP_16B_S)
#define ICPF_ACT_OP_16B		((u32)0x1 << ICPF_ACT_OP_16B_S)

#define ICPF_ACT_16B_INDEX_S	16
#define ICPF_ACT_16B_INDEX_M	ICPF_MAKE_MASK32(4, ICPF_ACT_16B_INDEX_S)
#define ICPF_ACT_16B_VAL_S	0
#define ICPF_ACT_16B_VAL_M	ICPF_MAKE_MASK32(16, ICPF_ACT_16B_VAL_S)

#define ICPF_ACT_MAKE_16B(prec, idx, val) \
	((ICPF_ACT_PREC_SET(prec)) | ICPF_ACT_OP_16B | \
	 (((u32)(idx) << ICPF_ACT_16B_INDEX_S) & ICPF_ACT_16B_INDEX_M) | \
	 (((u32)(val) << ICPF_ACT_16B_VAL_S) & ICPF_ACT_16B_VAL_M))

/* 16-Bit Action Indices */
#define ICPF_ACT_16B_INDEX_COUNT_SET		0
#define ICPF_ACT_16B_INDEX_SET_MCAST_IDX	1
#define ICPF_ACT_16B_INDEX_SET_VSI		2
#define ICPF_ACT_16B_INDEX_DEL_MD		4
#define ICPF_ACT_16B_INDEX_MOD_VSI_LIST		5

/* 16-Bit Action Miscellaneous */
#define ICPF_ACT_16B_COUNT_SET_CNT		2048 /* TODO: Value from NSL */
#define ICPF_ACT_16B_SET_VSI_SLOTS		2
#define ICPF_ACT_16B_FWD_VSI_CNT		1032 /* TODO: Value from NSL */
#define ICPF_ACT_16B_FWD_VSI_LIST_CNT		256
#define ICPF_ACT_16B_MOD_VSI_LIST_CNT		1024
#define ICPF_ACT_16B_FWD_PORT_CNT		4
#define ICPF_ACT_16B_DEL_MD_MID_CNT		32
#define ICPF_ACT_16B_MOD_VSI_LIST_SLOTS		4

/* 16-Bit SET_MCAST_IDX Action */
#define ICPF_ACT_16B_SET_MCAST_VALID	((u32)1 << 15)

/* 16-Bit SET_VSI Action Variants */
#define ICPF_ACT_16B_SET_VSI_VAL_S		0
#define ICPF_ACT_16B_SET_VSI_VAL_M		\
	ICPF_MAKE_MASK32(11, ICPF_ACT_16B_SET_VSI_VAL_S)
#define ICPF_ACT_16B_SET_VSI_PE_S		11
#define ICPF_ACT_16B_SET_VSI_PE_M		\
	ICPF_MAKE_MASK32(2, ICPF_ACT_16B_SET_VSI_PE_S)
#define ICPF_ACT_16B_SET_VSI_TYPE_S		14
#define ICPF_ACT_16B_SET_VSI_TYPE_M		\
	ICPF_MAKE_MASK32(2, ICPF_ACT_16B_SET_VSI_TYPE_S)

/* 16-Bit DEL_MD Action */
#define ICPF_ACT_16B_DEL_MD_0_S		0
#define ICPF_ACT_16B_DEL_MD_1_S		5

/* 16-Bit MOD_VSI_LIST Actions */
#define ICPF_ACT_16B_MOD_VSI_LIST_ID_S	0
#define ICPF_ACT_16B_MOD_VSI_LIST_ID_M	\
	ICPF_MAKE_MASK32(10, ICPF_ACT_16B_MOD_VSI_LIST_ID_S)
#define ICPF_ACT_16B_MOD_VSI_LIST_OP_S	14
#define ICPF_ACT_16B_MOD_VSI_LIST_OP_M	\
	ICPF_MAKE_MASK32(2, ICPF_ACT_16B_MOD_VSI_LIST_OP_S)
#define ICPF_MAKE_16B_MOD_VSI_LIST(op, id) \
	((((u32)(op) << ICPF_ACT_16B_MOD_VSI_LIST_OP_S) & \
		ICPF_ACT_16B_MOD_VSI_LIST_OP_M) | \
	 (((u32)(id) << ICPF_ACT_16B_MOD_VSI_LIST_ID_S) & \
		ICPF_ACT_16B_MOD_VSI_LIST_ID_M))

#define ICPF_ACT_16B_MAKE_SET_VSI(type, pe, val) \
	((((u32)(type) << ICPF_ACT_16B_SET_VSI_TYPE_S) & \
		ICPF_ACT_16B_SET_VSI_TYPE_M) | \
	 (((u32)(pe) << ICPF_ACT_16B_SET_VSI_PE_S) & \
		ICPF_ACT_16B_SET_VSI_PE_M) | \
	 (((u32)(val) << ICPF_ACT_16B_SET_VSI_VAL_S) & \
		ICPF_ACT_16B_SET_VSI_VAL_M))

/* TODO: Use common enums with NSL */
enum icpf_prot_eng {
	ICPF_PE_LAN = 0,
	ICPF_PE_RDMA,
	ICPF_PE_CRT
};

enum icpf_act_fwd_type {
	ICPF_ACT_FWD_VSI,
	ICPF_ACT_FWD_VSI_LIST,
	ICPF_ACT_FWD_PORT
};

enum icpf_act_mod_vsi_list_op {
	ICPF_ACT_MOD_VSI_LIST_AND,	/* result &= LIST_ID */
	ICPF_ACT_MOD_VSI_LIST_AND_XOR,	/* result &= ^LIST_ID */
	ICPF_ACT_MOD_VSI_LIST_OR	/* result |= LIST_ID */
};

/*******************************************************************************
 * 24-Bit Actions
 ******************************************************************************/
/* Group A */
#define ICPF_ACT_OP_24B_A_S	28
#define ICPF_ACT_OP_24B_A_M	ICPF_MAKE_MASK32(1, ICPF_ACT_OP_24B_A_S)
#define ICPF_ACT_24B_A_INDEX_S	24
#define ICPF_ACT_24B_A_INDEX_M	ICPF_MAKE_MASK32(4, ICPF_ACT_24B_A_INDEX_S)
#define ICPF_ACT_24B_A_VAL_S	0
#define ICPF_ACT_24B_A_VAL_M	ICPF_MAKE_MASK32(24, ICPF_ACT_24B_A_VAL_S)

#define ICPF_ACT_OP_24B_A	((u32)1 << ICPF_ACT_OP_24B_A_S)

#define ICPF_ACT_MAKE_24B_A(prec, idx, val) \
	((ICPF_ACT_PREC_SET(prec)) | ICPF_ACT_OP_24B_A | \
	 (((u32)(idx) << ICPF_ACT_24B_A_INDEX_S) & ICPF_ACT_24B_A_INDEX_M) | \
	 (((u32)(val) << ICPF_ACT_24B_A_VAL_S) & ICPF_ACT_24B_A_VAL_M))

#define ICPF_ACT_24B_INDEX_MOD_ADDR	0
#define ICPF_ACT_24B_INDEX_MIRROR_FIRST	1
#define ICPF_ACT_24B_INDEX_COUNT	2
#define ICPF_ACT_24B_INDEX_SET_Q	8
#define ICPF_ACT_24B_INDEX_MOD_PROFILE	9
#define ICPF_ACT_24B_INDEX_METER	10

#define ICPF_ACT_24B_COUNT_SLOTS	6
#define ICPF_ACT_24B_METER_SLOTS	6

#define ICPF_ACT_24B_MOD_ADDR_CNT	(16 * 1024 * 1024)
#define ICPF_ACT_24B_COUNT_ID_CNT	((u32)1 << 24)
#define ICPF_ACT_24B_SET_Q_CNT		(12 * 1024)
#define ICPF_ACT_24B_SET_Q_Q_RGN_BITS	3

/* 24-Bit MIRROR_FIRST Action */
#define ICPF_ACT_24B_MIRROR_FIRST_STATE_S	0
#define ICPF_ACT_24B_MIRROR_FIRST_STATE_M	\
	ICPF_MAKE_MASK32(15, ICPF_ACT_24B_MIRROR_FIRST_STATE_S)
#define ICPF_ACT_24B_MIRROR_FIRST_PROFILE_S	16
#define ICPF_ACT_24B_MIRROR_FIRST_PROFILE_M	\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_MIRROR_FIRST_PROFILE_S)

/* 24-Bit SET_Q Action */
#define ICPF_ACT_24B_SET_Q_Q_S		0
#define ICPF_ACT_24B_SET_Q_Q_M		\
	ICPF_MAKE_MASK32(14, ICPF_ACT_24B_SET_Q_Q_S)
#define ICPF_ACT_24B_SET_Q_Q_RGN_S	14
#define ICPF_ACT_24B_SET_Q_Q_RGN_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_SET_Q_Q_RGN_S)
#define ICPF_ACT_24B_SET_Q_IMPLICIT_VSI_DIS	ICPF_MAKE_MASK32(1, 17)
#define ICPF_ACT_24B_SET_Q_DST_PE_S	21
#define ICPF_ACT_24B_SET_Q_DST_PE_M	\
	ICPF_MAKE_MASK32(2, ICPF_ACT_24B_SET_Q_DST_PE_S)
#define ICPF_ACT_24B_SET_Q_VALID	ICPF_MAKE_MASK32(1, 23)

/* 24-Bit MOD_PROFILE Action */
enum icpf_act_mod_profile_hint {
	ICPF_ACT_MOD_PROFILE_NO_ADDR = 0, /* No associated MOD_ADDR action */
	ICPF_ACT_MOD_PROFILE_PREFETCH_128B, /* Prefetch 128B using MOD_ADDR */
	ICPF_ACT_MOD_PROFILE_PREFETCH_256B, /* Prefetch 256B using MOD_ADDR */
};

#define ICPF_ACT_24B_MOD_PROFILE_PROF_S		0
#define ICPF_ACT_24B_MOD_PROFILE_PROF_M		\
	ICPF_MAKE_MASK32(11, ICPF_ACT_24B_MOD_PROFILE_PROF_S)
#define ICPF_ACT_24B_MOD_PROFILE_XTLN_IDX_S	12
#define ICPF_ACT_24B_MOD_PROFILE_XTLN_IDX_M	\
	ICPF_MAKE_MASK32(2, ICPF_ACT_24B_MOD_PROFILE_XTLN_IDX_S)
#define ICPF_ACT_24B_MOD_PROFILE_HINT_S		14
#define ICPF_ACT_24B_MOD_PROFILE_HINT_M		\
	ICPF_MAKE_MASK32(2, ICPF_ACT_24B_MOD_PROFILE_HINT_S)
#define ICPF_ACT_24B_MOD_PROFILE_APPEND_ACT_BUS		((u32)1 << 16)
#define ICPF_ACT_24B_MOD_PROFILE_SET_MISS_PREPEND	((u32)1 << 17)
#define ICPF_ACT_24B_MOD_PROFILE_VALID			((u32)1 << 23)

#define ICPF_ACT_24B_MOD_PROFILE_PTYPE_XLTN_INDEXES	4
#define ICPF_ACT_24B_MOD_PROFILE_PROF_CNT		2048

/* 24-Bit METER Actions */
#define ICPF_ACT_24B_METER_INDEX_S	0
#define ICPF_ACT_24B_METER_INDEX_M	\
	ICPF_MAKE_MASK32(20, ICPF_ACT_24B_METER_INDEX_S)
#define ICPF_ACT_24B_METER_BANK_S	20
#define ICPF_ACT_24B_METER_BANK_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_METER_BANK_S)
#define ICPF_ACT_24B_METER_VALID	((u32)1 << 23)

#define ICPF_ACT_24B_METER_BANK_CNT	6
#define ICPF_ACT_24B_METER_INDEX_CNT	((u32)1 << 20)

/* Group B */
#define ICPF_ACT_OP_24B_B_S	27
#define ICPF_ACT_OP_24B_B_M	ICPF_MAKE_MASK32(2, ICPF_ACT_OP_24B_B_S)
#define ICPF_ACT_24B_B_INDEX_S	24
#define ICPF_ACT_24B_B_INDEX_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_B_INDEX_S)
#define ICPF_ACT_24B_B_VAL_S	0
#define ICPF_ACT_24B_B_VAL_M	ICPF_MAKE_MASK32(24, ICPF_ACT_24B_B_VAL_S)

#define ICPF_ACT_OP_24B_B	((u32)1 << ICPF_ACT_OP_24B_B_S)

#define ICPF_ACT_MAKE_24B_B(prec, idx, val) \
	((ICPF_ACT_PREC_SET(prec)) | ICPF_ACT_OP_24B_B | \
	 (((u32)(idx) << ICPF_ACT_24B_B_INDEX_S) & ICPF_ACT_24B_B_INDEX_M) | \
	 (((u32)(val) << ICPF_ACT_24B_B_VAL_S) & ICPF_ACT_24B_B_VAL_M))

#define ICPF_ACT_24B_INDEX_SET_MD	0
#define ICPF_ACT_24B_INDEX_RANGE_CHECK	6
#define ICPF_ACT_24B_SET_MD_SLOTS	6

/* Set/Add/Delete Metadata Actions - SET_MD[0-5], DEL_MD */
/* 8-Bit SET_MD */
#define ICPF_ACT_24B_SET_MD8_VAL_S	0
#define ICPF_ACT_24B_SET_MD8_VAL_M	\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_SET_MD8_VAL_S)
#define ICPF_ACT_24B_SET_MD8_MASK_S	8
#define ICPF_ACT_24B_SET_MD8_MASK_M	\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_SET_MD8_MASK_S)
#define ICPF_ACT_24B_SET_MD8_OFFSET_S	16
#define ICPF_ACT_24B_SET_MD8_OFFSET_M	\
	ICPF_MAKE_MASK32(4, ICPF_ACT_24B_SET_MD8_OFFSET_S)
#define ICPF_ACT_24B_SET_MD8_TYPE_ID_S	20
#define ICPF_ACT_24B_SET_MD8_TYPE_ID_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_SET_MD8_TYPE_ID_S)
/* 16-Bit SET_MD */
#define ICPF_ACT_24B_SET_MD16_VAL_S	0
#define ICPF_ACT_24B_SET_MD16_VAL_M	\
	ICPF_MAKE_MASK32(16, ICPF_ACT_24B_SET_MD16_VAL_S)
#define ICPF_ACT_24B_SET_MD16_MASK_L_S	16 /* For chained action */
#define ICPF_ACT_24B_SET_MD16_MASK_L_M	\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_SET_MD16_MASK_L_S)
#define ICPF_ACT_24B_SET_MD16_MASK_H_SR	8
#define ICPF_ACT_24B_SET_MD16_MASK_H_M	0xff
#define ICPF_ACT_24B_SET_MD16_OFFSET_S	16
#define ICPF_ACT_24B_SET_MD16_OFFSET_M	\
	ICPF_MAKE_MASK32(4, ICPF_ACT_24B_SET_MD16_OFFSET_S)
#define ICPF_ACT_24B_SET_MD16_TYPE_ID_S	20
#define ICPF_ACT_24B_SET_MD16_TYPE_ID_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_SET_MD16_TYPE_ID_S)
#define ICPF_ACT_24B_SET_MD16		((u32)1 << 23)

#define ICPF_ACT_24B_SET_MD32_VAL_L_M	ICPF_MAKE_MASK32(24, 0)

#define ICPF_ACT_24B_SET_MD8_OFFSET_MAX		15
#define ICPF_ACT_24B_SET_MD8_TYPE_ID_MAX	7
#define ICPF_ACT_24B_SET_MD16_OFFSET_MAX	15
#define ICPF_ACT_24B_SET_MD16_TYPE_ID_MAX	7

/* RANGE_CHECK Action */
enum icpf_rule_act_rc_mode {
	ICPF_RULE_ACT_RC_1_RANGE = 0,
	ICPF_RULE_ACT_RC_2_RANGES = 1,
	ICPF_RULE_ACT_RC_4_RANGES = 2,
	ICPF_RULE_ACT_RC_8_RANGES = 3
};

#define ICPF_ACT_24B_RC_TBL_IDX_S	0
#define ICPF_ACT_24B_RC_TBL_IDX_M	\
	ICPF_MAKE_MASK32(13, ICPF_ACT_24B_RC_TBL_IDX_S)
#define ICPF_ACT_24B_RC_START_BANK_S	13
#define ICPF_ACT_24B_RC_START_BANK_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_24B_RC_START_BANK_S)
#define ICPF_ACT_24B_RC_MODE_S		16
#define ICPF_ACT_24B_RC_MODE_M		\
	ICPF_MAKE_MASK32(2, ICPF_ACT_24B_RC_MODE_S)
#define ICPF_ACT_24B_RC_XTRACT_PROF_S	18
#define ICPF_ACT_24B_RC_XTRACT_PROF_M	\
	ICPF_MAKE_MASK32(6, ICPF_ACT_24B_RC_XTRACT_PROF_S)

#define ICPF_ACT_24B_RC_TBL_INDEX_CNT	(8 * 1024)
#define ICPF_ACT_24B_RC_BANK_CNT	8
#define ICPF_ACT_24B_RC_XTRACT_PROF_CNT	64

/*******************************************************************************
 * 24-Bit Chained Auxiliary Actions
 ******************************************************************************/

/* TODO: HAS is being updated.  Revise the order of chained and base action
 * when the HAS has it finalized.
 */
/**
 * 24-Bit Chained SET_MD Actions
 *
 * Chained SET_MD actions consume two consecutive action sets.  The first one is
 * the chained AUX action set.  The second one is the base/parent action set.
 * Chained SET_MD actions can add and/or update metadata structure with IDs from
 * 0 to 31 while the non-chained SET_MD variants can only update existing meta-
 * data IDs below 16.
 */

#define ICPF_ACT_24B_SET_MD_AUX_OFFSET_S	8
#define ICPF_ACT_24B_SET_MD_AUX_OFFSET_M	\
	ICPF_MAKE_MASK32(7, ICPF_ACT_24B_SET_MD_AUX_OFFSET_S)
#define ICPF_ACT_24B_SET_MD_AUX_ADD		((u32)1 << 15)
#define ICPF_ACT_24B_SET_MD_AUX_TYPE_ID_S	16
#define ICPF_ACT_24B_SET_MD_AUX_TYPE_ID_M	\
	ICPF_MAKE_MASK32(5, ICPF_ACT_24B_SET_MD_AUX_TYPE_ID_S)
#define ICPF_ACT_24B_SET_MD_AUX_DATA_S		0
#define ICPF_ACT_24B_SET_MD_AUX_DATA_M		\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_SET_MD_AUX_DATA_S)

#define ICPF_ACT_24B_SET_MD_AUX_16B_MASK_H_S	0
#define ICPF_ACT_24B_SET_MD_AUX_16B_MASK_H_M	\
	ICPF_MAKE_MASK32(8, ICPF_ACT_24B_SET_MD_AUX_16B_MASK_H_S)
#define ICPF_ACT_24B_SET_MD_AUX_32B_VAL_H_SR	24 /* Upper 8 bits of MD32 */
#define ICPF_ACT_24B_SET_MD_AUX_32B_VAL_H_M	0xff

#define ICPF_ACT_TYPE_CHAIN_DATA_S	29
#define ICPF_ACT_TYPE_CHAIN_DATA_M	\
	ICPF_MAKE_MASK32(3, ICPF_ACT_TYPE_CHAIN_DATA_S)
#define ICPF_ACT_TYPE_CHAIN_DATA	((u32)1 << ICPF_ACT_TYPE_CHAIN_DATA_S)

#define ICPF_ACT_24B_SET_MD_OP_S	21
#define ICPF_ACT_24B_SET_MD_OP_8B	((u32)0 << ICPF_ACT_24B_SET_MD_OP_S)
#define ICPF_ACT_24B_SET_MD_OP_16B	((u32)1 << ICPF_ACT_24B_SET_MD_OP_S)
#define ICPF_ACT_24B_SET_MD_OP_32B	((u32)2 << ICPF_ACT_24B_SET_MD_OP_S)

#define ICPF_ACT_24B_SET_MD_AUX_MAKE(op, mid, off, data) \
	(ICPF_ACT_TYPE_CHAIN_DATA | (op) | \
	 (((u32)(mid) << ICPF_ACT_24B_SET_MD_AUX_TYPE_ID_S) & \
		ICPF_ACT_24B_SET_MD_AUX_TYPE_ID_M) | \
	 (((u32)(off) << ICPF_ACT_24B_SET_MD_AUX_OFFSET_S) & \
		ICPF_ACT_24B_SET_MD_AUX_OFFSET_M) | \
	 (((u32)(data) << ICPF_ACT_24B_SET_MD_AUX_DATA_S) & \
		ICPF_ACT_24B_SET_MD_AUX_DATA_M))

/*******************************************************************************
 * 1-Bit Action Factory
 ******************************************************************************/

/**
 * icpf_act_drop - Encode a 1-bit DROP action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * The DROP action has precedence over the DEFER_DOP action.
 * Affect of ACT_COMMIT action on the DROP action:
 *  - ICPF_ACT_COMMIT_ALL: Packet is dropped.
 *  - ICPF_ACT_COMMIT_PRE_MOD or ICPF_ACT_COMMIT_NONE: Packet is not dropped.
 *  - ICPF_ACT_COMMIT_RECIR_ALL: Packet is dropped.  Recirculation is canceled.
 *  - ICPF_ACT_COMMIT_RECIR_PRE_MOD or ICPF_ACT_COMMIT_RECIR_NONE: Packet is not
 *    dropped. Recirculation continues.
 *
 * Once a DROP action is set, it cannot be reverted during the classification
 * process of a network packet.
 */
static inline union icpf_action_set icpf_act_drop(u8 prec)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_OP_DROP, 1);
	return a;
}

/**
 * icpf_act_hdr_split - Encode a 1-bit HEADER_SPLIT action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * Once a HEADER_SPLIT action is set, it cannot be reverted during the
 * classification process of a network packet.
 */
static inline union icpf_action_set icpf_act_hdr_split(u8 prec)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_OP_HDR_SPLIT, 1);
	return a;
}

/**
 * icpf_act_dir_change - Encode a 1-bit DIR_CHANGE action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action indicate the packet being classified will be reversing its
 * direction, DIR_CHANGE.  This action cancels recirculation for the packet.
 * Once set, DIR_CHANGE cannot be reverted during the classification of the
 * network packet.
 */
static inline union icpf_action_set icpf_act_dir_change(u8 prec)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_OP_DIR_CHANGE, 1);
	return a;
}

/**
 * icpf_act_defer_drop - Encode a 1-bit DEFER_DROP action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * A DEFER_DROP action does not stop the packet classification process, and
 * only becomes a DROP action in the recirculation pass or a DROP action is
 * encountered.
 * Once set, DEFER_DROP cannot be reverted during the classification of the
 * network packet.
 */
static inline union icpf_action_set icpf_act_defer_drop(u8 prec)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_OP_DEFER_DROP, 1);
	return a;
}

/**
 * icpf_act_orig_mir_md - Encode a 1-bit ORIG_MIR_MD action
 *
 * Return NOP if any given input parameter is invalid.
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @update: specifies if packet metadata update is performed on original packet
 *	    when the packet is mirrored.
 */
static inline union icpf_action_set icpf_act_orig_mir_md(u8 prec, bool update)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_OP_ORIG_MIR_MD,
				  update ? 1 : 0);
	return a;
}

/**
 * icpf_act_set_commit_mode - Encode a 1-bit ACT_COMMIT action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mode: commit mode to use
 *
 * Return NOP if any given input parameter is invalid.
 *
 * An ACT_COMMIT action specifies if and when all actions are committed.
 */
static inline union icpf_action_set
icpf_act_set_commit_mode(u8 prec, enum icpf_act_commit_mode mode)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_1B(prec, ICPF_ACT_1B_COMMIT_MODE_M, (u32)mode);
	return a;
}

/*******************************************************************************
 * 8-Bit Action Factory
 ******************************************************************************/

/**
 * icpf_act_mirror - Encode an 8-bit MIRROR action
 *
 * @slot: indicates the MIRROR action slot to use; valid range [0, 7]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @prof: mirror profile to use for mirroring
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This MIRROR action mirrors the packet being classified using the specified
 * mirror profile.
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set icpf_act_mirror(u8 slot, u8 prec, u8 prof)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_8B_MIRROR_SLOTS)
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_MIRROR + slot, prof);
	return a;
}

/**
 * icpf_act_rate_limit - Encode an 8-bit RATE_LIMIT action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @limiter: indicates a rate limiter to use; valid range [0, 127]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action selects one of the 128 rate limiter to apply to a packet.
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set icpf_act_rate_limit(u8 prec, u8 limiter)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    limiter >= ICPF_ACT_8B_RATE_LIMITER_CNT)
		return icpf_act_nop();
	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_RATE_LIMIT,
				  ICPF_ACT_8B_RATE_LIMITER_VALLID | limiter);
	return a;
}

/**
 * icpf_act_mod_meta - Encode an 8-bit MOD_META action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @prof: metadata modification profile; valid range [0, 15]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action indicates 1 of the 16 metadata modification profiles for the
 * Modifier to use
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set icpf_act_mod_meta(u8 prec, u8 prof)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) || prof >= ICPF_ACT_8B_MOD_META_PROF_CNT)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_MOD_META,
				  ICPF_ACT_8B_MOD_META_VALID | prof);

	return a;
}

/**
 * icpf_act_set_hash_profile - Encode an 8-bit SET_HASH_PROFILE action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @prof: indicates the HASH profile; valid range [0, 127]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action can be emitted by classification blocks before HASH to indicate
 * the Hash profile to use in the in the Hash profile derivation process.  A
 * profile value of 0 indicates no hashing computation.
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set icpf_act_set_hash_profile(u8 prec, u8 prof)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    prof >= ICPF_ACT_8B_SET_HASH_PROFILE_CNT)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_SET_HASH_PROFILE,
				  prof);

	return a;
}

/**
 * icpf_act_count_mode - Encode an 8-bit COUNT_MODE action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pre_mod_msk: bit mask indicating pre-modify mode for COUNT action slots
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action specifies which COUNT action slots count pre-Modification bytes.
 * Each bit position X in the "pre_mod_msk" is corresponding to COUNT[X] action
 * slot.  A 1 in a bit position instructs the corresponding COUNT slot to
 * increment a byte counter using pre-Modify packet content.  A 0 instructs a
 * COUNT action slot to increment byte counter using post-Modify packet content.
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set icpf_act_count_mode(u8 prec, u8 pre_mod_msk)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    (pre_mod_msk & (~(ICPF_ACT_8B_COUNT_MODE_MASK))) != 0)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_COUNT_MODE,
				  pre_mod_msk);

	return a;
}

/**
 * icpf_act_mirror_mode - Encode an 8-bit MIRROR_MODE action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @post_mod_msk: bit mask indicating which MIRROR action slots mirror post-
 *                Modify packets
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action specifies if individual MIRROR action slots mirror pre-Modify or
 * post-Modify packets.  A 1 at a bit position in "post_mod_msk" instructs the
 * corresponding MIRROR action slot to mirror post-Modify packets.  A 0 bit
 * instructs the corresponding MIRROR action slot to mirror pre-Modify packets.
 *
 * This 8-bit action can be merged with another 8-bit action to consume the one
 * action set using the icpf_act_merge_8b_acts() function.
 */
static inline union icpf_action_set
icpf_act_mirror_mode(u8 prec, u8 post_mod_msk)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_8B(prec, ICPF_ACT_8B_INDEX_MIRROR_MODE,
				  post_mod_msk);

	return a;
}

/**
 * icpf_act_merge_8b_acts - Merge 2 8-bit actions together
 *
 * @dst: the destination action set to merge into
 * @src: the source action set to merge from
 *
 * Merge an 8-bit action from a source action set into the destination action
 * set while keeping the destination action set's precedence.
 *
 * An action set can describe either one or two 8-bit actions.
 */
static inline void
icpf_act_merge_8b_acts(union icpf_action_set *dst,
		       const union icpf_action_set *src)
{
	dst->data &= ~(ICPF_ACT_8B_B_INDEX_M | ICPF_ACT_8B_B_VAL_M);
	dst->data |= src->data & (ICPF_ACT_8B_B_INDEX_M | ICPF_ACT_8B_B_VAL_M);
}

/*******************************************************************************
 * 16-Bit Action Factory
 ******************************************************************************/

/**
 * icpf_act_count_set - Encode a 16-bit COUNT_SET action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @cntr_set_id: counter set ID to use; valid range [0, 2047]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action increments counters in one of the 2048 assignable counter sets
 * using information from the network packet being classified.
 */
static inline union icpf_action_set icpf_act_count_set(u8 prec, u16 cntr_set_id)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    cntr_set_id >= ICPF_ACT_16B_COUNT_SET_CNT)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_COUNT_SET,
				   cntr_set_id);

	return a;
}

/**
 * icpf_act_set_mcast_idx - Encode a 16-bit SET_MCAST_IDX action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mcast_idx: remote multicast table index to use; valid range [0, 255]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action selects a remote multicast table (PMC_MCAST_TABLE) entry to use.
 */
static inline union icpf_action_set
icpf_act_set_mcast_idx(u8 prec, u8 mcast_idx)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();

	val = ICPF_ACT_16B_SET_MCAST_VALID | mcast_idx;
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_SET_MCAST_IDX, val);

	return a;
}

/**
 * icpf_act_fwd_vsi - Encode a 16-bit SET_VSI action (forward to a VSI)
 *
 * @slot: SET_VSI action slot; valid range [0, 1]; only SEM uses both.
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pe: target protocol engine
 * @vsi: target VSI; valid range [0, 1031]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This encodes the "Forward to Single VSI" variant of SET_VSI action.
 * SEM can use both SET_VSI action slots.  The other classification blocks can
 * only use slot 0.
 */
static inline union icpf_action_set
icpf_act_fwd_vsi(u8 slot, u8 prec, enum icpf_prot_eng pe, u16 vsi)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_16B_SET_VSI_SLOTS ||
	    vsi >= ICPF_ACT_16B_FWD_VSI_CNT)
		return icpf_act_nop();

	val = ICPF_ACT_16B_MAKE_SET_VSI(ICPF_ACT_FWD_VSI, pe, vsi);
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_SET_VSI + slot,
				   val);

	return a;
}

/**
 * icpf_act_fwd_vsi_list - Encode a 16-bit SET_VSI action (forward to VSI list)
 *
 * @slot: SET_VSI action slot; valid range [0, 1]; only SEM uses both.
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pe: target protocol engine
 * @vsi_list_id: target VSI list; valid range [0, 1023]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This encodes the "Forward to a VSI list" variant of SET_VSI action.
 * SEM can use both SET_VSI action slots.  The other classification blocks can
 * only use slot 0.
 *
 * This variant, in both SET_VSI action slots, can only be used for SEM.
 */
static inline union icpf_action_set
icpf_act_fwd_vsi_list(u8 slot, u8 prec, enum icpf_prot_eng pe, u16 vsi_list_id)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_16B_SET_VSI_SLOTS ||
	    vsi_list_id >= ICPF_ACT_16B_FWD_VSI_LIST_CNT)
		return icpf_act_nop();

	val = ICPF_ACT_16B_MAKE_SET_VSI(ICPF_ACT_FWD_VSI_LIST, pe, vsi_list_id);
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_SET_VSI + slot,
				   val);

	return a;
}

/**
 * icpf_act_fwd_port - Encode a 16-bit SET_VSI action (forward to a port)
 *
 * @slot: SET_VSI action slot; valid range [0, 1]; only SEM uses both.
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pe: target protocol engine
 * @vsi_list: target port; valid range [0, 1]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This encodes the "Forward to a port" variant of SET_VSI action.
 * SEM can use both SET_VSI action slots.  The other classification blocks can
 * only use slot 0.
 */
static inline union icpf_action_set
icpf_act_fwd_port(u8 slot, u8 prec, enum icpf_prot_eng pe, u8 port)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_16B_SET_VSI_SLOTS ||
	    port >= ICPF_ACT_16B_FWD_PORT_CNT)
		return icpf_act_nop();

	val = ICPF_ACT_16B_MAKE_SET_VSI(ICPF_ACT_FWD_PORT, pe, port);
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_SET_VSI + slot,
				   val);

	return a;
}

/**
 * icpf_act_del_md - Encode a 16-bit DEL_MD action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @md_id0: first metadata ID to delete; valid range [0, 31]
 * @md_id1: second metadata ID to delete; valid range [0, 31]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This DEL_MD action can delete up to two metadata IDs. To delete only one
 * metadata ID, set the other metadata ID to 0x1F (null metadata).
 */
static inline union icpf_action_set
icpf_act_del_md(u8 prec, u8 md_id0, u8 md_id1)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    md_id0 >= ICPF_ACT_16B_DEL_MD_MID_CNT ||
	    md_id1 >= ICPF_ACT_16B_DEL_MD_MID_CNT)
		return icpf_act_nop();

	val = md_id0 << ICPF_ACT_16B_DEL_MD_0_S |
		md_id1 << ICPF_ACT_16B_DEL_MD_1_S;
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_DEL_MD, val);

	return a;
}

/**
 * icpf_act_mod_vsi_list - Encode a 16-bit MOD_VSI_LIST action
 *
 * @slot: MOD_VSI_LIST action slot to use; valid range [0, 3]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @op: modify operation to use
 * @vsi_list_id: VSI list ID to use; valid range [0, 1023]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * MOD_VSI_LIST actions are only valid for SEM.
 *
 * These actions modify the VSI list used by the SEM classifier using another
 * VSI list and a given operation. MOD_VSI_LIST actions must be enabled by the
 * corresponding SEM profile.
 */
static inline union icpf_action_set
icpf_act_mod_vsi_list(u8 slot, u8 prec, enum icpf_act_mod_vsi_list_op op,
		      u16 vsi_list_id)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    slot >= ICPF_ACT_16B_MOD_VSI_LIST_SLOTS ||
	    vsi_list_id >= ICPF_ACT_16B_MOD_VSI_LIST_CNT)
		return icpf_act_nop();

	val = ICPF_MAKE_16B_MOD_VSI_LIST(op, vsi_list_id);
	a.data = ICPF_ACT_MAKE_16B(prec, ICPF_ACT_16B_INDEX_MOD_VSI_LIST + slot,
				   val);

	return a;
}

/*******************************************************************************
 * 24-Bit Action Factory
 ******************************************************************************/

/**
 * icpf_act_mod_addr - Encode a 24-bit MOD_ADDR action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mod_addr: Modify content entry index; valid range [0, 16M - 1] for 128B
 *	      Modify content entries, or [0, 8M - 1] for 256B Modify content
 *	      entries
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This MOD_ADDR specifies the index of the MOD content entry an accompanying
 * MOD_PROFILE action uses.  Some MOD_PROFILE actions may need to use extra
 * information from a Modify content entry, and requires an accompanying
 * MOD_ADDR action.
 */
static inline union icpf_action_set icpf_act_mod_addr(u8 prec, u32 mod_addr)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) || mod_addr >= ICPF_ACT_24B_MOD_ADDR_CNT)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_MOD_ADDR,
				     mod_addr);

	return a;
}

/**
 * icpf_act_mirror_first - Encode a 24-bit MIRROR_FIRST action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @state_idx: index of the Mirror First State Vector
 * @prof: ID of the Mirror profile to use for the first packet
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action provides the initial state and the Mirror profile to mirror the
 * first packet.
 *
 * The MIRROR_FIRST action overrides the first MIRROR action slot.  When the
 * MIRROR_FIRST action is used for a rule set, MIRROR[0] should not be used.
 */
static inline union icpf_action_set
icpf_act_mirror_first(u8 prec, u16 state_idx, u8 prof)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec))
		return icpf_act_nop();

	val = state_idx << ICPF_ACT_24B_MIRROR_FIRST_STATE_S |
		prof << ICPF_ACT_24B_MIRROR_FIRST_PROFILE_S;
	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_MIRROR_FIRST,
				     val);

	return a;
}

/**
 * icpf_act_count - Encode a 24-bit COUNT action
 *
 * @slot: COUNT action slot index to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @cntr_id: ID of the statistics counter to use
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action increments the packet counter and byte counter associated with
 * the specified counter ID.
 */
static inline union icpf_action_set
icpf_act_count(u8 slot, u8 prec, u32 cntr_id)
{
	union icpf_action_set a;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_24B_COUNT_SLOTS ||
	    cntr_id >= ICPF_ACT_24B_COUNT_ID_CNT)
		return icpf_act_nop();

	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_COUNT + slot,
				     cntr_id);

	return a;
}

/**
 * icpf_act_set_hash_queue - Encode a 24-bit SET_Q action (one queue variant)
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pe: target protocol engine
 * @q: absolute queue index to forward to
 * @no_implicit_vsi: disable implicit VSI action (for port to port flows)
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action is a "Forward to a single queue" variant of the SET_Q action.
 *
 * SEM performs Implicit VSI for SET_Q action when "no_impliciti_vsi" is false.
 * WCM and LEM never perform Implicit VSI for SET_Q actions.
 */
static inline union icpf_action_set
icpf_act_set_hash_queue(u8 prec, enum icpf_prot_eng pe, u16 q,
			bool no_implicit_vsi)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || q >= ICPF_ACT_24B_SET_Q_CNT)
		return icpf_act_nop();

	val = ICPF_ACT_24B_SET_Q_VALID | (u32)q |
		(((u32)pe << ICPF_ACT_24B_SET_Q_DST_PE_S) &
			ICPF_ACT_24B_SET_Q_DST_PE_M);
	if (no_implicit_vsi)
		val |= ICPF_ACT_24B_SET_Q_IMPLICIT_VSI_DIS;
	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_SET_Q, val);

	return a;
}

/**
 * icpf_act_set_hash_queue_region - Encode a 24-bit SET_Q action (queue region)
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @pe: target protocol engine
 * @q_bases: absolute queue index of the first queue in the region
 * @q_rgn_bits: number of bits addressing the queue region (2^q_rgn_bits queues)
 * @no_implicit_vsi: disable implicit VSI action (for port to port flows)
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action is a "Forward to a queue region" variant of the SET_Q action.
 *
 * SEM performs Implicit VSI for SET_Q action when "no_impliciti_vsi" is false.
 * WCM and LEM never perform Implicit VSI for SET_Q actions.
 */
static inline union icpf_action_set
icpf_act_set_hash_queue_region(u8 prec, enum icpf_prot_eng pe, u16 q_base,
			       u8 q_rgn_bits, bool no_implicit_vsi)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || q_base >= ICPF_ACT_24B_SET_Q_CNT ||
	    q_rgn_bits > ICPF_ACT_24B_SET_Q_Q_RGN_BITS)
		return icpf_act_nop();

	val = ICPF_ACT_24B_SET_Q_VALID | (u32)q_base |
		((u32)q_rgn_bits << ICPF_ACT_24B_SET_Q_Q_RGN_S) |
		(((u32)pe << ICPF_ACT_24B_SET_Q_DST_PE_S) &
			ICPF_ACT_24B_SET_Q_DST_PE_M);
	if (no_implicit_vsi)
		val |= ICPF_ACT_24B_SET_Q_IMPLICIT_VSI_DIS;
	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_SET_Q, val);

	return a;
}

/**
 * icpf_act_mod_profile - Encode a 24-bit MOD_PROFILE action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @prof: Modify profile to use
 * @ptype_xltn_idx: index of packet type translation table to use for
 *		    translating the current packet type to post-Modify packet
 *		    type
 * @append_act_bus: indicates if action bus is to be appended
 * @miss_prepend: indicates if Common.FLAGS[MISS_PREPEND] metadata flag is to
 *                be set.
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This action specifies a Modify profile to use for modifying the network
 * packet being classified.  In addition, it also provides a hint to whether
 * or not an accompanied MOD_ADDR action is expected and should be prefetched.
 *
 * There is only one MOD_PROFILE action slot.  If multiple classification blocks
 * emit this action, the precedence value and auxiliary precedence value will be
 * used to select one with higher precedence.
 */
static inline union icpf_action_set
icpf_act_mod_profile(u8 prec, u16 prof, u8 ptype_xltn_idx, bool append_act_bus,
		     bool miss_prepend, enum icpf_act_mod_profile_hint hint)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    prof >= ICPF_ACT_24B_MOD_PROFILE_PROF_CNT ||
	    ptype_xltn_idx >= ICPF_ACT_24B_MOD_PROFILE_PTYPE_XLTN_INDEXES)
		return icpf_act_nop();

	val = ICPF_ACT_24B_MOD_PROFILE_VALID |
		(((u32)hint << ICPF_ACT_24B_MOD_PROFILE_HINT_S) &
			ICPF_ACT_24B_MOD_PROFILE_HINT_M) |
		(((u32)ptype_xltn_idx << ICPF_ACT_24B_MOD_PROFILE_XTLN_IDX_S) &
			ICPF_ACT_24B_MOD_PROFILE_XTLN_IDX_M) |
		((u32)prof << ICPF_ACT_24B_MOD_PROFILE_PROF_S);
	if (append_act_bus)
		val |= ICPF_ACT_24B_MOD_PROFILE_APPEND_ACT_BUS;
	if (miss_prepend)
		val |= ICPF_ACT_24B_MOD_PROFILE_SET_MISS_PREPEND;

	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_MOD_PROFILE, val);

	return a;
}

/**
 * icpf_act_meter - Encode a 24-bit METER action
 *
 * @slot: METER action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @idx: Meter index for the corresponding "bank" to use; valid range [0, 1M-1]
 * @bank: Meter bank to use; valid range [0, 5]
 *
 * Return NOP if any given input parameter is invalid.
 *
 * A bank can only be used by one of the METER action slots.  If multiple METER
 * actions select the same bank, the action with the highest action slot wins.
 * In Policer mode, METER actions at the higher indexes have precedence over
 * ones at lower indexes.
 */
static inline union icpf_action_set
icpf_act_meter(u8 slot, u8 prec, u32 idx, u8 bank)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_24B_METER_SLOTS  ||
	    idx >= ICPF_ACT_24B_METER_INDEX_CNT ||
	    bank >= ICPF_ACT_24B_METER_BANK_CNT)
		return icpf_act_nop();

	val = ICPF_ACT_24B_METER_VALID |
		(u32)idx << ICPF_ACT_24B_METER_INDEX_S |
		(u32)bank << ICPF_ACT_24B_METER_BANK_S;
	a.data = ICPF_ACT_MAKE_24B_A(prec, ICPF_ACT_24B_INDEX_METER + slot,
				     val);

	return a;
}

/**
 * icpf_act_set_md8 - Encode a 24-bit SET_MD/8 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 7]
 * @off: offset within the metadata structure to set; valid range [0, 15]
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This SET_MD action sets/updates a byte of a given metadata ID structure
 * using one of the SET_MD action slots.  This action variant can only set
 * one the first 16 bytes of any of the first 7 metadata types.
 */
static inline union icpf_action_set
icpf_act_set_md8(u8 slot, u8 prec, u8 mid, u8 off, u8 val, u8 mask)
{
	union icpf_action_set a;
	u32 tmp;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_24B_SET_MD_SLOTS ||
	    mid > ICPF_ACT_24B_SET_MD8_TYPE_ID_MAX ||
	    off > ICPF_ACT_24B_SET_MD8_OFFSET_MAX)
		return icpf_act_nop();

	tmp = ((u32)mid << ICPF_ACT_24B_SET_MD8_TYPE_ID_S) |
		((u32)off << ICPF_ACT_24B_SET_MD8_OFFSET_S) |
		((u32)mask << ICPF_ACT_24B_SET_MD8_MASK_S) |
		((u32)val << ICPF_ACT_24B_SET_MD8_VAL_S);
	a.data = ICPF_ACT_MAKE_24B_B(prec, ICPF_ACT_24B_INDEX_SET_MD + slot,
				     tmp);

	return a;
}

/**
 * icpf_act_set_md16 - Encode a 24-bit SET_MD/16 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 7]
 * @word_off: offset within the metadata structure in multiple of words;
 *	      valid range [0, 15]
 * @val: value to set
 *
 * Return NOP if any given input parameter is invalid.
 *
 * This SET_MD action sets/updates a word of a given metadata ID structure
 * using one of the SET_MD action slots.  This action variant can only set
 * one the first 16 words of any of the first 7 metadata types.
 */
static inline union icpf_action_set
icpf_act_set_md16(u8 slot, u8 prec, u8 mid, u8 word_off, u16 val)
{
	union icpf_action_set a;
	u32 tmp;

	if (!ICPF_ACT_PREC_CHECK(prec) || slot >= ICPF_ACT_24B_SET_MD_SLOTS ||
	    mid > ICPF_ACT_24B_SET_MD16_TYPE_ID_MAX ||
	    word_off > ICPF_ACT_24B_SET_MD16_OFFSET_MAX)
		return icpf_act_nop();

	tmp = ((u32)ICPF_ACT_24B_SET_MD16) |
		((u32)mid << ICPF_ACT_24B_SET_MD16_TYPE_ID_S) |
		((u32)word_off << ICPF_ACT_24B_SET_MD16_OFFSET_S) |
		((u32)val << ICPF_ACT_24B_SET_MD16_VAL_S);
	a.data = ICPF_ACT_MAKE_24B_B(prec, ICPF_ACT_24B_INDEX_SET_MD + slot,
				     tmp);

	return a;
}

/**
 * icpf_act_set_md8_ext - Encode a 24-bit SET_MD/8 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @off: offset within the metadata structure to set; valid range [0, 127]
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * This SET_MD action sets/updates a byte of a given metadata ID structure
 * using one of the SET_MD action slots.  This action is made up of 2 chained
 * action sets.  The chained action set is the first.  The base/parent action
 * sets is the second.
 */
static inline void
icpf_act_set_md8_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		     u8 off, u8 val, u8 mask)
{
	if (slot >= ICPF_ACT_24B_SET_MD_SLOTS || !ICPF_ACT_PREC_CHECK(prec) ||
	    mid >= ICPF_METADATA_ID_CNT ||
	    off >= ICPF_METADATA_STRUCT_MAX_SZ) {
		/* Make actions in action sets NOPs on bad parameters */
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		u32 data;

		/* Chained action set comes first */
		ext->acts[0].data =
			ICPF_ACT_24B_SET_MD_AUX_MAKE(ICPF_ACT_24B_SET_MD_OP_8B,
						     mid, off, 0);

		data = ((u32)mask << ICPF_ACT_24B_SET_MD8_MASK_S) | val;
		ext->acts[1].data =
			ICPF_ACT_MAKE_24B_B(prec,
					    ICPF_ACT_24B_INDEX_SET_MD + slot,
					    data);
	}
}

/**
 * icpf_act_set_md16_ext - Encode a 24-bit SET_MD/16 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @off: offset within the metadata structure to set; valid range [0, 128-2]
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * This SET_MD action sets/updates a word of a given metadata ID structure
 * using one of the SET_MD action slots.  This action is made up of 2 chained
 * action sets.  The chained action set is the first.  The base/parent action
 * sets is the second.
 */
static inline void
icpf_act_set_md16_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		      u8 off, u16 val, u16 mask)
{
	if (slot >= ICPF_ACT_24B_SET_MD_SLOTS || !ICPF_ACT_PREC_CHECK(prec) ||
	    mid >= ICPF_METADATA_ID_CNT ||
	    (off + sizeof(u16)) > ICPF_METADATA_STRUCT_MAX_SZ) {
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		u32 tmp;

		/* Chained action set comes first */
		tmp = ((u32)mask >> ICPF_ACT_24B_SET_MD16_MASK_H_SR) &
			ICPF_ACT_24B_SET_MD16_MASK_H_M;
		ext->acts[0].data =
			ICPF_ACT_24B_SET_MD_AUX_MAKE(ICPF_ACT_24B_SET_MD_OP_16B,
						     mid, off, tmp);

		tmp = (((u32)mask << ICPF_ACT_24B_SET_MD16_MASK_L_S) &
			ICPF_ACT_24B_SET_MD16_MASK_L_M) | val;
		ext->acts[1].data =
			ICPF_ACT_MAKE_24B_B(prec,
					    ICPF_ACT_24B_INDEX_SET_MD + slot,
					    tmp);
	}
}

/**
 * icpf_act_set_md32_ext - Encode a 24-bit SET_MD/32 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @off: offset within the metadata structure to set; valid range [0, 128-4]
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * This SET_MD action sets/updates a dword of a given metadata ID structure
 * using one of the SET_MD action slots.  This action is made up of 2 chained
 * action sets.  The chained action set is the first.  The base/parent action
 * sets is the second.
 */
static inline void
icpf_act_set_md32_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		      u8 off, u32 val)
{
	if (slot >= ICPF_ACT_24B_SET_MD_SLOTS || !ICPF_ACT_PREC_CHECK(prec) ||
	    mid >= ICPF_METADATA_ID_CNT ||
	    (off + sizeof(u32)) > ICPF_METADATA_STRUCT_MAX_SZ) {
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		u32 tmp;

		/* Chained action set comes first */
		tmp = val >> ICPF_ACT_24B_SET_MD_AUX_32B_VAL_H_SR;
		ext->acts[0].data =
			ICPF_ACT_24B_SET_MD_AUX_MAKE(ICPF_ACT_24B_SET_MD_OP_32B,
						     mid, off, tmp);

		/* Lower 24 bits of value */
		tmp = val & ICPF_ACT_24B_SET_MD32_VAL_L_M;
		ext->acts[1].data =
			ICPF_ACT_MAKE_24B_B(prec,
					    ICPF_ACT_24B_INDEX_SET_MD + slot,
					    tmp);
	}
}

/**
 * icpf_act_add_md8_ext - Encode a 24-bit ADD_MD/8 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @len: length of the metadata ID structure to add in multiple of 8 bytes
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * This "ADD_MD" (8-bit) variant of SET_MD action adds and sets a byte of a new
 * metadata ID structure using one of the SET_MD action slots.  This action is
 * made up of 2 chained action sets.  The chained action set is the first.  The
 * base/parent action set is the second.
 *
 * Once a metadata ID has been added, SET_MD/8/16/32 actions can be used to set/
 * update its content.
 */
static inline void
icpf_act_add_md8_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		     u8 len, u8 val, u8 mask)
{
	if (len % 8 != 0) {
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		/* Offset in SET_MD becomes length for "ADD_MD" */
		icpf_act_set_md8_ext(ext, slot, prec, mid, len, val, mask);
		if (!icpf_is_nop_action(&ext->acts[0])) {
			/* Convert the chained action set to "ADD_MD" */
			ext->acts[0].data |= ICPF_ACT_24B_SET_MD_AUX_ADD;
		}
	}
}

/**
 * icpf_act_add_md16_ext - Encode a 24-bit ADD_MD/16 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @len: length of the metadata ID structure to add in multiple of 8 bytes
 * @val: value to set
 * @mask: mask indicating which bits to be set/updated
 *
 * This "ADD_MD" (16-bit) variant of SET_MD action adds and sets a word of a new
 * metadata ID structure using one of the SET_MD action slots.  This action is
 * made up of 2 chained action sets.  The chained action set is the first.  The
 * base/parent action set is the second.
 *
 * Once a metadata ID has been added, SET_MD/8/16/32 actions can be used to set/
 * update its content.
 */
static inline void
icpf_act_add_md16_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		      u8 len, u16 val, u16 mask)
{
	if (len % 8 != 0) {
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		/* Offset in SET_MD becomes length for "ADD_MD" */
		icpf_act_set_md16_ext(ext, slot, prec, mid, len, val, mask);
		if (!icpf_is_nop_action(&ext->acts[0])) {
			/* Convert the chained action set to "ADD_MD" */
			ext->acts[0].data |= ICPF_ACT_24B_SET_MD_AUX_ADD;
		}
	}
}

/**
 * icpf_act_add_md32_ext - Encode a 24-bit ADD_MD/32 action for an action slot
 *
 * @ext: chained action set
 * @slot: SET_MD action slot to use; valid range [0, 5]
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @mid: Metadata ID to set/update; valid range [0, 31]
 * @len: length of the metadata ID structure to add in multiple of 8 bytes
 * @val: value to set
 *
 * This "ADD_MD" (32-bit) variant of SET_MD action adds and sets a dword of a
 * new metadata ID structure using one of the SET_MD action slots.  This action
 * is made up of 2 chained action sets.  The chained action set is the first.
 * The base/parent action set is the second.
 *
 * Once a metadata ID has been added, SET_MD/8/16/32 actions can be used to set/
 * update its content.
 */
static inline void
icpf_act_add_md32_ext(struct icpf_action_set_ext *ext, u8 slot, u8 prec, u8 mid,
		      u8 len, u32 val)
{
	if (len % 8 != 0) {
		ext->acts[0] = icpf_act_nop();
		ext->acts[1] = icpf_act_nop();
	} else {
		/* Offset in SET_MD becomes length for "ADD_MD" */
		icpf_act_set_md32_ext(ext, slot, prec, mid, len, val);
		if (!icpf_is_nop_action(&ext->acts[0])) {
			/* Convert the chained action set to "ADD_MD" */
			ext->acts[0].data |= ICPF_ACT_24B_SET_MD_AUX_ADD;
		}
	}
}

/**
 * icpf_act_range_check - Encode a 24-bit RANGE_CHECK action
 *
 * @prec: 3-bit precedence value to use; valid range [1, 7]
 * @entry_idx: index of table entry
 * @start_bank: starting bank within the entry
 * @mode: number of banks to write
 * @prof: Range Check extraction profile to use
 *
 * Return NOP if any given input parameter is invalid.
 */
static inline union icpf_action_set
icpf_act_range_check(u8 prec, u16 entry_idx, u8 start_bank,
		     enum icpf_rule_act_rc_mode mode, u8 prof)
{
	union icpf_action_set a;
	u32 val;

	if (!ICPF_ACT_PREC_CHECK(prec) ||
	    entry_idx >= ICPF_ACT_24B_RC_TBL_INDEX_CNT ||
	    start_bank >= ICPF_ACT_24B_RC_BANK_CNT ||
	    prof >= ICPF_ACT_24B_RC_XTRACT_PROF_CNT) {
		return icpf_act_nop();
	}

	val = ((u32)prof << ICPF_ACT_24B_RC_XTRACT_PROF_S) |
		(((u32)mode << ICPF_ACT_24B_RC_MODE_S) &
			ICPF_ACT_24B_RC_MODE_M) |
		((u32)start_bank << ICPF_ACT_24B_RC_START_BANK_S) | entry_idx;

	a.data = ICPF_ACT_MAKE_24B_B(prec, ICPF_ACT_24B_INDEX_RANGE_CHECK, val);

	return a;
}

#endif /* _ICPF_ACTIONS_H_ */

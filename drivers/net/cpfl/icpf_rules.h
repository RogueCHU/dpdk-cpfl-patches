/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _ICPF_RULES_API_H_
#define _ICPF_RULES_API_H_

#include <base/idpf_controlq_api.h>
#include "icpf_actions.h"
#include "icpf_utils.h"

/* Rule Config queue opcodes */
enum icpf_ctlq_rule_cfg_opc {
	icpf_ctlq_sem_add_rule				= 0x1303,
	icpf_ctlq_sem_update_rule			= 0x1304,
	icpf_ctlq_sem_del_rule				= 0x1305,
	icpf_ctlq_sem_query_rule			= 0x1306,
	icpf_ctlq_sem_query_rule_hash_addr		= 0x1307,
	icpf_ctlq_sem_query_del_rule_hash_addr		= 0x1308,

	icpf_ctlq_mod_add_update_rule			= 0x1360,
	icpf_ctlq_mod_query_rule			= 0x1361,
};

/* macros for creating context for rule descriptor */
#define MEV_RULE_VSI_ID_S		0
#define MEV_RULE_VSI_ID_M		\
		MAKE_MASK64(0x7FF, MEV_RULE_VSI_ID_S)

#define MEV_RULE_TIME_SEL_S		13
#define MEV_RULE_TIME_SEL_M		\
		MAKE_MASK64(0x3, MEV_RULE_TIME_SEL_S)

#define MEV_RULE_TIME_SEL_VAL_S		15
#define MEV_RULE_TIME_SEL_VAL_M		\
		MAKE_MASK64(0x1, MEV_RULE_TIME_SEL_VAL_S)

#define MEV_RULE_PORT_NUM_S		16
#define MEV_RULE_HOST_ID_S		18
#define MEV_RULE_PORT_NUM_M		\
		MAKE_MASK64(0x3, MEV_RULE_PORT_NUM_S)
#define MEV_RULE_HOST_ID_M		\
		MAKE_MASK64(0x7, MEV_RULE_HOST_ID_S)

#define MEV_RULE_CACHE_WR_THRU_S	21
#define MEV_RULE_CACHE_WR_THRU_M	\
		MAKE_MASK64(0x1, MEV_RULE_CACHE_WR_THRU_S)

#define MEV_RULE_RESP_REQ_S		22
#define MEV_RULE_RESP_REQ_M		\
		MAKE_MASK64(0x3, MEV_RULE_RESP_REQ_S)
#define MEV_RULE_OBJ_ADDR_S		24
#define MEV_RULE_OBJ_ADDR_M		\
		MAKE_MASK64(0x7FFFFFF, MEV_RULE_OBJ_ADDR_S)
#define MEV_RULE_OBJ_ID_S		59
#define MEV_RULE_OBJ_ID_M		\
		MAKE_MASK64((u64)0x3, MEV_RULE_OBJ_ID_S)

/* macros for creating CFG_CTRL for sem/lem rule blob */
#define MEV_RULE_CFG_CTRL_PROF_ID_S			0
#define MEV_RULE_CFG_CTRL_PROF_ID_M			\
		MAKE_MASK16(0x7FF, MEV_RULE_CFG_CTRL_PROF_ID_S)

#define MEV_RULE_CFG_CTRL_SUB_PROF_ID_S		11
#define MEV_RULE_CFG_CTRL_SUB_PROF_ID_M		\
		MAKE_MASK16(0x3, MEV_RULE_CFG_CTRL_SUB_PROF_ID_S)
#define MEV_RULE_CFG_CTRL_PIN_CACHE_S		13
#define MEV_RULE_CFG_CTRL_PIN_CACHE_M		\
		MAKE_MASK16(0x1, MEV_RULE_CFG_CTRL_PIN_CACHE_S)
#define MEV_RULE_CFG_CTRL_CLEAR_MIRROR_S	14
#define MEV_RULE_CFG_CTRL_CLEAR_MIRROR_M	\
		MAKE_MASK16(0x1, MEV_RULE_CFG_CTRL_CLEAR_MIRROR_S)
#define MEV_RULE_CFG_CTRL_FIXED_FETCH_S		15
#define MEV_RULE_CFG_CTRL_FIXED_FETCH_M		\
		MAKE_MASK16(0x1, MEV_RULE_CFG_CTRL_FIXED_FETCH_S)

/*
 * macro to build the CFG_CTRL for rule packet data, which is one of
 * icpf_prep_sem_rule_blob()'s input parameter.
 */
 /* build SEM CFG_CTRL*/
#define ICPF_GET_MEV_SEM_RULE_CFG_CTRL(prof_id, sub_prof_id,		       \
				       pin_to_cache, fixed_fetch)	       \
		(SHIFT_VAL16((prof_id), MEV_RULE_CFG_CTRL_PROF_ID)	     | \
		 SHIFT_VAL16((sub_prof_id), MEV_RULE_CFG_CTRL_SUB_PROF_ID)   | \
		 SHIFT_VAL16((pin_to_cache), MEV_RULE_CFG_CTRL_PIN_CACHE)    | \
		 SHIFT_VAL16((fixed_fetch), MEV_RULE_CFG_CTRL_FIXED_FETCH))

/* macros for creating mod content config packets */
#define MEV_RULE_MOD_INDEX_S		24
#define MEV_RULE_MOD_INDEX_M		\
		MAKE_MASK64(0xFFFFFFFF, MEV_RULE_MOD_INDEX_S)

#define MEV_RULE_PIN_MOD_CONTENT_S	62
#define MEV_RULE_PIN_MOD_CONTENT_M	\
		MAKE_MASK64((u64)0x1, MEV_RULE_PIN_MOD_CONTENT_S)
#define MEV_RULE_MOD_OBJ_SIZE_S		63
#define MEV_RULE_MOD_OBJ_SIZE_M		\
		MAKE_MASK64((u64)0x1, MEV_RULE_MOD_OBJ_SIZE_S)

/*
 * struct icpf_sem_rule_cfg_pkt - Describes rule information for SEM
 * @key: The match content key
 * @actions: The action container consisting of up to 18 x 4B action sets.
 *           The number of valid actions in the set is taken from the value
 *           configured with the profile. Set by SW for Add, Update.
 * @cfg_ctrl: Config Control, Set by SW for Add, Update, Delete, and Query
 * @ctrl_word: Entry Control Word
 *
 * note: The key may be in mixed big/little endian format, the rest of members
 *       are in little endian
 */

struct icpf_sem_rule_cfg_pkt {
#define MEV_SEM_RULE_KEY_SIZE 128
	u8 key[MEV_SEM_RULE_KEY_SIZE];

#define MEV_SEM_RULE_ACT_SIZE 72
	u8 actions[MEV_SEM_RULE_ACT_SIZE];

	/* Bit(s):
	 * 10:0 : PROFILE_ID
	 * 12:11: SUB_PROF_ID (used for SEM only)
	 * 13   : pin the SEM key content into the cache
	 * 14   : Reserved
	 * 15   : Fixed_fetch
	 */
	u8 cfg_ctrl[2];

	/* Bit(s):
	 * 0:     valid
	 * 15:1:  Hints
	 * 26:16: PROFILE_ID, the profile associated with the entry
	 * 31:27: PF
	 * 55:32: FLOW ID (assigned by HW)
	 * 63:56: EPOCH
	 */
	u8 ctrl_word[8];
	u8 padding[46];
};

/*
 * union icpf_rule_cfg_pkt_record - Describes rule data blob
 * @sem_rule: SEM rule
 * @pkt_data: raw data
 * @mod_blob: MOD rule
 */
union icpf_rule_cfg_pkt_record {
	struct icpf_sem_rule_cfg_pkt sem_rule;
	u8 pkt_data[256];
	u8 mod_blob[256];
};

/**
 * icpf_rule_query_addr - LEM/SEM Rule Query Address strcuture
 * @obj_id: object id asssociated with the rule's profile
 * @obj_addr: rule's object base address within private memory space
 * @num_64B_rd: Number of 64B to read
 */
struct icpf_rule_query_addr {
	u8	obj_id;
	u32	obj_addr;
};

/**
 * icpf_rule_query_del_addr - Rule Query and Delete Address
 * @obj_id: object id asssociated with the rule's profile
 * @obj_addr: rule's object base address within private memory space
 */
struct icpf_rule_query_del_addr {
	u8	obj_id;
	u32	obj_addr;
};

/**
 * icpf_rule_mod_content - MOD Rule Content
 * @obj_size: size of MOD content entry
 * @pin_content: pin modify content to cache
 * @index: modify index, for modify content configuration only
 */
struct icpf_rule_mod_content {
	u8	obj_size;
	u8	pin_content;
	u32	index;
};

/**
 * icpf_rule_cfg_data_common - data struct for all rule opcodes
 * @opc: opcode
 * @cookie: SW cookie, response from RxQ keeps the value from paired TxQ
 * @port_num: port number
 * @host_id: host id
 * @pf_num: PF number
 * @resp_req: 0: no resp. 1:error only. 2:always generate response.
 * @ret_val: returned value from response
 * @buf_len: buffer length of payload
 * @payload: pointer to DMA memory of rule blob data
 *
 *note: some rules may only require part of strucure
 */
struct icpf_rule_cfg_data_common {
	enum icpf_ctlq_rule_cfg_opc opc;
	u64	cookie;
	u16	vsi_id;
	u8	port_num;
	u8	host_id;
	u8	time_sel;
	u8	time_sel_val;
	u8	cache_wr_thru;
	u8	resp_req;
	u32	ret_val;
	u16	buf_len;
	struct idpf_dma_mem *payload;
};

/**
 * icpf_rule_cfg_data - rule config data
 * @common: struct of rule config data for all opcodes.
 * @ext: extension of rule config data for special opcodes
 *
 * note: Before sending rule to HW, caller needs to fill
 *       in this struct then call icpf_prep_rule_desc().
 */
struct icpf_rule_cfg_data {
	struct icpf_rule_cfg_data_common common;
	union {
		struct icpf_rule_query_addr query_addr;
		struct icpf_rule_query_del_addr query_del_addr;
		struct icpf_rule_mod_content mod_content;
	} ext;
};

/**
 * icpf_fill_rule_mod_content - fill info for mod content
 * @mod_obj_size: MOD content entry size
 * @pin_mod_content: pin MOD content to cache
 * @mod_index: modify index for modify content configuration only
 */
static inline void
icpf_fill_rule_mod_content(u8 mod_obj_size,
			   u8 pin_mod_content,
			   u32 mod_index,
			   struct icpf_rule_mod_content *mod_content)
{
	mod_content->obj_size = mod_obj_size;
	mod_content->pin_content = pin_mod_content;
	mod_content->index = mod_index;
}

/**
 * icpf_fill_rule_cfg_data_common - fill in rule config data for all opcodes
 * @opc: opcode for rules
 * @cookie: SW cookie. caller decides how to use it
 * @vsi_id: vsi_id associated with the rule (LEM)
 * @port_num: port number
 * @host_id: host id (not used by LEM or SEM)
 * @time_sel: TIME_SEL value to use for the entry, only valid for
 *            Add and Update commands. Valid value : 0~3
 * @time_sel_val: 1 bit value. Indicates that TIME_SEL field is valid for Add
 *                and Update commands if the corresponding Profile is enabled
 *                for aging. No effect if the corresponding PROFILE is not
 *                enabled for flow aging. If the profile is enabled for flow
 *                aging and this bit is not set for Config ADD commands,
 *                hardware uses TIME_SEL = 0 as default age time value. For
 *                Config Update commands, if this bit is set to 0, TIME_SEL
 *                value for the entry is not updated.
 * @port_num: port number
 * @cache_wr_thru: enable(1) or disable (0) cache write through for Add/Update
 *                 Rule commands.
 * @resp_req: 0: no resp. 1:error only. 2:always generate response
 * @payload_len: byte length of payload
 * @payload: pointer to DMA memory of payload
 * @cfg_cmn: pointer to icpf_rule_cfg_data_common structure
 *
 * note: call this function before calls icpf_prep_rule_desc()
 */
static inline void
icpf_fill_rule_cfg_data_common(enum icpf_ctlq_rule_cfg_opc opc,
			       u64 cookie,
			       u16 vsi_id,
			       u8 port_num,
			       u8 host_id,
			       u8 time_sel,
			       u8 time_sel_val,
			       u8 cache_wr_thru,
			       u8 resp_req,
			       u16 payload_len,
			       struct idpf_dma_mem *payload,
			       struct icpf_rule_cfg_data_common *cfg_cmn)
{
	cfg_cmn->opc = opc;
	cfg_cmn->cookie = cookie;
	cfg_cmn->vsi_id = vsi_id;
	cfg_cmn->port_num = port_num;
	cfg_cmn->resp_req = resp_req;
	cfg_cmn->ret_val = 0;
	cfg_cmn->host_id = host_id;
	cfg_cmn->time_sel = time_sel;
	cfg_cmn->time_sel_val = time_sel_val;
	cfg_cmn->cache_wr_thru = cache_wr_thru;

	cfg_cmn->buf_len = payload_len;
	cfg_cmn->payload = payload;
}

void
icpf_prep_rule_desc(struct icpf_rule_cfg_data *cfg_data,
		    struct idpf_ctlq_msg *ctlq_msg);

void
icpf_prep_sem_rule_blob(const u8 *key,
			u8 key_byte_len,
			const u8 *act_bytes,
			u8 act_byte_len,
			u16 cfg_ctrl,
			union icpf_rule_cfg_pkt_record *rule_blob);

#endif /* _ICPF_RULES_API_H_ */

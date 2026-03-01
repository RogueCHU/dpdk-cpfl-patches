/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#include <base/idpf_controlq.h>
#include "icpf_rules.h"

 /**
  * icpf_prep_rule_desc_common_ctx - get bit common context for descriptor
  * @cmn_cfg: pointer to icpf_rule_cfg_data_common structure as input
  * return: a 64bit context value to be inserted to control descriptor
  */
static inline u64
icpf_prep_rule_desc_common_ctx(struct icpf_rule_cfg_data_common *cmn_cfg)
{
	u64 context = 0;

	switch (cmn_cfg->opc) {
	case icpf_ctlq_mod_query_rule:
	case icpf_ctlq_mod_add_update_rule:
		context |= SHIFT_VAL64(cmn_cfg->vsi_id,
				       MEV_RULE_VSI_ID);
		/* fall through */
	case icpf_ctlq_sem_query_rule_hash_addr:
	case icpf_ctlq_sem_query_del_rule_hash_addr:
	case icpf_ctlq_sem_add_rule:
	case icpf_ctlq_sem_del_rule:
	case icpf_ctlq_sem_query_rule:
	case icpf_ctlq_sem_update_rule:
		context |= SHIFT_VAL64(cmn_cfg->time_sel,
				       MEV_RULE_TIME_SEL);
		context |= SHIFT_VAL64(cmn_cfg->time_sel_val,
				       MEV_RULE_TIME_SEL_VAL);
		break;
	default:
		break;
	}

	return context;
}

/**
 * icpf_prep_rule_desc_ctx - get bit context for descriptor
 * @cfg_data: pointer to icpf_rule_cfg_data structure as input
 * return: a 64bit context value to be inserted to control descriptor
 */
static inline u64
icpf_prep_rule_desc_ctx(struct icpf_rule_cfg_data *cfg_data)
{
	u64 context = 0;

	context |= icpf_prep_rule_desc_common_ctx(&cfg_data->common);

	switch (cfg_data->common.opc) {
	case icpf_ctlq_mod_query_rule:
	case icpf_ctlq_mod_add_update_rule:
		context |= SHIFT_VAL64(cfg_data->ext.mod_content.obj_size,
				       MEV_RULE_MOD_OBJ_SIZE);
		context |= SHIFT_VAL64(cfg_data->ext.mod_content.pin_content,
				       MEV_RULE_PIN_MOD_CONTENT);
		context |= SHIFT_VAL64(cfg_data->ext.mod_content.index,
				       MEV_RULE_MOD_INDEX);
		break;
	case icpf_ctlq_sem_query_rule_hash_addr:
	case icpf_ctlq_sem_query_del_rule_hash_addr:
		context |= SHIFT_VAL64(cfg_data->ext.query_del_addr.obj_id,
				       MEV_RULE_OBJ_ID);
		context |= SHIFT_VAL64(cfg_data->ext.query_del_addr.obj_addr,
				       MEV_RULE_OBJ_ADDR);
		break;
	default:
		break;
	}

	return context;
}

/**
 * icpf_prep_rule_desc - build descriptor data from rule config data
 * @cfg_data: pointer to icpf_rule_cfg_data structure as input
 * @ctlq_msg: pointer to idpf_ctlq_msg structure as output
 *
 * note: call this function before sending rule to HW via fast path
 */
void
icpf_prep_rule_desc(struct icpf_rule_cfg_data *cfg_data,
		    struct idpf_ctlq_msg *ctlq_msg)
{
	u64 context;
	u64 *ctlq_ctx = (u64 *)&ctlq_msg->ctx.indirect.context[0];

	context = icpf_prep_rule_desc_ctx(cfg_data);
	*ctlq_ctx = CPU_TO_LE64(context);

	ctlq_msg->cookie.cfg.data = cfg_data->common.cookie;
	ctlq_msg->opcode = (u16)cfg_data->common.opc;
	ctlq_msg->data_len = cfg_data->common.buf_len;
	ctlq_msg->status = 0;
	ctlq_msg->ctx.indirect.payload = cfg_data->common.payload;
}

/**
 * icpf_prep_sem_rule_blob - build SEM rule blob data from rule entry info
 * @key: key for rule entry
 * @key_byte_len: the length of key in bytes
 * @act_sets: an array of action sets in bytes
 * @act_byte_len: the byte length of action sets
 * @cfg_ctrl: config control (see definition of lem(sem)_rule_cfg_pkt)
 * @ctrl_word: control word (see definition of lem(sem)_rule_cfg_pkt)
 * @rule_blob: pointer to the DMA memory of rule config record as output
 *
 * note: call this function before sending rule to HW via fast path
 */
void
icpf_prep_sem_rule_blob(const u8 *key,
			u8 key_byte_len,
			const u8 *act_bytes,
			u8 act_byte_len,
			u16 cfg_ctrl,
			union icpf_rule_cfg_pkt_record *rule_blob)
{
	u32 *act_dst = (u32 *)&rule_blob->sem_rule.actions;
	const u32 *act_src = (const u32 *)act_bytes;
	u32 i;

	idpf_memset(rule_blob, 0, sizeof(*rule_blob), IDPF_DMA_MEM);
	idpf_memcpy(rule_blob->sem_rule.key, key, key_byte_len,
		    ICPF_NONDMA_TO_DMA);

	for (i = 0; i < act_byte_len / sizeof(u32); i++)
		*act_dst++ = CPU_TO_LE32(*act_src++);

	*((u16 *)&rule_blob->sem_rule.cfg_ctrl) = CPU_TO_LE16(cfg_ctrl);
}

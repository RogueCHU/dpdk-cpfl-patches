/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _CPFL_FXP_RULE_H_
#define _CPFL_FXP_RULE_H_

#include "icpf_rules.h"

#define CPFL_MAX_KEY_LEN 128
#define CPFL_MAX_RULE_ACTIONS 32

struct cpfl_sem_rule_info {
	uint16_t prof_id;
	uint8_t sub_prof_id;
	uint8_t key[CPFL_MAX_KEY_LEN];
	uint8_t key_byte_len;
	uint8_t pin_to_cache;
	uint8_t fixed_fetch;
};

#define CPFL_MAX_MOD_CONTENT_LEN 256
struct cpfl_mod_rule_info {
	uint8_t mod_content[CPFL_MAX_MOD_CONTENT_LEN];
	uint8_t mod_content_byte_len;
	uint32_t mod_index;
	uint8_t pin_mod_content;
	uint8_t mod_obj_size;
};

enum cpfl_rule_type {
	CPFL_RULE_TYPE_NONE,
	CPFL_RULE_TYPE_SEM,
	CPFL_RULE_TYPE_MOD
};

struct cpfl_rule_info {
	enum cpfl_rule_type type;
	uint64_t cookie;
	uint8_t host_id;
	uint8_t port_num;
	uint8_t resp_req;
	/* TODO: change this to be dynamically allocated/reallocated */
	uint8_t act_bytes[CPFL_MAX_RULE_ACTIONS * sizeof(union icpf_action_set)];
	uint8_t act_byte_len;
	/* vsi is used for lem and lpm rules */
	uint16_t vsi;
	/* mod related fields */
	union {
		struct cpfl_mod_rule_info mod;
		struct cpfl_sem_rule_info sem;
	};
};

int cpfl_rule_update(struct idpf_hw *hw, struct idpf_ctlq_info *cq,
		     struct cpfl_rule_info *rinfo, int rule_num, bool add);
#endif /*CPFL_FXP_RULE_H*/

/* SPDX-Lcpflnse-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <stdbool.h>
#include <rte_flow.h>
#include <json-c/json.h>
#include "cpfl_ethdev.h"
#include "cpfl_flow_fxp_metadata.h"

#ifndef _CPFL_FLOW_PARSER_H_
#define _CPFL_FLOW_PARSER_H_

#define MAX_LENGTH 20
/* Version Information Begin */
struct cpfl_js_version {
	struct {
		char version[MAX_LENGTH];
		bool ignore;
	} spec;
	struct {
		uint8_t version;
		bool ignore;
	} dpdk;
	struct {
		char version[MAX_LENGTH];
		const char *name;
		bool ignore;
	} package;
};

/* Version Information End */

/* Pattern Rules Begin */
enum cpfl_js_pr_action_type {
	CPFL_JS_PR_ACTION_TYPE_SEM,
	CPFL_JS_PR_ACTION_TYPE_LEM,
	CPFL_JS_PR_ACTION_TYPE_WCM,
	CPFL_JS_VPORT_END = -1
};

#define CPFL_MAX_SEM_FV_KEY_SIZE 64

struct cpfl_js_pr_action_sem {
	uint16_t prof;
	uint16_t subprof;
	uint16_t keysize;
	uint8_t cpfl_js_pr_fv[CPFL_MAX_SEM_FV_KEY_SIZE];
};

#define CPFL_MAX_LEM_FV_KEY_SIZE 64

struct cpfl_js_pr_action_lem {
	uint16_t prof;
	uint16_t keysize;
	uint8_t cpfl_js_pr_fv[CPFL_MAX_LEM_FV_KEY_SIZE];
};

#define CPFL_MAX_WCM_FV_KEY_SIZE 40
#define CPFL_WCM_RAM_BANK_NUM 8

struct cpfl_js_pr_action_wcm {
	uint16_t prof;
	uint8_t config;
	uint16_t entry_index;
	uint8_t slice_start;
	uint8_t slice_count;
	uint16_t entry_start;
	uint16_t entry_count;
	uint16_t act_rams_mask[CPFL_WCM_RAM_BANK_NUM];
	uint8_t fv[CPFL_MAX_WCM_FV_KEY_SIZE];
	uint8_t msk[CPFL_MAX_WCM_FV_KEY_SIZE];
};

struct cpfl_js_pr_action {
	enum cpfl_js_pr_action_type type;
	union {
		struct cpfl_js_pr_action_sem sem;
		struct cpfl_js_pr_action_lem lem;
		struct cpfl_js_pr_action_wcm wcm;
	};
};

struct cpfl_batch_item {
	bool batch_rule_valid;
	uint16_t offset;
	uint16_t v_offset;
	uint16_t v_mask;
	uint32_t num;
	enum rte_flow_item_type type;
	const struct rte_flow_item *item;
	union {
		uint32_t num32;
		uint16_t num16;
	} start;
	union {
		uint32_t num32;
		uint16_t num16;
	} end;
};

/* Pattern Rules End */

/* Modification Rules Begin */

struct cpfl_js_mr_key_action_vxlan_encap {
	const char *protocols[MAX_LENGTH];
	uint16_t proto_size;
};

struct cpfl_js_mr_key_action_vxlan_decap {
};

enum cpfl_js_mr_key_action_modify_field_op {
	SET,
	ADD,
	SUB
};

struct cpfl_js_mr_key_action_modify_field {
	enum rte_flow_modify_op op;
	struct {
		enum rte_flow_field_id type;
		uint32_t level;
		uint32_t offset;
	} src;
	struct {
		enum rte_flow_field_id type;
		uint32_t level;
		uint32_t offset;
	} dst;

	uint32_t width;
};

struct cpfl_js_mr_key_action {
	enum rte_flow_action_type type;
	union {
		struct cpfl_js_mr_key_action_vxlan_encap encap;
		struct cpfl_js_mr_key_action_vxlan_decap decap;
		struct cpfl_js_mr_key_action_modify_field field;
	};
};

struct cpfl_js_mr_action_mod {
	uint16_t prof;
	uint16_t byte_len;
	uint8_t data[256];
};

struct cpfl_js_mr_action_mod_meta {
	uint16_t prof;
};

enum cpfl_js_mr_action_type {
	CPFL_JS_MR_ACTION_TYPE_MOD,
	CPFL_JS_MR_ACTION_TYPE_MOD_META
};

struct cpfl_js_mr_action {
	enum cpfl_js_mr_action_type type;
	union {
		struct cpfl_js_mr_action_mod mod;
		struct cpfl_js_mr_action_mod_meta mod_meta;
	};
};

/* Modification Rules End */

/* Metadata Begin */
struct cpfl_js_metadatas_info {
	uint8_t type;
	uint8_t start;
	uint8_t width;
};

/* Metadata End */

struct cpfl_js_flow_parser {
	struct cpfl_js_version version;
	json_object *json_root;
};

int cpfl_parse_actions(struct cpfl_js_flow_parser *parser, const struct rte_flow_action *actions,
		       struct cpfl_js_mr_action *mr_action);
int cpfl_parse_items_attr(struct cpfl_js_flow_parser *parser, const struct rte_flow_item *items,
			  const struct rte_flow_attr *attr, struct cpfl_itf *itf,
			  struct cpfl_js_pr_action *pr_action, struct cpfl_batch_item *range);
int cpfl_parser_create(struct cpfl_js_flow_parser **flow_parser, const char *filename);
int cpfl_parser_destroy(struct cpfl_js_flow_parser *parser);
int cpfl_parse_vport_rules(struct cpfl_js_flow_parser *parser, struct cpfl_itf *itf,
			   struct cpfl_js_pr_action *cpfl_vports); /* cpfl_vports is an array */
int cpfl_parse_metadatas(struct cpfl_js_flow_parser *parser,
			 int index,
			 struct cpfl_js_metadatas_info *md_info);

#endif

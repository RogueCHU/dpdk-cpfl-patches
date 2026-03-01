/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#ifndef _CPFL_TDI_JS_PARSER_H_
#define _CPFL_TDI_JS_PARSER_H_

#include <stdint.h>
#include <stdbool.h>

enum cpfl_tdi_table_type {
	CPFL_TDI_TABLE_TYPE_MATCH,
};

enum cpfl_tdi_table_dir {
	CPFL_TDI_TABLE_DIR_RX,
	CPFL_TDI_TABLE_DIR_TX,
	CPFL_TDI_TABLE_DIR_BI,
};

enum cpfl_tdi_match_type {
	CPFL_TDI_MATCH_TYPE_EXACT,
	CPFL_TDI_MATCH_TYPE_SELECTOR,
};

enum cpfl_tdi_byte_order {
	CPFL_TDI_BYTE_ORDER_HOST,
	CPFL_TDI_BYTE_ORDER_NETWORK,
};

#define CPFL_TDI_NAME_SIZE_MAX 80

struct cpfl_tdi_match_key_format {
	uint32_t match_key_handle;
	enum cpfl_tdi_byte_order byte_order;
	uint16_t byte_array_index;
	uint16_t start_bit_offset;
	uint16_t bit_width;
};

struct cpfl_tdi_match_key_field {
	const char *name;
	const char *instance_name;
	const char *field_name;
	enum cpfl_tdi_match_type match_type;
	uint16_t bit_width;
	uint32_t index;
	uint32_t position;
};

struct cpfl_tdi_p4_parameter {
	const char *name;
	uint16_t bit_width;
};

struct cpfl_tdi_action {
	const char *name;
	uint32_t handle;
	bool constant_default_action;
	bool is_compiler_added_action;
	bool allowed_as_hit_action;
	bool allowed_as_default_action;
	uint16_t p4_parameter_num;
	struct cpfl_tdi_p4_parameter *p4_parameters;
};

struct cpfl_tdi_immediate_field {
	const char *param_name;
	uint32_t param_handle;
	uint16_t dest_start;
	uint16_t start_bit_offset;
	uint16_t dest_width;
};

enum cpfl_tdi_mod_field_type {
	CPFL_TDI_MOD_FIELD_TYPE_PARAMETER,
	CPFL_TDI_MOD_FIELD_TYPE_CONSTANT,
};

#define CPFL_TDI_VALUE_SIZE_MAX 16

struct cpfl_tdi_mod_field {
	const char *name;
	uint32_t handle;
	uint32_t param_handle;
	enum cpfl_tdi_mod_field_type type;
	enum cpfl_tdi_byte_order byte_order;
	uint16_t byte_array_index;
	uint16_t start_bit_offset;
	uint16_t bit_width;
	uint16_t value_size;
	uint8_t value[CPFL_TDI_VALUE_SIZE_MAX];
};

struct cpfl_tdi_mod_content_format {
	uint16_t mod_profile;
	uint16_t mod_obj_size;
	uint16_t mod_field_num;
	struct cpfl_tdi_mod_field *mod_fields;
};

struct cpfl_tdi_hw_action_parameter {
	const char *param_name;
	uint32_t param_handle;
};

enum cpfl_tdi_action_code {
	CPFL_TDI_ACTION_CODE_NONE,
	CPFL_TDI_ACTION_CODE_SET10_1b,
	CPFL_TDI_ACTION_CODE_SET1_16b,
	CPFL_TDI_ACTION_CODE_SET1A_24b,
	CPFL_TDI_ACTION_CODE_SET1B_24b,
};

enum cpfl_tdi_setmd_action_code {
	CPFL_TDI_SETMD_ACTION_CODE_NONE,
	CPFL_TDI_SETMD_ACTION_CODE_SET_8b,
	CPFL_TDI_SETMD_ACTION_CODE_SET_16b,
};

struct cpfl_tdi_hw_action {
	uint16_t prec;
	enum cpfl_tdi_action_code action_code;
	enum cpfl_tdi_setmd_action_code setmd_action_code;
	uint16_t index;
	uint16_t mod_profile;
	uint16_t prefetch;
	uint16_t parameter_num;
	struct cpfl_tdi_hw_action_parameter *parameters;
	uint32_t p4_ref_action_handle;
	uint32_t p4_ref_table_handle;
	uint16_t value;
	uint16_t mask;
	uint16_t type_id;
	uint16_t offset;
};

struct cpfl_tdi_action_format {
	const char *action_name;
	uint32_t action_handle;
	uint16_t immediate_field_num;
	struct cpfl_tdi_immediate_field *immediate_fields;
	struct cpfl_tdi_mod_content_format mod_content_format;
	uint16_t hw_action_num;
	struct cpfl_tdi_hw_action *hw_actions_list;
};

enum cpfl_tdi_hw_block {
	CPFL_TDI_HW_BLOCK_SEM,
	CPFL_TDI_HW_BLOCK_LEM,
	CPFL_TDI_HW_BLOCK_WCM,
	CPFL_TDI_HW_BLOCK_MOD,
	CPFL_TDI_HW_BLOCK_HASH,
	CPFL_TDI_HW_BLOCK_RC,
};

struct cpfl_tdi_wcm_params {
	uint16_t wcm_group;
	uint16_t slice_start_idx;
	uint16_t table_width;
	uint16_t entry_cnt;
	uint16_t entry_idx;
	uint8_t act_rams[16];
};

struct cpfl_tdi_hardware_block {
	enum cpfl_tdi_hw_block hw_block;
	uint32_t id;
	const char *hw_interface;
	uint16_t profile_num;
	uint16_t profile[4];
	uint16_t action_format_num;
	struct cpfl_tdi_action_format *action_format;
	union {
		struct {
			uint16_t sub_profile;
			uint32_t obj_id;
		} sem;
		struct {
			struct cpfl_tdi_wcm_params wcm_params;
		} wcm;
		struct {
			const char *hw_resource;
			uint32_t hw_resource_id;
		} mod;
	};
};

struct cpfl_tdi_match_attributes {
	uint16_t hardware_block_num;
	struct cpfl_tdi_hardware_block *hardware_blocks;
};

struct cpfl_tdi_table {
	enum cpfl_tdi_table_type table_type;
	enum cpfl_tdi_table_dir direction;
	uint32_t handle;
	const char *name;
	bool add_on_miss;
	bool idle_timeout_with_auto_delete;
	uint16_t match_key_field_num;
	struct cpfl_tdi_match_key_field *match_key_fields;
	uint16_t match_key_format_num;
	struct cpfl_tdi_match_key_format *match_key_format;
	uint32_t default_action_handle;
	uint16_t action_num;
	struct cpfl_tdi_action *actions;
	struct cpfl_tdi_match_attributes match_attributes;
};

struct cpfl_tdi_hash_space_cfg {
	uint32_t base_128_entries;
	uint32_t base_256_entries;
};

struct cpfl_tdi_rc_entry_space_cfg {
	uint32_t rc_num_banks;
	uint32_t rc_num_entries;
};

struct cpfl_tdi_gc_hardware_block {
	enum cpfl_tdi_hw_block hw_block;
	union {
		struct cpfl_tdi_hash_space_cfg hash_space_cfg;
		struct cpfl_tdi_rc_entry_space_cfg rc_entry_space_cfg;
	};
};

struct cpfl_tdi_global_configs {
	uint16_t hardware_block_num;
	struct cpfl_tdi_gc_hardware_block *hardware_blocks;
};

struct cpfl_tdi_program {
	const char *program_name;
	const char *build_date;
	const char *compile_command;
	const char *compiler_version;
	const char *schema_version;
	const char *target;
	struct cpfl_tdi_global_configs global_configs;
	uint16_t table_num;
	struct cpfl_tdi_table *tables;
};

int cpfl_tdi_program_create(struct cpfl_tdi_program **program, const char *filename);
int cpfl_tdi_program_destroy(struct cpfl_tdi_program *program);

#endif

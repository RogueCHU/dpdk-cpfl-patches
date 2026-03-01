/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#ifndef _CPFL_TDI_H_
#define _CPFL_TDI_H_

#include <rte_tdi_driver.h>
#include "cpfl_ethdev.h"
#include "cpfl_tdi_js_parser.h"

struct cpfl_tdi_param_info {
	uint32_t id;
	uint16_t offset;
	uint16_t size;
};

#define CPFL_TDI_TABLE_KEY_FIELD_MAX 32

struct cpfl_tdi_table_node {
	TAILQ_ENTRY(cpfl_tdi_table_node) next;
	const struct cpfl_tdi_table *table;
	struct cpfl_tdi_action_node **actions;
	uint16_t buf_len;
	struct cpfl_tdi_param_info params[CPFL_TDI_TABLE_KEY_FIELD_MAX];
};

#define CPFL_TDI_ACTION_PARAMETER_NUM_MAX 16
#define CPFL_TDI_ACTION_BUF_SIZE_MAX 256

struct cpfl_tdi_action_node {
	TAILQ_ENTRY(cpfl_tdi_action_node) next;
	const struct cpfl_tdi_action *action;
	const struct cpfl_tdi_action_format *format;
	uint32_t buf_len;
	struct cpfl_tdi_param_info params[CPFL_TDI_ACTION_PARAMETER_NUM_MAX];
	uint8_t init_buf[CPFL_TDI_ACTION_BUF_SIZE_MAX];
	uint8_t query_msk[CPFL_TDI_ACTION_BUF_SIZE_MAX];
};

extern const struct rte_tdi_ops cpfl_tdi_ops;

int cpfl_tdi_init(struct cpfl_adapter_ext *ad);
int cpfl_tdi_uninit(struct cpfl_adapter_ext *ad);

#endif

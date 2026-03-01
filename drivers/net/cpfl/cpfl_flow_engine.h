/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _CPFL_FLOW_ENGINE_H_
#define _CPFL_FLOW_ENGINE_H_

#include <rte_flow.h>
#include "cpfl_ethdev.h"

enum cpfl_flow_engine_type {
	CPFL_FLOW_ENGINE_NONE = 0,
	CPFL_FLOW_ENGINE_FXP,
};

typedef int (*engine_init_t)(struct cpfl_adapter_ext *ad);
typedef void (*engine_uninit_t)(struct cpfl_adapter_ext *ad);
typedef int (*engine_create_t)(struct cpfl_vport_ext *vport,
			       struct rte_flow *flow,
			       void *meta,
			       struct rte_flow_error *error);
typedef int (*engine_destroy_t)(struct cpfl_vport_ext *vport,
			        struct rte_flow *flow,
			        struct rte_flow_error *error);
typedef int (*engine_query_t)(struct cpfl_vport_ext *vport,
			      struct rte_flow *flow,
			      struct rte_flow_query_count *count,
			      struct rte_flow_error *error);
typedef void (*engine_free_t) (struct rte_flow *flow);
typedef int (*engine_parse_pattern_action_t)(struct cpfl_vport_ext *vport,
					     const struct rte_flow_attr *attr,
					     const struct rte_flow_item pattern[],
					     const struct rte_flow_action actions[],
					     void **meta);

struct cpfl_flow_engine {
	TAILQ_ENTRY(cpfl_flow_engine) node;
	enum cpfl_flow_engine_type type;
	engine_init_t init;
	engine_uninit_t uninit;
	engine_create_t create;
	engine_destroy_t destroy;
	engine_query_t query_count;
	engine_free_t free;
	engine_parse_pattern_action_t parse_pattern_action;
};

void cpfl_flow_engine_register(struct cpfl_flow_engine *engine);

struct cpfl_flow_engine *
cpfl_flow_engine_match(struct cpfl_vport_ext *vport,
		       const struct rte_flow_attr *attr,
		       const struct rte_flow_item pattern[],
		       const struct rte_flow_action actions[],
		       void **meta);
int
cpfl_flow_engine_init(struct cpfl_adapter_ext *adapter);
void
cpfl_flow_engine_uninit(struct cpfl_adapter_ext *adapter);
#endif

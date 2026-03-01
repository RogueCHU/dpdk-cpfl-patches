/* SPDX-Lidpfnse-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _CPFL_FLOW_H_
#define _CPFL_FLOW_H_

#include "cpfl_ethdev.h"
#include "cpfl_flow_engine.h"
#ifdef RTE_FLOW_SHIM
#include <rte_flow_shim_flow.h>
#endif

extern const struct rte_flow_ops cpfl_flow_ops;
#ifdef RTE_FLOW_SHIM
extern struct rte_flow_ops shim_flow_ops;
#endif

struct rte_flow {
	TAILQ_ENTRY(rte_flow) next;
	struct cpfl_flow_engine *engine;
#ifdef RTE_FLOW_SHIM
    struct shim_table_data p4_table_data;
#endif
	void *rule;
};

int cpfl_flow_init(struct cpfl_adapter_ext *ad);
void cpfl_flow_uninit(struct cpfl_adapter_ext *ad);

#endif

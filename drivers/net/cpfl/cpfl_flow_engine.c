/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <rte_tailq.h>

#include "cpfl_flow_engine.h"

TAILQ_HEAD(cpfl_flow_engine_list, cpfl_flow_engine);

static struct cpfl_flow_engine_list engine_list = TAILQ_HEAD_INITIALIZER(engine_list);

void
cpfl_flow_engine_register(struct cpfl_flow_engine *engine)
{
	TAILQ_INSERT_TAIL(&engine_list, engine, node);
}

struct cpfl_flow_engine *
cpfl_flow_engine_match(struct cpfl_vport_ext *vport,
		       const struct rte_flow_attr *attr,
		       const struct rte_flow_item pattern[],
		       const struct rte_flow_action actions[],
		       void **meta)
{
	struct cpfl_flow_engine *engine = NULL;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(engine, &engine_list, node, temp) {
		if (engine->parse_pattern_action(vport, attr, pattern, actions, meta) < 0)
			continue;
		return engine;
	}

	return NULL;
}

int
cpfl_flow_engine_init(struct cpfl_adapter_ext *adapter)
{
	struct cpfl_flow_engine *engine = NULL;
	void *temp;
	int ret;

	RTE_TAILQ_FOREACH_SAFE(engine, &engine_list, node, temp) {
		if (!engine->init) {
			PMD_INIT_LOG(ERR, "Invalid engine type (%d)",
				     engine->type);
			return -ENOTSUP;
		}

		ret = engine->init(adapter);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to initialize engine %d",
				     engine->type);
			return ret;
		}
	}

	return 0;
}

void
cpfl_flow_engine_uninit(struct cpfl_adapter_ext *adapter)
{
	struct cpfl_flow_engine *engine = NULL;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(engine, &engine_list, node, temp) {
		if (engine->uninit)
			engine->uninit(adapter);
	}
}

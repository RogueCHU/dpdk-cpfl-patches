/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eth_ctrl.h>
#include <rte_tailq.h>
#include <rte_flow_driver.h>
#include <rte_flow.h>
#include <rte_bitmap.h>
#include "icpf_rules.h"
#include "cpfl_logs.h"
#include "cpfl_ethdev.h"
#include "cpfl_flow.h"
#include "cpfl_fxp_rule.h"
#include "cpfl_flow_js_parser.h"
#include "cpfl_flow_engine.h"

#define COOKIE_DEF	0x1000
#define PREC_DEF	1
#define PREC_SET	5
#define TYPE_ID		3
#define OFFSET		0x0a
#define HOST_ID_DEF	0
#define PF_NUM_DEF	0
#define PORT_NUM_DEF	0
#define RESP_REQ_DEF	2
#define PIN_TO_CACHE_DEF	0
#define CLEAR_MIRROR_1ST_STATE_DEF  0
#define FIXED_FETCH_DEF 0
#define PTI_DEF		0
#define PREFETCH_DEF	2
#define MOD_OBJ_SIZE_DEF	0
#define PIN_MOD_CONTENT_DEF	0

#define MAX_MOD_CONTENT_INDEX	256

static uint32_t fxp_mod_idx_alloc(struct cpfl_adapter_ext *ad);
static void fxp_mod_idx_free(struct cpfl_adapter_ext *ad, uint32_t idx);

uint64_t rule_cookie = COOKIE_DEF;
struct rule_info_meta {
	uint32_t rule_num;
	uint32_t pr_num;
	uint32_t mr_num;
	struct cpfl_rule_info rules[0];
};

static int
cpfl_fxp_create(struct cpfl_vport_ext *vport,
		struct rte_flow *flow,
		void *meta,
		struct rte_flow_error *error)
{
	int ret = 0;
	uint32_t cpq_id = 0;
	struct cpfl_adapter_ext *ad = vport->itf.adapter;
	struct idpf_hw *hw = (void *)&(ad->base.hw);
	struct rule_info_meta *rim = meta;

	cpq_id = vport->base.devarg_id * 2;

	ret = cpfl_rule_update(hw, ad->ctlqp[cpq_id], rim->rules,
			       rim->rule_num, true);

	if (!ret) {
		flow->rule = rim;
	} else {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "cpfl filter create flow fail");
		goto error;
	}

error:
	return ret;
}

static inline void
cpfl_fxp_rule_free(struct rte_flow *flow)
{
	rte_free(flow->rule);
	flow->rule = NULL;
}

static int
cpfl_fxp_destroy(struct cpfl_vport_ext *vport,
		 struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	int ret;
	uint32_t cpq_id = 0;
	struct cpfl_adapter_ext *ad = vport->itf.adapter;
	struct idpf_hw *hw = (void *)&ad->base.hw;
	struct rule_info_meta *rim;
	uint32_t i;

	rim = flow->rule;

	if (!rim) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "no such flow create by cpfl filter");

		cpfl_fxp_rule_free(flow);

		return -rte_errno;
	}

	cpq_id = vport->base.devarg_id * 2;

	ret = cpfl_rule_update(hw, ad->ctlqp[cpq_id], rim->rules, rim->pr_num, false);
	if (ret) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "fail to destroy cpfl filter rule");
		return -rte_errno;
	}

	/* free mod index */
	for (i = rim->pr_num; i < rim->rule_num; i++)
		fxp_mod_idx_free(ad, rim->rules[i].mod.mod_index);

	cpfl_fxp_rule_free(flow);

	return ret;
}

static bool
cpfl_fxp_parse_pattern(const struct cpfl_js_pr_action *pr_action,
		       struct rule_info_meta *rim,
		       int i)
{
	if (pr_action->type == CPFL_JS_PR_ACTION_TYPE_SEM) {
		struct cpfl_rule_info *rinfo = &rim->rules[i];

		rinfo->type = CPFL_RULE_TYPE_SEM;
		rinfo->sem.prof_id = pr_action->sem.prof;
		rinfo->sem.sub_prof_id = pr_action->sem.subprof;
		rinfo->sem.key_byte_len = pr_action->sem.keysize;
		rte_memcpy(rinfo->sem.key, pr_action->sem.cpfl_js_pr_fv, rinfo->sem.key_byte_len);
		rinfo->sem.pin_to_cache = PIN_TO_CACHE_DEF;
		rinfo->sem.fixed_fetch = FIXED_FETCH_DEF;
	} else {
		PMD_DRV_LOG(ERR, "Invalid pattern item.");
		return false;
	}

	return true;
}

static int
cpfl_parse_mod_content(struct cpfl_adapter_ext *adapter,
		       struct cpfl_rule_info *match_rinfo,
		       struct cpfl_rule_info *mod_rinfo,
		       const struct cpfl_js_mr_action *mr_action)
{
	struct cpfl_mod_rule_info *minfo = &mod_rinfo->mod;
	uint32_t mod_idx;
	int i;
	int next = match_rinfo->act_byte_len / (sizeof(union icpf_action_set));
	union icpf_action_set *act_set =
		&((union icpf_action_set *)match_rinfo->act_bytes)[next];

	if (!mr_action || mr_action->type != CPFL_JS_MR_ACTION_TYPE_MOD)
		return -EINVAL;

	*act_set = icpf_act_mod_profile(PREC_DEF,
					mr_action->mod.prof,
					PTI_DEF,
					0, /* append */
					0, /* prepend */
					PREFETCH_DEF);

	act_set++;
	match_rinfo->act_byte_len += sizeof(union icpf_action_set);

	mod_idx = fxp_mod_idx_alloc(adapter);
	if (mod_idx == MAX_MOD_CONTENT_INDEX) {
		PMD_DRV_LOG(ERR, "Out of Mod Index.");
		return -ENOMEM;
	}

	*act_set = icpf_act_mod_addr(PREC_DEF, mod_idx);

	act_set++;
	match_rinfo->act_byte_len += sizeof(union icpf_action_set);

	mod_rinfo->type = CPFL_RULE_TYPE_MOD;
	minfo->mod_obj_size = MOD_OBJ_SIZE_DEF;
	minfo->pin_mod_content = PIN_MOD_CONTENT_DEF;
	minfo->mod_index = mod_idx;
	mod_rinfo->cookie = 0x1237561;
	mod_rinfo->port_num = PORT_NUM_DEF;
	mod_rinfo->resp_req = RESP_REQ_DEF;

	minfo->mod_content_byte_len = mr_action->mod.byte_len + 2;
	for (i = 0; i < minfo->mod_content_byte_len; i++)
		minfo->mod_content[i] = mr_action->mod.data[i];

	return 0;
}

static int
cpfl_fxp_parse_action(struct cpfl_itf *itf,
		      const struct rte_flow_action *actions,
		      const struct cpfl_js_mr_action *mr_action,
		      struct rule_info_meta *rim,
		      int priority,
		      uint32_t egress,
		      int index,
		      bool is_vport_rule)
{
	const struct rte_flow_action_ethdev *act_ethdev;
	const struct rte_flow_item_meta *act_meta;
	const struct rte_flow_action *action;
	const struct rte_flow_action_queue *act_q;
	const struct rte_flow_action_rss *rss;
	struct rte_eth_dev_data *data;
	enum rte_flow_action_type action_type;
	struct cpfl_vport_ext *vport;
	/* used when action is REPRESENTED_PORT or REPRESENTED_PORT type */
	struct cpfl_itf *dst_itf;
	uint16_t dev_id; /*vsi_id or phyical port id*/
	bool is_vsi;
	int queue_id = -1;
	bool fwd_vsi = false;
	bool fwd_q = false;
	uint32_t i;
	struct cpfl_rule_info *rinfo = &rim->rules[index];
	union icpf_action_set *act_set = (void *)rinfo->act_bytes;

	if (priority == 0)
		priority = PREC_DEF;
	for (action = actions; action->type !=
			RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			if (!fwd_vsi)
				fwd_vsi = true;
			else
				goto err;
			if (is_vport_rule) {
				dst_itf = itf;
			} else {
				act_ethdev = action->conf;
				dst_itf = cpfl_get_itf_by_port_id(act_ethdev->port_id);
			}

			if (dst_itf == NULL)
				goto err;

			if (dst_itf->type == CPFL_ITF_TYPE_VPORT) {
				vport = (struct cpfl_vport_ext *)dst_itf;
				queue_id = vport->base.chunks_info.rx_start_qid;
			} else {
				queue_id = -2;
			}

			is_vsi = (action_type == RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR ||
				dst_itf->type == CPFL_ITF_TYPE_REPRESENTOR);
			if (is_vsi || is_vport_rule)
				dev_id = cpfl_get_vsi_id(dst_itf);
			else
				dev_id = cpfl_get_port_id(dst_itf);

			if (dev_id == CPFL_INVALID_HW_ID)
				goto err;

			if (is_vsi || is_vport_rule)
				*act_set = icpf_act_fwd_vsi(0, priority, 0, dev_id);
			else
				*act_set = icpf_act_fwd_port(0, priority, 0, dev_id);
			act_set++;
			rinfo->act_byte_len += sizeof(union icpf_action_set);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_META:
			act_meta = action->conf;
			*act_set = icpf_act_set_md16(0, PREC_SET, TYPE_ID, OFFSET,
					act_meta->data);
			act_set++;
			rinfo->act_byte_len +=
				sizeof(union icpf_action_set);
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			if (!fwd_q)
				fwd_q = true;
			else
				goto err;
			if (queue_id == -2)
				goto err;
			act_q = action->conf;
			data = itf->data;
			if (act_q->index >= data->nb_rx_queues)
				goto err;

			vport = (struct cpfl_vport_ext *)itf;
			if (queue_id < 0)
				queue_id = vport->base.chunks_info.rx_start_qid;
			queue_id += act_q->index;
			*act_set = icpf_act_set_hash_queue(priority, 0, queue_id, 0);
			act_set++;
			rinfo->act_byte_len += sizeof(union icpf_action_set);
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss = action->conf;
			if (rss->queue_num <= 1)
				goto err;
			for (i = 0; i < rss->queue_num - 1; i++) {
				if (rss->queue[i + 1] != rss->queue[i] + 1)
					goto err;
			}
			data = itf->data;
			if (rss->queue[rss->queue_num - 1] >= data->nb_rx_queues)
				goto err;
#define FXP_MAX_QREGION_SIZE 128
			if (!(rte_is_power_of_2(rss->queue_num) &&
			      rss->queue_num <= FXP_MAX_QREGION_SIZE))
				goto err;

			if (!fwd_q)
				fwd_q = true;
			else
				goto err;
			if (queue_id == -2)
				goto err;
			vport = (struct cpfl_vport_ext *)itf;
			if (queue_id < 0)
				queue_id = vport->base.chunks_info.rx_start_qid;
			queue_id += rss->queue[0];
			*act_set = icpf_act_set_hash_queue_region(priority, 0, queue_id,
								  rss->queue_num, 0);
			act_set++;
			rinfo->act_byte_len += sizeof(union icpf_action_set);
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			(*act_set).data = icpf_act_drop(0x1).data;
			act_set++;
			rinfo->act_byte_len += sizeof(union icpf_action_set);
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
#define TX_BASE_TYPE_ID 0x02
#define L4_CSUM_MD_VALUE 0x02
#define L4_CSUM_MASK 0x02
			if (egress) {
				*act_set = icpf_act_set_md8(0, PREC_SET, TX_BASE_TYPE_ID, 0,
							    L4_CSUM_MD_VALUE, L4_CSUM_MASK);
				act_set++;
				rinfo->act_byte_len += sizeof(union icpf_action_set);
			}
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
			break;
		default:
			goto err;
		}
	}

	if (mr_action != NULL) {
		uint32_t i;

		for (i = 0; i < rim->mr_num; i++)
			if (cpfl_parse_mod_content(itf->adapter, rinfo,
						   &rim->rules[(1 + i) * rim->pr_num + index],
						   &mr_action[i]))
				goto err;
	}

	return 0;

err:
	PMD_DRV_LOG(ERR, "Invalid action type");
	return -EINVAL;
}

static void
cpfl_fill_rinfo_default_value(struct cpfl_rule_info *rinfo)
{
	if (rule_cookie == ~0llu)
		rule_cookie = COOKIE_DEF;
	rinfo->cookie = rule_cookie++;
	rinfo->host_id = HOST_ID_DEF;
	rinfo->port_num = PORT_NUM_DEF;
	rinfo->resp_req = RESP_REQ_DEF;
}

static bool is_mod_action(const struct rte_flow_action actions[])
{
	const struct rte_flow_action *action;
	enum rte_flow_action_type action_type;

	if (!actions || actions->type == RTE_FLOW_ACTION_TYPE_END)
		return false;

	for (action = actions; action->type !=
			RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			return true;
		default:
			continue;
		}
	}
	return false;
}

static bool
cpfl_fxp_get_metadata_port(struct cpfl_itf *itf,
			   const struct rte_flow_action actions[],
			   bool is_vport_rule)
{
	const struct rte_flow_action *action;
	enum rte_flow_action_type action_type;
	const struct rte_flow_action_ethdev *ethdev;
	struct cpfl_itf *target_itf;
	bool ret;

	if (itf->type == CPFL_ITF_TYPE_VPORT) {
		ret = cpfl_metadata_write_port_id(itf);
		if (!ret) {
			PMD_DRV_LOG(ERR, "fail to write port id");
			return false;
		}
	}

	ret = cpfl_metadata_write_sourcevsi(itf);
	if (!ret) {
		PMD_DRV_LOG(ERR, "fail to write source vsi id");
		return false;
	}

	ret = cpfl_metadata_write_vsi(itf);
	if (!ret) {
		PMD_DRV_LOG(ERR, "fail to write vsi id");
		return false;
	}

	if (!actions || actions->type == RTE_FLOW_ACTION_TYPE_END)
		return false;

	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			if (is_vport_rule) {
				target_itf = itf;
			} else {
				ethdev = (const struct rte_flow_action_ethdev *)action->conf;
				target_itf = cpfl_get_itf_by_port_id(ethdev->port_id);
				if (!target_itf) {
					PMD_DRV_LOG(ERR, "fail to get target_itf by port id");
					return false;
				}
			}
			ret = cpfl_metadata_write_targetvsi(target_itf);
			if (!ret) {
				PMD_DRV_LOG(ERR, "fail to write target vsi id");
				return false;
			}
			return true;
		default:
			continue;
		}
	}
	return false;
}

static int
cpfl_fxp_reset_fv(struct cpfl_js_pr_action *pr_action, struct cpfl_batch_item *range, uint32_t i)
{
	uint8_t *fv;
	uint32_t t;

	if (!pr_action)
		return -EINVAL;

	fv = pr_action->sem.cpfl_js_pr_fv;
	t = range->start.num32 + (uint32_t)i;
	if (t > range->end.num32)
		return -EINVAL;
	if (2 * range->offset > CPFL_MAX_LEM_FV_KEY_SIZE - 4)
		return -EINVAL;

	if (range->type == RTE_FLOW_ITEM_TYPE_IPV4) {
		fv[2 * range->offset] = (uint8_t)((t & 0xff000000) >> 24);
		fv[2 * range->offset + 1] = (uint8_t)((t & 0x00ff0000) >> 16);
		fv[2 * range->offset + 2] = (uint8_t)((t & 0x0000ff00) >> 8);
		fv[2 * range->offset + 3] = (uint8_t)(t & 0x000000ff);
	} else {
		fv[2 * range->offset] = (uint8_t)(((uint16_t)t & 0xff00) >> 8);
		fv[2 * range->offset + 1] = (uint8_t)((uint16_t)t & 0x00ff);
	}

	return 0;
}

static int
cpfl_fxp_parse_pattern_action(struct cpfl_vport_ext *vport,
			      const struct rte_flow_attr *attr,
			      const struct rte_flow_item pattern[],
			      const struct rte_flow_action actions[],
			      void **meta)
{
	struct cpfl_js_pr_action pr_action = { 0 };
	struct cpfl_adapter_ext *adapter = vport->itf.adapter;
#define MAX_MR_ACTION_NUM 8
	struct cpfl_js_mr_action mr_action[MAX_MR_ACTION_NUM] = { 0 };
	uint32_t rule_num = 0, pr_num = 0, mr_num = 0;
	struct cpfl_batch_item range;
	struct rule_info_meta *rim;
	uint32_t i;
	int ret;

	ret = cpfl_fxp_get_metadata_port(&vport->itf, actions, false);
	if (ret != 1) {
		PMD_DRV_LOG(ERR, "Fail to save metadata.");
		return -EINVAL;
	}

	range.batch_rule_valid = FALSE;
	ret = cpfl_parse_items_attr(adapter->flow_parser, pattern, attr,
				   &vport->itf, &pr_action, &range);

	if (ret != 1) {
		PMD_DRV_LOG(ERR, "No Match pattern support.");
		return -EINVAL;
	}

	if (is_mod_action(actions)) {
		ret = cpfl_parse_actions(adapter->flow_parser, actions, mr_action);
		if (ret != 1) {
			PMD_DRV_LOG(ERR, "action parse fails.");
			return -EINVAL;
		}
		/* TODO, cpfl_parse_actions should return an array of mr_action */
		mr_num++;
	}

	if (range.batch_rule_valid)
		pr_num = range.num;
	else
		pr_num = 1;

	rule_num = pr_num * (1 + mr_num);

	rim = rte_zmalloc(NULL, sizeof(struct rule_info_meta) +
			    rule_num * sizeof(struct cpfl_rule_info), 0);
	if (rim == NULL)
		return -ENOMEM;

	rim->rule_num = rule_num;
	rim->pr_num = pr_num;
	rim->mr_num = mr_num;

	for (i = 0; i < pr_num; i++) {
		if (range.batch_rule_valid) {
			if (cpfl_fxp_reset_fv(&pr_action, &range, i)) {
				PMD_DRV_LOG(ERR, "Invalid input set");
				rte_free(rim);
				return -rte_errno;
			}
		}

		if (!cpfl_fxp_parse_pattern(&pr_action, rim, i)) {
			PMD_DRV_LOG(ERR, "Invalid input set");
			rte_free(rim);
			return -rte_errno;
		}

		if (cpfl_fxp_parse_action(&vport->itf, actions, mr_action, rim, attr->priority,
					  attr->egress, i, false)) {
			PMD_DRV_LOG(ERR, "Invalid input set");
			rte_free(rim);
			return -rte_errno;
		}

		cpfl_fill_rinfo_default_value(&rim->rules[i]);
	}

	if (meta == NULL)
		rte_free(rim);
	else
		*meta = rim;

	return 0;
}

static int fxp_mod_init(struct cpfl_adapter_ext *ad)
{
	uint32_t size = rte_bitmap_get_memory_footprint(MAX_MOD_CONTENT_INDEX);

	void *mem = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

	if (mem == NULL)
		return -ENOMEM;

	/* a set bit represent a free slot */
	ad->mod_bm = rte_bitmap_init_with_all_set(MAX_MOD_CONTENT_INDEX, mem, size);
	if (ad->mod_bm == NULL) {
		rte_free(mem);
		return -EINVAL;
	}

	ad->mod_bm_mem = mem;

	return 0;
}

static void fxp_mod_uninit(struct cpfl_adapter_ext *ad)
{
	rte_free(ad->mod_bm_mem);
	ad->mod_bm_mem = NULL;
	ad->mod_bm = NULL;
}

static uint32_t fxp_mod_idx_alloc(struct cpfl_adapter_ext *ad)
{
	uint64_t slab = 0;
	uint32_t pos = 0;

	if (!rte_bitmap_scan(ad->mod_bm, &pos, &slab))
		return MAX_MOD_CONTENT_INDEX;

	pos += __builtin_ffsll(slab) - 1;
	rte_bitmap_clear(ad->mod_bm, pos);

	return pos;
}

static void fxp_mod_idx_free(struct cpfl_adapter_ext *ad, uint32_t idx)
{
	rte_bitmap_set(ad->mod_bm, idx);
}

static int
cpfl_fxp_query(struct cpfl_vport_ext *vport __rte_unused,
	       struct rte_flow *flow __rte_unused,
	       struct rte_flow_query_count *count __rte_unused,
	       struct rte_flow_error *error)
{
	rte_flow_error_set(error, EINVAL,
			   RTE_FLOW_ERROR_TYPE_HANDLE,
			   NULL,
			   "count action not supported by this module");

	return -rte_errno;
}

static void
cpfl_fxp_uninit(struct cpfl_adapter_ext *ad)
{
	fxp_mod_uninit(ad);
}

static int
cpfl_fxp_init(struct cpfl_adapter_ext *ad)
{
	int ret = 0;

	ret = fxp_mod_init(ad);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to init mod content bitmap.");
		return ret;
	}

	return ret;
}

static struct
cpfl_flow_engine cpfl_fxp_engine = {
	.type = CPFL_FLOW_ENGINE_FXP,
	.init = cpfl_fxp_init,
	.uninit = cpfl_fxp_uninit,
	.create = cpfl_fxp_create,
	.destroy = cpfl_fxp_destroy,
	.query_count = cpfl_fxp_query,
	.parse_pattern_action = cpfl_fxp_parse_pattern_action,
};

RTE_INIT(cpfl_sw_engine_init)
{
	struct cpfl_flow_engine *engine = &cpfl_fxp_engine;

	cpfl_flow_engine_register(engine);
}

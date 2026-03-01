/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */
#include "cpfl_ethdev.h"

#include "cpfl_fxp_rule.h"
#include "cpfl_logs.h"

#define CTLQ_SEND_RETRIES 100
#define CPFL_FLOW_BATCH_SIZE 500

static int
cpfl_send_ctlq_msg(struct idpf_hw *hw, struct idpf_ctlq_info *cq, u16 num_q_msg,
		struct idpf_ctlq_msg q_msg[])
{
	struct idpf_ctlq_msg **msg_ptr_list;
	u16 clean_count = 0;
	int num_cleaned = 0;
	int retries = 0;
	int ret = 0;

	msg_ptr_list = calloc(num_q_msg, sizeof(struct idpf_ctlq_msg *));
	if (!msg_ptr_list) {
		PMD_INIT_LOG(ERR, "no memory for cleaning ctlq");
		ret = -ENOMEM;
		goto err;
	}

	ret = idpf_vport_ctlq_send(hw, cq, num_q_msg, q_msg);
	if (ret) {
		PMD_INIT_LOG(ERR, "icpf_ctlq_send() failed with error: 0x%4x", ret);
		goto send_err;
	}

	while (retries <= CTLQ_SEND_RETRIES) {
		clean_count = num_q_msg - num_cleaned;
		ret = idpf_vport_ctlq_clean_sq(cq, &clean_count,
				&msg_ptr_list[num_cleaned]);
		if (ret) {
			PMD_INIT_LOG(ERR, "clean ctlq failed: 0x%4x", ret);
			goto send_err;
		}

		num_cleaned += clean_count;
		retries++;
		if (num_cleaned >= num_q_msg)
			break;
		rte_delay_us_sleep(10);
	}

	if (retries > CTLQ_SEND_RETRIES) {
		PMD_INIT_LOG(ERR, "timed out while polling for completions");
		ret = -1;
		goto send_err;
	}

send_err:
	if (msg_ptr_list)
		free(msg_ptr_list);
err:
	return ret;
}

static int
pack_mod_rule(struct cpfl_rule_info *rinfo, struct idpf_dma_mem *dma,
	      struct idpf_ctlq_msg *msg)
{
	struct cpfl_mod_rule_info *minfo = &rinfo->mod;
	union icpf_rule_cfg_pkt_record *blob = NULL;
	struct icpf_rule_cfg_data cfg = {0};

	/* prepare rule blob */
	if (!dma->va) {
		PMD_INIT_LOG(ERR, "dma mem passed to %s is null\n", __func__);
		return -1;
	}
	blob = (union icpf_rule_cfg_pkt_record *)dma->va;
	memset(blob, 0, sizeof(*blob));
	memset(&cfg, 0, sizeof(cfg));

	/* fill info for both query and add/update */
	icpf_fill_rule_mod_content(minfo->mod_obj_size,
				   minfo->pin_mod_content,
				   minfo->mod_index,
				   &cfg.ext.mod_content);

	/* only fill content for add/update */
	memcpy(blob->mod_blob, minfo->mod_content,
	       minfo->mod_content_byte_len);

#define NO_HOST_NEEDED 0
	/* pack message */
	icpf_fill_rule_cfg_data_common(icpf_ctlq_mod_add_update_rule,
				       rinfo->cookie,
				       0, /* vsi_id not used for mod */
				       rinfo->port_num,
				       NO_HOST_NEEDED,
				       0, /* time_sel */
				       0, /* time_sel_val */
				       0, /* cache_wr_thru */
				       rinfo->resp_req,
				       (u16)sizeof(*blob),
				       (void *)dma,
				       &cfg.common);
	icpf_prep_rule_desc(&cfg, msg);
	return 0;
}

static int pack_sem_rule(struct cpfl_rule_info *rinfo, struct idpf_dma_mem *dma,
			 struct idpf_ctlq_msg *msg, bool add)
{
	union icpf_rule_cfg_pkt_record *blob = NULL;
	struct icpf_rule_cfg_data cfg;
	uint16_t cfg_ctrl;

	if (!dma->va) {
		PMD_INIT_LOG(ERR, "dma mem passed to %s is null\n", __func__);
		return -1;
	}
	blob = (union icpf_rule_cfg_pkt_record *)dma->va;
	memset(blob, 0, sizeof(*blob));
	memset(msg, 0, sizeof(*msg));

	cfg_ctrl = ICPF_GET_MEV_SEM_RULE_CFG_CTRL(rinfo->sem.prof_id,
					  rinfo->sem.sub_prof_id,
					  rinfo->sem.pin_to_cache,
					  rinfo->sem.fixed_fetch);
	icpf_prep_sem_rule_blob(rinfo->sem.key, rinfo->sem.key_byte_len,
				rinfo->act_bytes, rinfo->act_byte_len,
				cfg_ctrl, blob);

	icpf_fill_rule_cfg_data_common(add ? icpf_ctlq_sem_add_rule : icpf_ctlq_sem_del_rule,
				       rinfo->cookie,
				       rinfo->vsi,
				       rinfo->port_num,
				       rinfo->host_id,
				       0, /* time_sel */
				       0, /* time_sel_val */
				       0, /* cache_wr_thru */
				       rinfo->resp_req,
				       sizeof(union icpf_rule_cfg_pkt_record),
				       dma,
				       &cfg.common);
	icpf_prep_rule_desc(&cfg, msg);
	return 0;
}

static int pack_rule(struct cpfl_rule_info *rinfo, struct idpf_dma_mem *dma,
		       struct idpf_ctlq_msg *msg, bool add)
{
	int ret = 0;

	if (rinfo->type == CPFL_RULE_TYPE_SEM) {

		if (pack_sem_rule(rinfo, dma, msg, add) < 0)
			ret = -1;

	} else if (rinfo->type == CPFL_RULE_TYPE_MOD) {
		if (pack_mod_rule(rinfo, dma, msg) < 0)
			ret = -1;
	}

	return ret;
}

int
cpfl_rule_update(struct idpf_hw *hw, struct idpf_ctlq_info *cq, struct cpfl_rule_info *rinfo,
		 int rule_num, bool add)
{
	int i, j, used = 0;
	int ret = 0;

	int buf_sz = sizeof(union icpf_rule_cfg_pkt_record);
	struct idpf_dma_mem dma[CPFL_FLOW_BATCH_SIZE];
	struct idpf_ctlq_msg msg[CPFL_FLOW_BATCH_SIZE];

	memset(dma, 0, sizeof(dma));
	memset(msg, 0, sizeof(msg));

	for (j = 0; j < CPFL_FLOW_BATCH_SIZE; j++) {
		if (!idpf_alloc_dma_mem(NULL, &dma[j], buf_sz)) {
			PMD_INIT_LOG(ERR, "Could not alloc dma memory");
			return -ENOMEM;
		}
	}

	for (i = 0; i < rule_num / CPFL_FLOW_BATCH_SIZE; i++) {
		for (j = 0; j < CPFL_FLOW_BATCH_SIZE; j++) {
			ret = pack_rule(&rinfo[i * CPFL_FLOW_BATCH_SIZE + j],
					&dma[j], &msg[j], add);
			if (ret) {
				PMD_INIT_LOG(ERR, "Could not create rule");
				goto err;
			}
		}
		ret = cpfl_send_ctlq_msg(hw, cq, CPFL_FLOW_BATCH_SIZE, msg);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to send rule");
			goto err;
		}
	}
	used = rule_num / CPFL_FLOW_BATCH_SIZE * CPFL_FLOW_BATCH_SIZE;
	if (used == rule_num)
		goto err;

	for (i = used; i < rule_num; i++) {
		j = i - used;
		ret = pack_rule(&rinfo[i], &dma[j], &msg[j], add);
		if (ret) {
			PMD_INIT_LOG(ERR, "Could not create rule");
			goto err;
		}
	}
	ret = cpfl_send_ctlq_msg(hw, cq, rule_num - used, msg);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to send rule");
		goto err;
	}
err:
	for (j = 0; j < CPFL_FLOW_BATCH_SIZE; j++)
		idpf_free_dma_mem(NULL, &dma[j]);
	return ret;
}

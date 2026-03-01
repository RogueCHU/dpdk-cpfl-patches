#include "cpfl_ethdev.h"
#include "icpf_rules.h"
#include "rte_pmd_idpf.h"
#include "rte_pmd_iecm.h"

#define CTLQ_SEND_RETRIES 10000
bool is_p4sde_active = false;

extern bool p4sde_quiesce_set;

static int
idpf_vc_clean(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_msg *q_msg[IDPF_CTLQ_LEN];
	uint16_t num_q_msg = IDPF_CTLQ_LEN;
	struct idpf_dma_mem *dma_mem;
	int err;
	uint32_t i;

#ifndef FIX
	if (p4sde_quiesce_set == true ) {
		PMD_DRV_LOG(ERR, "p4sde_qiesce_set is true\n");
		return 0;
	}
#endif

	for (i = 0; i < 10; i++) {
		err = idpf_vport_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
		msleep(20);
		if (num_q_msg > 0)
			break;
	}
	if (err != 0)
		return err;

	/* Empty queue is not an error */
	for (i = 0; i < num_q_msg; i++) {
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem != NULL) {
			idpf_free_dma_mem(&adapter->hw, dma_mem);
			rte_free(dma_mem);
		}
		rte_free(q_msg[i]);
	}

	return 0;
}

int cpfl_ctlq_send_p4sde_cpchnl(uint32_t op, uint8_t *msg,
			     uint16_t msg_size, uint32_t cookie2, __rte_unused bool poll_for_resp)
{
	struct cpfl_adapter_ext *adapter_ext = cpfl_get_adapter_ext();
	struct idpf_adapter *adapter = &adapter_ext->base;

	struct idpf_ctlq_msg *ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	err = idpf_vc_clean(adapter);
	if (err != 0)
		goto err;

	ctlq_msg = rte_zmalloc(NULL, sizeof(struct idpf_ctlq_msg), 0);
	if (ctlq_msg == NULL) {
		err = -ENOMEM;
		goto err;
	}

	dma_mem = rte_zmalloc(NULL, sizeof(struct idpf_dma_mem), 0);
	if (dma_mem == NULL) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	dma_mem->size = IDPF_DFLT_MBX_BUF_SIZE;
	idpf_alloc_dma_mem(&adapter->hw, dma_mem, dma_mem->size);
	if (dma_mem->va == NULL) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}

#define CPCHNL2_OP_PKG_LOAD        0x8022
#define CPCHNL2_OP_SET_BOOT_STATE  0x8E04
	/* msg = cpchnl hdr + actual payload */
	if (op == CPCHNL2_OP_PKG_LOAD) {
		PMD_DRV_LOG(DEBUG, "set package frag info");
		memcpy(ctlq_msg->ctx.indirect.context, msg, IDPF_INDIRECT_CTX_SIZE);
		msg = msg + IDPF_INDIRECT_CTX_SIZE;
		msg_size = msg_size - IDPF_INDIRECT_CTX_SIZE;
	}

	if (op == CPCHNL2_OP_SET_BOOT_STATE) {
		PMD_DRV_LOG(DEBUG, "set boot state");
		memcpy(ctlq_msg->ctx.indirect.context, msg, msg_size);
		msg = msg + msg_size;
		msg_size = 0;
	}

	memcpy(dma_mem->va, msg, msg_size);

	ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_pf;
	ctlq_msg->func_id = 0;
	ctlq_msg->data_len = msg_size;
#ifdef CPCHNL2_SUPPORT
	ctlq_msg->mbx_v2.opcode2 = op;
	ctlq_msg->mbx_v2.cookie2 = cookie2;
	ctlq_msg->mbx_v2.retval2 = VIRTCHNL_STATUS_SUCCESS;
#else
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = VIRTCHNL_STATUS_SUCCESS;
#endif
	ctlq_msg->ctx.indirect.payload = dma_mem;

	err = idpf_vport_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err != 0)
		goto send_error;

	return 0;

send_error:
	idpf_free_dma_mem(&adapter->hw, dma_mem);
dma_alloc_error:
	rte_free(dma_mem);
dma_mem_error:
	rte_free(ctlq_msg);
err:
	return err;
}

void *
rte_pmd_alloc_dma_mem(struct idpf_dma_mem *mem, u64 size)
{
	const struct rte_memzone *mz = NULL;
	char z_name[RTE_MEMZONE_NAMESIZE];

	if (!mem)
		return NULL;

	snprintf(z_name, sizeof(z_name), "idpf_dma_%"PRIu64, rte_rand());
	mz = rte_memzone_reserve_aligned(z_name, size, SOCKET_ID_ANY,
			RTE_MEMZONE_IOVA_CONTIG, RTE_PGSIZE_4K);
	if (!mz)
		return NULL;

	mem->size = size;
	mem->va = mz->addr;
	mem->pa = mz->iova;
	mem->zone = (const void *)mz;
	memset(mem->va, 0, size);

	return mem->va;
}

void
rte_pmd_free_dma_mem(struct idpf_dma_mem *dma)
{
	idpf_free_dma_mem(NULL, dma);
}

int rte_pmd_free_rule_buf(struct idpf_dma_mem *dma)
{
	idpf_free_dma_mem(NULL, dma);
	return 0;
}

int rte_pmd_alloc_rule_buf(struct idpf_dma_mem *dma)
{
	int buf_sz = sizeof(union icpf_rule_cfg_pkt_record);
	
	dma->va = idpf_alloc_dma_mem(NULL, dma, buf_sz);
	if (!dma->va) {
		PMD_INIT_LOG(ERR, "Could not alloc dma memory");
		return -ENOMEM;
	}

	return 0;
}

int
rte_pmd_alloc_rule_send_buf(__rte_unused u32 opcode,
			    struct idpf_ctlq_msg **msg_out,
			    struct idpf_dma_mem **dma_out)
{
	int buf_sz = sizeof(union icpf_rule_cfg_pkt_record);
	struct idpf_ctlq_msg *msg;
	struct idpf_dma_mem *dma;

	dma = calloc(1, sizeof(struct idpf_dma_mem));
	if (!dma) {
		PMD_INIT_LOG(ERR, "Failed to alloc rule dma");
		return -1;
	}
	if (!rte_pmd_alloc_dma_mem(dma, buf_sz)) {
		PMD_INIT_LOG(ERR, "Could not alloc dma memory");
		goto err_free_dma;
	}

	msg = calloc(1, sizeof(struct idpf_ctlq_msg));
	if (!msg) {
		PMD_INIT_LOG(ERR, "Failed to alloc rule msg");
		goto err_free_dma_mem;
	}

	*msg_out = msg;
	*dma_out = dma;
	return 0;

err_free_dma_mem:
	idpf_free_dma_mem(NULL, dma);
err_free_dma:
	free(dma);
	return -1;
}

static void
free_rule_send_buf(struct idpf_ctlq_msg *msg, struct idpf_dma_mem *dma)
{
	if (dma) {
		idpf_free_dma_mem(NULL, dma);
		free(dma);
	}

	if (msg)
		free(msg);
}

void
rte_pmd_free_rule_send_buf(struct idpf_ctlq_msg *msg, struct idpf_dma_mem *dma)
{
	free_rule_send_buf(msg, dma);
}

static int
cpfl_send_ctlq_msg_fast(struct idpf_hw *hw, struct idpf_ctlq_info *cq, u16 num_q_msg,
		struct idpf_ctlq_msg q_msg[], struct idpf_send_msg *q_send_msg)
{
	struct idpf_ctlq_msg **msg_ptr_list;
	u16 clean_count = 0;
	int num_cleaned = 0;
	int retries = 0;
	u16 clean_idx;
	u16 send_idx;
	int ret = 0;
	u32 msg_count = 0;
	bool pingpong;

	msg_ptr_list = q_send_msg->q_msg_list;
	pingpong = q_send_msg->pingpong;

	send_idx = (pingpong == 1) ? q_send_msg->batch_size : 0;

	ret = idpf_vport_ctlq_send(hw, cq, num_q_msg, &q_msg[send_idx]);
	if (ret) {
		PMD_INIT_LOG(ERR, "idpf_ctlq_send() failed with error: 0x%4x", ret);
		goto err;
	}

	if (q_send_msg->new_session == 1)
		return 0;

	clean_idx = (pingpong == 1) ? 0 : q_send_msg->batch_size;
	msg_count = q_send_msg->msg_count[!pingpong];

	while (retries <= CTLQ_SEND_RETRIES) {
		clean_count = msg_count - num_cleaned;
		ret = idpf_vport_ctlq_clean_sq(cq, &clean_count,
				&msg_ptr_list[clean_idx]);
		if (ret) {
			PMD_INIT_LOG(ERR, "clean ctlq failed: 0x%4x", ret);
			goto err;
		}

		num_cleaned += clean_count;
		clean_idx += clean_count;
		retries++;
		if (num_cleaned >= msg_count)
			break;
	}

	if (retries > CTLQ_SEND_RETRIES) {
		PMD_INIT_LOG(ERR, "timed out while polling for completions");
		ret = -1;
	}

err:
	return ret;
}

static int
cpfl_send_ctlq_msg_p4sde(struct idpf_hw *hw, struct idpf_ctlq_info *cq, u16 num_q_msg,
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
	ret = idpf_vport_ctlq_send_sync(hw, cq, num_q_msg, q_msg);
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
		rte_delay_us_sleep(1);
	}

	if (retries > CTLQ_SEND_RETRIES) {
		PMD_INIT_LOG(ERR, "timed out while polling for completions");
		ret = -1;
	}

send_err:
	if (msg_ptr_list)
		free(msg_ptr_list);
err:
	return ret;
}

int
rte_pmd_send_ctlq_msg(struct idpf_hw *hw, struct idpf_ctlq_info *cq, u16 num_q_msg,
		struct idpf_ctlq_msg q_msg[], struct idpf_send_msg *q_send_msg)
{
	if (q_send_msg)
		return cpfl_send_ctlq_msg_fast(hw, cq, num_q_msg, q_msg, q_send_msg);
	else
		return cpfl_send_ctlq_msg_p4sde(hw, cq, num_q_msg, q_msg);
}

int rte_pmd_ctlq_clean_sq(struct idpf_ctlq_info *cq, u16 *clean_count,
			     struct idpf_ctlq_msg *msg_status[])
{
	return idpf_vport_ctlq_clean_sq(cq, clean_count, msg_status);
}

int
rte_pmd_recv_ctlq_msg(struct idpf_ctlq_info *cq, u16 *num_q_msg,
			struct idpf_ctlq_msg *q_msg)
{
	return idpf_vc_ctlq_recv(cq, num_q_msg, q_msg);
}

int
rte_pmd_ctlq_post_rx_buffs(struct idpf_hw *hw, struct idpf_ctlq_info *cq,
			   u16 *buff_count, struct idpf_dma_mem **buffs)
{
	return idpf_vc_ctlq_post_rx_buffs(hw, cq, buff_count, buffs);
}

int rte_pmd_idpf_get_hw(struct idpf_hw **hw)
{
	struct cpfl_adapter_ext *adapter =  cpfl_get_adapter_ext();
	struct idpf_adapter *base = &adapter->base;

	*hw = &base->hw;

	return 0;
}
/* just return first pair of config queues*/
int rte_pmd_idpf_get_cfgqs(struct idpf_ctlq_info **cfg_tx_cq,
			   struct idpf_ctlq_info **cfg_rx_cq)
{
	int i = 0;

	if (!cfg_tx_cq || !cfg_rx_cq)
		return -1;
	struct cpfl_adapter_ext *adapter =  cpfl_get_adapter_ext();
	if (!adapter)
		return -1;

	*cfg_tx_cq = adapter->ctlqp[i * 2];
	*cfg_rx_cq = adapter->ctlqp[(i * 2) + 1];

	return 0;
}

int rte_pmd_idpf_get_all_cfgqs(struct idpf_ctlq_info **cfg_tx_cq,
				struct idpf_ctlq_info **cfg_rx_cq,
				uint8_t num_cfgqs, uint8_t start_idx)
{
	int i, i_max, j = 0;

	if (!cfg_tx_cq || !cfg_rx_cq)
		return -1;

	struct cpfl_adapter_ext *adapter =  cpfl_get_adapter_ext();
	if (!adapter)
		return -1;

	if (num_cfgqs <= CPFL_RX_CFGQ_NUM) {
		i = start_idx;
		i_max = start_idx + num_cfgqs;

		for (; i < i_max; i++, j++) {
			cfg_tx_cq[j] = adapter->ctlqp[i * 2];
			cfg_rx_cq[j] = adapter->ctlqp[(i * 2) + 1];
		}
		printf("%d config queues are assigned. Start Qid %d\n", num_cfgqs, cfg_tx_cq[0]->q_id);

		return 0;
	}
	else {
		printf("Error: Req cfgqs %u is greater than unused cfgqs %d\n", num_cfgqs, adapter->unused_cfgqs);
		return -1;
	}
}
void cpf_pmd_get_vport_stats(uint16_t vport_id)
{
	struct cpfl_adapter_ext *adapter_ext = cpfl_get_adapter_ext();
	struct idpf_adapter *adapter = &adapter_ext->base;
	struct virtchnl2_vport_stats *s;
	struct virtchnl2_vport_stats vport_stats;
	struct idpf_cmd_info args;
	int err;

	vport_stats.vport_id = vport_id;
	args.ops = VIRTCHNL2_OP_GET_STATS;
	args.in_args = (u8 *)&vport_stats;
	args.in_args_size = sizeof(vport_stats);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_vc_cmd_execute(adapter, &args);
	if (err) {
		printf("Failed to execute command of VIRTCHNL2_OP_GET_STATS");
		return err;
	}
	s = (struct virtchnl2_vport_stats *)args.out_buffer;
	printf("ingress bytes: %lu\n"
		"ingress unicast packet: %lu\n"
		"ingress multicast packet: %lu\n"
		"ingress broadcast packet: %lu\n"
		"ingress discards packet: %lu\n"
		"ingress errors packet: %lu\n"
		"ingress unknown packet: %lu\n"
		"egress bytes: %lu\n"
		"egress unicast packet: %lu\n"
		"egress multicast packet: %lu\n"
		"egress broadcast packet: %lu\n"
		"egress discards packet: %lu\n"
		"egress errors packet: %lu\n",
		s->rx_bytes,
		s->rx_unicast,
		s->rx_multicast,
		s->rx_broadcast,
		s->rx_discards,
		s->rx_errors,
		s->rx_unknown_protocol,
		s->tx_bytes,
		s->tx_unicast,
		s->tx_multicast,
		s->tx_broadcast,
		s->tx_discards,
		s->tx_errors);

	return 0;
}

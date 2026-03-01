/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _RTE_PMD_IDPF_H_
#define _RTE_PMD_IDPF_H_
#include <rte_common.h>

#ifdef IS_CPF_PMD_ENABLED
struct idpf_hw;
struct idpf_ctlq_info;
struct idpf_ctlq_msg;
struct idpf_dma_mem;
extern bool is_p4sde_active;

int rte_pmd_idpf_get_hw(struct idpf_hw **hw);
int rte_pmd_idpf_get_cfgqs(struct idpf_ctlq_info **cfg_tx_cq,
			   struct idpf_ctlq_info **cfg_rx_cq);
int rte_pmd_idpf_get_all_cfgqs(struct idpf_ctlq_info **cfg_tx_cq,
				   struct idpf_ctlq_info **cfg_rx_cq,
				   uint8_t num_cfgqs,
				   uint8_t cfgqs_start_idx);
typedef int (*cpfl_callback_func)(void *ctrl);
void cpfl_register_callback(cpfl_callback_func ptr);
/* Shared API with p4sde */
int cpfl_ctlq_send_p4sde_cpchnl(uint32_t v_opcode, uint8_t *msg,
			     uint16_t msg_size, uint32_t cookie2,
			     __rte_unused bool is_resp_needed);
void cpfl_disable_ctlq_recv();
void cpf_pmd_get_vport_stats(uint16_t vport_id);
#endif
#endif

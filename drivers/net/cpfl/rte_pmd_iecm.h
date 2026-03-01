/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */
#ifndef _RTE_PMD_IECM_H_
#define _RTE_PMD_IECM_H_

#include <sys/queue.h>
#include <rte_spinlock.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_random.h>
#include <rte_io.h>

#ifdef container_of
#undef container_of
#endif

#ifndef LIST_ENTRY_TYPE
#define LIST_ENTRY_TYPE(type)      LIST_ENTRY(type)
#endif

#ifdef IS_CPF_PMD_ENABLED

struct idpf_send_msg {
	bool pingpong;
	bool new_session;
	u32  batch_size;
	u32  msg_count[2];
	struct idpf_ctlq_msg **q_msg_list;
};
int rte_pmd_recv_ctlq_msg(struct idpf_ctlq_info *cq, u16 *num_q_msg,
		          struct idpf_ctlq_msg *q_msg);

int rte_pmd_alloc_rule_send_buf(__rte_unused u32 opcode,
				struct idpf_ctlq_msg **msg_out,
				struct idpf_dma_mem **dma_out);
void rte_pmd_free_rule_send_buf(struct idpf_ctlq_msg *msg, struct idpf_dma_mem *dma);

int rte_pmd_send_ctlq_msg(struct idpf_hw *hw, struct idpf_ctlq_info *cq, u16 num_q_msg,
		struct idpf_ctlq_msg *q_msg, struct idpf_send_msg *q_send_msg);

int rte_pmd_alloc_rule_buf(struct idpf_dma_mem *dma);
int rte_pmd_free_rule_buf(struct idpf_dma_mem *dma);
void * rte_pmd_alloc_dma_mem(struct idpf_dma_mem *mem, u64 size);
void rte_pmd_free_dma_mem(struct idpf_dma_mem *mem);
int rte_pmd_ctlq_clean_sq(struct idpf_ctlq_info *cq, u16 *clean_count,
			     struct idpf_ctlq_msg *msg_status[]);
int rte_pmd_ctlq_post_rx_buffs(struct idpf_hw *hw, struct idpf_ctlq_info *cq,
			   u16 *buff_count, struct idpf_dma_mem **buffs);
#endif
#endif /* _RTE_PMD_IECM_H_ */

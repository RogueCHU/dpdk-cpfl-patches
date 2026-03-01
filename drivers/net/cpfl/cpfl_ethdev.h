/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _CPFL_ETHDEV_H_
#define _CPFL_ETHDEV_H_

#include <stdint.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <rte_hash.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_tdi_driver.h>

#include <idpf_common_device.h>
#include <idpf_common_virtchnl.h>
#include <base/idpf_prototype.h>
#include <base/virtchnl2.h>

#include "cpfl_flow_fxp_metadata.h"
#include "cpfl_logs.h"
#include "cpfl_cpchnl.h"
#include "cpfl_tdi_entry.h"
#include "cpfl_representor.h"

#ifdef RTE_FLOW_SHIM
#include "cpfl_p4sde_init.h"
#endif

/* Currently, backend supports up to 8 vports */
#define CPFL_MAX_VPORT_NUM	8

#define CPFL_INVALID_VPORT_IDX	0xffff

#define CPFL_DFLT_Q_VEC_NUM	1

#define CPFL_MIN_BUF_SIZE	1024
#define CPFL_MAX_FRAME_SIZE	9728
#define CPFL_DEFAULT_MTU	RTE_ETHER_MTU

#define CPFL_VLAN_TAG_SIZE	4
#define CPFL_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + CPFL_VLAN_TAG_SIZE * 2)

#define CPFL_RSS_OFFLOAD_ALL (				\
		RTE_ETH_RSS_IPV4                |	\
		RTE_ETH_RSS_FRAG_IPV4           |	\
		RTE_ETH_RSS_NONFRAG_IPV4_TCP    |	\
		RTE_ETH_RSS_NONFRAG_IPV4_UDP    |	\
		RTE_ETH_RSS_NONFRAG_IPV4_SCTP   |	\
		RTE_ETH_RSS_NONFRAG_IPV4_OTHER  |	\
		RTE_ETH_RSS_IPV6                |	\
		RTE_ETH_RSS_FRAG_IPV6           |	\
		RTE_ETH_RSS_NONFRAG_IPV6_TCP    |	\
		RTE_ETH_RSS_NONFRAG_IPV6_UDP    |	\
		RTE_ETH_RSS_NONFRAG_IPV6_SCTP   |	\
		RTE_ETH_RSS_NONFRAG_IPV6_OTHER  |	\
		RTE_ETH_RSS_L2_PAYLOAD)

#define CPFL_ADAPTER_NAME_LEN	(PCI_PRI_STR_SIZE + 1)

#define CPFL_ALARM_INTERVAL	50000 /* us */

/* Device IDs */
#define IDPF_DEV_ID_CPF			0x1453

#define CPFL_HOST_ID_HOST	0
#define CPFL_HOST_ID_ACC	1
#define CPFL_PF_TYPE_APF	0
#define CPFL_PF_TYPE_CPF	1

#define CPFL_RX_CFGQ_NUM	16
#define CPFL_TX_CFGQ_NUM	16
#define CPFL_CFGQ_NUM		32

struct cpfl_vport_param {
	struct cpfl_adapter_ext *adapter;
	uint16_t devarg_id; /* arg id from user */
	uint16_t idx;       /* index in adapter->vports[]*/
};

#define CPFL_PARSER_NAME_MAX	100
#define CPFL_REPR_ARG_NUM_MAX	4

/* Struct used when parse driver specific devargs */
struct cpfl_devargs {
	uint16_t req_vports[CPFL_MAX_VPORT_NUM];
	uint16_t req_vport_nb;
	char flow_parser[CPFL_PARSER_NAME_MAX];
	char tdi_parser[CPFL_PARSER_NAME_MAX];
#ifdef RTE_FLOW_SHIM
	char rfs_conf[CPFL_PARSER_NAME_MAX];
#endif
#ifdef IS_CPF_PMD_ENABLED
	char bf_switchd_lib_path[CPFL_PARSER_NAME_MAX];
	char bf_switchd_lib_conf[CPFL_PARSER_NAME_MAX];
	uint8_t bf_switchd_lib_lock;
#endif
	uint8_t repr_args_num;
	struct rte_eth_devargs repr_args[CPFL_REPR_ARG_NUM_MAX];
};

#define CPFL_DEV_TO_VPORT(dev)		((struct cpfl_vport_ext *)((dev)->data->dev_private))
#define CPFL_DEV_TO_REPR(dev)		((struct cpfl_repr *)((dev)->data->dev_private))
#define CPFL_DEV_TO_ITF(dev)		((struct cpfl_itf *)((dev)->data->dev_private))
#define CPFL_DEV_TO_ADAPTER(dev)	(CPFL_DEV_TO_ITF(dev)->adapter)

enum cpfl_itf_type {
	CPFL_ITF_TYPE_VPORT,
	CPFL_ITF_TYPE_REPRESENTOR
};

struct cpfl_itf {
	enum cpfl_itf_type type;
	struct cpfl_adapter_ext *adapter;
	void *data;
};

TAILQ_HEAD(cpfl_flow_list, rte_flow);

struct cpfl_vport_id {
	uint32_t vport_id;
};

struct cpfl_vport_info {
	struct cpchnl_vport_loc loc;
	bool enabled;

};

struct cpfl_vport_ext {
	struct cpfl_itf itf;
	struct idpf_vport base;
	struct cpfl_flow_list flow_list;

	struct idpf_dma_mem tdi_dma;
	struct idpf_dma_mem tdi_dma_batch[CPFL_TDI_ENTRY_BATCH_SIZE];
	struct idpf_ctlq_msg tdi_ctrl_msgs[CPFL_TDI_ENTRY_BATCH_SIZE];
	struct cpfl_tdi_entry_ring tdi_tx_entry_ring;
	struct cpfl_tdi_entry_ring tdi_rx_entry_ring;
};

struct cpfl_repr {
	struct cpfl_itf itf;
	struct cpfl_repr_id repr_id;
	struct cpfl_vport_info *vport_info;
};

struct cpfl_tdi_table_node;
TAILQ_HEAD(cpfl_tdi_table_list, cpfl_tdi_table_node);

struct cpfl_tdi_action_node;
TAILQ_HEAD(cpfl_tdi_action_list, cpfl_tdi_action_node);

struct cpfl_adapter_ext {
	TAILQ_ENTRY(cpfl_adapter_ext) next;
	struct idpf_adapter base;

	char name[CPFL_ADAPTER_NAME_LEN];

	struct cpfl_vport_ext **vports;
	uint16_t max_vport_nb;

	uint16_t cur_vports; /* bit mask of created vport */
	uint16_t cur_vport_nb;

	uint16_t used_vecs_num;
	struct cpfl_devargs devargs;

	/* ctrl vport and ctrl queues. */
	struct cpfl_vport_ext ctrl_vport;
	uint8_t ctrl_vport_recv_info[IDPF_DFLT_MBX_BUF_SIZE];
	struct idpf_ctlq_info *ctlqp[CPFL_CFGQ_NUM];
	struct idpf_ctlq_create_info cfgq_info[CPFL_CFGQ_NUM];

	rte_spinlock_t vport_map_lock;
	struct rte_hash *vport_map_hash;

	rte_spinlock_t repr_lock;
	struct rte_hash *repr_whitelist_hash;

	struct cpfl_metadata meta;
	struct cpfl_js_flow_parser *flow_parser;

	struct rte_bitmap *mod_bm;
	void *mod_bm_mem;

	struct cpfl_tdi_program *tdi_program;
	struct cpfl_tdi_table_list tdi_table_list;
	struct cpfl_tdi_action_list tdi_action_list;
	int tdi_action_num;
	struct rte_tdi_cache tdi_cache;
#ifdef IS_CPF_PMD_ENABLED
	uint8_t unused_cfgqs;
#endif
};

TAILQ_HEAD(cpfl_adapter_list, cpfl_adapter_ext);

int cpfl_vc_create_ctrl_vport(struct cpfl_adapter_ext *adapter);
int cpfl_config_ctlq_rx(struct cpfl_adapter_ext *adapter);
int cpfl_config_ctlq_tx(struct cpfl_adapter_ext *adapter);

#define CPFL_DEV_TO_PCI(eth_dev)		\
	RTE_DEV_TO_PCI((eth_dev)->device)
#define CPFL_ADAPTER_TO_EXT(p)					\
	container_of((p), struct cpfl_adapter_ext, base)

#define CPFL_INVALID_HW_ID	UINT16_MAX

static inline uint16_t
cpfl_get_port_id(struct cpfl_itf *itf)
{
	if (itf->type == CPFL_ITF_TYPE_VPORT) {
		struct cpfl_vport_ext *vport = (void *)itf;

		return vport->base.devarg_id;
	}

	return CPFL_INVALID_HW_ID;
}

static inline uint16_t
cpfl_get_vsi_id(struct cpfl_itf *itf)
{
	struct cpfl_adapter_ext *adapter = itf->adapter;
	struct cpfl_vport_info *info;
	uint32_t vport_id;
	int ret;

	if (itf->type != CPFL_ITF_TYPE_VPORT)
		return CPFL_INVALID_HW_ID;

	vport_id = ((struct cpfl_vport_ext *)itf)->base.vport_id;

	rte_spinlock_lock(&adapter->vport_map_lock);
	ret = rte_hash_lookup_data(adapter->vport_map_hash, &vport_id, (void **)&info);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "vport id not exist");
		goto err;
	}

	rte_spinlock_unlock(&adapter->vport_map_lock);
	return info->loc.vsi_id;

err:
	rte_spinlock_unlock(&adapter->vport_map_lock);
	return CPFL_INVALID_HW_ID;
}

static inline struct cpfl_itf *
cpfl_get_itf_by_port_id(uint16_t port_id)
{
	struct rte_eth_dev *dev;
	if (port_id >= RTE_MAX_ETHPORTS) {
		PMD_DRV_LOG(ERR, "port_id should be < %d.", RTE_MAX_ETHPORTS);
		return NULL;
	}

	dev = &rte_eth_devices[port_id];

	if (dev->state == RTE_ETH_DEV_UNUSED) {
		PMD_DRV_LOG(ERR, "eth_dev[%d] is unused.", port_id);
		return NULL;
	}

	if (!dev->data) {
		PMD_DRV_LOG(ERR, "eth_dev[%d] data not be allocated.", port_id);
		return NULL;
	}

	return CPFL_DEV_TO_ITF(dev);
}
#ifdef IS_CPF_PMD_ENABLED
struct cpfl_adapter_ext* cpfl_get_adapter_ext(void);
#endif
#endif /* _CPFL_ETHDEV_H_ */

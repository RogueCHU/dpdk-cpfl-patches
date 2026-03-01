/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include "cpfl_representor.h"
#include "cpfl_rxtx.h"

static int
cpfl_repr_whitelist_update(struct cpfl_adapter_ext *adapter,
			   struct cpfl_repr_id *repr_id,
			   struct rte_eth_dev *dev)
{
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);
	if (rte_hash_lookup(adapter->repr_whitelist_hash, repr_id) < 0) {
		ret = -ENOENT;
		goto err;
	}

	ret = rte_hash_add_key_data(adapter->repr_whitelist_hash, repr_id, dev);
	if (ret < 0)
		goto err;

	rte_spinlock_unlock(&adapter->repr_lock);
	return 0;
err:
	rte_spinlock_unlock(&adapter->repr_lock);
	return ret;
}

static int
cpfl_repr_whitelist_add(struct cpfl_adapter_ext *adapter,
			struct cpfl_repr_id *repr_id)
{
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);
	if (rte_hash_lookup(adapter->repr_whitelist_hash, repr_id) >= 0) {
		ret = -EEXIST;
		goto err;
	}

	ret = rte_hash_add_key(adapter->repr_whitelist_hash, repr_id);
	if (ret < 0)
		goto err;

	rte_spinlock_unlock(&adapter->repr_lock);
	return 0;
err:
	rte_spinlock_unlock(&adapter->repr_lock);
	return ret;
}

static int
cpfl_repr_devargs_process_one(struct cpfl_adapter_ext *adapter,
			      struct rte_eth_devargs *eth_da)
{
	struct cpfl_repr_id repr_id;
	int ret, c, p, v;

	for (c = 0; c < eth_da->nb_mh_controllers; c++) {
		for (p = 0; p < eth_da->nb_ports; p++) {
			repr_id.type = eth_da->type;
			if (eth_da->type == RTE_ETH_REPRESENTOR_PF) {
				repr_id.host_id = eth_da->mh_controllers[c];
				repr_id.pf_id = eth_da->ports[p];
				repr_id.vf_id = 0;
				ret = cpfl_repr_whitelist_add(adapter, &repr_id);
				if (ret == -EEXIST)
					continue;
				if (ret) {
					PMD_DRV_LOG(ERR, "Failed to add PF repr to whitelist, "
							 "host_id = %d, pf_id = %d.",
						    repr_id.host_id, repr_id.pf_id);
					return ret;
				}
			} else if (eth_da->type == RTE_ETH_REPRESENTOR_VF) {
				for (v = 0; v < eth_da->nb_representor_ports; v++) {
					repr_id.host_id = eth_da->mh_controllers[c];
					repr_id.pf_id = eth_da->ports[p];
					repr_id.vf_id = eth_da->representor_ports[v];
					ret = cpfl_repr_whitelist_add(adapter, &repr_id);
					if (ret == -EEXIST)
						continue;
					if (ret) {
						PMD_DRV_LOG(ERR, "Failed to add VF repr to whitelist, "
								 "host_id = %d, pf_id = %d, vf_id = %d.",
							    repr_id.host_id,
							    repr_id.pf_id,
							    repr_id.vf_id);
						return ret;
					}
				}
			}
		}
	}

	return 0;
}

int
cpfl_repr_devargs_process(struct cpfl_adapter_ext *adapter)
{
	struct cpfl_devargs *devargs = &adapter->devargs;
	int ret, i, j;

	/* check and refine repr args */
	for (i = 0; i < devargs->repr_args_num; i++) {
		struct rte_eth_devargs *eth_da = &devargs->repr_args[i];

		/* set default host_id to xeon host */
		if (eth_da->nb_mh_controllers == 0) {
			eth_da->nb_mh_controllers = 1;
			eth_da->mh_controllers[0] = CPFL_HOST_ID_HOST;
		} else {
			for (j = 0; j < eth_da->nb_mh_controllers; j++) {
				if (eth_da->mh_controllers[j] > CPFL_HOST_ID_ACC) {
					PMD_INIT_LOG(ERR, "Invalid Host ID %d",
						     eth_da->mh_controllers[j]);
					return -EINVAL;
				}
			}
		}

		/* set default pf to APF */
		if (eth_da->nb_ports == 0) {
			eth_da->nb_ports = 1;
			eth_da->ports[0] = CPFL_PF_TYPE_APF;
		} else {
			for (j = 0; j < eth_da->nb_ports; j++) {
				if (eth_da->ports[j] > CPFL_PF_TYPE_CPF) {
					PMD_INIT_LOG(ERR, "Invalid Host ID %d",
						     eth_da->ports[j]);
					return -EINVAL;
				}
			}
		}

		ret = cpfl_repr_devargs_process_one(adapter, eth_da);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_repr_whitelist_del(struct cpfl_adapter_ext *adapter,
			struct cpfl_repr_id *repr_id)
{
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);

	ret = rte_hash_del_key(adapter->repr_whitelist_hash, repr_id);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Failed to delete repr from whitelist."
				 "host_id = %d, type = %d, pf_id = %d, vf_id = %d",
				 repr_id->host_id, repr_id->type,
				 repr_id->pf_id, repr_id->vf_id);
		goto err;
	}

	rte_spinlock_unlock(&adapter->repr_lock);
	return 0;
err:
	rte_spinlock_unlock(&adapter->repr_lock);
	return ret;
}

static int
cpfl_repr_uninit(struct rte_eth_dev *eth_dev)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(eth_dev);
	struct cpfl_adapter_ext *adapter = repr->itf.adapter;

	eth_dev->data->mac_addrs = NULL;

	cpfl_repr_whitelist_del(adapter, &repr->repr_id);

	return 0;
}

static int
cpfl_repr_dev_configure(struct rte_eth_dev *dev)
{
	/* now only 1 RX queue is supported */
	if (dev->data->nb_rx_queues > 1)
		return -EINVAL;

	return 0;
}

static int
cpfl_repr_dev_close(struct rte_eth_dev *dev)
{
	return cpfl_repr_uninit(dev);
}

static int
cpfl_repr_dev_info_get(struct rte_eth_dev *ethdev,
		       struct rte_eth_dev_info *dev_info)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(ethdev);

	dev_info->device = ethdev->device;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;
	dev_info->min_rx_bufsize = CPFL_MIN_BUF_SIZE;
	dev_info->max_rx_pktlen = CPFL_MAX_FRAME_SIZE;

	dev_info->flow_type_rss_offloads = CPFL_RSS_OFFLOAD_ALL;

	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP		|
		RTE_ETH_RX_OFFLOAD_QINQ_STRIP		|
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_RX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_RX_OFFLOAD_SCATTER		|
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER		|
		RTE_ETH_RX_OFFLOAD_RSS_HASH		|
		RTE_ETH_RX_OFFLOAD_TIMESTAMP;

	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT		|
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT		|
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS		|
		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_free_thresh = CPFL_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = CPFL_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = CPFL_DEFAULT_TX_RS_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = CPFL_MAX_RING_DESC,
		.nb_min = CPFL_MIN_RING_DESC,
		.nb_align = CPFL_ALIGN_RING_DESC,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = CPFL_MAX_RING_DESC,
		.nb_min = CPFL_MIN_RING_DESC,
		.nb_align = CPFL_ALIGN_RING_DESC,
	};

	dev_info->switch_info.name = ethdev->device->name;
	dev_info->switch_info.domain_id = 0; /* the same domain*/
	dev_info->switch_info.port_id = repr->vport_info->loc.vsi_id;

	return 0;
}

static int
cpfl_repr_dev_start(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
cpfl_repr_dev_stop(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	dev->data->dev_started = 0;
	return 0;
}

static const struct eth_dev_ops cpfl_repr_dev_ops = {
	.dev_start		= cpfl_repr_dev_start,
	.dev_stop		= cpfl_repr_dev_stop,
	.dev_configure		= cpfl_repr_dev_configure,
	.dev_close		= cpfl_repr_dev_close,
	.dev_infos_get		= cpfl_repr_dev_info_get,
};

static int
cpfl_repr_init(struct rte_eth_dev *eth_dev, void *init_param)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(eth_dev);
	struct cpfl_repr_param *param = init_param;
	struct cpfl_adapter_ext *adapter = param->adapter;

	repr->repr_id = param->repr_id;
	repr->vport_info = param->vport_info;
	repr->itf.type = CPFL_ITF_TYPE_REPRESENTOR;
	repr->itf.adapter = adapter;
	repr->itf.data = eth_dev->data;

	eth_dev->dev_ops = &cpfl_repr_dev_ops;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	/* bit[15:14] type
	 * bit[13] xeon/acc
	 * bit[12] apf/cpf
	 * bit[11:0] vf
	 */
	eth_dev->data->representor_id =
		(uint16_t)(repr->repr_id.type << 14 |
			   repr->repr_id.host_id << 13 |
			   repr->repr_id.pf_id << 12 |
			   repr->repr_id.vf_id);

	return cpfl_repr_whitelist_update(adapter, &repr->repr_id, eth_dev);
}

static bool
match_host_pf_id(uint8_t repr_host_id __rte_unused,
		 uint8_t repr_pf_id __rte_unused,
		 uint8_t vport_host_id __rte_unused,
		 uint8_t vport_pf_id __rte_unused)
{
	/* Need to fix, right now only check host_id */
	if (repr_host_id == CPFL_HOST_ID_HOST && vport_host_id == 0)
		return true;

	if (repr_host_id == CPFL_HOST_ID_ACC && vport_host_id == 4)
		return true;

	return false;
}

static bool
match_repr_with_vport(const struct cpfl_repr_id *repr_id, struct cpchnl_vport_loc *loc)
{
	if (!match_host_pf_id(repr_id->host_id,
			      repr_id->pf_id,
			      loc->host_id,
			      loc->pf_num))
		return false;

	if (repr_id->type == RTE_ETH_REPRESENTOR_PF &&
	    loc->func_type == CPCHNL_VSI_FTYPE_PF)
		return true;

	if (repr_id->type == RTE_ETH_REPRESENTOR_VF &&
	    (loc->func_type == CPCHNL_VSI_FTYPE_VF ||
	    loc->func_type == CPCHNL_VSI_FTYPE_VM))
		return repr_id->vf_id == loc->vf_vm_num;

	return false;
}

int
cpfl_repr_create(struct rte_pci_device *pci_dev, struct cpfl_adapter_ext *adapter)
{
	struct rte_eth_dev *dev;
	uint32_t iter = 0;
	const struct cpfl_repr_id *repr_id;
	const struct cpfl_vport_id *vp_id;
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);

	while (rte_hash_iterate(adapter->repr_whitelist_hash,
				(const void **)&repr_id, (void **)&dev, &iter) >= 0) {
		struct cpfl_vport_info *vi;
		char name[RTE_ETH_NAME_MAX_LEN];
		uint32_t iter_iter = 0;
		bool matched;

		/* skip representor already be created */
		if (dev != NULL)
			continue;

		if (repr_id->type == RTE_ETH_REPRESENTOR_VF)
			snprintf(name, sizeof(name), "cpfl_%s_rep_c%dpf%dvf%d",
				 pci_dev->device.name,
				 repr_id->host_id,
				 repr_id->pf_id,
				 repr_id->vf_id);
		else
			snprintf(name, sizeof(name), "cpfl_%s_rep_c%dpf%d",
				 pci_dev->device.name,
				 repr_id->host_id,
				 repr_id->pf_id);

		/* find a matched vport */
		rte_spinlock_lock(&adapter->vport_map_lock);

		matched = false;
		while (rte_hash_iterate(adapter->vport_map_hash,
					(const void **)&vp_id, (void **)&vi, &iter_iter) >= 0) {
			struct cpfl_repr_param param;

			if (!match_repr_with_vport(repr_id, &vi->loc))
				continue;

			param.adapter = adapter;
			param.repr_id = *repr_id;
			param.vport_info = vi;

			ret = rte_eth_dev_create(&pci_dev->device,
						 name,
						 sizeof(struct cpfl_repr),
						 NULL, NULL, cpfl_repr_init,
						 &param);
			if (ret != 0) {
				PMD_INIT_LOG(ERR, "Failed to create representor %s", name);
				rte_spinlock_unlock(&adapter->vport_map_lock);
				rte_spinlock_unlock(&adapter->repr_lock);
				return ret;
			}
		}

		/* warning if no match vport detected */
		if (!matched)
			PMD_INIT_LOG(WARNING, "No matched vport for representor %s "
					      "creation will be deferred when vport is detected",
					      name);

		rte_spinlock_unlock(&adapter->vport_map_lock);
	}

	rte_spinlock_unlock(&adapter->repr_lock);

	return 0;
}

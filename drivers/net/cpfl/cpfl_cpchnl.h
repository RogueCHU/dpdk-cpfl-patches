/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _IDPF_CPCHNL_H_
#define _IDPF_CPCHNL_H_

#define CPCHNL_OP_EVENT_NOTIFICATION	0xA000

/* Cpchnl vsi func types */
enum cpchnl_vsi_ftype {
	CPCHNL_VSI_FTYPE_VF = 0x0,
	CPCHNL_VSI_FTYPE_VM = 0x1,
	CPCHNL_VSI_FTYPE_PF = 0x2,
};

enum cpchnl_event {
	CPCHNL_EVENT_UNKNOWN = 0,
	CPCHNL_EVENT_VPORT_CREATED,
	CPCHNL_EVENT_VPORT_DESTROYED,
	CPCHNL_EVENT_VPORT_ENABLED,
	CPCHNL_EVENT_VPORT_DISABLED,
	CPCHNL_EVENT_LINK_STATUS,
};

/* Cpchnl location informaion */
struct cpchnl_vport_loc {
	__le32 vport_id;
	__le16 vsi_id;
	__le16 vf_vm_num;
	/* See enum cpchnl_vsi_ftype */
	s32 func_type;
	u8 pf_num;
	u8 host_id;
	u8 pad[2];
};

enum cpchnl_link_event {
	CPCHNL_EVENT_LINK_STATE_CHANGED,
};

#define CPCHNL_ETH_LENGTH_OF_ADDRESS    6
struct cpchl_event_info {
	/* See enum cpchnl_event */
	s32 event;
	union {
		/* This is for CPCHNL_EVENT_VPORT_CREATED */
		struct {
			struct cpchnl_vport_loc vport;
#ifndef LINUX_SUPPORT
			u8 mac_addr[CPCHNL_ETH_LENGTH_OF_ADDRESS];
#else
			u8 mac_addr[ETH_ALEN];
#endif
			__le16 num_tx_q;
			__le16 num_rx_q;
			__le16 max_mtu;
		} vport_created;
		/* This is for vPort events other than
		 * CPCHNL_EVENT_VPORT_CREATED
		 */
		struct {
			__le32 vport_id;
		} vport_events;
		/* This is for CPCHNL_EVENT_LINK_STATUS */
		struct {
			u8  port_num;  /* Logical port number */
			u8  pad[3];
			/* See enum cpchnl_link_event */
			s32 event_id;
			/* See enum cpchnl_port_link_state */
			s32 link_state;
			/* See enum cpchnl_link_speed */
			s32 link_speed;
		} link_event;
	} data;
};

#endif /* _IDPF_CPCHNL_H_ */

/* SPDX-Lcpflnse-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <stdio.h>
#include <stdlib.h>

#include "cpfl_flow_js_parser.h"

typedef struct json_object json_object;
#define SUCCESS 1
#define NOT_MATCH -1
#define NOT_SUPPORT -2
#define INVALID -3

static void
cpfl_parse_version(json_object *cjson_ver, struct cpfl_js_version *version)
{
	json_object *spec, *dpdk, *package, *ob;
	const char *s;

	spec = json_object_object_get(cjson_ver, "spec");
	s = json_object_get_string(json_object_object_get(spec, "version"));
	memcpy(version->spec.version, s, strlen(s) + 1);
	version->spec.ignore = json_object_get_int(json_object_object_get(spec, "ignore"));

	dpdk = json_object_object_get(cjson_ver, "dpdk");
	version->dpdk.version = json_object_get_int(json_object_object_get(dpdk, "version"));
	version->dpdk.ignore = json_object_get_int(json_object_object_get(dpdk, "ignore"));

	package = json_object_object_get(cjson_ver, "package");
	s = json_object_get_string(json_object_object_get(package, "version"));
	memcpy(version->package.version, s, strlen(s) + 1);
	ob = json_object_object_get(package, "name");
	if (ob)
		version->package.name = json_object_get_string(ob);
	else
		version->package.name = NULL;

	version->package.ignore = json_object_get_int(json_object_object_get(package, "ignore"));
}

static void
cpfl_parse_fv_metadata(json_object *cjson_value, struct cpfl_itf *itf,
		       uint16_t offset, uint8_t *fv)
{
	uint16_t type, v_offset, mask, data;

	type = json_object_get_int(json_object_object_get(cjson_value, "type"));
	v_offset = json_object_get_int(json_object_object_get(cjson_value, "offset"));
	mask = json_object_get_int(json_object_object_get(cjson_value, "mask"));

	data = cpfl_metadata_read16(&itf->adapter->meta, type, v_offset) & mask;
	fv[2 * offset] = (uint8_t)(data & 0x00ff);
	fv[2 * offset + 1] = (uint8_t)((data & 0xff00) >> 8);
}

static void
cpfl_parse_fv_protocol_last(const struct rte_flow_item *items, const uint8_t *pointer,
			    uint16_t offset, uint16_t v_offset, uint16_t v_mask,
			    struct cpfl_batch_item *range)
{
	const uint8_t *p_last;
	const void *item_last = items->last;

	p_last = &(((const uint8_t *)(item_last))[v_offset]);
	if (items->type == RTE_FLOW_ITEM_TYPE_IPV4) {
		uint16_t end_l, start_l, end_h, start_h;

		end_l = ntohs((*((const uint16_t *)(p_last + 2))) & v_mask);
		end_h = ntohs((*((const uint16_t *)(p_last))) & v_mask);
		if (end_l == 0 && end_h == 0)
			return;
		start_l = ntohs((*((const uint16_t *)(pointer + 2))) & v_mask);
		start_h = ntohs((*((const uint16_t *)pointer)) & v_mask);
		range->start.num32 = (((uint32_t)start_h) << 16) | start_l;
		range->end.num32 = (((uint32_t)end_h) << 16) | end_l;
		if (range->start.num32 >= range->end.num32) {
			range->batch_rule_valid = FALSE;
			PMD_DRV_LOG(ERR, "batch range is not correct");
			return;
		}
		range->offset = offset;
#define RANGE_NUM 0xfffff
		if (range->end.num32 - range->start.num32 > RANGE_NUM) {
			range->batch_rule_valid = FALSE;
			PMD_DRV_LOG(ERR, "batch range is too big");
			return;
		}
		range->num = range->end.num32 - range->start.num32 + 1;
	} else if (items->type == RTE_FLOW_ITEM_TYPE_TCP ||
		   items->type == RTE_FLOW_ITEM_TYPE_UDP) {
		uint16_t end, start;

		end = ntohs((*((const uint16_t *)p_last)) & v_mask);
		if (end == 0)
			return;
		start = ntohs((*((const uint16_t *)pointer)) & v_mask);
		if (start >= end) {
			range->batch_rule_valid = FALSE;
			PMD_DRV_LOG(ERR, "batch range is not correct");
			return;
		}
		range->num = end - start + 1;
		range->end.num16 = end;
		range->start.num16 = start;
		range->offset = offset;
	} else if (items->type == RTE_FLOW_ITEM_TYPE_ETH) {
		/* only support low 16 bits */
		uint16_t end, start;

		end = ntohs((*((const uint16_t *)(p_last + 4))) & v_mask);
		if (end == 0)
			return;
		start = ntohs((*((const uint16_t *)(pointer + 4))) & v_mask);
		if (start >= end) {
			range->batch_rule_valid = FALSE;
			PMD_DRV_LOG(ERR, "batch range is not correct");
			return;
		}
		range->num = end - start + 1;
		range->end.num16 = end;
		range->start.num16 = start;
		range->offset = offset + 2;
	} else {
		PMD_DRV_LOG(DEBUG, "not support this last item: %d.", items->type);
		return;
	}
	range->batch_rule_valid = TRUE;
	range->v_offset = v_offset;
	range->v_mask = v_mask;
	range->type = items->type;
}

static void
cpfl_parse_fv_protocol(json_object *cjson_value, const struct rte_flow_item *items,
		       uint16_t offset, uint8_t *fv, struct cpfl_batch_item *range)
{
	uint16_t v_layer, v_offset, v_mask;
	const char *v_header;
	int j, layer, length;
	uint16_t temp_fv;

	length = 0;
	while ((items + length++)->type != RTE_FLOW_ITEM_TYPE_END)
		continue;

	v_layer = json_object_get_int(json_object_object_get(cjson_value, "layer"));
	v_header = json_object_get_string(json_object_object_get(cjson_value, "header"));
	v_offset = json_object_get_int(json_object_object_get(cjson_value, "offset"));
	v_mask = json_object_get_int(json_object_object_get(cjson_value, "mask"));
	layer = 0;
	for (j = 0; j < length - 1; j++) {
		if ((strcmp(v_header, "eth") == 0 && items[j].type == RTE_FLOW_ITEM_TYPE_ETH) ||
		    (strcmp(v_header, "ipv4") == 0 && items[j].type == RTE_FLOW_ITEM_TYPE_IPV4) ||
		    (strcmp(v_header, "tcp") == 0 && items[j].type == RTE_FLOW_ITEM_TYPE_TCP) ||
		    (strcmp(v_header, "udp") == 0 && items[j].type == RTE_FLOW_ITEM_TYPE_UDP) ||
		    (strcmp(v_header, "vxlan") == 0 && items[j].type == RTE_FLOW_ITEM_TYPE_VXLAN)) {
			if (layer == v_layer) {
				/* copy out 16 bits from offset
				 */
				const uint8_t *pointer;

				pointer = &(((const uint8_t *)(items[j].spec))[v_offset]);
				temp_fv = ntohs((*((const uint16_t *)pointer)) & v_mask);
				fv[2 * offset] = (uint8_t)((temp_fv & 0xff00) >> 8);
				fv[2 * offset + 1] = (uint8_t)(temp_fv & 0x00ff);
				if (items[j].last && !range->batch_rule_valid) {
					cpfl_parse_fv_protocol_last(&items[j], pointer, offset,
								    v_offset, v_mask, range);
				}
				break;
			}
			layer++;
		} /* TODO: more type... */
	}
}

static void
cpfl_parse_fieldvectors(json_object *cjson_fv, uint8_t *fv, const struct rte_flow_item *items,
			struct cpfl_itf *itf, struct cpfl_batch_item *range)
{
	int size, i, length;

	length = 0;
	while ((items + length++)->type != RTE_FLOW_ITEM_TYPE_END)
		continue;
	size = json_object_array_length(cjson_fv);
	for (i = 0; i < size; i++) {
		json_object *object, *cjson_value;
		uint16_t offset;
		uint16_t temp_fv;
		const char *type;

		object = json_object_array_get_idx(cjson_fv, i);
		offset = json_object_get_int(json_object_object_get(object, "offset"));
		type = json_object_get_string(json_object_object_get(object, "type"));
		cjson_value = json_object_object_get(object, "value");
		/* type=int */
		if (strcmp(type, "immediate") == 0) {
			uint16_t value_int;

			value_int = json_object_get_int(cjson_value);

			temp_fv = (value_int << 8) & 0xff00;
			fv[2 * offset] = (uint8_t)((temp_fv & 0xff00) >> 8);
			fv[2 * offset + 1] = (uint8_t)(temp_fv & 0x00ff);
		} else if (strcmp(type, "metadata") == 0) {
			cpfl_parse_fv_metadata(cjson_value, itf, offset, fv);
		} else if (strcmp(type, "protocol") == 0) {
			cpfl_parse_fv_protocol(cjson_value, items, offset, fv, range);
		} else {
			PMD_DRV_LOG(DEBUG, "not support this type: %s.", type);
		}
	}
}

static int
cpfl_parse_pr_actions(json_object *cjson_pr_actions, const struct rte_flow_item *items,
		      const struct rte_flow_attr *attr, struct cpfl_itf *itf,
		      struct cpfl_js_pr_action *pr_action, struct cpfl_batch_item *range)
{
	int i, size;

	size = json_object_array_length(cjson_pr_actions);
	for (i = 0; i < size; i++) {
		json_object *object;
		const char *type;

		object = json_object_array_get_idx(cjson_pr_actions, i);
		/* pr->actions->type */
		type = json_object_get_string(json_object_object_get(object, "type"));
		/* pr->actions->data */
		if (attr->group == 1 && strcmp(type, "sem") == 0) {
			json_object *cjson_fv, *cjson_pr_action_sem, *cjson_prof, *cjson_ks,
			*cjson_subprof;

			pr_action->type = CPFL_JS_PR_ACTION_TYPE_SEM;
			cjson_pr_action_sem = json_object_object_get(object, "data");
			cjson_prof = json_object_object_get(cjson_pr_action_sem, "profile");
			pr_action->sem.prof = json_object_get_int(cjson_prof);
			cjson_subprof = json_object_object_get(cjson_pr_action_sem, "subprofile");
			pr_action->sem.subprof = json_object_get_int(cjson_subprof);
			cjson_ks = json_object_object_get(cjson_pr_action_sem, "keysize");
			pr_action->sem.keysize = json_object_get_int(cjson_ks);
			cjson_fv = json_object_object_get(cjson_pr_action_sem, "fieldvectors");
			memset(pr_action->sem.cpfl_js_pr_fv, 0,
			       sizeof(pr_action->sem.cpfl_js_pr_fv));
			cpfl_parse_fieldvectors(cjson_fv, pr_action->sem.cpfl_js_pr_fv,
						items, itf, range);
			return SUCCESS;
		} else if (attr->group == 4 && strcmp(type, "lem") == 0) {
			/* not test */
			json_object *cjson_fv, *cjson_pr_action_lem, *cjson_prof, *cjson_ks;

			pr_action->type = CPFL_JS_PR_ACTION_TYPE_LEM;
			cjson_pr_action_lem = json_object_object_get(object, "data");
			cjson_prof = json_object_object_get(cjson_pr_action_lem, "profile");
			pr_action->lem.prof = json_object_get_int(cjson_prof);
			cjson_ks = json_object_object_get(cjson_pr_action_lem, "keysize");
			pr_action->lem.keysize = json_object_get_int(cjson_ks);
			cjson_fv = json_object_object_get(cjson_pr_action_lem, "fieldvectors");
			memset(pr_action->lem.cpfl_js_pr_fv, 0,
			       sizeof(pr_action->lem.cpfl_js_pr_fv));
			cpfl_parse_fieldvectors(cjson_fv, pr_action->lem.cpfl_js_pr_fv,
						items, itf, range);
			return SUCCESS;
		} else if (attr->group == 2 && strcmp(type, "wcm") == 0) {
			/* TODO */
			return NOT_SUPPORT;
		} else if (attr->group == 3 && strcmp(type, "lpm") == 0) {
			/* TODO */
			PMD_DRV_LOG(DEBUG, "Not support LPM.\n");
			return NOT_SUPPORT;
		} else if (attr->group > 3) {
			return NOT_SUPPORT;
		}
	}
	return NOT_MATCH;
}

static int
str2MAC(const char *mask, uint8_t *addr_bytes)
{
	int i, size, j;
	uint8_t n;

	size = strlen(mask);
	n = 0;
	j = 0;
	for (i = 0; i < size; i++) {
		char ch = mask[i];

		if (ch == ':') {
			if (j >= RTE_ETHER_ADDR_LEN)
				return INVALID;
			addr_bytes[j++] = n;
			n = 0;
		} else if (ch >= 'a' && ch <= 'f') {
			n = n * 16 + ch - 'a' + 10;
		} else if (ch >= 'A' && ch <= 'F') {
			n = n * 16 + ch - 'A' + 10;
		} else if (ch >= '0' && ch <= '9') {
			n = n * 16 + ch - '0';
		} else {
			return INVALID;
		}
	}
	if (j < RTE_ETHER_ADDR_LEN)
		addr_bytes[j++] = n;

	if (j != RTE_ETHER_ADDR_LEN)
		return INVALID;
	return SUCCESS;
}

static int
cpfl_check_eth_mask(const char *mask, const uint8_t addr_bytes[RTE_ETHER_ADDR_LEN])
{
	int i, ret;
	uint8_t mask_bytes[RTE_ETHER_ADDR_LEN] = {0};

	ret = str2MAC(mask, mask_bytes);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "string to mac address failed.\n");
		return INVALID;
	}
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (mask_bytes[i] != addr_bytes[i])
			return NOT_MATCH;
	}
	return SUCCESS;
}

static int
cpfl_check_ipv4_mask(const char *mask, rte_be32_t addr)
{
	uint32_t out_addr;

	/* success return 1; invalid return 0; fail return -1 */
	int ret = inet_pton(AF_INET, mask, &out_addr);

	if (ret <= 0)
		return INVALID;

	if (out_addr != addr)
		return NOT_MATCH;

	return SUCCESS;
}

static int
cpfl_check_eth(json_object *cjson_pr_key_proto_fields, const struct rte_flow_item_eth *eth_mask)
{
	/* eth_mask->dst.addr_bytes */
	if (cjson_pr_key_proto_fields) {
		int field_size, j;
		int flag_dst_addr, flag_src_addr, flag_ether_type;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !eth_mask)
			return NOT_MATCH;

		if (field_size == 0 && eth_mask)
			return NOT_MATCH;

		if (field_size == 0 && !eth_mask)
			return SUCCESS;

		flag_dst_addr = false;
		flag_src_addr = false;
		flag_ether_type = false;
		for (j = 0; j < field_size; j++) {
			json_object *subobject, *cjson_mask;
			const char *name, *s_mask;

			subobject = json_object_array_get_idx(cjson_pr_key_proto_fields, j);
			/* match: rte_flow_item_eth.dst, more see Field Mapping
			 */
			name = json_object_get_string(json_object_object_get(subobject, "name"));
			/* match: rte_flow_item->mask */

			if (strcmp(name, "src_addr") == 0) {
				cjson_mask = json_object_object_get(subobject, "mask");
				s_mask = json_object_get_string(cjson_mask);

				if (cpfl_check_eth_mask(s_mask, eth_mask->src.addr_bytes) < 0)
					return NOT_MATCH;

				flag_src_addr = true;
			} else if (strcmp(name, "dst_addr") == 0) {
				cjson_mask = json_object_object_get(subobject, "mask");
				s_mask = json_object_get_string(cjson_mask);

				if (cpfl_check_eth_mask(s_mask, eth_mask->dst.addr_bytes) < 0)
					return NOT_MATCH;

				flag_dst_addr = true;
			} else if (strcmp(name, "ether_type") == 0) {
				cjson_mask = json_object_object_get(subobject, "mask");
				uint16_t mask = json_object_get_int(cjson_mask);

				if (mask != eth_mask->type)
					return NOT_MATCH;

				flag_ether_type = true;
			} else {
				/* TODO: more type... */
				return NOT_SUPPORT;
			}
		}
		if (!flag_src_addr) {
			if (strcmp((const char *)eth_mask->src.addr_bytes,
				   "\x00\x00\x00\x00\x00\x00") != 0)
				return NOT_MATCH;
		}
		if (!flag_dst_addr) {
			if (strcmp((const char *)eth_mask->dst.addr_bytes,
				   "\x00\x00\x00\x00\x00\x00") != 0)
				return NOT_MATCH;
		}
		if (!flag_ether_type) {
			if (eth_mask->hdr.ether_type != (rte_be16_t)0)
				return NOT_MATCH;
		}
	}
	return SUCCESS;
}

static int
cpfl_check_ipv4(json_object *cjson_pr_key_proto_fields, const struct rte_flow_item_ipv4 *ipv4_mask)
{
	if (cjson_pr_key_proto_fields) {
		int field_size, j;
		int flag_next_proto_id, flag_src_addr, flag_dst_addr;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !ipv4_mask)
			return NOT_MATCH;

		if (field_size == 0 && ipv4_mask)
			return NOT_MATCH;

		if (field_size == 0 && !ipv4_mask)
			return SUCCESS;

		flag_dst_addr = false;
		flag_src_addr = false;
		flag_next_proto_id = false;
		for (j = 0; j < field_size; j++) {
			json_object *subobject;
			const char *name;

			subobject = json_object_array_get_idx(cjson_pr_key_proto_fields, j);
			/* match: rte_flow_item_eth.dst, more see Field Mapping
			 */
			name = json_object_get_string(json_object_object_get(subobject, "name"));
			if (strcmp(name, "src_addr") == 0) {
				/* match: rte_flow_item->mask */
				const char *mask;
				json_object *cjson_mask;

				cjson_mask = json_object_object_get(subobject, "mask");
				mask = json_object_get_string(cjson_mask);
				if (cpfl_check_ipv4_mask(mask, ipv4_mask->hdr.src_addr) < 0)
					return NOT_MATCH;

				flag_src_addr = true;
			} else if (strcmp(name, "dst_addr") == 0) {
				const char *mask;
				json_object *cjson_mask;

				cjson_mask = json_object_object_get(subobject, "mask");
				mask = json_object_get_string(cjson_mask);
				if (cpfl_check_ipv4_mask(mask, ipv4_mask->hdr.dst_addr) < 0)
					return NOT_MATCH;

				flag_dst_addr = true;
			} else if (strcmp(name, "next_proto_id") == 0) {
				uint8_t mask;

				mask =
				    json_object_get_int(json_object_object_get(subobject, "mask"));
				if (mask != ipv4_mask->hdr.next_proto_id)
					return NOT_MATCH;

				flag_next_proto_id = true;
			} else {
				return NOT_SUPPORT;
			}
		}
		if (!flag_src_addr) {
			if (ipv4_mask->hdr.src_addr != (rte_be32_t)0)
				return NOT_MATCH;
		}
		if (!flag_dst_addr) {
			if (ipv4_mask->hdr.dst_addr != (rte_be32_t)0)
				return NOT_MATCH;
		}
		if (!flag_next_proto_id) {
			if (ipv4_mask->hdr.next_proto_id != (uint8_t)0)
				return NOT_MATCH;
		}
	}
	return SUCCESS;
}

static int
cpfl_check_tcp(json_object *cjson_pr_key_proto_fields, const struct rte_flow_item_tcp *tcp_mask)
{
	if (cjson_pr_key_proto_fields) {
		int field_size, j;
		int flag_src_port, flag_dst_port;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !tcp_mask)
			return NOT_MATCH;

		if (field_size == 0 && tcp_mask)
			return NOT_MATCH;

		if (field_size == 0 && !tcp_mask)
			return SUCCESS;

		flag_src_port = false;
		flag_dst_port = false;
		for (j = 0; j < field_size; j++) {
			json_object *subobject;
			const char *name;
			uint16_t mask;

			subobject = json_object_array_get_idx(cjson_pr_key_proto_fields, j);
			/* match: rte_flow_item_eth.dst, more see Field Mapping
			 */
			name = json_object_get_string(json_object_object_get(subobject, "name"));
			/* match: rte_flow_item->mask */
			mask = json_object_get_int(json_object_object_get(subobject, "mask"));
			if (strcmp(name, "src_port") == 0) {
				if (tcp_mask->hdr.src_port != mask)
					return NOT_MATCH;

				flag_src_port = true;
			} else if (strcmp(name, "dst_port") == 0) {
				if (tcp_mask->hdr.dst_port != mask)
					return NOT_MATCH;

				flag_dst_port = true;
			} else {
				return NOT_SUPPORT;
			}
		}
		if (!flag_src_port) {
			if (tcp_mask->hdr.src_port != (rte_be16_t)0)
				return NOT_MATCH;
		}
		if (!flag_dst_port) {
			if (tcp_mask->hdr.dst_port != (rte_be16_t)0)
				return NOT_MATCH;
		}
	}
	return SUCCESS;
}

static int
cpfl_check_udp(json_object *cjson_pr_key_proto_fields, const struct rte_flow_item_udp *udp_mask)
{
	if (cjson_pr_key_proto_fields) {
		int field_size, j;
		bool flag_src_port, flag_dst_port;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !udp_mask)
			return NOT_MATCH;

		if (field_size == 0 && udp_mask)
			return NOT_MATCH;

		if (field_size == 0 && !udp_mask)
			return SUCCESS;

		flag_src_port = false;
		flag_dst_port = false;
		for (j = 0; j < field_size; j++) {
			json_object *subobject;
			const char *name;
			uint16_t mask;

			subobject = json_object_array_get_idx(cjson_pr_key_proto_fields, j);
			/* match: rte_flow_item_eth.dst */
			name = json_object_get_string(json_object_object_get(subobject, "name"));
			/* match: rte_flow_item->mask */
			mask = json_object_get_int(json_object_object_get(subobject, "mask"));
			if (strcmp(name, "src_port") == 0) {
				if (udp_mask->hdr.src_port != mask)
					return NOT_MATCH;

				flag_src_port = true;
			} else if (strcmp(name, "dst_port") == 0) {
				if (udp_mask->hdr.dst_port != mask)
					return NOT_MATCH;

				flag_dst_port = true;
			} else {
				return NOT_SUPPORT;
			}
		}
		if (!flag_src_port) {
			if (udp_mask->hdr.src_port != (rte_be16_t)0)
				return NOT_MATCH;
		}
		if (!flag_dst_port) {
			if (udp_mask->hdr.dst_port != (rte_be16_t)0)
				return NOT_MATCH;
		}
	}
	return SUCCESS;
}

static int
cpfl_check_vxlan(json_object *cjson_pr_key_proto_fields,
		 const struct rte_flow_item_vxlan *vxlan_mask)
{
	if (cjson_pr_key_proto_fields) {
		int field_size, j;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !vxlan_mask)
			return NOT_MATCH;

		if (field_size == 0 && vxlan_mask)
			return NOT_MATCH;

		if (field_size == 0 && !vxlan_mask)
			return SUCCESS;

		for (j = 0; j < field_size; j++) {
			json_object *subobject;
			const char *name;
			int64_t mask;

			subobject = json_object_array_get_idx(cjson_pr_key_proto_fields, j);
			name = json_object_get_string(json_object_object_get(subobject, "name"));
			/* match: rte_flow_item->mask */
			mask = json_object_get_int64(json_object_object_get(subobject, "mask"));
			if (strcmp(name, "vx_vni") == 0) {
				if ((int64_t)RTE_BE32(vxlan_mask->hdr.vx_vni) != mask)
					return NOT_MATCH;
			}
		}
	}
	return SUCCESS;
}
static int
cpfl_check_icmp(json_object *cjson_pr_key_proto_fields,
		 const struct rte_flow_item_icmp *icmp_mask)
{
	if (cjson_pr_key_proto_fields) {
		int field_size;

		field_size = json_object_array_length(cjson_pr_key_proto_fields);
		if (field_size != 0 && !icmp_mask)
			return NOT_MATCH;

		if (field_size == 0 && icmp_mask)
			return NOT_MATCH;

		if (field_size == 0 && !icmp_mask)
			return SUCCESS;
	}
	return SUCCESS;
}
static int
cpfl_check_pattern_key_proto(json_object *cjson_pr_key_proto, const struct rte_flow_item *items)
{
	int size, i, length;

	size = json_object_array_length(cjson_pr_key_proto);
	length = 0;
	while ((items + length++)->type != RTE_FLOW_ITEM_TYPE_END)
		continue;

	if (size + 1 != length)
		return NOT_MATCH;

	for (i = 0; i < size; i++) {
		json_object *object, *cjson_pr_key_proto_type, *cjson_pr_key_proto_fields;
		const char *type;

		object = json_object_array_get_idx(cjson_pr_key_proto, i);
		/* pr->key->proto->type */
		cjson_pr_key_proto_type = json_object_object_get(object, "type");
		/* match: map type to a "enum rte_flow_item_type" */
		type = json_object_get_string(cjson_pr_key_proto_type);
		/* pr->key->proto->fields */
		cjson_pr_key_proto_fields = json_object_object_get(object, "fields");
		if (strcmp(type, "eth") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_ETH) {
				const struct rte_flow_item_eth *eth_mask;
				int ret;

				eth_mask = (const struct rte_flow_item_eth *)items[i].mask;
				ret = cpfl_check_eth(cjson_pr_key_proto_fields, eth_mask);
				if (ret < 0)
					return ret;
			} else {
				return NOT_MATCH;
			}
		} else if (strcmp(type, "ipv4") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_IPV4) {
				const struct rte_flow_item_ipv4 *ipv4_mask;
				int ret;

				ipv4_mask = (const struct rte_flow_item_ipv4 *)items[i].mask;
				ret = cpfl_check_ipv4(cjson_pr_key_proto_fields, ipv4_mask);
				if (ret < 0)
					return ret;
			} else {
				return NOT_MATCH;
			}
		} else if (strcmp(type, "tcp") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_TCP) {
				const struct rte_flow_item_tcp *tcp_mask;
				int ret;

				tcp_mask = (const struct rte_flow_item_tcp *)items[i].mask;
				ret = cpfl_check_tcp(cjson_pr_key_proto_fields, tcp_mask);
				if (ret < 0)
					return ret;
			} else {
				return NOT_MATCH;
			}
		} else if (strcmp(type, "udp") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_UDP) {
				const struct rte_flow_item_udp *udp_mask;
				int ret;

				udp_mask = (const struct rte_flow_item_udp *)items[i].mask;
				ret = cpfl_check_udp(cjson_pr_key_proto_fields, udp_mask);
				if (ret < 0)
					return ret;
			} else {
				return NOT_MATCH;
			}
		} else if (strcmp(type, "vxlan") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_VXLAN) {
				const struct rte_flow_item_vxlan *vxlan_mask;
				int ret;

				vxlan_mask = (const struct rte_flow_item_vxlan *)items[i].mask;
				ret = cpfl_check_vxlan(cjson_pr_key_proto_fields, vxlan_mask);
				if (ret < 0)
					return ret;

			} else {
				return NOT_MATCH;
			}
		} else if (strcmp(type, "icmp") == 0) {
			if (items[i].type == RTE_FLOW_ITEM_TYPE_ICMP) {
				const struct rte_flow_item_icmp *icmp_mask;
				int ret;

				icmp_mask = (const struct rte_flow_item_icmp *)items[i].mask;
				ret = cpfl_check_icmp(cjson_pr_key_proto_fields, icmp_mask);
				if (ret < 0)
					return ret;

			} else {
				return NOT_MATCH;
			}
		} else {
			PMD_DRV_LOG(ERR, "Not support type %s.\n", type);
			return NOT_SUPPORT;
		} /* TODO:more type... */
	}
	return SUCCESS;
}

static int
cpfl_check_pattern_key_attr(json_object *cjson_pr_key_attr, const struct rte_flow_attr *attr)
{
	int j, size;

	size = json_object_array_length(cjson_pr_key_attr);
	for (j = 0; j < size; j++) {
		json_object *subobject;
		const char *name;
		int value;

		subobject = json_object_array_get_idx(cjson_pr_key_attr, j);
		/* match: struct rte_flow_attr(ingress,egress) */
		name = json_object_get_string(json_object_object_get(subobject, "Name"));
		value = json_object_get_int(json_object_object_get(subobject, "Value"));
		if (strcmp(name, "ingress") == 0) {
			if (value != attr->ingress)
				return NOT_MATCH;

		} else if (strcmp(name, "egress") == 0) {
			if (value != attr->egress)
				return NOT_MATCH;
		} else {
			/* TODO: more... */
			PMD_DRV_LOG(ERR, "Not support attr name %s.\n", name);
			return NOT_SUPPORT;
		}
	}
	return SUCCESS;
}

/* output: struct cpfl_js_pr_action* pr_action */
static int
cpfl_parse_pattern_rules(json_object *cjson_pr, const struct rte_flow_item *items,
			 const struct rte_flow_attr *attr, struct cpfl_itf *itf,
			 struct cpfl_js_pr_action *pr_action, struct cpfl_batch_item *range)
{
	int i, size;

	size = json_object_array_length(cjson_pr);
	for (i = 0; i < size; i++) {
		json_object *object, *cjson_pr_actions, *cjson_pr_key, *cjson_pr_key_proto,
		    *cjson_pr_key_attr;
		int ret;

		object = json_object_array_get_idx(cjson_pr, i);
		/* pr->key */
		cjson_pr_key = json_object_object_get(object, "key");
		/* pr->key->protocols */
		cjson_pr_key_proto = json_object_object_get(cjson_pr_key, "protocols");
		ret = cpfl_check_pattern_key_proto(cjson_pr_key_proto, items);
		if (ret < 0)
			continue;

		/* pr->key->attributes */
		cjson_pr_key_attr = json_object_object_get(cjson_pr_key, "attributes");
		ret = cpfl_check_pattern_key_attr(cjson_pr_key_attr, attr);
		if (ret < 0)
			continue;
		/* pr->actions */
		cjson_pr_actions = json_object_object_get(object, "actions");
		ret = cpfl_parse_pr_actions(cjson_pr_actions, items, attr, itf, pr_action, range);
		return ret;
	}
	return NOT_MATCH;
}

int
cpfl_parse_items_attr(struct cpfl_js_flow_parser *parser, const struct rte_flow_item *items,
		      const struct rte_flow_attr *attr, struct cpfl_itf *itf,
		      struct cpfl_js_pr_action *pr_action, struct cpfl_batch_item *range)
{
	int ret;
	json_object *cjson_pr;

	/* Pattern Rules */
	cjson_pr = json_object_object_get(parser->json_root, "patterns");
	if (!cjson_pr) {
		PMD_DRV_LOG(ERR, "The patterns is mandatory.\n");
		return NOT_MATCH;
	}
	ret = cpfl_parse_pattern_rules(cjson_pr, items, attr, itf, pr_action, range);
	return ret;
}

/* modifications rules */
static int
cpfl_check_actions_vxlan_encap(struct cpfl_js_mr_key_action_vxlan_encap *encap,
			       const struct rte_flow_action *action)
{
	const struct rte_flow_action_vxlan_encap *action_vxlan_encap;
	struct rte_flow_item *definition;
	int def_length, i, proto_size;

	action_vxlan_encap = (const struct rte_flow_action_vxlan_encap *)action->conf;
	definition = action_vxlan_encap->definition;
	def_length = 0;
	while ((definition + def_length++)->type != RTE_FLOW_ITEM_TYPE_END)
		continue;
	proto_size = encap->proto_size;
	if (proto_size != def_length)
		return NOT_MATCH;
	if (strcmp(encap->protocols[0], "vxlan_encap") != 0)
		return NOT_MATCH;

	for (i = 0; i < proto_size - 1; i++) {
		const char *s;

		s = encap->protocols[i + 1];
		if (strcmp(s, "eth") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_ETH)
				return NOT_MATCH;
			/* else if (i + 1 < proto_size - 1 && definition[i +
			 *  1].type == RTE_FLOW_ITEM_TYPE_VLAN)
			 *  {
			 *	eth vlan? ipv4
			 *	i++;
			 *  }
			 */
		} else if (strcmp(s, "vlan") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_VOID)
				return NOT_MATCH;
		} else if (strcmp(s, "ipv4") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_IPV4)
				return NOT_MATCH;
		} else if (strcmp(s, "udp") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_UDP)
				return NOT_MATCH;
		} else if (strcmp(s, "tcp") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_TCP)
				return NOT_MATCH;
		} else if (strcmp(s, "vxlan") == 0) {
			if (definition[i].type != RTE_FLOW_ITEM_TYPE_VXLAN)
				return NOT_MATCH;
		} else {
			PMD_DRV_LOG(ERR, "Not support protocol %s.\n", s);
			return NOT_SUPPORT;
			/* TODO: more type... */
		}
	}
	// printf("check actions items.\n");
	return SUCCESS;
}

static int
cpfl_check_actions_modify_field(struct cpfl_js_mr_key_action_modify_field *field,
				const struct rte_flow_action *action)
{
	const struct rte_flow_action_modify_field *modify_field;

	modify_field = (const struct rte_flow_action_modify_field *)action->conf;
	if (field->op != modify_field->operation || field->src.type != modify_field->src.field ||
	    field->dst.type != modify_field->dst.field ||
	    field->dst.level != modify_field->dst.level ||
	    field->dst.offset != modify_field->dst.offset || field->width != modify_field->width)
		return NOT_MATCH;

	return SUCCESS;
}

static int
cpfl_check_mr_actions(const struct rte_flow_action *actions, const int len, int size)
{
	int i = 0;
	bool mod1_valid = false;
	bool mod2_valid = false;
	enum rte_flow_action_type type;

	if (!actions)
		return NOT_SUPPORT;

	while (i < len) {
		if (actions[i].type != RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP &&
		    actions[i].type != RTE_FLOW_ACTION_TYPE_VXLAN_DECAP &&
		    actions[i].type != RTE_FLOW_ACTION_TYPE_MODIFY_FIELD) {
			i++;
			continue;
		}

		mod1_valid = true;
		type = actions[i].type;
		i++;
		while (i < len) {
			if (actions[i].type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP ||
			    actions[i].type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
				if (type == RTE_FLOW_ACTION_TYPE_MODIFY_FIELD && size > 1)
					mod2_valid = true;
				else
					return NOT_SUPPORT;
			} else if (actions[i].type == RTE_FLOW_ACTION_TYPE_MODIFY_FIELD) {
				if ((type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP ||
				     type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) && size > 1)
					mod2_valid = true;
				else
					return NOT_SUPPORT;
			}
			i++;
		}
	}

	if (mod1_valid || mod2_valid)
		return SUCCESS;
	else
		return NOT_SUPPORT;

}
/* output: struct cpfl_js_mr_key_action *mr_key_action */
/* check and parse */
static int
cpfl_parse_mr_key_action(json_object *cjson_mr_key_action, int size,
			 const struct rte_flow_action *actions,
			 struct cpfl_js_mr_key_action *mr_key_action)
{
	int actions_length, i, j;
	int ret;

	actions_length = 0;
	while ((actions + actions_length++)->type != RTE_FLOW_ACTION_TYPE_END)
		continue;
	if (size > actions_length - 1)
		return NOT_MATCH;

	ret = cpfl_check_mr_actions(actions, actions_length, size);
	if (ret < 0)
		return ret;

	for (i = 0; i < size; i++) {
		json_object *object, *cjson_mr_key_action_data;
		const char *type;

		j = 0;
		object = json_object_array_get_idx(cjson_mr_key_action, i);
		/* mr->key->actions->type */
		type = json_object_get_string(json_object_object_get(object, "type"));
		/* mr->key->actions->data */
		cjson_mr_key_action_data = json_object_object_get(object, "data");
		/* match: <type> action matches RTE_FLOW_ACTION_TYPE_<type> */

		if (strcmp(type, "vxlan_encap") == 0) {
			int proto_size;
			struct cpfl_js_mr_key_action_vxlan_encap *encap;
			json_object *cjson_mr_key_action_proto;

			while (j < actions_length &&
			       actions[j].type != RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
				j++;
			}
			if (j >= actions_length)
				return NOT_MATCH;

			mr_key_action[i].type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP;
			cjson_mr_key_action_proto =
			    json_object_object_get(cjson_mr_key_action_data, "protocols");
			encap = &mr_key_action[i].encap;
			if (!cjson_mr_key_action_proto) {
				proto_size = 0;
				encap->proto_size = proto_size;
			} else {
				int k;

				proto_size = json_object_array_length(cjson_mr_key_action_proto);
				encap->proto_size = proto_size;
				for (k = 0; k < proto_size; k++) {
					const char *s;
					json_object *subobject;

					subobject =
					    json_object_array_get_idx(cjson_mr_key_action_proto, k);
					s = json_object_get_string(subobject);
					encap->protocols[k] = s;
				}
			}

			ret = cpfl_check_actions_vxlan_encap(encap, &actions[j]);
			if (ret < 0)
				return NOT_MATCH;

			j++;
		} else if (strcmp(type, "vxlan_decap") == 0) {
			while (j < actions_length &&
			       actions[j].type != RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
				j++;
			}
			if (j >= actions_length)
				return NOT_MATCH;

			mr_key_action[i].type = RTE_FLOW_ACTION_TYPE_VXLAN_DECAP;
			j++;
		} else if (strcmp(type, "modify_field") == 0) {
			json_object *temp, *level, *offset, *cjson_dst, *cjson_src, *cjson_width;
			const char *op, *type;
			int ret;

			while (j < actions_length &&
			       actions[j].type != RTE_FLOW_ACTION_TYPE_MODIFY_FIELD) {
				j++;
			}
			if (j >= actions_length)
				return NOT_MATCH;

			mr_key_action[i].type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
			temp = json_object_object_get(cjson_mr_key_action_data, "op");
			op = json_object_get_string(temp);
			/* Matches rte_flow_action_modify_field->op as an enum
			 * rte_flow_modify_op
			 */
			if (strcmp(op, "set") == 0)
				mr_key_action[i].field.op = RTE_FLOW_MODIFY_SET;
			else if (strcmp(op, "add") == 0)
				mr_key_action[i].field.op = RTE_FLOW_MODIFY_ADD;
			else if (strcmp(op, "sub") == 0)
				mr_key_action[i].field.op = RTE_FLOW_MODIFY_SUB;

			/* match: Matches rte_flow_action_modify_field->src */
			cjson_src = json_object_object_get(cjson_mr_key_action_data, "src");
			/* match: Matches enum rte_flow_field_id by naming
			 * converion: RTE_FLOW_FIELD_<type>
			 */
			type = json_object_get_string(json_object_object_get(cjson_src, "type"));
			if (strcmp(type, "value") == 0) {
				mr_key_action[i].field.src.type = RTE_FLOW_FIELD_VALUE;
			} else if (strcmp(type, "pointer") == 0) {
				mr_key_action[i].field.src.type = RTE_FLOW_FIELD_POINTER;
			} else if (strcmp(type, "mac_src") == 0) {
				mr_key_action[i].field.src.type = RTE_FLOW_FIELD_MAC_SRC;
			} else if (strcmp(type, "gtp_teid") == 0) {
				mr_key_action[i].field.src.type = RTE_FLOW_FIELD_GTP_TEID;
			} else if (strcmp(type, "tag") == 0) {
				mr_key_action[i].field.src.type = RTE_FLOW_FIELD_TAG;
			} else {
				PMD_DRV_LOG(ERR, "Doesn't support the "
						 "mr.key.action.field.src.type\n");
			}

			/* Matches to rte_flow_action_modify_data->level. */
			level = json_object_object_get(cjson_src, "level");
			if (!level)
				mr_key_action[i].field.src.level = 0;
			else
				mr_key_action[i].field.src.level = json_object_get_int(level);

			/* Matches to rte_flow_action_modify_data->offset. */
			offset = json_object_object_get(cjson_src, "offset");
			if (!offset)
				mr_key_action[i].field.src.offset = 0;
			else
				mr_key_action[i].field.src.offset = json_object_get_int(offset);

			cjson_dst = json_object_object_get(cjson_mr_key_action_data, "dst");
			type = json_object_get_string(json_object_object_get(cjson_dst, "type"));
			if (strcmp(type, "ipv4_src") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_IPV4_SRC;
			else if (strcmp(type, "ipv4_dst") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_IPV4_DST;
			else if (strcmp(type, "pointer") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_POINTER;
			else if (strcmp(type, "mac_src") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_MAC_SRC;
			else if (strcmp(type, "gtp_teid") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_GTP_TEID;
			else if (strcmp(type, "tag") == 0)
				mr_key_action[i].field.dst.type = RTE_FLOW_FIELD_TAG;
			else
				PMD_DRV_LOG(ERR, "Doesn't support mr.key.action.field.dst.type\n");

			/* Matches to rte_flow_action_modify_data->level. */
			level = json_object_object_get(cjson_dst, "level");
			if (!level)
				mr_key_action[i].field.dst.level = 0;
			else
				mr_key_action[i].field.dst.level = json_object_get_int(level);

			/* Matches to rte_flow_action_modify_data->offset. */
			offset = json_object_object_get(cjson_dst, "offset");
			if (!offset)
				mr_key_action[i].field.dst.offset = 0;
			else
				mr_key_action[i].field.dst.offset = json_object_get_int(offset);

			/* matches to rte_flow_action_modify_field->width */
			cjson_width = json_object_object_get(cjson_mr_key_action_data, "width");
			mr_key_action[i].field.width = json_object_get_int(cjson_width);
			ret = cpfl_check_actions_modify_field(&mr_key_action[i].field, &actions[j]);
			if (ret < 0)
				return NOT_MATCH;

			j++;
		} else {
			PMD_DRV_LOG(ERR, "Not support mr_key_action type %s.\n", type);
			return NOT_SUPPORT;
		}
	}

	return SUCCESS;
}

static void
cpfl_parse_modify_field_layout(const struct rte_flow_action_modify_field *modify_field,
			       const char *hint, int start, int offset, int size, uint8_t *buffer)
{
	if (strcmp(hint, "pointer") == 0) {
		if (modify_field->src.field == RTE_FLOW_FIELD_POINTER) {
			if (modify_field->operation == RTE_FLOW_MODIFY_SET) {
				/* TODO */
				memcpy(buffer + start, modify_field->src.value + offset, size);
			} else if (modify_field->operation == RTE_FLOW_MODIFY_ADD) {
			} else if (modify_field->operation == RTE_FLOW_MODIFY_SUB) {
			}
		} else {
			/* TODO:more? */
		}
	} else if (strcmp(hint, "value") == 0) {
		if (modify_field->src.field == RTE_FLOW_FIELD_VALUE &&
		    modify_field->operation == RTE_FLOW_MODIFY_SET) {
			memcpy(buffer + start, modify_field->src.value + offset, size);
		}
	} else {
		/* TODO:more hint? */
	}
}

/* output: uint8_t *buffer, uint16_t *byte_len */
static int
cpfl_parse_layout(json_object *layout, struct cpfl_js_mr_key_action *mr_key_action,
		  const struct rte_flow_action *actions, uint8_t *buffer, uint16_t *byte_len)
{
	int layout_size, i, start, actions_length;

	layout_size = json_object_array_length(layout);
	start = 0;
	actions_length = 0;
	while ((actions + actions_length++)->type != RTE_FLOW_ACTION_TYPE_END)
		continue;
	for (i = 0; i < layout_size; i++) {
		json_object *object;
		int index, size, offset, j;
		const char *hint;
		const uint8_t *addr;
		struct cpfl_js_mr_key_action *temp;

		object = json_object_array_get_idx(layout, i);
		/* index links to the element of the actions array. */
		index = json_object_get_int(json_object_object_get(object, "index"));
		size = json_object_get_int(json_object_object_get(object, "size"));
		offset = json_object_get_int(json_object_object_get(object, "offset"));
		if (index == -1) {
			hint = "dummpy";
			start += size;
			continue;
		}
		hint = json_object_get_string(json_object_object_get(object, "hint"));
		addr = NULL;
		temp = mr_key_action + index;

		for (j = 0; j < actions_length - 1; j++) {
			if (temp->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP &&
			    actions[j].type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
				const struct rte_flow_action_vxlan_encap *action_vxlan_encap;
				struct rte_flow_item *definition;
				int def_length, k;

				action_vxlan_encap =
				    (const struct rte_flow_action_vxlan_encap *)actions[j].conf;
				definition = action_vxlan_encap->definition;
				def_length = 0;
				while ((definition + def_length++)->type != RTE_FLOW_ITEM_TYPE_END)
					continue;
				for (k = 0; k < def_length - 1; k++) {
					if ((strcmp(hint, "eth") == 0 &&
					     definition[k].type == RTE_FLOW_ITEM_TYPE_ETH) ||
					    (strcmp(hint, "ipv4") == 0 &&
					     definition[k].type == RTE_FLOW_ITEM_TYPE_IPV4) ||
					    (strcmp(hint, "udp") == 0 &&
					     definition[k].type == RTE_FLOW_ITEM_TYPE_UDP) ||
					    (strcmp(hint, "tcp") == 0 &&
					     definition[k].type == RTE_FLOW_ITEM_TYPE_TCP) ||
					    (strcmp(hint, "vxlan") == 0 &&
					     definition[k].type == RTE_FLOW_ITEM_TYPE_VXLAN)) {
						addr = (const uint8_t *)(definition[k].spec);
						memcpy(buffer + start, addr + offset, size);
						break;
					} /* TODO: more hint... */
				}
				if (k == def_length - 1) {
					PMD_DRV_LOG(ERR, "can not find corresponding "
							 "definition, hint: %s\n", hint);
				}
				break;
			} else if (temp->type == RTE_FLOW_ACTION_TYPE_MODIFY_FIELD &&
				   actions[j].type == RTE_FLOW_ACTION_TYPE_MODIFY_FIELD) {
				const struct rte_flow_action_modify_field *modify_field;
				modify_field =
				    (const struct rte_flow_action_modify_field *)actions[j].conf;
				cpfl_parse_modify_field_layout(modify_field, hint, start, offset,
							       size, buffer);
				break;
			}
			/* else TODO: more type... */
		}
		if (j == actions_length - 1) {
			PMD_DRV_LOG(ERR, "Not found matching action.\n");
			return NOT_MATCH;
		}

		start += size;
	}
	*byte_len = start;
	return SUCCESS;
}

static int
cpfl_parse_mr_action(json_object *cjson_mr_action, struct cpfl_js_mr_key_action *mr_key_action,
		     const struct rte_flow_action *actions, struct cpfl_js_mr_action *mr_action)
{
	json_object *cjson_mr_action_data;
	const char *type;

	/* mr->action->type */
	type = json_object_get_string(json_object_object_get(cjson_mr_action, "type"));
	/* mr->action->data */
	cjson_mr_action_data = json_object_object_get(cjson_mr_action, "data");
	if (strcmp(type, "mod") == 0) {
		json_object *layout;

		mr_action->type = CPFL_JS_MR_ACTION_TYPE_MOD;
		mr_action->mod.byte_len = 0;
		mr_action->mod.prof =
		    json_object_get_int(json_object_object_get(cjson_mr_action_data, "profile"));
		layout = json_object_object_get(cjson_mr_action_data, "layout");
		if (layout) {
			int ret;

			memset(mr_action->mod.data, 0, sizeof(mr_action->mod.data));
			ret = cpfl_parse_layout(layout, mr_key_action, actions, mr_action->mod.data,
						&mr_action->mod.byte_len);
			if (ret < 0)
				return NOT_MATCH;
		}
		return SUCCESS;
	} else if (strcmp(type, "mod_meta") == 0) {
		mr_action->type = CPFL_JS_MR_ACTION_TYPE_MOD_META;
		mr_action->mod_meta.prof =
		    json_object_get_int(json_object_object_get(cjson_mr_action_data, "profile"));
		return SUCCESS;
	}
	return 0;
}

/* output: struct cpfl_js_mr_action *mr_action */
static int
cpfl_parse_mod_rules(json_object *cjson_mr, const struct rte_flow_action *actions,
		     struct cpfl_js_mr_action *mr_action)
{
	int i, size;

	size = json_object_array_length(cjson_mr);
	for (i = 0; i < size; i++) {
		int key_action_size, ret;
		struct cpfl_js_mr_key_action *mr_key_action;
		json_object *object, *cjson_mr_key, *cjson_mr_action, *cjson_mr_key_action;

		object = json_object_array_get_idx(cjson_mr, i);
		/* mr->key */
		cjson_mr_key = json_object_object_get(object, "key");
		/* mr->key->actions */
		cjson_mr_key_action = json_object_object_get(cjson_mr_key, "actions");
		key_action_size = json_object_array_length(cjson_mr_key_action);

		mr_key_action =
		    rte_malloc(NULL, sizeof(struct cpfl_js_mr_key_action) * key_action_size, 0);
		if (!mr_key_action)
			rte_exit(EXIT_FAILURE, "Failed to allocate memory for mr_key_action.");

		ret = cpfl_parse_mr_key_action(cjson_mr_key_action, key_action_size, actions,
					       mr_key_action);
		if (ret < 0) {
			rte_free(mr_key_action);
			continue;
		}
		/* mr->action */
		cjson_mr_action = json_object_object_get(object, "action");
		ret = cpfl_parse_mr_action(cjson_mr_action, mr_key_action, actions, mr_action);
		rte_free(mr_key_action);
		if (ret == SUCCESS)
			return SUCCESS;
	}
	return 0;
}

int
cpfl_parse_actions(struct cpfl_js_flow_parser *parser, const struct rte_flow_action *actions,
		   struct cpfl_js_mr_action *mr_action)
{
	json_object *cjson_mr;

	/* modifications rules */
	cjson_mr = json_object_object_get(parser->json_root, "modifications");
	if (!cjson_mr) {
		PMD_DRV_LOG(ERR, "The modifications is optional.\n");
	} else {
		int ret;

		ret = cpfl_parse_mod_rules(cjson_mr, actions, mr_action);
		if (ret == SUCCESS)
			return SUCCESS;
	}
	return 0;
}

static void
cpfl_parse_vports_fv(json_object *cjson_fv, struct cpfl_itf *itf,
		     const char *type, uint8_t *fv)
{
	RTE_SET_USED(type);
	int size, i;

	size = json_object_array_length(cjson_fv);
	for (i = 0; i < size; i++) {
		json_object *object, *cjson_value;
		uint16_t offset;

		object = json_object_array_get_idx(cjson_fv, i);
		offset = json_object_get_int(json_object_object_get(object, "offset"));
		cjson_value = json_object_object_get(object, "value");
		cpfl_parse_fv_metadata(cjson_value, itf, offset, fv);
	}
}

static void
cpfl_parse_vport_per_act(json_object *sub_oj, struct cpfl_itf *itf, const char *type,
			 struct cpfl_js_pr_action *cpfl_vports)
{
	const char *act_type;
	act_type = json_object_get_string(json_object_object_get(sub_oj, "type"));
	/* vport->actions->data */
	if (strcmp(act_type, "sem") == 0) {
		json_object *cjson_fv, *cjson_action_sem, *cjson_prof, *cjson_ks,
		    *cjson_subprof;

		cpfl_vports->type = CPFL_JS_PR_ACTION_TYPE_SEM;
		cjson_action_sem = json_object_object_get(sub_oj, "data");
		cjson_prof = json_object_object_get(cjson_action_sem, "profile");
		cpfl_vports->sem.prof = json_object_get_int(cjson_prof);
		cjson_subprof = json_object_object_get(cjson_action_sem, "subprofile");
		cpfl_vports->sem.subprof = json_object_get_int(cjson_subprof);
		cjson_ks = json_object_object_get(cjson_action_sem, "keysize");
		cpfl_vports->sem.keysize = json_object_get_int(cjson_ks);
		cjson_fv = json_object_object_get(cjson_action_sem, "fieldvectors");
		memset(cpfl_vports->sem.cpfl_js_pr_fv, 0,
		       sizeof(cpfl_vports->sem.cpfl_js_pr_fv));
		cpfl_parse_vports_fv(cjson_fv, itf, type, cpfl_vports->sem.cpfl_js_pr_fv);
	} else {
		PMD_DRV_LOG(ERR, "not support this type[%s] for vports rules", act_type);
	}
}

int
cpfl_parse_vport_rules(struct cpfl_js_flow_parser *parser, struct cpfl_itf *itf,
			   struct cpfl_js_pr_action *cpfl_vports)
{
	json_object *cjson_vport;
	int i, size;

	if (!parser) {
		PMD_DRV_LOG(DEBUG, "Flow parser is NULL.\n");
		return 0;
	}

	/* Vport Rules */
	cjson_vport = json_object_object_get(parser->json_root, "vports");
	if (!cjson_vport) {
		PMD_DRV_LOG(DEBUG, "The Vport Rules is optional.\n");
		return 0;
	}

	size = json_object_array_length(cjson_vport);

	if (!cpfl_vports) {
		PMD_DRV_LOG(ERR, "not allocate cpfl_vports.");
		return 0;
	}

	/* size should be less than a MAX value */
	cpfl_vports[size].type = CPFL_JS_VPORT_END;

	for (i = 0; i < size; i++) {
		json_object *object, *cjson_actions, *cjson_type;
		const char *type;
		int act_size, j;

		object = json_object_array_get_idx(cjson_vport, i);
		/* vport->key->type */
		cjson_type = json_object_object_get(json_object_object_get(object, "key"), "type");
		type = json_object_get_string(cjson_type);
		/* vport->actions */
		cjson_actions = json_object_object_get(object, "actions");
		act_size = json_object_array_length(cjson_actions);
		for (j = 0; j < act_size; j++) {
			json_object *sub_ob;

			sub_ob = json_object_array_get_idx(cjson_actions, j);
			cpfl_parse_vport_per_act(sub_ob, itf, type, cpfl_vports + i);
		}
	}
	return SUCCESS;
}

int
cpfl_parse_metadatas(struct cpfl_js_flow_parser *parser, int index,
			     struct cpfl_js_metadatas_info *md_info)
{
	json_object *cj_md;
	int i, size;
	/* Metadata */
	cj_md = json_object_object_get(parser->json_root, "metadata");
	if (!cj_md) {
		PMD_DRV_LOG(DEBUG, "The Metadata is optional.\n");
		return 0;
	}

	size = json_object_array_length(cj_md);
	for (i = 0; i < size; i++) {
		json_object *object, *cj_index, *cj_action;

		object = json_object_array_get_idx(cj_md, i);
		/* metadatas->key */
		cj_index = json_object_object_get(json_object_object_get(object, "key"),
						  "index");
		if (json_object_get_int(cj_index) != index) {
			continue;
		}
		/* metadatas->action */
		cj_action = json_object_object_get(object, "action");
		md_info->type = json_object_get_int(json_object_object_get(cj_action, "type"));
		md_info->start = json_object_get_int(json_object_object_get(cj_action, "start"));
		md_info->width = json_object_get_int(json_object_object_get(cj_action, "length"));
		return SUCCESS;
	}
	return NOT_MATCH;
}

int
cpfl_parser_create(struct cpfl_js_flow_parser **flow_parser, const char *filename)
{
	struct cpfl_js_flow_parser *parser;
	json_object *root, *js_ver;

	parser = rte_zmalloc("flow_parser", sizeof(struct cpfl_js_flow_parser), 0);
	if (!parser) {
		PMD_DRV_LOG(ERR, "Not enought memory to create flow parser.\n");
		return -ENOMEM;
	}

	root = json_object_from_file(filename);
	if (!root) {
		PMD_DRV_LOG(ERR, "No JSON.\n");
		return -EINVAL;
	}
	parser->json_root = root;
	/* version */
	js_ver = json_object_object_get(parser->json_root, "version");
	if (!js_ver) {
		PMD_DRV_LOG(ERR, "The version is mandatory.\n");
		return -EINVAL;
	}

	cpfl_parse_version(js_ver, &parser->version);
	*flow_parser = parser;

	return 0;
}

int
cpfl_parser_destroy(struct cpfl_js_flow_parser *parser)
{
	rte_free(parser);

	return 0;
}

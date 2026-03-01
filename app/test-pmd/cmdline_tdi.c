/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include <rte_malloc.h>
#include <rte_tdi.h>
#include <rte_mempool.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_tailq.h>
#include <arpa/inet.h>

#include "testpmd.h"
#include "cmdline_tdi.h"

#define TDI_FIELD_VALUE_BYTE_MAX 16
#define TDI_TABLE_KEY_NUM_MAX 256
#define TDI_ACTION_NUM_MAX 256

struct tdi_table_key_obj {
	TAILQ_ENTRY(tdi_table_key_obj) next;
	uint32_t key_id;
	struct rte_tdi_table_info tinfo;
	struct rte_tdi_table_key *key;
	struct rte_tdi_table_key_field_info key_fields[RTE_TDI_KEY_FIELD_NUM_MAX];
	uint8_t key_value_buf1[RTE_TDI_KEY_FIELD_NUM_MAX][TDI_FIELD_VALUE_BYTE_MAX];
	uint8_t key_value_buf2[RTE_TDI_KEY_FIELD_NUM_MAX][TDI_FIELD_VALUE_BYTE_MAX];
};

struct tdi_action_obj {
	TAILQ_ENTRY(tdi_action_obj) next;
	uint32_t action_id;
	struct rte_tdi_table_info tinfo;
	struct rte_tdi_action_spec_info asinfo;
	struct rte_tdi_action *action;
	struct rte_tdi_action_spec_field_info fields[RTE_TDI_ACTION_SPEC_FIELD_NUM_MAX];
	uint8_t value_buf[RTE_TDI_ACTION_SPEC_FIELD_NUM_MAX][TDI_FIELD_VALUE_BYTE_MAX];
};

static struct rte_hash *_table_key_obj_hash;
static struct rte_hash *_action_obj_hash;

TAILQ_HEAD(tdi_table_key_obj_list, tdi_table_key_obj);
TAILQ_HEAD(tdi_action_obj_list, tdi_action_obj);

static struct tdi_table_key_obj_list _table_key_obj_list;
static struct tdi_action_obj_list _action_obj_list;

static struct rte_hash *
get_tdi_table_key_obj_hash(void)
{
	if (_table_key_obj_hash == NULL) {
		struct rte_hash_parameters params = {
			.name = "testpmd_tdi_table_key_hash",
			.entries = TDI_TABLE_KEY_NUM_MAX,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = SOCKET_ID_ANY,
			.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
		};

		_table_key_obj_hash = rte_hash_create(&params);
		TAILQ_INIT(&_table_key_obj_list);
	}

	return _table_key_obj_hash;
}

static struct rte_hash *
get_tdi_action_obj_hash(void)
{
	if (_action_obj_hash == NULL) {
		struct rte_hash_parameters params = {
			.name = "testpmd_tdi_actionhash",
			.entries = TDI_ACTION_NUM_MAX,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = SOCKET_ID_ANY,
			.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
		};

		_action_obj_hash = rte_hash_create(&params);
		TAILQ_INIT(&_action_obj_list);
	}

	return _action_obj_hash;
}

static void print_table_key_obj(struct tdi_table_key_obj *kobj)
{
	char buf1[50];
	char buf2[50];
	uint16_t i, j;

	printf("%-15s%d\n", "Key ID:", kobj->key_id);
	printf("%-15s%d\n", "Table ID:", kobj->tinfo.id);
	printf("%-15s%s\n", "Table Name:", kobj->tinfo.name);
	printf("%-15s%-50s%s\n", "Field ID", "Name", "Value(hex)");

	for (i = 0; i < kobj->tinfo.key_field_num; i++) {
		struct rte_tdi_table_key_field_info *kfinfo = &kobj->key_fields[i];
		char *hex1 = buf1;
		char *hex2 = buf2;

		for (j = 0; j < kfinfo->byte_width; j++)
			hex1 += sprintf(hex1, "%02X ", kobj->key_value_buf1[i][j]);

		printf("%-15d%-50s%s\n", kfinfo->field_id, kfinfo->name, buf1);
		if (kfinfo->match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT) {
			for (j = 0; j < kfinfo->byte_width; j++)
				hex2 += sprintf(hex2, "%02X ", kobj->key_value_buf2[i][j]);
			printf("%-65s%s\n", "", buf2);
		}
	}
}

static void print_action_obj(struct tdi_action_obj *aobj)
{
	char buf[50];
	uint16_t i, j;

	printf("%-15s%d\n", "Action ID:", aobj->action_id);
	printf("%-15s%d\n", "Table ID:", aobj->tinfo.id);
	printf("%-15s%s\n", "Table Name:", aobj->tinfo.name);
	printf("%-15s%d\n", "Spec ID:", aobj->asinfo.id);
	printf("%-15s%s\n", "Spec Name:", aobj->asinfo.name);
	printf("%-15s%-50s%s\n", "Field ID", "Name", "Value(hex)");

	for (i = 0; i < aobj->asinfo.field_num; i++) {
		struct rte_tdi_action_spec_field_info *finfo = &aobj->fields[i];
		char *hex = buf;

		for (j = 0; j < finfo->byte_width; j++)
			hex += sprintf(hex, "%02X ", aobj->value_buf[i][j]);

		printf("%-15d%-50s%s\n", finfo->field_id, finfo->name, buf);
	}
}

static void split_string(const char *input, char *before, char *after)
{
	const char *period_pos = strchr(input, '/');
	if (period_pos) {
		int index = period_pos - input;

		strncpy(before, input, index);
		before[index] = '\0';
		strncpy(after, input + index + 1, strlen(input) - index - 1);
		after[strlen(input) - index - 1] = '\0';
	}
}

static bool parse_uint16(const char *str, uint16_t *val)
{
	char *endptr;
	long value = strtol(str, &endptr, 10);

	if (*endptr != '\0')
		return false;

	if (value < 0 || value > UINT16_MAX)
		return false;

	*val = (uint16_t)value;
	return true;
}

static int parse_ipv4_string(const char *str, unsigned char *out)
{
	int a, b, c, d;

	if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
		return -1;

	if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
		return -1;

	out[0] = a;
	out[1] = b;
	out[2] = c;
	out[3] = d;

	return 0;
}

static int parse_ipv6_string(const char *str, unsigned char *out)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, str, &addr) != 1)
		return -1;

	memcpy(out, &addr.s6_addr, sizeof(addr.s6_addr));
	return 0;
}

static int parse_mac_string(const char *str, unsigned char *out)
{
	int a, b, c, d, e, f;

	if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6)
		return -1;

	if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 ||
	    d < 0 || d > 255 || e < 0 || e > 255 || f < 0 || f > 255)
		return -1;

	out[0] = a;
	out[1] = b;
	out[2] = c;
	out[3] = d;
	out[4] = e;
	out[5] = f;

	return 0;
}

static int parse_integer_string(const char *str, unsigned char *out)
{
	char *endptr;
	uint64_t value = strtoull(str, &endptr, 10);
	int i;

	if (strncmp(str, "0x", 2) == 0)
		value = strtoull(str + 2, &endptr, 16);
	else
		value = strtoull(str, &endptr, 10);

	if (*endptr != '\0')
		return -1;

	for (i = 0; i < 8; i++) {
		out[i] = (unsigned char)(value & 0xff);
		value >>= 8;
		if (value == 0)
			break;
	}

	return i + 1;
}

static int parse_hex_string(const char *hex_string, unsigned char *bytes, uint16_t byte_width)
{
	int i;
	int j = 0;
	int str_len = strlen(hex_string);

	if (str_len < 2 || hex_string[0] != '"' || hex_string[str_len - 1] != '"')
		return -1;

	for (i = 1; i < str_len - 1; i += 2) {
		char str[3];
		char *endptr;
		long value;

		str[0] = hex_string[i];
		str[1] = hex_string[i + 1];
		str[2] = '\0';
		value = strtol(str, &endptr, 16);
		if (*endptr != '\0')
			return -1;

		bytes[j++] = (unsigned char)value;
		if (j == byte_width)
			break;
	}

	return j;
}

static int parse_str_to_buf(const char *input, uint8_t *buf, uint16_t byte_width)
{
	int ret;

	ret = parse_ipv4_string(input, buf);
	if (ret == 0)
		return 4;

	ret = parse_ipv6_string(input, buf);
	if (ret == 0)
		return 16;

	ret = parse_mac_string(input, buf);
	if (ret == 0)
		return 6;

	ret = parse_integer_string(input, buf);
	if (ret > 0)
		return ret;

	ret = parse_hex_string(input, buf, byte_width);
	if (ret > 0)
		return ret;

	return -1;
}

/* *** Show tdi table list *** */
struct cmd_tdi_table_list_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t list;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_list_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_list_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_list_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_list_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_list_list =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_list_result, list, "list");
static cmdline_parse_token_num_t cmd_tdi_table_list_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_list_result, port_id, RTE_UINT16);

static void cmd_tdi_table_list_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_list_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct rte_tdi_id_list *id_list;
	struct rte_tdi_error err;
	uint32_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_tdi_table_list_popup(port_id, &id_list, &err);
	if (ret != 0) {
		printf("Failed to popup table id list.\n");
		return;
	}

	printf("%-20s%-30s%s\n", "ID", "Name", "Annotation");
	for (i = 0; i < id_list->num; i++) {
		uint32_t id = (id_list->ids[i]);
		struct rte_tdi_table_info tinfo;

		ret = rte_tdi_table_info_get(port_id, id, &tinfo, &err);
		if (ret != 0) {
			printf("Failed to get table info of id: %d\n", id);
			goto fin;
		}
		printf("%-20d%-30s%s\n", id, tinfo.name, tinfo.annotation);
	}
fin:
	rte_free(id_list);
}

cmdline_parse_inst_t cmd_tdi_table_list = {
	.f = cmd_tdi_table_list_parsed,
	.data = NULL,
	.help_str = "tdi table list <port_id>",
	.tokens = {
		(void *)&cmd_tdi_table_list_tdi,
		(void *)&cmd_tdi_table_list_table,
		(void *)&cmd_tdi_table_list_list,
		(void *)&cmd_tdi_table_list_port_id,
		NULL,
	},
};

/* *** Show tdi table info *** */
struct cmd_tdi_table_info_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t info;
	uint16_t port_id;
	uint32_t table_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_info_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_info_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_info_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_info_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_info_info=
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_info_result, info, "info");
static cmdline_parse_token_num_t cmd_tdi_table_info_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_info_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_info_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_info_result, table_id, RTE_UINT32);

static const char *
__match_type_to_str(enum rte_tdi_table_key_match_type type)
{
	switch (type) {
	case RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT:
		return "exact";
	case RTE_TDI_TABLE_KEY_MATCH_TYPE_WILDCARD:
		return "wildcard";
	case RTE_TDI_TABLE_KEY_MATCH_TYPE_RANGE:
		return "range";
	default:
		return "unknown";
	}
}

static const char *
__byte_order_to_str(enum rte_tdi_byte_order byteorder)
{
	switch (byteorder) {
	case RTE_TDI_BYTE_ORDER_HOST:
		return "host";
	case RTE_TDI_BYTE_ORDER_NETWORK:
		return "network";
	default:
		return "unknown";
	}
}

static void cmd_tdi_table_info_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_info_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	struct rte_tdi_table_info tinfo;
	struct rte_tdi_error err;
	uint32_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_tdi_table_info_get(port_id, table_id, &tinfo, &err);
	if (ret != 0) {
		printf("Failed to get table info.\n");
		return;
	}

	printf("%-15s%d\n", "ID:", tinfo.id);
	printf("%-15s%s\n", "Name:", tinfo.name);
	printf("%-15s%s\n", "Annotation:", tinfo.annotation);
	printf("%-15s%-30s%-15s%-15s%-15s%-15s%s\n",
			"Field ID", "Name", "Match Type", "Bit Width",
			"Byte Width", "Byte Order", "Annotation");

	for (i = 0; i < tinfo.key_field_num; i++) {
		struct rte_tdi_table_key_field_info kfinfo;
		uint32_t field_id = tinfo.key_fields[i];

		ret = rte_tdi_table_key_field_info_get(port_id, table_id, field_id, &kfinfo, &err);
		if (ret != 0) {
			printf("Failed to get key field info from id %d\n", field_id);
			return;
		}

		printf("%-15d%-30s%-15s%-15d%-15d%-15s%s\n",
				field_id,
				kfinfo.name,
				__match_type_to_str(kfinfo.match_type),
				kfinfo.bit_width,
				kfinfo.byte_width,
				__byte_order_to_str(kfinfo.byte_order),
				kfinfo.annotation);
	}

	printf("%-15s%-30s%s\n", "Spec ID", "Name", "Annotation");

	for (i = 0; i < tinfo.action_spec_num; i++) {
		struct rte_tdi_action_spec_info asinfo;
		uint32_t spec_id = tinfo.action_specs[i];

		ret = rte_tdi_action_spec_info_get(port_id, spec_id, &asinfo, &err);
		if (ret != 0) {
			printf("Failed to get action spec info from id %d\n", spec_id);
			return;
		}

		printf("%-15d%-30s%s\n", spec_id, asinfo.name, asinfo.annotation);
	}
}

cmdline_parse_inst_t cmd_tdi_table_info = {
	.f = cmd_tdi_table_info_parsed,
	.data = NULL,
	.help_str = "tdi table info <port_id> <table_id>",
	.tokens = {
		(void *)&cmd_tdi_table_info_tdi,
		(void *)&cmd_tdi_table_info_table,
		(void *)&cmd_tdi_table_info_info,
		(void *)&cmd_tdi_table_info_port_id,
		(void *)&cmd_tdi_table_info_table_id,
		NULL,
	},
};

/* *** Show tdi action_spec list *** */
struct cmd_tdi_action_spec_list_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action_spec;
	cmdline_fixed_string_t list;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_spec_list_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_list_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_spec_list_action_spec =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_list_result, action_spec, "action_spec");
static cmdline_parse_token_string_t cmd_tdi_action_spec_list_list =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_list_result, list, "list");
static cmdline_parse_token_num_t cmd_tdi_action_spec_list_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_spec_list_result, port_id, RTE_UINT16);

static void cmd_tdi_action_spec_list_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_spec_list_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct rte_tdi_id_list *id_list;
	struct rte_tdi_error err;
	uint32_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_tdi_action_spec_list_popup(port_id, &id_list, &err);
	if (ret != 0) {
		printf("Failed to popup action_spec id list.\n");
		return;
	}

	printf("%-20s%-30s%s\n", "ID", "Name", "Annotation");
	for (i = 0; i < id_list->num; i++) {
		uint32_t id = (id_list->ids[i]);
		struct rte_tdi_action_spec_info asinfo;

		ret = rte_tdi_action_spec_info_get(port_id, id, &asinfo, &err);
		if (ret != 0) {
			printf("Failed to get action spec info of id: %d\n", id);
			goto fin;
		}
		printf("%-20d%-30s%s\n", id, asinfo.name, asinfo.annotation);
	}
fin:
	rte_free(id_list);
}

cmdline_parse_inst_t cmd_tdi_action_spec_list = {
	.f = cmd_tdi_action_spec_list_parsed,
	.data = NULL,
	.help_str = "tdi action_spec list <port_id>",
	.tokens = {
		(void *)&cmd_tdi_action_spec_list_tdi,
		(void *)&cmd_tdi_action_spec_list_action_spec,
		(void *)&cmd_tdi_action_spec_list_list,
		(void *)&cmd_tdi_action_spec_list_port_id,
		NULL,
	},
};

/* *** Show tdi action_spec info *** */
struct cmd_tdi_action_spec_info_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action_spec;
	cmdline_fixed_string_t info;
	uint16_t port_id;
	uint32_t spec_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_spec_info_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_info_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_spec_info_action_spec =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_info_result, action_spec, "action_spec");
static cmdline_parse_token_string_t cmd_tdi_action_spec_info_info =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_spec_info_result, info, "info");
static cmdline_parse_token_num_t cmd_tdi_action_spec_info_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_spec_info_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_spec_info_spec_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_spec_info_result, spec_id, RTE_UINT32);

static void cmd_tdi_action_spec_info_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_spec_info_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t spec_id = res->spec_id;
	struct rte_tdi_action_spec_info asinfo;
	struct rte_tdi_error err;
	uint32_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_tdi_action_spec_info_get(port_id, spec_id, &asinfo, &err);
	if (ret != 0) {
		printf("Failed to get action_spec info.\n");
		return;
	}

	printf("%-15s%d\n", "ID:", asinfo.id);
	printf("%-15s%s\n", "Name:", asinfo.name);
	printf("%-15s%s\n", "Annotation:", asinfo.annotation);
	printf("%-15s%-30s%-15s%-15s%-15s%s\n",
			"Field ID", "Name", "Bit Width",
			"Byte Width", "Byte Order", "Annotation");

	for (i = 0; i < asinfo.field_num; i++) {
		struct rte_tdi_action_spec_field_info finfo;
		uint32_t field_id = asinfo.fields[i];

		ret = rte_tdi_action_spec_field_info_get(port_id, spec_id, field_id, &finfo, &err);
		if (ret != 0) {
			printf("Failed to get key field info from id %d\n", field_id);
			return;
		}

		printf("%-15d%-30s%-15d%-15d%-15s%s\n",
				field_id,
				finfo.name,
				finfo.bit_width,
				finfo.byte_width,
				__byte_order_to_str(finfo.byte_order),
				finfo.annotation);
	}

}

cmdline_parse_inst_t cmd_tdi_action_spec_info = {
	.f = cmd_tdi_action_spec_info_parsed,
	.data = NULL,
	.help_str = "tdi action spec info <port_id> <spec_id>",
	.tokens = {
		(void *)&cmd_tdi_action_spec_info_tdi,
		(void *)&cmd_tdi_action_spec_info_action_spec,
		(void *)&cmd_tdi_action_spec_info_info,
		(void *)&cmd_tdi_action_spec_info_port_id,
		(void *)&cmd_tdi_action_spec_info_spec_id,
		NULL,
	},
};

/* *** Show tdi table key list *** */
struct cmd_tdi_table_key_list_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t list;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_list_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_list_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_list_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_list_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_list_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_list_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_list_list =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_list_result, list, "list");
static cmdline_parse_token_num_t cmd_tdi_table_key_list_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_list_result, port_id, RTE_UINT16);

static void cmd_tdi_table_key_list_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_list_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct tdi_table_key_obj *kobj;
	struct rte_hash *key_hash;
	void *temp;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key object hash.\n");
		return;
	}

	printf("%-15s%-15s%s\n", "Key ID", "Table ID", "Table Name");

	RTE_TAILQ_FOREACH_SAFE(kobj, &_table_key_obj_list, next, temp)
		printf("%-15d%-15d%s\n", kobj->key_id, kobj->tinfo.id, kobj->tinfo.name);
}

cmdline_parse_inst_t cmd_tdi_table_key_list = {
	.f = cmd_tdi_table_key_list_parsed,
	.data = NULL,
	.help_str = "tdi table key list <port_id>",
	.tokens = {
		(void *)&cmd_tdi_table_key_list_tdi,
		(void *)&cmd_tdi_table_key_list_table,
		(void *)&cmd_tdi_table_key_list_key,
		(void *)&cmd_tdi_table_key_list_list,
		(void *)&cmd_tdi_table_key_list_port_id,
		NULL,
	},
};

/* *** Show tdi table key info *** */
struct cmd_tdi_table_key_info_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t info;
	uint16_t port_id;
	uint32_t key_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_info_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_info_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_info_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_info_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_info_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_info_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_info_info=
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_info_result, info, "info");
static cmdline_parse_token_num_t cmd_tdi_table_key_info_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_info_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_info_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_info_result, key_id, RTE_UINT32);

static void cmd_tdi_table_key_info_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_info_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	struct tdi_table_key_obj *kobj;
	struct rte_hash *key_hash;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key object hash.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object of id: %d does not exist.\n", key_id);
		return;
	}

	print_table_key_obj(kobj);
}

cmdline_parse_inst_t cmd_tdi_table_key_info = {
	.f = cmd_tdi_table_key_info_parsed,
	.data = NULL,
	.help_str = "tdi table key info <port_id> <key_id>",
	.tokens = {
		(void *)&cmd_tdi_table_key_info_tdi,
		(void *)&cmd_tdi_table_key_info_table,
		(void *)&cmd_tdi_table_key_info_key,
		(void *)&cmd_tdi_table_key_info_info,
		(void *)&cmd_tdi_table_key_info_port_id,
		(void *)&cmd_tdi_table_key_info_key_id,
		NULL,
	},
};

/* *** Show tdi action list *** */
struct cmd_tdi_action_list_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t list;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_list_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_list_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_list_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_list_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_list_list =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_list_result, list, "list");
static cmdline_parse_token_num_t cmd_tdi_action_list_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_list_result, port_id, RTE_UINT16);

static void cmd_tdi_action_list_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_list_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;
	void *temp;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action object hash.\n");
		return;
	}

	printf("%-15s%-15s%-30s%-15s%s\n",
			"Action ID", "Table ID", "Table Name", "Spec ID", "Spec Name");

	RTE_TAILQ_FOREACH_SAFE(aobj, &_action_obj_list, next, temp)
		printf("%-15d%-15d%-30s%-15d%s\n",
				aobj->action_id, aobj->tinfo.id, aobj->tinfo.name,
				aobj->asinfo.id, aobj->asinfo.name);
}

cmdline_parse_inst_t cmd_tdi_action_list = {
	.f = cmd_tdi_action_list_parsed,
	.data = NULL,
	.help_str = "tdi action list <port_id>",
	.tokens = {
		(void *)&cmd_tdi_action_list_tdi,
		(void *)&cmd_tdi_action_list_action,
		(void *)&cmd_tdi_action_list_list,
		(void *)&cmd_tdi_action_list_port_id,
		NULL,
	},
};

/* *** Show tdi action info *** */
struct cmd_tdi_action_info_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t info;
	uint16_t port_id;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_info_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_info_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_info_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_info_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_info_info=
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_info_result, info, "info");
static cmdline_parse_token_num_t cmd_tdi_action_info_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_info_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_info_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_info_result, action_id, RTE_UINT32);

static void cmd_tdi_action_info_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_info_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t action_id = res->action_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action object hash.\n");
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action object of id: %d does not exist.\n", action_id);
		return;
	}

	print_action_obj(aobj);
}

cmdline_parse_inst_t cmd_tdi_action_info = {
	.f = cmd_tdi_action_info_parsed,
	.data = NULL,
	.help_str = "tdi action info <port_id> <action_id>",
	.tokens = {
		(void *)&cmd_tdi_action_info_tdi,
		(void *)&cmd_tdi_action_info_action,
		(void *)&cmd_tdi_action_info_info,
		(void *)&cmd_tdi_action_info_port_id,
		(void *)&cmd_tdi_action_info_action_id,
		NULL,
	},
};

/* *** Create tdi table key object *** */
struct cmd_tdi_table_key_create_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t create;
	uint16_t port_id;
	uint32_t table_id;
	uint32_t key_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_create_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_create_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_create_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_create_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_create_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_create_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_create_create =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_create_result, create, "create");
static cmdline_parse_token_num_t cmd_tdi_table_key_create_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_create_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_create_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_create_result, table_id, RTE_UINT32);
static cmdline_parse_token_num_t cmd_tdi_table_key_create_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_create_result, key_id, RTE_UINT32);

static void cmd_tdi_table_key_create_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_create_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t key_id = res->key_id;
	struct tdi_table_key_obj *kobj;
	struct rte_hash *key_hash;
	struct rte_tdi_error err;
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key object hash.\n");
		return;
	}

	if (rte_hash_lookup(key_hash, &key_id) >= 0) {
		printf("Key with id %d already exists\n", key_id);
		return;
	}

	kobj = rte_zmalloc(NULL, sizeof(struct tdi_table_key_obj), 0);
	if (kobj == NULL) {
		printf("Out of memory!\n");
		return;
	}

	kobj->key_id = key_id;
	ret = rte_tdi_table_info_get(port_id, table_id, &kobj->tinfo, &err);
	if (ret != 0) {
		printf("Failed to get table info of id %d.\n", table_id);
		rte_free(kobj);
		return;
	}

	for (i = 0; i < kobj->tinfo.key_field_num; i++) {
		uint32_t field_id = kobj->tinfo.key_fields[i];

		ret = rte_tdi_table_key_field_info_get(port_id, table_id, field_id,
						       &kobj->key_fields[i], &err);
		if (ret != 0) {
			printf("Failed to get table %d key field info of id %d.\n", table_id, field_id);
			rte_free(kobj);
			return;
		}
	}

	ret = rte_tdi_table_key_create(port_id, table_id, &kobj->key, &err);
	if (ret != 0) {
		printf("Failed to create key form table with id %d.\n", table_id);
		rte_free(kobj);
		return;
	}

	ret = rte_hash_add_key_data(key_hash, &key_id, kobj);
	if (ret != 0) {
		rte_tdi_table_key_destroy(port_id, kobj->key, &err);
		printf("Failed to add key to hash table, key destroyed.\n");
		return;
	}

	TAILQ_INSERT_TAIL(&_table_key_obj_list, kobj, next);

	printf("Key (%d) was created.\n", key_id);
}

cmdline_parse_inst_t cmd_tdi_table_key_create = {
	.f = cmd_tdi_table_key_create_parsed,
	.data = NULL,
	.help_str = "tdi table key create <port_id> <table_id> <key_id>",
	.tokens = {
		(void *)&cmd_tdi_table_key_create_tdi,
		(void *)&cmd_tdi_table_key_create_table,
		(void *)&cmd_tdi_table_key_create_key,
		(void *)&cmd_tdi_table_key_create_create,
		(void *)&cmd_tdi_table_key_create_port_id,
		(void *)&cmd_tdi_table_key_create_table_id,
		(void *)&cmd_tdi_table_key_create_key_id,
		NULL,
	},
};

/* *** Destroy tdi table key object *** */
struct cmd_tdi_table_key_destroy_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t destroy;
	uint16_t port_id;
	uint32_t key_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_destroy =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, destroy, "destroy");
static cmdline_parse_token_num_t cmd_tdi_table_key_destroy_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_destroy_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_destroy_result, key_id, RTE_UINT32);

static void cmd_tdi_table_key_destroy_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_destroy_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	struct tdi_table_key_obj *kobj;
	struct rte_hash *key_hash;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key object hash.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key with id %d not exists\n", key_id);
		return;
	}

	rte_hash_del_key(key_hash, &key_id);
	TAILQ_REMOVE(&_table_key_obj_list, kobj, next);

	ret = rte_tdi_table_key_destroy(port_id, kobj->key, &err);
	rte_free(kobj);
	if (ret != 0) {
		printf("Failed to destroy key from PMD, but still remove it from key list.\n");
		return;
	}

	printf("Key (%id) was destroyed.\n", key_id);
}

cmdline_parse_inst_t cmd_tdi_table_key_destroy = {
	.f = cmd_tdi_table_key_destroy_parsed,
	.data = NULL,
	.help_str = "tdi table key destroy <port_id> <key_id>",
	.tokens = {
		(void *)&cmd_tdi_table_key_destroy_tdi,
		(void *)&cmd_tdi_table_key_destroy_table,
		(void *)&cmd_tdi_table_key_destroy_key,
		(void *)&cmd_tdi_table_key_destroy_destroy,
		(void *)&cmd_tdi_table_key_destroy_port_id,
		(void *)&cmd_tdi_table_key_destroy_key_id,
		NULL,
	},
};

/* *** Destroy all tdi table key object *** */
struct cmd_tdi_table_key_destroy_all_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t destroy;
	cmdline_fixed_string_t all;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_all_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_all_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_all_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_all_destroy =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, destroy, "destroy");
static cmdline_parse_token_string_t cmd_tdi_table_key_destroy_all_all =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, all, "all");
static cmdline_parse_token_num_t cmd_tdi_table_key_destroy_all_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_destroy_all_result, port_id, RTE_UINT16);

static void cmd_tdi_table_key_destroy_all_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_destroy_all_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct tdi_table_key_obj *kobj;
	struct rte_hash *key_hash;
	struct rte_tdi_error err;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key object hash.\n");
		return;
	}

	rte_hash_free(key_hash);

	while ((kobj = TAILQ_FIRST(&_table_key_obj_list))) {
		TAILQ_REMOVE(&_table_key_obj_list, kobj, next);

		int ret = rte_tdi_table_key_destroy(port_id, kobj->key, &err);
		if (ret != 0)
			printf("Failed to destroy key (%d) from PMD, but still remove it from key list.\n", kobj->key_id);

		rte_free(kobj);
	}

	printf("All keys were destroyed.\n");
}

cmdline_parse_inst_t cmd_tdi_table_key_destroy_all = {
	.f = cmd_tdi_table_key_destroy_all_parsed,
	.data = NULL,
	.help_str = "tdi table key destroy all <port_id>",
	.tokens = {
		(void *)&cmd_tdi_table_key_destroy_all_tdi,
		(void *)&cmd_tdi_table_key_destroy_all_table,
		(void *)&cmd_tdi_table_key_destroy_all_key,
		(void *)&cmd_tdi_table_key_destroy_all_destroy,
		(void *)&cmd_tdi_table_key_destroy_all_all,
		(void *)&cmd_tdi_table_key_destroy_all_port_id,
		NULL,
	},
};

/* *** Set exact match table key field *** */
struct cmd_tdi_table_key_field_set_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t key_id;
	cmdline_fixed_string_t field;
	uint32_t field_id;
	cmdline_fixed_string_t value;
	cmdline_multi_string_t value_value;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_field =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, field, "field");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, field_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_value =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_result, value, "value");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_value_value =
	TOKEN_STRING_INITIALIZER(struct cmd_tdi_table_key_field_set_result,
			value_value, TOKEN_STRING_MULTI);

static void cmd_tdi_table_key_field_set_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_field_set_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_table_key_field_info kfinfo;
	struct rte_tdi_error err;
	uint8_t value_buf[16] = { 0 };
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_key_field_info_get(port_id, kobj->tinfo.id, field_id, &kfinfo, &err);
	if (ret != 0) {
		printf("Failed to get key field (%d) info of table (%d).\n", field_id, kobj->tinfo.id);
		return;
	}

	ret = parse_str_to_buf(res->value_value, value_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse value string into a matched byte array.\n");
		return;
	}

	printf("Set value in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", value_buf[i]);
	printf("\n");

	ret = rte_tdi_table_key_field_set(port_id, kobj->key, kfinfo.field_id, value_buf, kfinfo.byte_width, &err);
	if (ret != 0) {
		printf("Failed to set field (%d) of key (%d).\n", kfinfo.field_id, key_id);
		return;
	}

	for (i = 0; i < kobj->tinfo.key_field_num; i++) {
		if (kobj->tinfo.key_fields[i] != field_id)
			continue;

		rte_memcpy(kobj->key_value_buf1[i], value_buf, kfinfo.byte_width);
		break;
	}
}

cmdline_parse_inst_t cmd_tdi_table_key_field_set = {
	.f = cmd_tdi_table_key_field_set_parsed,
	.data = NULL,
	.help_str = "tdi table key set <port_id> <key_id> field <field_id> value <value>",
	.tokens = {
		(void *)&cmd_tdi_table_key_field_set_tdi,
		(void *)&cmd_tdi_table_key_field_set_table,
		(void *)&cmd_tdi_table_key_field_set_key,
		(void *)&cmd_tdi_table_key_field_set_set,
		(void *)&cmd_tdi_table_key_field_set_port_id,
		(void *)&cmd_tdi_table_key_field_set_key_id,
		(void *)&cmd_tdi_table_key_field_set_field,
		(void *)&cmd_tdi_table_key_field_set_field_id,
		(void *)&cmd_tdi_table_key_field_set_value,
		(void *)&cmd_tdi_table_key_field_set_value_value,
		NULL,
	},
};

/* *** Set wildcart match table key field *** */
struct cmd_tdi_table_key_field_set_with_mask_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t key_id;
	cmdline_fixed_string_t field_with_mask;
	uint32_t field_id;
	cmdline_fixed_string_t value;
	cmdline_multi_string_t value_value;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_mask_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_mask_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_field_with_mask =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, field_with_mask, "field_with_mask");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_mask_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, field_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_value =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_mask_result, value, "value");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_mask_value_value =
	TOKEN_STRING_INITIALIZER(struct cmd_tdi_table_key_field_set_with_mask_result,
			value_value, TOKEN_STRING_MULTI);

static void cmd_tdi_table_key_field_set_with_mask_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_field_set_with_mask_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_table_key_field_info kfinfo;
	struct rte_tdi_error err;
	uint8_t value_buf[16] = { 0 };
	uint8_t mask_buf[16] = { 0 };
	char value_str[80] = { 0 };
	char mask_str[80] = { 0 };
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_key_field_info_get(port_id, kobj->tinfo.id, field_id, &kfinfo, &err);
	if (ret != 0) {
		printf("Failed to get key field (%d) info of table (%d).\n", field_id, kobj->tinfo.id);
		return;
	}

	split_string(res->value_value, value_str, mask_str);

	ret = parse_str_to_buf(value_str, value_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse value string into a matched byte array.\n");
		return;
	}

	printf("Set value in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", value_buf[i]);
	printf("\n");

	ret = parse_str_to_buf(mask_str, mask_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse mask string into a matched byte array.\n");
		return;
	}

	printf("Set mask in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", mask_buf[i]);
	printf("\n");

	ret = rte_tdi_table_key_field_set_with_mask(port_id, kobj->key, kfinfo.field_id, value_buf,
						    mask_buf, kfinfo.byte_width, &err);
	if (ret != 0) {
		printf("Failed to set field (%d) of key (%d).\n", kfinfo.field_id, key_id);
		return;
	}
}

cmdline_parse_inst_t cmd_tdi_table_key_field_set_with_mask = {
	.f = cmd_tdi_table_key_field_set_with_mask_parsed,
	.data = NULL,
	.help_str = "tdi table key set <port_id> <key_id> field_with_mask <field_id> value <value>/<mask>",
	.tokens = {
		(void *)&cmd_tdi_table_key_field_set_with_mask_tdi,
		(void *)&cmd_tdi_table_key_field_set_with_mask_table,
		(void *)&cmd_tdi_table_key_field_set_with_mask_key,
		(void *)&cmd_tdi_table_key_field_set_with_mask_set,
		(void *)&cmd_tdi_table_key_field_set_with_mask_port_id,
		(void *)&cmd_tdi_table_key_field_set_with_mask_key_id,
		(void *)&cmd_tdi_table_key_field_set_with_mask_field_with_mask,
		(void *)&cmd_tdi_table_key_field_set_with_mask_field_id,
		(void *)&cmd_tdi_table_key_field_set_with_mask_value,
		(void *)&cmd_tdi_table_key_field_set_with_mask_value_value,
		NULL,
	},
};

/* *** Set range match table key field *** */
struct cmd_tdi_table_key_field_set_with_range_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t key_id;
	cmdline_fixed_string_t field_with_range;
	uint32_t field_id;
	cmdline_fixed_string_t value;
	cmdline_multi_string_t value_value;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_range_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_range_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_field_with_range =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, field_with_range, "field_with_range");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_range_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, field_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_value =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_range_result, value, "value");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_range_value_value =
	TOKEN_STRING_INITIALIZER(struct cmd_tdi_table_key_field_set_with_range_result,
			value_value, TOKEN_STRING_MULTI);

static void cmd_tdi_table_key_field_set_with_range_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_field_set_with_range_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_table_key_field_info kfinfo;
	struct rte_tdi_error err;
	uint8_t min_buf[16] = { 0 };
	uint8_t max_buf[16] = { 0 };
	char min_str[80] = { 0 };
	char max_str[80] = { 0 };
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_key_field_info_get(port_id, kobj->tinfo.id, field_id, &kfinfo, &err);
	if (ret != 0) {
		printf("Failed to get key field (%d) info of table (%d).\n", field_id, kobj->tinfo.id);
		return;
	}

	split_string(res->value_value, min_str, max_str);

	ret = parse_str_to_buf(min_str, min_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse min value string into a matched byte array.\n");
		return;
	}

	printf("Set min value in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", min_buf[i]);
	printf("\n");

	ret = parse_str_to_buf(max_str, max_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse max value string into a matched byte array.\n");
		return;
	}

	printf("Set max value in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", max_buf[i]);
	printf("\n");

	ret = rte_tdi_table_key_field_set_with_range(port_id, kobj->key, kfinfo.field_id, min_buf,
						     max_buf, kfinfo.byte_width, &err);
	if (ret != 0) {
		printf("Failed to set field (%d) of key (%d).\n", kfinfo.field_id, key_id);
		return;
	}
}

cmdline_parse_inst_t cmd_tdi_table_key_field_set_with_range = {
	.f = cmd_tdi_table_key_field_set_with_range_parsed,
	.data = NULL,
	.help_str = "tdi table key set <port_id> <key_id> field_with_range <field_id> value <min>/<max>",
	.tokens = {
		(void *)&cmd_tdi_table_key_field_set_with_range_tdi,
		(void *)&cmd_tdi_table_key_field_set_with_range_table,
		(void *)&cmd_tdi_table_key_field_set_with_range_key,
		(void *)&cmd_tdi_table_key_field_set_with_range_set,
		(void *)&cmd_tdi_table_key_field_set_with_range_port_id,
		(void *)&cmd_tdi_table_key_field_set_with_range_key_id,
		(void *)&cmd_tdi_table_key_field_set_with_range_field_with_range,
		(void *)&cmd_tdi_table_key_field_set_with_range_field_id,
		(void *)&cmd_tdi_table_key_field_set_with_range_value,
		(void *)&cmd_tdi_table_key_field_set_with_range_value_value,
		NULL,
	},
};

/* *** Set lpm match table key field *** */
struct cmd_tdi_table_key_field_set_with_prefix_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t key;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t key_id;
	cmdline_fixed_string_t field_with_prefix;
	uint32_t field_id;
	cmdline_fixed_string_t value;
	cmdline_multi_string_t value_value;
};

static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, key, "key");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_prefix_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_prefix_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_field_with_prefix =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, field_with_prefix, "field_with_prefix");
static cmdline_parse_token_num_t cmd_tdi_table_key_field_set_with_prefix_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, field_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_value =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_key_field_set_with_prefix_result, value, "value");
static cmdline_parse_token_string_t cmd_tdi_table_key_field_set_with_prefix_value_value =
	TOKEN_STRING_INITIALIZER(struct cmd_tdi_table_key_field_set_with_prefix_result,
			value_value, TOKEN_STRING_MULTI);

static void cmd_tdi_table_key_field_set_with_prefix_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_key_field_set_with_prefix_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t key_id = res->key_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_table_key_field_info kfinfo;
	struct rte_tdi_error err;
	uint8_t val_buf[16] = { 0 };
	char val_str[80] = { 0 };
	char pfx_str[80] = { 0 };
	uint16_t prefix = 0;
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_key_field_info_get(port_id, kobj->tinfo.id, field_id, &kfinfo, &err);
	if (ret != 0) {
		printf("Failed to get key field (%d) info of table (%d).\n", field_id, kobj->tinfo.id);
		return;
	}

	split_string(res->value_value, val_str, pfx_str);

	ret = parse_str_to_buf(val_str, val_buf, kfinfo.byte_width);
	if (ret < 0 || ret > kfinfo.byte_width) {
		printf("Failed to parse min value string into a matched byte array.\n");
		return;
	}

	printf("Set min value in bytes: ");
	for (i = 0; i < kfinfo.byte_width; i++)
		printf("%02X ", val_buf[i]);
	printf("\n");

	if (!parse_uint16(pfx_str, &prefix)) {
		printf("Failed to parse prefix.\n");
		return;
	}
	printf("Set prefix :%d\n", prefix);

	ret = rte_tdi_table_key_field_set_with_prefix(port_id, kobj->key, kfinfo.field_id, val_buf,
						      kfinfo.byte_width, prefix, &err);
	if (ret != 0) {
		printf("Failed to set field (%d) of key (%d).\n", kfinfo.field_id, key_id);
		return;
	}
}

cmdline_parse_inst_t cmd_tdi_table_key_field_set_with_prefix = {
	.f = cmd_tdi_table_key_field_set_with_prefix_parsed,
	.data = NULL,
	.help_str = "tdi table key set <port_id> <key_id> field_with_prefix <field_id> value <value>|<prefix>",
	.tokens = {
		(void *)&cmd_tdi_table_key_field_set_with_prefix_tdi,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_table,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_key,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_set,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_port_id,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_key_id,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_field_with_prefix,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_field_id,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_value,
		(void *)&cmd_tdi_table_key_field_set_with_prefix_value_value,
		NULL,
	},
};

/* *** Create tdi action object *** */
struct cmd_tdi_action_create_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t create;
	uint16_t port_id;
	uint32_t table_id;
	uint32_t spec_id;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_create_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_create_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_create_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_create_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_create_create =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_create_result, create, "create");
static cmdline_parse_token_num_t cmd_tdi_action_create_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_create_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_create_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_create_result, table_id, RTE_UINT32);
static cmdline_parse_token_num_t cmd_tdi_action_create_spec_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_create_result, spec_id, RTE_UINT32);
static cmdline_parse_token_num_t cmd_tdi_action_create_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_create_result, action_id, RTE_UINT32);

static void cmd_tdi_action_create_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_create_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t spec_id = res->spec_id;
	uint32_t action_id = res->action_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;
	struct rte_tdi_error err;
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action object hash.\n");
		return;
	}

	if (rte_hash_lookup(action_hash, &action_id) >= 0) {
		printf("Action with id %d already exists\n", action_id);
		return;
	}

	aobj = rte_zmalloc(NULL, sizeof(struct tdi_action_obj), 0);
	if (aobj == NULL) {
		printf("Out of memory!\n");
		return;
	}

	aobj->action_id = action_id;

	ret = rte_tdi_table_info_get(port_id, table_id, &aobj->tinfo, &err);
	if (ret != 0) {
		printf("Failed to get table info of id %d.\n", table_id);
		rte_free(aobj);
		return;
	}

	ret = rte_tdi_action_spec_info_get(port_id, spec_id, &aobj->asinfo, &err);
	if (ret != 0) {
		printf("Failed to get action spec info of id %d.\n", spec_id);
		rte_free(aobj);
		return;
	}

	for (i = 0; i < aobj->asinfo.field_num; i++) {
		uint32_t field_id = aobj->asinfo.fields[i];

		ret = rte_tdi_action_spec_field_info_get(port_id, spec_id, field_id,
							 &aobj->fields[i], &err);
		if (ret != 0) {
			printf("Failed to get action spec %d field info of id %d.\n", spec_id, field_id);
			rte_free(aobj);
			return;
		}
	}

	ret = rte_tdi_action_create(port_id, table_id, spec_id, &aobj->action, &err);
	if (ret != 0) {
		printf("Failed to create key form table with id %d and spec_id %d.\n",
				table_id, spec_id);
		rte_free(aobj);
		return;
	}

	ret = rte_hash_add_key_data(action_hash, &action_id, aobj);
	if (ret != 0) {
		rte_tdi_action_destroy(port_id, aobj->action, &err);
		printf("Failed to add action to hash table, action destroyed.\n");
		return;
	}

	TAILQ_INSERT_TAIL(&_action_obj_list, aobj, next);

	printf("Action (%d) was created\n", action_id);
}

cmdline_parse_inst_t cmd_tdi_action_create = {
	.f = cmd_tdi_action_create_parsed,
	.data = NULL,
	.help_str = "tdi action create <port_id> <table_id> <spec_id> <action_id>",
	.tokens = {
		(void *)&cmd_tdi_action_create_tdi,
		(void *)&cmd_tdi_action_create_action,
		(void *)&cmd_tdi_action_create_create,
		(void *)&cmd_tdi_action_create_port_id,
		(void *)&cmd_tdi_action_create_table_id,
		(void *)&cmd_tdi_action_create_spec_id,
		(void *)&cmd_tdi_action_create_action_id,
		NULL,
	},
};

/* *** Destroy tdi action object *** */
struct cmd_tdi_action_destroy_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t destroy;
	uint16_t port_id;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_destroy_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_destroy_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_destroy_destroy =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_result, destroy, "destroy");
static cmdline_parse_token_num_t cmd_tdi_action_destroy_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_destroy_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_destroy_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_destroy_result, action_id, RTE_UINT32);

static void cmd_tdi_action_destroy_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_destroy_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t action_id = res->action_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action object hash.\n");
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action with id %d not exists\n", action_id);
		return;
	}

	rte_hash_del_key(action_hash, &action_id);
	TAILQ_REMOVE(&_action_obj_list, aobj, next);

	ret = rte_tdi_action_destroy(port_id, aobj->action, &err);
	rte_free(aobj);
	if (ret != 0) {
		printf("Failed to destroy action from PMD, but still remove it from action list.\n");
		return;
	}

	printf("Action (%d) was destroyed.\n", action_id);
}

cmdline_parse_inst_t cmd_tdi_action_destroy = {
	.f = cmd_tdi_action_destroy_parsed,
	.data = NULL,
	.help_str = "tdi action destroy <port_id> <action_id>",
	.tokens = {
		(void *)&cmd_tdi_action_destroy_tdi,
		(void *)&cmd_tdi_action_destroy_action,
		(void *)&cmd_tdi_action_destroy_destroy,
		(void *)&cmd_tdi_action_destroy_port_id,
		(void *)&cmd_tdi_action_destroy_action_id,
		NULL,
	},
};

/* *** Destroy all tdi action object *** */
struct cmd_tdi_action_destroy_all_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t destroy;
	cmdline_fixed_string_t all;
	uint16_t port_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_destroy_all_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_all_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_destroy_all_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_all_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_destroy_all_destroy =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_all_result, destroy, "destroy");
static cmdline_parse_token_string_t cmd_tdi_action_destroy_all_all =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_destroy_all_result, all, "all");
static cmdline_parse_token_num_t cmd_tdi_action_destroy_all_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_destroy_all_result, port_id, RTE_UINT16);

static void cmd_tdi_action_destroy_all_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_destroy_all_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;
	struct rte_tdi_error err;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action object hash.\n");
		return;
	}

	rte_hash_free(action_hash);

	while ((aobj = TAILQ_FIRST(&_action_obj_list))) {
		TAILQ_REMOVE(&_action_obj_list, aobj, next);

		int ret = rte_tdi_action_destroy(port_id, aobj->action, &err);
		if (ret != 0)
			printf("Failed to destroy action (%d) from PMD, but still remove it from action list.\n", aobj->action_id);

		rte_free(aobj);
	}

	printf("All actions were destroyed.\n");
}

cmdline_parse_inst_t cmd_tdi_action_destroy_all = {
	.f = cmd_tdi_action_destroy_all_parsed,
	.data = NULL,
	.help_str = "tdi table action destroy all <port_id>",
	.tokens = {
		(void *)&cmd_tdi_action_destroy_all_tdi,
		(void *)&cmd_tdi_action_destroy_all_action,
		(void *)&cmd_tdi_action_destroy_all_destroy,
		(void *)&cmd_tdi_action_destroy_all_all,
		(void *)&cmd_tdi_action_destroy_all_port_id,
		NULL,
	},
};

/* *** Set action field *** */
struct cmd_tdi_action_field_set_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t action_id;
	cmdline_fixed_string_t field;
	uint32_t field_id;
	cmdline_fixed_string_t value;
	cmdline_multi_string_t value_value;
};

static cmdline_parse_token_string_t cmd_tdi_action_field_set_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_set_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_field_set_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_set_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_field_set_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_set_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_action_field_set_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_set_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_field_set_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_set_result, action_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_action_field_set_field =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_set_result, field, "field");
static cmdline_parse_token_num_t cmd_tdi_action_field_set_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_set_result, field_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_action_field_set_value =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_set_result, value, "value");
static cmdline_parse_token_string_t cmd_tdi_action_field_set_value_value =
	TOKEN_STRING_INITIALIZER(struct cmd_tdi_action_field_set_result,
			value_value, TOKEN_STRING_MULTI);

static void cmd_tdi_action_field_set_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{

	struct cmd_tdi_action_field_set_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t action_id = res->action_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *action_hash;
	struct tdi_action_obj *aobj;
	struct rte_tdi_action_spec_field_info finfo;
	struct rte_tdi_error err;
	uint8_t value_buf[16] = { 0 };
	uint16_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get actioni hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action object with id %d does not exist.\n", action_id);
		return;
	}

	ret = rte_tdi_action_spec_field_info_get(port_id, aobj->asinfo.id, field_id, &finfo, &err);
	if (ret != 0) {
		printf("Failed to get field (%d) info of action spec (%d).\n", field_id, aobj->asinfo.id);
		return;
	}

	ret = parse_str_to_buf(res->value_value, value_buf, finfo.byte_width);
	if (ret < 0 || ret > finfo.byte_width) {
		printf("Failed to parse value string into a matched byte array.\n");
		return;
	}

	printf("Set value in bytes: ");
	for (i = 0; i < finfo.byte_width; i++)
		printf("%02X ", value_buf[i]);
	printf("\n");

	ret = rte_tdi_action_field_set(port_id, aobj->action, finfo.field_id, value_buf, finfo.byte_width, &err);
	if (ret != 0) {
		printf("Failed to get field (%d) of action (%d).\n", finfo.field_id, action_id);
		return;
	}

	for (i = 0; i < aobj->asinfo.field_num; i++) {
		if (aobj->asinfo.fields[i] != field_id)
			continue;

		rte_memcpy(aobj->value_buf[i], value_buf, finfo.byte_width);
		break;
	}
}

cmdline_parse_inst_t cmd_tdi_action_field_set = {
	.f = cmd_tdi_action_field_set_parsed,
	.data = NULL,
	.help_str = "tdi table action set <port_id> <action_id> field <field_id> value <value>",
	.tokens = {
		(void *)&cmd_tdi_action_field_set_tdi,
		(void *)&cmd_tdi_action_field_set_action,
		(void *)&cmd_tdi_action_field_set_set,
		(void *)&cmd_tdi_action_field_set_port_id,
		(void *)&cmd_tdi_action_field_set_action_id,
		(void *)&cmd_tdi_action_field_set_field,
		(void *)&cmd_tdi_action_field_set_field_id,
		(void *)&cmd_tdi_action_field_set_value,
		(void *)&cmd_tdi_action_field_set_value_value,
		NULL,
	},
};

/* *** Get action field *** */
struct cmd_tdi_action_field_get_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t get;
	uint16_t port_id;
	uint32_t action_id;
	cmdline_fixed_string_t field;
	uint32_t field_id;
};

static cmdline_parse_token_string_t cmd_tdi_action_field_get_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_get_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_action_field_get_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_get_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_action_field_get_get =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_get_result, get, "get");
static cmdline_parse_token_num_t cmd_tdi_action_field_get_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_get_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_action_field_get_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_get_result, action_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_action_field_get_field =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_action_field_get_result, field, "field");
static cmdline_parse_token_num_t cmd_tdi_action_field_get_field_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_action_field_get_result, field_id, RTE_UINT32);

static void cmd_tdi_action_field_get_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_action_field_get_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t action_id = res->action_id;
	uint32_t field_id = res->field_id;
	struct rte_hash *action_hash;
	struct tdi_action_obj *aobj;
	struct rte_tdi_action_spec_field_info finfo;
	struct rte_tdi_error err;
	uint8_t value_buf[16];
	uint16_t size;
	uint16_t i;
	char str_buf[50];
	char *hex;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get actioni hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action object with id %d does not exist.\n", action_id);
		return;
	}

	ret = rte_tdi_action_spec_field_info_get(port_id, aobj->asinfo.id, field_id, &finfo, &err);
	if (ret != 0) {
		printf("Failed to get field (%d) info of action spec (%d).\n", field_id, aobj->asinfo.id);
		return;
	}

	size = 16;
	ret = rte_tdi_action_field_get(port_id, aobj->action, finfo.field_id, value_buf, &size, &err);
	if (ret != 0) {
		printf("Failed to get field (%d) of action (%d).\n", finfo.field_id, action_id);
		return;
	}

	printf("%-15s%d\n", "Spec ID:", finfo.spec_id);
	printf("%-15s%d\n", "Field ID:", finfo.field_id);
	printf("%-15s%s\n", "Name:", finfo.name);

	hex = str_buf;
	for (i = 0; i < size; i++)
		hex += sprintf(hex, "%02X ", value_buf[i]);

	printf("%-15s%s\n", "value:", str_buf);

}

cmdline_parse_inst_t cmd_tdi_action_field_get = {
	.f = cmd_tdi_action_field_get_parsed,
	.data = NULL,
	.help_str = "tdi action get <port_id> <action_id> field <field_id>",
	.tokens = {
		(void *)&cmd_tdi_action_field_get_tdi,
		(void *)&cmd_tdi_action_field_get_action,
		(void *)&cmd_tdi_action_field_get_get,
		(void *)&cmd_tdi_action_field_get_port_id,
		(void *)&cmd_tdi_action_field_get_action_id,
		(void *)&cmd_tdi_action_field_get_field,
		(void *)&cmd_tdi_action_field_get_field_id,
		NULL,
	},
};

/* *** Add table entry *** */
struct cmd_tdi_table_entry_add_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t add;
	uint16_t port_id;
	uint32_t table_id;
	cmdline_fixed_string_t key;
	uint32_t key_id;
	cmdline_fixed_string_t action;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_entry_add_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_entry_add_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_entry_add_entry =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, entry, "entry");
static cmdline_parse_token_string_t cmd_tdi_table_entry_add_add  =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, add, "add");
static cmdline_parse_token_num_t cmd_tdi_table_entry_add_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_entry_add_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, table_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_add_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, key, "key");
static cmdline_parse_token_num_t cmd_tdi_table_entry_add_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_add_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, action, "action");
static cmdline_parse_token_num_t cmd_tdi_table_entry_add_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_add_result, action_id, RTE_UINT32);

static void cmd_tdi_table_entry_add_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_entry_add_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t key_id = res->key_id;
	uint32_t action_id = res->action_id;
	struct rte_hash *key_hash;
	struct rte_hash *action_hash;
	struct tdi_table_key_obj *kobj;
	struct tdi_action_obj *aobj;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key hash table.\n");
		return;
	}

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action object with id %d does not exist.\n", action_id);
		return;
	}

	ret = rte_tdi_table_entry_add(port_id, table_id, kobj->key, aobj->action, &err);
	if (ret != 0) {
		printf("Failed to add entry to table (%d) with key (%d) and action (%d).\n",
				table_id, key_id, action_id);
		return;
	}

	printf("Entry with key (%d) and action (%d) was added.\n", key_id, action_id);
}

cmdline_parse_inst_t cmd_tdi_table_entry_add = {
	.f = cmd_tdi_table_entry_add_parsed,
	.data = NULL,
	.help_str = "tdi table entry add <port_id> <table_id> key <key_id> action <action_id>",
	.tokens = {
		(void *)&cmd_tdi_table_entry_add_tdi,
		(void *)&cmd_tdi_table_entry_add_table,
		(void *)&cmd_tdi_table_entry_add_entry,
		(void *)&cmd_tdi_table_entry_add_add,
		(void *)&cmd_tdi_table_entry_add_port_id,
		(void *)&cmd_tdi_table_entry_add_table_id,
		(void *)&cmd_tdi_table_entry_add_key,
		(void *)&cmd_tdi_table_entry_add_key_id,
		(void *)&cmd_tdi_table_entry_add_action,
		(void *)&cmd_tdi_table_entry_add_action_id,
		NULL,
	},
};

/* *** Query table entry *** */
struct cmd_tdi_table_entry_query_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t query;
	uint16_t port_id;
	uint32_t table_id;
	cmdline_fixed_string_t key;
	uint32_t key_id;
	cmdline_fixed_string_t action;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_entry_query_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_entry_query_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_entry_query_entry =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, entry, "entry");
static cmdline_parse_token_string_t cmd_tdi_table_entry_query_query  =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, query, "query");
static cmdline_parse_token_num_t cmd_tdi_table_entry_query_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_entry_query_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, table_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_query_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, key, "key");
static cmdline_parse_token_num_t cmd_tdi_table_entry_query_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, key_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_query_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, action, "action");
static cmdline_parse_token_num_t cmd_tdi_table_entry_query_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_query_result, action_id, RTE_UINT32);

static void cmd_tdi_table_entry_query_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_entry_query_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t key_id = res->key_id;
	uint32_t action_id = res->action_id;
	struct rte_hash *key_hash;
	struct rte_hash *action_hash;
	struct tdi_table_key_obj *kobj;
	struct tdi_action_obj *aobj;
	struct rte_tdi_action *action;
	struct rte_tdi_error err;
	uint16_t size;
	uint32_t i;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key hash table.\n");
		return;
	}

	action_hash = get_tdi_action_obj_hash();
	if (action_hash == NULL) {
		printf("Failed to get action hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) >= 0) {
		printf("Action object with id %d already exist.\n", action_id);
		return;
	}

	ret = rte_tdi_table_entry_query(port_id, table_id, kobj->key, &action, &err);
	if (ret != 0) {
		printf("Failed to query entry from table (%d) with key (%d).\n",
				table_id, key_id);
		return;
	}

	aobj = rte_zmalloc(NULL, sizeof(struct tdi_action_obj), 0);
	if (aobj == NULL) {
		printf("Out of memory, fail to create tdi action object.\n");
		goto err;
	}

	aobj->action = action;
	ret = rte_tdi_table_info_get(port_id, table_id, &aobj->tinfo, &err);
	if (ret != 0) {
		printf("Failed to get table info with table_id %d.\n", table_id);
		goto err;
	}

	ret = rte_tdi_action_spec_info_get(port_id, action->spec_id, &aobj->asinfo, &err);
	if (ret != 0) {
		printf("Failed to get action spec info with spec_id %d.\n", action->spec_id);
		goto err;
	}

	for (i = 0; i < aobj->asinfo.field_num; i++) {
		uint32_t field_id = aobj->asinfo.fields[i];

		size = TDI_FIELD_VALUE_BYTE_MAX;
		ret = rte_tdi_action_field_get(port_id, action, field_id, aobj->value_buf[i], &size, &err);
		if (ret != 0) {
			printf("Failed to get action field value with id %d.\n", field_id);
			goto err;
		}
	}

	ret = rte_hash_add_key_data(action_hash, &action_id, (void **)&aobj);
	if (ret != 0) {
		rte_tdi_action_destroy(port_id, aobj->action, &err);
		printf("Failed to add action to hash table, action destroyed.\n");
		return;
	}

	printf("Entry with key (%d) was queryed.\n", key_id);

	print_table_key_obj(kobj);
	print_action_obj(aobj);

	return;
err:
	rte_tdi_action_destroy(port_id, action, &err);
}

cmdline_parse_inst_t cmd_tdi_table_entry_query = {
	.f = cmd_tdi_table_entry_query_parsed,
	.data = NULL,
	.help_str = "tdi table entry query <port_id> key <key_id> action <action_id>",
	.tokens = {
		(void *)&cmd_tdi_table_entry_query_tdi,
		(void *)&cmd_tdi_table_entry_query_table,
		(void *)&cmd_tdi_table_entry_query_entry,
		(void *)&cmd_tdi_table_entry_query_query,
		(void *)&cmd_tdi_table_entry_query_port_id,
		(void *)&cmd_tdi_table_entry_query_table_id,
		(void *)&cmd_tdi_table_entry_query_key,
		(void *)&cmd_tdi_table_entry_query_key_id,
		(void *)&cmd_tdi_table_entry_query_action,
		(void *)&cmd_tdi_table_entry_query_action_id,
		NULL,
	},
};


/* *** Delete table entry *** */
struct cmd_tdi_table_entry_del_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t del;
	uint16_t port_id;
	uint32_t table_id;
	cmdline_fixed_string_t key;
	uint32_t key_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_entry_del_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_entry_del_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_entry_del_entry =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, entry, "entry");
static cmdline_parse_token_string_t cmd_tdi_table_entry_del_del  =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, del, "del");
static cmdline_parse_token_num_t cmd_tdi_table_entry_del_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_entry_del_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, table_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_del_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, key, "key");
static cmdline_parse_token_num_t cmd_tdi_table_entry_del_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_del_result, key_id, RTE_UINT32);

static void cmd_tdi_table_entry_del_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_entry_del_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t key_id = res->key_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_entry_del(port_id, table_id, kobj->key, &err);
	if (ret != 0) {
		printf("Failed to delete entry from table (%d) with key (%d).\n",
				table_id, key_id);
		return;
	}

	printf("Entry with key (%d) was deleted.\n", key_id);
}

cmdline_parse_inst_t cmd_tdi_table_entry_del = {
	.f = cmd_tdi_table_entry_del_parsed,
	.data = NULL,
	.help_str = "tdi table entry del <port_id> <table_id> key <key_id>",
	.tokens = {
		(void *)&cmd_tdi_table_entry_del_tdi,
		(void *)&cmd_tdi_table_entry_del_table,
		(void *)&cmd_tdi_table_entry_del_entry,
		(void *)&cmd_tdi_table_entry_del_del,
		(void *)&cmd_tdi_table_entry_del_port_id,
		(void *)&cmd_tdi_table_entry_del_table_id,
		(void *)&cmd_tdi_table_entry_del_key,
		(void *)&cmd_tdi_table_entry_del_key_id,
		NULL,
	},
};

/* *** Query table entry hit count *** */
struct cmd_tdi_table_entry_count_query_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t count;
	cmdline_fixed_string_t query;
	uint16_t port_id;
	uint32_t table_id;
	cmdline_fixed_string_t key;
	uint32_t key_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_entry =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, entry, "entry");
static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_count =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, count, "count");
static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_query =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, query, "query");
static cmdline_parse_token_num_t cmd_tdi_table_entry_count_query_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_entry_count_query_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, table_id, RTE_UINT32);
static cmdline_parse_token_string_t cmd_tdi_table_entry_count_query_key =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, key, "key");
static cmdline_parse_token_num_t cmd_tdi_table_entry_count_query_key_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_entry_count_query_result, key_id, RTE_UINT32);

static void cmd_tdi_table_entry_count_query_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_entry_count_query_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t key_id = res->key_id;
	struct rte_hash *key_hash;
	struct tdi_table_key_obj *kobj;
	struct rte_tdi_error err;
	struct rte_tdi_query_count cnt;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	key_hash = get_tdi_table_key_obj_hash();
	if (key_hash == NULL) {
		printf("Failed to get table key hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(key_hash, &key_id, (void **)&kobj) < 0) {
		printf("Key object with id %d does not exist.\n", key_id);
		return;
	}

	ret = rte_tdi_table_entry_count_query(port_id, table_id, kobj->key, &cnt, &err);
	if (ret != 0) {
		printf("Failed to query entry count from table (%d) with key (%d).\n",
				table_id, key_id);
		return;
	}

	printf("Counter Queried:\n");
	if (cnt.hits_set)
		printf("%-15s%-15ld\n", "hits", cnt.hits);
	if (cnt.bytes_set)
		printf("%-15s%-15ld\n", "bytes", cnt.bytes);
}

cmdline_parse_inst_t cmd_tdi_table_entry_count_query = {
	.f = cmd_tdi_table_entry_count_query_parsed,
	.data = NULL,
	.help_str = "tdi table entry count query <port_id> key <key_id>",
	.tokens = {
		(void *)&cmd_tdi_table_entry_count_query_tdi,
		(void *)&cmd_tdi_table_entry_count_query_table,
		(void *)&cmd_tdi_table_entry_count_query_entry,
		(void *)&cmd_tdi_table_entry_count_query_count,
		(void *)&cmd_tdi_table_entry_count_query_query,
		(void *)&cmd_tdi_table_entry_count_query_port_id,
		(void *)&cmd_tdi_table_entry_count_query_table_id,
		(void *)&cmd_tdi_table_entry_count_query_key,
		(void *)&cmd_tdi_table_entry_count_query_key_id,
		NULL,
	},
};

/* *** Set table default action *** */
struct cmd_tdi_table_default_action_set_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t dflt;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t set;
	uint16_t port_id;
	uint32_t table_id;
	uint32_t action_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_default_action_set_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_set_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_set_default =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, dflt, "default");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_set_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_set_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, set, "set");
static cmdline_parse_token_num_t cmd_tdi_table_default_action_set_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_default_action_set_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, table_id, RTE_UINT32);
static cmdline_parse_token_num_t cmd_tdi_table_default_action_set_action_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_default_action_set_result, action_id, RTE_UINT32);

static void cmd_tdi_table_default_action_set_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_default_action_set_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	uint32_t action_id = res->port_id;
	struct tdi_action_obj *aobj;
	struct rte_hash *action_hash;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	action_hash = get_tdi_action_obj_hash();
	if (action_hash != NULL) {
		printf("Failed to get action hash table.\n");
		return;
	}

	if (rte_hash_lookup_data(action_hash, &action_id, (void **)&aobj) < 0) {
		printf("Action with id %d not exists\n", action_id);
		return;
	}

	ret = rte_tdi_table_default_action_set(port_id, table_id, aobj->action, &err);
	if (ret != 0)
		printf("Failed to set default action for table (%d) with action (%d).\n",
				table_id, action_id);

	printf("Set default action for table (%d).\n", table_id);
}

cmdline_parse_inst_t cmd_tdi_table_default_action_set = {
	.f = cmd_tdi_table_default_action_set_parsed,
	.data = NULL,
	.help_str = "tdi table default action set <port_id> <table_id> <action_id>",
	.tokens = {
		(void *)&cmd_tdi_table_default_action_set_tdi,
		(void *)&cmd_tdi_table_default_action_set_table,
		(void *)&cmd_tdi_table_default_action_set_default,
		(void *)&cmd_tdi_table_default_action_set_action,
		(void *)&cmd_tdi_table_default_action_set_set,
		(void *)&cmd_tdi_table_default_action_set_port_id,
		(void *)&cmd_tdi_table_default_action_set_table_id,
		(void *)&cmd_tdi_table_default_action_set_action_id,
		NULL,
	},
};

/* *** Cancel table default action *** */
struct cmd_tdi_table_default_action_cancel_result {
	cmdline_fixed_string_t tdi;
	cmdline_fixed_string_t table;
	cmdline_fixed_string_t dflt;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t cancel;
	uint16_t port_id;
	uint32_t table_id;
};

static cmdline_parse_token_string_t cmd_tdi_table_default_action_cancel_tdi =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, tdi, "tdi");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_cancel_table =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, table, "table");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_cancel_default =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, dflt, "default");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_cancel_action =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, action, "action");
static cmdline_parse_token_string_t cmd_tdi_table_default_action_cancel_cancel =
	TOKEN_STRING_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, cancel, "cancel");
static cmdline_parse_token_num_t cmd_tdi_table_default_action_cancel_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_tdi_table_default_action_cancel_table_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_tdi_table_default_action_cancel_result, table_id, RTE_UINT32);

static void cmd_tdi_table_default_action_cancel_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_tdi_table_default_action_cancel_result *res = parsed_result;
	uint16_t port_id = res->port_id;
	uint32_t table_id = res->table_id;
	struct rte_tdi_error err;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	ret = rte_tdi_table_default_action_cancel(port_id, table_id, &err);
	if (ret != 0)
		printf("Failed to cancel default action for table (%d).\n", table_id);

	printf("Default action canceled from table (%d).\n", table_id);
}

cmdline_parse_inst_t cmd_tdi_table_default_action_cancel = {
	.f = cmd_tdi_table_default_action_cancel_parsed,
	.data = NULL,
	.help_str = "tdi table default action cancel <port_id> <table_id>",
	.tokens = {
		(void *)&cmd_tdi_table_default_action_cancel_tdi,
		(void *)&cmd_tdi_table_default_action_cancel_table,
		(void *)&cmd_tdi_table_default_action_cancel_default,
		(void *)&cmd_tdi_table_default_action_cancel_action,
		(void *)&cmd_tdi_table_default_action_cancel_cancel,
		(void *)&cmd_tdi_table_default_action_cancel_port_id,
		(void *)&cmd_tdi_table_default_action_cancel_table_id,
		NULL,
	},
};

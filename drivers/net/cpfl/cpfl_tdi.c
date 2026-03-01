/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <rte_tailq.h>
#include <rte_hash_crc.h>
#include <rte_tailq.h>

#include "cpfl_tdi.h"
#include "cpfl_tdi_entry.h"
#include "cpfl_fxp_rule.h"
#include "icpf_actions.h"

static void dump_buf(const uint8_t *buf, int len)
{
	int i = 0;

	for (i = 0; i < len; i++) {
		printf("%02X ", buf[i]);
		if (i % 16 == 15 || i == len -1)
			printf("\n");
	}
}

/*help function to do right shift on a byte array */
static void shift_right(uint8_t* buf, int length, uint32_t shift_amount)
{
	int  bytes = shift_amount / 8;
	int remaining = shift_amount % 8;
	int i = 0;

	if (shift_amount == 0)
		return;
    
	// shift the bytes to the right
	for (i = 0; i < length - bytes; i++)
		buf[i] = buf[i + bytes];
	for (i = length - bytes; i < length; i++)
		buf[i] = 0;
		
	// shift the remaining bits to the right
	if (remaining > 0) {
		int left = 8 - remaining;
		uint8_t pre_left_byte = 0;
		for (i = length - bytes - 1; i >= 0; i--) {
			uint8_t right_byte = buf[i] >> remaining;
			uint8_t left_byte = buf[i] << left;

			buf[i] = pre_left_byte | right_byte;
			pre_left_byte = left_byte;
		}
	}	
}

/*help function to do left shift on a byte array */
static void shift_left(uint8_t *buf, int length, uint32_t shift_amount)
{
	uint32_t i;
	int j;
	uint32_t carry = 0;

	if (shift_amount == 0)
		return;

	for (i = 0; i < shift_amount; i += 8) {
		for (j = 0; j < length; j++) {
			uint32_t temp = (buf[j] << (shift_amount - i)) | carry;

			carry = (temp >> 8) & 0xff;
			buf[j] = temp & 0xff;
		}
	}
}

/* help function to init a mask array with bit_width */
static void init_msk_buf(uint8_t *buf, int length, uint32_t bit_width)
{
	uint32_t i;

	memset(buf, 0, length);
	for (i = 0; i < bit_width; i++) {
		shift_left(buf, length, 1);
		buf[0] += 1;
	}
}

/* help function to OR a byte array with value and mask */
static void or_buf(uint8_t *buf, int length, uint8_t *values, uint8_t *mask)
{
	int i;

	for (i = 0; i < length; i++)
		buf[i] = (values[i] & mask[i]) | (buf[i] & ~mask[i]);
}

static void set_buf(uint8_t *buf, int length, uint8_t *values, uint8_t *mask)
{
	int i;

	for (i = 0; i < length; i++)
		buf[i] = values[i] & mask[i];
}

static uint32_t
to_action_code(struct cpfl_tdi_hw_action *ha, uint8_t *val)
{
	switch (ha->action_code) {
	case CPFL_TDI_ACTION_CODE_SET1A_24b:
		switch (ha->index) {
		case 0: /* mod addr */
			return icpf_act_mod_addr(ha->prec,
						 *(uint32_t *)val)
				.data;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1A_24b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1_16b:
		switch (ha->index) {
		case 2: /* set vsi */
			return icpf_act_fwd_vsi(0,
						 ha->prec,
						 ICPF_PE_LAN,
						 *(uint16_t *)val)
				.data;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1_16b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
		switch (ha->setmd_action_code) {
		case CPFL_TDI_SETMD_ACTION_CODE_SET_16b:
			return icpf_act_set_md16(ha->index,
						 ha->prec,
						 ha->type_id,
						 ha->offset,
						 *(uint16_t *)val)
				.data;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1b_24b setmd code %d", ha->setmd_action_code);
			break;
		}
		break;
	default:
		PMD_DRV_LOG(WARNING, "Unsupported action code code %d", ha->action_code);
		break;
	}

	return 0;
}

static int
cpfl_tdi_table_list_popup(struct rte_eth_dev *dev,
			  struct rte_tdi_id_list **list,
			  struct rte_tdi_error *error)
{
	struct cpfl_adapter_ext *adapter = CPFL_DEV_TO_ADAPTER(dev);
	struct cpfl_tdi_table_node *node;
	void *list_buf;
	void *temp;
	int size;
	int i;

	size = sizeof(struct rte_tdi_id_list) + sizeof(uint32_t) * (adapter->tdi_program->table_num);
	list_buf = rte_malloc(NULL, size, 0);

	if (!list_buf) {
		if (error)
			error->type = RTE_TDI_ERROR_TYPE_TABLE_LIST;
		return -ENOMEM;
	}

	*list = list_buf;
	(*list)->num = adapter->tdi_program->table_num;

	i = 0;
	RTE_TAILQ_FOREACH_SAFE(node, &adapter->tdi_table_list, next, temp) {
		const struct cpfl_tdi_table *table = node->table;

		(*list)->ids[i++] = table->handle;
	}

	return 0;
}

static int
cpfl_tdi_table_info_get(struct rte_eth_dev *dev,
			uint32_t table_id,
			struct rte_tdi_drv_table_info *info,
			struct rte_tdi_error *error)
{
	struct cpfl_adapter_ext *adapter = CPFL_DEV_TO_ADAPTER(dev);
	struct cpfl_tdi_table_node *node;
	void *temp;
	int i;

	RTE_TAILQ_FOREACH_SAFE(node, &adapter->tdi_table_list, next, temp) {
		const struct cpfl_tdi_table *table = node->table;

		if (table->handle != table_id)
			continue;

		if (table->match_key_field_num > RTE_TDI_KEY_FIELD_NUM_MAX) {
			PMD_DRV_LOG(ERR, "Too many fields (%d) in tdi table %s",
				    table->match_key_field_num, table->name);
			goto err;
		}

		if (table->action_num > RTE_TDI_ACTION_SPEC_NUM_MAX) {
			PMD_DRV_LOG(ERR, "Too many action types (%d) in tdi table %s",
				    table->action_num, table->name);
			goto err;
		}

		info->info.id = table_id;
		info->info.name = table->name;
		info->info.annotation = NULL;
		/* need to fix */
		info->info.key_field_num = table->match_key_field_num;
		for (i = 0; i < info->info.key_field_num; i++)
			info->info.key_fields[i] = table->match_key_fields[i].index;

		info->info.action_spec_num = table->action_num;
		for (i = 0; i < table->action_num; i++)
			info->info.action_specs[i] = table->actions[i].handle;

		if (table->match_key_format_num == 0) {
			node->buf_len = 0;
			for (i = 0; i < table->match_key_field_num; i++) {
				struct cpfl_tdi_match_key_field *field = &table->match_key_fields[i];
				uint32_t size = (uint16_t)(field->bit_width >> 3);

				node->params[i].id = field->index;
				node->params[i].offset = node->buf_len;
				node->params[i].size = size;
				node->buf_len += size;

			}
		} else {
			for (i = 0; i < table->match_key_format_num ; i++) {
				struct cpfl_tdi_match_key_format *format = &table->match_key_format[i];

				node->buf_len = format->byte_array_index + (uint16_t)(format->bit_width >> 3);
				node->params[i].id = format->match_key_handle;
				node->params[i].offset = format->byte_array_index;
				node->params[i].size = (uint16_t)(format->bit_width >> 3);
			}
		}
		info->priv = node;

		return 0;
	}

err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_TABLE_INFO;
	return -EINVAL;
}

struct cpfl_tdi_table_key_field_info {
	struct cpfl_tdi_match_key_field *field;
	struct cpfl_tdi_match_key_format *format;
	struct cpfl_tdi_param_info param;
};

static void
cpfl_tdi_table_key_field_info_put(__rte_unused struct rte_eth_dev *dev,
				  struct rte_tdi_drv_table_key_field_info *info)
{
	rte_free(info->priv);
}

static int
cpfl_tdi_table_key_field_info_get(__rte_unused struct rte_eth_dev *dev,
				  const struct rte_tdi_drv_table_info *tinfo,
				  uint32_t field_id,
				  struct rte_tdi_drv_table_key_field_info *info,
				  struct rte_tdi_error *error)
{
	struct cpfl_tdi_table_node *node = tinfo->priv;
	const struct cpfl_tdi_table *table = node->table;
	int ret = -EINVAL;
	int i, j;

	for (i = 0; i < table->match_key_field_num; i++) {
		struct cpfl_tdi_match_key_field *field = &table->match_key_fields[i];
		struct cpfl_tdi_table_key_field_info *tkfinfo;

		if (field->index != field_id)
			continue;

		tkfinfo = rte_zmalloc(NULL,
				     sizeof(struct cpfl_tdi_table_key_field_info), 0);
		if (tkfinfo == NULL) {
			ret = -ENOMEM;
			goto err;
		}

		info->info.table_id = table->handle;
		info->info.field_id = field->index;
		info->info.name = field->name;
		info->info.annotation = field->instance_name;
		info->info.match_type = RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT;
		info->info.byte_order = RTE_TDI_BYTE_ORDER_HOST;
		info->info.bit_width = field->bit_width;
		info->info.byte_width = (uint16_t)((field->bit_width + 7) >> 3);

		tkfinfo->field = field;
		tkfinfo->param = node->params[i];
		info->priv = tkfinfo;

		/* adjust byte width */
		for (j = 0; j < table->match_key_format_num; j++) {
			struct cpfl_tdi_match_key_format *format = &table->match_key_format[j];

			if (format->match_key_handle != field_id)
				continue;

			info->info.byte_order = (enum rte_tdi_byte_order)format->byte_order;
			if (i != table->match_key_field_num - 1)
				info->info.byte_width =
					(uint16_t)(table->match_key_fields[i + 1].position - field->position);

			tkfinfo->format = format;
			return 0;
		}

		return 0;
	}

err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_TABLE_KEY_FIELD_INFO;
	return ret;
}

static int
cpfl_tdi_action_spec_list_popup(struct rte_eth_dev *dev,
				struct rte_tdi_id_list **list,
				struct rte_tdi_error *error)
{
	struct cpfl_adapter_ext *adapter = CPFL_DEV_TO_ADAPTER(dev);
	struct cpfl_tdi_action_node *node;
	void *list_buf;
	void *temp;
	int size;
	int i;

	size = sizeof(struct rte_tdi_id_list) +
		sizeof(uint32_t) * adapter->tdi_action_num;
	list_buf = rte_malloc(NULL, size, 0);

	if (!list_buf) {
		if (error)
			error->type = RTE_TDI_ERROR_TYPE_TABLE_LIST;
		return -ENOMEM;
	}

	*list = list_buf;
	(*list)->num = adapter->tdi_action_num;

	i = 0;
	RTE_TAILQ_FOREACH_SAFE(node, &adapter->tdi_action_list, next, temp)
		(*list)->ids[i++] = node->action->handle;

	return 0;
}

static int
cpfl_tdi_action_spec_info_get(struct rte_eth_dev *dev,
			      uint32_t spec_id,
			      struct rte_tdi_drv_action_spec_info *info,
			      struct rte_tdi_error *error)
{
	struct cpfl_adapter_ext *adapter = CPFL_DEV_TO_ADAPTER(dev);
	struct cpfl_tdi_action_node *node;
	uint16_t i;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(node, &adapter->tdi_action_list, next, temp) {
		if (node->action->handle != spec_id)
			continue;

		info->info.id = spec_id;
		info->info.name = node->action->name;
		info->info.annotation = NULL;
		info->info.field_num = 0;
		info->priv = node;

		if (node->format == NULL)
			return 0;

		info->info.field_num = node->format->immediate_field_num;

		for (i = 0; i < node->format->immediate_field_num; i++)
			info->info.fields[i] =
				node->format->immediate_fields[i].param_handle;

		return 0;
	}

	if (error)
		error->type = RTE_TDI_ERROR_TYPE_TABLE_KEY_FIELD_INFO;
	return -EINVAL;
}

struct cpfl_tdi_action_spec_field_info {
	struct cpfl_tdi_immediate_field *field;
	struct cpfl_tdi_param_info param;
	struct cpfl_tdi_mod_field *mod_field;
	struct cpfl_tdi_hw_action *hw_action;
};

static void
cpfl_tdi_action_spec_field_info_put(__rte_unused struct rte_eth_dev *dev,
				    struct rte_tdi_drv_action_spec_field_info *info)
{
	rte_free(info->priv);
}

static int
cpfl_tdi_action_spec_field_info_get(__rte_unused struct rte_eth_dev *dev,
				    const struct rte_tdi_drv_action_spec_info *asinfo,
				    uint32_t field_id,
				    struct rte_tdi_drv_action_spec_field_info *info,
				    struct rte_tdi_error *error)
{
	struct cpfl_tdi_action_node *node = asinfo->priv;
	int ret = -EINVAL;
	int i;

	if (node->format == NULL)
		goto err;

	for (i = 0; i < node->format->immediate_field_num; i++) {
		struct cpfl_tdi_immediate_field *field = &node->format->immediate_fields[i];
		struct cpfl_tdi_action_spec_field_info *asfinfo;

		if (field->param_handle != field_id)
			continue;

		asfinfo = rte_malloc(NULL,
				sizeof(struct cpfl_tdi_action_spec_field_info), 0);
		if (asfinfo == NULL) {
			ret = -ENOMEM;
			goto err;
		}

		info->info.spec_id = asinfo->info.id;
		info->info.field_id = field->param_handle;
		info->info.name = field->param_name;
		info->info.annotation = NULL;
		info->info.bit_width = field->dest_width;
		if (i == node->format->immediate_field_num - 1)
			info->info.byte_width = (uint16_t)((field->dest_width + 7 ) >> 3);
		else
			info->info.byte_width =
				(uint16_t)(node->format->immediate_fields[i+1].dest_start - field->dest_start);
		info->info.byte_order = RTE_TDI_BYTE_ORDER_HOST;

		asfinfo->field = field;
		asfinfo->param = node->params[i];

		for (i = 0; i < node->format->mod_content_format.mod_field_num; i++) {
			struct cpfl_tdi_mod_field *mod_field =
				&node->format->mod_content_format.mod_fields[i];

			if (mod_field->type != CPFL_TDI_MOD_FIELD_TYPE_PARAMETER)
				continue;

			if (mod_field->param_handle != field_id)
				continue;

			asfinfo->mod_field = mod_field;
			info->info.byte_order = (enum rte_tdi_byte_order)mod_field->byte_order;
		}

		for (i = 0; i < node->format->hw_action_num; i++) {
			struct cpfl_tdi_hw_action *hw_action = &node->format->hw_actions_list[i];

			if (hw_action->parameter_num == 0)
				continue;

			if (hw_action->parameters[0].param_handle != field_id)
				continue;

			asfinfo->hw_action = hw_action;
		}

		info->priv = asfinfo;

		return 0;
	}
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_ACTION_SPEC_FIELD_INFO;
	return ret;
}

static int
cpfl_tdi_cache_get(struct rte_eth_dev *dev,
		   struct rte_tdi_cache **cache)
{
	struct cpfl_adapter_ext *adapter = CPFL_DEV_TO_ADAPTER(dev);

	*cache = &adapter->tdi_cache;

	return 0;
}

#define CPFL_TDI_MAX_TABLE_KEY_SIZE 128

struct cpfl_tdi_table_key_obj {
	uint16_t buf_len;
	uint8_t buf[CPFL_TDI_MAX_TABLE_KEY_SIZE];
	const struct cpfl_tdi_table_node *tnode;
};

static uint16_t
cpfl_tdi_table_key_size_get(__rte_unused struct rte_eth_dev *dev,
			    __rte_unused uint32_t table_id)
{
	return sizeof(struct cpfl_tdi_table_key_obj);
}

static int
cpfl_tdi_table_key_init(__rte_unused struct rte_eth_dev *dev,
			const struct rte_tdi_drv_table_info *tinfo,
			struct rte_tdi_table_key *key,
			struct rte_tdi_error *error __rte_unused)
{
	struct cpfl_tdi_table_node *node = tinfo->priv;
	struct cpfl_tdi_table_key_obj *kobj = (void *)key->data;

	kobj->tnode = node;
	kobj->buf_len = node->buf_len;

	return 0;
}

struct cpfl_tdi_action_obj {
	const struct cpfl_tdi_table *table;
	struct cpfl_tdi_action_node *node;
	uint16_t buf_len;
	uint8_t buf[CPFL_TDI_ACTION_BUF_SIZE_MAX];
};

static uint16_t
cpfl_tdi_action_size_get(__rte_unused struct rte_eth_dev *dev,
			 __rte_unused uint32_t spec_id)
{
	return sizeof(struct cpfl_tdi_action_obj);
}

static int
cpfl_tdi_action_init(__rte_unused struct rte_eth_dev *dev,
		     const struct rte_tdi_drv_table_info *tinfo,
		     const struct rte_tdi_drv_action_spec_info *asinfo,
		     struct rte_tdi_action *action,
		     struct rte_tdi_error *error __rte_unused)
{
	struct cpfl_tdi_table_node *tnode = tinfo->priv;
	struct cpfl_tdi_action_node *anode = asinfo->priv;
	struct cpfl_tdi_action_obj *aobj = (void *)action->data;

	aobj->table = tnode->table;
	aobj->node = anode;
	aobj->buf_len = anode->buf_len;
	rte_memcpy(aobj->buf, anode->init_buf, anode->buf_len);

	return 0;
}

static int
cpfl_tdi_table_key_field_set(struct rte_eth_dev *dev __rte_unused,
			     struct rte_tdi_table_key *key,
			     const struct rte_tdi_drv_table_key_field_info *kfinfo,
			     const uint8_t *value,
			     uint16_t size,
			     struct rte_tdi_error *error __rte_unused)
{
	struct cpfl_tdi_table_key_field_info *tkfinfo = kfinfo->priv;
	struct cpfl_tdi_param_info *pi = &tkfinfo->param;
	struct cpfl_tdi_table_key_obj *kobj = (void *)key->data;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };

	uint8_t *target = &kobj->buf[pi->offset];

	if (tkfinfo->format == NULL ||
	    (tkfinfo->format->start_bit_offset == 0 &&
	     tkfinfo->format->bit_width % 8 == 0)) {
		rte_memcpy(target, value, size);
	} else {
		rte_memcpy(val_buf, value, size);
		shift_left(val_buf, pi->size, tkfinfo->format->start_bit_offset);
		init_msk_buf(msk_buf, pi->size, tkfinfo->format->bit_width);
		shift_left(msk_buf, pi->size, tkfinfo->format->start_bit_offset);
		or_buf(target, pi->size, val_buf, msk_buf);
	}

	printf("Key:\n");
	dump_buf(kobj->buf, kobj->buf_len);
	return 0;
}

static int
cpfl_tdi_action_field_set(struct rte_eth_dev *dev __rte_unused,
			  struct rte_tdi_action *action,
			  const struct rte_tdi_drv_action_spec_field_info *finfo,
			  const uint8_t *value,
			  uint16_t size,
			  struct rte_tdi_error *error __rte_unused)
{
	struct cpfl_tdi_action_obj *aobj = (void *)action->data;
	struct cpfl_tdi_action_node *node = aobj->node;
	struct cpfl_tdi_action_spec_field_info *asfinfo = finfo->priv;
	struct cpfl_tdi_param_info *pi = &asfinfo->param;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };

	rte_memcpy(val_buf, value, size);

	if (node->format->mod_content_format.mod_field_num > 0) {
		struct cpfl_tdi_mod_field *mf = asfinfo->mod_field;

		shift_left(val_buf, pi->size, mf->start_bit_offset);
		init_msk_buf(msk_buf, pi->size, mf->bit_width);
		shift_left(msk_buf, pi->size, mf->start_bit_offset);
		or_buf(&aobj->buf[pi->offset], pi->size, val_buf, msk_buf);
	} else {
		struct cpfl_tdi_hw_action *ha = asfinfo->hw_action;
		uint32_t action_code = to_action_code(ha, val_buf);

		rte_memcpy(&aobj->buf[pi->offset], &action_code, 4);
	}

	printf("Action:\n");
	dump_buf(aobj->buf, aobj->buf_len);
	return 0;
}

static uint32_t to_action_val(struct cpfl_tdi_hw_action *ha, uint32_t code)
{
	uint32_t val;

	switch (ha->action_code) {
	case CPFL_TDI_ACTION_CODE_SET1A_24b:
		switch (ha->index) {
		case 0: /* mod addr */
			return (code & ICPF_ACT_24B_A_VAL_M) >> ICPF_ACT_24B_A_VAL_S;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1A_24b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1_16b:
		switch (ha->index) {
		case 2: /* vsi */
			val = (code & ICPF_ACT_16B_VAL_M) >> ICPF_ACT_16B_VAL_S;
			return (val & ICPF_ACT_16B_SET_VSI_VAL_M) >> ICPF_ACT_16B_SET_VSI_VAL_S;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1_16b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1B_24b:
		switch (ha->setmd_action_code) {
		case CPFL_TDI_SETMD_ACTION_CODE_SET_16b:
			val = (code & ICPF_ACT_24B_B_VAL_M) >> ICPF_ACT_24B_B_VAL_S;
			return val >> ICPF_ACT_24B_SET_MD16_VAL_S;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1b_24b setmd code %d", ha->setmd_action_code);
			break;
		}
		break;
	default:
		PMD_DRV_LOG(WARNING, "Unsupported action code code %d", ha->action_code);
		break;
	}

	return 0;
}

static int
cpfl_tdi_action_field_get(struct rte_eth_dev *dev __rte_unused,
			  const struct rte_tdi_action *action,
			  const struct rte_tdi_drv_action_spec_field_info *finfo,
			  uint8_t *value,
			  uint16_t *size,
			  struct rte_tdi_error *error __rte_unused)
{
	const struct cpfl_tdi_action_obj *aobj = (const void *)action->data;
	struct cpfl_tdi_action_node *node = aobj->node;
	struct cpfl_tdi_action_spec_field_info *asfinfo = finfo->priv;
	struct cpfl_tdi_param_info *pi = &asfinfo->param;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX] = { 0 };

	rte_memcpy(val_buf, &aobj->buf[pi->offset], pi->size);

	*size = finfo->info.byte_width;
	if (node->format->mod_content_format.mod_field_num > 0) {
		struct cpfl_tdi_mod_field *mf = asfinfo->mod_field;

		shift_right(val_buf, pi->size, mf->start_bit_offset);
		init_msk_buf(msk_buf, pi->size, mf->bit_width);
		set_buf(value, *size, val_buf, msk_buf);
	} else {
		struct cpfl_tdi_hw_action *ha = asfinfo->hw_action;
		uint32_t action_code = *(const uint32_t *)&aobj->buf[pi->offset];

		uint32_t action_val = to_action_val(ha, action_code);

		rte_memcpy(value, &action_val, *size);
	}

	printf("Action:\n");
	dump_buf(aobj->buf, aobj->buf_len);
	return 0;
}

static void pack_sem_entry(const struct cpfl_tdi_table_key_obj *key,
			   const struct cpfl_tdi_action_obj *action,
			   struct cpfl_tdi_hardware_block *hb,
			   enum rte_tdi_table_entry_op op,
			   struct idpf_dma_mem *dma,
			   struct idpf_ctlq_msg *msg)
{
	union icpf_rule_cfg_pkt_record *blob;
	struct icpf_rule_cfg_data cfg = { 0 };
	uint16_t cfg_ctrl;
	enum icpf_ctlq_rule_cfg_opc opc = 0;

	blob = (void *)dma->va;
	memset(blob, 0, sizeof(*blob));

	cfg_ctrl = ICPF_GET_MEV_SEM_RULE_CFG_CTRL(hb->profile[0],
						  hb->sem.sub_profile,
						  0, 0);

	switch (op) {
	case RTE_TDI_TABLE_ENTRY_OP_ADD:
		icpf_prep_sem_rule_blob(key->buf, key->buf_len, action->buf, action->buf_len,
					cfg_ctrl, blob);
		opc = icpf_ctlq_sem_add_rule;
		break;
	case RTE_TDI_TABLE_ENTRY_OP_DEL:
		icpf_prep_sem_rule_blob(key->buf, key->buf_len, NULL, 0,
					cfg_ctrl, blob);
		opc = icpf_ctlq_sem_del_rule;
		break;
	case RTE_TDI_TABLE_ENTRY_OP_QRY:
		icpf_prep_sem_rule_blob(key->buf, key->buf_len, NULL, 0,
					cfg_ctrl, blob);
		opc = icpf_ctlq_sem_query_rule;
		break;
	default:
		PMD_DRV_LOG(ERR, "Unknown ops, this is a bug.\n");
		break;
	}

	icpf_fill_rule_cfg_data_common(opc,
				       0xa2b87, /* cookie */
				       0, /* vsi */
				       0, /* port_num */
				       0, /* host_id */
				       0, /* time_sel */
				       0, /* time_sel_val */
				       0, /* cache_wr_thru */
				       2, /* resp_req */
				       sizeof(union icpf_rule_cfg_pkt_record),
				       dma,
				       &cfg.common);

	icpf_prep_rule_desc(&cfg, msg);
}

static void pack_mod_entry(const struct cpfl_tdi_table_key_obj *key,
			   const struct cpfl_tdi_action_obj *action,
			   enum rte_tdi_table_entry_op op,
			   struct idpf_dma_mem *dma,
			   struct idpf_ctlq_msg *msg)
{

	union icpf_rule_cfg_pkt_record *blob;
	struct icpf_rule_cfg_data cfg = { 0 };
	uint32_t mod_index;
	enum icpf_ctlq_rule_cfg_opc opc = 0;

	blob = (void *)dma->va;
	memset(blob, 0, sizeof(*blob));

	mod_index = *(const uint32_t *)&key->buf[0];

	switch (op) {
	case RTE_TDI_TABLE_ENTRY_OP_ADD:
		icpf_fill_rule_mod_content(action->buf_len, 0, mod_index,
					  &cfg.ext.mod_content);

		rte_memcpy(blob->mod_blob, action->buf, action->buf_len);
		opc = icpf_ctlq_mod_add_update_rule;
		break;
	case RTE_TDI_TABLE_ENTRY_OP_QRY:
		opc = icpf_ctlq_mod_query_rule;
		break;
	default:
		break;	
	}

	icpf_fill_rule_cfg_data_common(opc,
				       0x1237561, /* cookie */
				       0, /* vsi */
				       0, /* port_num */
				       0, /* host_id */
				       0, /* time_sel */
				       0, /* time_sel_val */
				       0, /* cache_wr_thru */
				       2, /* resp_req */
				       sizeof(union icpf_rule_cfg_pkt_record),
				       dma,
				       &cfg.common);

	icpf_prep_rule_desc(&cfg, msg);
}

static int
cpfl_tdi_table_entry_add(struct rte_eth_dev *dev,
			 const struct rte_tdi_table_key *key,
			 const struct rte_tdi_action *action,
			 struct rte_tdi_error *error)
{
	const struct cpfl_tdi_table_key_obj *kobj = (const void *)key->data;
	const struct cpfl_tdi_action_obj *aobj = (const void *)action->data;
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	const struct cpfl_tdi_table *table = kobj->tnode->table;
	struct cpfl_tdi_hardware_block *hb;
	struct cpfl_adapter_ext *ad = CPFL_DEV_TO_ADAPTER(dev);
	struct idpf_hw *hw = (void *)&ad->base.hw;
	struct idpf_ctlq_info *cq = ad->ctlqp[vport->base.devarg_id * 2];
	struct idpf_ctlq_msg msg = { 0 };
	int ret;

	if (table->match_attributes.hardware_block_num == 0) {
		PMD_DRV_LOG(ERR, "No valid hardware block be specified");
		goto err;
	}

	printf("Key:\n");
	dump_buf(kobj->buf, kobj->buf_len);
	printf("Action:\n");
	dump_buf(aobj->buf, aobj->buf_len);

	hb = &table->match_attributes.hardware_blocks[0];
	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		pack_sem_entry(kobj, aobj, hb,
			       RTE_TDI_TABLE_ENTRY_OP_ADD,
			       &vport->tdi_dma, &msg);
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		pack_mod_entry(kobj, aobj,
			       RTE_TDI_TABLE_ENTRY_OP_ADD,
			       &vport->tdi_dma, &msg);
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported hardware block %d\n", hb->hw_block);
		goto err;
	}

	ret = idpf_vport_ctlq_send(hw, cq, 1, &msg);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send ctrl msg.\n");
		goto err;
	}

	if (msg.status != 0) {
		PMD_DRV_LOG(ERR, "Failed to add entry with error %d\n", msg.status);
		goto err;
	}

	return 0;
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static int
cpfl_tdi_table_entry_del(struct rte_eth_dev *dev,
			 const struct rte_tdi_table_key *key,
			 struct rte_tdi_error *error)
{
	const struct cpfl_tdi_table_key_obj *kobj = (const void *)key->data;
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	const struct cpfl_tdi_table *table = kobj->tnode->table;
	struct cpfl_tdi_hardware_block *hb;
	struct cpfl_adapter_ext *ad = CPFL_DEV_TO_ADAPTER(dev);
	struct idpf_hw *hw = (void *)&ad->base.hw;
	struct idpf_ctlq_info *cq = ad->ctlqp[vport->base.devarg_id * 2];
	struct idpf_ctlq_msg msg = { 0 };
	int ret;

	if (table->match_attributes.hardware_block_num == 0) {
		PMD_DRV_LOG(ERR, "No valid hardware block be specified");
		goto err;
	}

	printf("Key:\n");
	dump_buf(kobj->buf, kobj->buf_len);

	hb = &table->match_attributes.hardware_blocks[0];
	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		pack_sem_entry(kobj, NULL, hb,
			       RTE_TDI_TABLE_ENTRY_OP_DEL,
			       &vport->tdi_dma, &msg);
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		/* do nothing */
		return 0;
	default:
		PMD_DRV_LOG(ERR, "Unsupported hardware block %d\n", hb->hw_block);
		goto err;
	}

	ret = idpf_vport_ctlq_send(hw, cq, 1, &msg);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send ctrl msg.\n");
		goto err;
	}

	if (msg.status != 0) {
		PMD_DRV_LOG(ERR, "Failed to delete entry with error %d\n", msg.status);
		goto err;
	}

	return 0;
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static bool
check_action_buf(uint32_t *expect, uint32_t *mask, uint32_t *buf, int size)
{
	int i;

	for (i = 0; i < size; i++)
		if ((buf[i] & mask[i]) != expect[i])
			return false;

	return true;
}

static struct cpfl_tdi_action_node *
get_sem_action_node(const struct cpfl_tdi_table_node *node,
		      struct icpf_sem_rule_cfg_pkt *rule)
{
	int i;

	for (i = 0; i < node->table->action_num; i++) {
		struct cpfl_tdi_action_node *anode = node->actions[i];

		if (check_action_buf((void *)anode->init_buf,
				     (void *)anode->query_msk,
				     (void *)rule->actions,  MEV_SEM_RULE_ACT_SIZE >> 2))
			return anode;
	}

	return NULL;
}

static struct cpfl_tdi_action_node *
get_mod_action_node(const struct cpfl_tdi_table_node *node)
{
	int i;

	for (i = 0; i < node->table->action_num; i++) {
		struct cpfl_tdi_action_node *anode = node->actions[i];

		if (anode->format->mod_content_format.mod_field_num > 0)
			return anode;
	}

	return NULL;
}

static struct cpfl_tdi_action_node *
match_action_node(const struct cpfl_tdi_table_node *tnode,
		  enum cpfl_tdi_hw_block hw_block,
		  void *payload_wb,
		  void **abuf,
		  uint16_t *abuf_len)
{
	struct cpfl_tdi_action_node *anode;
	struct icpf_sem_rule_cfg_pkt *sem_rule;

	switch (hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		sem_rule = payload_wb;
		anode = get_sem_action_node(tnode, sem_rule);
		if (anode != NULL) {
			*abuf_len = MEV_SEM_RULE_ACT_SIZE;
			*abuf = &sem_rule->actions[0];
			return anode;
		}
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		anode = get_mod_action_node(tnode);
		if (anode == NULL) {
			*abuf_len = 256;
			*abuf = payload_wb;
			return anode;
		}

		break;
	default:
		break;
	}

	return NULL;
}

static int
cpfl_tdi_table_entry_query(struct rte_eth_dev *dev,
			   const struct rte_tdi_table_key *key,
			   struct rte_tdi_action **action,
			   struct rte_tdi_error *error)
{
	const struct cpfl_tdi_table_key_obj *kobj = (const void *)key->data;
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	const struct cpfl_tdi_table_node *tnode = kobj->tnode;
	const struct cpfl_tdi_table *table = tnode->table;
	struct cpfl_tdi_hardware_block *hb;
	struct cpfl_adapter_ext *ad = CPFL_DEV_TO_ADAPTER(dev);
	struct idpf_hw *hw = (void *)&ad->base.hw;
	struct idpf_ctlq_info *cq = ad->ctlqp[vport->base.devarg_id * 2];
	struct idpf_ctlq_msg msg = { 0 };
	struct rte_tdi_action *new_action;
	struct cpfl_tdi_action_node *anode;
	struct cpfl_tdi_action_obj *aobj;
	uint16_t abuf_len;
	void *abuf;
	int ret;

	if (table->match_attributes.hardware_block_num == 0) {
		PMD_DRV_LOG(ERR, "No valid hardware block be specified");
		goto err;
	}

	printf("Key:\n");
	dump_buf(kobj->buf, kobj->buf_len);

	hb = &table->match_attributes.hardware_blocks[0];
	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		pack_sem_entry(kobj, NULL, hb,
			       RTE_TDI_TABLE_ENTRY_OP_QRY,
			       &vport->tdi_dma, &msg);
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		pack_mod_entry(kobj, NULL,
			       RTE_TDI_TABLE_ENTRY_OP_QRY,
			       &vport->tdi_dma, &msg);
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported hardware block %d\n", hb->hw_block);
		goto err;
	}

	ret = idpf_vport_ctlq_send(hw, cq, 1, &msg);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send ctrl msg.\n");
		goto err;
	}

	if (msg.status != 0) {
		PMD_DRV_LOG(ERR, "Failed to query entry with error %d\n", msg.status);
		goto err;
	}

	/* create action object */
	new_action = rte_zmalloc(NULL, sizeof(struct rte_tdi_action) +
				sizeof(struct cpfl_tdi_action_obj), 0);

	if (new_action == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create new action object.\n");
		goto err;
	}

	aobj = (void *)new_action->data;
	/* fill action data */
	new_action->table_id = key->table_id;
	anode = match_action_node(tnode, hb->hw_block, msg.ctx.indirect.payload->va,
				  &abuf, &abuf_len);

	if (anode == NULL) {
		PMD_DRV_LOG(ERR, "Can't figure sem action format.\n");
		goto err;
	}

	new_action->spec_id = anode->format->action_handle;
	aobj->table = table;
	aobj->node = anode;
	aobj->buf_len = abuf_len;
	rte_memcpy(aobj->buf, abuf, abuf_len);
	
	printf("Action:\n");
	dump_buf(aobj->buf, aobj->buf_len);

	*action = new_action;

	return 0;
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static int
cpfl_tdi_table_entry_add_prepare(struct rte_eth_dev *dev,
				 struct rte_tdi_table_key *key,
				 struct rte_tdi_action *action,
				 struct rte_tdi_error *error)
{
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	const struct cpfl_tdi_table_key_obj *kobj = (const void *)key->data;
	const struct cpfl_tdi_table *table = kobj->tnode->table;
	struct cpfl_tdi_hardware_block *hb;

	hb = &table->match_attributes.hardware_blocks[0];
	switch (hb->hw_block) {
		case CPFL_TDI_HW_BLOCK_SEM:
		case CPFL_TDI_HW_BLOCK_MOD:
			break;
		default:
			PMD_DRV_LOG(ERR, "Unsupported hardware block %d\n", hb->hw_block);
			goto err;
	}

	if (cpfl_tdi_entry_ring_enqueue(&vport->tdi_tx_entry_ring,
					0, /* need to fix */
					key,
					action,
					RTE_TDI_TABLE_ENTRY_OP_ADD))
		return 0;
	PMD_DRV_LOG(ERR, "Internal ring buffer is full!\n");
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static int
cpfl_tdi_table_entry_del_prepare(struct rte_eth_dev *dev,
				 struct rte_tdi_table_key *key,
				 struct rte_tdi_error *error)
{
	struct cpfl_vport_ext *vport = dev->data->dev_private;

	if (cpfl_tdi_entry_ring_enqueue(&vport->tdi_tx_entry_ring,
					0, /* need to fix */
					key,
					NULL,
					RTE_TDI_TABLE_ENTRY_OP_DEL))
		return 0;

	PMD_DRV_LOG(ERR, "Internal ring buffer is full!\n");
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static int
cpfl_tdi_table_entry_commit(struct rte_eth_dev *dev,
			    struct rte_tdi_error *error)
{
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	struct cpfl_tdi_entry_ring *rx_ring = &vport->tdi_rx_entry_ring;
	struct cpfl_tdi_entry_ring *tx_ring = &vport->tdi_tx_entry_ring;
	uint32_t available = CPFL_TDI_ENTRY_RING_SIZE - rx_ring->count;
	uint32_t remain = available > tx_ring->count ?
		tx_ring->count : available;
	struct cpfl_adapter_ext *ad = CPFL_DEV_TO_ADAPTER(dev);
	struct idpf_hw *hw = (void *)&ad->base.hw;
	struct idpf_ctlq_info *cq = ad->ctlqp[vport->base.devarg_id * 2];
	int ret;

	uint16_t count = 0;
	while (remain > 0) {
		struct idpf_ctlq_msg *msg = &vport->tdi_ctrl_msgs[count % CPFL_TDI_ENTRY_BATCH_SIZE];
		struct idpf_dma_mem *dma = &vport->tdi_dma_batch[count % CPFL_TDI_ENTRY_BATCH_SIZE];
		uint32_t cookie;
		struct rte_tdi_table_key *key;
		struct rte_tdi_action *action;
		enum rte_tdi_table_entry_op op;
		struct cpfl_tdi_table_key_obj *kobj;
		struct cpfl_tdi_action_obj *aobj;
		const struct cpfl_tdi_table *table;
		struct cpfl_tdi_hardware_block *hb;

		if (!cpfl_tdi_entry_ring_dequeue(tx_ring,
						 &cookie,
						 &key,
						 &action,
						 &op))
			break;

		kobj = (void *)key->data;
		aobj = (action == NULL) ? NULL : (void *)action->data;
		table = kobj->tnode->table;
		memset(msg, 0, sizeof(struct idpf_ctlq_msg));
		hb = &table->match_attributes.hardware_blocks[0];

		switch (hb->hw_block) {
		case CPFL_TDI_HW_BLOCK_SEM:
			pack_sem_entry(kobj, aobj, hb, op, dma, msg);
			break;
		case CPFL_TDI_HW_BLOCK_MOD:
			/* do nothing */
			if (op != RTE_TDI_TABLE_ENTRY_OP_DEL)
				pack_mod_entry(kobj, NULL, op, dma, msg);
			break;
		default:
			/* this should never happend. */
			PMD_DRV_LOG(WARNING, "Unsupported hardware block %d\n", hb->hw_block);
			break;
		}

		/* need to fix, assume pull in the same thread. */
		cpfl_tdi_entry_ring_enqueue(rx_ring,
					    cookie,
					    key,
					    action,
					    op);

		count++;
		remain--;

		if (count % CPFL_TDI_ENTRY_BATCH_SIZE == 0) {
			ret = idpf_vport_ctlq_send(hw, cq, CPFL_TDI_ENTRY_BATCH_SIZE, vport->tdi_ctrl_msgs);
			if (ret != 0) {
				PMD_DRV_LOG(ERR, "Failed to send ctrl msg.\n");
				goto err;
			}
		}
	}

	if (count % CPFL_TDI_ENTRY_BATCH_SIZE > 0) {
		ret = idpf_vport_ctlq_send(hw, cq, count % CPFL_TDI_ENTRY_BATCH_SIZE, vport->tdi_ctrl_msgs);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to send ctrl msg.\n");
			goto err;
		}
	}

	return 0;
err:
	if (error)
		error->type = RTE_TDI_ERROR_TYPE_UNSPECIFIED;
	return -EINVAL;
}

static int
cpfl_tdi_table_entry_status_pull(struct rte_eth_dev *dev,
				 struct rte_tdi_table_entry_status *stats,
				 int size,
				 struct rte_tdi_error *error __rte_unused)
{
	struct cpfl_vport_ext *vport = dev->data->dev_private;
	struct cpfl_tdi_entry_ring *rx_ring = &vport->tdi_rx_entry_ring;
	int count = 0;

	while (count < size) {
		uint32_t cookie;
		struct rte_tdi_table_key *key;
		struct rte_tdi_action *action;
		enum rte_tdi_table_entry_op op;
	
		if (!cpfl_tdi_entry_ring_dequeue(rx_ring,
						 &cookie,
						 &key,
						 &action,
						 &op))
			break;

		stats[count].key = key;
		stats[count].action = action;
		stats[count].err = RTE_TDI_ERROR_TYPE_NONE;
		stats[count].op = op;
		count++;
	}

	return count;
}

const struct rte_tdi_ops cpfl_tdi_ops = {
	.cache_get = cpfl_tdi_cache_get,
	.table_list_popup = cpfl_tdi_table_list_popup,
	.table_info_get = cpfl_tdi_table_info_get,
	.table_key_field_info_get = cpfl_tdi_table_key_field_info_get,
	.table_key_field_info_put = cpfl_tdi_table_key_field_info_put,
	.action_spec_list_popup = cpfl_tdi_action_spec_list_popup,
	.action_spec_info_get = cpfl_tdi_action_spec_info_get,
	.action_spec_field_info_get = cpfl_tdi_action_spec_field_info_get,
	.action_spec_field_info_put = cpfl_tdi_action_spec_field_info_put,
	.table_key_size_get = cpfl_tdi_table_key_size_get,
	.table_key_init = cpfl_tdi_table_key_init,
	.action_size_get = cpfl_tdi_action_size_get,
	.action_init = cpfl_tdi_action_init,
	.table_key_field_set = cpfl_tdi_table_key_field_set,
	.action_field_set = cpfl_tdi_action_field_set,
	.action_field_get = cpfl_tdi_action_field_get,
	.table_entry_add = cpfl_tdi_table_entry_add,
	.table_entry_del = cpfl_tdi_table_entry_del,
	.table_entry_query = cpfl_tdi_table_entry_query,
	.table_entry_add_prepare = cpfl_tdi_table_entry_add_prepare,
	.table_entry_del_prepare = cpfl_tdi_table_entry_del_prepare,
	.table_entry_commit = cpfl_tdi_table_entry_commit,
	.table_entry_status_pull = cpfl_tdi_table_entry_status_pull,
};

static void
free_table_list(struct cpfl_adapter_ext *ad)
{
	struct cpfl_tdi_table_node *node;

	while ((node = TAILQ_FIRST(&ad->tdi_table_list))) {
		TAILQ_REMOVE(&ad->tdi_table_list, node, next);
		rte_free(node);
	}
}

static int
build_table_list(struct cpfl_adapter_ext *ad)
{
	struct cpfl_tdi_program *prog = ad->tdi_program;
	int i;

	TAILQ_INIT(&ad->tdi_table_list);

	for (i = 0; i < prog->table_num; i++) {
		struct cpfl_tdi_table *table = &prog->tables[i];
		struct cpfl_tdi_table_node *node;

		node = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_table_node), 0);
		if (node == NULL)
			return -ENOMEM;

		node->table = table;
		TAILQ_INSERT_TAIL(&ad->tdi_table_list, node, next);
	}

	return 0;
}

static void free_action_list(struct cpfl_adapter_ext *ad)
{
	struct cpfl_tdi_action_node *action;

	while ((action = TAILQ_FIRST(&ad->tdi_action_list))) {
		TAILQ_REMOVE(&ad->tdi_action_list, action, next);
		rte_free(action);
	}
}

static void
build_action_params(struct cpfl_tdi_action_node *node)
{
	int i, j;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX];
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX];

	node->buf_len = 0;
	/* build mod content layout */
	if (node->format->mod_content_format.mod_field_num > 0) {
		for (i = 0; i < node->format->mod_content_format.mod_field_num; i++) {
			struct cpfl_tdi_mod_field *mf =
				&node->format->mod_content_format.mod_fields[i];
			uint16_t size = (uint16_t)((mf->start_bit_offset + mf->bit_width) >> 3);

			node->buf_len += size;

			if (mf->type == CPFL_TDI_MOD_FIELD_TYPE_CONSTANT) {
				rte_memcpy(val_buf, mf->value, size);
				shift_left(val_buf, size, mf->start_bit_offset);
				init_msk_buf(msk_buf, size, mf->bit_width);
				shift_left(msk_buf, size, mf->start_bit_offset);
				or_buf(&node->init_buf[mf->byte_array_index], size, val_buf, msk_buf);
				continue;
			}

			for (j = 0; j < node->format->immediate_field_num; j++) {
				struct cpfl_tdi_immediate_field *imf = &node->format->immediate_fields[j];

				if (imf->param_handle == mf->param_handle) {
					node->params[j].id = imf->param_handle;
					node->params[j].offset = mf->byte_array_index;
					node->params[j].size = size;
				}
			}
		}
	/* build action buffer layout */
	} else if (node->format->hw_action_num > 0) {
		for (i = 0; i < node->format->hw_action_num; i++) {
			struct cpfl_tdi_hw_action *ha = &node->format->hw_actions_list[i];
			uint32_t msk = UINT32_MAX;
			uint32_t action_code = 0;
			uint16_t offset;
			uint16_t size;

			switch (ha->action_code) {
			case CPFL_TDI_ACTION_CODE_SET10_1b:
			case CPFL_TDI_ACTION_CODE_SET1_16b:
			case CPFL_TDI_ACTION_CODE_SET1A_24b:
			case CPFL_TDI_ACTION_CODE_SET1B_24b:
				offset = node->buf_len;
				size = 4;
				node->buf_len += 4; /* 32 bit action encode */
				break;
			default:
				continue;
			}

			if (ha->parameter_num == 0) {
				switch (ha->action_code) {
				case CPFL_TDI_ACTION_CODE_SET10_1b:
					switch (ha->index) {
					case 0: /* drop */
						action_code = ICPF_ACT_MAKE_1B(ha->prec,
								ICPF_ACT_1B_OP_DROP,
								ha->value & ha->mask);
						break;
					default:
						continue;
					}
					break;
				case CPFL_TDI_ACTION_CODE_SET1A_24b:
					switch (ha->index) {
					case 9: /* mod profile */
						action_code = icpf_act_mod_profile(ha->prec,
								   ha->mod_profile,
								   0, 0, 0,
								   ICPF_ACT_MOD_PROFILE_PREFETCH_256B)
								.data;
						break;
					case 8: /* queue */
						/* need to fix, ingore as no hint from context.json */
						break;
					default:
						break;
					}
					break;
				case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
					switch (ha->setmd_action_code) {
					case CPFL_TDI_SETMD_ACTION_CODE_SET_8b:
						action_code = icpf_act_set_md8(ha->index,
									       ha->prec,
									       ha->type_id,
									       ha->offset,
									       ha->value,
									       ha->mask).data;
						break;
					default:
						break;
					}
					break;
				default:
					continue;
				}

				rte_memcpy(&node->init_buf[offset], &action_code, 4);
				rte_memcpy(&node->query_msk[offset], &msk, 4);
				continue;
			} else {
				uint32_t code_msk = 0;
				uint32_t dummy = 0;
				uint32_t action_code = to_action_code(ha, (void *)&dummy);
				switch (ha->action_code) {
				case CPFL_TDI_ACTION_CODE_SET10_1b:
					code_msk = ~ICPF_ACT_1B_VAL_M;
					break;
				case CPFL_TDI_ACTION_CODE_SET1_16b:
					code_msk = ~ICPF_ACT_16B_VAL_M;
					break;
				case CPFL_TDI_ACTION_CODE_SET1A_24b:
					code_msk = ~ICPF_ACT_24B_A_VAL_M;
					break;
				case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
					code_msk = ~ICPF_ACT_24B_B_VAL_M;
					break;
				default:
					continue;
				}

				rte_memcpy(&node->init_buf[offset], &action_code, 4);
				rte_memcpy(&node->query_msk[offset], &code_msk, 4);
			}

			/* only check the first parameter */
			struct cpfl_tdi_hw_action_parameter *hap = &ha->parameters[0];
			for (j = 0; j < node->format->immediate_field_num; j ++) {
				struct cpfl_tdi_immediate_field *imf = &node->format->immediate_fields[j];

				if (imf->param_handle == hap->param_handle) {
					node->params[j].id = imf->param_handle;
					node->params[j].offset = offset;
					node->params[j].size = size;
				}
			}

		}
	}
}

static int
build_action_list(struct cpfl_adapter_ext *ad)
{
#define _HASH_TABLE_NAME_SIZE	32
#define _HASH_TABLE_ENTRY_SIZE	1024
	struct cpfl_tdi_program *prog = ad->tdi_program;
	char hname[_HASH_TABLE_NAME_SIZE];
	struct rte_hash *ht;
	int ret = 0;
	int i, j, k;

	snprintf(hname, _HASH_TABLE_NAME_SIZE, "cpfl_tdi_action_hash");

	struct rte_hash_parameters params = {
		.name = hname,
	        .entries = _HASH_TABLE_ENTRY_SIZE,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = 0,
	};

	ht = rte_hash_create(&params);

	if (ht == NULL) {
		PMD_INIT_LOG(ERR, "Failed to create hash table %s", hname);
		return -EINVAL;
	}

	TAILQ_INIT(&ad->tdi_action_list);

	for (i = 0; i < prog->table_num; i++) {
		struct cpfl_tdi_table *table = &prog->tables[i];

		for (j = 0; j < table->action_num; j++) {
			struct cpfl_tdi_action *action = &table->actions[j];
			uint32_t handle = action->handle;
			struct cpfl_tdi_action_node *node;

			/* skip if already exist */
			if (rte_hash_lookup(ht, &handle) >= 0)
				continue;

			node = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_action_node), 0);
			if (node == NULL) {
				ret = -ENOMEM;
				goto err;
			}

			node->action = action;
			ret = rte_hash_add_key_data(ht, &handle, node);
			if (ret != 0)
				goto err;


			TAILQ_INSERT_TAIL(&ad->tdi_action_list, node, next);
		}

		for (j = 0; j < table->match_attributes.hardware_block_num; j++) {
			struct cpfl_tdi_hardware_block *hardware_block =
				&table->match_attributes.hardware_blocks[j];

			for (k = 0; k < hardware_block->action_format_num; k++) {
				struct cpfl_tdi_action_format *format =
					&hardware_block->action_format[k];
				uint32_t handle = format->action_handle;
				struct cpfl_tdi_action_node *node = NULL;

				if (rte_hash_lookup_data(ht, &handle, (void **)&node) >= 0) {

					if (node->format == NULL) {
						node->format = format;
						build_action_params(node);
					}
				}
			}
		}
	}

	ad->tdi_action_num = rte_hash_count(ht);
	rte_hash_free(ht);

	return 0;

err:

	rte_hash_free(ht);
	free_action_list(ad);
	return ret;
}

static struct cpfl_tdi_action_node *
get_action_node(struct cpfl_adapter_ext *ad, uint32_t spec_id)
{
	struct cpfl_tdi_action_node *node;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(node, &ad->tdi_action_list, next, temp) {
		if (node->action->handle == spec_id)
			return node;
	}

	return NULL;
}

static int 
link_action_to_table(struct cpfl_adapter_ext *ad)
{
	struct cpfl_tdi_table_node *node;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(node, &ad->tdi_table_list, next, temp) {
		const struct cpfl_tdi_table *table = node->table;
		int i;

		node->actions = rte_malloc(NULL, sizeof(struct cpfl_tdi_action_node *) *
				table->action_num, 0);

		if (node->actions == NULL)
			return -ENOMEM;

		for (i = 0; i < table->action_num; i++) {
			struct cpfl_tdi_action *action = &table->actions[i];
			struct cpfl_tdi_action_node *anode = get_action_node(ad, action->handle);

			if (anode == NULL)
				return -EINVAL;

			node->actions[i] = anode;
		}
	}

	return 0;
}

int
cpfl_tdi_init(struct cpfl_adapter_ext *ad)
{
	int ret;

	if (ad->devargs.tdi_parser[0] == '\0') {
		PMD_INIT_LOG(WARNING, "tdi module is not initialized");
		return 0;
	}

	ret = cpfl_tdi_program_create(&ad->tdi_program, ad->devargs.tdi_parser);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to create tdi program from file %s",
			     ad->devargs.tdi_parser);
		return ret;
	}

	ret = build_table_list(ad);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to build tdi table list");
		return ret;
	}

	ret = build_action_list(ad);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to build tdi action list");
		free_table_list(ad);
		return ret;
	}

	ret = link_action_to_table(ad);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to link tdi action to table");
		free_table_list(ad);
		free_action_list(ad);
		return ret;
	}

	return 0;
}

int
cpfl_tdi_uninit(struct cpfl_adapter_ext *ad)
{
	if (ad->devargs.tdi_parser[0] == '\0')
		return 0;

	free_table_list(ad);
	free_action_list(ad);

	return cpfl_tdi_program_destroy(ad->tdi_program);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 Intel Corporation.
 */

#ifndef RTE_TDI_H_
#define RTE_TDI_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * Max number of key field in a table.
 */
#define RTE_TDI_KEY_FIELD_NUM_MAX		256
/**
 * Max number of action spec in a table.
 */
#define RTE_TDI_ACTION_SPEC_NUM_MAX		64
/**
 * Max number of field in an action spec.
 */
#define RTE_TDI_ACTION_SPEC_FIELD_NUM_MAX	16

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Verbose error types.
 *
 * Provide the type of the object referenced by struct
 * rte_tdi_error.cause.
 */
enum rte_tdi_error_type {
	RTE_TDI_ERROR_TYPE_NONE, /**< No error. */
	RTE_TDI_ERROR_TYPE_UNSPECIFIED, /**< Cause unspecified. */
	RTE_TDI_ERROR_TYPE_TABLE_LIST, /**< Table id list. */
	RTE_TDI_ERROR_TYPE_TABLE_INFO, /**< Table info. */
	RTE_TDI_ERROR_TYPE_TABLE_KEY_FIELD_INFO, /**< Table key field info. */
	RTE_TDI_ERROR_TYPE_TABLE_KEY, /**< Table key object. */
	RTE_TDI_ERROR_TYPE_ACTION_SPEC_LIST, /**< Action spec id list. */
	RTE_TDI_ERROR_TYPE_ACTION_SPEC_INFO, /**< Action spec info. */
	RTE_TDI_ERROR_TYPE_ACTION_SPEC_FIELD_INFO, /** <Action spec field info. */
	RTE_TDI_ERROR_TYPE_ACTION, /**< Action object. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Verbose error structure definition.
 *
 * This object is normally allocated by applications and set by PMDs, the
 * message points to a constant string which does not need to be freed by
 * the application, however its pointer can be considered valid only as long
 * as its associated DPDK port remains configured. Closing the underlying
 * device or unloading the PMD invalidates it.
 *
 * Both cause and message may be NULL regardless of the error type.
 */
struct rte_tdi_error {
	enum rte_tdi_error_type type; /**< Cause field and error types. */
	const void *cause; /**< Object reponisble for the error. */
	const char *message; /**< Human-readable error message. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table key match type.
 *
 * To specify the key match type of a table.
 */
enum rte_tdi_table_key_match_type {
	RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT, /**< Exact match. */
	RTE_TDI_TABLE_KEY_MATCH_TYPE_WILDCARD, /**< Wildcard match. */
	RTE_TDI_TABLE_KEY_MATCH_TYPE_RANGE, /**< Range match. */
	RTE_TDI_TABLE_KEY_MATCH_TYPE_LPM, /**< longest prefix match. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Byte order.
 *
 * To specify the byte order of table key / action field value in bytes.
 */
enum rte_tdi_byte_order {
	RTE_TDI_BYTE_ORDER_HOST, /**< follow host byte order. */
	RTE_TDI_BYTE_ORDER_NETWORK, /**< follow network byte order. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Flow rule table info.
 *
 * A structure stores the properties of a flow rule table.
 * Typically, a flow rule table represents to a P4 table which describe a
 * match/action unit in packet process pipeline.
 */
struct rte_tdi_table_info {
	uint32_t id; /**< Identifier of a table within the ethdev. */
	const char *name; /**< Name of the table. */
	const char *annotation; /**< Human readable message about this table. */
	uint16_t key_field_num; /**< Number of key field. */
	uint32_t key_fields[RTE_TDI_KEY_FIELD_NUM_MAX]; /**< Key field id array. */
	uint16_t action_spec_num; /**< Number of action spec. */
	uint32_t action_specs[RTE_TDI_ACTION_SPEC_NUM_MAX]; /**< Action spec id array */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table key field info.
 *
 * A structure stores the properties of a table key field.
 */
struct rte_tdi_table_key_field_info {
	uint32_t table_id; /**< Identifier of a table within the ethdev. */
	uint32_t field_id; /**< Identifier of the key field within the table. */
	const char *name;  /**< Name of the key field. */
	const char *annotation; /**< Human readable message about this key field. */
	enum rte_tdi_table_key_match_type match_type; /**< Key match type. */
	uint16_t bit_width; /**< Bit width of the field value. */
	uint16_t byte_width; /**< Number of bytes to store the field value. */
	/**
	 * Byte order of the byte array that store the key value.
	 */
	enum rte_tdi_byte_order byte_order;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Action spec info.
 *
 * A structure stores the properties of a action specification.
 * Typically, a action specification represents a P4 Action.
 */
struct rte_tdi_action_spec_info {
	uint32_t id; /**< Identifier of a action spec within the ethdev. */
	const char *name; /**< Name of the action spec. */
	const char *annotation; /**< Human readable message about this action spec */
	uint16_t field_num; /**< Number of fields */
	uint32_t fields[RTE_TDI_ACTION_SPEC_FIELD_NUM_MAX]; /**< Field id array */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Action spec field info.
 *
 * A structure stores the properties of a action spec field.
 */
struct rte_tdi_action_spec_field_info {
	uint32_t spec_id; /**< Identifier of a action spec within the ethdev. */
	uint32_t field_id; /**< Identifier of the field within the action spec. */
	const char *name; /**< Name of the field. */
	const char *annotation; /**< Human readable message about this action spec. */
	uint16_t bit_width; /**< Bit width of the field value */
	uint16_t byte_width; /**< Number of bytes to store the field value. */
	/**
	 * Byte order of the byte array that stores the key value.
	 */
	enum rte_tdi_byte_order byte_order;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table Key object.
 *
 * A structure represent a table key object, should be created / destroyed by
 * rte_tdi_table_key_create and rte_tdi_table_key_destroy.
 */
struct rte_tdi_table_key {
	uint32_t table_id; /**< Indicate which table the key instance belongs to. */
	int ref_cnt; /**< Reference count. */
	uint8_t data[]; /**< PMD specific data. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Action object.
 *
 * A structure represent a table action object, should be created / destroyed by
 * rte_tdi_action_create and rte_tdi_action_key_destroy.
 */
struct rte_tdi_action {
	uint32_t table_id; /**< Indicate which table the action instance belongs to. */
	uint32_t spec_id; /**< Indicate which action spec the action follow. */
	int ref_cnt; /**< Reference count. */
	uint8_t data[]; /**< PMD specific data. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table entry hit count.
 *
 * Structure to store the table entry hit counters.
 */
struct rte_tdi_query_count {
	uint32_t reset:1; /**< Reset counters after query [in]. */
	uint32_t hits_set:1; /**< Hits field is set [out]. */
	uint32_t bytes_set:1; /**< Bytes field is set [out]. */
	uint32_t reserved:29; /**< Reserved, must be zero [in, out]. */
	uint64_t hits; /**< Number of hits for this rule [out]. */
	uint64_t bytes; /**< Number of bytes through this rule [out]. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * ID list.
 *
 * An id list with variant size, should be created by
 * rte_tdi_table_list_popup or rte_tdi_action_list_popup.
 *
 * Application need to free the list by rte_free.
 */
struct rte_tdi_id_list {
	uint32_t num; /**< Number of the id list */
	uint32_t ids[]; /**< ID array */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Popup table id list.
 *
 * A variant size list that store all table identifiers will be created.
 * Application need to free the list by rte_free.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[out] list
 *    A variant size id list, store all table identifiers of current ethernet
 *    device.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_list_popup(uint16_t port_id,
			 struct rte_tdi_id_list **list,
			 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get table info by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[out] info
 *    Pointer to store the table info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_info_get(uint16_t port_id,
		       uint32_t table_id,
		       struct rte_tdi_table_info *info,
		       struct rte_tdi_error *error);

/**
 * @warning
* @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get table info by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] name
 *    Table name.
 * @param[out] info
 *    Pointer to store the table info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_info_get_by_name(uint16_t port_id,
			       const char *name,
			       struct rte_tdi_table_info *info,
			       struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get table key info by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] field_id
 *    Key field identifier.
 * @param[info] info
 *    Pointer to store the table key field info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_info_get(uint16_t port_id,
				 uint32_t table_id,
				 uint32_t field_id,
				 struct rte_tdi_table_key_field_info *info,
				 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Popup action spec id list.
 *
 * A variant size list that store all action spec identifiers will be created.
 * Application need to free the list by rte_free.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_spec_list_popup(uint16_t port_id,
			       struct rte_tdi_id_list **list,
			       struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get action spec info by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] spec_id
 *    Action spec identifier.
 * @info[out] info
 *    Pointer to store the action spec info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_spec_info_get(uint16_t port_id,
			     uint32_t spec_id,
			     struct rte_tdi_action_spec_info *info,
			     struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get action spec info by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] name
 *    Action spec name.
 * @info[out] info
 *    Pointer to store the action spec info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_spec_info_get_by_name(uint16_t port_id,
				     const char *name,
				     struct rte_tdi_action_spec_info *info,
				     struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get action spec field info by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] spec_id
 *    Action spec identifier.
 * @param[in] field_id
 *    Field identifier.
 * @param[out] info
 *    Pointer to store the action spec field info.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_spec_field_info_get(uint16_t port_id,
				   uint32_t spec_id,
				   uint32_t field_id,
				   struct rte_tdi_action_spec_field_info *info,
				   struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create a table key object.
 *
 * Application need to call rte_tdi_table_key_destroy to free the key object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[out] key
 *    Table key object created by PMD.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_create(uint16_t port_id,
			 uint32_t table_id,
			 struct rte_tdi_table_key **key,
			 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy a table key object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to destroy.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_destroy(uint16_t port_id,
			  struct rte_tdi_table_key *key,
			  struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create an action object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] spec_id
 *    Action spec identifier.
 * @param[out] action
 *    Action key created by PMD.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_create(uint16_t port_id,
		      uint32_t table_id,
		      uint32_t spec_id,
		      struct rte_tdi_action **action,
		      struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy an action object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] action
 *    Action object to destroy.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_destroy(uint16_t port_id,
		       struct rte_tdi_action *action,
		       struct rte_tdi_error *error);


/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set table key field value by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] field_id
 *    key field identifier.
 * @param[in] value
 *    Byte array to store the value
 * @param[in] size
 *    Size of the byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set(uint16_t port_id,
			    struct rte_tdi_table_key *key,
			    uint32_t field_id,
			    const uint8_t *value,
			    uint16_t size,
			    struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set table key field value by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] name
 *    key field name.
 * @param[in] value
 *    Byte array to store the value to match.
 * @param[in] size
 *    Size of the byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_by_name(uint16_t port_id,
				    struct rte_tdi_table_key *key,
				    const char *name,
				    const uint8_t *value,
				    uint16_t size,
				    struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set wildcard match key field by identifier.
 *
 * For wildcard match, only a bit set in mask should be matched.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] field_id
 *    Key field identifier.
 * @param[in] value
 *    Byte array stores the value to match.
 * @param[in] mask
 *    Byte array stores the bit mask.
 * @param[in] size
 *    Size of value and mask byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_mask(uint16_t port_id,
				      struct rte_tdi_table_key *key,
				      uint32_t field_id,
				      const uint8_t *value,
				      const uint8_t *mask,
				      uint16_t size,
				      struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set wildcard match key field by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] name
 *    Key field name.
 * @param[in] value
 *    Byte array stores the value to match.
 * @param[in] mask
 *    Byte array stores the bit mask.
 * @param[in] size
 *    Size of value and mask byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_mask_by_name(uint16_t port_id,
					      struct rte_tdi_table_key *key,
					      const char *name,
					      const uint8_t *value,
					      const uint8_t *mask,
					      uint16_t size,
					      struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set range match key field by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] field_id
 *    Key field identifier.
 * @param[in] min
 *    Byte array stores the min value of the range to match
 * @param[in] max
 *    Byte array stores the max value of the range to match
 * @param[in] size
 *    Size of the min and max byte array
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_range(uint16_t port_id,
				       struct rte_tdi_table_key *key,
				       uint32_t field_id,
				       const uint8_t *min,
				       const uint8_t *max,
				       uint16_t size,
				       struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set range match key field by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] name
 *    Key field name.
 * @param[in] min
 *    Byte array stores the min value of the range to match
 * @param[in] max
 *    Byte array stores the max value of the range to match
 * @param[in] size
 *    Size of the min and max byte array
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_range_by_name(uint16_t port_id,
					       struct rte_tdi_table_key *key,
					       const char *name,
					       const uint8_t *min,
					       const uint8_t *max,
					       uint16_t size,
					       struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set lpm match key field by identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] field_id
 *    Key field identifier.
 * @param[in] value
 *    Byte array stores the value to match.
 * @param[in] size
 *    Size of value byte array.
 * @param[in] prefix
 *    Bits of the prefix to match, must <= (8 * size)
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_prefix(uint16_t port_id,
					struct rte_tdi_table_key *key,
					uint32_t field_id,
					const uint8_t *value,
					uint16_t size,
					uint16_t prefix,
					struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set lpm match key field by name.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to update.
 * @param[in] name
 *    Key field name.
 * @param[in] value
 *    Byte array stores the value to match.
 * @param[in] size
 *    Size of value byte array.
 * @param[in] prefix
 *    Bits of the prefix to match, must <= (8 * size)
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_field_set_with_prefix_by_name(uint16_t port_id,
						struct rte_tdi_table_key *key,
						const char *name,
						const uint8_t *value,
						uint16_t size,
						uint16_t prefix,
						struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set action field value.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] action
 *    Action object to update.
 * @param[in] field_id
 *    Field identifier.
 * @param[in] value
 *    Byte array stores the value of the field.
 * @param[in] size
 *    Size of the byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_field_set(uint16_t port_id,
			 struct rte_tdi_action *action,
			 uint32_t field_id,
			 const uint8_t *value,
			 uint16_t size,
			 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * get action field value.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] action
 *    Action object to query.
 * @param[in] field_id
 *    Field identifier.
 * @param[out] value
 *    Byte array stores the value of the field.
 * @param[in | out] size
 *    Input as size of the byte array, return the size of the value.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_field_get(uint16_t port_id,
			 const struct rte_tdi_action *action,
			 uint32_t field_id,
			 uint8_t *value,
			 uint16_t *size,
			 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] action
 *    Action object to update.
 * @param[in] name
 *    Field name.
 * @param[in] value
 *    Byte array stores the value of the field.
 * @param[in] size
 *    Size of the byte array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_field_set_by_name(uint16_t port_id,
				 struct rte_tdi_action *action,
				 const char *name,
				 const uint8_t *value,
				 uint16_t size,
				 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set table default action.
 *
 * The default action will take effect when a packet hit no rules.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier
 * @param[in] action
 *    Default action object.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_default_action_set(uint16_t port_id,
				 uint32_t table_id,
				 const struct rte_tdi_action *action,
				 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Cancel table default action
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_default_action_cancel(uint32_t port_id,
				    uint32_t table_id,
				    struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Add matching rule as a table entry.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object.
 * @param[in] action
 *    Action object.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_add(uint16_t port_id,
			uint32_t table_id,
			const struct rte_tdi_table_key *key,
			const struct rte_tdi_action *action,
			struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Query action of a table entry.
 *
 * If success, a new rte_tdi_action object will be created.
 * Use rte_tdi_action_destroy to free the resource.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object.
 * @param[out] action
 *    Action object returned.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_query(uint16_t port_id,
			  uint32_t table_id,
			  const struct rte_tdi_table_key *key,
			  struct rte_tdi_action **action,
			  struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Delete a table entry.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object to match.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_del(uint16_t port_id,
			uint32_t table_id,
			const struct rte_tdi_table_key *key,
			struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Query rule hit counters.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object to match.
 * @param[out] count
 *    Pointer stores the hit counters.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_count_query(uint16_t port_id,
				uint32_t table_id,
				const struct rte_tdi_table_key *key,
				struct rte_tdi_query_count *count,
				struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Clone a table key object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] key
 *    Table key object to clone.
 * @param[out] new_key
 *    New table key object be created by PMD.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_key_clone(uint16_t port_id,
			const struct rte_tdi_table_key *key,
			struct rte_tdi_table_key **new_key,
			struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Clone a action object.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] action
 *    Action object to clone.
 * @param[out] new_action
 *    New action object be created by PMD.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_action_clone(uint16_t port_id,
		     const struct rte_tdi_action *action,
		     struct rte_tdi_action **new_action,
		     struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Prepare table entry adding.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object.
 * @param[in] action
 *    Action object.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_add_prepare(uint16_t port_id,
				uint32_t table_id,
				struct rte_tdi_table_key *key,
				struct rte_tdi_action *action,
				struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Prepare table entry deletion.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] table_id
 *    Table identifier.
 * @param[in] key
 *    Table key object to match.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_del_prepare(uint16_t port_id,
				uint32_t table_id,
				struct rte_tdi_table_key *key,
				struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Commit all prepared adding and deletion requests.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_commit(uint16_t port_id,
			   struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table entry operation type.
 */

enum rte_tdi_table_entry_op {
	RTE_TDI_TABLE_ENTRY_OP_ADD, /* Add an entry */
	RTE_TDI_TABLE_ENTRY_OP_DEL, /* Delete an entry */
	RTE_TDI_TABLE_ENTRY_OP_QRY, /* Query an entry */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Table entry update status.
 */
struct rte_tdi_table_entry_status {
	struct rte_tdi_table_key *key; /**< Table key object of the entry */
	struct rte_tdi_action *action; /**< Action object of the entry */
	enum rte_tdi_table_entry_op op; /**< Operation type */
	enum rte_tdi_error_type err; /**< Error type */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Pull table entry update status.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[out] stats
 *    An array stores the status of all finished entry adding / delete
 *    requests.
 * @param[in] size
 *    Size of the input array.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    >=0 on success, indiates the number of status be pulled.
 *    A negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_table_entry_status_pull(uint16_t port_id,
				struct rte_tdi_table_entry_status *stats,
				int size,
				struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get PNA port identifier.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] ethdev_port_id
 *    Ethdev port identifier maps to the required PNA port.
 * @param[out] pna_port_id
 *    Pointer stores the PNA port identifier.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_pna_port_get(uint16_t port_id,
		     uint16_t ethdev_port_id,
		     uint32_t *hw_port_id,
		     struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get a PNA queue identifer from a ethdev Rx queue.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] ethdev_port_id
 *    Ethdev port identifier the Rx queue belongs to.
 * @param[in] ethdev_queue_id
 *    Ethdev Rx queue index that maps to the required PNA queue identifier.
 * @param[out] pna_queue_id
 *    Pointer stores the PNA queue identifier.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_pna_rx_queue_get(uint16_t port_id,
			 uint16_t ethdev_port_id,
			 uint16_t ethdev_queue_id,
			 uint32_t *hw_queue_id,
			 struct rte_tdi_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get a PNA queue identifer from a ethdev Tx queue.
 *
 * @param[in] port_id
 *    Port identifier of the Ethernet device.
 * @param[in] ethdev_port_id
 *    Ethdev port identifier the Tx queue belongs to.
 * @param[in] ethdev_queue_id
 *    Ethdev Tx queue index that maps to the required PNA queue identifier.
 * @param[out] pna_queue_id
 *    Pointer stores the PNA queue identifier.
 * @param[out] error
 *    Perform verbose error reporting if not NULL. PMDs initialize this
 *    structure in case of error only.
 *
 * @return
 *    0 on success, a negative errno value otherwise and rte_errno is set.
 */
__rte_experimental int
rte_tdi_pna_tx_queue_get(uint16_t port_id,
			 uint16_t ethdev_port_id,
			 uint16_t ethdev_queue_id,
			 uint32_t *hw_queue_id,
			 struct rte_tdi_error *error);
#endif

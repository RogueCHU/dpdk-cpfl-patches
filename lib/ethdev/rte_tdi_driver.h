/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 Intel Corporation.
 */

#ifndef RTE_TDI_DRIVER_H_
#define RTE_TDI_DRIVER_H_

#include <rte_hash.h>
#include "ethdev_driver.h"
#include "rte_tdi.h"

/**
 * Help function to set the tdi error.
 */
static inline int
rte_tdi_error_set(struct rte_tdi_error *error,
		  int code,
		  enum rte_tdi_error_type type,
		  const void *cause,
		  const char *message)
{
	if (error) {
		*error = (struct rte_tdi_error) {
			.type = type,
			.cause = cause,
			.message = message,
		};
	}
	rte_errno = code;

	return code;
}

/**
 * PMD oriented table info structure.
 */
struct rte_tdi_drv_table_info {
	struct rte_tdi_table_info info; /**< General table info. */
	void *priv; /**< Pointer to store PMD specific data. */
};

/**
 * PMD oriented table key field info structure.
 */
struct rte_tdi_drv_table_key_field_info {
	struct rte_tdi_table_key_field_info info; /**< General table key field info. */
	void *priv; /**< Pointer to store PMD specific data. */
};

/**
 * Structure of the tdi table key field info cache object.
 */
struct rte_tdi_table_key_field_cache {
	TAILQ_ENTRY(rte_tdi_table_key_field_cache) next; /**< link to next cache object. */
	struct rte_tdi_drv_table_key_field_info key_field_info; /**< A copy of key field info. */
};

RTE_TAILQ_HEAD(rte_tdi_table_key_field_cache_list, rte_tdi_table_key_field_cache);
RTE_TAILQ_HEAD(rte_tdi_table_cache_list, rte_tdi_table_cache);

/**
 * Structure of the tdi table info cache object.
 *
 * A tdi table info cache object stores hash table and link list of key field
 * info cache objects.
 */
struct rte_tdi_table_cache {
	TAILQ_ENTRY(rte_tdi_table_cache) next; /**< Link to next table info cache object. */
	struct rte_tdi_drv_table_info table_info; /**< A copy of table info */
	struct rte_hash *field_hash_by_id; /**< table key field hash table by id. */
	struct rte_hash *field_hash_by_name; /**< table key field hash table by name. */
	/**
	 * tdi table key field cache list.
	 */
	struct rte_tdi_table_key_field_cache_list key_field_cache_list;
};

/**
 * PMD oriented action spec info structure.
 */
struct rte_tdi_drv_action_spec_info {
	struct rte_tdi_action_spec_info info; /**< General action spec info. */
	void *priv; /**< Pointer to store PMD specific data. */
};

/**
 * PMD oriented action spec field info structure.
 */
struct rte_tdi_drv_action_spec_field_info {
	struct rte_tdi_action_spec_field_info info; /**< General action spec field info. */
	void *priv; /**< Pointer to store PMD specific data. */
};

/**
 * Structure of the tdi action spec field info cache object.
 */
struct rte_tdi_action_spec_field_cache {
	TAILQ_ENTRY(rte_tdi_action_spec_field_cache) next; /**< Link to next objet. */
	struct rte_tdi_drv_action_spec_field_info field_info; /**< A copy of field info. */
};

RTE_TAILQ_HEAD(rte_tdi_action_spec_field_cache_list, rte_tdi_action_spec_field_cache);
RTE_TAILQ_HEAD(rte_tdi_action_spec_cache_list, rte_tdi_action_spec_cache);

/**
 * Structure of the action spec info cache object.
 *
 * A tdi action spec info cache object stores hash table and link list of field
 * info cache objects.
 */
struct rte_tdi_action_spec_cache {
	TAILQ_ENTRY(rte_tdi_action_spec_cache) next; /**< Link to next object. */
	struct rte_tdi_drv_action_spec_info action_spec_info; /**< A copy of action spec info. */
	struct rte_hash *field_hash_by_id; /**< Field info hash table by id. */
	struct rte_hash *field_hash_by_name; /**< Field info hash table by name. */
	struct rte_tdi_action_spec_field_cache_list field_cache_list; /**< Field info cache list. */
};

/**
 * Structure of the tdi cache object.
 *
 * A tdi cache object stores the hash table and link list of tdi table info and
 * action spec info cache objects.
 *
 * A tdi cache object should be created by PMD and accessed by rte_tdi from
 * ops->cache_get(). PMD should call rte_tdi_cache_free to release the object
 * before all ports that link to this object be closed.
 */
struct rte_tdi_cache {
	struct rte_tdi_id_list *table_list; /**< Table id list. */
	struct rte_hash *table_cache_hash_by_id; /**< Table info cache object hash table by id. */
	/**
	 * Table info cache object hash table by name.
	 */
	struct rte_hash *table_cache_hash_by_name;
	struct rte_tdi_table_cache_list table_cache_list; /**< Table info cache object list. */
	struct rte_tdi_id_list *action_spec_list; /**< Action spec id list. */
	/**
	 * Action spec info cache object hash table by name.
	 */
	struct rte_hash *action_spec_cache_hash_by_id;
	/**
	 * Action spec info cache object list.
	 */
	struct rte_hash *action_spec_cache_hash_by_name;
	/**
	 * Action spec info cache object hash table by id.
	 */
	struct rte_tdi_action_spec_cache_list action_spec_cache_list;
};

/**
 * tdi operations structure implemented by PMDs.
 */
struct rte_tdi_ops {
	int (*cache_get)(struct rte_eth_dev *dev,
			 struct rte_tdi_cache **cache);
	/* See rte_tdi_table_list_popup(). */
	int (*table_list_popup)(struct rte_eth_dev *dev,
				struct rte_tdi_id_list **list,
				struct rte_tdi_error *error);
	/* See rte_tdi_table_info_get(). */
	int (*table_info_get)(struct rte_eth_dev *dev,
			      uint32_t table_id,
			      struct rte_tdi_drv_table_info *info,
			      struct rte_tdi_error *error);
	/**
	 * PMD no need to implement this API if no additional resource be allocated
	 * in table_info_get().
	 */
	void (*table_info_put)(struct rte_eth_dev *dev,
			       struct rte_tdi_drv_table_info *info);
	/* See rte_tdi_table_key_field_info_get(). */
	int (*table_key_field_info_get)(struct rte_eth_dev *dev,
					const struct rte_tdi_drv_table_info *tinfo,
					uint32_t field_id,
					struct rte_tdi_drv_table_key_field_info *info,
					struct rte_tdi_error *error);
	/**
	 * PMD no need to implement this API if no additional resource be allocated
	 * in table_key_field_info_get().
	 */
	void (*table_key_field_info_put)(struct rte_eth_dev *dev,
					 struct rte_tdi_drv_table_key_field_info *info);
	/* See rte_tdi_action_spec_list_popup(). */
	int (*action_spec_list_popup)(struct rte_eth_dev *dev,
				     struct rte_tdi_id_list **list,
				     struct rte_tdi_error *error);
	/* See rte_tdi_action_spec_info_get(). */
	int (*action_spec_info_get)(struct rte_eth_dev *dev,
				    uint32_t spec_id,
				    struct rte_tdi_drv_action_spec_info *info,
				    struct rte_tdi_error *error);
	/**
	 * PMD no need to implement this API if no additional resource be allocated
	 * in action_spec_info_get().
	 */
	void (*action_spec_info_put)(struct rte_eth_dev *dev,
				     struct rte_tdi_drv_action_spec_info *info);
	/* See rte_tdi_action_spec_field_info_get(). */
	int (*action_spec_field_info_get)(struct rte_eth_dev *dev,
					  const struct rte_tdi_drv_action_spec_info *asinfo,
					  uint32_t field_id,
					  struct rte_tdi_drv_action_spec_field_info *info,
					  struct rte_tdi_error *error);
	/**
	 * PMD no need to implement this API if no additional resource be allocated
	 * in action_spec_field_info_get().
	 */
	void (*action_spec_field_info_put)(struct rte_eth_dev *dev,
					   struct rte_tdi_drv_action_spec_field_info *info);
	/* Return the key size of specific table */
	uint16_t (*table_key_size_get)(struct rte_eth_dev *dev,
				       uint32_t table_id);
	/**
	 * See rte_tdi_table_key_create().
	 * Init PMD specific table key data if necessary.
	 */
	int (*table_key_init)(struct rte_eth_dev *dev,
			      const struct rte_tdi_drv_table_info *tinfo,
			      struct rte_tdi_table_key *key,
			      struct rte_tdi_error *error);
	/**
	 * See rte_tdi_table_key_destroy().
	 * Cleanup PMD specific table key data if necessary.
	 */
	int (*table_key_deinit)(struct rte_eth_dev *dev,
				struct rte_tdi_table_key *key,
				struct rte_tdi_error *error);
	/**
	 * See rte_tdi_table_key_clone().
	 * Copy PMD specific data if need to overwrite the
	 * default memory copy implemention.
	 */
	int (*table_key_clone)(struct rte_eth_dev *dev,
			       const struct rte_tdi_table_key *key,
			       struct rte_tdi_table_key *new_key,
			       struct rte_tdi_error *error);
	/* Return the action size of specific action spec. */
	uint16_t (*action_size_get)(struct rte_eth_dev *dev,
				    uint32_t spec_id);
	/**
	 * See rte_tdi_action_create().
	 * Init PMD specific action data if necessary.
	 */
	int (*action_init)(struct rte_eth_dev *dev,
			   const struct rte_tdi_drv_table_info *tinfo,
			   const struct rte_tdi_drv_action_spec_info *asinfo,
			   struct rte_tdi_action *action,
			   struct rte_tdi_error *error);
	/**
	 * See rte_tdi_action_destroy().
	 * Cleanup PMD specific action data if necessary.
	 */
	int (*action_deinit)(struct rte_eth_dev *dev,
			     struct rte_tdi_action *action,
			     struct rte_tdi_error *error);
	/**
	 * See rte_tdi_action_clone().
	 * Copy PMD specific data if need to overwrite the
	 * default memory copy implemention.
	 */
	int (*action_clone)(struct rte_eth_dev *dev,
			    const struct rte_tdi_action *action,
			    struct rte_tdi_action *new_action,
			    struct rte_tdi_error *error);
	/* See rte_tdi_table_key_field_set(). */
	int (*table_key_field_set)(struct rte_eth_dev *dev,
				   struct rte_tdi_table_key *key,
				   const struct rte_tdi_drv_table_key_field_info *kfinfo,
				   const uint8_t *value,
				   uint16_t size,
				   struct rte_tdi_error *error);
	/* See rte_tdi_table_key_field_set_with_mask(). */
	int (*table_key_field_set_with_mask)(struct rte_eth_dev *dev,
					     struct rte_tdi_table_key *key,
					     const struct rte_tdi_drv_table_key_field_info *info,
					     const uint8_t *data,
					     const uint8_t *mask,
					     uint16_t size,
					     struct rte_tdi_error *error);
	/* See rte_tdi_table_key_field_set_with_range(). */
	int (*table_key_field_set_with_range)(struct rte_eth_dev *dev,
					      struct rte_tdi_table_key *key,
					      const struct rte_tdi_drv_table_key_field_info *info,
					      const uint8_t *from,
					      const uint8_t *to,
					      uint16_t size,
					      struct rte_tdi_error *error);
	/* See rte_tdi_table_key_field_set_with_prefix(). */
	int (*table_key_field_set_with_prefix)(struct rte_eth_dev *dev,
					       struct rte_tdi_table_key *key,
					       const struct rte_tdi_drv_table_key_field_info *info,
					       const uint8_t *value,
					       uint16_t size,
					       uint16_t prefix,
					       struct rte_tdi_error *error);
	/* See rte_tdi_action_field_set(). */
	int (*action_field_set)(struct rte_eth_dev *dev,
				struct rte_tdi_action *action,
				const struct rte_tdi_drv_action_spec_field_info *finfo,
				const uint8_t *value,
				uint16_t size,
				struct rte_tdi_error *error);
	/* See rte_tdi_action_field_get(). */
	int (*action_field_get)(struct rte_eth_dev *dev,
				const struct rte_tdi_action *action,
				const struct rte_tdi_drv_action_spec_field_info *finfo,
				uint8_t *value,
				uint16_t *size,
				struct rte_tdi_error *error);
	/* See rte_tdi_table_default_action_set(). */
	int (*table_default_action_set)(struct rte_eth_dev *dev,
					const struct rte_tdi_drv_table_info *info,
					const struct rte_tdi_action *action,
					struct rte_tdi_error *error);
	/* See rte_tdi_table_default_action_cancel(). */
	int (*table_default_action_cancel)(struct rte_eth_dev *dev,
					   const struct rte_tdi_drv_table_info *info,
					   struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_add(). */
	int (*table_entry_add)(struct rte_eth_dev *dev,
			       const struct rte_tdi_table_key *key,
			       const struct rte_tdi_action *action,
			       struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_query(). */
	int (*table_entry_query)(struct rte_eth_dev *dev,
				 const struct rte_tdi_table_key *key,
				 struct rte_tdi_action **action,
				 struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_del(). */
	int (*table_entry_del)(struct rte_eth_dev *dev,
			       const struct rte_tdi_table_key *key,
			       struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_count_query(). */
	int (*table_entry_count_query)(struct rte_eth_dev *dev,
				       const struct rte_tdi_table_key *key,
				       struct rte_tdi_query_count *count,
				       struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_add_prepare(). */
	int (*table_entry_add_prepare)(struct rte_eth_dev *dev,
				       struct rte_tdi_table_key *key,
				       struct rte_tdi_action *action,
				       struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_del_prepare(). */
	int (*table_entry_del_prepare)(struct rte_eth_dev *dev,
				       struct rte_tdi_table_key *key,
				       struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_commit(). */
	int (*table_entry_commit)(struct rte_eth_dev *dev,
				  struct rte_tdi_error *error);
	/* See rte_tdi_table_entry_status_pull(). */
	int (*table_entry_status_pull)(struct rte_eth_dev *dev,
				       struct rte_tdi_table_entry_status *stats,
				       int size,
				       struct rte_tdi_error *error);
	/* See rte_tdi_pna_port_get(). */
	int (*pna_port_get)(struct rte_eth_dev *dev,
			    struct rte_eth_dev *target,
			    uint32_t *pna_port_id,
			    struct rte_tdi_error *error);
	/* See rte_tdi_pna_rx_queue_get(). */
	int (*pna_rx_queue_get)(struct rte_eth_dev *dev,
				struct rte_eth_dev *target,
				uint16_t queue_id,
				uint32_t *pna_queue_id,
				struct rte_tdi_error *error);
	/* See rte_tdi_pna_tx_queue_get(). */
	int (*pna_tx_queue_get)(struct rte_eth_dev *dev,
				struct rte_eth_dev *target,
				uint16_t queue_id,
				uint32_t *pna_queue_id,
				struct rte_tdi_error *error);
};

/**
 * Get tdi operations structure from a port.
 *
 * @param[in] port_id
 *    Port identifier to query.
 * @param[out] error
 *    Pointer to tdi error structure.
 *
 * @return
 *   The tdi operation structure associated with port_id, NULL in cause of
 *   error, in which case rte_errno is set and the error structure contains
 *   additional details.
 */
const struct rte_tdi_ops *
rte_tdi_ops_get(uint16_t port_id, struct rte_tdi_error *error);

__rte_internal
void rte_tdi_cache_free(struct rte_eth_dev *dev, struct rte_tdi_cache *cache);

#endif

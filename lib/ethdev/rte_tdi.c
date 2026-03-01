/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 Intel Corporation.
 */

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>
#include <rte_telemetry.h>
#include "rte_ethdev.h"
#include "rte_tdi.h"
#include "rte_tdi_driver.h"

#define RTE_TDI_CACHE_ENTRY_SIZE 1024
#define RTE_TDI_OBJ_NAME_MAX 80

#define __table_info_put(dev, ops, info)				\
	do {								\
		if (!!(ops)->table_info_put)				\
			(ops)->table_info_put(dev, info);		\
	} while (0)

#define __table_key_field_info_put(dev, ops, info)			\
	do {								\
		if (!!(ops)->table_key_field_info_put)			\
			(ops)->table_key_field_info_put(dev, info);	\
	} while (0)

#define __action_spec_info_put(dev, ops, info)				\
	do {								\
		if (!!(ops)->action_spec_info_put)			\
			(ops)->action_spec_info_put(dev, info);		\
	} while (0)

#define __action_spec_field_info_put(dev, ops, info)			\
	do {								\
		if (!!(ops)->action_spec_field_info_put)		\
			(ops)->action_spec_field_info_put(dev, info);	\
	} while (0)

static int
tdi_err(uint16_t port_id, int ret, struct rte_tdi_error *error)
{
	if (ret == 0)
		return 0;
	if (rte_eth_dev_is_removed(port_id))
		return rte_tdi_error_set(error, EIO,
					 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
					 NULL, rte_strerror(EIO));
	return ret;
}

static struct rte_hash *
create_hash(const char *name, uint32_t key_len)
{
	struct rte_hash_parameters params = {
		.name = name,
		.entries = RTE_TDI_CACHE_ENTRY_SIZE,
		.key_len = key_len,
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = 0,
	};

	return rte_hash_create(&params);
}

static void
free_table_cache(struct rte_eth_dev *dev,
		 const struct rte_tdi_ops *ops,
		 struct rte_tdi_cache *cache)
{
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_table_key_field_cache *kfcache;

	if (cache->table_list != NULL)
		rte_free(cache->table_list);

	if (cache->table_cache_hash_by_name != NULL) {
		rte_hash_free(cache->table_cache_hash_by_name);
		cache->table_cache_hash_by_name = NULL;
	}

	if (cache->table_cache_hash_by_id != NULL) {
		rte_hash_free(cache->table_cache_hash_by_id);
		cache->table_cache_hash_by_id = NULL;
	}

	while ((tcache = TAILQ_FIRST(&cache->table_cache_list))) {
		if (tcache->field_hash_by_name != NULL)
			rte_hash_free(tcache->field_hash_by_name);

		if (tcache->field_hash_by_id != NULL)
			rte_hash_free(tcache->field_hash_by_id);

		while ((kfcache = TAILQ_FIRST(&tcache->key_field_cache_list))) {
			TAILQ_REMOVE(&tcache->key_field_cache_list, kfcache, next);
			__table_key_field_info_put(dev, ops, &kfcache->key_field_info);
			rte_free(kfcache);
		}

		TAILQ_REMOVE(&cache->table_cache_list, tcache, next);
		__table_info_put(dev, ops, &tcache->table_info);
		rte_free(tcache);
	}
}

static bool
build_table_key_field_cache(struct rte_eth_dev *dev,
			    const struct rte_tdi_ops *ops,
			    struct rte_tdi_table_cache *tcache)
{
	struct rte_tdi_table_info *tinfo;
	uint16_t port_id;
	uint32_t table_id;
	char hname[32];
	uint16_t i;

	if (ops->table_key_field_info_get == NULL)
		return false;

	tinfo = &tcache->table_info.info;
	port_id = dev->data->port_id;
	table_id = tinfo->id;

	snprintf(hname, 32, "tdi_tkf_name_p%d_t%d", port_id, table_id);
	tcache->field_hash_by_name = create_hash(hname, RTE_TDI_OBJ_NAME_MAX);
	if (tcache->field_hash_by_name == NULL)
		return false;

	snprintf(hname, 32, "tdi_tkf_id_p%d_t%d", port_id, table_id);
	tcache->field_hash_by_id = create_hash(hname, sizeof(uint32_t));
	if (tcache->field_hash_by_id == NULL)
		return false;

	TAILQ_INIT(&tcache->key_field_cache_list);

	for (i = 0; i < tinfo->key_field_num; i++) {
		uint32_t id = tinfo->key_fields[i];
		struct rte_tdi_table_key_field_cache *kfcache =
			rte_malloc(NULL, sizeof(struct rte_tdi_table_key_field_cache), 0);
		char name[RTE_TDI_OBJ_NAME_MAX] = { 0 };

		if (kfcache == NULL)
			return false;

		if (ops->table_key_field_info_get(dev, &tcache->table_info, id,
						  &kfcache->key_field_info, NULL) != 0)
			return false;

		if (rte_hash_add_key_data(tcache->field_hash_by_id, &id, kfcache) != 0)
			return false;

		TAILQ_INSERT_TAIL(&tcache->key_field_cache_list, kfcache, next);

		if (kfcache->key_field_info.info.name == NULL ||
		    strlen(kfcache->key_field_info.info.name) == 0 ||
		    strlen(kfcache->key_field_info.info.name) >= RTE_TDI_OBJ_NAME_MAX)
			continue;

		strcpy(name, kfcache->key_field_info.info.name);
		if (rte_hash_add_key_data(tcache->field_hash_by_name, name, tcache) != 0)
			return false;
	}

	return true;
}

static bool
build_table_cache(struct rte_eth_dev *dev,
		  const struct rte_tdi_ops *ops,
		  struct rte_tdi_cache *cache)
{
	uint16_t port_id;
	char hname[32];
	uint16_t i;

	if (cache->table_cache_hash_by_id != NULL)
		return true;

	if (ops->table_info_get == NULL)
		return false;

	if (cache->table_list == NULL) {
		if (!ops->table_list_popup)
			return false;

		ops->table_list_popup(dev, &cache->table_list, NULL);
	}

	if (cache->table_list == NULL)
		return false;

	TAILQ_INIT(&cache->table_cache_list);

	port_id = dev->data->port_id;
	snprintf(hname, 32, "tdi_t_name_p%d", port_id);
	cache->table_cache_hash_by_name = create_hash(hname, RTE_TDI_OBJ_NAME_MAX);
	if (cache->table_cache_hash_by_name == NULL)
		goto fail;

	snprintf(hname, 32, "tdi_t_id_p%d", port_id);
	cache->table_cache_hash_by_id = create_hash(hname, sizeof(uint32_t));
	if (cache->table_cache_hash_by_id == NULL)
		goto fail;

	for (i = 0; i < cache->table_list->num; i++) {
		uint32_t id = cache->table_list->ids[i];
		struct rte_tdi_table_cache *tcache =
			rte_malloc(NULL, sizeof(struct rte_tdi_table_cache), 0);
		char name[RTE_TDI_OBJ_NAME_MAX] = { 0 };

		if (tcache == NULL)
			goto fail;

		if (ops->table_info_get(dev, id, &tcache->table_info, NULL) != 0)
			goto fail;

		if (!build_table_key_field_cache(dev, ops, tcache))
			goto fail;

		if (rte_hash_add_key_data(cache->table_cache_hash_by_id, &id,
					  tcache) != 0)
			goto fail;

		TAILQ_INSERT_TAIL(&cache->table_cache_list, tcache, next);

		if (tcache->table_info.info.name == NULL ||
		    strlen(tcache->table_info.info.name) == 0 ||
		    strlen(tcache->table_info.info.name) >= RTE_TDI_OBJ_NAME_MAX)
			continue;

		strcpy(name, tcache->table_info.info.name);
		if (rte_hash_add_key_data(cache->table_cache_hash_by_name,
					  name, tcache) != 0)
			goto fail;
	}

	return true;

fail:
	free_table_cache(dev, ops, cache);
	return false;
}

static struct rte_tdi_table_cache *
get_table_cache_by_id(struct rte_eth_dev *dev,
		     const struct rte_tdi_ops *ops,
		     struct rte_tdi_cache *cache,
		     uint32_t table_id)
{
	struct rte_tdi_table_cache *tcache;

	if (!build_table_cache(dev, ops, cache))
		return NULL;

	if (rte_hash_lookup_data(cache->table_cache_hash_by_id, &table_id, (void **)&tcache) >= 0)
		return tcache;

	return NULL;
}

static struct rte_tdi_table_cache *
get_table_cache_by_name(struct rte_eth_dev *dev,
		       const struct rte_tdi_ops *ops,
		       struct rte_tdi_cache *cache,
		       const char *name)
{
	struct rte_tdi_table_cache *tcache;
	char tname[RTE_TDI_OBJ_NAME_MAX];

	if (!build_table_cache(dev, ops, cache))
		return NULL;

	if (name == NULL || strlen(name) == 0 || strlen(name) >= RTE_TDI_OBJ_NAME_MAX)
		return NULL;

	strcpy(tname, name);

	if (rte_hash_lookup_data(cache->table_cache_hash_by_id, tname, (void **)&tcache) >= 0)
		return tcache;

	return NULL;
}

static struct rte_tdi_table_key_field_cache *
get_table_key_field_info_by_id(struct rte_tdi_table_cache *tcache,
			       uint32_t field_id)
{
	struct rte_tdi_table_key_field_cache *kfcache;

	if (rte_hash_lookup_data(tcache->field_hash_by_id, &field_id, (void **)&kfcache) >= 0)
		return kfcache;

	return NULL;
}

static struct rte_tdi_table_key_field_cache *
get_table_key_field_info_by_name(struct rte_tdi_table_cache *tcache,
				 const char *name)
{
	struct rte_tdi_table_key_field_cache *kfcache;
	char kfname[RTE_TDI_OBJ_NAME_MAX];

	if (name == NULL || strlen(name) == 0 || strlen(name) >= RTE_TDI_OBJ_NAME_MAX)
		return NULL;

	strcpy(kfname, name);

	if (rte_hash_lookup_data(tcache->field_hash_by_name, kfname, (void **)&kfcache) > 0)
		return kfcache;

	return NULL;
}

int
rte_tdi_table_list_popup(uint16_t port_id,
			 struct rte_tdi_id_list **list,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_cache *cache;
	int size;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_list_popup)
		goto err;

	if (!list)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	if (!build_table_cache(dev, ops, cache))
		goto err;

	size = sizeof(struct rte_tdi_id_list) + sizeof(uint32_t) * cache->table_list->num;
	*list = rte_malloc(NULL, size, 0);

	if (*list == NULL)
		goto err;

	rte_memcpy(*list, cache->table_list, size);

	return 0;
direct:
	ret = ops->table_list_popup(dev, list, error);
	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_info_get(uint16_t port_id,
		       uint32_t table_id,
		       struct rte_tdi_table_info *info,
		       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_info_get)
		goto err;

	if (!info)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	*info = tcache->table_info.info;
	return 0;

direct:
	ret = ops->table_info_get(dev, table_id, &dtinfo, error);
	if (ret == 0) {
		*info = dtinfo.info;
		__table_info_put(dev, ops, &dtinfo);
	}
	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_info_get_by_name(uint16_t port_id,
			       const char *name,
			       struct rte_tdi_table_info *info,
			       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;

	if (!ops)
		return -rte_errno;

	if (!info || !name)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	tcache = get_table_cache_by_name(dev, ops, cache, name);
	if (tcache == NULL)
		goto err;

	*info = tcache->table_info.info;
	return 0;

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_info_get(uint16_t port_id,
				 uint32_t table_id,
				 uint32_t field_id,
				 struct rte_tdi_table_key_field_info *info,
				 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key_field_cache *kfcache;
	struct rte_tdi_drv_table_key_field_info dkfinfo;
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_info_get || !ops->table_key_field_info_get)
		goto err;

	if (!info)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_id(tcache, field_id);
	if (kfcache == NULL)
		goto err;

	*info = kfcache->key_field_info.info;
	return 0;

direct:
	ret = ops->table_info_get(dev, table_id, &dtinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->table_key_field_info_get(dev, &dtinfo, field_id, &dkfinfo, error);
	if (ret == 0) {
		*info = dkfinfo.info;
		__table_key_field_info_put(dev, ops, &dkfinfo);
	}
	__table_info_put(dev, ops, &dtinfo);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

static void
free_action_spec_cache(struct rte_eth_dev *dev,
		       const struct rte_tdi_ops *ops,
		       struct rte_tdi_cache *cache)
{
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_action_spec_field_cache *fcache;

	if (cache->action_spec_list != NULL)
		rte_free(cache->action_spec_list);

	if (cache->action_spec_cache_hash_by_name != NULL) {
		rte_hash_free(cache->action_spec_cache_hash_by_name);
		cache->action_spec_cache_hash_by_name = NULL;
	}

	if (cache->action_spec_cache_hash_by_id != NULL) {
		rte_hash_free(cache->action_spec_cache_hash_by_id);
		cache->action_spec_cache_hash_by_id = NULL;
	}

	while ((ascache = TAILQ_FIRST(&cache->action_spec_cache_list))) {
		if (ascache->field_hash_by_name != NULL)
			rte_hash_free(ascache->field_hash_by_name);

		if (ascache->field_hash_by_id != NULL)
			rte_hash_free(ascache->field_hash_by_id);

		while ((fcache = TAILQ_FIRST(&ascache->field_cache_list))) {
			TAILQ_REMOVE(&ascache->field_cache_list, fcache, next);
			__action_spec_field_info_put(dev, ops, &fcache->field_info);
			rte_free(fcache);
		}

		TAILQ_REMOVE(&cache->action_spec_cache_list, ascache, next);
		__action_spec_info_put(dev, ops, &ascache->action_spec_info);
		rte_free(ascache);
	}
}

static bool
build_action_spec_field_cache(struct rte_eth_dev *dev,
			      const struct rte_tdi_ops *ops,
			      struct rte_tdi_action_spec_cache *ascache)
{
	struct rte_tdi_action_spec_info *asinfo;
	uint16_t port_id;
	uint32_t spec_id;
	char hname[32];
	uint16_t i;

	if (ops->action_spec_field_info_get == NULL)
		return false;

	port_id = dev->data->port_id;
	asinfo = &ascache->action_spec_info.info;
	spec_id = asinfo->id;

	snprintf(hname, 32, "tdi_asf_name_p%d_t%d", port_id, spec_id);
	ascache->field_hash_by_name = create_hash(hname, RTE_TDI_OBJ_NAME_MAX);
	if (ascache->field_hash_by_name == NULL)
		return false;

	snprintf(hname, 32, "tdi_asf_id_p%d_t%d", port_id, spec_id);
	ascache->field_hash_by_id = create_hash(hname, sizeof(uint32_t));
	if (ascache->field_hash_by_id == NULL)
		return false;

	TAILQ_INIT(&ascache->field_cache_list);

	for (i = 0; i < asinfo->field_num; i++) {
		uint32_t id = asinfo->fields[i];
		struct rte_tdi_action_spec_field_cache *fcache =
			rte_malloc(NULL, sizeof(struct rte_tdi_action_spec_field_cache), 0);
		char name[RTE_TDI_OBJ_NAME_MAX] = { 0 };

		if (fcache == NULL)
			return false;

		if (ops->action_spec_field_info_get(dev, &ascache->action_spec_info, id,
						    &fcache->field_info, NULL) != 0)
			return false;

		if (rte_hash_add_key_data(ascache->field_hash_by_id, &id, fcache) != 0)
			return false;

		TAILQ_INSERT_TAIL(&ascache->field_cache_list, fcache, next);

		if (fcache->field_info.info.name == NULL ||
		    strlen(fcache->field_info.info.name) == 0 ||
		    strlen(fcache->field_info.info.name) >= RTE_TDI_OBJ_NAME_MAX)
			continue;

		strcpy(name, fcache->field_info.info.name);
		if (rte_hash_add_key_data(ascache->field_hash_by_name,
					  name, ascache) != 0)
			return false;
	}

	return true;
}

static bool
build_action_spec_cache(struct rte_eth_dev *dev,
			const struct rte_tdi_ops *ops,
			struct rte_tdi_cache *cache)
{
	uint16_t port_id;
	char hname[32];
	uint16_t i;

	if (cache->action_spec_cache_hash_by_id != NULL)
		return true;

	if (ops->action_spec_info_get == NULL)
		return false;

	if (cache->action_spec_list == NULL) {
		if (!ops->action_spec_list_popup)
			return false;

		ops->action_spec_list_popup(dev, &cache->action_spec_list, NULL);
	}

	if (cache->action_spec_list == NULL)
		return false;

	TAILQ_INIT(&cache->action_spec_cache_list);

	port_id = dev->data->port_id;
	snprintf(hname, 32, "tdi_as_name_p%d", port_id);
	cache->action_spec_cache_hash_by_name = create_hash(hname, RTE_TDI_OBJ_NAME_MAX);
	if (cache->action_spec_cache_hash_by_name == NULL)
		goto fail;

	snprintf(hname, 32, "tdi_as_id_p%d", port_id);
	cache->action_spec_cache_hash_by_id = create_hash(hname, sizeof(uint32_t));
	if (cache->action_spec_cache_hash_by_id == NULL)
		goto fail;

	for (i = 0; i < cache->action_spec_list->num; i++) {
		uint32_t id = cache->action_spec_list->ids[i];
		struct rte_tdi_action_spec_cache *ascache =
			rte_malloc(NULL, sizeof(struct rte_tdi_action_spec_cache), 0);
		char name[RTE_TDI_OBJ_NAME_MAX] = { 0 };

		if (ascache == NULL)
			goto fail;

		if (ops->action_spec_info_get(dev, id, &ascache->action_spec_info, NULL) != 0)
			goto fail;

		if (!build_action_spec_field_cache(dev, ops, ascache))
			goto fail;

		if (rte_hash_add_key_data(cache->action_spec_cache_hash_by_id,
					  &id, ascache) != 0)
			goto fail;

		TAILQ_INSERT_TAIL(&cache->action_spec_cache_list, ascache, next);

		if (ascache->action_spec_info.info.name == NULL ||
		    strlen(ascache->action_spec_info.info.name) == 0 ||
		    strlen(ascache->action_spec_info.info.name) >= RTE_TDI_OBJ_NAME_MAX)
			continue;

		strcpy(name, ascache->action_spec_info.info.name);
		if (rte_hash_add_key_data(cache->action_spec_cache_hash_by_name,
					  name, ascache) != 0)
			goto fail;
	}

	return true;

fail:
	free_action_spec_cache(dev, ops, cache);
	return false;
}

static struct rte_tdi_action_spec_cache *
get_action_spec_cache_by_id(struct rte_eth_dev *dev,
		     const struct rte_tdi_ops *ops,
		     struct rte_tdi_cache *cache,
		     uint32_t spec_id)
{
	struct rte_tdi_action_spec_cache *ascache;

	if (!build_action_spec_cache(dev, ops, cache))
		return NULL;

	if (rte_hash_lookup_data(cache->action_spec_cache_hash_by_id,
				 &spec_id, (void **)&ascache) >= 0)
		return ascache;

	return NULL;
}

static struct rte_tdi_action_spec_cache *
get_action_spec_cache_by_name(struct rte_eth_dev *dev,
		       const struct rte_tdi_ops *ops,
		       struct rte_tdi_cache *cache,
		       const char *name)
{
	struct rte_tdi_action_spec_cache *ascache;
	char tname[RTE_TDI_OBJ_NAME_MAX];

	if (!build_action_spec_cache(dev, ops, cache))
		return NULL;

	if (name == NULL || strlen(name) == 0 || strlen(name) >= RTE_TDI_OBJ_NAME_MAX)
		return NULL;

	strcpy(tname, name);

	if (rte_hash_lookup_data(cache->action_spec_cache_hash_by_id,
				 tname, (void **)&ascache) >= 0)
		return ascache;

	return NULL;
}

int
rte_tdi_action_spec_list_popup(uint16_t port_id,
			       struct rte_tdi_id_list **list,
			       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_cache *cache;
	int size;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_spec_list_popup)
		goto err;

	if (!list)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	if (!build_action_spec_cache(dev, ops, cache))
		goto err;

	size = sizeof(struct rte_tdi_id_list) + sizeof(uint32_t) * cache->action_spec_list->num;
	*list = rte_malloc(NULL, size, 0);

	if (*list == NULL)
		goto err;

	rte_memcpy(*list, cache->action_spec_list, size);

	return 0;

direct:
	ret = ops->action_spec_list_popup(dev, list, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_spec_info_get(uint16_t port_id,
			     uint32_t spec_id,
			     struct rte_tdi_action_spec_info *info,
			     struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_action_spec_info asinfo;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_spec_info_get)
		goto err;

	if (!info)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, spec_id);
	if (ascache == NULL)
		goto err;

	*info = ascache->action_spec_info.info;
	return 0;

direct:
	ret = ops->action_spec_info_get(dev, spec_id, &asinfo, error);
	if (ret == 0) {
		*info = asinfo.info;
		__action_spec_info_put(dev, ops, &asinfo);
	}
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_spec_info_get_by_name(uint16_t port_id,
				     const char *name,
				     struct rte_tdi_action_spec_info *info,
				     struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_cache *cache = NULL;

	if (!ops)
		return -rte_errno;

	if (!info || !name)
		goto err;

	if (!!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	ascache = get_action_spec_cache_by_name(dev, ops, cache, name);
	if (ascache == NULL)
		goto err;

	*info = ascache->action_spec_info.info;
	return 0;

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

static struct rte_tdi_action_spec_field_cache *
get_action_spec_field_info_by_id(struct rte_tdi_action_spec_cache *ascache,
			       uint32_t field_id)
{
	struct rte_tdi_action_spec_field_cache *fcache;

	if (rte_hash_lookup_data(ascache->field_hash_by_id, &field_id, (void **)&fcache) >= 0)
		return fcache;

	return NULL;
}

static struct rte_tdi_action_spec_field_cache *
get_action_spec_field_info_by_name(struct rte_tdi_action_spec_cache *ascache,
				   const char *name)
{
	struct rte_tdi_action_spec_field_cache *fcache;
	char fname[RTE_TDI_OBJ_NAME_MAX];

	if (name == NULL || strlen(name) == 0 || strlen(name) >= RTE_TDI_OBJ_NAME_MAX)
		return NULL;

	strcpy(fname, name);

	if (rte_hash_lookup_data(ascache->field_hash_by_name, fname, (void **)&fcache) > 0)
		return fcache;

	return NULL;
}

int
rte_tdi_action_spec_field_info_get(uint16_t port_id,
				   uint32_t spec_id,
				   uint32_t field_id,
				   struct rte_tdi_action_spec_field_info *info,
				   struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_action_spec_field_info dfinfo;
	struct rte_tdi_action_spec_field_cache *fcache;
	struct rte_tdi_drv_action_spec_info asinfo;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_spec_info_get || !ops->action_spec_field_info_get)
		goto err;

	if (!info)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, spec_id);
	if (ascache == NULL)
		goto err;

	fcache = get_action_spec_field_info_by_id(ascache, field_id);
	if (fcache == NULL)
		goto err;

	*info = fcache->field_info.info;
	return 0;

direct:
	ret = ops->action_spec_info_get(dev, spec_id, &asinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->action_spec_field_info_get(dev, &asinfo, field_id, &dfinfo, error);
	if (ret == 0) {
		*info = dfinfo.info;
		__action_spec_field_info_put(dev, ops, &dfinfo);
	}
	__action_spec_info_put(dev, ops, &asinfo);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_create(uint16_t port_id,
			 uint32_t table_id,
			 struct rte_tdi_table_key **key,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	struct rte_tdi_table_key *new_key;
	bool direct = false;
	uint16_t key_size;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_info_get || !ops->table_key_size_get)
		goto err;

	if (!key)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	dtinfo = tcache->table_info;
	goto create;

direct:
	ret = ops->table_info_get(dev, table_id, &dtinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	direct = true;

create:

	key_size = ops->table_key_size_get(dev, table_id);
	new_key = rte_malloc(NULL, sizeof(struct rte_tdi_table_key) + key_size, 0);
	if (new_key == NULL)
		goto err;

	new_key->table_id = table_id;
	if (!!ops->table_key_init) {
		ret = ops->table_key_init(dev, &dtinfo, new_key, error);
		if (ret != 0) {
			rte_free(new_key);
			goto fin;
		}
	}
	*key = new_key;
fin:
	if (direct)
		__table_info_put(dev, ops, &dtinfo);

	return tdi_err(port_id, ret, error);
err:
	if (direct)
		__table_info_put(dev, ops, &dtinfo);

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_destroy(uint16_t port_id,
			  struct rte_tdi_table_key *key,
			  struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret = 0;

	if (!ops)
		return -rte_errno;

	if (!key || key->ref_cnt > 0)
		goto err;

	if (!!ops->table_key_deinit) {
		ret = ops->table_key_deinit(dev, key, error);
		if (ret != 0)
			goto fin;
	}

	rte_free(key);

fin:
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

static inline bool
verify_action(struct rte_tdi_table_info *info, uint32_t spec_id)
{
	int i;

	for (i = 0; i < info->action_spec_num; i++)
		if (spec_id == info->action_specs[i])
			return true;

	return false;
}

int
rte_tdi_action_create(uint16_t port_id,
		      uint32_t table_id,
		      uint32_t spec_id,
		      struct rte_tdi_action **action,
		      struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_action_spec_info dasinfo;
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	struct rte_tdi_action *new_action;
	uint16_t action_size;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_info_get || !ops->action_spec_info_get || !ops->action_size_get)
		goto err;

	if (!action)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, spec_id);
	if (ascache == NULL)
		goto err;

	dtinfo = tcache->table_info;
	dasinfo = ascache->action_spec_info;
	goto verify;

direct:
	ret = ops->table_info_get(dev, spec_id, &dtinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->action_spec_info_get(dev, spec_id, &dasinfo, error);
	if (ret != 0) {
		__table_info_put(dev, ops, &dtinfo);
		return tdi_err(port_id, ret, error);
	}

	direct = true;

verify:
	if (!verify_action(&dtinfo.info, spec_id))
		goto err;

	action_size = ops->action_size_get(dev, spec_id);
	new_action = rte_malloc(NULL, sizeof(struct rte_tdi_action) + action_size, 0);
	if (!new_action)
		goto err;

	new_action->table_id = table_id;
	new_action->spec_id = spec_id;
	if (!!ops->action_init) {
		ret = ops->action_init(dev, &dtinfo, &dasinfo, new_action, error);
		if (ret != 0) {
			rte_free(new_action);
			goto fin;
		}
	}

	*action = new_action;

fin:
	if (direct) {
		__table_info_put(dev, ops, &dtinfo);
		__action_spec_info_put(dev, ops, &dasinfo);
	}

	return tdi_err(port_id, ret, error);

err:
	if (direct) {
		__table_info_put(dev, ops, &dtinfo);
		__action_spec_info_put(dev, ops, &dasinfo);
	}

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_destroy(uint16_t port_id,
		       struct rte_tdi_action *action,
		       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret = 0;

	if (!ops)
		return -rte_errno;

	if (!action || action->ref_cnt > 0)
		goto err;

	if (!!ops->action_deinit) {
		ret = ops->action_deinit(dev, action, error);
		if (ret != 0)
			goto fin;
	}

	rte_free(action);
fin:
	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set(uint16_t port_id,
			    struct rte_tdi_table_key *key,
			    uint32_t field_id,
			    const uint8_t *value,
			    uint16_t size,
			    struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info tinfo;
	struct rte_tdi_drv_table_key_field_info dkfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_table_key_field_cache *kfcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set || !ops->table_info_get || !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_id(tcache, field_id);
	if (kfcache == NULL)
		goto err;

	dkfinfo = kfcache->key_field_info;
	goto set;

direct:
	ret = ops->table_info_get(dev, key->table_id, &tinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->table_key_field_info_get(dev, &tinfo, field_id, &dkfinfo, error);
	if (!!ops->table_info_put)
		ops->table_info_put(dev, &tinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

set:
	if (dkfinfo.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT)
		goto err;

	ret = ops->table_key_field_set(dev, key, &dkfinfo, value, size, error);
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);
	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_by_name(uint16_t port_id,
				    struct rte_tdi_table_key *key,
				    const char *name,
				    const uint8_t *value,
				    uint16_t size,
				    struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key_field_cache *kfcache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set || !ops->table_info_get || !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !name || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_name(tcache, name);
	if (kfcache == NULL)
		goto err;

	if (kfcache->key_field_info.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_EXACT)
		goto err;

	ret = ops->table_key_field_set(dev, key, &kfcache->key_field_info,
				       value, size, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_mask(uint16_t port_id,
				      struct rte_tdi_table_key *key,
				      uint32_t field_id,
				      const uint8_t *value,
				      const uint8_t *mask,
				      uint16_t size,
				      struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info tinfo;
	struct rte_tdi_drv_table_key_field_info dkfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_table_key_field_cache *kfcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_mask ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_id(tcache, field_id);
	if (kfcache == NULL)
		goto err;

	dkfinfo = kfcache->key_field_info;
	goto set;

direct:
	ret = ops->table_info_get(dev, key->table_id, &tinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->table_key_field_info_get(dev, &tinfo, field_id, &dkfinfo, error);
	if (!!ops->table_info_put)
		ops->table_info_put(dev, &tinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

set:
	if (dkfinfo.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_WILDCARD)
		goto err;

	ret = ops->table_key_field_set_with_mask(dev, key, &dkfinfo,
						 value, mask, size, error);
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);
	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_mask_by_name(uint16_t port_id,
					      struct rte_tdi_table_key *key,
					      const char *name,
					      const uint8_t *value,
					      const uint8_t *mask,
					      uint16_t size,
					      struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key_field_cache *kfcache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_mask ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !name || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_name(tcache, name);
	if (kfcache == NULL)
		goto err;

	if (kfcache->key_field_info.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_WILDCARD)
		goto err;

	ret = ops->table_key_field_set_with_mask(dev, key, &kfcache->key_field_info,
						 value, mask, size, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_range(uint16_t port_id,
				       struct rte_tdi_table_key *key,
				       uint32_t field_id,
				       const uint8_t *min,
				       const uint8_t *max,
				       uint16_t size,
				       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info tinfo;
	struct rte_tdi_drv_table_key_field_info dkfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_table_key_field_cache *kfcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_range ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !min || !max)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache != NULL)
		goto err;

	kfcache = get_table_key_field_info_by_id(tcache, field_id);
	if (kfcache != NULL)
		goto err;

	dkfinfo = kfcache->key_field_info;
	goto set;

direct:
	ret = ops->table_info_get(dev, key->table_id, &tinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->table_key_field_info_get(dev, &tinfo, field_id, &dkfinfo, error);
	if (!!ops->table_info_put)
		ops->table_info_put(dev, &tinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

set:
	if (dkfinfo.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_RANGE)
		goto err;

	ret = ops->table_key_field_set_with_range(dev, key, &dkfinfo, min, max, size, error);
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);

	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_range_by_name(uint16_t port_id,
					       struct rte_tdi_table_key *key,
					       const char *name,
					       const uint8_t *min,
					       const uint8_t *max,
					       uint16_t size,
					       struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key_field_cache *kfcache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_range ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || key->ref_cnt > 0 || !name || !min || !max)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_name(tcache, name);
	if (kfcache == NULL)
		goto err;

	if (kfcache->key_field_info.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_RANGE)
		goto err;

	ret = ops->table_key_field_set_with_range(dev, key, &kfcache->key_field_info,
						  min, max, size, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_prefix(uint16_t port_id,
					struct rte_tdi_table_key *key,
					uint32_t field_id,
					const uint8_t *value,
					uint16_t size,
					uint16_t prefix,
					struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info tinfo;
	struct rte_tdi_drv_table_key_field_info dkfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_table_key_field_cache *kfcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_prefix ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache != NULL)
		goto err;

	kfcache = get_table_key_field_info_by_id(tcache, field_id);
	if (kfcache != NULL)
		goto err;

	dkfinfo = kfcache->key_field_info;
	goto set;

direct:
	ret = ops->table_info_get(dev, key->table_id, &tinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->table_key_field_info_get(dev, &tinfo, field_id, &dkfinfo, error);
	if (!!ops->table_info_put)
		ops->table_info_put(dev, &tinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

set:
	if (dkfinfo.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_LPM)
		goto err;

	ret = ops->table_key_field_set_with_prefix(dev, key, &dkfinfo, value, size, prefix, error);
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);

	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__table_key_field_info_put(dev, ops, &dkfinfo);

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_field_set_with_prefix_by_name(uint16_t port_id,
						struct rte_tdi_table_key *key,
						const char *name,
						const uint8_t *value,
						uint16_t size,
						uint16_t prefix,
						struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key_field_cache *kfcache;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_field_set_with_prefix ||
	    !ops->table_info_get ||
	    !ops->table_key_field_info_get)
		goto err;

	if (!key || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	tcache = get_table_cache_by_id(dev, ops, cache, key->table_id);
	if (tcache == NULL)
		goto err;

	kfcache = get_table_key_field_info_by_name(tcache, name);
	if (kfcache == NULL)
		goto err;

	if (kfcache->key_field_info.info.match_type != RTE_TDI_TABLE_KEY_MATCH_TYPE_LPM)
		goto err;

	ret = ops->table_key_field_set_with_prefix(dev, key, &kfcache->key_field_info,
						  value, size, prefix, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_field_set(uint16_t port_id,
			 struct rte_tdi_action *action,
			 uint32_t field_id,
			 const uint8_t *value,
			 uint16_t size,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_action_spec_info asinfo;
	struct rte_tdi_drv_action_spec_field_info dfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_action_spec_field_cache *fcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_field_set ||
	    !ops->action_spec_info_get ||
	    !ops->action_spec_field_info_get)
		goto err;

	if (!action || action->ref_cnt > 0 || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, action->spec_id);
	if (ascache == NULL)
		goto err;

	fcache = get_action_spec_field_info_by_id(ascache, field_id);
	if (fcache == NULL)
		goto err;

	dfinfo = fcache->field_info;
	goto set;

direct:
	ret = ops->action_spec_info_get(dev, action->spec_id, &asinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->action_spec_field_info_get(dev, &asinfo, field_id, &dfinfo, error);
	__action_spec_info_put(dev, ops, &asinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

set:
	ret = ops->action_field_set(dev, action, &dfinfo, value, size, error);
	if (direct)
		__action_spec_field_info_put(dev, ops, &dfinfo);

	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__action_spec_field_info_put(dev, ops, &dfinfo);

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_field_get(uint16_t port_id,
			 const struct rte_tdi_action *action,
			 uint32_t field_id,
			 uint8_t *value,
			 uint16_t *size,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_action_spec_info asinfo;
	struct rte_tdi_drv_action_spec_field_info dfinfo;
	struct rte_tdi_cache *cache;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_action_spec_field_cache *fcache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_field_get ||
	    !ops->action_spec_info_get ||
	    !ops->action_spec_field_info_get)
		goto err;

	if (!action || !value || !size)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, action->spec_id);
	if (ascache == NULL)
		goto err;

	fcache = get_action_spec_field_info_by_id(ascache, field_id);
	if (fcache == NULL)
		goto err;

	dfinfo = fcache->field_info;
	goto get;

direct:
	ret = ops->action_spec_info_get(dev, action->spec_id, &asinfo, NULL);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	ret = ops->action_spec_field_info_get(dev, &asinfo, field_id, &dfinfo, error);
	__action_spec_info_put(dev, ops, &asinfo);
	if (ret != 0)
		return tdi_err(port_id, ret, error);
	direct = true;

get:
	ret = ops->action_field_get(dev, action, &dfinfo, value, size, error);
	if (direct)
		__action_spec_field_info_put(dev, ops, &dfinfo);

	return tdi_err(port_id, ret, error);

err:
	if (direct)
		__action_spec_field_info_put(dev, ops, &dfinfo);

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_field_set_by_name(uint16_t port_id,
				 struct rte_tdi_action *action,
				 const char *name,
				 const uint8_t *value,
				 uint16_t size,
				 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_action_spec_field_cache *fcache;
	struct rte_tdi_action_spec_cache *ascache;
	struct rte_tdi_cache *cache = NULL;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->action_field_set ||
	    !ops->action_spec_info_get ||
	    !ops->action_spec_field_info_get)
		goto err;

	if (!action || action->ref_cnt > 0 || !name || !value)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto err;

	ascache = get_action_spec_cache_by_id(dev, ops, cache, action->spec_id);
	if (ascache == NULL)
		goto err;

	fcache = get_action_spec_field_info_by_name(ascache, name);
	if (fcache == NULL)
		goto err;

	ret = ops->action_field_set(dev, action, &fcache->field_info,
				    value, size, error);
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_default_action_set(uint16_t port_id,
				 uint32_t table_id,
				 const struct rte_tdi_action *action,
				 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_default_action_set || !ops->table_info_get)
		goto err;

	if (!action)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	dtinfo = tcache->table_info;
	goto verify;

direct:
	ret = ops->table_info_get(dev, table_id, &dtinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	direct = true;

verify:
	if (!verify_action(&dtinfo.info, action->spec_id))
		goto err;

	ret = ops->table_default_action_set(dev, &dtinfo, action, error);
	if (direct)
		__table_info_put(dev, ops, &dtinfo);

	return tdi_err(port_id, ret, error);
err:
	if (direct)
		__table_info_put(dev, ops, &dtinfo);
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_default_action_cancel(uint32_t port_id,
				    uint32_t table_id,
				    struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_drv_table_info dtinfo;
	struct rte_tdi_table_cache *tcache;
	struct rte_tdi_cache *cache;
	bool direct = false;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_default_action_cancel || !ops->table_info_get)
		goto err;

	if (!ops->cache_get || ops->cache_get(dev, &cache) != 0)
		goto direct;

	tcache = get_table_cache_by_id(dev, ops, cache, table_id);
	if (tcache == NULL)
		goto err;

	dtinfo = tcache->table_info;
	goto cancel;

direct:
	ret = ops->table_info_get(dev, table_id, &dtinfo, error);
	if (ret != 0)
		return tdi_err(port_id, ret, error);

	direct = true;

cancel:
	ret = ops->table_default_action_cancel(dev, &dtinfo, error);
	if (direct)
		__table_info_put(dev, ops, &dtinfo);

	return tdi_err(port_id, ret, error);
err:
	if (direct)
		__table_info_put(dev, ops, &dtinfo);
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_add(uint16_t port_id,
			uint32_t table_id,
			const struct rte_tdi_table_key *key,
			const struct rte_tdi_action *action,
			struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_add)
		goto err;

	if (!key || !action)
		goto err;

	if (table_id != key->table_id || table_id != action->table_id)
		goto err;

	ret = ops->table_entry_add(dev, key, action, error);

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_query(uint16_t port_id,
			  uint32_t table_id,
			  const struct rte_tdi_table_key *key,
			  struct rte_tdi_action **action,
			  struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_query)
		goto err;

	if (!key || !action)
		goto err;

	if (table_id != key->table_id)
		goto err;

	ret = ops->table_entry_query(dev, key, action, error);

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_del(uint16_t port_id,
			uint32_t table_id,
			const struct rte_tdi_table_key *key,
			struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_del)
		goto err;

	if (!key)
		goto err;

	if (table_id != key->table_id)
		goto err;

	ret = ops->table_entry_del(dev, key, error);

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_count_query(uint16_t port_id,
				uint32_t table_id,
				const struct rte_tdi_table_key *key,
				struct rte_tdi_query_count *count,
				struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_count_query)
		goto err;

	if (!key)
		goto err;

	if (table_id != key->table_id)
		goto err;

	ret = ops->table_entry_count_query(dev, key, count, error);

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_key_clone(uint16_t port_id,
			const struct rte_tdi_table_key *key,
			struct rte_tdi_table_key **new_key,
			struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_table_key *nk;
	uint16_t key_size;
	int ret = 0;

	if (!ops)
		return -rte_errno;

	if (!ops->table_key_size_get)
		goto err;

	if (!key)
		goto err;

	key_size = ops->table_key_size_get(dev, key->table_id);
	nk = rte_malloc(NULL, sizeof(struct rte_tdi_table_key) + key_size, 0);
	if (!nk)
		goto err;

	nk->table_id = key->table_id;

	if (!!ops->table_key_clone) {
		ret = ops->table_key_clone(dev, key, nk, error);
		if (ret != 0) {
			rte_free(nk);
			goto fin;
		}
	} else {
		rte_memcpy(nk->data, key->data, key_size);
	}

	*new_key = nk;
fin:
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_action_clone(uint16_t port_id,
		     const struct rte_tdi_action *action,
		     struct rte_tdi_action **new_action,
		     struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_tdi_action *na;
	uint16_t action_size;
	int ret = 0;

	if (!ops)
		return -rte_errno;

	if (!ops->action_size_get)
		goto err;

	if (!action)
		goto err;

	action_size = ops->action_size_get(dev, action->spec_id);
	na = rte_malloc(NULL, sizeof(struct rte_tdi_action) + action_size, 0);
	if (!na)
		goto err;

	na->table_id = action->table_id;
	na->spec_id = action->spec_id;

	if (!!ops->action_clone) {
		ret = ops->action_clone(dev, action, na, error);
		if (ret != 0) {
			rte_free(na);
			goto fin;
		}
	} else {
		rte_memcpy(na->data, action->data, action_size);
	}
	*new_action = na;
fin:
	return tdi_err(port_id, ret, error);

err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_add_prepare(uint16_t port_id,
				uint32_t table_id,
				struct rte_tdi_table_key *key,
				struct rte_tdi_action *action,
				struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_add_prepare)
		goto err;

	if (!key || !action)
		goto err;

	if (table_id != key->table_id || table_id != action->table_id)
		goto err;

	ret = ops->table_entry_add_prepare(dev, key, action, error);
	if (ret == 0) {
		key->ref_cnt++;
		action->ref_cnt++;
	}

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_del_prepare(uint16_t port_id,
				uint32_t table_id,
				struct rte_tdi_table_key *key,
				struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_del_prepare)
		goto err;

	if (!key)
		goto err;

	if (table_id != key->table_id)
		goto err;

	ret = ops->table_entry_del_prepare(dev, key, error);

	if (ret == 0)
		key->ref_cnt++;

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_commit(uint16_t port_id,
			   struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_commit)
		goto err;

	ret = ops->table_entry_commit(dev, error);

	return tdi_err(port_id, ret, error);
err:

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_table_entry_status_pull(uint16_t port_id,
				struct rte_tdi_table_entry_status *stats,
				int size,
				struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	void *drv_stats = stats;
	int i, ret;

	if (!ops)
		return -rte_errno;

	if (!ops->table_entry_status_pull)
		goto err;

	if (!stats)
		goto err;

	ret = ops->table_entry_status_pull(dev, drv_stats, size, error);
	if (ret > 0) {
		for (i = 0; i < ret; i++) {
			stats[i].key->ref_cnt--;
			if (stats[i].action != 0)
				stats[i].action->ref_cnt--;
		}
	}

	return tdi_err(port_id, ret, error);
err:
	return rte_tdi_error_set(error, -ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_pna_port_get(uint16_t port_id,
		     uint16_t ethdev_port_id,
		     uint32_t *pna_port_id,
		     struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int ret;

	if (!ops)
		return -rte_errno;

	if (!rte_eth_dev_is_valid_port(ethdev_port_id))
		goto err;

	if (!ops->pna_port_get)
		goto err;

	ret = ops->pna_port_get(dev, &rte_eth_devices[ethdev_port_id], pna_port_id, error);

	return tdi_err(port_id, ret, error);
err:

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

int
rte_tdi_pna_rx_queue_get(uint16_t port_id,
			 uint16_t ethdev_port_id,
			 uint16_t ethdev_queue_id,
			 uint32_t *pna_queue_id,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_eth_dev *target;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!rte_eth_dev_is_valid_port(ethdev_port_id))
		goto err;

	target = &rte_eth_devices[ethdev_port_id];
	if (ethdev_queue_id >= target->data->nb_tx_queues)
		goto err;

	if (!ops->pna_port_get)
		goto err;

	ret = ops->pna_rx_queue_get(dev, target, ethdev_queue_id, pna_queue_id, error);

	return tdi_err(port_id, ret, error);
err:

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));

}

int
rte_tdi_pna_tx_queue_get(uint16_t port_id,
			 uint16_t ethdev_port_id,
			 uint16_t ethdev_queue_id,
			 uint32_t *pna_queue_id,
			 struct rte_tdi_error *error)
{
	const struct rte_tdi_ops *ops = rte_tdi_ops_get(port_id, error);
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_eth_dev *target;
	int ret;

	if (!ops)
		return -rte_errno;

	if (!rte_eth_dev_is_valid_port(ethdev_port_id))
		goto err;

	target = &rte_eth_devices[ethdev_port_id];
	if (ethdev_queue_id >= target->data->nb_tx_queues)
		goto err;

	if (!ops->pna_port_get)
		goto err;

	ret = ops->pna_tx_queue_get(dev, target, ethdev_queue_id, pna_queue_id, error);

	return tdi_err(port_id, ret, error);
err:

	return rte_tdi_error_set(error, ENOSYS,
				 RTE_TDI_ERROR_TYPE_UNSPECIFIED,
				 NULL, rte_strerror(ENOSYS));
}

void
rte_tdi_cache_free(struct rte_eth_dev *dev, struct rte_tdi_cache *cache)
{
	const struct rte_tdi_ops *ops;

	if (dev == NULL || cache == NULL)
		return;

	ops = rte_tdi_ops_get(dev->data->port_id, NULL);
	if (ops == NULL)
		return;

	free_table_cache(dev, ops, cache);
	free_action_spec_cache(dev, ops, cache);
}

const struct rte_tdi_ops *
rte_tdi_ops_get(uint16_t port_id, struct rte_tdi_error *error)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	const struct rte_tdi_ops *ops;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		rte_tdi_error_set(error,
			ENODEV,
			RTE_TDI_ERROR_TYPE_UNSPECIFIED,
			NULL,
			rte_strerror(ENODEV));
		return NULL;
	}

	if ((dev->dev_ops->tdi_ops_get == NULL) ||
		(dev->dev_ops->tdi_ops_get(dev, &ops) != 0) ||
		(ops == NULL)) {
		rte_tdi_error_set(error,
			ENOSYS,
			RTE_TDI_ERROR_TYPE_UNSPECIFIED,
			NULL,
			rte_strerror(ENOSYS));
		return NULL;
	}

	return ops;
}

static int parse_int_1(const char* str, int* output)
{
	int count = 0;
	char *str_cpy = strdup(str);
	char* token = strtok(str_cpy, ",");

	while (token != NULL) {
		int num = atoi(token);
		if (num == 0 && strcmp(token, "0") != 0)
			goto err;
		if (count >= 1)
			goto err;
		*output = num;
		count++;
		token = strtok(NULL, ",");
	}
	if (count != 1)
		goto err;

	free(str_cpy);

	return 0;
err:
	free(str_cpy);
	return -EINVAL;
}

static int parse_int_2(const char* str, int* output1, int *output2)
{
	int count = 0;
	char *str_cpy = strdup(str);
	char* token = strtok(str_cpy, ",");
	int tmp[2];

	while (token != NULL) {
		int num = atoi(token);
		if (num == 0 && strcmp(token, "0") != 0)
			goto err;

		if (count >= 2)
			goto err;
		tmp[count] = num;
		count++;
		token = strtok(NULL, ",");
	}
	if (count != 2)
		goto err;

	*output1 = tmp[0];
	*output2 = tmp[1];
	free(str_cpy);

	return 0;
err:
	free(str_cpy);
	return -EINVAL;
}

static int parse_int_3(const char* str, int* output1, int *output2, int *output3)
{
	int count = 0;
	char *str_cpy = strdup(str);
	char* token = strtok(str_cpy, ",");
	int tmp[3];

	while (token != NULL) {
		int num = atoi(token);
		if (num == 0 && strcmp(token, "0") != 0)
			goto err;

		if (count >= 3)
			goto err;
		tmp[count] = num;
		count++;
		token = strtok(NULL, ",");
	}
	if (count != 3)
		goto err;

	*output1 = tmp[0];
	*output2 = tmp[1];
	*output3 = tmp[2];
	free(str_cpy);

	return 0;
err:
	free(str_cpy);
	return -EINVAL;
}

static int
tdi_tel_table_list_handler(const char *cmd __rte_unused,
			   const char *params,
			   struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	struct rte_tdi_id_list *ids;
	uint32_t i;
	int port_id;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_1(params, &port_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_table_list_popup((uint16_t)port_id, &ids, &err);
	if (ret != 0)
		return ret;

	rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
	for (i = 0; i < ids->num; i++)
		rte_tel_data_add_array_int(d, ids->ids[i]);

	rte_free(ids);

	return 0;
}

static int
tdi_tel_action_spec_list_handler(const char *cmd __rte_unused,
				 const char *params,
				 struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	struct rte_tdi_id_list *ids;
	uint32_t i;
	int port_id;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_1(params, &port_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_action_spec_list_popup((uint16_t)port_id, &ids, &err);
	if (ret != 0)
		return ret;

	rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
	for (i = 0; i < ids->num; i++)
		rte_tel_data_add_array_int(d, ids->ids[i]);

	rte_free(ids);

	return 0;
}

static int
tdi_tel_table_info_handler(const char *cmd __rte_unused,
			   const char *params,
			   struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	int port_id, table_id;
	struct rte_tdi_table_info tinfo;
	struct rte_tel_data *fields = NULL;
	struct rte_tel_data *specs = NULL;
	uint16_t i;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_2(params, &port_id, &table_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_table_info_get((uint16_t)port_id, (uint32_t)table_id, &tinfo, &err);
	if (ret != 0)
		return ret;

	fields = rte_tel_data_alloc();
	if (fields == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	specs = rte_tel_data_alloc();
	if (specs == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_int(d, "id", table_id);
	rte_tel_data_add_dict_string(d, "name", tinfo.name);
	rte_tel_data_add_dict_string(d, "annoation", tinfo.annotation);

	rte_tel_data_start_array(fields, RTE_TEL_INT_VAL);
	for (i = 0; i < tinfo.key_field_num; i++)
		rte_tel_data_add_array_int(fields, tinfo.key_fields[i]);
	rte_tel_data_add_dict_container(d, "key_fields", fields, false);

	rte_tel_data_start_array(specs, RTE_TEL_INT_VAL);
	for (i = 0; i < tinfo.action_spec_num; i++)
		rte_tel_data_add_array_int(specs, tinfo.action_specs[i]);
	rte_tel_data_add_dict_container(d, "action_specs", specs, false);

	return 0;
err:
	if (fields != NULL)
		rte_tel_data_free(fields);
	if (specs != NULL)
		rte_tel_data_free(specs);

	return ret;
}

static int
tdi_tel_action_spec_info_handler(const char *cmd __rte_unused,
				 const char *params,
				 struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	int port_id, spec_id;
	struct rte_tdi_action_spec_info asinfo;
	struct rte_tel_data *fields = NULL;
	uint16_t i;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_2(params, &port_id, &spec_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_action_spec_info_get((uint16_t)port_id, (uint32_t)spec_id, &asinfo, &err);
	if (ret != 0)
		return ret;

	fields = rte_tel_data_alloc();
	if (fields == NULL)
		return -ENOMEM;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_int(d, "id", spec_id);
	rte_tel_data_add_dict_string(d, "name", asinfo.name);
	rte_tel_data_add_dict_string(d, "annoation", asinfo.annotation);

	rte_tel_data_start_array(fields, RTE_TEL_INT_VAL);
	for (i = 0; i < asinfo.field_num ; i++)
		rte_tel_data_add_array_int(fields, asinfo.fields[i]);
	rte_tel_data_add_dict_container(d, "fields", fields, false);

	return 0;
}

static const char *
match_type_to_str(enum rte_tdi_table_key_match_type match_type)
{
	switch (match_type) {
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
byte_order_to_str(enum rte_tdi_byte_order byte_order)
{
	switch (byte_order) {
		case RTE_TDI_BYTE_ORDER_HOST:
			return "host";
		case RTE_TDI_BYTE_ORDER_NETWORK:
			return "network";
		default:
			return "unknown";
	}
}

static int
tdi_tel_table_key_field_info_handler(const char *cmd __rte_unused,
				     const char *params,
				     struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	int port_id, table_id, field_id;
	struct rte_tdi_table_key_field_info kfinfo;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_3(params, &port_id, &table_id, &field_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_table_key_field_info_get((uint16_t)port_id, (uint32_t)table_id, (uint32_t)field_id, &kfinfo, &err);
	if (ret != 0)
		return ret;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_int(d, "table_id", table_id);
	rte_tel_data_add_dict_int(d, "field_id", field_id);
	rte_tel_data_add_dict_string(d, "name", kfinfo.name);
	rte_tel_data_add_dict_string(d, "annoation", kfinfo.annotation);
	rte_tel_data_add_dict_string(d, "match_type", match_type_to_str(kfinfo.match_type));
	rte_tel_data_add_dict_int(d, "bit_width", kfinfo.bit_width);
	rte_tel_data_add_dict_int(d, "byte_width", kfinfo.byte_width);
	rte_tel_data_add_dict_string(d, "byte_order", byte_order_to_str(kfinfo.byte_order));

	return 0;
}

static int
tdi_tel_action_spec_field_info_handler(const char *cmd __rte_unused,
				       const char *params,
				       struct rte_tel_data *d)
{
	struct rte_tdi_error err;
	int port_id, spec_id, field_id;
	struct rte_tdi_action_spec_field_info finfo;
	int ret;

	if (params == NULL)
		return -EINVAL;

	ret = parse_int_3(params, &port_id, &spec_id, &field_id);
	if (ret != 0)
		return ret;

	ret = rte_tdi_action_spec_field_info_get((uint16_t)port_id, (uint32_t)spec_id, (uint32_t)field_id, &finfo, &err);
	if (ret != 0)
		return ret;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_int(d, "table_id", spec_id);
	rte_tel_data_add_dict_int(d, "field_id", field_id);
	rte_tel_data_add_dict_string(d, "name", finfo.name);
	rte_tel_data_add_dict_string(d, "annoation", finfo.annotation);
	rte_tel_data_add_dict_int(d, "bit_width", finfo.bit_width);
	rte_tel_data_add_dict_int(d, "byte_width", finfo.byte_width);
	rte_tel_data_add_dict_string(d, "byte_order", byte_order_to_str(finfo.byte_order));

	return 0;
}

RTE_INIT(ethdev_tdi_telemetry_init)
{
	rte_telemetry_register_cmd("/ethdev/tdi/table_list", tdi_tel_table_list_handler,
			"Returns list of tdi table identifiers of a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/tdi/action_spec_list", tdi_tel_action_spec_list_handler,
			"Returns list of tdi action spec identifiers of a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/tdi/table_info", tdi_tel_table_info_handler,
			"Returns a tdi table info by port_id and table_id. Parameters: int port_id, int table_id");
	rte_telemetry_register_cmd("/ethdev/tdi/action_spec_info", tdi_tel_action_spec_info_handler,
			"Returns a tdi action spec info by port_id and spec_id. Parameters: int port_id, int spec_id");
	rte_telemetry_register_cmd("/ethdev/tdi/table_key_field_info", tdi_tel_table_key_field_info_handler,
			"Returns a tdi table key field info by port_id, table_id and field_id. Parameters: int port_id, int table_id, int field_id");
	rte_telemetry_register_cmd("/ethdev/tdi/action_spec_field_info", tdi_tel_action_spec_field_info_handler,
			"Returns a tdi action field info by port_id, spec_id and field_id. Parameters: int port_id, int spec_id, int field_id");
}


#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "cpfl_flow_fxp_metadata.h"
#include "cpfl_logs.h"

void
cpfl_metadata_write16(struct cpfl_metadata *meta, int type, int offset, uint16_t data)
{
	rte_memcpy(&(meta->chunks[type].data[offset]), &data, sizeof(uint16_t));
}

uint16_t
cpfl_metadata_read16(struct cpfl_metadata *meta, int type, int offset)
{
	return *((uint16_t *)(&(meta->chunks[type].data[offset])));
}

bool
cpfl_metadata_write_port_id(struct cpfl_itf *itf)
{
	uint32_t dev_id;
	const int type = 0;
	const int offset = 5;

	dev_id = cpfl_get_port_id(itf);
	if (dev_id == CPFL_INVALID_HW_ID) {
		PMD_DRV_LOG(ERR, "fail to get hw ID\n");
		return false;
	}
	dev_id = dev_id << 3;
	cpfl_metadata_write16(&itf->adapter->meta, type, offset, dev_id);

	return true;
}
bool
cpfl_metadata_write_targetvsi(struct cpfl_itf *itf)
{
	uint32_t dev_id;
	const int type = 6;
	const int offset = 2;
	dev_id = cpfl_get_vsi_id(itf);
	if (dev_id == CPFL_INVALID_HW_ID) {
		PMD_DRV_LOG(ERR, "fail to get hw ID");
		return false;
	}
	dev_id = dev_id << 1;
	cpfl_metadata_write16(&itf->adapter->meta, type, offset, dev_id);
	return true;
}
bool
cpfl_metadata_write_sourcevsi(struct cpfl_itf *itf)
{
	uint32_t dev_id;
	const int type = 6;
	const int offset = 0;
	dev_id = cpfl_get_vsi_id(itf);
	if (dev_id == CPFL_INVALID_HW_ID) {
		PMD_DRV_LOG(ERR, "fail to get hw ID");
		return false;
	}
	cpfl_metadata_write16(&itf->adapter->meta, type, offset, dev_id);
	return true;
}

void
cpfl_metadata_init(struct cpfl_metadata *meta)
{
	int i;
	for (i = 0; i < CPFL_META_LENGTH; i++)
		meta->chunks[i].type = i;
}

bool cpfl_metadata_write_vsi(struct cpfl_itf *itf)
{
	uint32_t dev_id;
	const int type = 0;
	const int offset = 24;
	dev_id = cpfl_get_vsi_id(itf);
	if (dev_id == CPFL_INVALID_HW_ID) {
		PMD_DRV_LOG(ERR, "fail to get hw ID");
		return false;
	}
	cpfl_metadata_write16(&itf->adapter->meta, type, offset, dev_id);
	return true;
}

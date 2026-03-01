#include <rte_flow.h>
#include <rte_memcpy.h>

#include "cpfl_ethdev.h"

#ifndef _CPFL_FXP_METADATA_H_
#define _CPFL_FXP_METADATA_H_

#define CPFL_META_CHUNK_LENGTH	1024
#define CPFL_META_LENGTH	32	

struct cpfl_metadata_chunk {
	int type;
	uint8_t data[CPFL_META_CHUNK_LENGTH];
};


struct cpfl_metadata {
	int length;
	struct cpfl_metadata_chunk chunks[CPFL_META_LENGTH];
};

struct cpfl_itf;

void cpfl_metadata_init(struct cpfl_metadata *meta);
bool cpfl_metadata_write_port_id(struct cpfl_itf *itf);
bool cpfl_metadata_write_vsi(struct cpfl_itf *itf);
bool cpfl_metadata_write_targetvsi(struct cpfl_itf *itf);
bool cpfl_metadata_write_sourcevsi(struct cpfl_itf *itf);
void cpfl_metadata_write16(struct cpfl_metadata *meta, int type, int offset, uint16_t data);
uint16_t cpfl_metadata_read16(struct cpfl_metadata *meta, int type, int offset);
#endif

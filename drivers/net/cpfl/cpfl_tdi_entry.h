#ifndef _CPFL_TDI_ENTRY_H_
#define _CPFL_TDI_ENTRY_H_

#include <rte_tdi.h>

struct cpfl_tdi_entry {
	uint32_t cookie;
	struct rte_tdi_table_key *key;
	struct rte_tdi_action *action;
	enum rte_tdi_table_entry_op op;
};

#define CPFL_TDI_ENTRY_RING_SIZE 512
#define CPFL_TDI_ENTRY_BATCH_SIZE 128

struct cpfl_tdi_entry_ring {
	struct cpfl_tdi_entry entries[CPFL_TDI_ENTRY_RING_SIZE];
	uint32_t head;
	uint32_t tail;
	uint16_t count;
};

static inline void
cpfl_tdi_entry_ring_init(struct cpfl_tdi_entry_ring *ring)
{
	ring->head = 0;
	ring->tail = 0;
	ring->count = 0;
}

static inline bool
cpfl_tdi_entry_ring_is_full(struct cpfl_tdi_entry_ring *ring)
{
	return ring->count == CPFL_TDI_ENTRY_RING_SIZE;
}

static inline bool
cpfl_tdi_entry_ring_is_empty(struct cpfl_tdi_entry_ring *ring)
{
	return ring->head == ring->tail;
}

static inline bool
cpfl_tdi_entry_ring_enqueue(struct cpfl_tdi_entry_ring *ring,
			    uint32_t cookie,
			    struct rte_tdi_table_key *key,
			    struct rte_tdi_action *action,
			    enum rte_tdi_table_entry_op op)
{
	struct cpfl_tdi_entry *entry =
		&ring->entries[ring->head % CPFL_TDI_ENTRY_RING_SIZE];

	if (cpfl_tdi_entry_ring_is_full(ring))
		return false;

	entry->cookie = cookie;
	entry->key = key;
	entry->action = action;
	entry->op = op;

	ring->head++;
	ring->count++;

        return true;
}

static inline bool
cpfl_tdi_entry_ring_dequeue(struct cpfl_tdi_entry_ring *ring,
			    uint32_t *cookie,
			    struct rte_tdi_table_key **key,
			    struct rte_tdi_action **action,
			    enum rte_tdi_table_entry_op *op)
{
	struct cpfl_tdi_entry *entry =
		&ring->entries[ring->tail % CPFL_TDI_ENTRY_RING_SIZE];

	if (cpfl_tdi_entry_ring_is_empty(ring))
		return false;

	*cookie = entry->cookie;
	*key = entry->key;
	*action = entry->action;
	*op= entry->op;

	ring->tail++;
	ring->count--;

        return true;
}

static inline void
cpfl_tdi_entry_ring_uninit(struct cpfl_tdi_entry_ring *ring)
{
	uint32_t cookie;
	struct rte_tdi_table_key *key;
	struct rte_tdi_action *action;
	enum rte_tdi_table_entry_op op;

	while (!cpfl_tdi_entry_ring_is_empty(ring)) {

		cpfl_tdi_entry_ring_dequeue(ring,
					    &cookie,
					    &key,
					    &action,
					    &op);

		if (key != NULL)
			rte_free(key);
		if (action != NULL)
			rte_free(action);
	}
}

#endif

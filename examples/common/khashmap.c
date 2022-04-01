#include "khashmap.h"
#include <linux/jhash.h>
#include <stdio.h>
#include <stdlib.h>

/* Copied from the kernel */
/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | ((__typeof__(x))((y)-1)))+1)

static unsigned long roundup_pow_of_two(unsigned long n)
{
	for (int i = sizeof(size_t) * 8 - 1; i--; i >= 0) {
		if ((1UL << i) < n) {
			return 1UL << (i + 1);
		}
	}

	return 1;
}

int khashmap_init(struct khashmap *map, uint32_t key_size, uint32_t value_size,
		uint32_t max_entries)
{
	map->key_size = key_size;
	map->value_size = value_size;
	map->max_entries = max_entries;
	map->count = 0;

	map->n_buckets = roundup_pow_of_two(map->max_entries);

	map->elem_size = sizeof(struct khashmap_elem) + round_up(map->key_size, 8)
			+ round_up(map->value_size, 8);

	map->buckets = calloc(map->n_buckets, sizeof(struct khashmap_bucket));
	if (!map->buckets) {
		fprintf(stderr, "khashmap: error allocating buckets\n");
		return 1;
	}

	/*
	 * Should be set to a random value but it introduces additional variability
	 * in tests. eBPF maps use a random value.
	 */
	map->hashrnd = 0;

	for (int i = 0; i < map->n_buckets; i++) {
		INIT_HLIST_NULLS_HEAD(&map->buckets[i].head, i);
		pthread_spin_init(&map->buckets[i].lock, PTHREAD_PROCESS_PRIVATE);
	}

	map->elems = calloc(map->elem_size, map->max_entries);
	if (!map->elems) {
		fprintf(stderr, "khashmap: error allocating elements\n");
		return 1;
	}

	map->next_free = map->elems;

	return 0;
}

void khashmap_free(struct khashmap *map)
{
	free(map->elems);
	free(map->buckets);
	__builtin_memset(map, 0, sizeof(*map));
}

size_t khashmap_size(const struct khashmap *map)
{
	return map->count;
}

static inline struct khashmap_bucket *__select_bucket(struct khashmap *map,
		uint32_t hash)
{
	return &map->buckets[hash & (map->n_buckets - 1)];
}

static inline struct hlist_nulls_head *select_bucket(struct khashmap *map,
		uint32_t hash)
{
	return &__select_bucket(map, hash)->head;
}

/* this lookup function can only be called with bucket lock taken */
static struct khashmap_elem *lookup_elem_raw(struct hlist_nulls_head *head,
		uint32_t hash, void *key, uint32_t key_size)
{
	struct hlist_nulls_node *n;
	struct khashmap_elem *l;

	hlist_nulls_for_each_entry(l, n, head, hash_node)
		if (l->hash == hash && !__builtin_memcmp(&l->key, key, key_size))
			return l;

	return NULL;
}

/* can be called without bucket lock. it will repeat the loop in
 * the unlikely event when elements moved from one bucket into another
 * while link list is being walked (why should an element be moved to another
 * bucket?)
 */
static struct khashmap_elem *lookup_nulls_elem_raw(
		struct hlist_nulls_head *head, uint32_t hash, void *key,
		uint32_t key_size, uint32_t n_buckets)
{
	struct hlist_nulls_node *n;
	struct khashmap_elem *l;

again:
	hlist_nulls_for_each_entry(l, n, head, hash_node)
		if (l->hash == hash && !__builtin_memcmp(&l->key, key, key_size))
			return l;

	if (get_nulls_value(n) != (hash & (n_buckets - 1)))
		goto again;

	return NULL;
}

int khashmap_update_elem(struct khashmap *map, void *key, void *value,
		uint64_t map_flags)
{
	struct khashmap_elem *elem;
	struct hlist_nulls_head *head;
	struct khashmap_bucket *b;
	uint32_t hash;
	int ret;

	hash = jhash(key, map->key_size, map->hashrnd);

	b = __select_bucket(map, hash);
	head = &b->head;

	ret = pthread_spin_lock(&b->lock);
	if (ret) {
		fprintf(stderr, "khashmap: error acquiring bucket lock\n");
		return 1;
	}

	/*
	 * Here I handle things in a different way from kernel due to RCU:
	 * In the kernel they always allocate a new element, add it to the head of
	 * the list and delete the old one (if present).
	 * Here if the element is already present I just replace its data (not
	 * thread safe) 
	 */
	elem = lookup_elem_raw(&b->head, hash, key, map->key_size);
	if (!elem) {
		elem = map->next_free;
		map->next_free += map->elem_size;
		hlist_nulls_add_head(&elem->hash_node, head);
		map->count++;
	}

	elem->hash = hash;
	__builtin_memcpy(elem->key, key, map->key_size);
	__builtin_memcpy(elem->key + round_up(map->key_size, 8), value,
			map->value_size);

	pthread_spin_unlock(&b->lock);
	return 0;
}

void *khashmap_lookup_elem(struct khashmap *map, void *key)
{
	struct hlist_nulls_head *head;
	struct khashmap_elem *l;
	uint32_t hash, key_size;

	key_size = map->key_size;

	hash = jhash(key, key_size, map->hashrnd);

	head = select_bucket(map, hash);
	struct khashmap_bucket *b = __select_bucket(map, hash);

	l = lookup_nulls_elem_raw(head, hash, key, key_size, map->n_buckets);

	if (l)
		return l->key + round_up(map->key_size, 8);

	return NULL;
}

int khashmap_delete_elem(struct khashmap *map, void *key)
{
	struct hlist_nulls_head *head;
	struct khashmap_bucket *b;
	struct khashmap_elem *l;
	unsigned long flags;
	uint32_t hash, key_size;
	int ret;

	key_size = map->key_size;

	hash = jhash(key, key_size, map->hashrnd);
	b = __select_bucket(map, hash);
	head = &b->head;

	ret = pthread_spin_lock(&b->lock);
	if (ret) {
		fprintf(stderr, "khashmap: error acquiring bucket lock\n");
		return 1;
	}

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l) {
		hlist_nulls_del(&l->hash_node);
		map->count--;
		/* Should make the element available in a free list */
	} else {
		ret = 2;
	}

	pthread_spin_unlock(&b->lock);
	return ret;
}

int khashmap_clear(struct khashmap *map) {
	int ret;

	for (int i = 0; i < map->n_buckets; i++) {
		ret = pthread_spin_lock(&map->buckets[i].lock);
		if (ret) {
			fprintf(stderr, "khashmap: error acquiring bucket lock\n");
			return 1;
		}

		INIT_HLIST_NULLS_HEAD(&map->buckets[i].head, i);

		pthread_spin_unlock(&map->buckets[i].lock);
	}

	map->next_free = map->elems;

	return 0;
}
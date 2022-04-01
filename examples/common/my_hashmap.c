#include "my_hashmap.h"

#include <linux/jhash.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static size_t roundup_pow_of_two(size_t n)
{
	for (int i = sizeof(size_t) * 8 - 1; i--; i >= 0) {
		if ((1UL << i) < n) {
			return 1UL << (i + 1);
		}
	}

	return 1;
}

void my_hashmap__init(struct my_hashmap *map, size_t capacity, size_t key_size,
		size_t value_size)
{
	map->cap = roundup_pow_of_two(capacity);
	map->sz = 0;
	map->key_size = key_size;
	map->value_size = value_size;

	map->buckets = calloc(map->cap, sizeof(struct my_hashmap_entry *));
	if (!map->buckets) {
		fprintf(stderr, "hashamp: malloc error\n");
		exit(-1);
	}

	map->elems = calloc(map->cap,
			sizeof(struct my_hashmap_entry) + key_size + value_size);
	if (!map->elems) {
		fprintf(stderr, "hashamp: malloc error\n");
		exit(-1);
	}

	map->next_free = 0;
}

void my_hashmap__clear(struct my_hashmap *map)
{
	for (int i = 0; i < map->cap; i++) {
		map->buckets[i] = NULL;
	}
	map->sz = 0;
	map->next_free = 0;
}

void my_hashmap__free(struct my_hashmap *map)
{
	if (!map)
		return;

	my_hashmap__clear(map);
	free(map->buckets);
	free(map->elems);
	map->cap = 0;
}

size_t my_hashmap__size(const struct my_hashmap *map)
{
	return map->sz;
}

size_t my_hashmap__capacity(const struct my_hashmap *map)
{
	return map->cap;
}

static inline struct my_hashmap_entry **_select_bucket(
		const struct my_hashmap *map, uint32_t hash)
{
	return &map->buckets[hash & (map->cap - 1)];
}

static struct my_hashmap_entry *my_hashmap_find_entry(
		const struct my_hashmap *map, const void *key, uint32_t hash)
{
	struct my_hashmap_entry *cur;

	if (!map->buckets)
		return NULL;

	for (cur = *_select_bucket(map, hash); cur; cur = cur->next) {
		if (!__builtin_memcmp(key, cur->key, map->key_size)) {
			return cur;
		}
	}

	return NULL;
}

int my_hashmap__set(struct my_hashmap *map, const void *key, void *value)
{
	struct my_hashmap_entry *entry, **bucket;
	uint32_t h;
	int err;

	h = jhash(key, map->key_size, 0);
	entry = my_hashmap_find_entry(map, key, h);
	if (!entry) {
		entry = map->elems + (sizeof(struct my_hashmap_entry) + map->key_size
			+ map->value_size) * map->next_free;
		bucket = _select_bucket(map, h);
		entry->next = *bucket;
		*bucket = entry;
		map->next_free++;
		map->sz++;
	}

	__builtin_memcpy(entry->key, key, map->key_size);
	__builtin_memcpy(entry->key + map->key_size, value, map->value_size);

	return 0;
}

void *my_hashmap__find(const struct my_hashmap *map, const void *key)
{
	uint32_t h;

	h = jhash(key, map->key_size, 0);
	struct my_hashmap_entry *entry = my_hashmap_find_entry(map, key, h);
	if (entry) {
		return entry->key + map->key_size;
	} else {
		return NULL;
	}
}

bool my_hashmap__delete(struct my_hashmap *map, const void *key)
{
	// struct my_hashmap_entry **pprev, *entry;
	// size_t h;

	// h = hash_bits(map->hash_fn(key, map->ctx), map->cap_bits);
	// if (!my_hashmap_find_entry(map, key, h, &pprev, &entry))
	// 	return false;

	// if (old_key)
	// 	*old_key = entry->key;
	// if (old_value)
	// 	*old_value = entry->value;

	// my_hashmap_del_entry(pprev, entry);
	// free(entry);
	// map->sz--;

	return true;
}


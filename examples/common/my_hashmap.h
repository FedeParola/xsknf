#ifndef __MY_HASHMAP_H
#define __MY_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>

struct my_hashmap_entry {
	struct my_hashmap_entry *next;
	char key[];
};

struct my_hashmap {
	struct my_hashmap_entry **buckets;
	void *elems;
	size_t cap;
	size_t sz;
	size_t key_size;
	size_t value_size;
	size_t next_free;
};

void my_hashmap__init(struct my_hashmap *map, size_t capacity, size_t key_size,
		size_t value_size);
void my_hashmap__clear(struct my_hashmap *map);
void my_hashmap__free(struct my_hashmap *map);

size_t my_hashmap__size(const struct my_hashmap *map);
size_t my_hashmap__capacity(const struct my_hashmap *map);

int my_hashmap__set(struct my_hashmap *map, const void *key, void *value);
bool my_hashmap__delete(struct my_hashmap *map, const void *key);
void *my_hashmap__find(const struct my_hashmap *map, const void *key);

/*
 * my_hashmap__for_each_entry - iterate over all entries in hashmap
 * @map: hashmap to iterate
 * @cur: struct my_hashmap_entry * used as a loop cursor
 * @bkt: integer used as a bucket loop cursor
 */
#define my_hashmap__for_each_entry(map, cur, bkt)				    \
	for (bkt = 0; bkt < map->cap; bkt++)				    \
		for (cur = map->buckets[bkt]; cur; cur = cur->next)

/*
 * my_hashmap__for_each_entry_safe - iterate over all entries in hashmap, safe
 * against removals
 * @map: hashmap to iterate
 * @cur: struct my_hashmap_entry * used as a loop cursor
 * @tmp: struct my_hashmap_entry * used as a temporary next cursor storage
 * @bkt: integer used as a bucket loop cursor
 */
#define my_hashmap__for_each_entry_safe(map, cur, tmp, bkt)		    \
	for (bkt = 0; bkt < map->cap; bkt++)				    \
		for (cur = map->buckets[bkt];				    \
		     cur && ({tmp = cur->next; true; });		    \
		     cur = tmp)

#endif /* __MY_HASHMAP_H */

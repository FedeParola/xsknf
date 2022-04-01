#include <linux/list_nulls.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

struct khashmap_bucket {
	struct hlist_nulls_head head;
	pthread_spinlock_t lock;
};

struct khashmap {
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	struct khashmap_bucket *buckets;
	void *elems;
	void *next_free;	/* For the moment just use elements sequentially */
	atomic_int count;	/* number of elements in this hashtable */
	uint32_t n_buckets;	/* number of hash buckets */
	uint32_t elem_size;	/* size of each element in bytes */
	uint32_t hashrnd;
};

struct khashmap_elem {
	struct hlist_nulls_node hash_node;
	uint32_t hash;
	char key[] __attribute__((aligned(8)));
};

int khashmap_init(struct khashmap *map, uint32_t key_size, uint32_t value_size,
		uint32_t max_entries);
void khashmap_free(struct khashmap *map);

size_t khashmap_size(const struct khashmap *map);

int khashmap_update_elem(struct khashmap *map, void *key, void *value,
		uint64_t map_flags);
void *khashmap_lookup_elem(struct khashmap *map, void *key);
int khashmap_delete_elem(struct khashmap *map, void *key);
int khashmap_clear(struct khashmap *map);
#include <stdint.h>

/*
 * Xeon Gold 5120 cache hierarchy:
 * L1D:  32 KiB per core ->    512 64 B lines
 * L2:    1 MiB per core ->  16384 64 B lines
 * L3: 19.25 MiB unified -> 315392 64 B lines
 */
#define ARRAY_SIZE 10000000

struct cache_line {
	uint8_t data[64];
} __attribute__((aligned(64)));

struct global_data {
	unsigned test_size;
	int action;
};
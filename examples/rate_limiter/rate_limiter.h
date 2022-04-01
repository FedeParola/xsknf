#include <stdint.h>

enum {
  ACTION_PASS,
  ACTION_LIMIT,
  ACTION_DROP
};

struct bucket {
  int64_t tokens;
  uint64_t refill_rate;  // tokens/ms
  uint64_t capacity;
  uint64_t last_refill;  // Timestamp of the last time the bucket was refilled in ms
};

// struct contract {
//   int8_t action;
//   struct bucket bucket;
//   struct bpf_spin_lock lock;
// } /*__attribute__((packed))*/;

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} __attribute__((packed));

#define MAX_CONTRACTS 100000
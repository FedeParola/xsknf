#include <stdint.h>

#define MAX_ACL_SIZE 1000000
#define MAX_SERVICES 1024
#define MAX_BACKENDS MAX_SERVICES * 128
#define MAX_SESSIONS 2*1000000

struct service_id {
	uint32_t vaddr;
	uint16_t vport;
	uint8_t proto;
} __attribute__((packed));

struct service_info {
	unsigned backends;
} __attribute__((packed));

struct backend_id {
	struct service_id service;
	unsigned index;
} __attribute__((packed));

struct backend_info {
	uint32_t addr;
	uint16_t port;
	uint8_t mac_addr[6];
	uint16_t ifindex;
} __attribute__((packed));

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} __attribute__((packed));

enum direction {
	DIR_TO_CLIENT,
	DIR_TO_BACKEND
};

struct replace_info {
	enum direction dir;
	uint32_t addr;
	uint16_t port;
	uint8_t mac_addr[6];
	uint16_t ifindex;
} __attribute__((packed));

static inline uint16_t csum_fold(uint32_t csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

static inline uint32_t csum_unfold(uint16_t n)
{
	return (uint32_t)n;
}

static inline uint32_t csum_add(uint32_t csum, uint32_t addend)
{
	csum += addend;
	return csum + (csum < addend);
}
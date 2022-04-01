#include "hashmap_test.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

/* 
 * Including the common/statistcis.h header creates problems with other
 * inclusions
 */
struct xdp_cpu_stats {
	unsigned long rx_npkts;
	unsigned long tx_npkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct xdp_cpu_stats);
	__uint(max_entries, 1);
} xdp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, unsigned long);
	__uint(max_entries, 1);
} lookup_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, KEY_SIZE);
	__type(value, int);
	__uint(max_entries, HASHMAP_SIZE);
} kern_map SEC(".maps");

static uint8_t key[KEY_SIZE] = {0};

SEC("xdp") int hashmap(struct xdp_md *ctx)
{
	int zero = 0;
	int *val = NULL;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	unsigned long before = bpf_ktime_get_ns();

	val = bpf_map_lookup_elem(&kern_map, key);

	unsigned long elapsed = bpf_ktime_get_ns() - before;
	unsigned long *tot_lookup = bpf_map_lookup_elem(&lookup_time, &zero);
	if (!tot_lookup) {
		return XDP_ABORTED;
	}
	*tot_lookup += elapsed;

	if (!val) {
		bpf_printk("Value not found. Should not happen");
		return XDP_ABORTED;
	}

	*(unsigned *)key = (*(unsigned *)key + 1) % HASHMAP_SIZE;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";

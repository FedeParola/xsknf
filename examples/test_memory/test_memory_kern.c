#include "test_memory.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* 
 * Including the common/statistics.h header creates problems with other
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
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} xsks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cache_line);
	__uint(max_entries, ARRAY_SIZE);
} array SEC(".maps");

struct global_data global = {0};

SEC("xdp") int handle_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	/*
	 * Need to send the at least one packet to user space for busy polling to
	 * work in combined mode.
	 * In pure XDP the redirect will fail and the packet will be sent back.
	 */
	if (stats->rx_npkts == 1) {
		return bpf_redirect_map(&xsks, 0, global.action);
	}

	if (data + sizeof(uint64_t) > data_end) {
		return XDP_ABORTED;
	}

	unsigned idx = bpf_get_prandom_u32() % global.test_size;
	struct cache_line *val = bpf_map_lookup_elem(&array, &idx);
	if (!val) {
		return XDP_ABORTED;
	}

	*(uint8_t *)(data) = val->data[0];
	val->data[1] = *(uint8_t *)(data + 1);

	return global.action;
}

char _license[] SEC("license") = "GPL";
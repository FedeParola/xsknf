#include "macswap.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
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
		return bpf_redirect_map(&xsks, 0, XDP_TX);
		// return bpf_redirect_map(&xsks, 0, XDP_PASS);
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	swap_mac_addresses(data);
	if (global.double_macswap) {
		swap_mac_addresses_v2(data);
	}

	return global.action;
}

SEC("tc") int handle_tc(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return TC_ACT_SHOT;
	}
	stats->tx_npkts++;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_SHOT;
	}

	swap_mac_addresses(data);
	if (global.double_macswap) {
		swap_mac_addresses_v2(data);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

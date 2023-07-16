#include "checksummer.h"
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
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
	 * In pure XDP the redirect will fail and the packet will be dropped.
	 */
	if (stats->rx_npkts == 1) {
		return bpf_redirect_map(&xsks, 0, global.action);
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_TX;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (ip->protocol != IPPROTO_UDP) {
		return XDP_TX;
	}

	struct udphdr *udp = (void *)ip + (ip->ihl << 2);
	if ((void *)(udp + 1) > data_end) {
		return XDP_ABORTED;
	}

	uint32_t csum_buffer = 0;

	/* Compute pseudo-header checksum */
	csum_buffer += (uint16_t)ip->saddr;
	csum_buffer += (uint16_t)(ip->saddr >> 16);
	csum_buffer += (uint16_t)ip->daddr;
	csum_buffer += (uint16_t)(ip->daddr >> 16);
	csum_buffer += (uint16_t)ip->protocol << 8;
	csum_buffer += udp->len;

	/* Clean old checksum */
	udp->check = 0;

	for (int i = 0; i < MAX_CHECKSUM_ITERATIONS; i++) {
		if (i >= global.csum_iterations) {
			break;
		}

		/* Compute checksum on udp header + payload */
		uint16_t * volatile payload = (void *)udp;
		for (int j = 0; j < MAX_UDP_LENGTH; j += 2) {
			if ((void *)(payload + 1) > data_end) {
				break;
			}
			csum_buffer += *payload;
			payload++;
		}
		if ((void *)payload + 1 <= data_end) {
			/* In case payload is not 2 bytes aligned */
			csum_buffer += *(uint8_t *)payload;
		}
	}

	uint16_t csum = (uint16_t)csum_buffer + (uint16_t)(csum_buffer >> 16);
	csum = ~csum;

	udp->check = csum;

	// return global.action;
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";

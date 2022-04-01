#include "firewall.h"
#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} xsks SEC(".maps");

#ifdef MONITOR_LOOKUP_TIME
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, unsigned long);
	__uint(max_entries, 1);
} lookup_time SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} global_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct session_id);
	__type(value, int);
	__uint(max_entries, MAX_ACL_SIZE);
} acl SEC(".maps");

SEC("xdp") int firewall(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct session_id key = {0};
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
		return bpf_redirect_map(&xsks, 0, XDP_DROP);
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_TX;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return XDP_ABORTED;
	}

	void *next = (void *)iph + (iph->ihl << 2);

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > data_end) {
			return XDP_ABORTED;
		}

		key.sport = tcph->source;
		key.dport = tcph->dest;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > data_end) {
			return XDP_ABORTED;
		}

		key.sport = udph->source;
		key.dport = udph->dest;

		break;

	default:
		return XDP_TX;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;

    /* Only copy the hash */
    // uint32_t hash = jhash(&key, sizeof(struct session_id), 0);
    // bpf_map_update_elem(&global_hash, &zero, &hash, 0);
	// return XDP_DROP;

    /* Full hash table lookup */
#ifdef MONITOR_LOOKUP_TIME
	unsigned long before = bpf_ktime_get_ns();
#endif
	int *action = bpf_map_lookup_elem(&acl, &key);
#ifdef MONITOR_LOOKUP_TIME
    unsigned long elapsed = bpf_ktime_get_ns() - before;
	unsigned long *tot_lookup = bpf_map_lookup_elem(&lookup_time, &zero);
	if (!tot_lookup) {
		return XDP_ABORTED;
	}
	*tot_lookup += elapsed;
#endif

	if (action) {
		return *action;
	} else {
		return XDP_TX;
	}
}

char _license[] SEC("license") = "GPL";

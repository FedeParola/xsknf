#include "lbfw.h"
#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct session_id);
	__type(value, int);
	__uint(max_entries, MAX_ACL_SIZE);
} acl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct service_id);
	__type(value, struct service_info);
	__uint(max_entries, MAX_SERVICES);
} services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct backend_id);
	__type(value, struct backend_info);
	__uint(max_entries, MAX_BACKENDS);
} backends SEC(".maps");

/* 
 * A PERCPU_LRU map should be used here. Simple HASH is used to be coherent with
 * user space data plane
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct session_id);
	__type(value, struct replace_info);
	__uint(max_entries, MAX_SESSIONS);
} active_sessions SEC(".maps");

SEC("xdp1") int handle_xdp_hybrid(struct xdp_md *ctx)
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
	 * Need to send at least one packet to user space for busy polling to
	 * work in combined mode.
	 */
	if (stats->rx_npkts == 1) {
		return bpf_redirect_map(&xsks, 0, XDP_ABORTED);
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		/* Let the kernel handle it */
		return XDP_PASS;
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
		/* Let the kernel handle it */
		return XDP_PASS;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;
	int *action = bpf_map_lookup_elem(&acl, &key);

	if (action) {
		return *action;
	} else {
		/* Only TCP and UDP packets are sent to user space */
		return bpf_redirect_map(&xsks, 0, XDP_ABORTED);
	}
}

SEC("xdp2") int handle_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return XDP_ABORTED;
	}

	void *next = (void *)iph + (iph->ihl << 2);
	uint16_t *sport, *dport, *l4check;

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > data_end) {
			return XDP_ABORTED;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > data_end) {
			return XDP_ABORTED;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
		return XDP_PASS;
	}

	struct session_id sid = {0};
	sid.saddr = iph->saddr;
	sid.daddr = iph->daddr;
	sid.proto = iph->protocol;
	sid.sport = *sport;
	sid.dport = *dport;

	int *action = bpf_map_lookup_elem(&acl, &sid);
	if (action) {
		return *action;
	}

	/* Used for checksum update before forwarding */
	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

	unsigned output = -1;

	/* Look for known sessions */
	struct replace_info *rep = bpf_map_lookup_elem(&active_sessions, &sid);
	if (rep) {
		goto UPDATE;
	}

	bpf_printk("Session not found");

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo = bpf_map_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		/* Destination is not a virtual service */
		return XDP_PASS;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo = bpf_map_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		bpf_printk("ERROR: missing backend");
		return XDP_ABORTED;
	}

	/* Store the forward session */
	struct replace_info fwd_rep;
	fwd_rep.dir = DIR_TO_BACKEND;
	fwd_rep.addr = bkdinfo->addr;
	fwd_rep.port = bkdinfo->port;
	__builtin_memcpy(&fwd_rep.mac_addr, &bkdinfo->mac_addr,
			sizeof(fwd_rep.mac_addr));
	fwd_rep.ifindex = bkdinfo->ifindex;
	rep = &fwd_rep;
	if (bpf_map_update_elem(&active_sessions, &sid, &fwd_rep, 0)) {
		bpf_printk("ERROR: unable to add forward session to map");
		goto UPDATE;
	}

	/* Store the backward session */
	struct replace_info bwd_rep;
	bwd_rep.dir = DIR_TO_CLIENT;
	bwd_rep.addr = srvid.vaddr;
	bwd_rep.port = srvid.vport;
	__builtin_memcpy(&bwd_rep.mac_addr, &eth->h_source, sizeof(eth->h_source));
	bwd_rep.ifindex = ctx->ingress_ifindex;
	sid.daddr = sid.saddr;
	sid.dport = sid.sport;
	sid.saddr = bkdinfo->addr;
	sid.sport = bkdinfo->port;
	if (bpf_map_update_elem(&active_sessions, &sid, &bwd_rep, 0)) {
		bpf_printk("ERROR: unable to add backward session to map");
		goto UPDATE;
	}

UPDATE:;
	if (rep->dir == DIR_TO_BACKEND) {
		old_addr = iph->daddr;
		iph->daddr = rep->addr;
		old_port = *dport;
		*dport = rep->port;
	} else {
		old_addr = iph->saddr;
		iph->saddr = rep->addr;
		old_port = *sport;
		*sport = rep->port;
	}
	new_addr = rep->addr;
	new_port = rep->port;
	__builtin_memcpy(&eth->h_source, &eth->h_dest, sizeof(eth->h_source));
	__builtin_memcpy(&eth->h_dest, &rep->mac_addr, sizeof(eth->h_dest));
	output = rep->ifindex;

	/* Update ip checksum */
	uint32_t csum = ~csum_unfold(iph->check);
	csum = csum_add(csum, ~old_addr);
	csum = csum_add(csum, new_addr);
	iph->check = csum_fold(csum);

	/* Update l4 checksum */
	csum = ~csum_unfold(*l4check);
	csum = csum_add(csum, ~old_addr);
	csum = csum_add(csum, new_addr);
	csum = csum_add(csum, ~old_port);
	csum = csum_add(csum, new_port);
	*l4check = csum_fold(csum);

	if (output == ctx->ingress_ifindex) {
		return XDP_TX;
	} else {
		// return bpf_redirect(output, 0);
		/* Let kernel networking redirect the packet */
		return XDP_PASS;
	}
}

char _license[] SEC("license") = "GPL";

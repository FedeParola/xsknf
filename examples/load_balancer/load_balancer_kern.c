#include "load_balancer.h"
#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
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

struct global_data global = {0};

static inline int load_balancer(struct xdp_md *ctx)
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

	/* Used for checksum update before forwarding */
	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

	unsigned output = -1;

	/* Look for known sessions */
	struct replace_info *rep = bpf_map_lookup_elem(&active_sessions, &sid);
	if (rep) {
		goto UPDATE;
	}

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

SEC("xdp1") int standard_xdp(struct xdp_md *ctx) {
	return load_balancer(ctx);
}

SEC("xdp2") int hybrid_xdp(struct xdp_md *ctx) {
	if (ctx->rx_queue_index < global.passthrough_queues) {
	 	return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
	} else {
		return load_balancer(ctx);
	}
}

/*
 * The egress code should be tailored to only care of backward (backend to
 * client) sessions. The ingress code on the other hand must handle both
 * directions (assuming no Direct Server Return).
 * Here I'm keeping the same code for both direction to make it similar to the
 * userspace version.
 * 
 * In (a better) alternative the egress code should only perform DSR. In
 * addition DSR would allow to remove BACKWARD sessions tracking also in
 * ingress, since a backward packet will never enter the ingress direction of
 * the LB.
 */
SEC("tc") int handle_tc(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return TC_ACT_SHOT;
	}
	stats->rx_npkts++;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_SHOT;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return TC_ACT_SHOT;
	}

	void *next = (void *)iph + (iph->ihl << 2);
	uint16_t *sport, *dport, *l4check;

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > data_end) {
			return TC_ACT_SHOT;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > data_end) {
			return TC_ACT_SHOT;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
		return TC_ACT_OK;
	}

	struct session_id sid = {0};
	sid.saddr = iph->saddr;
	sid.daddr = iph->daddr;
	sid.proto = iph->protocol;
	sid.sport = *sport;
	sid.dport = *dport;

	/* Used for checksum update before forwarding */
	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

	/* Look for known sessions */
	struct replace_info *rep = bpf_map_lookup_elem(&active_sessions, &sid);
	if (rep) {
		goto UPDATE;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo = bpf_map_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		/* Destination is not a virtual service */
		return TC_ACT_OK;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo = bpf_map_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		bpf_printk("ERROR: missing backend");
		return TC_ACT_SHOT;
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

	/* Update ip checksum */
	uint32_t csum = ~csum_unfold(iph->check);
	csum = csum_add(csum, ~old_addr);
	csum = csum_add(csum, new_addr);
	iph->check = csum_fold(csum);

	/* Update l4 checksum, need to use helpers to account for offloading */
	if (bpf_l4_csum_replace(ctx, (void *)l4check - data, old_addr, new_addr,
			4 | BPF_F_PSEUDO_HDR)) {
		bpf_printk("ERROR: bpf_l4_csum_replace() on addr");
		return TC_ACT_SHOT;
	}
	if (bpf_l4_csum_replace(ctx, (void *)l4check - data, old_port, new_port,
			2)) {
		bpf_printk("ERROR: bpf_l4_csum_replace() on port");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

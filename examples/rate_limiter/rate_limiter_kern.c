#include "rate_limiter.h"


#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct contract {
  int8_t action;
  int8_t local;
  struct bucket bucket;
  struct bpf_spin_lock lock;
};

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
	__type(value, struct contract);
	__uint(max_entries, MAX_CONTRACTS);
} contracts SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, int);
// 	__type(value, uint64_t);
// 	__uint(max_entries, 1);
// } clock SEC(".maps");


static inline int limit_rate(struct xdp_md *ctx, struct session_id *session, struct contract *contract) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	//int zero = 0;
	const char fmt_str[] = "Available tokens: %d\n";

	uint64_t now = bpf_ktime_get_ns();    /* Francesco Cappa: TO BE CHANGED */
	now /= 1000000;

	// uint64_t *clock_p = bpf_map_lookup_elem(&clock, &zero);
	// if (!clock_p) {
	// 	bpf_printk("Error in retrieving clock.\n");
	// 	return XDP_DROP;
	// }

  	// uint64_t now = *clock_p;  // In ms

	//Refill tokens
	if (now > contract->bucket.last_refill){
		bpf_spin_lock(&contract->lock);
		if (now > contract->bucket.last_refill) {
			uint64_t new_tokens =
				(now - contract->bucket.last_refill) * contract->bucket.refill_rate;
			if (contract->bucket.tokens + new_tokens > contract->bucket.capacity) {
				new_tokens = contract->bucket.capacity - contract->bucket.tokens;
			}
		__sync_fetch_and_add(&contract->bucket.tokens, new_tokens);
		contract->bucket.last_refill = now;
		}
		bpf_spin_unlock(&contract->lock);
		bpf_trace_printk(fmt_str, sizeof(fmt_str), contract->bucket.tokens);
	}

	// // Consume tokens
	uint64_t needed_tokens = (data_end - data) * 8;
	uint8_t retval;
	// const char fmt_str2[] = "Needed tokens: %d\n";
	// bpf_trace_printk(fmt_str2, sizeof(fmt_str2), needed_tokens);

	if (contract->bucket.tokens >= needed_tokens) {
		__sync_fetch_and_add(&contract->bucket.tokens, -needed_tokens);
		retval = XDP_TX;
	} else {
		retval = XDP_DROP;
	}
	return retval;
}


SEC("xdp") int rate_limiter(struct xdp_md *ctx) {
  // bpf_printk("Entering XDP program..\n");
  int index = ctx->rx_queue_index;
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
	// if (stats->rx_npkts %2 == 0){
    // 	bpf_printk("Redirecting to AF_XDP...\n");
	// 	return bpf_redirect_map(&xsks, 0, XDP_DROP);
	// }
	

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

	// default:
	// 	key.sport = 0;
	// 	key.dport = 0;
    // break;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;

	struct contract *contract = bpf_map_lookup_elem(&contracts, &key);

	if (!contract) {
		bpf_printk("No value retrieved.\n");
		return XDP_DROP;
	}

// /* What should be redirected to AF_XDP: remote traffic */
  if(contract->local == 0){
	  bpf_printk("Redirecting to AF_XDP..\n");
	  return bpf_redirect_map(&xsks, index, XDP_DROP);
  }


  //Apply action
  switch (contract->action) {
    case ACTION_PASS:
      return XDP_PASS;
      break;

    case ACTION_LIMIT:
      return limit_rate(ctx, &key, contract);
      break;

    case ACTION_DROP:
      return XDP_DROP;
      break;
  }
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
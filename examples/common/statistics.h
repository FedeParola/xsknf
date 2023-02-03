#include "utils.h"
#include <xsknf.h>

struct xdp_cpu_stats {
	unsigned long rx_npkts;
	unsigned long tx_npkts;
};

void init_stats();
void dump_stats(struct xsknf_config config, struct bpf_object *obj,
		int extra_stats, int app_stats);

/*
 * Write cumulative stats to file on SIGUSR1 reception.
 * It would be cleaner to just read the rx_packets counter of the driver through
 * ethtool, however it doen't report the right number of packets for the AF_XDP
 * standard test case (many packets are correctly received by the driver but
 * don't make it to the user space due tu full UMEM ring).
 */
void print_stats(struct xsknf_config *config, struct bpf_object *obj);
#ifndef __XSKNF_XSKNF_H
#define __XSKNF_XSKNF_H

#include <stdint.h>
#include <bpf/libbpf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XSKNF_MAX_INTERFACES 32
#define XSKNF_MAX_WORKERS 32

/* Application working modes */
#define MODE_AF_XDP 0x1
#define MODE_XDP 0x2
#define MODE_COMBINED MODE_AF_XDP | MODE_XDP

/* 
 * Custom packet processing function defined by the user.
 * Returns the ifindex toward which redirect the packet or -1 to drop it
 */
int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex);

struct xsknf_config {
	char *interfaces[XSKNF_MAX_INTERFACES];
	uint32_t bind_flags[XSKNF_MAX_INTERFACES];
	unsigned num_interfaces;
	unsigned workers;
    unsigned working_mode;
    uint32_t xdp_flags;
    uint32_t batch_size;
    int poll;
    int unaligned_chunks;
    int xsk_frame_size;
    int busy_poll;
	char xdp_filename[256];
};

struct xsknf_socket_stats {
    /* Ring level stats */
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;

    /* Application level stats */
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long tx_wakeup_sendtos;
    unsigned long tx_trigger_sendtos;
	unsigned long opt_polls;
};


int xsknf_parse_args(int argc, char **argv, struct xsknf_config *config);
int xsknf_init(struct xsknf_config *config, struct bpf_object **bpf_obj);
int xsknf_cleanup();
int xsknf_start_workers();
int xsknf_stop_workers();
int xsknf_get_socket_stats(unsigned worker_idx, unsigned iface_idx,
		struct xsknf_socket_stats *stats);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* __XSKNF_XSKNF_H */
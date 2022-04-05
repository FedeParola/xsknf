#include "checksummer.h"
#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <xsknf.h>

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static int opt_csum_iterations = 1;

struct bpf_object *obj;
struct xsknf_config config;

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return 0;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > pkt_end) {
		return -1;
	}

	if (ip->protocol != IPPROTO_UDP) {
		return 0;
	}

	struct udphdr *udp = (void *)ip + (ip->ihl << 2);
	if ((void *)(udp + 1) > pkt_end) {
		return -1;
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

	/* eBPF-compatible code */
	// for (int i = 0; i < MAX_CHECKSUM_ITERATIONS; i++) {
	// 	if (i >= opt_csum_iterations) {
	// 		break;
	// 	}

	// 	/* Compute checksum on udp header + payload */
	// 	uint16_t *payload = (void *)udp;
	// 	for (int j = 0; j < MAX_UDP_LENGTH; j += 2) {
	// 		if ((void *)(payload + 1) > pkt_end) {
	// 			break;
	// 		}
	// 		csum_buffer += *payload;
	// 		payload++;
	// 	}
	// 	if ((void *)payload + 1 <= pkt_end) {
	// 		/* In case payload is not 2 bytes aligned */
	// 		csum_buffer += *(uint8_t *)payload;
	// 	}
	// }

	/* Sane code */
	for (int i = 0; i < opt_csum_iterations; i++) {
		/* Compute checksum on udp header + payload */
		uint16_t *payload = (void *)udp;
		while ((void *)(payload + 1) <= pkt_end) {
			csum_buffer += *payload;
			payload++;
		}
		if ((void *)payload + 1 <= pkt_end) {
			/* In case payload is not 2 bytes aligned */
			csum_buffer += *(uint8_t *)payload;
		}
	}

	uint16_t csum = (uint16_t)csum_buffer + (uint16_t)(csum_buffer >> 16);
	csum = ~csum;

    udp->check = csum;

    return 0;
}

static struct option long_options[] = {
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
	{"csum-iterations", no_argument, 0, 'i'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [XSKNF_OPTIONS] -- [APP_OPTIONS]\n"
		"  App options:\n"
		"  -q, --quiet		Do not display any stats.\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"  -i, --csum-iterations	Number of times to recompute the checksum.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "qxai:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			opt_quiet = 1;
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'a':
			opt_app_stats = 1;
			break;
		case 'i':
			opt_csum_iterations = atoi(optarg);
			break;
		default:
			usage(basename(app_path));
		}
	}
}

static void int_exit(int sig)
{
	benchmark_done = 1;
}

static void int_usr(int sig)
{
	print_stats(&config, obj);
}

int main(int argc, char **argv)
{
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	signal(SIGUSR1, int_usr);

	xsknf_parse_args(argc, argv, &config);
	xsknf_init(&config, &obj);

	parse_command_line(argc, argv, argv[0]);

	setlocale(LC_ALL, "");

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *map;
		int zero = 0, iter_map, ret;

		map = bpf_object__find_map_by_name(obj, "checksum_iterations");
		iter_map = bpf_map__fd(map);
		if (iter_map < 0) {
			fprintf(stderr, "ERROR: no checksum_iterations map found: %s\n",
				strerror(iter_map));
			exit(EXIT_FAILURE);
		}

		ret = bpf_map_update_elem(iter_map, &zero, &opt_csum_iterations, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem 0\n");
			exit(EXIT_FAILURE);
		}
	}

	xsknf_start_workers();

	init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);
		}
	}

	xsknf_cleanup();

	return 0;
}
#include "macswap.h"
#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <xsknf.h>

enum action {
	ACTION_REDIRECT,
	ACTION_DROP,
	ACTION_PASS
};

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static enum action opt_action = ACTION_REDIRECT;
static int opt_double_macswap = 0;

struct bpf_object *obj;
struct xsknf_config config;

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	swap_mac_addresses(pkt);
	if (opt_double_macswap) {
		swap_mac_addresses_v2(pkt);
	}

	return opt_action == ACTION_DROP ?
			-1 : (ingress_ifindex + 1) % config.num_interfaces;
}

static struct option long_options[] = {
	{"action", required_argument, 0, 'c'},
	{"double-macswap", no_argument, 0, 'd'},
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [XSKNF_OPTIONS] -- [APP_OPTIONS]\n"
		"  App options:\n"
		"  -c, --action		REDIRECT, DROP packets or PASS to network stack (default REDIRECT).\n"
		"  -d, --double-macswap	Perform a double macswap on the packet.\n"
		"  -q, --quiet		Do not display any stats.\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "c:dqxa", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			if (!strcmp(optarg, "REDIRECT")) {
				opt_action = ACTION_REDIRECT;
			} else if (!strcmp(optarg, "DROP")) {
				opt_action = ACTION_DROP;
			} else if (!strcmp(optarg, "PASS")) {
				opt_action = ACTION_PASS;
			} else {
				fprintf(stderr, "ERROR: invalid action %s\n", optarg);
				usage(basename(app_path));
			}
			break;
		case 'd':
			opt_double_macswap = 1;
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'a':
			opt_app_stats = 1;
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
	strcpy(config.tc_progname, "handle_tc");
	xsknf_init(&config, &obj);

	parse_command_line(argc, argv, argv[0]);

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *global_map = bpf_object__find_map_by_name(obj,
				"macswap_.bss");
		if (!global_map) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data\n");
			exit(EXIT_FAILURE);
		}

		int global_fd = bpf_map__fd(global_map), zero = 0;
		if (global_fd < 0) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data fd\n");
			exit(EXIT_FAILURE);
		}

		struct global_data global;
		switch (opt_action) {
		case ACTION_REDIRECT:
			global.action = XDP_TX;
			break;
		case ACTION_DROP:
			global.action = XDP_DROP;
			break;
		case ACTION_PASS:
			global.action = XDP_PASS;
			break;
		}
		global.double_macswap = opt_double_macswap;
		if (bpf_map_update_elem(global_fd, &zero, &global, 0)) {
			fprintf(stderr, "ERROR: unable to initialize eBPF global data\n");
			exit(EXIT_FAILURE);
		}

	}

	setlocale(LC_ALL, "");

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
#include "test_memory.h"
#include "../common/statistics.h"
#include <bpf/bpf.h>
#include <getopt.h>
#include <libgen.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <xsknf.h>

enum action {
	ACTION_REDIRECT,
	ACTION_DROP
};

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static enum action opt_action = ACTION_REDIRECT;

struct bpf_object *obj;
struct xsknf_config config;

unsigned opt_test_size = 1;
struct cache_line array[ARRAY_SIZE];

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	if (pkt + sizeof(uint64_t) > pkt_end) {
		return XDP_ABORTED;
	}

	unsigned idx = rand() % opt_test_size;
	*(uint8_t *)pkt = array[idx].data[0];
	array[idx].data[1] = *(uint8_t *)(pkt + 1);

	return opt_action == ACTION_REDIRECT ?
			(ingress_ifindex + 1) % config.num_interfaces : -1;
}

static struct option long_options[] = {
	{"action", required_argument, 0, 'c'},
	{"test-size", required_argument, 0, 's'},
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
		"  -c, --action		REDIRECT or DROP packets (default REDIRECT).\n"
		"  -s, --test-size	Number of consecutive array entries to access.\n"
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
		c = getopt_long(argc, argv, "qxas:c:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			if (!strcmp(optarg, "REDIRECT")) {
				opt_action = ACTION_REDIRECT;
			} else if (!strcmp(optarg, "DROP")) {
				opt_action = ACTION_DROP;
			} else {
				fprintf(stderr, "ERROR: invalid action %s\n", optarg);
				usage(basename(app_path));
			}
			break;
		case 's':
			opt_test_size = atoi(optarg);
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
	xsknf_init(&config, &obj);

	parse_command_line(argc, argv, argv[0]);

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *global_map = bpf_object__find_map_by_name(obj,
				"test_mem.bss");
		if (!global_map) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data\n");
			exit(EXIT_FAILURE);
		}

		int global_fd = bpf_map__fd(global_map), zero = 0;
		if (global_fd < 0) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data fd\n");
			exit(EXIT_FAILURE);
		}

		struct global_data global = {
			.test_size = opt_test_size,
			.action = opt_action == ACTION_REDIRECT ? XDP_TX : XDP_DROP
		};
		if (bpf_map_update_elem(global_fd, &zero, &global, 0)) {
			fprintf(stderr, "ERROR: unable to initialize eBPF global data\n");
			exit(EXIT_FAILURE);
		}

	}

	/* Need to init the array, otherwise the compiler removes it */
	for (int i = 0; i < ARRAY_SIZE; i++) {
		*(uint64_t *)array[i].data = i;
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
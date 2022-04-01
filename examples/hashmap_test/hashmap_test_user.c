#include "hashmap_test.h"
#include "../common/statistics.h"
#include "../common/my_hashmap.h"

#include <bpf/bpf.h>
// #include <bpf/hashmap.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/jhash.h>
#include <locale.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <xsknf.h>

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static volatile unsigned long lookup_time = 0;

static struct bpf_object *obj;
static struct xsknf_config config;

struct test_entry {
	uint8_t key[KEY_SIZE];
	int value;
};

static struct test_entry test_entries[HASHMAP_SIZE];
static struct my_hashmap user_map;

static size_t hash_fn(const void *key, void *ctx)
{
	return (size_t)jhash(key, (uint32_t)(long)ctx, 0);
}

static bool equal_fn(const void *key1, const void *key2, void *ctx)
{
	return !memcmp(key1, key2, (uint32_t)(long)ctx);
}

static void init_hashmap()
{
	int i;

	/* 
	 * Keys go from 0 to HASHMAP_SIZE-1.
	 * I store them randomly shuffled so that in the data plane I can access
	 * them in sequence (no random functions) and have a random memory access
	 * pattern anyway
	 */
	unsigned keys[HASHMAP_SIZE];
	for (i = 0; i < HASHMAP_SIZE; i++) {
		keys[i] = i;
	}

	for (i = 0; i < HASHMAP_SIZE - 1; i++) {
        int j = i + rand() / (RAND_MAX / (HASHMAP_SIZE - i) + 1);
        unsigned t = keys[j];
        keys[j] = keys[i];
        keys[i] = t;
	}

	for (i = 0; i < HASHMAP_SIZE; i++) {
		*(unsigned *)test_entries[i].key = keys[i];
		test_entries[i].value = keys[i] + 1;
	}

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *map;
		int kern_map, ret;

		map = bpf_object__find_map_by_name(obj, "kern_map");
		kern_map = bpf_map__fd(map);
		if (kern_map < 0) {
			fprintf(stderr, "ERROR: no kern_map map found: %s\n",
				strerror(kern_map));
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < HASHMAP_SIZE; i++) {
			ret = bpf_map_update_elem(kern_map, test_entries[i].key,
					&test_entries[i].value, 0);
			if (ret) {
				fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
				exit(EXIT_FAILURE);
			}
		}
	}

	if (config.working_mode & MODE_AF_XDP) {
		// hashmap__init(&user_map, hash_fn, equal_fn, (void *)KEY_SIZE);
		my_hashmap__init(&user_map, HASHMAP_SIZE, KEY_SIZE, sizeof(int));

		for (int i = 0; i < HASHMAP_SIZE; i++) {
			my_hashmap__set(&user_map, test_entries[i].key,
					&test_entries[i].value);
		}

		printf("Hashmap capacity: %lu, size: %lu\n",
				my_hashmap__capacity(&user_map), my_hashmap__size(&user_map));
	}

	return;
}

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	static uint8_t key[KEY_SIZE] = {0};
	int *value = NULL;

	struct timespec tp_before, tp_after;
	clock_gettime(CLOCK_MONOTONIC, &tp_before);

	value = my_hashmap__find(&user_map, key);

	clock_gettime(CLOCK_MONOTONIC, &tp_after);
	lookup_time += tp_after.tv_nsec + tp_after.tv_sec * 1000000000
			- (tp_before.tv_nsec + tp_before.tv_sec * 1000000000);

	if (!value) {
		return -1;
	}

	*(unsigned *)key = (*(unsigned *)key + 1) % HASHMAP_SIZE;

	return 0;
}

static struct option long_options[] = {
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
		c = getopt_long(argc, argv, "qxa", long_options, &option_index);
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
		default:
			usage(basename(app_path));
		}
	}
}

static void int_exit(int sig)
{
	benchmark_done = 1;
}

int main(int argc, char **argv)
{
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	xsknf_init(argc, argv, &config, &obj);

	parse_command_line(argc, argv, argv[0]);

	setlocale(LC_ALL, "");

	init_hashmap();

	xsknf_start_workers();

	init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);
		}

		unsigned long rx_npkts = 0;

		if (config.working_mode == MODE_AF_XDP) {
			struct xsknf_socket_stats stats;

			for (int i = 0; i < config.workers; i++) {
				for (int j = 0; j < config.num_interfaces; j++) {
					xsknf_get_socket_stats(i, j, &stats);
					rx_npkts += stats.rx_npkts;
				}
			}

		} else {
			unsigned int nr_cpus = libbpf_num_possible_cpus();
			struct xdp_cpu_stats values[nr_cpus];
			int i, map_fd, zero = 0;
			struct bpf_map *map;

			map = bpf_object__find_map_by_name(obj, "xdp_stats");
			map_fd = bpf_map__fd(map);
			if (map_fd < 0) {
				fprintf(stderr, "ERROR: no xdp_stats map found: %s\n",
					strerror(map_fd));
					exit(EXIT_FAILURE);
			}

			if ((bpf_map_lookup_elem(map_fd, &zero, values)) != 0) {
				fprintf(stderr,
						"ERROR: bpf_map_lookup_elem failed key:0x%X\n",
						zero);
				exit(EXIT_FAILURE);
			}

			for (int i = 0; i < nr_cpus; i++) {
				rx_npkts += values[i].rx_npkts;
			}

			map = bpf_object__find_map_by_name(obj, "lookup_time");
			map_fd = bpf_map__fd(map);
			if (map_fd < 0) {
				fprintf(stderr, "ERROR: no lookup_time map found: %s\n",
					strerror(map_fd));
					exit(EXIT_FAILURE);
			}

			unsigned long xdp_lookup_time;
			if ((bpf_map_lookup_elem(map_fd, &zero,
					&xdp_lookup_time)) != 0) {
				fprintf(stderr,
						"ERR: bpf_map_lookup_elem failed key:0x%X\n", zero);
				exit(EXIT_FAILURE);
			}

			lookup_time = xdp_lookup_time;
		}

		printf("Average lookup time %lu\n",
					rx_npkts == 0 ? 0 : lookup_time / rx_npkts);
	}

	xsknf_cleanup();

	return 0;
}
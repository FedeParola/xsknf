#include "firewall.h"
#include "../common/khashmap.h"
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
#ifdef MONITOR_LOOKUP_TIME
#include <time.h>
#endif

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
#ifdef MONITOR_LOOKUP_TIME
volatile unsigned long lookup_time = 0;
#endif

struct bpf_object *obj;
struct xsknf_config config;

#define IP_STRLEN 16
#define ACTION_STRLEN 5
#define PROTO_STRLEN 4

struct khashmap acl;

static void init_acl(const char *acl_path)
{
	char saddr[IP_STRLEN], daddr[IP_STRLEN], action[ACTION_STRLEN],
			proto[PROTO_STRLEN];
	unsigned sport, dport;
	FILE *f = fopen(acl_path, "r");
	struct session_id sid;
	struct in_addr addr;
	unsigned nrules;
	int i, ret, act, acl_map = -1;

	printf("Loading the ACL...\n");

	if (f == NULL) {
		exit_with_error(errno);
	}

	/* The first line shall contain the number of rules */
	if(fscanf(f, "%u\n", &nrules) != 1) {
		exit_with_error(-1);
	}

	khashmap_init(&acl, sizeof(struct session_id), sizeof(int), MAX_ACL_SIZE);
	if (config.working_mode & MODE_XDP) {
		struct bpf_map *map = bpf_object__find_map_by_name(obj, "acl");
		acl_map = bpf_map__fd(map);
		if (acl_map < 0) {
			fprintf(stderr, "ERROR: no acl map found: %s\n", strerror(acl_map));
			exit(EXIT_FAILURE);
		}
	}

	i = 0;
	while (fscanf(f, " %s %s %u %u %s %s ", saddr, daddr, &sport, &dport,
			proto, action) != EOF) {
		inet_aton(saddr, &addr);
		sid.saddr = addr.s_addr;

		inet_aton(daddr, &addr);
		sid.daddr = addr.s_addr;

		sid.sport = htons(sport);
		sid.dport = htons(dport);

		if (strcmp(proto, "TCP") == 0) {
			sid.proto = IPPROTO_TCP;
		} else if (strcmp(proto, "UDP") == 0) {
			sid.proto = IPPROTO_UDP;
		} else {
			fprintf(stderr, "Unexpected L4 protocol: %s\n", proto);
			exit(EXIT_FAILURE);
		}

		if (strcmp(action, "DROP") == 0) {
			act = -1;
		} else {
			act = atoi(action);
		}

		if (config.working_mode == MODE_AF_XDP) {
			if (khashmap_update_elem(&acl, &sid, &act, 0)) {
				fprintf(stderr, "Error adding elemetn to hash map\n");
				exit(EXIT_FAILURE);
			}
		} else {
			act = XDP_DROP;
			if (bpf_map_update_elem(acl_map, &sid, &act, 0)) {
				fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
				exit(EXIT_FAILURE);
			}
		}

		i++;
	}

	if (i != nrules) {
		fprintf(stderr, "Incorrent input file: mismatch in rules number\n");
		exit(-1);
	}

	printf("Added %d rules\n", nrules);

	return;
}

static void clear_acl()
{
	if (config.working_mode == MODE_AF_XDP) {
		khashmap_free(&acl);
	}
}

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;
	struct session_id key;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return 0;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > pkt_end) {
		return -1;
	}

	void *next = (void *)iph + (iph->ihl << 2);

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > pkt_end) {
			return -1;
		}

		key.sport = tcph->source;
		key.dport = tcph->dest;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > pkt_end) {
			return -1;
		}

		key.sport = udph->source;
		key.dport = udph->dest;

		break;

	default:
		return 0;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;

	int *action = NULL;
#ifdef MONITOR_LOOKUP_TIME
    struct timespec tp_before, tp_after;
    clock_gettime(CLOCK_MONOTONIC, &tp_before);
#endif
	action = khashmap_lookup_elem(&acl, &key);
#ifdef MONITOR_LOOKUP_TIME
    clock_gettime(CLOCK_MONOTONIC, &tp_after);
    lookup_time += tp_after.tv_nsec + tp_after.tv_sec * 1000000000
			- (tp_before.tv_nsec + tp_before.tv_sec * 1000000000);
#endif

	if (action) {
		return *action;
	} else {
		return 0;
	}
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

	init_acl("./acl.txt");

	xsknf_start_workers();

	init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);

#ifdef MONITOR_LOOKUP_TIME
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
#endif  /* MONITOR_LOOKUP_TIME */
		}
	}

	xsknf_cleanup();

	clear_acl();

	return 0;
}
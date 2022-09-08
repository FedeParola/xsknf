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

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static char *opt_acl_path = "./acl.txt";

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
				fprintf(stderr, "Error adding element to hash map\n");
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

	int *action = khashmap_lookup_elem(&acl, &key);
	if (action) {
		return *action;
	} else {
		return 0;
	}
}

static struct option long_options[] = {
	{"acl-path", required_argument, 0, 'f'},
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
		"  -f, --acl-path	ACL file path (default ./acl.txt)\n"
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
		c = getopt_long(argc, argv, "qxaf:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			opt_acl_path = optarg;
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

	setlocale(LC_ALL, "");

	init_acl(opt_acl_path);

	xsknf_start_workers();

	init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);
		}
	}

	xsknf_cleanup();

	clear_acl();

	return 0;
}
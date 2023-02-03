#include "load_balancer.h"
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
static char *opt_services_path = NULL;
static unsigned opt_passthrough = 0;
static int opt_spread_flows = 0;
static unsigned opt_local = 0;

struct bpf_object *obj;
struct xsknf_config config;

#define IP_STRLEN 16
#define PROTO_STRLEN 4
#define IFNAME_STRLEN 256

#define MEMCACHED_PORT 11211

struct service_entry {
	struct service_id key;
	struct service_info value;
};

struct backend_entry {
	struct backend_id key;
	struct backend_info value;
};

struct khashmap services;
struct khashmap backends;
/* 
 * This map should be handled in a LRU way, clearing older sessions when the map
 * is full. This is not done for simplicity.
 * In the eBPF LRU_HASH_MAP every bucket is handled as a LRU queue, this is
 * possible since it has a static size
 */
struct khashmap active_sessions;

static int ifname_to_app_idx(char *ifname)
{
	for (int i = 0; i < config.num_interfaces; i++) {
		if (strcmp(ifname, config.interfaces[i]) == 0) {
			return i;
		}
	}

	return -1;
}

static int ifname_to_kern_idx(char *ifname)
{
	return if_nametoindex(ifname);
}

void store_session(struct session_id *sid, struct replace_info *rep, int mapfd)
{
	if (config.working_mode & MODE_XDP) {
		uint16_t old_ifindex = rep->ifindex;
		if (rep->ifindex < config.num_interfaces) {
			rep->ifindex = ifname_to_kern_idx(config.interfaces[rep->ifindex]);
		}
		if (bpf_map_update_elem(mapfd, sid, rep, 0)) {
			fprintf(stderr, "ERROR: unable to add session to bpf map\n");
			exit(EXIT_FAILURE);
		}
		rep->ifindex = old_ifindex;
	} 
	
	if ((config.working_mode & MODE_AF_XDP)) {
		if (khashmap_update_elem(&active_sessions, sid, rep, 0)) {
			fprintf(stderr, "ERROR: unable to add session to map\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void load_services(const char *services_path)
{
	char srv_addr[IP_STRLEN], bkd_addr[IP_STRLEN], proto[PROTO_STRLEN],
			ifname[IFNAME_STRLEN];
	unsigned srv_port, bkd_port;
	uint8_t mac_addr[6];
	FILE *f;
	struct service_info *srv_info;
	struct backend_entry *bkd_entry;
	struct in_addr addr;
	unsigned nservices, nbackends, service_first_free = 0;
	int i, ret, ifindex, *srvindex;
	struct service_entry *service_entries;
	struct backend_entry *backend_entries;
	struct khashmap srv_to_index;

	if (config.working_mode & MODE_AF_XDP) {
		khashmap_init(&active_sessions, sizeof(struct session_id),
				sizeof(struct replace_info), MAX_SESSIONS);
		khashmap_init(&services, sizeof(struct service_id),
				sizeof(struct service_info), MAX_SERVICES);
		khashmap_init(&backends, sizeof(struct backend_id),
				sizeof(struct backend_info), MAX_BACKENDS);
	}

	if (services_path) {
		printf("Loading services...\n");

		f = fopen(services_path, "r");
		if (f == NULL) {
			exit_with_error(errno);
		}

		/* The first line shall contain the number of services and backends */
		if(fscanf(f, "%u %u\n", &nservices, &nbackends) != 2) {
			fprintf(stderr, "ERROR: wrong services file format\n");
			exit_with_error(-1);
		}

		printf("Reading %u services and %u backends\n", nservices, nbackends);

		service_entries = malloc(sizeof(struct service_entry) * nservices);
		backend_entries = malloc(sizeof(struct backend_entry) * nbackends);
		khashmap_init(&srv_to_index, sizeof(struct service_id), sizeof(int),
				nservices);

		i = 0;
		while ((ret = fscanf(f, " %s %u %s %s %u"
				" %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx %s", srv_addr, &srv_port,
				proto, bkd_addr, &bkd_port, &mac_addr[0], &mac_addr[1],
				&mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5], ifname))
				!= EOF) {		
			if (ret < 12) {
				fprintf(stderr, "ERROR: wrong services file format\n");
				exit(EXIT_FAILURE);
			}

			bkd_entry = &backend_entries[i];
			inet_aton(srv_addr, &addr);
			bkd_entry->key.service.vaddr = addr.s_addr;
			bkd_entry->key.service.vport = htons(srv_port);
			if (strcmp(proto, "TCP") == 0) {
				bkd_entry->key.service.proto = IPPROTO_TCP;
			} else if (strcmp(proto, "UDP") == 0) {
				bkd_entry->key.service.proto = IPPROTO_UDP;
			} else {
				fprintf(stderr, "ERROR: Unexpected L4 protocol: %s\n", proto);
				exit(-1);
			}

			inet_aton(bkd_addr, &addr);
			bkd_entry->value.addr = addr.s_addr;
			bkd_entry->value.port = htons(bkd_port);
			__builtin_memcpy(&bkd_entry->value.mac_addr, mac_addr,
					sizeof(mac_addr));

			if (!strcmp(ifname, "local")) {
				/* This works only in tests */
				ifindex = 1;
			} else {
				ifname_to_app_idx(ifname);
			}
			if (ifindex == -1) {
				fprintf(stderr, "ERROR: Parsed unknown interface %s\n", ifname);
				exit(EXIT_FAILURE);
			}
			bkd_entry->value.ifindex = ifindex;

			srvindex = khashmap_lookup_elem(&srv_to_index,
					&bkd_entry->key.service);
			if (!srvindex) {
				struct service_entry *srv_entry =
						&service_entries[service_first_free];
				srv_entry->key = bkd_entry->key.service;
				srv_entry->value.backends = 0;
				srv_info = &srv_entry->value;

				if (khashmap_update_elem(&srv_to_index, &srv_entry->key,
						&service_first_free, 0)) {
					fprintf(stderr,
							"ERROR: unable to add service index to hash map\n");
					exit(EXIT_FAILURE);
				}

				service_first_free++;
			} else {
				srv_info = &service_entries[*srvindex].value;
			}

			bkd_entry->key.index = srv_info->backends;
			srv_info->backends++;

			i++;
		}

		if (i != nbackends || service_first_free != nservices) {
			fprintf(stderr,
					"ERROR: incorrent input file: mismatch in items number\n");
			exit(-1);
		}

		if (config.working_mode & MODE_AF_XDP) {
			for (int i = 0; i < nservices; i++) {
				if (khashmap_update_elem(&services, &service_entries[i].key,
						&service_entries[i].value, 0)) {
					fprintf(stderr,
							"ERROR: unable to add service to hash map\n");
					exit(EXIT_FAILURE);
				}
			}

			for (int i = 0; i < nbackends; i++) {
				if (khashmap_update_elem(&backends, &backend_entries[i].key,
						&backend_entries[i].value, 0)) {
					fprintf(stderr,
							"ERROR: unable to add backend to hash map\n");
					exit(EXIT_FAILURE);
				}
			}
		}

		if (config.working_mode & MODE_XDP) {
			struct bpf_map *map;
			int i, mapfd;

			map = bpf_object__find_map_by_name(obj, "services");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no services map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
			for (int i = 0; i < nservices; i++) {
				if (bpf_map_update_elem(mapfd, &service_entries[i].key,
						&service_entries[i].value, 0)) {
					fprintf(stderr,
							"ERROR: unable to add service to bpf map %d\n", i);
					exit(EXIT_FAILURE);
				}
			}

			map = bpf_object__find_map_by_name(obj, "backends");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no backends map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
			for (int i = 0; i < nbackends; i++) {
				if (bpf_map_update_elem(mapfd, &backend_entries[i].key,
						&backend_entries[i].value, 0)) {
					fprintf(stderr,
							"ERROR: unable to add backend to bpf map %d\n", i);
					exit(EXIT_FAILURE);
				}
			}
		}

		printf("Added %u services and %u backends\n", nservices, nbackends);

		free(service_entries);
		free(backend_entries);
		khashmap_free(&srv_to_index);
	}

	if (opt_passthrough > 0) {
		struct bpf_map *map;
		int mapfd = 0;
		struct session_id sid;

		if (config.working_mode & MODE_XDP) {
			map = bpf_object__find_map_by_name(obj, "active_sessions");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no active_sessions map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
		}

		for (int i = 0; i < opt_passthrough; i++) {
			sid.saddr = 0x0a | htonl((uint32_t)i);  /* 10.i */
			if (opt_spread_flows) {
				/* 172.(i % workers) */
				sid.daddr = 0xac | htonl((uint32_t)(i % config.workers + 1));
			} else {
				sid.daddr = 0x010000ac; /* 172.0.0.1 */
			}
			sid.sport = htons(5000);
			sid.dport = htons(80);
			sid.proto = IPPROTO_UDP;

			/* Store the forward session */
			struct replace_info rep;
			rep.dir = DIR_TO_BACKEND;
			rep.addr = 0x020000c0; // 192.0.0.2
			rep.port = htons(80);
			uint8_t mac[6] = {0x0a, 0x00, 0x00, 0x00, 0x00, 0x01};
			__builtin_memcpy(&rep.mac_addr, mac, sizeof(rep.mac_addr));
			rep.ifindex = 0;
			store_session(&sid, &rep, mapfd);
			
			/* Store the backward session */
			sid.daddr = sid.saddr;
			sid.saddr = rep.addr;
			sid.dport = sid.sport;
			sid.sport = rep.port;
			rep.dir = DIR_TO_CLIENT;
			rep.addr = 0x010000ac; // 172.0.0.1
			rep.port = htons(80);
			__builtin_memcpy(&rep.mac_addr, mac, sizeof(rep.mac_addr));
			rep.ifindex = 0;
			store_session(&sid, &rep, mapfd);
		}

		printf("Added %d pass-through sessions\n", opt_passthrough);
	}

	if (opt_local > 0) {
		struct bpf_map *map;
		int mapfd = 0;
		struct session_id sid;

		if (config.working_mode & MODE_XDP) {
			map = bpf_object__find_map_by_name(obj, "active_sessions");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no active_sessions map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
		}

		for (int i = 0; i < opt_local; i++) {
			sid.saddr = 0x020000ac;  /* 172.0.0.2 */
			sid.daddr = 0x010000ac;  /* 172.0.0.1 */
			sid.sport = htons(5000 + i);
			sid.dport = htons(MEMCACHED_PORT);
			sid.proto = IPPROTO_TCP;

			/* Store the forward session */
			struct replace_info rep;
			rep.dir = DIR_TO_BACKEND;
			rep.addr = 0x0100a8c0;  /* 192.168.0.1 */
			rep.port = htons(MEMCACHED_PORT);
			uint8_t mac[6] = {0x0a, 0x00, 0x00, 0x00, 0x00, 0x00};
			__builtin_memcpy(&rep.mac_addr, mac, sizeof(rep.mac_addr));
			rep.ifindex = 1;
			store_session(&sid, &rep, mapfd);
			
			/* Store the backward session */
			sid.daddr = sid.saddr;
			sid.saddr = rep.addr;
			sid.dport = sid.sport;
			sid.sport = rep.port;
			rep.dir = DIR_TO_CLIENT;
			rep.addr = 0x010000ac;  /* 172.0.0.1 */
			rep.port = htons(MEMCACHED_PORT);
			mac[5] = 0x02;  /* 0a:00:00:00:00:02 */
			__builtin_memcpy(&rep.mac_addr, mac, sizeof(rep.mac_addr));
			rep.ifindex = 0;
			store_session(&sid, &rep, mapfd);
		}

		printf("Added %d local sessions\n", opt_local);
	}

	return;
}

static void clear_maps()
{
	if (config.working_mode == MODE_AF_XDP) {
		khashmap_clear(&active_sessions);
		khashmap_clear(&backends);
		khashmap_clear(&services);
	}
}

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return config.num_interfaces > 1 ?
				(ingress_ifindex + 1) % config.num_interfaces : -1;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > pkt_end) {
		return -1;
	}

	void *next = (void *)iph + (iph->ihl << 2);
	uint16_t *sport, *dport, *l4check;

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > pkt_end) {
			return -1;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > pkt_end) {
			return -1;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
		return config.num_interfaces > 1 ?
				(ingress_ifindex + 1) % config.num_interfaces : -1;
	}

	struct session_id sid = {0};
	sid.saddr = iph->saddr;
	sid.daddr = iph->daddr;
	sid.proto = iph->protocol;
	sid.sport = *sport;
	sid.dport = *dport;

	/* Used for checksum update before forward */
	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

	unsigned output = -1;

	/* Look for known sessions */
	struct replace_info *rep = khashmap_lookup_elem(&active_sessions, &sid);
	if (rep) {
		goto UPDATE;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo = khashmap_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		/* Destination is not a virtual service */
		return config.num_interfaces > 1 ?
				(ingress_ifindex + 1) % config.num_interfaces : -1;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo = khashmap_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		fprintf(stderr, "ERROR: missing backend\n");
		return -1;
	}

	/* Store the forward session */
	struct replace_info fwd_rep;
	fwd_rep.dir = DIR_TO_BACKEND;
	fwd_rep.addr = bkdinfo->addr;
	fwd_rep.port = bkdinfo->port;
	__builtin_memcpy(fwd_rep.mac_addr, &bkdinfo->mac_addr,
			sizeof(fwd_rep.mac_addr));
	fwd_rep.ifindex = bkdinfo->ifindex;
	rep = &fwd_rep;
	if (khashmap_update_elem(&active_sessions, &sid, &fwd_rep, 0)) {
		fprintf(stderr, "ERROR: unable to add forward session to map\n");
		goto UPDATE;
	}

	/* Store the backward session */
	struct replace_info bwd_rep;
	bwd_rep.dir = DIR_TO_CLIENT;
	bwd_rep.addr = srvid.vaddr;
	bwd_rep.port = srvid.vport;
	__builtin_memcpy(&bwd_rep.mac_addr, &eth->h_source, sizeof(eth->h_source));
	bwd_rep.ifindex = ingress_ifindex;
	sid.daddr = sid.saddr;
	sid.dport = sid.sport;
	sid.saddr = bkdinfo->addr;
	sid.sport = bkdinfo->port;
	if (khashmap_update_elem(&active_sessions, &sid, &bwd_rep, 0)) {
		fprintf(stderr, "ERROR: unable to add backward session to map\n");
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

	return output;
}

static struct option long_options[] = {
	{"services-path", required_argument, 0, 'p'},
	{"passthrough", required_argument, 0, 'p'},
	{"spread-flows", no_argument, 0, 's'},
	{"local", required_argument, 0, 'l'},
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
		"  -f, --services-path	Path of the services file.\n"
		"  -p, --passthrough=n	Populate the table of active sessions with n sessions for the pass-through test.\n"
		"  -s, --spread-flows	Spread pass-through flows on a different virtual service for every worker.\n"
		"  -l, --local=n		Populate the table of active sessions with n sessions for the local test.\n"
		"  -q, --quiet		Do not display any stats.\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c, ret;
	unsigned int extended_mac[6];

	for (;;) {
		c = getopt_long(argc, argv, "f:p:sl:qxa", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			opt_services_path = optarg;
			break;
		case 'p':
			opt_passthrough = atoi(optarg);
			break;
		case 's':
			opt_spread_flows = 1;
			break;
		case 'l':
			opt_local = atoi(optarg);
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

	if (opt_spread_flows && opt_passthrough == 0) {
		fprintf(stderr, "ERROR: the spread-flows option can only be set after "
				"configuring a number of pass-through flows\n");
		usage(basename(app_path));
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
	parse_command_line(argc, argv, argv[0]);

	strcpy(config.tc_progname, "handle_tc");
	strcpy(config.xdp_progname,
			opt_spread_flows ? "hybrid_xdp" : "standard_xdp");

	xsknf_init(&config, &obj);

	load_services(opt_services_path);

	if (config.working_mode & MODE_XDP && opt_spread_flows) {
		struct bpf_map *global_map = bpf_object__find_map_by_name(obj,
				"load_bal.bss");
		if (!global_map) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data\n");
			exit(EXIT_FAILURE);
		}

		int global_fd = bpf_map__fd(global_map), zero = 0;
		if (global_fd < 0) {
			fprintf(stderr, "ERROR: unable to retrieve eBPF global data fd\n");
			exit(EXIT_FAILURE);
		}

		struct global_data global = {.passthrough_queues = config.workers};
		if (bpf_map_update_elem(global_fd, &zero, &global, 0)) {
			fprintf(stderr, "ERROR: unable to initialize eBPF global data\n");
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

	clear_maps();

	return 0;
}
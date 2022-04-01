#include "rate_limiter.h"

#include "../common/khashmap.h"
#include "../common/my_hashmap.h"
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
#include <time.h>
#include <pthread.h>
#include <sys/sysinfo.h>

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
#ifdef MONITOR_LOOKUP_TIME
volatile unsigned long lookup_time = 0;
#endif

struct bpf_object *obj;
struct xsknf_config config;

pthread_t clock_thread;


#define IP_STRLEN 16
#define PROTO_STRLEN 4

struct contract {
  int8_t action;
  int8_t local;
  struct bucket bucket;
  pthread_spinlock_t lock;
};

struct contract_entry{
	struct session_id key;
	struct contract contract;	// Policy to be applied to the session key
};

struct khashmap contracts;
//struct khashmap clock_hashmap;
struct contract_entry *entries;

// void *update_clock(void * args){
// 	struct bpf_map *map;
// 	int zero = 0, clock_map, ret; 
// 	uint64_t msec = 0;
// 	khashmap_init(&clock_hashmap, sizeof(int), sizeof(uint64_t), 1);

// 	while(true){
// 		msec++;
// 		if(config.working_mode & MODE_XDP){
// 			map = bpf_object__find_map_by_name(obj, "clock");
// 			clock_map = bpf_map__fd(map);

// 			if (clock_map < 0) {
// 				fprintf(stderr, "ERROR: no clock map found: %s\n",
// 					strerror(clock_map));
// 				exit(EXIT_FAILURE);
// 			}
// 			ret = bpf_map_update_elem(clock_map, &zero, &msec, BPF_ANY);

// 			if (ret) {
// 				fprintf(stderr, "ERROR: bpf_map_update_elem.\n");
// 				exit(EXIT_FAILURE);
// 			}
// 		}
// 		if(config.working_mode & AF_XDP){
// 				if((khashmap_update_elem(&clock_hashmap, &zero,
// 					&msec, 0))){
// 						fprintf(stderr,"ERROR: AF_XDP update time.\n");
// 						exit(EXIT_FAILURE);
// 					}
// 		}
// 		printf("Updating clock (%lu) ...\n", msec);
// 		usleep(1000);
// 	}
// 	exit(0);
// }

static inline unsigned limit_rate(void *pkt,unsigned len, struct contract *contract){
	void *pkt_end = pkt + len;
	//int zero = 0;
	// clock_t now = clock();
	// now/= 1000;
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	uint64_t now = time.tv_sec * 1000 + time.tv_nsec/1000000;
	// uint64_t *clock = (unsigned long *)khashmap_lookup_elem(&clock_hashmap, &zero);
	// uint64_t now = *clock;

	// struct timespec t;
	// clock_gettime(CLOCK_MONOTONIC, &t);
	// uint64_t now = t.tv_nsec;

	if (now > contract->bucket.last_refill){
		// printf("Refilling..\n");
		//pthread_spin_lock(&contract->lock);
		if (now > contract->bucket.last_refill) {
			uint64_t new_tokens =
				(now - contract->bucket.last_refill) * contract->bucket.refill_rate;

			if (contract->bucket.tokens + new_tokens > contract->bucket.capacity) {
				new_tokens = contract->bucket.capacity - contract->bucket.tokens;
			}

		__sync_fetch_and_add(&contract->bucket.tokens, new_tokens);
		contract->bucket.last_refill = now;
		// printf("Last refill: %lu\n", contract->bucket.last_refill);
		//pthread_spin_unlock(&contract->lock);
	}
  }
  
  // Consume tokens
  uint64_t needed_tokens = (pkt_end - pkt) * 8;
  int8_t retval;

  if (contract->bucket.tokens >= needed_tokens) {
    __sync_fetch_and_add(&contract->bucket.tokens, -needed_tokens);
    retval = 0;
  } else {
	 // printf("Not enough tokens..\n");
    retval = -1;
  }
  return retval;
}

int xsknf_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{

	void *pkt_end = pkt + len;
	struct session_id key;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return 0;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > pkt_end) {
		return 0;
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
	// case IPPROTO_ICMP:
	// 	key.sport = 0;
	// 	key.dport = 0;
	// 	break;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;

// #ifdef MONITOR_LOOKUP_TIME
//     struct timespec tp_before, tp_after;
//     clock_gettime(CLOCK_MONOTONIC, &tp_before);
// #endif
	struct contract *contract = khashmap_lookup_elem(&contracts, &key);
	// action = my_hashmap__find(&acl, &key);
// #ifdef MONITOR_LOOKUP_TIME
//     clock_gettime(CLOCK_MONOTONIC, &tp_after);
//     lookup_time += tp_after.tv_nsec + tp_after.tv_sec * 1000000000
// 			- (tp_before.tv_nsec + tp_before.tv_sec * 1000000000);
// #endif
if (!contract) {
	return -1;
  }
//   if(contract->local == 1){
// 	  return -1;
//   }
  // Apply action
  switch (contract->action) {
    case ACTION_PASS:
      return 0;
      break;

    case ACTION_LIMIT:
    	return limit_rate(pkt, len, contract);
      break;

    case ACTION_DROP:
      return -1;
      break;
  }
  return 0;
}

static void init_contracts(const char *conctracts_path)
{
	char saddr[IP_STRLEN], daddr[IP_STRLEN], proto[PROTO_STRLEN];
	unsigned sport, dport;
	unsigned action, local;
	uint64_t refill_rate, capacity;
	FILE *f = fopen(conctracts_path, "r");
	struct in_addr addr;
	struct contract_entry *entry;
	unsigned nrules;
	int i, ret;

	printf("Loading the contracts...\n");
	if (f == NULL) {
		exit_with_error(errno);
	}

	/* The first line shall contain the number of rules */
	if(fscanf(f, "%u", &nrules) != 1) {
		exit_with_error(-1);
	}

	entries = (struct contract_entry *)malloc(nrules * sizeof(struct contract_entry));

	i = 0;
	while(fscanf(f, "%s %s %u %u %s %u %u %lu %lu",
	 	saddr, daddr, &sport, &dport, proto, &action, &local, &refill_rate, &capacity) != EOF){
		entry = &entries[i];

		inet_aton(saddr, &addr);
		entry->key.saddr = addr.s_addr;

		inet_aton(daddr, &addr);
		entry->key.daddr = addr.s_addr;

		entry->key.sport = htons(sport);
		entry->key.dport = htons(dport);
	


		if (strcmp(proto, "TCP") == 0) {
			entry->key.proto = IPPROTO_TCP;
		} else if (strcmp(proto, "UDP") == 0) {
			entry->key.proto = IPPROTO_UDP;
		}else if (strcmp(proto, "ICMP") == 0) {
			entry->key.proto = IPPROTO_ICMP;
		}
		else {
			fprintf(stderr, "Unexpected L4 protocol: %s\n", proto);
			exit(-1);
		}

		/* initialize contract attributes associated to the session key */
		entry->contract.action = action;
		entry->contract.local = local;
		entry->contract.bucket.tokens = 0;
		entry->contract.bucket.last_refill = 0;
		entry->contract.bucket.refill_rate = refill_rate;
		entry->contract.bucket.capacity = capacity;
		pthread_spin_init(&entry->contract.lock, 0);

		i++;

		if (config.working_mode & MODE_XDP) {
			struct bpf_map *map;
			int i, contracts_map;

			map = bpf_object__find_map_by_name(obj, "contracts");
			contracts_map = bpf_map__fd(map);
			if (contracts_map < 0) {
				fprintf(stderr, "ERROR: no contracts map found: %s\n",
					strerror(contracts_map));
				exit(EXIT_FAILURE);
			}
			ret = bpf_map_update_elem(contracts_map, &entry->key, &entry->contract, BPF_ANY);
			if (ret) {
				fprintf(stderr, "ERROR: bpf_map_update_elem.\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	if (i != nrules) {
		fprintf(stderr, "Incorrent input file: mismatch in rules number\n");
		exit(-1);
	}
	

	if (config.working_mode & MODE_AF_XDP) {
		khashmap_init(&contracts, sizeof(struct session_id), sizeof(struct contract), MAX_CONTRACTS);
		// my_hashmap__init(&acl, nrules, sizeof(struct session_id), sizeof(int));
		for(int i = 0; i < nrules; i++){
			if(khashmap_update_elem(&contracts, &entries[i].key,
					&entries[i].contract, 0)){
				fprintf(stderr, "Error adding elemetn to hash map\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	printf("Contract loaded..\n");
    return;
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

	xsknf_init(argc, argv, &config, &obj);

	parse_command_line(argc, argv, argv[0]);

	setlocale(LC_ALL, "");

	init_contracts("./contracts");

	printf("Clock thread launched..\n");

	xsknf_start_workers();

	init_stats();

	//pthread_create(&clock_thread, NULL, update_clock, NULL);


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

	return 0;
}

#include "statistics.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#define NSTATS 13

struct socket_stats_ps {
	/* Ring level stats */
	double rx_npkts;
	double tx_npkts;
	double rx_dropped_npkts;
	double rx_invalid_npkts;
	double tx_invalid_npkts;
	double rx_full_npkts;
	double rx_fill_empty_npkts;
	double tx_empty_npkts;

	/* Application level stats */
	double rx_empty_polls;
	double fill_fail_polls;
	double tx_wakeup_sendtos;
	double tx_trigger_sendtos;
	double opt_polls;
};

static unsigned long start_time;
static unsigned long prev_time;
struct xsknf_socket_stats
		old_socket_stats[XSKNF_MAX_WORKERS][XSKNF_MAX_WORKERS];
struct xdp_cpu_stats old_xdp_stats[XSKNF_MAX_WORKERS];
unsigned long old_total_xdp = 0;

static void compute_stats_per_second(struct xsknf_socket_stats *current,
		struct xsknf_socket_stats *prev, long dt,
		struct socket_stats_ps *stats_ps)
{
	long *curr_arr = (long *)current, *prev_arr = (long *)prev;
	double *stats_ps_arr = (double *)stats_ps;

	for (int i = 0; i < NSTATS; i++) {
		stats_ps_arr[i] = (curr_arr[i] - prev_arr[i]) * 1000000000. / dt;
	}
}

static void acc_stats(struct xsknf_socket_stats *acc,
		struct xsknf_socket_stats *stats)
{
	unsigned long *acc_arr = (unsigned long*)acc,
			*stats_arr = (unsigned long*)stats;

	for (int i = 0; i < NSTATS; i++) {
		acc_arr[i] += stats_arr[i];
	}
}

static void acc_stats_per_second(struct socket_stats_ps *acc,
		struct socket_stats_ps *stats)
{
	double *acc_arr = (double *)acc, *stats_arr = (double *)stats;

	for (int i = 0; i < NSTATS; i++) {
		acc_arr[i] += stats_arr[i];
	}
}

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void print_socket_stats(struct xsknf_socket_stats *stats,
		struct socket_stats_ps *stats_ps, unsigned long dt,
		int extra_stats, int app_stats)
{
	char *fmt = "%-18s %'-14.0f %'-14lu\n";

	printf("%-14s %-14s %-14.2f\n", "pps", "pkts", dt / 1000000000.);
	printf(fmt, "rx", stats_ps->rx_npkts, stats->rx_npkts);
	printf(fmt, "tx", stats_ps->tx_npkts, stats->tx_npkts);

	if (extra_stats) {
		printf(fmt, "rx dropped", stats_ps->rx_dropped_npkts,
				stats->rx_dropped_npkts);
		printf(fmt, "rx invalid", stats_ps->rx_invalid_npkts,
				stats->rx_invalid_npkts);
		printf(fmt, "tx invalid", stats_ps->tx_invalid_npkts,
				stats->tx_invalid_npkts);
		printf(fmt, "rx queue full", stats_ps->rx_full_npkts,
				stats->rx_full_npkts);
		printf(fmt, "fill ring empty", stats_ps->rx_fill_empty_npkts,
				stats->rx_fill_empty_npkts);
		printf(fmt, "tx ring empty", stats_ps->tx_empty_npkts,
				stats->tx_empty_npkts);
	}

	if (app_stats) {
		printf("%-18s %-14s %-14s\n", "", "calls/s", "count");
		printf(fmt, "rx empty polls", stats_ps->rx_empty_polls,
				stats->rx_empty_polls);
		printf(fmt, "fill fail polls", stats_ps->fill_fail_polls,
				stats->fill_fail_polls);
		printf(fmt, "tx wakeup sendtos", stats_ps->tx_wakeup_sendtos,
				stats->tx_wakeup_sendtos);
		printf(fmt, "tx trigger sendtos", stats_ps->tx_trigger_sendtos,
				stats->tx_trigger_sendtos);
		printf(fmt, "opt polls", stats_ps->opt_polls,
				stats->opt_polls);
	}
}

void init_stats()
{
	start_time = get_nsecs();
	prev_time = start_time;
}

void dump_stats(struct xsknf_config config, struct bpf_object *obj,
		int extra_stats, int app_stats)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	struct xsknf_socket_stats stats, total = {0};
	struct socket_stats_ps stats_ps, total_ps = {0};
	char buff[256];

	prev_time = now;

	if (config.working_mode & MODE_AF_XDP) {
		for (int i = 0; i < config.workers; i++) {
			for (int j = 0; j < config.num_interfaces; j++) {
				xsknf_get_socket_stats(i, j, &stats);
				compute_stats_per_second(&stats, &old_socket_stats[i][j],
						dt, &stats_ps);

				snprintf(buff, 256, " %s@wrk%d", config.interfaces[j], i);
				printf("\n%-19s", buff);

				print_socket_stats(&stats, &stats_ps, dt, extra_stats,
						app_stats);

				memcpy(&old_socket_stats[i][j], &stats,
						sizeof(struct xsknf_socket_stats));

				acc_stats(&total, &stats);
				acc_stats_per_second(&total_ps, &stats_ps);
			}
		}

		printf("\n%-19s", " TOTAL");
		print_socket_stats(&total, &total_ps, dt, extra_stats, app_stats);
	}

	if (config.working_mode & MODE_XDP) {
		unsigned int nr_cpus = libbpf_num_possible_cpus();
		unsigned long total_xdp = 0;
		double total_xdp_pps = 0;
		struct xdp_cpu_stats values[nr_cpus];
		uint64_t lookup_time;
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
					"ERR: bpf_map_lookup_elem failed key:0x%X\n", zero);
			exit(EXIT_FAILURE);
		}

		/* Record and sum values from each CPU */
		for (int i = 0; i < nr_cpus; i++) {
			if (values[i].rx_npkts - old_xdp_stats[i].rx_npkts > 0
					|| values[i].tx_npkts - old_xdp_stats[i].tx_npkts > 0) {
				double rx_pps, tx_pps;

				rx_pps = (values[i].rx_npkts - old_xdp_stats[i].rx_npkts) *
						1000000000. / dt;
				total_xdp_pps += rx_pps;
				tx_pps = (values[i].tx_npkts - old_xdp_stats[i].tx_npkts) *
						1000000000. / dt;
				total_xdp += values[i].rx_npkts;

				snprintf(buff, 256, "\n XDP cpu%d", i);
				printf("%-18s %-14s %-14s %-14.2f\n", buff, "pps", "pkts",
						dt / 1000000000.);
				char *fmt = "%-18s %'-14.0f %'-14lu\n";
				printf(fmt, "rx", rx_pps, values[i].rx_npkts);
				printf(fmt, "tx", tx_pps, values[i].tx_npkts);

				old_xdp_stats[i] = values[i];
			}
		}

		printf("\n%-18s %-14s %-14s %-14.2f\n", " TOTAL XDP", "pps", "pkts",
				dt / 1000000000.);
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		printf(fmt, "rx", total_xdp_pps,
				total_xdp > 0 ? total_xdp : old_total_xdp);
		printf(fmt, "tx", 0.0, 0);

		if (total_xdp > 0) {
			old_total_xdp = total_xdp;
		}
	}
}

void print_stats(struct xsknf_config *config, struct bpf_object *obj)
{
	unsigned long total_rx = 0;
	FILE *statsf = fopen("./stats.txt", "w");
	if (!statsf)
		exit_with_error(errno);

	if (config->working_mode == MODE_AF_XDP) {
		struct xsknf_socket_stats stats;

		for (int i = 0; i < config->workers; i++) {
			for (int j = 0; j < config->num_interfaces; j++) {
				xsknf_get_socket_stats(i, j, &stats);
				total_rx += stats.rx_npkts;
			}
		}

	} else if (config->working_mode & MODE_XDP) {
		unsigned int nr_cpus = libbpf_num_possible_cpus();
		struct xdp_cpu_stats values[nr_cpus];
		int i, xdp_stats, zero = 0;
		struct bpf_map *map;

		map = bpf_object__find_map_by_name(obj, "xdp_stats");
		xdp_stats = bpf_map__fd(map);
		if (xdp_stats < 0) {
			fprintf(stderr, "ERROR: no xdp_stats map found: %s\n",
				strerror(xdp_stats));
				exit(EXIT_FAILURE);
		}

		if ((bpf_map_lookup_elem(xdp_stats, &zero, values)) != 0) {
			fprintf(stderr,
					"ERR: bpf_map_lookup_elem failed key:0x%X\n", zero);
			exit(EXIT_FAILURE);
		}

		for (int i = 0; i < nr_cpus; i++) {
			total_rx += values[i].rx_npkts;
		}
	}

	fprintf(statsf, "%lu\n", total_rx);

	fclose(statsf);
}
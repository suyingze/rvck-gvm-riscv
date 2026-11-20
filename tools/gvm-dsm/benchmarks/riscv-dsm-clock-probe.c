// SPDX-License-Identifier: GPL-2.0
/*
 * Probe clock consistency while one task moves across GiantVM vCPUs.
 *
 * This deliberately samples the RISC-V time CSR, the vDSO clock path, and
 * the clock_gettime syscall path.  A genuine cross-host virtual-time issue
 * should be visible in more than just one userspace API.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CPU_COUNT_TEST 4
#define CLOCK_COUNT_TEST 4

struct sample {
	uint64_t rdtime;
	uint64_t clock_ns[CLOCK_COUNT_TEST];
	int actual_cpu;
};

static const char *const clock_names[CLOCK_COUNT_TEST] = {
	"realtime_vdso",
	"monotonic_vdso",
	"raw_vdso",
	"raw_syscall",
};

static uint64_t timespec_ns(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

static uint64_t read_rdtime(void)
{
	uint64_t value;

	asm volatile("rdtime %0" : "=r"(value));
	return value;
}

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(EXIT_FAILURE);
}

static void pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		die("sched_setaffinity");
}

static void take_sample(struct sample *sample)
{
	struct timespec ts;

	sample->rdtime = read_rdtime();
	if (clock_gettime(CLOCK_REALTIME, &ts))
		die("clock_gettime realtime");
	sample->clock_ns[0] = timespec_ns(&ts);
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		die("clock_gettime monotonic");
	sample->clock_ns[1] = timespec_ns(&ts);
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts))
		die("clock_gettime raw vdso");
	sample->clock_ns[2] = timespec_ns(&ts);
	if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC_RAW, &ts))
		die("clock_gettime raw syscall");
	sample->clock_ns[3] = timespec_ns(&ts);
	sample->actual_cpu = sched_getcpu();
}

static uint64_t parse_u64(const char *text, const char *name)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 0);
	if (errno || *text == '\0' || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, text);
		exit(EXIT_FAILURE);
	}
	return value;
}

static unsigned int parse_cpu_list(char *text, unsigned int *cpu_ids)
{
	char *saveptr = NULL;
	char *token;
	unsigned int count = 0;

	for (token = strtok_r(text, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		uint64_t cpu;

		if (count == CPU_COUNT_TEST) {
			fprintf(stderr, "too many CPUs in list\n");
			exit(EXIT_FAILURE);
		}
		cpu = parse_u64(token, "cpu");
		if (cpu >= CPU_COUNT_TEST) {
			fprintf(stderr, "CPU out of range: %" PRIu64 "\n", cpu);
			exit(EXIT_FAILURE);
		}
		cpu_ids[count++] = cpu;
	}
	if (!count) {
		fprintf(stderr, "empty CPU list\n");
		exit(EXIT_FAILURE);
	}
	return count;
}

int main(int argc, char **argv)
{
	uint64_t iterations = 5000;
	uint64_t threshold_ns = 1000000000ULL;
	uint64_t threshold_cycles = 10000000ULL;
	uint64_t last_rdtime[CPU_COUNT_TEST] = { 0 };
	uint64_t last_clock[CPU_COUNT_TEST][CLOCK_COUNT_TEST] = { { 0 } };
	uint64_t max_rdtime_span = 0;
	uint64_t max_clock_span[CLOCK_COUNT_TEST] = { 0 };
	uint64_t span_anomalies_rdtime = 0;
	uint64_t span_anomalies[CLOCK_COUNT_TEST] = { 0 };
	uint64_t backward_rdtime = 0;
	uint64_t backward_clock[CLOCK_COUNT_TEST] = { 0 };
	uint64_t transition_back_rdtime = 0;
	uint64_t transition_back_clock[CLOCK_COUNT_TEST] = { 0 };
	int64_t direction_upper_cycles = INT64_MAX;
	int64_t direction_lower_cycles = INT64_MIN;
	uint64_t printed = 0;
	uint64_t iter;
	unsigned int i, c;
	struct sample values[CPU_COUNT_TEST];
	uint64_t previous_rdtime = 0;
	uint64_t previous_clock[CLOCK_COUNT_TEST] = { 0 };
	bool have_previous = false;
	unsigned int cpu_ids[CPU_COUNT_TEST] = { 0, 1, 2, 3 };
	unsigned int nr_cpus = CPU_COUNT_TEST;
	char *cpu_list = NULL;

	if (argc > 1)
		iterations = parse_u64(argv[1], "iterations");
	if (argc > 2)
		threshold_ns = parse_u64(argv[2], "threshold_ns");
	if (argc > 3)
		threshold_cycles = parse_u64(argv[3], "threshold_cycles");
	if (argc > 4) {
		cpu_list = strdup(argv[4]);
		if (!cpu_list)
			die("strdup");
		nr_cpus = parse_cpu_list(cpu_list, cpu_ids);
	}
	if (argc > 5) {
		fprintf(stderr, "usage: %s [iterations [threshold_ns [threshold_cycles [cpu-list]]]]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	printf("probe=giantvm-clock iterations=%" PRIu64
	       " threshold_ns=%" PRIu64 " threshold_cycles=%" PRIu64
	       " cpus=",
	       iterations, threshold_ns, threshold_cycles);
	for (i = 0; i < nr_cpus; i++)
		printf("%s%u", i ? "," : "", cpu_ids[i]);
	printf("\n");
	printf("anomaly_columns=iteration,cpu,actual_cpu,rdtime,realtime_vdso,"
	       "monotonic_vdso,raw_vdso,raw_syscall\n");
	fflush(stdout);

	for (iter = 0; iter < iterations; iter++) {
		uint64_t min_rdtime = UINT64_MAX, max_rdtime = 0;
		uint64_t min_clock[CLOCK_COUNT_TEST];
		uint64_t max_clock[CLOCK_COUNT_TEST] = { 0 };
		bool anomalous = false;

		for (c = 0; c < CLOCK_COUNT_TEST; c++)
			min_clock[c] = UINT64_MAX;

		/* Alternate direction so both node0->node1 and node1->node0 are tested. */
		for (i = 0; i < nr_cpus; i++) {
			unsigned int slot = (iter & 1) ? nr_cpus - 1 - i : i;
			unsigned int cpu = cpu_ids[slot];

			pin_cpu(cpu);
			take_sample(&values[cpu]);
			if (values[cpu].actual_cpu != (int)cpu) {
				fprintf(stderr, "affinity mismatch requested=%u actual=%d\n",
					cpu, values[cpu].actual_cpu);
				return EXIT_FAILURE;
			}

			if (last_rdtime[cpu] && values[cpu].rdtime < last_rdtime[cpu])
				backward_rdtime++;
			last_rdtime[cpu] = values[cpu].rdtime;
			if (have_previous && values[cpu].rdtime < previous_rdtime)
				transition_back_rdtime++;
			previous_rdtime = values[cpu].rdtime;

			for (c = 0; c < CLOCK_COUNT_TEST; c++) {
				if (last_clock[cpu][c] &&
				    values[cpu].clock_ns[c] < last_clock[cpu][c])
					backward_clock[c]++;
				last_clock[cpu][c] = values[cpu].clock_ns[c];
				if (have_previous &&
				    values[cpu].clock_ns[c] < previous_clock[c])
					transition_back_clock[c]++;
				previous_clock[c] = values[cpu].clock_ns[c];
			}
			have_previous = true;
		}

		/*
		 * For a two-CPU run, alternating the sampling direction gives NTP-like
		 * bounds for (second CPU clock - first CPU clock).  Sampling CPU A then
		 * B gives an upper bound that includes migration time; B then A gives a
		 * lower bound.  The tightest pair estimates offset and uncertainty.
		 */
		if (nr_cpus == 2) {
			int64_t delta = (int64_t)(values[cpu_ids[1]].rdtime -
						  values[cpu_ids[0]].rdtime);

			if (!(iter & 1) && delta < direction_upper_cycles)
				direction_upper_cycles = delta;
			if ((iter & 1) && delta > direction_lower_cycles)
				direction_lower_cycles = delta;
		}

		for (i = 0; i < nr_cpus; i++) {
			unsigned int cpu = cpu_ids[i];

			if (values[cpu].rdtime < min_rdtime)
				min_rdtime = values[cpu].rdtime;
			if (values[cpu].rdtime > max_rdtime)
				max_rdtime = values[cpu].rdtime;
			for (c = 0; c < CLOCK_COUNT_TEST; c++) {
				if (values[cpu].clock_ns[c] < min_clock[c])
					min_clock[c] = values[cpu].clock_ns[c];
				if (values[cpu].clock_ns[c] > max_clock[c])
					max_clock[c] = values[cpu].clock_ns[c];
			}
		}

		if (max_rdtime - min_rdtime > max_rdtime_span)
			max_rdtime_span = max_rdtime - min_rdtime;
		if (max_rdtime - min_rdtime > threshold_cycles) {
			span_anomalies_rdtime++;
			anomalous = true;
		}
		for (c = 0; c < CLOCK_COUNT_TEST; c++) {
			uint64_t span = max_clock[c] - min_clock[c];

			if (span > max_clock_span[c])
				max_clock_span[c] = span;
			if (span > threshold_ns) {
				span_anomalies[c]++;
				anomalous = true;
			}
		}

		if (anomalous && printed < 20) {
			for (i = 0; i < nr_cpus; i++) {
				unsigned int cpu = cpu_ids[i];

				printf("anomaly,%" PRIu64 ",%u,%d,%" PRIu64
				       ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
				       ",%" PRIu64 "\n",
				       iter, cpu, values[cpu].actual_cpu,
				       values[cpu].rdtime, values[cpu].clock_ns[0],
				       values[cpu].clock_ns[1], values[cpu].clock_ns[2],
				       values[cpu].clock_ns[3]);
			}
			printed++;
			fflush(stdout);
		}
	}

	printf("summary,rdtime,max_span_cycles=%" PRIu64
	       ",span_anomalies=%" PRIu64 ",same_cpu_backwards=%" PRIu64
	       ",transition_backwards=%" PRIu64 "\n",
	       max_rdtime_span, span_anomalies_rdtime, backward_rdtime,
	       transition_back_rdtime);
	for (c = 0; c < CLOCK_COUNT_TEST; c++)
		printf("summary,%s,max_span_ns=%" PRIu64
		       ",span_anomalies=%" PRIu64 ",same_cpu_backwards=%" PRIu64
		       ",transition_backwards=%" PRIu64 "\n",
		       clock_names[c], max_clock_span[c], span_anomalies[c],
		       backward_clock[c], transition_back_clock[c]);
	if (nr_cpus == 2 && direction_upper_cycles != INT64_MAX &&
	    direction_lower_cycles != INT64_MIN) {
		int64_t estimate = direction_lower_cycles +
			(direction_upper_cycles - direction_lower_cycles) / 2;
		int64_t uncertainty =
			(direction_upper_cycles - direction_lower_cycles) / 2;

		printf("summary,rdtime_offset,cpu_a=%u,cpu_b=%u,lower_cycles=%" PRId64
		       ",upper_cycles=%" PRId64 ",estimate_cycles=%" PRId64
		       ",uncertainty_cycles=%" PRId64 "\n",
		       cpu_ids[0], cpu_ids[1], direction_lower_cycles,
		       direction_upper_cycles, estimate, uncertainty);
	}

	free(cpu_list);
	return EXIT_SUCCESS;
}

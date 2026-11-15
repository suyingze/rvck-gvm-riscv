// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Two-page process-shared ping-pong benchmark for a DSM guest.
 *
 * The parent and child are pinned to different guest CPUs. Each side is the
 * sole writer of one page and waits on the page written by the other side.
 * Only the parent reads the clock, so cpu-a should remain on node0.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_BYTES 4096U

struct page_flag {
	_Atomic uint64_t value;
	unsigned char padding[PAGE_BYTES - sizeof(_Atomic uint64_t)];
} __attribute__((aligned(PAGE_BYTES)));

struct shared_area {
	struct page_flag parent_to_child;
	struct page_flag child_to_parent;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--cpu-a N] [--cpu-b N] [--iterations N] "
		"[--warmup N] [--repeats N] [--compute N]\n",
		prog);
}

static unsigned long parse_ulong(const char *name, const char *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(EXIT_FAILURE);
	}
	return parsed;
}

static void pin_to_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		fprintf(stderr, "sched_setaffinity(cpu=%u): %s\n",
			cpu, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static inline void spin_hint(void)
{
	__asm__ __volatile__("nop" ::: "memory");
}

static void compute_work(volatile uint64_t *state, unsigned long rounds)
{
	uint64_t value = *state;
	unsigned long i;

	for (i = 0; i < rounds; i++) {
		value ^= value << 13;
		value ^= value >> 7;
		value ^= value << 17;
	}
	*state = value;
}

static void wait_for_value(_Atomic uint64_t *flag, uint64_t expected)
{
	while (atomic_load_explicit(flag, memory_order_acquire) != expected)
		spin_hint();
}

static uint64_t clock_raw_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int compare_u64(const void *left, const void *right)
{
	const uint64_t a = *(const uint64_t *)left;
	const uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

int main(int argc, char **argv)
{
	unsigned int cpu_a = 0;
	unsigned int cpu_b = 2;
	unsigned long iterations = 1000;
	unsigned long warmup = 100;
	unsigned long repeats = 5;
	unsigned long compute = 0;
	struct shared_area *shared;
	uint64_t *samples;
	uint64_t sequence = 0;
	volatile uint64_t parent_state = UINT64_C(0x243f6a8885a308d3);
	int ready_pipe[2];
	pid_t child;
	unsigned long i, repeat;

	for (i = 1; i < (unsigned long)argc; i++) {
		if (!strcmp(argv[i], "--cpu-a") && i + 1 < (unsigned long)argc)
			cpu_a = parse_ulong("cpu-a", argv[++i]);
		else if (!strcmp(argv[i], "--cpu-b") &&
			 i + 1 < (unsigned long)argc)
			cpu_b = parse_ulong("cpu-b", argv[++i]);
		else if (!strcmp(argv[i], "--iterations") &&
			 i + 1 < (unsigned long)argc)
			iterations = parse_ulong("iterations", argv[++i]);
		else if (!strcmp(argv[i], "--warmup") &&
			 i + 1 < (unsigned long)argc)
			warmup = parse_ulong("warmup", argv[++i]);
		else if (!strcmp(argv[i], "--repeats") &&
			 i + 1 < (unsigned long)argc)
			repeats = parse_ulong("repeats", argv[++i]);
		else if (!strcmp(argv[i], "--compute") &&
			 i + 1 < (unsigned long)argc)
			compute = parse_ulong("compute", argv[++i]);
		else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (!iterations || !repeats || cpu_a == cpu_b) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED) {
		perror("mmap");
		return EXIT_FAILURE;
	}
	memset(shared, 0, sizeof(*shared));

	samples = calloc(repeats, sizeof(*samples));
	if (!samples) {
		perror("calloc");
		return EXIT_FAILURE;
	}
	if (pipe(ready_pipe) < 0) {
		perror("pipe");
		return EXIT_FAILURE;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}
	if (child == 0) {
		char ready = 'R';
		uint64_t child_sequence = 0;
		volatile uint64_t child_state =
			UINT64_C(0x13198a2e03707344);

		close(ready_pipe[0]);
		pin_to_cpu(cpu_b);
		if (write(ready_pipe[1], &ready, sizeof(ready)) != sizeof(ready))
			_exit(EXIT_FAILURE);
		close(ready_pipe[1]);

		for (i = 0; i < warmup + iterations * repeats; i++) {
			child_sequence++;
			wait_for_value(&shared->parent_to_child.value,
				       child_sequence);
			compute_work(&child_state, compute);
			atomic_store_explicit(&shared->child_to_parent.value,
					      child_sequence, memory_order_release);
		}
		_exit(child_state ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(ready_pipe[1]);
	pin_to_cpu(cpu_a);
	{
		char ready;

		if (read(ready_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
			fprintf(stderr, "child did not become ready\n");
			return EXIT_FAILURE;
		}
	}
	close(ready_pipe[0]);

	for (i = 0; i < warmup; i++) {
		sequence++;
		compute_work(&parent_state, compute);
		atomic_store_explicit(&shared->parent_to_child.value, sequence,
				      memory_order_release);
		wait_for_value(&shared->child_to_parent.value, sequence);
	}

	printf("mode=two-page-pingpong cpu_a=%u cpu_b=%u iterations=%lu "
	       "warmup=%lu repeats=%lu compute=%lu\n",
	       cpu_a, cpu_b, iterations, warmup, repeats, compute);
	printf("repeat,total_ns,roundtrips,ns_per_roundtrip,roundtrips_per_sec\n");

	for (repeat = 0; repeat < repeats; repeat++) {
		uint64_t start = clock_raw_ns();
		uint64_t end;
		double ns_per_roundtrip;
		double roundtrips_per_sec;

		for (i = 0; i < iterations; i++) {
			sequence++;
			compute_work(&parent_state, compute);
			atomic_store_explicit(&shared->parent_to_child.value,
					      sequence, memory_order_release);
			wait_for_value(&shared->child_to_parent.value, sequence);
		}
		end = clock_raw_ns();
		samples[repeat] = end - start;
		ns_per_roundtrip = (double)samples[repeat] / iterations;
		roundtrips_per_sec = 1000000000.0 / ns_per_roundtrip;
		printf("%lu,%" PRIu64 ",%lu,%.3f,%.3f\n", repeat + 1,
		       samples[repeat], iterations, ns_per_roundtrip,
		       roundtrips_per_sec);
		fflush(stdout);
	}

	{
		int status;
		uint64_t total = 0;
		double mean;

		if (waitpid(child, &status, 0) < 0) {
			perror("waitpid");
			return EXIT_FAILURE;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "child failed: status=%d\n", status);
			return EXIT_FAILURE;
		}

		qsort(samples, repeats, sizeof(*samples), compare_u64);
		for (repeat = 0; repeat < repeats; repeat++)
			total += samples[repeat];
		mean = (double)total / repeats / iterations;
		printf("summary,min_ns=%.3f,median_ns=%.3f,mean_ns=%.3f,"
		       "max_ns=%.3f,checksum=0x%016" PRIx64 "\n",
		       (double)samples[0] / iterations,
		       (double)samples[repeats / 2] / iterations,
		       mean,
		       (double)samples[repeats - 1] / iterations,
		       parent_state);
	}

	munmap(shared, sizeof(*shared));
	free(samples);
	return EXIT_SUCCESS;
}

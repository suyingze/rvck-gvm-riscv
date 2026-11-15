// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Bulk-synchronous private-data benchmark for GiantVM and MPI.
 *
 * Build the shared-memory version with pthreads. Build the distributed
 * version from the same source with -DUSE_MPI so both execute the identical
 * compute kernel and differ only in their synchronization mechanism.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_MPI
#include <mpi.h>
#else
#include <pthread.h>
#include <sys/mman.h>
#endif

#define MAX_WORKERS 64U
#define PAGE_BYTES 4096U

struct config {
	unsigned int cpus[MAX_WORKERS];
	unsigned int workers;
	unsigned int expected_workers;
	bool have_cpus;
	bool have_workers;
	size_t elements;
	unsigned long rounds;
	unsigned long steps;
	unsigned long warmup_steps;
	unsigned long repeats;
};

struct sample {
	uint64_t elapsed_ns;
	uint64_t operations;
	uint64_t checksum;
};

static void usage(const char *prog, FILE *stream)
{
	fprintf(stream,
		"Usage: %s [options]\n"
		"  --cpus LIST       pthread worker CPUs, for example 0,1,2,3\n"
		"  --workers N       expected pthread workers or MPI ranks\n"
		"  --elements N      uint64 elements private to each worker\n"
		"  --rounds N        integer mixing rounds per element and step\n"
		"  --steps N         measured compute-and-barrier steps\n"
		"  --warmup N        unmeasured compute-and-barrier steps\n"
		"  --repeats N       measured repetitions\n"
		"  --help            print this help\n",
		prog);
}

static unsigned long parse_ulong(const char *name, const char *text)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, text);
		exit(EXIT_FAILURE);
	}
	return value;
}

static void parse_cpu_list(struct config *cfg, const char *text)
{
	char *copy = strdup(text);
	char *cursor = NULL;
	char *token;

	if (!copy) {
		perror("strdup");
		exit(EXIT_FAILURE);
	}
	cfg->workers = 0;
	for (token = strtok_r(copy, ",", &cursor); token;
	     token = strtok_r(NULL, ",", &cursor)) {
		unsigned long cpu;
		unsigned int i;

		if (cfg->workers == MAX_WORKERS) {
			fprintf(stderr, "too many CPUs; maximum is %u\n", MAX_WORKERS);
			exit(EXIT_FAILURE);
		}
		cpu = parse_ulong("CPU", token);
		if (cpu >= CPU_SETSIZE) {
			fprintf(stderr, "CPU %lu exceeds CPU_SETSIZE=%d\n",
				cpu, CPU_SETSIZE);
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < cfg->workers; i++) {
			if (cfg->cpus[i] == cpu) {
				fprintf(stderr, "duplicate CPU: %lu\n", cpu);
				exit(EXIT_FAILURE);
			}
		}
		cfg->cpus[cfg->workers++] = (unsigned int)cpu;
	}
	free(copy);
	if (!cfg->workers) {
		fprintf(stderr, "CPU list is empty\n");
		exit(EXIT_FAILURE);
	}
	cfg->have_cpus = true;
}

static void parse_args(struct config *cfg, int argc, char **argv)
{
	int arg;

	for (arg = 1; arg < argc; arg++) {
		if (!strcmp(argv[arg], "--cpus") && arg + 1 < argc) {
			parse_cpu_list(cfg, argv[++arg]);
		} else if (!strcmp(argv[arg], "--workers") && arg + 1 < argc) {
			unsigned long workers = parse_ulong("workers", argv[++arg]);

			if (!workers || workers > MAX_WORKERS) {
				fprintf(stderr, "workers must be in [1, %u]\n", MAX_WORKERS);
				exit(EXIT_FAILURE);
			}
			cfg->expected_workers = (unsigned int)workers;
			cfg->have_workers = true;
		} else if (!strcmp(argv[arg], "--elements") && arg + 1 < argc) {
			cfg->elements = parse_ulong("elements", argv[++arg]);
		} else if (!strcmp(argv[arg], "--rounds") && arg + 1 < argc) {
			cfg->rounds = parse_ulong("rounds", argv[++arg]);
		} else if (!strcmp(argv[arg], "--steps") && arg + 1 < argc) {
			cfg->steps = parse_ulong("steps", argv[++arg]);
		} else if (!strcmp(argv[arg], "--warmup") && arg + 1 < argc) {
			cfg->warmup_steps = parse_ulong("warmup", argv[++arg]);
		} else if (!strcmp(argv[arg], "--repeats") && arg + 1 < argc) {
			cfg->repeats = parse_ulong("repeats", argv[++arg]);
		} else if (!strcmp(argv[arg], "--help")) {
			usage(argv[0], stdout);
			exit(EXIT_SUCCESS);
		} else {
			usage(argv[0], stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!cfg->elements || !cfg->rounds || !cfg->steps || !cfg->repeats) {
		fprintf(stderr, "elements, rounds, steps and repeats must be nonzero\n");
		exit(EXIT_FAILURE);
	}
	if (cfg->elements > SIZE_MAX / sizeof(uint64_t)) {
		fprintf(stderr, "private buffer is too large\n");
		exit(EXIT_FAILURE);
	}
}

static uint64_t clock_raw_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static inline uint64_t mix_once(uint64_t value)
{
	value ^= value << 13;
	value ^= value >> 7;
	value ^= value << 17;
	return value;
}

static void initialize_buffer(uint64_t *buffer, size_t elements,
			      unsigned int worker)
{
	size_t element;

	for (element = 0; element < elements; element++) {
		uint64_t global_element = (uint64_t)worker * elements + element;

		buffer[element] = UINT64_C(0xd1b54a32d192ed03) *
			(global_element + 1);
	}
}

static void compute_buffer(uint64_t *buffer, size_t elements,
			   unsigned long rounds)
{
	size_t element;

	for (element = 0; element < elements; element++) {
		uint64_t value = buffer[element];
		unsigned long round;

		for (round = 0; round < rounds; round++)
			value = mix_once(value);
		buffer[element] = value;
	}
}

static uint64_t checksum_buffer(const uint64_t *buffer, size_t elements,
				unsigned int worker)
{
	uint64_t checksum = 0;
	size_t element;

	for (element = 0; element < elements; element++) {
		uint64_t global_element = (uint64_t)worker * elements + element;

		checksum ^= mix_once(buffer[element] +
			UINT64_C(0x94d049bb133111eb) *
			(global_element + 1));
	}
	return checksum;
}

static uint64_t operation_count(const struct config *cfg)
{
	uint64_t value = cfg->workers;
	uint64_t factor[] = { cfg->elements, cfg->rounds, cfg->steps };
	size_t i;

	for (i = 0; i < sizeof(factor) / sizeof(factor[0]); i++) {
		if (factor[i] && value > UINT64_MAX / factor[i]) {
			fprintf(stderr, "operation count overflows uint64\n");
			exit(EXIT_FAILURE);
		}
		value *= factor[i];
	}
	return value;
}

static int compare_sample(const void *left, const void *right)
{
	const struct sample *a = left;
	const struct sample *b = right;

	return (a->elapsed_ns > b->elapsed_ns) -
		(a->elapsed_ns < b->elapsed_ns);
}

static void print_sample(unsigned long repeat, const struct sample *sample,
			 uint64_t steps)
{
	double ns_per_operation =
		(double)sample->elapsed_ns / sample->operations;
	double operations_per_sec =
		(double)sample->operations * 1.0e9 / sample->elapsed_ns;
	double steps_per_sec = (double)steps * 1.0e9 / sample->elapsed_ns;

	printf("%lu,%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%.3f,0x%016" PRIx64
	       "\n",
	       repeat, sample->elapsed_ns, sample->operations, ns_per_operation,
	       operations_per_sec, steps_per_sec, sample->checksum);
	fflush(stdout);
}

static void print_summary(struct sample *samples, unsigned long repeats)
{
	uint64_t total_ns = 0;
	unsigned long repeat;
	double mean_ns_per_operation;

	qsort(samples, repeats, sizeof(*samples), compare_sample);
	for (repeat = 0; repeat < repeats; repeat++)
		total_ns += samples[repeat].elapsed_ns;
	mean_ns_per_operation = (double)total_ns /
		((double)repeats * samples[0].operations);
	printf("summary,min_ns_per_op=%.3f,median_ns_per_op=%.3f,"
	       "mean_ns_per_op=%.3f,max_ns_per_op=%.3f\n",
	       (double)samples[0].elapsed_ns / samples[0].operations,
	       (double)samples[repeats / 2].elapsed_ns /
		       samples[repeats / 2].operations,
	       mean_ns_per_operation,
	       (double)samples[repeats - 1].elapsed_ns /
		       samples[repeats - 1].operations);
}

#ifndef USE_MPI

struct pthread_run;

struct worker_context {
	struct pthread_run *run;
	unsigned int index;
	unsigned int cpu;
	uint64_t *buffer;
};

struct pthread_run {
	const struct config *cfg;
	pthread_barrier_t *ready;
	pthread_barrier_t *go;
	pthread_barrier_t *step;
	pthread_barrier_t *done;
	struct worker_context **contexts;
	struct sample *samples;
};

static int pin_current_thread(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static uint64_t pthread_checksum(const struct pthread_run *run)
{
	uint64_t checksum = 0;
	unsigned int worker;

	for (worker = 0; worker < run->cfg->workers; worker++)
		checksum ^= checksum_buffer(run->contexts[worker]->buffer,
			run->cfg->elements, worker);
	return checksum;
}

static void *pthread_worker(void *opaque)
{
	struct worker_context *ctx = opaque;
	struct pthread_run *run = ctx->run;
	const struct config *cfg = run->cfg;
	unsigned long repeat;
	unsigned long step;
	int ret;

	ret = pin_current_thread(ctx->cpu);
	if (ret) {
		fprintf(stderr, "pthread_setaffinity_np(cpu=%u): %s\n",
			ctx->cpu, strerror(ret));
		exit(EXIT_FAILURE);
	}
	initialize_buffer(ctx->buffer, cfg->elements, ctx->index);
	for (step = 0; step < cfg->warmup_steps; step++) {
		compute_buffer(ctx->buffer, cfg->elements, cfg->rounds);
		pthread_barrier_wait(run->step);
	}

	for (repeat = 0; repeat < cfg->repeats; repeat++) {
		uint64_t start_ns = 0;

		pthread_barrier_wait(run->ready);
		if (ctx->index == 0)
			start_ns = clock_raw_ns();
		pthread_barrier_wait(run->go);
		for (step = 0; step < cfg->steps; step++) {
			compute_buffer(ctx->buffer, cfg->elements, cfg->rounds);
			pthread_barrier_wait(run->step);
		}
		pthread_barrier_wait(run->done);
		if (ctx->index == 0) {
			run->samples[repeat].elapsed_ns = clock_raw_ns() - start_ns;
			run->samples[repeat].operations = operation_count(cfg);
			run->samples[repeat].checksum = pthread_checksum(run);
			print_sample(repeat + 1, &run->samples[repeat], cfg->steps);
		}
	}
	return NULL;
}

static int run_pthread(const struct config *cfg)
{
	struct pthread_run run = { .cfg = cfg };
	void *control = MAP_FAILED;
	void *contexts_region = MAP_FAILED;
	void *buffers = MAP_FAILED;
	pthread_t *threads = NULL;
	size_t buffer_bytes = cfg->elements * sizeof(uint64_t);
	size_t stride = (buffer_bytes + PAGE_BYTES - 1) & ~(PAGE_BYTES - 1);
	unsigned int worker;
	int status = EXIT_FAILURE;

	if (!cfg->have_cpus) {
		fprintf(stderr, "pthread backend requires --cpus\n");
		return EXIT_FAILURE;
	}
	if (cfg->have_workers && cfg->expected_workers != cfg->workers) {
		fprintf(stderr, "expected %u pthread workers, got %u CPUs\n",
			cfg->expected_workers, cfg->workers);
		return EXIT_FAILURE;
	}
	if (!stride || stride > SIZE_MAX / cfg->workers) {
		fprintf(stderr, "private buffer mapping is too large\n");
		return EXIT_FAILURE;
	}

	control = mmap(NULL, PAGE_BYTES * 4, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	contexts_region = mmap(NULL, PAGE_BYTES * cfg->workers,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	buffers = mmap(NULL, stride * cfg->workers, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (control == MAP_FAILED || contexts_region == MAP_FAILED ||
	    buffers == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	run.ready = control;
	run.go = (pthread_barrier_t *)((unsigned char *)control + PAGE_BYTES);
	run.step = (pthread_barrier_t *)((unsigned char *)control +
		PAGE_BYTES * 2);
	run.done = (pthread_barrier_t *)((unsigned char *)control +
		PAGE_BYTES * 3);
	run.contexts = calloc(cfg->workers, sizeof(*run.contexts));
	run.samples = calloc(cfg->repeats, sizeof(*run.samples));
	threads = calloc(cfg->workers, sizeof(*threads));
	if (!run.contexts || !run.samples || !threads) {
		perror("calloc");
		goto out;
	}
	if (pthread_barrier_init(run.ready, NULL, cfg->workers) ||
	    pthread_barrier_init(run.go, NULL, cfg->workers) ||
	    pthread_barrier_init(run.step, NULL, cfg->workers) ||
	    pthread_barrier_init(run.done, NULL, cfg->workers)) {
		fprintf(stderr, "pthread_barrier_init failed\n");
		goto out;
	}

	printf("backend=pthread workers=%u cpus=", cfg->workers);
	for (worker = 0; worker < cfg->workers; worker++)
		printf("%s%u", worker ? "," : "", cfg->cpus[worker]);
	printf(" elements_per_worker=%zu global_elements=%zu "
	       "bytes_per_worker=%zu rounds=%lu steps=%lu "
	       "warmup=%lu repeats=%lu control_layout=page-isolated\n",
	       cfg->elements, cfg->elements * cfg->workers, buffer_bytes,
	       cfg->rounds, cfg->steps,
	       cfg->warmup_steps, cfg->repeats);
	printf("repeat,elapsed_ns,operations,ns_per_operation,operations_per_sec,"
	       "steps_per_sec,checksum\n");
	fflush(stdout);

	for (worker = 0; worker < cfg->workers; worker++) {
		run.contexts[worker] = (struct worker_context *)
			((unsigned char *)contexts_region + PAGE_BYTES * worker);
		run.contexts[worker]->run = &run;
		run.contexts[worker]->index = worker;
		run.contexts[worker]->cpu = cfg->cpus[worker];
		run.contexts[worker]->buffer = (uint64_t *)
			((unsigned char *)buffers + stride * worker);
		if (pthread_create(&threads[worker], NULL, pthread_worker,
				   run.contexts[worker])) {
			fprintf(stderr, "pthread_create(worker=%u) failed\n", worker);
			exit(EXIT_FAILURE);
		}
	}
	for (worker = 0; worker < cfg->workers; worker++)
		pthread_join(threads[worker], NULL);
	print_summary(run.samples, cfg->repeats);
	status = EXIT_SUCCESS;

out:
	free(threads);
	free(run.samples);
	free(run.contexts);
	if (buffers != MAP_FAILED)
		munmap(buffers, stride * cfg->workers);
	if (contexts_region != MAP_FAILED)
		munmap(contexts_region, PAGE_BYTES * cfg->workers);
	if (control != MAP_FAILED)
		munmap(control, PAGE_BYTES * 4);
	return status;
}

#else

static int run_mpi(struct config *cfg, int argc, char **argv)
{
	int rank;
	int world;
	int processor_len;
	char processor[MPI_MAX_PROCESSOR_NAME];
	uint64_t *buffer;
	struct sample *samples = NULL;
	unsigned long step;
	unsigned long repeat;
	int status = EXIT_FAILURE;

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &world);
	MPI_Get_processor_name(processor, &processor_len);
	if (world <= 0 || world > (int)MAX_WORKERS) {
		if (rank == 0)
			fprintf(stderr, "MPI ranks must be in [1, %u]\n", MAX_WORKERS);
		MPI_Abort(MPI_COMM_WORLD, 2);
	}
	if (cfg->have_cpus) {
		if (rank == 0)
			fprintf(stderr, "MPI backend does not accept --cpus\n");
		MPI_Abort(MPI_COMM_WORLD, 3);
	}
	if (cfg->have_workers && cfg->expected_workers != (unsigned int)world) {
		if (rank == 0)
			fprintf(stderr, "expected %u MPI ranks, got %d\n",
				cfg->expected_workers, world);
		MPI_Abort(MPI_COMM_WORLD, 4);
	}
	cfg->workers = (unsigned int)world;
	buffer = malloc(cfg->elements * sizeof(*buffer));
	if (!buffer) {
		fprintf(stderr, "rank %d: buffer allocation failed\n", rank);
		MPI_Abort(MPI_COMM_WORLD, 5);
	}
	initialize_buffer(buffer, cfg->elements, (unsigned int)rank);
	if (rank == 0) {
		samples = calloc(cfg->repeats, sizeof(*samples));
		if (!samples) {
			perror("calloc");
			MPI_Abort(MPI_COMM_WORLD, 6);
		}
	}

	for (int current = 0; current < world; current++) {
		MPI_Barrier(MPI_COMM_WORLD);
		if (rank == current) {
			printf("rank=%d/%d host=%s cpu=%d\n", rank, world,
			       processor, sched_getcpu());
			fflush(stdout);
		}
	}
	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0) {
		printf("backend=mpi workers=%d elements_per_worker=%zu "
		       "global_elements=%zu bytes_per_worker=%zu "
		       "rounds=%lu steps=%lu warmup=%lu repeats=%lu\n",
		       world, cfg->elements, cfg->elements * (size_t)world,
		       cfg->elements * sizeof(*buffer),
		       cfg->rounds, cfg->steps, cfg->warmup_steps, cfg->repeats);
		printf("repeat,elapsed_ns,operations,ns_per_operation,"
		       "operations_per_sec,steps_per_sec,checksum\n");
		fflush(stdout);
	}

	for (step = 0; step < cfg->warmup_steps; step++) {
		compute_buffer(buffer, cfg->elements, cfg->rounds);
		MPI_Barrier(MPI_COMM_WORLD);
	}
	for (repeat = 0; repeat < cfg->repeats; repeat++) {
		uint64_t start_ns = 0;
		uint64_t elapsed_ns = 0;
		uint64_t local_checksum;
		uint64_t global_checksum = 0;

		MPI_Barrier(MPI_COMM_WORLD);
		if (rank == 0)
			start_ns = clock_raw_ns();
		MPI_Barrier(MPI_COMM_WORLD);
		for (step = 0; step < cfg->steps; step++) {
			compute_buffer(buffer, cfg->elements, cfg->rounds);
			MPI_Barrier(MPI_COMM_WORLD);
		}
		MPI_Barrier(MPI_COMM_WORLD);
		if (rank == 0)
			elapsed_ns = clock_raw_ns() - start_ns;
		local_checksum = checksum_buffer(buffer, cfg->elements,
			(unsigned int)rank);
		MPI_Reduce(&local_checksum, &global_checksum, 1, MPI_UINT64_T,
			   MPI_BXOR, 0, MPI_COMM_WORLD);
		if (rank == 0) {
			samples[repeat].elapsed_ns = elapsed_ns;
			samples[repeat].operations = operation_count(cfg);
			samples[repeat].checksum = global_checksum;
			print_sample(repeat + 1, &samples[repeat], cfg->steps);
		}
	}
	if (rank == 0)
		print_summary(samples, cfg->repeats);
	status = EXIT_SUCCESS;
	free(samples);
	free(buffer);
	MPI_Finalize();
	return status;
}

#endif

int main(int argc, char **argv)
{
	struct config cfg = {
		.elements = 512,
		.rounds = 100,
		.steps = 100,
		.warmup_steps = 10,
		.repeats = 7,
	};

	parse_args(&cfg, argc, argv);
#ifdef USE_MPI
	return run_mpi(&cfg, argc, argv);
#else
	return run_pthread(&cfg);
#endif
}

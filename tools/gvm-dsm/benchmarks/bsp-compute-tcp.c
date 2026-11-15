// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Two-VM bulk-synchronous benchmark using explicit TCP messages.
 *
 * Each VM runs one process with two pinned pthread workers.  Workers only
 * modify private buffers.  A global barrier first synchronizes the two local
 * workers, exchanges one sequence word between VM leaders over TCP, and then
 * releases the local workers.  The compute kernel and checksum match
 * bsp-compute-bench.c so GiantVM/pthread and distributed-VM/TCP execute the
 * same useful work.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_WORKERS 64U
#define PAGE_BYTES 4096U

enum role {
	ROLE_UNSET,
	ROLE_SERVER,
	ROLE_CLIENT,
};

struct config {
	enum role role;
	char peer[INET_ADDRSTRLEN];
	unsigned int port;
	unsigned int cpus[MAX_WORKERS];
	unsigned int local_workers;
	unsigned int global_workers;
	unsigned int worker_offset;
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

struct run;

struct worker_context {
	struct run *run;
	unsigned int local_index;
	unsigned int global_index;
	unsigned int cpu;
	uint64_t *buffer;
};

struct run {
	const struct config *cfg;
	int socket_fd;
	uint64_t barrier_sequence;
	pthread_barrier_t *arrive;
	pthread_barrier_t *release;
	struct worker_context **contexts;
	struct sample *samples;
};

static void usage(const char *prog, FILE *stream)
{
	fprintf(stream,
		"Usage: %s --role server|client [options]\n"
		"  --peer ADDR       server address required by client\n"
		"  --port N          TCP port (default 42000)\n"
		"  --cpus LIST       local worker CPUs, for example 0,1\n"
		"  --global-workers N total workers across both VMs\n"
		"  --worker-offset N first global worker index on this VM\n"
		"  --elements N      uint64 elements private to each worker\n"
		"  --rounds N        integer mixing rounds per element and step\n"
		"  --steps N         measured compute-and-barrier steps\n"
		"  --warmup N        unmeasured compute-and-barrier steps\n"
		"  --repeats N       measured repetitions\n",
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
	for (token = strtok_r(copy, ",", &cursor); token;
	     token = strtok_r(NULL, ",", &cursor)) {
		unsigned long cpu;
		unsigned int i;

		if (cfg->local_workers == MAX_WORKERS) {
			fprintf(stderr, "too many CPUs\n");
			exit(EXIT_FAILURE);
		}
		cpu = parse_ulong("CPU", token);
		if (cpu >= CPU_SETSIZE) {
			fprintf(stderr, "CPU %lu exceeds CPU_SETSIZE\n", cpu);
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < cfg->local_workers; i++) {
			if (cfg->cpus[i] == cpu) {
				fprintf(stderr, "duplicate CPU %lu\n", cpu);
				exit(EXIT_FAILURE);
			}
		}
		cfg->cpus[cfg->local_workers++] = (unsigned int)cpu;
	}
	free(copy);
}

static void parse_args(struct config *cfg, int argc, char **argv)
{
	int arg;

	for (arg = 1; arg < argc; arg++) {
		if (!strcmp(argv[arg], "--role") && arg + 1 < argc) {
			const char *role = argv[++arg];

			if (!strcmp(role, "server"))
				cfg->role = ROLE_SERVER;
			else if (!strcmp(role, "client"))
				cfg->role = ROLE_CLIENT;
			else {
				fprintf(stderr, "invalid role: %s\n", role);
				exit(EXIT_FAILURE);
			}
		} else if (!strcmp(argv[arg], "--peer") && arg + 1 < argc) {
			if (strlen(argv[++arg]) >= sizeof(cfg->peer)) {
				fprintf(stderr, "peer address is too long\n");
				exit(EXIT_FAILURE);
			}
			strcpy(cfg->peer, argv[arg]);
		} else if (!strcmp(argv[arg], "--port") && arg + 1 < argc) {
			cfg->port = parse_ulong("port", argv[++arg]);
		} else if (!strcmp(argv[arg], "--cpus") && arg + 1 < argc) {
			parse_cpu_list(cfg, argv[++arg]);
		} else if (!strcmp(argv[arg], "--global-workers") && arg + 1 < argc) {
			cfg->global_workers = parse_ulong("global-workers", argv[++arg]);
		} else if (!strcmp(argv[arg], "--worker-offset") && arg + 1 < argc) {
			cfg->worker_offset = parse_ulong("worker-offset", argv[++arg]);
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
	if (cfg->role == ROLE_UNSET || !cfg->local_workers ||
	    !cfg->global_workers || !cfg->elements || !cfg->rounds ||
	    !cfg->steps || !cfg->repeats || !cfg->port || cfg->port > 65535) {
		fprintf(stderr, "missing or invalid required option\n");
		exit(EXIT_FAILURE);
	}
	if (cfg->role == ROLE_CLIENT && !cfg->peer[0]) {
		fprintf(stderr, "client requires --peer\n");
		exit(EXIT_FAILURE);
	}
	if (cfg->worker_offset + cfg->local_workers > cfg->global_workers) {
		fprintf(stderr, "local worker indexes exceed global worker count\n");
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
	uint64_t value = cfg->global_workers;
	uint64_t factor[] = { cfg->elements, cfg->rounds, cfg->steps };
	size_t i;

	for (i = 0; i < sizeof(factor) / sizeof(factor[0]); i++) {
		if (factor[i] && value > UINT64_MAX / factor[i]) {
			fprintf(stderr, "operation count overflow\n");
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
	       "\n", repeat, sample->elapsed_ns, sample->operations,
	       ns_per_operation, operations_per_sec, steps_per_sec,
	       sample->checksum);
	fflush(stdout);
}

static void print_summary(struct sample *samples, unsigned long repeats)
{
	uint64_t total_ns = 0;
	unsigned long repeat;

	qsort(samples, repeats, sizeof(*samples), compare_sample);
	for (repeat = 0; repeat < repeats; repeat++)
		total_ns += samples[repeat].elapsed_ns;
	printf("summary,min_ns_per_op=%.3f,median_ns_per_op=%.3f,"
	       "mean_ns_per_op=%.3f,max_ns_per_op=%.3f\n",
	       (double)samples[0].elapsed_ns / samples[0].operations,
	       (double)samples[repeats / 2].elapsed_ns /
		       samples[repeats / 2].operations,
	       (double)total_ns /
		       ((double)repeats * samples[0].operations),
	       (double)samples[repeats - 1].elapsed_ns /
		       samples[repeats - 1].operations);
}

static void transfer_exact(int fd, void *buffer, size_t length, bool send_data)
{
	unsigned char *cursor = buffer;

	while (length) {
		ssize_t ret = send_data ? send(fd, cursor, length, MSG_NOSIGNAL) :
			recv(fd, cursor, length, MSG_WAITALL);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0) {
			if (ret < 0)
				perror(send_data ? "send" : "recv");
			else
				fprintf(stderr, "peer closed TCP connection\n");
			exit(EXIT_FAILURE);
		}
		cursor += ret;
		length -= (size_t)ret;
	}
}

static int configure_socket(int fd)
{
	int one = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
		perror("setsockopt(TCP_NODELAY)");
		return -1;
	}
	return 0;
}

static int open_server(unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int listen_fd;
	int one = 1;
	int fd;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listen_fd, 1) < 0) {
		perror("bind/listen");
		exit(EXIT_FAILURE);
	}
	printf("tcp_listen=0.0.0.0:%u\n", port);
	fflush(stdout);
	fd = accept(listen_fd, NULL, NULL);
	if (fd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	close(listen_fd);
	if (configure_socket(fd))
		exit(EXIT_FAILURE);
	return fd;
}

static int open_client(const char *peer, unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)port),
	};
	unsigned int attempt;

	if (inet_pton(AF_INET, peer, &address.sin_addr) != 1) {
		fprintf(stderr, "invalid peer IPv4 address: %s\n", peer);
		exit(EXIT_FAILURE);
	}
	for (attempt = 1; attempt <= 100; attempt++) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);

		if (fd < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}
		if (!connect(fd, (struct sockaddr *)&address, sizeof(address))) {
			if (configure_socket(fd))
				exit(EXIT_FAILURE);
			return fd;
		}
		close(fd);
		usleep(100000);
	}
	fprintf(stderr, "cannot connect to %s:%u\n", peer, port);
	exit(EXIT_FAILURE);
}

static void global_barrier(struct worker_context *ctx)
{
	struct run *run = ctx->run;
	uint64_t sequence;

	pthread_barrier_wait(run->arrive);
	if (!ctx->local_index) {
		sequence = ++run->barrier_sequence;
		if (run->cfg->role == ROLE_SERVER) {
			uint64_t reply;

			transfer_exact(run->socket_fd, &sequence, sizeof(sequence), true);
			transfer_exact(run->socket_fd, &reply, sizeof(reply), false);
			if (reply != sequence) {
				fprintf(stderr, "barrier sequence mismatch\n");
				exit(EXIT_FAILURE);
			}
		} else {
			uint64_t request;

			transfer_exact(run->socket_fd, &request, sizeof(request), false);
			if (request != sequence) {
				fprintf(stderr, "barrier sequence mismatch\n");
				exit(EXIT_FAILURE);
			}
			transfer_exact(run->socket_fd, &request, sizeof(request), true);
		}
	}
	pthread_barrier_wait(run->release);
}

static int pin_current_thread(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static uint64_t local_checksum(const struct run *run)
{
	uint64_t checksum = 0;
	unsigned int worker;

	for (worker = 0; worker < run->cfg->local_workers; worker++)
		checksum ^= checksum_buffer(run->contexts[worker]->buffer,
			run->cfg->elements,
			run->contexts[worker]->global_index);
	return checksum;
}

static void exchange_checksum(struct run *run, uint64_t local,
			      uint64_t *global)
{
	if (run->cfg->role == ROLE_SERVER) {
		uint64_t remote;

		transfer_exact(run->socket_fd, &remote, sizeof(remote), false);
		*global = local ^ remote;
	} else {
		transfer_exact(run->socket_fd, &local, sizeof(local), true);
	}
}

static void *worker_main(void *opaque)
{
	struct worker_context *ctx = opaque;
	struct run *run = ctx->run;
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
	initialize_buffer(ctx->buffer, cfg->elements, ctx->global_index);
	for (step = 0; step < cfg->warmup_steps; step++) {
		compute_buffer(ctx->buffer, cfg->elements, cfg->rounds);
		global_barrier(ctx);
	}
	for (repeat = 0; repeat < cfg->repeats; repeat++) {
		uint64_t start_ns = 0;

		global_barrier(ctx);
		if (!ctx->local_index && cfg->role == ROLE_SERVER)
			start_ns = clock_raw_ns();
		global_barrier(ctx);
		for (step = 0; step < cfg->steps; step++) {
			compute_buffer(ctx->buffer, cfg->elements, cfg->rounds);
			global_barrier(ctx);
		}
		global_barrier(ctx);
		if (!ctx->local_index) {
			uint64_t checksum = local_checksum(run);
			uint64_t global_checksum = 0;

			if (cfg->role == ROLE_SERVER) {
				run->samples[repeat].elapsed_ns =
					clock_raw_ns() - start_ns;
				run->samples[repeat].operations =
					operation_count(cfg);
			}
			exchange_checksum(run, checksum, &global_checksum);
			if (cfg->role == ROLE_SERVER) {
				run->samples[repeat].checksum = global_checksum;
				print_sample(repeat + 1, &run->samples[repeat],
					cfg->steps);
			}
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.port = 42000,
		.global_workers = 4,
		.elements = 512,
		.rounds = 100,
		.steps = 100,
		.warmup_steps = 10,
		.repeats = 7,
	};
	struct run run = { .cfg = &cfg, .socket_fd = -1 };
	void *barriers = MAP_FAILED;
	void *contexts_region = MAP_FAILED;
	void *buffers = MAP_FAILED;
	pthread_t *threads = NULL;
	size_t buffer_bytes;
	size_t stride;
	unsigned int worker;
	int status = EXIT_FAILURE;

	parse_args(&cfg, argc, argv);
	buffer_bytes = cfg.elements * sizeof(uint64_t);
	stride = (buffer_bytes + PAGE_BYTES - 1) & ~(PAGE_BYTES - 1);
	if (!stride || stride > SIZE_MAX / cfg.local_workers) {
		fprintf(stderr, "private buffer mapping is too large\n");
		return EXIT_FAILURE;
	}
	run.socket_fd = cfg.role == ROLE_SERVER ? open_server(cfg.port) :
		open_client(cfg.peer, cfg.port);
	barriers = mmap(NULL, PAGE_BYTES * 2, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	contexts_region = mmap(NULL, PAGE_BYTES * cfg.local_workers,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	buffers = mmap(NULL, stride * cfg.local_workers,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (barriers == MAP_FAILED || contexts_region == MAP_FAILED ||
	    buffers == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	run.arrive = barriers;
	run.release = (pthread_barrier_t *)((unsigned char *)barriers +
		PAGE_BYTES);
	run.contexts = calloc(cfg.local_workers, sizeof(*run.contexts));
	run.samples = calloc(cfg.repeats, sizeof(*run.samples));
	threads = calloc(cfg.local_workers, sizeof(*threads));
	if (!run.contexts || !run.samples || !threads) {
		perror("calloc");
		goto out;
	}
	if (pthread_barrier_init(run.arrive, NULL, cfg.local_workers) ||
	    pthread_barrier_init(run.release, NULL, cfg.local_workers)) {
		fprintf(stderr, "pthread_barrier_init failed\n");
		goto out;
	}
	if (cfg.role == ROLE_SERVER) {
		printf("backend=tcp-distributed-vm local_workers=%u "
		       "global_workers=%u elements_per_worker=%zu "
		       "global_elements=%zu rounds=%lu steps=%lu warmup=%lu "
		       "repeats=%lu hierarchy=local-pthread+cross-vm-tcp\n",
		       cfg.local_workers, cfg.global_workers, cfg.elements,
		       cfg.elements * cfg.global_workers, cfg.rounds, cfg.steps,
		       cfg.warmup_steps, cfg.repeats);
		printf("repeat,elapsed_ns,operations,ns_per_operation,"
		       "operations_per_sec,steps_per_sec,checksum\n");
		fflush(stdout);
	}
	for (worker = 0; worker < cfg.local_workers; worker++) {
		run.contexts[worker] = (struct worker_context *)
			((unsigned char *)contexts_region + PAGE_BYTES * worker);
		run.contexts[worker]->run = &run;
		run.contexts[worker]->local_index = worker;
		run.contexts[worker]->global_index = cfg.worker_offset + worker;
		run.contexts[worker]->cpu = cfg.cpus[worker];
		run.contexts[worker]->buffer = (uint64_t *)
			((unsigned char *)buffers + stride * worker);
		if (pthread_create(&threads[worker], NULL, worker_main,
				   run.contexts[worker])) {
			fprintf(stderr, "pthread_create failed\n");
			exit(EXIT_FAILURE);
		}
	}
	for (worker = 0; worker < cfg.local_workers; worker++)
		pthread_join(threads[worker], NULL);
	if (cfg.role == ROLE_SERVER)
		print_summary(run.samples, cfg.repeats);
	status = EXIT_SUCCESS;

out:
	if (run.socket_fd >= 0)
		close(run.socket_fd);
	free(threads);
	free(run.samples);
	free(run.contexts);
	if (buffers != MAP_FAILED)
		munmap(buffers, stride * cfg.local_workers);
	if (contexts_region != MAP_FAILED)
		munmap(contexts_region, PAGE_BYTES * cfg.local_workers);
	if (barriers != MAP_FAILED)
		munmap(barriers, PAGE_BYTES * 2);
	return status;
}

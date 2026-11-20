// SPDX-License-Identifier: GPL-2.0
/*
 * Compare the RISC-V time counters of two physical hosts.
 *
 * The server returns rdtime immediately after each request.  The client reads
 * its local counter before and after the round trip, which bounds the remote
 * clock offset without assuming a symmetric network delay.  Repeating the
 * measurement later reveals relative oscillator drift.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static void write_full(int fd, const void *buffer, size_t size)
{
	const unsigned char *cursor = buffer;

	while (size) {
		ssize_t written = write(fd, cursor, size);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			die("write");
		}
		if (!written) {
			errno = EPIPE;
			die("write eof");
		}
		cursor += written;
		size -= written;
	}
}

static bool read_full(int fd, void *buffer, size_t size)
{
	unsigned char *cursor = buffer;

	while (size) {
		ssize_t received = read(fd, cursor, size);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			die("read");
		}
		if (!received)
			return false;
		cursor += received;
		size -= received;
	}
	return true;
}

static int make_address(const char *ip, const char *port_text,
			struct sockaddr_in *address)
{
	uint64_t port = parse_u64(port_text, "port");

	if (!port || port > 65535) {
		fprintf(stderr, "port out of range: %" PRIu64 "\n", port);
		exit(EXIT_FAILURE);
	}
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, ip, &address->sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", ip);
		exit(EXIT_FAILURE);
	}
	return 0;
}

static void run_server(const char *ip, const char *port_text)
{
	struct sockaddr_in address;
	int one = 1;
	int listener;
	int client;
	unsigned char request;

	make_address(ip, port_text, &address);
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
		die("socket");
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		die("setsockopt");
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)))
		die("bind");
	if (listen(listener, 1))
		die("listen");
	printf("server_ready ip=%s port=%s\n", ip, port_text);
	fflush(stdout);

	client = accept(listener, NULL, NULL);
	if (client < 0)
		die("accept");
	while (read_full(client, &request, sizeof(request))) {
		uint64_t remote_cycles = htobe64(read_rdtime());

		write_full(client, &remote_cycles, sizeof(remote_cycles));
	}
	close(client);
	close(listener);
}

static void run_client(const char *ip, const char *port_text, uint64_t samples)
{
	struct sockaddr_in address;
	int64_t best_estimate = 0;
	uint64_t best_rtt = UINT64_MAX;
	uint64_t min_rtt = UINT64_MAX;
	uint64_t max_rtt = 0;
	long double estimate_sum = 0;
	uint64_t accepted = 0;
	int client;
	uint64_t i;

	make_address(ip, port_text, &address);
	client = socket(AF_INET, SOCK_STREAM, 0);
	if (client < 0)
		die("socket");
	if (connect(client, (struct sockaddr *)&address, sizeof(address)))
		die("connect");

	for (i = 0; i < samples; i++) {
		unsigned char request = 1;
		uint64_t remote_be;
		uint64_t remote;
		uint64_t before;
		uint64_t after;
		uint64_t rtt;
		int64_t estimate;

		before = read_rdtime();
		write_full(client, &request, sizeof(request));
		if (!read_full(client, &remote_be, sizeof(remote_be))) {
			errno = ECONNRESET;
			die("server closed connection");
		}
		after = read_rdtime();
		remote = be64toh(remote_be);
		rtt = after - before;
		estimate = (int64_t)(remote - (before + rtt / 2));
		if (rtt < min_rtt)
			min_rtt = rtt;
		if (rtt > max_rtt)
			max_rtt = rtt;
		if (rtt < best_rtt) {
			best_rtt = rtt;
			best_estimate = estimate;
		}
	}

	/* Average the low-latency half around the best RTT in a second pass. */
	for (i = 0; i < samples; i++) {
		unsigned char request = 1;
		uint64_t remote_be;
		uint64_t remote;
		uint64_t before = read_rdtime();
		uint64_t after;
		uint64_t rtt;

		write_full(client, &request, sizeof(request));
		if (!read_full(client, &remote_be, sizeof(remote_be))) {
			errno = ECONNRESET;
			die("server closed connection");
		}
		after = read_rdtime();
		remote = be64toh(remote_be);
		rtt = after - before;
		if (rtt <= best_rtt * 2) {
			estimate_sum += (int64_t)(remote - (before + rtt / 2));
			accepted++;
		}
	}

	printf("summary,samples=%" PRIu64 ",best_offset_cycles=%" PRId64
	       ",best_rtt_cycles=%" PRIu64 ",uncertainty_cycles=%" PRIu64
	       ",min_rtt_cycles=%" PRIu64 ",max_rtt_cycles=%" PRIu64,
	       samples, best_estimate, best_rtt, best_rtt / 2,
	       min_rtt, max_rtt);
	if (accepted)
		printf(",low_latency_mean_cycles=%.0Lf,accepted=%" PRIu64,
		       estimate_sum / accepted, accepted);
	printf("\n");
	close(client);
}

int main(int argc, char **argv)
{
	if (argc < 4 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		fprintf(stderr, "usage: %s server IP PORT | client IP PORT [SAMPLES]\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	if (!strcmp(argv[1], "server")) {
		if (argc != 4) {
			fprintf(stderr, "server mode does not accept a sample count\n");
			return EXIT_FAILURE;
		}
		run_server(argv[2], argv[3]);
	} else {
		uint64_t samples = argc == 5 ? parse_u64(argv[4], "samples") : 10000;

		if (argc > 5 || !samples) {
			fprintf(stderr, "invalid client arguments\n");
			return EXIT_FAILURE;
		}
		run_client(argv[2], argv[3], samples);
	}
	return EXIT_SUCCESS;
}

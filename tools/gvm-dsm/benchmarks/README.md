# GiantVM DSM benchmarks

This directory contains small guest-side benchmarks used to isolate DSM
mechanisms from application behavior.

## dsm-page-pingpong

`dsm-page-pingpong.c` pins a parent and child process to two guest CPUs.  Each
process is the only writer of one 4 KiB page and waits for the page written by
the other process.  One measured round trip therefore contains a request and
an acknowledgement through the DSM page protocol.

The optional `--compute N` argument runs `N` integer-mixing rounds on each side
between notifications.  It is intended for measuring how much useful work is
needed to amortize one DSM synchronization round trip.  Keep the timing parent
on a node-0 CPU; guest clocks on remote CPUs are not a reliable cross-node
timebase.

Example build and run inside a RISC-V guest:

```sh
gcc -O2 -Wall -Wextra -std=gnu11 -pthread \
  dsm-page-pingpong.c -o dsm-page-pingpong

./dsm-page-pingpong --cpu-a 0 --cpu-b 2 \
  --iterations 1000 --warmup 100 --repeats 7 --compute 10000
```

## BSP compute/barrier comparison

`bsp-compute-bench.c` provides two builds of the same private-buffer compute
kernel.  The default pthread build runs inside one GiantVM guest and uses a
pthread barrier.  The MPI build uses MPI ranks and an MPI barrier.  Keeping a
fixed global element count while changing from two local workers to four
workers split across two hosts gives a directly comparable strong-scaling
test.

Build both variants:

```sh
gcc -O3 -Wall -Wextra -Werror -std=gnu11 -pthread \
  bsp-compute-bench.c -o bsp-compute-pthread

mpicc -O3 -Wall -Wextra -Werror -std=gnu11 -DUSE_MPI \
  bsp-compute-bench.c -o bsp-compute-mpi
```

`run-bsp-pthread-scan.sh` scans the GiantVM guest with workers on CPUs 0/1 and
then 0/1/2/3.  `run-bsp-mpi-scan.sh` runs the corresponding Open MPI + UCX
scan on the two hosts.  The two rankfiles pin MPI ranks to host CPUs 2 and 3.
The site-specific defaults in the MPI runner can be replaced with environment
variables; in particular `NODE0_HOST`, `NODE1_HOST`, `OMPI_PREFIX`, `BENCH`,
`UCX_DEVICE`, and the rankfile paths.

Both runners scan 1, 10, 100, 1000, and 10000 compute rounds between barriers.
Compare medians within each backend using:

```text
speedup = local two-worker elapsed / cross-host four-worker elapsed
parallel efficiency = speedup / 2
```

The checksum for every repeat must match between the two-worker and
four-worker cases and between the pthread and MPI builds.

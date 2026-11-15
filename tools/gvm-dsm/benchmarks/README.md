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

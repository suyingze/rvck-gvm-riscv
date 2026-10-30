# GVM RISC-V DSM two-node launch helpers

These helpers add repeatable run preparation and safety checks on top of the
previously validated QEMU launch scripts.  They do not replace or modify:

```text
start-common.sh
start-dsm-node0.sh
start-dsm-node1.sh
start-dsm-quick-node0.sh
start-dsm-quick-node1.sh
```

Deploy this directory beside those five scripts on both hosts.  On node0:

```bash
./prepare-dsm-run.sh rdma --check-only
./prepare-dsm-run.sh rdma
```

Start node1 first:

```bash
./start-dsm-run-node1.sh quick
```

Then start node0:

```bash
./start-dsm-run-node0.sh quick
```

Use `full` instead of `quick` for a systemd boot.  Every quick or full test
requires a newly prepared rootfs.  Site-specific kernel names, data-plane
addresses and artifact paths live in `profiles/`.

The generated `current-run.env` and `logs/` are intentionally not tracked.

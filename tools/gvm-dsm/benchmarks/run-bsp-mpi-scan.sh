#!/usr/bin/env bash
set -euo pipefail

NODE0_HOST="${NODE0_HOST:-10.0.2.168}"
NODE1_HOST="${NODE1_HOST:-10.0.0.159}"
NODE1_SSH="${NODE1_SSH:-ubuntu@${NODE1_HOST}}"
OMPI_PREFIX="${OMPI_PREFIX:-/home/ubuntu/opt/openmpi-4.1.6-ucx}"
BENCH="${BENCH:-/home/ubuntu/gvm-riscv-work/benchmarks/bsp-compute-mpi}"
RANKFILE_LOCAL2="${RANKFILE_LOCAL2:-/home/ubuntu/gvm-riscv-work/benchmarks/bsp-mpi-rankfile-local2}"
RANKFILE_TWO_NODE4="${RANKFILE_TWO_NODE4:-/home/ubuntu/gvm-riscv-work/benchmarks/bsp-mpi-rankfile-two-node4}"
GLOBAL_ELEMENTS="${GLOBAL_ELEMENTS:-2048}"
REPEATS="${REPEATS:-7}"
UCX_DEVICE="${UCX_DEVICE:-rocep1s0f0:1}"
RDMA_DEVICE="${RDMA_DEVICE:-rocep1s0f0}"
LOG_DIR="${LOG_DIR:-/home/ubuntu/gvm-riscv-work/benchmarks/logs}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_DIR}/bsp-mpi-scan-${RUN_ID}.log"

if (( GLOBAL_ELEMENTS % 4 != 0 )); then
    echo "GLOBAL_ELEMENTS must be divisible by 4" >&2
    exit 2
fi
for path in "${OMPI_PREFIX}/bin/mpirun" "${BENCH}" \
            "${RANKFILE_LOCAL2}" "${RANKFILE_TWO_NODE4}"; do
    test -e "${path}" || { echo "missing local path: ${path}" >&2; exit 1; }
done
ssh -o BatchMode=yes -o ConnectTimeout=8 "${NODE1_SSH}" \
    "test -x '${BENCH}'"
test -z "$(pgrep -f '[q]emu-system-riscv64' || true)"
ssh -o BatchMode=yes "${NODE1_SSH}" \
    "test -z \"\$(pgrep -f '[q]emu-system-riscv64' || true)\""

local_sha="$(sha256sum "${BENCH}" | awk '{print $1}')"
remote_sha="$(ssh -o BatchMode=yes "${NODE1_SSH}" \
    "sha256sum '${BENCH}'" | awk '{print $1}')"
if [[ "${local_sha}" != "${remote_sha}" ]]; then
    echo "MPI benchmark differs between nodes" >&2
    exit 1
fi

mkdir -p -- "${LOG_DIR}"
export UCX_TLS=rc,self,posix,sysv
export UCX_NET_DEVICES="${UCX_DEVICE}"

MPI_COMMON=(
    --prefix "${OMPI_PREFIX}"
    --mca pml ucx
    --mca btl '^openib'
    -x UCX_TLS
    -x UCX_NET_DEVICES
)

rdma_counters() {
    local label="$1"

    echo "RDMA_COUNTERS label=${label} node=node0"
    for counter in port_xmit_data port_rcv_data; do
        printf '%s=' "${counter}"
        cat "/sys/class/infiniband/${RDMA_DEVICE}/ports/1/counters/${counter}"
    done
    echo "RDMA_COUNTERS label=${label} node=node1"
    ssh -o BatchMode=yes "${NODE1_SSH}" \
        "for counter in port_xmit_data port_rcv_data; do printf '%s=' \"\${counter}\"; cat '/sys/class/infiniband/${RDMA_DEVICE}/ports/1/counters/'\"\${counter}\"; done"
}

run_one() {
    local name="$1"
    local workers="$2"
    local elements="$3"
    local rounds="$4"
    local steps="$5"
    local warmup="$6"
    shift 6

    echo "=== BSP_MPI_CASE_BEGIN name=${name} ==="
    "${OMPI_PREFIX}/bin/mpirun" "${MPI_COMMON[@]}" "$@" \
        "${BENCH}" --workers "${workers}" --elements "${elements}" \
        --rounds "${rounds}" --steps "${steps}" --warmup "${warmup}" \
        --repeats "${REPEATS}"
    echo "=== BSP_MPI_CASE_END name=${name} status=0 ==="
}

run_pair() {
    local label="$1"
    local rounds="$2"
    local steps="$3"
    local warmup="$4"

    run_one "${label}_local2" 2 $((GLOBAL_ELEMENTS / 2)) \
        "${rounds}" "${steps}" "${warmup}" \
        --host "${NODE0_HOST}:2" -np 2 --rankfile "${RANKFILE_LOCAL2}"
    run_one "${label}_two_node4" 4 $((GLOBAL_ELEMENTS / 4)) \
        "${rounds}" "${steps}" "${warmup}" \
        --host "${NODE0_HOST}:2,${NODE1_HOST}:2" -np 4 \
        --rankfile "${RANKFILE_TWO_NODE4}"
}

{
    echo "=== BSP_MPI_SCAN_BEGIN ==="
    echo "run_id=${RUN_ID}"
    echo "benchmark_sha256=${local_sha}"
    echo "global_elements=${GLOBAL_ELEMENTS} repeats=${REPEATS}"
    echo "UCX_TLS=${UCX_TLS}"
    echo "UCX_NET_DEVICES=${UCX_NET_DEVICES}"
    "${OMPI_PREFIX}/bin/mpirun" --version | head -n 1
    rdma link show "${RDMA_DEVICE}/1"
    ssh -o BatchMode=yes "${NODE1_SSH}" rdma link show "${RDMA_DEVICE}/1"

    echo "=== BSP_MPI_TRANSPORT_VERIFY ==="
    UCX_LOG_LEVEL=info "${OMPI_PREFIX}/bin/mpirun" "${MPI_COMMON[@]}" \
        -x UCX_LOG_LEVEL --host "${NODE0_HOST}:2,${NODE1_HOST}:2" -np 4 \
        --rankfile "${RANKFILE_TWO_NODE4}" "${BENCH}" --workers 4 \
        --elements 32 --rounds 2 --steps 2 --warmup 1 --repeats 1

    rdma_counters before
    run_pair rounds_1 1 200 20
    run_pair rounds_10 10 200 20
    run_pair rounds_100 100 100 10
    run_pair rounds_1000 1000 50 5
    run_pair rounds_10000 10000 20 2
    rdma_counters after
    echo "=== BSP_MPI_SCAN_END ==="
} 2>&1 | tee "${LOG_FILE}"

if ! grep -q 'inter-node.*rc_mlx5/rocep1s0f0:1' "${LOG_FILE}"; then
    echo "UCX transport verification failed" >&2
    exit 1
fi
echo "saved ${LOG_FILE}"

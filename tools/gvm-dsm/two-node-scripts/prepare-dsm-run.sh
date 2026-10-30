#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: prepare-dsm-run.sh <rdma|tcp> [--check-only]

Run this script on node0 (192.168.100.1).  It validates both hosts and,
unless --check-only is supplied, creates a fresh writable rootfs, copies it
to node1, verifies both checksums, and publishes current-run.env.
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage >&2
    exit 2
fi

PROFILE_NAME="$1"
CHECK_ONLY=0
if [[ $# -eq 2 ]]; then
    if [[ "$2" != "--check-only" ]]; then
        usage >&2
        exit 2
    fi
    CHECK_ONLY=1
fi

PROFILE_FILE="${SCRIPT_DIR}/profiles/${PROFILE_NAME}.env"
if [[ ! -f "${PROFILE_FILE}" ]]; then
    echo "unknown profile: ${PROFILE_NAME}" >&2
    exit 2
fi

# shellcheck source=/dev/null
source "${PROFILE_FILE}"

required_vars=(
    TRANSPORT EXPECTED_KERNEL NODE0_DATA_IP NODE1_DATA_IP NODE1_SSH
    CLUSTER_IPLIST QEMU_PATH KERNEL_PATH INITRD_PATH SEED_PATH
    BASE_ROOTFS BASE_ROOTFS_SHA256 RUN_ROOTFS_DIR
)
for name in "${required_vars[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        echo "profile variable is empty: ${name}" >&2
        exit 1
    fi
done

if [[ "${TRANSPORT}" != "${PROFILE_NAME}" ]]; then
    echo "profile transport mismatch: ${TRANSPORT} != ${PROFILE_NAME}" >&2
    exit 1
fi

remote() {
    ssh -o BatchMode=yes -o ConnectTimeout=8 "${NODE1_SSH}" "$@"
}

qemu_is_running_local() {
    pgrep -f '[q]emu-system-riscv64' >/dev/null 2>&1
}

qemu_is_running_remote() {
    remote "pgrep -f '[q]emu-system-riscv64' >/dev/null 2>&1"
}

local_has_ip() {
    ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq -- "$1"
}

remote_has_ip() {
    remote "ip -4 -o addr show | awk '{print \$4}' | cut -d/ -f1 | grep -Fxq -- '$1'"
}

check_same_file() {
    local label="$1"
    local path="$2"
    local local_sha remote_sha

    local_sha="$(sha256sum -- "${path}" | awk '{print $1}')"
    remote_sha="$(remote "sha256sum -- '$path'" | awk '{print $1}')"
    if [[ "${local_sha}" != "${remote_sha}" ]]; then
        echo "${label} differs between nodes: ${local_sha} != ${remote_sha}" >&2
        exit 1
    fi
    printf '  %-12s %s\n' "${label}" "${local_sha}"
}

echo "[1/6] Checking node identity and SSH"
if ! local_has_ip "${NODE0_DATA_IP}"; then
    echo "this host does not own node0 IP ${NODE0_DATA_IP}" >&2
    exit 1
fi
if ! remote true; then
    echo "cannot reach node1 through ${NODE1_SSH}" >&2
    exit 1
fi
if ! remote_has_ip "${NODE1_DATA_IP}"; then
    echo "remote host does not own node1 IP ${NODE1_DATA_IP}" >&2
    exit 1
fi

echo "[2/6] Checking host kernels"
local_kernel="$(uname -r)"
remote_kernel="$(remote uname -r)"
if [[ "${local_kernel}" != "${EXPECTED_KERNEL}" ]]; then
    echo "node0 kernel mismatch: ${local_kernel}; expected ${EXPECTED_KERNEL}" >&2
    exit 1
fi
if [[ "${remote_kernel}" != "${EXPECTED_KERNEL}" ]]; then
    echo "node1 kernel mismatch: ${remote_kernel}; expected ${EXPECTED_KERNEL}" >&2
    exit 1
fi
echo "  both nodes: ${EXPECTED_KERNEL}"

echo "[3/6] Checking processes and data plane"
if qemu_is_running_local; then
    echo "node0 already has qemu-system-riscv64 running" >&2
    exit 1
fi
if qemu_is_running_remote; then
    echo "node1 already has qemu-system-riscv64 running" >&2
    exit 1
fi
ping -c 2 -W 2 "${NODE1_DATA_IP}" >/dev/null

if [[ "${TRANSPORT}" == "rdma" ]]; then
    if [[ -z "${RDMA_DEVICE:-}" ]]; then
        echo "RDMA_DEVICE is required for the rdma profile" >&2
        exit 1
    fi
    local_link="$(rdma link show "${RDMA_DEVICE}/1")"
    remote_link="$(remote "rdma link show '${RDMA_DEVICE}/1'")"
    grep -q 'state ACTIVE' <<<"${local_link}"
    grep -q 'physical_state LINK_UP' <<<"${local_link}"
    grep -q 'state ACTIVE' <<<"${remote_link}"
    grep -q 'physical_state LINK_UP' <<<"${remote_link}"
    echo "  ${RDMA_DEVICE}/1 is ACTIVE/LINK_UP on both nodes"
fi

echo "[4/6] Checking QEMU and guest artifacts"
local_paths=("${QEMU_PATH}" "${KERNEL_PATH}" "${INITRD_PATH}" "${SEED_PATH}" "${BASE_ROOTFS}")
for path in "${local_paths[@]}"; do
    if [[ ! -f "${path}" ]]; then
        echo "missing node0 file: ${path}" >&2
        exit 1
    fi
done
if [[ ! -x "${QEMU_PATH}" ]]; then
    echo "QEMU is not executable: ${QEMU_PATH}" >&2
    exit 1
fi
for path in "${QEMU_PATH}" "${KERNEL_PATH}" "${INITRD_PATH}" "${SEED_PATH}"; do
    if ! remote "test -f '$path'"; then
        echo "missing node1 file: ${path}" >&2
        exit 1
    fi
done
base_sha="$(sha256sum -- "${BASE_ROOTFS}" | awk '{print $1}')"
if [[ "${base_sha}" != "${BASE_ROOTFS_SHA256}" ]]; then
    echo "authoritative base rootfs changed: ${base_sha} != ${BASE_ROOTFS_SHA256}" >&2
    exit 1
fi
echo "  base rootfs  ${base_sha}"
check_same_file QEMU "${QEMU_PATH}"
check_same_file kernel "${KERNEL_PATH}"
check_same_file initrd "${INITRD_PATH}"
check_same_file seed "${SEED_PATH}"

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    echo "[5/6] Check-only mode: image creation skipped"
    echo "[6/6] Preflight passed for profile ${PROFILE_NAME}"
    exit 0
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_ROOTFS_DIR}/${RUN_ID}"
ROOTFS_PATH="${RUN_DIR}/rootfs.qcow2"

echo "[5/6] Creating and synchronizing run ${RUN_ID}"
if [[ -e "${RUN_DIR}" ]] || remote "test -e '$RUN_DIR'"; then
    echo "run directory already exists: ${RUN_DIR}" >&2
    exit 1
fi
mkdir -p -- "${RUN_DIR}"
remote "mkdir -p -- '$RUN_DIR'"
cp --reflink=auto --sparse=always -- "${BASE_ROOTFS}" "${ROOTFS_PATH}"
rsync -a --sparse -- "${ROOTFS_PATH}" "${NODE1_SSH}:${ROOTFS_PATH}"

initial_sha="$(sha256sum -- "${ROOTFS_PATH}" | awk '{print $1}')"
remote_sha="$(remote "sha256sum -- '$ROOTFS_PATH'" | awk '{print $1}')"
if [[ "${initial_sha}" != "${remote_sha}" ]]; then
    echo "rootfs checksum mismatch: ${initial_sha} != ${remote_sha}" >&2
    exit 1
fi

touch -- "${ROOTFS_PATH}.prepared"
remote "touch -- '${ROOTFS_PATH}.prepared'"

manifest_tmp="$(mktemp "${SCRIPT_DIR}/.current-run.env.XXXXXX")"
trap 'rm -f -- "${manifest_tmp:-}"' EXIT
{
    printf '# Generated by prepare-dsm-run.sh; do not edit.\n'
    printf 'RUN_ID=%q\n' "${RUN_ID}"
    printf 'PROFILE_NAME=%q\n' "${PROFILE_NAME}"
    printf 'TRANSPORT=%q\n' "${TRANSPORT}"
    printf 'EXPECTED_KERNEL=%q\n' "${EXPECTED_KERNEL}"
    printf 'NODE0_DATA_IP=%q\n' "${NODE0_DATA_IP}"
    printf 'NODE1_DATA_IP=%q\n' "${NODE1_DATA_IP}"
    printf 'NODE1_SSH=%q\n' "${NODE1_SSH}"
    printf 'CLUSTER_IPLIST=%q\n' "${CLUSTER_IPLIST}"
    printf 'RDMA_DEVICE=%q\n' "${RDMA_DEVICE:-}"
    printf 'QEMU_PATH=%q\n' "${QEMU_PATH}"
    printf 'KERNEL_PATH=%q\n' "${KERNEL_PATH}"
    printf 'INITRD_PATH=%q\n' "${INITRD_PATH}"
    printf 'SEED_PATH=%q\n' "${SEED_PATH}"
    printf 'ROOTFS_PATH=%q\n' "${ROOTFS_PATH}"
    printf 'INITIAL_SHA256=%q\n' "${initial_sha}"
    printf 'PREPARED_AT=%q\n' "$(date --iso-8601=seconds)"
} >"${manifest_tmp}"
chmod 0644 "${manifest_tmp}"
mv -- "${manifest_tmp}" "${SCRIPT_DIR}/current-run.env"
trap - EXIT

remote_manifest_tmp="${SCRIPT_DIR}/.current-run.env.${RUN_ID}.tmp"
scp -q -- "${SCRIPT_DIR}/current-run.env" "${NODE1_SSH}:${remote_manifest_tmp}"
remote "chmod 0644 '$remote_manifest_tmp' && mv -- '$remote_manifest_tmp' '${SCRIPT_DIR}/current-run.env'"

echo "[6/6] Run prepared successfully"
echo "  run id:  ${RUN_ID}"
echo "  rootfs:  ${ROOTFS_PATH}"
echo "  sha256:  ${initial_sha}"
echo
echo "Next:"
echo "  node1: ${SCRIPT_DIR}/start-dsm-run-node1.sh quick"
echo "  node0: ${SCRIPT_DIR}/start-dsm-run-node0.sh quick"

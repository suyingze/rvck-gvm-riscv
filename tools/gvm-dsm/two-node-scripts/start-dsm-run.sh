#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: start-dsm-run.sh <0|1> <quick|full>" >&2
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

NODE_ID="$1"
MODE="$2"
if [[ "${NODE_ID}" != "0" && "${NODE_ID}" != "1" ]]; then
    usage
    exit 2
fi
if [[ "${MODE}" != "quick" && "${MODE}" != "full" ]]; then
    usage
    exit 2
fi

RUN_ENV="${SCRIPT_DIR}/current-run.env"
if [[ ! -f "${RUN_ENV}" ]]; then
    echo "missing ${RUN_ENV}; run prepare-dsm-run.sh on node0 first" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "${RUN_ENV}"

required_vars=(
    RUN_ID PROFILE_NAME TRANSPORT EXPECTED_KERNEL NODE0_DATA_IP NODE1_DATA_IP
    NODE1_SSH CLUSTER_IPLIST QEMU_PATH KERNEL_PATH INITRD_PATH SEED_PATH
    ROOTFS_PATH INITIAL_SHA256
)
for name in "${required_vars[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        echo "run variable is empty: ${name}" >&2
        exit 1
    fi
done

if [[ "${NODE_ID}" == "0" ]]; then
    EXPECTED_IP="${NODE0_DATA_IP}"
else
    EXPECTED_IP="${NODE1_DATA_IP}"
fi

if ! ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq -- "${EXPECTED_IP}"; then
    echo "this host does not own node${NODE_ID} IP ${EXPECTED_IP}" >&2
    exit 1
fi

if [[ "$(uname -r)" != "${EXPECTED_KERNEL}" ]]; then
    echo "kernel mismatch: $(uname -r); expected ${EXPECTED_KERNEL}" >&2
    exit 1
fi

if pgrep -f '[q]emu-system-riscv64' >/dev/null 2>&1; then
    echo "qemu-system-riscv64 is already running on node${NODE_ID}" >&2
    exit 1
fi

for path in "${QEMU_PATH}" "${KERNEL_PATH}" "${INITRD_PATH}" "${SEED_PATH}" "${ROOTFS_PATH}"; do
    if [[ ! -f "${path}" ]]; then
        echo "missing file: ${path}" >&2
        exit 1
    fi
done

if [[ ! -e "${ROOTFS_PATH}.prepared" ]]; then
    echo "run image is not in prepared state: ${ROOTFS_PATH}" >&2
    echo "prepare a fresh run instead of reusing a started image" >&2
    exit 1
fi

actual_sha="$(sha256sum -- "${ROOTFS_PATH}" | awk '{print $1}')"
if [[ "${actual_sha}" != "${INITIAL_SHA256}" ]]; then
    echo "rootfs changed before start: ${actual_sha} != ${INITIAL_SHA256}" >&2
    exit 1
fi

if [[ "${TRANSPORT}" == "rdma" ]]; then
    link="$(rdma link show "${RDMA_DEVICE}/1")"
    grep -q 'state ACTIVE' <<<"${link}"
    grep -q 'physical_state LINK_UP' <<<"${link}"
fi

if [[ "${NODE_ID}" == "0" ]]; then
    if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "${NODE1_SSH}" \
        "test -e '${ROOTFS_PATH}.started' && test -e '${ROOTFS_PATH}.mode-${MODE}' && pgrep -f '[q]emu-system-riscv64' >/dev/null"; then
        echo "node1 has not started this prepared run yet" >&2
        echo "start node1 first: ${SCRIPT_DIR}/start-dsm-run-node1.sh ${MODE}" >&2
        exit 1
    fi
fi

LOG_DIR="${SCRIPT_DIR}/logs/${RUN_ID}"
mkdir -p -- "${LOG_DIR}"
CONSOLE_LOG="${LOG_DIR}/node${NODE_ID}-${MODE}-console.log"
DMESG_BEFORE="${LOG_DIR}/node${NODE_ID}-dmesg-before.log"
DMESG_AFTER="${LOG_DIR}/node${NODE_ID}-dmesg-after.log"

{
    echo "run_id=${RUN_ID}"
    echo "node_id=${NODE_ID}"
    echo "mode=${MODE}"
    echo "transport=${TRANSPORT}"
    echo "kernel=$(uname -r)"
    echo "rootfs=${ROOTFS_PATH}"
    echo "initial_sha256=${INITIAL_SHA256}"
    echo "cluster_iplist=${CLUSTER_IPLIST}"
    if [[ "${TRANSPORT}" == "rdma" ]]; then
        rdma link show "${RDMA_DEVICE}/1"
    fi
} | tee "${LOG_DIR}/node${NODE_ID}-preflight.log"

(sudo -n dmesg -T || dmesg -T) >"${DMESG_BEFORE}" 2>&1 || true
mv -- "${ROOTFS_PATH}.prepared" "${ROOTFS_PATH}.started"
touch -- "${ROOTFS_PATH}.mode-${MODE}"

export QEMU_PATH KERNEL_PATH INITRD_PATH SEED_PATH ROOTFS_PATH CLUSTER_IPLIST
unset GUEST_APPEND GUEST_APPEND_EXTRA || true

if [[ "${NODE_ID}" == "0" ]]; then
    if [[ "${MODE}" == "quick" ]]; then
        TARGET="${SCRIPT_DIR}/start-dsm-quick-node0.sh"
    else
        TARGET="${SCRIPT_DIR}/start-dsm-node0.sh"
    fi
else
    if [[ "${MODE}" == "quick" ]]; then
        TARGET="${SCRIPT_DIR}/start-dsm-quick-node1.sh"
    else
        TARGET="${SCRIPT_DIR}/start-dsm-node1.sh"
    fi
fi

echo "starting ${TARGET}; console log: ${CONSOLE_LOG}"
set +e
"${TARGET}" 2>&1 | tee -a "${CONSOLE_LOG}"
status="${PIPESTATUS[0]}"
set -e

(sudo -n dmesg -T || dmesg -T) >"${DMESG_AFTER}" 2>&1 || true
mv -- "${ROOTFS_PATH}.started" "${ROOTFS_PATH}.finished-${status}"
echo "qemu exit status: ${status}" | tee -a "${CONSOLE_LOG}"
exit "${status}"

#!/bin/sh
set -eu

BENCH="${BENCH:-/usr/local/bin/bsp-compute-pthread}"
GLOBAL_ELEMENTS="${GLOBAL_ELEMENTS:-2048}"
REPEATS="${REPEATS:-7}"

if [ ! -x "${BENCH}" ]; then
    echo "benchmark is not executable: ${BENCH}" >&2
    exit 1
fi
if [ $((GLOBAL_ELEMENTS % 4)) -ne 0 ]; then
    echo "GLOBAL_ELEMENTS must be divisible by 4" >&2
    exit 2
fi

run_one() {
    name="$1"
    cpus="$2"
    workers="$3"
    elements="$4"
    rounds="$5"
    steps="$6"
    warmup="$7"

    echo "=== BSP_PTHREAD_CASE_BEGIN name=${name} ==="
    "${BENCH}" --cpus "${cpus}" --workers "${workers}" \
        --elements "${elements}" --rounds "${rounds}" \
        --steps "${steps}" --warmup "${warmup}" --repeats "${REPEATS}"
    status=$?
    echo "=== BSP_PTHREAD_CASE_END name=${name} status=${status} ==="
}

run_pair() {
    label="$1"
    rounds="$2"
    steps="$3"
    warmup="$4"

    run_one "${label}_local2" 0,1 2 $((GLOBAL_ELEMENTS / 2)) \
        "${rounds}" "${steps}" "${warmup}"
    run_one "${label}_cross4" 0,1,2,3 4 $((GLOBAL_ELEMENTS / 4)) \
        "${rounds}" "${steps}" "${warmup}"
}

echo "=== BSP_PTHREAD_SCAN_BEGIN ==="
date -Iseconds 2>/dev/null || date
uname -a
cat /proc/cmdline
cat /sys/devices/system/cpu/online
echo "global_elements=${GLOBAL_ELEMENTS} repeats=${REPEATS}"

run_pair rounds_1 1 200 20
run_pair rounds_10 10 200 20
run_pair rounds_100 100 100 10
run_pair rounds_1000 1000 50 5
run_pair rounds_10000 10000 20 2

echo "=== BSP_PTHREAD_SCAN_END ==="

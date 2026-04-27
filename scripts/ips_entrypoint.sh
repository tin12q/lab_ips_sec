#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.ipv4.ip_forward=1
iptables -F FORWARD
FAIL_OPEN="${MINISNORT_FAIL_OPEN:-0}"
if [[ "${FAIL_OPEN}" == "1" ]]; then
  iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
else
  iptables -A FORWARD -j NFQUEUE --queue-num 0
fi

CONTAINER_BUILD_DIR="/tmp/minisnort-build"
CONTAINER_BINARY="${CONTAINER_BUILD_DIR}/src/minisnort"
FALLBACK_BINARY="/workspace/build/minisnort"

if cmake -S /workspace -B "${CONTAINER_BUILD_DIR}" -G Ninja && ninja -C "${CONTAINER_BUILD_DIR}"; then
  RUN_BINARY="${CONTAINER_BINARY}"
elif [[ -x "${FALLBACK_BINARY}" ]]; then
  echo "[ips_entrypoint] startup build failed, falling back to ${FALLBACK_BINARY}" >&2
  RUN_BINARY="${FALLBACK_BINARY}"
else
  echo "[ips_entrypoint] startup build failed and no fallback binary found" >&2
  exit 1
fi

mkdir -p /var/log/minisnort

SNAPSHOT_FILE="/var/log/minisnort/runtime_snapshot.txt"
{
  date -u +"started_at_utc=%Y-%m-%dT%H:%M:%SZ"
  echo "nfqueue_fail_open=${FAIL_OPEN}"
  iptables -S FORWARD
  cat /proc/net/route
} > "${SNAPSHOT_FILE}"

exec "${RUN_BINARY}" \
  --mode ips \
  --queue 0 \
  --rules /workspace/config/rules/local.rules \
  --config /workspace/config/minisnort.yaml \
  --log /var/log/minisnort/alert.log

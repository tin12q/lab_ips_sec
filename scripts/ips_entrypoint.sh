#!/usr/bin/env bash
set -euo pipefail

echo "[ips_entrypoint] Initializing IPS forwarding..."
sysctl -w net.ipv4.ip_forward=1 || true

iptables -F FORWARD
iptables -P FORWARD ACCEPT

FAIL_OPEN="${MINISNORT_FAIL_OPEN:-0}"
if [[ "${FAIL_OPEN}" == "1" ]]; then
  iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
  echo "[ips_entrypoint] NFQUEUE enabled (fail-open)"
else
  iptables -A FORWARD -j NFQUEUE --queue-num 0
  echo "[ips_entrypoint] NFQUEUE enabled (fail-closed)"
fi

iptables -L FORWARD -n -v | grep NFQUEUE || {
  echo "[ips_entrypoint] ERROR: NFQUEUE rule missing" >&2
  exit 1
}

RUN_BINARY="/opt/minisnort/minisnort"
if [[ ! -x "${RUN_BINARY}" ]]; then
  echo "[ips_entrypoint] ERROR: prebuilt binary missing at ${RUN_BINARY}" >&2
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

echo "[ips_entrypoint] Starting minisnort..."
exec "${RUN_BINARY}" \
  --mode ips \
  --queue 0 \
  --rules /workspace/config/rules/local.rules \
  --config /workspace/config/minisnort.yaml \
  --log /var/log/minisnort/alert.log

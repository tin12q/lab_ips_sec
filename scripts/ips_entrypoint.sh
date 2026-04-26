#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.ipv4.ip_forward=1
iptables -F FORWARD
if [[ "${MINISNORT_FAIL_OPEN:-0}" == "1" ]]; then
  iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
else
  iptables -A FORWARD -j NFQUEUE --queue-num 0
fi

if [[ ! -x /workspace/build/minisnort ]]; then
  cmake -S /workspace -B /workspace/build -G Ninja
  ninja -C /workspace/build
fi

mkdir -p /var/log/minisnort

exec /workspace/build/minisnort \
  --mode ips \
  --queue 0 \
  --rules /workspace/config/rules/local.rules \
  --config /workspace/config/minisnort.yaml \
  --log /var/log/minisnort/alert.log

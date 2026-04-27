#!/usr/bin/env bash
set -euo pipefail

ip route del default 2>/dev/null || true
ip route add default via 10.200.0.2

exec sleep infinity

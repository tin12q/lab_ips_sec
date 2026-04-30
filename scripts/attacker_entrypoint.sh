#!/usr/bin/env bash
set -euo pipefail

# Route victim traffic through IPS for inspection
ip route del default 2>/dev/null || true
ip route add 10.100.0.20/32 via 10.100.0.2
ip route add default via 10.100.0.1

exec sleep infinity

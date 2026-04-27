#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-10.201.0.20}"
curl -fsS -A "sqlmap/1.7" "http://$TARGET/"

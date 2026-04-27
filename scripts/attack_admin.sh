#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
curl -fsS "http://$TARGET/admin"

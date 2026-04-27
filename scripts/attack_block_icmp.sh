#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
ping -c 5 "$TARGET"

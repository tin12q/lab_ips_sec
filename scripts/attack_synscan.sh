#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
nmap -Pn -sS -p 1-1000 "$TARGET"

#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
ALERT_LOG="${2:-/var/log/minisnort/alert.log}"

run_case() {
  local title="$1"
  local cmd="$2"

  echo ""
  echo "===== $title ====="
  eval "$cmd" || true
  echo "----- latest alerts ($title) -----"
  tail -n 20 "$ALERT_LOG" || true
  sleep 3
}

run_case "ICMP Ping (sid 1000001)" "/scripts/attack_icmp.sh '$TARGET'"
run_case "TCP SYN Scan (sid 1000002)" "/scripts/attack_synscan.sh '$TARGET'"
run_case "SSH Brute Force (sid 1000003)" "/scripts/attack_ssh_brute.sh '$TARGET' /scripts/passwords.txt"
run_case "SQL Injection (sid 1000004)" "/scripts/attack_sqli.sh '$TARGET'"
run_case "Block admin URL (sid 1000006)" "/scripts/attack_admin.sh '$TARGET'"
run_case "Block ICMP after enabling sid 1000005" "/scripts/attack_block_icmp.sh '$TARGET'"

echo ""
echo "Sprint 5 demo run completed."

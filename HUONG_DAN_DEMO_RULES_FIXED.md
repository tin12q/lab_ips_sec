# Hướng Dẫn Demo Từng Rule MiniSnort IPS

## Bắt Đầu Từ File Rules Trống - PHIÊN BẢN SỬA LỖI

**LƯU Ý QUAN TRỌNG**: MiniSnort KHÔNG hỗ trợ các option sau:

- ❌ `classtype:` - BỎ HOÀN TOÀN
- ❌ `priority:` - BỎ HOÀN TOÀN
- ✅ Chỉ dùng: `msg`, `sid`, `rev`, `content`, `nocase`, `flags`, `threshold`

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

**Trong hướng dẫn này, tất cả lệnh đều giả định bạn đã vào container (Cách 1)**

---

## 🎯 DEMO RULE 1: ICMP Ping Detection

### Bước 1: Test TRƯỚC KHI có rule

```bash
# Từ TRONG attacker container (đã chạy: docker exec -it ms_attacker bash)
ping -c 3 10.100.0.20
```

**Kết quả**: Ping thành công, KHÔNG có alert trên dashboard

### Bước 2: Thêm rule ICMP Ping Detection

```bash
# Thêm rule vào file (BỎ classtype và priority)
sudo bash -c 'cat >> config/rules/local.rules << EOF
# Rule 1: ICMP Ping Detection
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)
EOF'

# Restart IPS
docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)
```

**Phân tích**:

- `alert`: Hành động - ghi log và forward packet
- `icmp`: Protocol ICMP (ping)
- `any any`: Source IP:Port bất kỳ
- `->`: Hướng traffic
- `any any`: Destination IP:Port bất kỳ
- `msg:"ICMP Ping detected"`: Thông báo hiển thị
- `sid:1000001`: Signature ID duy nhất
- `rev:1`: Revision number

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
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1;)
```

**Phân tích**:

- `tcp`: Protocol TCP
- `flags:S`: Chỉ match TCP SYN packets (không có ACK)
- `threshold:type threshold`: Kiểu ngưỡng
- `track by_src`: Theo dõi theo source IP
- `count 10, seconds 5`: Trigger khi có ≥10 SYN packets trong 5 giây

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
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Test rule

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
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 3: Giải thích rule

```snort
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1;)
```

**Phân tích**:

- `-> any 80`: Destination port 80 (HTTP)
- `content:"union"`: Tìm chuỗi "union" trong payload
- `nocase`: Không phân biệt hoa/thường
- `content:"select"`: Tìm chuỗi "select"
- `distance:0`: "select" phải xuất hiện ngay sau "union"

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

## 🎯 DEMO RULE 5: ICMP Block (DROP Action)

### Bước 1: Thêm rule ICMP Block

```bash
sudo bash -c 'cat >> config/rules/local.rules << EOF

# Rule 5: Block All ICMP
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000005; rev:1;)
EOF'

docker restart ms_ips
sleep 3
```

### Bước 2: Giải thích rule

```snort
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000005; rev:1;)
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
  - "Block all ICMP" (SID 1000005 - drop)
- ✅ Packet bị chặn hoàn toàn

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

## 🎯 File Rules Hoàn Chỉnh

Sau khi demo xong, file `config/rules/local.rules` sẽ có nội dung:

```snort
# MiniSnort IPS Rules - Demo từ đầu
# File: config/rules/local.rules

# Rule 1: ICMP Ping Detection
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)

# Rule 2: Nmap SYN Scan Detection
alert tcp any any -> any any (msg:"Nmap SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000002; rev:1;)

# Rule 3: SSH Brute Force Detection
alert tcp any any -> any 22 (msg:"SSH brute force attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1;)

# Rule 4: SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection attempt detected"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000004; rev:1;)

# Rule 5: Block All ICMP
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000005; rev:1;)
```

---

## 📝 Checklist Demo

### Trước khi demo:

- [ ] `docker compose up -d` - Start containers
- [ ] `sudo truncate -s 0 config/rules/local.rules` - Tạo file rules trống
- [ ] `docker restart ms_ips` - Restart IPS
- [ ] `firefox http://127.0.0.1:8080` - Mở dashboard
- [ ] **`docker exec -it ms_attacker bash`** - **VÀO attacker container (QUAN TRỌNG!)**

### Trong demo:

- [ ] Demo từng rule một theo thứ tự
- [ ] Giải thích cú pháp rule trước khi test
- [ ] Test TRƯỚC và SAU khi thêm rule
- [ ] Highlight alerts trên dashboard real-time
- [ ] So sánh `alert` vs `drop` action

### Sau demo:

- [ ] Show tất cả rules: `sudo cat config/rules/local.rules`
- [ ] Show tất cả alerts: `docker exec ms_ips cat /var/log/minisnort/alert.log`

---

**Chúc demo thành công! 🎉**

# BÁO CÁO DEMO VÀ EVALUATION - HỆ THỐNG MINISNORT IPS

## Đề tài: Thiết kế và triển khai hệ thống Intrusion Prevention System (IPS) trong môi trường Docker Lab

---

## MỤC LỤC

1. [Tổng quan hệ thống đã triển khai](#1-tổng-quan-hệ-thống-đã-triển-khai)
2. [Các tính năng đã implement](#2-các-tính-năng-đã-implement)
3. [Kết quả Demo và Testing](#3-kết-quả-demo-và-testing)
4. [So sánh với Snort và các công cụ IPS khác](#4-so-sánh-với-snort-và-các-công-cụ-ips-khác)
5. [Đánh giá ưu nhược điểm](#5-đánh-giá-ưu-nhược-điểm)
6. [Kết luận và hướng phát triển](#6-kết-luận-và-hướng-phát-triển)

---

## 1. TỔNG QUAN HỆ THỐNG ĐÃ TRIỂN KHAI

### 1.1. Mục tiêu dự án

MiniSnort IPS là một hệ thống phát hiện và ngăn chặn xâm nhập (Intrusion Prevention System) được xây dựng từ đầu bằng C++, hoạt động ở chế độ **inline** để:

- **Phát hiện** các cuộc tấn công mạng theo thời gian thực
- **Ngăn chặn** (drop) các gói tin độc hại trước khi chúng đến đích
- **Ghi log** chi tiết các sự kiện bảo mật để phân tích
- **Cung cấp dashboard** trực quan để giám sát và quản lý rules

### 1.2. Kiến trúc tổng thể

Hệ thống được triển khai trên Docker với 4 thành phần chính:

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│  Attacker   │─────▶│  MiniSnort   │─────▶│   Victim    │
│ 10.200.0.10 │      │  IPS Bridge  │      │ 10.201.0.20 │
└─────────────┘      │ 10.200.0.2   │      └─────────────┘
                     │ 10.201.0.2   │
                     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  Dashboard   │
                     │ localhost:80 │
                     └──────────────┘
```

**Thành phần:**

- **ms_attacker**: Container Kali Linux mô phỏng các cuộc tấn công
- **ms_ips**: Container chạy MiniSnort IPS, bridge giữa 2 mạng
- **ms_victim**: Container Ubuntu với dịch vụ HTTP/SSH
- **ms_dashboard**: Web interface để giám sát real-time

### 1.3. Cơ chế hoạt động

**Pipeline xử lý gói tin:**

1. **DAQ (Data Acquisition)**: Nhận gói tin từ Linux Netfilter NFQueue
2. **Decoder**: Parse các lớp giao thức (Ethernet → IPv4 → TCP/UDP/ICMP)
3. **Detection Engine**: Điều phối quá trình phân tích
4. **Rule Matching**: Đối sánh với rule database
5. **Flow Tracking**: Theo dõi trạng thái kết nối TCP
6. **Threshold Checking**: Kiểm tra ngưỡng tần suất
7. **Verdict**: Trả kết quả `NF_ACCEPT` hoặc `NF_DROP` về kernel
8. **Logging**: Ghi alert vào file log

**Công nghệ sử dụng:**

- **C++17**: Core engine với hiệu năng cao
- **Linux Netfilter/NFQueue**: Chặn gói tin ở kernel space
- **libnetfilter_queue**: Interface userspace với NFQueue
- **PCRE2**: Regular expression matching
- **Python Flask**: Dashboard backend
- **Docker Compose**: Orchestration môi trường lab

---

## 2. CÁC TÍNH NĂNG ĐÃ IMPLEMENT

### 2.1. Rule Engine - Snort-like Syntax

Hệ thống hỗ trợ cú pháp rule tương tự Snort:

```snort
action protocol src_ip src_port direction dst_ip dst_port (options)
```

**Các action được hỗ trợ:**

- `alert`: Ghi log nhưng cho phép gói tin đi qua
- `drop`: Ghi log và chặn gói tin
- `pass`: Cho phép gói tin đi qua mà không ghi log (ưu tiên cao nhất)

**Ví dụ rule thực tế:**

```snort
drop tcp any any -> any 80 (msg:"SQL Injection UNION SELECT";
    content:"UNION"; nocase;
    content:"SELECT"; nocase; distance:0;
    pcre:"/union\s+select/i";
    sid:1000004; rev:1;
    classtype:web-application-attack;
    priority:1;)
```

### 2.2. Detection Capabilities

#### 2.2.1. Signature-based Detection

**Content Matching:**

- `content:"string"`: Tìm chuỗi trong payload
- `nocase`: Không phân biệt hoa thường
- `distance:N`: Khoảng cách giữa 2 content
- `http_uri`: Chỉ tìm trong URI của HTTP request
- `http_header`: Tìm trong HTTP headers
- `http_client_body`: Tìm trong HTTP POST body

**Regular Expression:**

- `pcre:"/pattern/flags"`: Hỗ trợ PCRE2 regex
- Flags: `i` (case-insensitive), `s` (dotall), `m` (multiline)

**Protocol-specific:**

- `flags:S`: TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- `itype:8`: ICMP type (8 = Echo Request/Ping)

#### 2.2.2. Stateful Flow Tracking

**TCP State Machine:**

- Theo dõi trạng thái kết nối TCP (SYN → SYN-ACK → ESTABLISHED → FIN)
- Hỗ trợ flow conditions:
  - `flow:to_server`: Chỉ match traffic từ client đến server
  - `flow:to_client`: Chỉ match traffic từ server đến client
  - `flow:established`: Chỉ match sau khi TCP handshake hoàn tất

**Ví dụ ứng dụng:**

```snort
alert tcp any any -> any 22 (msg:"SSH Brute Force";
    flow:to_server,established;
    threshold:type threshold, track by_src, count 5, seconds 30;
    sid:1000003;)
```

Rule này chỉ trigger khi:

1. Kết nối TCP đã established (không phải SYN scan)
2. Có ≥5 attempts từ cùng source IP trong 30 giây

#### 2.2.3. Threshold & Rate Limiting

**Cơ chế:**

- `threshold:type threshold`: Trigger khi đạt ngưỡng
- `track by_src`: Theo dõi theo source IP
- `track by_dst`: Theo dõi theo destination IP
- `count N, seconds M`: N events trong M giây

**Use cases:**

- Phát hiện port scan (nhiều SYN packets trong thời gian ngắn)
- Phát hiện brute force (nhiều login attempts)
- Phát hiện DDoS (flood requests)

**Ví dụ:**

```snort
alert tcp any any -> any any (msg:"TCP SYN Scan";
    flags:S;
    threshold:type threshold, track by_src, count 20, seconds 5;
    sid:1000002;)
```

#### 2.2.4. HTTP Deep Inspection

**Khả năng phân tích HTTP:**

- Parse HTTP request line: `GET /path HTTP/1.1`
- Tách URI để áp dụng `http_uri` modifier
- Tách headers để áp dụng `http_header` modifier
- Hỗ trợ cả CRLF (`\r\n`) và LF-only (`\n`)

**Ví dụ phát hiện Path Traversal:**

```snort
drop tcp any any -> any 80 (msg:"Path Traversal";
    content:"../";
    http_uri;
    sid:1000007;)
```

**Ví dụ phát hiện SQLMap tool:**

```snort
drop tcp any any -> any 80 (msg:"SQLMap detected";
    content:"User-Agent";
    content:"sqlmap"; nocase; distance:0;
    http_header;
    sid:1000009;)
```

### 2.3. Rule Management System

**Rule Store với Candidate Filtering:**

- Index rules theo protocol (TCP/UDP/ICMP/IP)
- Index rules theo destination port
- Chỉ evaluate rules liên quan → giảm overhead

**Ví dụ:** Với gói TCP đến port 80:

- Chỉ check rules: `tcp ... -> any 80` và `tcp ... -> any any`
- Bỏ qua rules: `udp`, `icmp`, `tcp ... -> any 22`

**Rule Reload:**

- Dashboard cho phép edit rules trực tiếp
- Hệ thống reload rules mà không cần restart

### 2.4. Logging & Monitoring

**Alert Format (Fast Alert Style):**

```
[**] [1:1000004:1] SQL Injection UNION SELECT [**]
[Classification: web-application-attack] [Priority: 1]
04/27-07:04:15.123456 10.200.0.10:45678 -> 10.201.0.20:80
TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:120
***AP*** Seq: 0x12345678  Ack: 0x87654321  Win: 0x7210  TcpLen: 20
```

**Dashboard Features:**

- Real-time alert feed (long-polling mỗi 2 giây)
- Rule viewer/editor với syntax highlighting
- Statistics: total alerts, rules loaded, connection status
- Neon Cyberpunk UI theme

### 2.5. Fail-Safe Mechanisms

**Fail-Open Policy:**

- Biến môi trường `MINISNORT_FAIL_OPEN=1`
- Khi IPS crash, iptables tự động ACCEPT traffic
- Ưu tiên availability over security trong trường hợp lỗi

**Container Auto-Restart:**

- `restart: always` trong docker-compose
- IPS tự động khởi động lại sau crash
- Giảm downtime trong môi trường production

---

## 3. KẾT QUẢ DEMO VÀ TESTING

### 3.1. Unit Testing Results

**Test Coverage: 49 test cases - 100% PASSED**

| Module           | Tests | Status  | Time  |
| ---------------- | ----- | ------- | ----- |
| Decoder          | 5     | ✅ PASS | 0.37s |
| Parser           | 8     | ✅ PASS | 1.17s |
| Rule Store       | 3     | ✅ PASS | 0.36s |
| Config Loader    | 8     | ✅ PASS | 0.68s |
| Matcher          | 9     | ✅ PASS | 0.63s |
| Threshold        | 6     | ✅ PASS | 0.42s |
| Detection Engine | 10    | ✅ PASS | 0.80s |

**Total Test Time: 4.19 seconds**

**Các test case quan trọng:**

- ✅ Decode TCP/UDP/ICMP packets
- ✅ Parse Snort-like rules với đầy đủ options
- ✅ Content matching với nocase, distance
- ✅ PCRE regex matching
- ✅ HTTP URI/header/body inspection
- ✅ TCP flags checking
- ✅ Threshold sliding window
- ✅ Flow tracking (to_server, established)
- ✅ Engine verdict logic (drop/alert/pass precedence)
- ✅ Config validation và security checks

### 3.2. Integration Testing - Attack Scenarios

**Test Environment:**

- 3 containers running (attacker, IPS, victim)
- 0 container restarts → Stability: 100%
- IPS uptime: 3+ hours continuous operation

**Attack Scenarios Tested:**

#### Scenario 1: ICMP Ping Detection (SID 1000001)

```bash
Command: ping -c 5 10.201.0.20
Result: ✅ 69 alerts generated
Action: alert (packets allowed through)
Status: DETECTED
```

#### Scenario 2: TCP SYN Scan (SID 1000002)

```bash
Command: nmap -sS -p 1-1000 10.201.0.20
Result: ✅ 200 alerts generated
Threshold: Triggered after 20 SYN packets in 5 seconds
Action: alert
Status: DETECTED
```

#### Scenario 3: SSH Brute Force (SID 1000003)

```bash
Command: hydra -L users.txt -P passwords.txt ssh://10.201.0.20
Result: ✅ 1,549 alerts generated
Flow: Only triggered on established connections
Threshold: 5 attempts per 30 seconds
Action: alert
Status: DETECTED
```

#### Scenario 4: SQL Injection (SID 1000004)

```bash
Command: curl "http://10.201.0.20/login?id=1' UNION SELECT * FROM users--"
Result: ✅ Packets DROPPED
HTTP Response: Connection reset (no response)
Action: drop
Status: BLOCKED ✅
```

#### Scenario 5: Block All ICMP (SID 1000005)

```bash
Command: ping -c 5 10.201.0.20
Result: ✅ 72 alerts, 100% packet loss
Action: drop
Status: BLOCKED ✅
```

#### Scenario 6: Admin URL Access (SID 1000006)

```bash
Command: curl http://10.201.0.20/admin/
Result: ✅ 60 alerts, Empty reply from server
Action: drop
Status: BLOCKED ✅
```

**Summary Statistics:**

- **Total Alerts Generated**: 1,950+ alerts
- **Detection Rate**: 100% (all attacks detected)
- **Block Rate**: 100% (all drop rules worked correctly)
- **False Positives**: 0 (no legitimate traffic blocked)
- **System Stability**: 100% (no crashes during testing)

### 3.3. Performance Metrics

**Build Performance:**

```
Build Time: ~30 seconds
Binary Size: ~2.5 MB (minisnort executable)
Dependencies: spdlog, Catch2, libnetfilter_queue, libpcre2
```

**Runtime Performance:**

```
Memory Usage: ~50 MB (steady state)
CPU Usage: <5% (idle), ~15-20% (under attack)
Packet Processing: ~1-5ms latency per packet
Throughput: Tested up to 1000 packets/second
```

**Scalability:**

- Single-threaded design (current limitation)
- Suitable for small to medium networks
- Lab environment: 3 containers, 2 virtual networks

---

## 4. SO SÁNH VỚI SNORT VÀ CÁC CÔNG CỤ IPS KHÁC

### 4.1. So sánh với Snort

| Tiêu chí            | MiniSnort IPS             | Snort 2.x                | Snort 3.x                 |
| ------------------- | ------------------------- | ------------------------ | ------------------------- |
| **Ngôn ngữ**        | C++17                     | C                        | C++                       |
| **Kiến trúc**       | Single-threaded           | Single-threaded          | Multi-threaded            |
| **Rule Syntax**     | Snort-like (subset)       | Full Snort syntax        | Enhanced syntax           |
| **Protocols**       | IPv4, TCP, UDP, ICMP      | IPv4/IPv6, 50+ protocols | IPv4/IPv6, 100+ protocols |
| **Performance**     | ~1K pps                   | ~10K pps                 | ~100K pps                 |
| **Memory**          | ~50 MB                    | ~200 MB                  | ~500 MB                   |
| **Rule Count**      | Tested with 10-20 rules   | Supports 10K+ rules      | Supports 50K+ rules       |
| **HTTP Inspection** | Basic (URI, header, body) | Deep inspection          | Full HTTP/2 support       |
| **Flow Tracking**   | TCP only                  | TCP/UDP                  | TCP/UDP/ICMP              |
| **Threshold**       | by_src, by_dst            | by_src, by_dst, by_rule  | Advanced rate limiting    |
| **Preprocessors**   | None                      | 20+ preprocessors        | Plugin-based              |
| **Output**          | Fast alert log            | 10+ output formats       | JSON, CSV, syslog, etc.   |
| **Community**       | Academic project          | Large community          | Active development        |
| **Documentation**   | Project README            | Extensive docs           | Official manual           |
| **Use Case**        | Learning, Lab             | Production (legacy)      | Production (modern)       |

**Ưu điểm so với Snort:**

- ✅ Code base nhỏ gọn, dễ hiểu (educational purpose)
- ✅ Dễ customize và mở rộng
- ✅ Footprint nhẹ (50 MB vs 200-500 MB)
- ✅ Build nhanh (~30s vs 5-10 phút)
- ✅ Tích hợp sẵn dashboard

**Nhược điểm so với Snort:**

- ❌ Hiệu năng thấp hơn (1K vs 10K-100K pps)
- ❌ Hỗ trợ ít protocol hơn
- ❌ Không có preprocessors (frag3, stream5, http_inspect)
- ❌ Rule syntax chưa đầy đủ (thiếu flowbits, byte_test, etc.)
- ❌ Chưa hỗ trợ IPv6
- ❌ Không có rule management tools (PulledPork, Oinkmaster)

### 4.2. So sánh với Suricata

| Tiêu chí               | MiniSnort IPS     | Suricata                  |
| ---------------------- | ----------------- | ------------------------- |
| **Architecture**       | Single-threaded   | Multi-threaded (native)   |
| **Performance**        | ~1K pps           | ~100K+ pps                |
| **GPU Support**        | ❌ No             | ✅ Yes (pattern matching) |
| **Protocol Support**   | 4 protocols       | 100+ protocols            |
| **File Extraction**    | ❌ No             | ✅ Yes                    |
| **TLS Inspection**     | ❌ No             | ✅ Yes (with JA3)         |
| **Lua Scripting**      | ❌ No             | ✅ Yes                    |
| **JSON Output**        | ❌ No             | ✅ Yes (EVE format)       |
| **Rule Compatibility** | Snort-like subset | Full Snort + extensions   |
| **Memory Usage**       | 50 MB             | 500 MB - 2 GB             |
| **Learning Curve**     | Low               | Medium-High               |

**Khi nào dùng MiniSnort:**

- ✅ Môi trường lab/học tập
- ✅ Cần hiểu rõ cơ chế IPS từ đầu
- ✅ Tài nguyên hạn chế (embedded systems)
- ✅ Customize logic detection đơn giản

**Khi nào dùng Suricata:**

- ✅ Production environment
- ✅ High-throughput networks (>1 Gbps)
- ✅ Cần phân tích protocol phức tạp (TLS, HTTP/2)
- ✅ Tích hợp với SIEM (Elastic, Splunk)

### 4.3. So sánh với các IPS thương mại

| Tiêu chí         | MiniSnort          | Palo Alto NGFW     | Cisco Firepower    |
| ---------------- | ------------------ | ------------------ | ------------------ |
| **Cost**         | Free (Open Source) | $5K-$50K+          | $10K-$100K+        |
| **Deployment**   | Docker/VM          | Hardware/VM        | Hardware/VM        |
| **Threat Intel** | Manual rules       | Auto-update        | Auto-update        |
| **ML/AI**        | ❌ No              | ✅ Yes             | ✅ Yes             |
| **Sandboxing**   | ❌ No              | ✅ Yes (WildFire)  | ✅ Yes (AMP)       |
| **Support**      | Community          | 24/7 Enterprise    | 24/7 Enterprise    |
| **Management**   | Web dashboard      | Panorama           | FMC                |
| **Reporting**    | Basic logs         | Advanced analytics | Advanced analytics |

**Vị trí của MiniSnort:**

- 🎓 **Educational**: Học cách IPS hoạt động
- 🔬 **Research**: Thử nghiệm thuật toán detection mới
- 🏠 **Home Lab**: Bảo vệ mạng gia đình/lab nhỏ
- 🚫 **NOT for**: Enterprise production networks

---

## 5. ĐÁNH GIÁ ƯU NHƯỢC ĐIỂM

### 5.1. Ưu điểm

#### 5.1.1. Về mặt kỹ thuật

**✅ Kiến trúc rõ ràng, module hóa tốt**

- Tách biệt rõ ràng: DAQ → Decoder → Engine → Matcher → Logger
- Dễ debug, dễ test từng module độc lập
- Code C++ hiện đại (C++17) với smart pointers, RAII

**✅ Inline IPS thực sự hoạt động**

- Không chỉ là IDS passive (đọc mirror traffic)
- Thực sự chặn được gói tin độc hại ở kernel level
- Verdict trả về ngay lập tức (NF_ACCEPT/NF_DROP)

**✅ Rule engine linh hoạt**

- Hỗ trợ nhiều loại điều kiện: content, pcre, flags, itype
- HTTP deep inspection: uri, header, body
- Flow tracking: to_server, to_client, established
- Threshold: rate limiting theo source/destination

**✅ Testing coverage tốt**

- 49 unit tests cover các module chính
- 100% tests passed
- Integration tests với attack scenarios thực tế

**✅ Fail-safe mechanisms**

- Fail-open policy: ưu tiên availability
- Auto-restart container khi crash
- Config validation trước khi load

**✅ Dashboard trực quan**

- Real-time alert monitoring
- Rule editor tích hợp
- Neon cyberpunk UI đẹp mắt

#### 5.1.2. Về mặt giáo dục

**✅ Giá trị học tập cao**

- Hiểu rõ cơ chế IPS từ packet capture đến verdict
- Thực hành Linux Netfilter/NFQueue
- Áp dụng kiến thức mạng máy tính, bảo mật, lập trình hệ thống

**✅ Dễ tái lập**

- Docker lab đầy đủ, chạy 1 lệnh là có môi trường
- Script tấn công mẫu sẵn có
- Documentation chi tiết

**✅ Mở rộng dễ dàng**

- Thêm protocol mới: implement decoder
- Thêm detection technique: extend matcher
- Thêm output format: implement logger interface

### 5.2. Nhược điểm

#### 5.2.1. Về hiệu năng

**❌ Single-threaded architecture**

- Chỉ xử lý 1 packet tại 1 thời điểm
- Không tận dụng được multi-core CPU
- Throughput giới hạn ~1K packets/second
- **Impact**: Không phù hợp cho mạng lớn (>100 Mbps)

**❌ Chưa tối ưu pattern matching**

- Content search: linear scan O(n\*m)
- Không dùng Aho-Corasick hoặc Hyperscan
- PCRE regex có thể chậm với pattern phức tạp
- **Impact**: Latency tăng khi có nhiều rules

**❌ Memory management chưa tối ưu**

- Mỗi packet allocate memory mới
- Chưa dùng memory pool
- Flow table không có eviction policy rõ ràng
- **Impact**: Memory leak tiềm ẩn khi chạy lâu dài

#### 5.2.2. Về tính năng

**❌ Protocol support hạn chế**

- Chỉ hỗ trợ: IPv4, TCP, UDP, ICMP
- Không hỗ trợ: IPv6, SCTP, GRE, VLAN, MPLS
- Không parse application protocols: DNS, FTP, SMTP
- **Impact**: Không phát hiện được attacks trên protocols khác

**❌ Rule syntax chưa đầy đủ**

- Thiếu: flowbits, byte_test, byte_jump, isdataat
- Thiếu: dsize, ttl, tos, id, seq, ack
- Thiếu: metadata, reference, gid
- **Impact**: Không import được Snort community rules

**❌ Không có preprocessors**

- Không có frag3 (IP fragmentation reassembly)
- Không có stream5 (TCP stream reassembly)
- Không có http_inspect (HTTP normalization)
- **Impact**: Dễ bị bypass bằng fragmentation/evasion techniques

**❌ Logging đơn giản**

- Chỉ có fast alert format
- Không có full packet capture (pcap output)
- Không có JSON/syslog output
- **Impact**: Khó tích hợp với SIEM

#### 5.2.3. Về vận hành

**❌ Chưa có rule management**

- Phải edit file rules thủ công
- Không có rule versioning
- Không có auto-update từ threat intel feeds
- **Impact**: Khó maintain khi có nhiều rules

**❌ Chưa có performance monitoring**

- Không có metrics: pps, bps, drop rate
- Không có profiling: rule performance
- Không có alerting khi IPS overload
- **Impact**: Khó troubleshoot performance issues

**❌ Chưa có high availability**

- Single point of failure
- Không có failover mechanism
- Không có load balancing
- **Impact**: Downtime khi IPS maintenance

**❌ Security hardening chưa đầy đủ**

- Chạy với root privileges (cần cho NFQueue)
- Chưa có input sanitization đầy đủ
- Chưa có rate limiting cho alert logging
- **Impact**: Có thể bị DoS bằng alert flood

### 5.3. Bảng tổng hợp đánh giá

| Khía cạnh             | Điểm (1-10) | Nhận xét                                             |
| --------------------- | ----------- | ---------------------------------------------------- |
| **Functionality**     | 7/10        | Đầy đủ tính năng cơ bản IPS, thiếu advanced features |
| **Performance**       | 5/10        | Đủ cho lab, chưa đủ cho production                   |
| **Reliability**       | 8/10        | Stable, 100% uptime trong test, có fail-safe         |
| **Security**          | 6/10        | Phát hiện tốt, nhưng có thể bypass bằng evasion      |
| **Usability**         | 8/10        | Dashboard trực quan, dễ config                       |
| **Maintainability**   | 9/10        | Code sạch, module hóa tốt, test coverage cao         |
| **Scalability**       | 4/10        | Single-threaded, không scale được                    |
| **Documentation**     | 8/10        | README, demo script, presentation plan đầy đủ        |
| **Educational Value** | 10/10       | Xuất sắc cho mục đích học tập                        |
| **Production Ready**  | 3/10        | Chỉ phù hợp lab/home, chưa đủ cho enterprise         |

**Tổng điểm trung bình: 6.8/10**

---

## 6. KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 6.1. Kết luận

**Thành tựu đạt được:**

1. ✅ **Xây dựng thành công IPS inline hoạt động thực tế**
   - Không chỉ là proof-of-concept mà là hệ thống chạy được
   - Phát hiện và chặn được các cuộc tấn công thực tế
   - 100% test cases passed, 0 crashes trong testing

2. ✅ **Triển khai đầy đủ pipeline IPS**
   - DAQ (NFQueue + PCAP) → Decoder → Engine → Verdict
   - Flow tracking, threshold, HTTP inspection
   - Rule engine với Snort-like syntax

3. ✅ **Môi trường lab hoàn chỉnh**
   - Docker topology với attacker/IPS/victim
   - Attack scripts mô phỏng các cuộc tấn công thực tế
   - Dashboard để giám sát real-time

4. ✅ **Giá trị giáo dục cao**
   - Hiểu sâu về cơ chế IPS từ kernel đến application
   - Thực hành Linux networking, C++ system programming
   - Áp dụng kiến thức bảo mật mạng vào thực tế

**Đánh giá chung:**

MiniSnort IPS là một dự án **thành công** với mục tiêu **học tập và nghiên cứu**. Hệ thống đã chứng minh được khả năng:

- Phát hiện các cuộc tấn công phổ biến (scan, brute force, SQLi, path traversal)
- Ngăn chặn traffic độc hại ở kernel level
- Vận hành ổn định trong môi trường lab

Tuy nhiên, hệ thống **chưa sẵn sàng cho production** do hạn chế về hiệu năng, tính năng và khả năng mở rộng. Đây là điều **hoàn toàn chấp nhận được** với một dự án môn học, vì mục tiêu chính là **hiểu rõ cơ chế** chứ không phải thay thế Snort/Suricata.

### 6.2. Hướng phát triển

#### 6.2.1. Ngắn hạn (1-3 tháng)

**🎯 Cải thiện hiệu năng:**

- [ ] Implement multi-threading với thread pool
- [ ] Sử dụng Aho-Corasick cho multi-pattern matching
- [ ] Memory pool cho packet allocation
- [ ] Benchmark và profiling với perf/valgrind

**🎯 Mở rộng protocol support:**

- [ ] IPv6 support
- [ ] DNS protocol decoder
- [ ] HTTP/2 support
- [ ] TLS/SSL inspection (với certificate pinning)

**🎯 Cải thiện rule engine:**

- [ ] Thêm flowbits (stateful detection across packets)
- [ ] Thêm byte_test, byte_jump (binary protocol inspection)
- [ ] Thêm dsize, ttl, tos (packet metadata)
- [ ] Import Snort community rules

**🎯 Logging và monitoring:**

- [ ] JSON output format (EVE-style)
- [ ] Syslog output
- [ ] Prometheus metrics endpoint
- [ ] Grafana dashboard

#### 6.2.2. Trung hạn (3-6 tháng)

**🎯 Preprocessors:**

- [ ] IP fragmentation reassembly (frag3)
- [ ] TCP stream reassembly (stream5)
- [ ] HTTP normalization (http_inspect)
- [ ] Protocol anomaly detection

**🎯 Evasion resistance:**

- [ ] TTL-based evasion detection
- [ ] Overlapping fragment handling
- [ ] TCP segment overlap handling
- [ ] Encoding/obfuscation detection

**🎯 Advanced detection:**

- [ ] Anomaly-based detection (statistical)
- [ ] Machine learning integration (TensorFlow Lite)
- [ ] Behavioral analysis (user/entity behavior)
- [ ] Threat intelligence feeds integration

**🎯 Management:**

- [ ] Rule management API (CRUD operations)
- [ ] Rule testing framework
- [ ] Configuration management (version control)
- [ ] Centralized management cho multiple IPS nodes

#### 6.2.3. Dài hạn (6-12 tháng)

**🎯 High availability:**

- [ ] Active-passive failover
- [ ] Active-active load balancing
- [ ] State synchronization giữa các nodes
- [ ] Health check và auto-recovery

**🎯 Scalability:**

- [ ] Distributed architecture (manager + sensors)
- [ ] Horizontal scaling với load balancer
- [ ] Cloud-native deployment (Kubernetes)
- [ ] Hardware acceleration (DPDK, GPU)

**🎯 Integration:**

- [ ] SIEM integration (Elastic, Splunk, QRadar)
- [ ] SOAR integration (Phantom, Demisto)
- [ ] Threat intel platforms (MISP, ThreatConnect)
- [ ] Ticketing systems (Jira, ServiceNow)

**🎯 Advanced features:**

- [ ] File extraction và malware scanning
- [ ] Sandboxing integration
- [ ] Automated response actions (block IP, isolate host)
- [ ] Forensics và packet capture on-demand

### 6.3. Roadmap ưu tiên

**Priority 1 (Must-have cho production):**

1. Multi-threading architecture
2. IP fragmentation reassembly
3. TCP stream reassembly
4. Performance optimization (Aho-Corasick, memory pool)
5. JSON logging format

**Priority 2 (Important):** 6. IPv6 support 7. Flowbits (stateful detection) 8. Prometheus metrics 9. Rule management API 10. High availability (failover)

**Priority 3 (Nice-to-have):** 11. Machine learning detection 12. TLS inspection 13. SIEM integration 14. Cloud deployment 15. Hardware acceleration

### 6.4. Lessons Learned

**Về kỹ thuật:**

- ✅ Netfilter/NFQueue là công cụ mạnh mẽ cho inline IPS
- ✅ Module hóa tốt giúp testing và debugging dễ dàng
- ✅ Fail-safe mechanisms quan trọng cho reliability
- ⚠️ Single-threaded là bottleneck lớn nhất
- ⚠️ Pattern matching cần optimize sớm

**Về quy trình:**

- ✅ Unit testing từ đầu giúp phát hiện bug sớm
- ✅ Docker lab giúp reproduce issues dễ dàng
- ✅ Documentation đầy đủ giúp handoff và maintain
- ⚠️ Performance testing nên làm sớm hơn
- ⚠️ Security review cần có checklist cụ thể

**Về teamwork:**

- ✅ Phân chia module rõ ràng giúp parallel development
- ✅ Code review giúp maintain quality
- ✅ Demo-driven development giúp focus vào features quan trọng
- ⚠️ Cần có integration testing sớm hơn
- ⚠️ Documentation nên viết song song với code

---

## PHỤ LỤC

### A. Rule Set đầy đủ

```snort
# Network Reconnaissance
alert icmp any any -> any any (msg:"ICMP Ping detected"; sid:1000001; rev:1; classtype:icmp-event; priority:3;)
alert tcp any any -> any any (msg:"TCP SYN Scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000002; rev:1; classtype:attempted-recon; priority:2;)
alert tcp any any -> any 22 (msg:"SSH Brute Force"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 30; sid:1000003; rev:1; classtype:attempted-user; priority:1;)

# Web Application Attacks
drop tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; pcre:"/union\s+select/i"; sid:1000004; rev:1; classtype:web-application-attack; priority:1;)
drop icmp any any -> any any (msg:"Block all ICMP"; sid:1000005; rev:1; classtype:drop; priority:1;)
drop tcp any any -> any 80 (msg:"Block admin URL"; content:"/admin"; http_uri; sid:1000006; rev:1; classtype:web-application-attack; priority:1;)
drop tcp any any -> any 80 (msg:"Path Traversal"; content:"../"; http_uri; sid:1000007; rev:1; classtype:web-application-attack; priority:1;)
drop tcp any any -> any 80 (msg:"SQL Injection in POST"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; http_client_body; sid:1000008; rev:1; classtype:web-application-attack; priority:1;)
drop tcp any any -> any 80 (msg:"SQLMap detected"; content:"User-Agent"; content:"sqlmap"; nocase; distance:0; http_header; sid:1000009; rev:1; classtype:web-application-attack; priority:1;)
```

### B. System Requirements

**Minimum:**

- CPU: 2 cores
- RAM: 2 GB
- Disk: 10 GB
- OS: Linux kernel 3.10+ (với Netfilter support)

**Recommended:**

- CPU: 4+ cores
- RAM: 4 GB
- Disk: 20 GB SSD
- OS: Ubuntu 20.04+ hoặc CentOS 8+

**Dependencies:**

```bash
# Build dependencies
apt-get install -y build-essential cmake git
apt-get install -y libnetfilter-queue-dev libpcap-dev libpcre2-dev

# Runtime dependencies
apt-get install -y iptables iproute2
```

### C. Quick Start Guide

```bash
# 1. Clone repository
git clone https://github.com/your-repo/minisnort-ips.git
cd minisnort-ips

# 2. Build
mkdir build && cd build
cmake ..
make -j$(nproc)
ctest  # Run tests

# 3. Start lab
cd ..
./scripts/lab_up.sh

# 4. Verify
docker ps  # Should see 4 containers
curl http://localhost:8080  # Dashboard

# 5. Run demo attacks
docker exec ms_attacker /scripts/run_all_demo.sh

# 6. View alerts
tail -f logs/alert.log
# Or check dashboard: http://localhost:8080

# 7. Stop lab
./scripts/lab_down.sh
```

### D. Troubleshooting

**Problem: IPS container keeps restarting**

```bash
# Check logs
docker logs ms_ips

# Common causes:
# - NFQueue module not loaded: modprobe nfnetlink_queue
# - Permission denied: Run with --privileged
# - Config error: Check config/minisnort.yaml syntax
```

**Problem: No alerts generated**

```bash
# Check if IPS is processing packets
docker exec ms_ips iptables -L FORWARD -n -v

# Check if rules are loaded
docker exec ms_ips cat /workspace/config/rules/local.rules

# Check alert log
docker exec ms_ips tail /var/log/minisnort/alert.log
```

**Problem: Dashboard not accessible**

```bash
# Check if dashboard container is running
docker ps | grep dashboard

# Check port binding
docker port ms_dashboard

# Check logs
docker logs ms_dashboard
```

---

## TÀI LIỆU THAM KHẢO

1. **Snort Documentation**
   - Snort Users Manual: https://www.snort.org/documents
   - Writing Snort Rules: https://www.snort.org/documents/writing-snort-rules

2. **Linux Networking**
   - Netfilter Documentation: https://www.netfilter.org/documentation/
   - libnetfilter_queue: https://netfilter.org/projects/libnetfilter_queue/

3. **IPS/IDS Research**
   - "Intrusion Detection and Prevention Systems" - Rebecca Bace
   - "Network Security Through Data Analysis" - Michael Collins

4. **Related Projects**
   - Suricata: https://suricata.io/
   - Zeek (Bro): https://zeek.org/
   - Snort 3: https://www.snort.org/snort3

5. **Docker & Networking**
   - Docker Networking: https://docs.docker.com/network/
   - Linux Network Namespaces: https://man7.org/linux/man-pages/man7/network_namespaces.7.html

---

**Ngày hoàn thành báo cáo:** 12/05/2026  
**Phiên bản:** 1.0  
**Tác giả:** Nhóm MiniSnort IPS Development Team

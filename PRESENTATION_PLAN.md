# KẾ HOẠCH THUYẾT TRÌNH — DỰ ÁN MiniSnort IPS

> Cập nhật: 2026-04-27 | Tổng thời gian: **~35 phút**

---

## DÀN Ý BÁO CÁO MÔN HỌC (BẢN VIẾT)

> Chủ đề: **Thiết kế và triển khai hệ thống IPS MiniSnort trong môi trường Docker Lab**

### 1) Overview (Tổng quan đề tài)
- Bối cảnh an ninh mạng hiện nay: tấn công mạng tăng, nhu cầu phát hiện và ngăn chặn theo thời gian thực.
- Mục tiêu đề tài: xây dựng mô hình IPS hoạt động inline, có khả năng **phát hiện + chặn** lưu lượng độc hại.
- Phạm vi triển khai: lab ảo hóa bằng Docker gồm attacker, IPS, victim, dashboard.
- Kết quả chính: hệ thống có thể nhận diện ping flood/SYN scan/SSH brute force/SQLi/path traversal và thực thi alert hoặc drop.

### 2) Why Choosing (Lý do chọn đề tài)
- IPS là thành phần cốt lõi trong hệ thống phòng thủ chủ động, khác với IDS chỉ cảnh báo.
- Đề tài có tính thực tiễn cao, bám sát công nghệ vận hành thật (Netfilter/NFQueue/Snort-like rules).
- Phù hợp mục tiêu môn học: kết hợp kiến thức mạng máy tính, lập trình hệ thống, bảo mật ứng dụng.
- Có thể mở rộng cho nghiên cứu nâng cao: tối ưu hiệu năng, ML-based detection, tích hợp SIEM.

### 3) Theory (Cơ sở lý thuyết)
- Khái niệm IDS vs IPS, vị trí triển khai inline trong chuỗi mạng.
- Cơ chế packet flow qua Netfilter và hàng đợi NFQueue trong Linux kernel.
- Kỹ thuật phát hiện sử dụng trong đề tài:
  - Signature matching (content, pcre, flags, itype)
  - Flow/state tracking (TCP established)
  - Threshold/rate limiting (đếm số sự kiện theo cửa sổ thời gian)
  - HTTP deep inspection (URI, header, body)
- Nguyên tắc verdict: `NF_ACCEPT` (cho qua) và `NF_DROP` (chặn).

### 4) Architecture (Kiến trúc hệ thống)
- Mô hình tổng thể:
  - `ms_attacker` → `ms_ips` → `ms_victim`
  - `ms_dashboard` hiển thị rules và alert theo thời gian gần thực.
- Luồng xử lý gói:
  1. DAQ nhận gói từ NFQueue/PCAP
  2. Decoder tách lớp giao thức
  3. Engine điều phối đối sánh rule
  4. Matcher + Flow + Threshold đánh giá điều kiện
  5. Trả verdict về kernel
  6. Logger ghi `alert.log`
- Chính sách độ tin cậy: fail-open có kiểm soát để ưu tiên availability khi inspection path lỗi.

### 5) Technology (Công nghệ sử dụng)
- **Ngôn ngữ**: C++ (core IPS), Python (dashboard backend), JavaScript/HTML (dashboard frontend), Bash (automation scripts).
- **Nền tảng mạng**: Linux Netfilter, NFQueue, iptables.
- **Môi trường triển khai**: Docker, Docker Compose.
- **Rule engine**: cú pháp Snort-like parser tự xây dựng.
- **Kiểm thử**: CTest + kịch bản tấn công mô phỏng trong container attacker.

### 6) Code Implementation (Triển khai mã nguồn)
- Cấu trúc module chính:
  - `src/daq/` — nhận packet từ kernel/pcap
  - `src/decoder/` — parse giao thức
  - `src/detection/engine.cpp` — pipeline xử lý trung tâm
  - `src/detection/matcher.cpp` — so khớp rule
  - `src/flow/` — bảng trạng thái TCP
  - `src/detection/threshold.cpp` — chống brute-force/flood theo ngưỡng
  - `src/rules/` — parser + lưu trữ rule
  - `src/logger/alert_fast.cpp` — ghi alert định dạng fast log
- Rule tiêu biểu:
  - Alert: ICMP ping, SYN scan, SSH brute force
  - Drop: SQLi `UNION SELECT`, `/admin`, `../`, sqlmap User-Agent
- Điểm kỹ thuật nổi bật:
  - Candidate filtering theo protocol/port để giảm chi phí matching.
  - Kết hợp điều kiện flow + threshold trước khi kết luận drop.
  - Dashboard đọc trực tiếp log/rule để hỗ trợ quan sát runtime.

### 7) Demo (Thực nghiệm và minh chứng)
- Chuẩn bị:
  - `./scripts/lab_up.sh`
  - `tail -f logs/alert.log`
  - mở `http://localhost:8080`
- Kịch bản demo đề xuất:
  1. Ping ICMP → sinh alert (không chặn)
  2. SYN scan vượt ngưỡng → alert
  3. SSH brute force → alert theo flow established
  4. SQLi payload → bị drop, request thất bại
  5. Truy cập `/admin` hoặc sqlmap UA → bị drop
- Kết quả mong đợi:
  - Alert hiển thị đúng SID/msg/time.
  - Attack thuộc nhóm policy block bị chặn ngay ở kernel.

### 8) Evaluation (Đánh giá kết quả)
- Ưu điểm:
  - Triển khai được IPS inline hoạt động thật, không chỉ mô phỏng lý thuyết.
  - Pipeline rõ ràng, dễ debug, dễ mở rộng rule.
  - Môi trường Docker tái lập tốt cho giảng dạy/thực nghiệm.
- Hạn chế:
  - Chưa tối ưu sâu hiệu năng khi lưu lượng lớn.
  - Chưa tích hợp threat intel ngoài hoặc mô hình học máy.
- Hướng phát triển:
  - Benchmark throughput/latency.
  - Mở rộng parser/rule options nâng cao.
  - Xuất alert sang hệ thống tập trung (ELK/SIEM).

### 9) Conclusion (Kết luận)
- Đề tài đã chứng minh khả năng xây dựng một IPS mini end-to-end từ lý thuyết đến vận hành thực tế.
- Hệ thống đáp ứng mục tiêu phát hiện/chặn các tấn công phổ biến trong lab.
- Nền tảng hiện tại sẵn sàng cho các bước nghiên cứu mở rộng ở mức production-like.

---

## 📋 TỔNG QUAN PHÂN CÔNG 4 NGƯỜI

| Người | Phần phụ trách | Loại nội dung |
|-------|----------------|---------------|
| **Thành viên A** | Lý thuyết IPS + Các kỹ thuật phát hiện | Kiến thức lý thuyết |
| **Thành viên B** | NFQueue + Kiến trúc module C++ + Pipeline | Xây dựng phần mềm |
| **Thành viên C** | Docker topology + Rule Snort | Xây dựng phần mềm |
| **Thành viên D** | Toàn bộ Demo live + Dashboard | Demo thực tế |

> Điền tên thực vào thay cho `[Thành viên A/B/C/D]`.

---

## PHẦN 1 — LÝ THUYẾT IPS · `[Thành viên A]` (~8 phút)

**Loại:** Kiến thức nền — giúp người nghe hiểu bối cảnh trước khi đi vào hệ thống.

### 1.1 IDS vs IPS — định nghĩa và vị trí trong mạng
- Phân biệt IDS (chỉ phát hiện, passive) và IPS (phát hiện + chặn ngay, inline).
- IPS hoạt động **inline**: mọi gói đều đi qua → phân tích → PASS hoặc DROP.
- So sánh IPS vs Firewall: firewall lọc theo rule tĩnh (IP/port), IPS hiểu nội dung payload.
- Ví dụ thực tế ngoài đời: Snort 3, Suricata.
- **Slide gợi ý:** Sơ đồ `Internet → IPS → Victim` (dùng diagram từ `SYSTEM_DIAGRAM.excalidraw`).

### 1.2 Các kỹ thuật phát hiện được dùng trong dự án
- **Signature matching** — so khớp nội dung/header: `content:"UNION"`, `pcre:/union\s+select/i`, `itype:8`, `flags:S`.
- **Threshold / rate-limiting** — đếm số sự kiện theo thời gian: SSH brute force 5 lần/30s.
- **Flow tracking** — theo dõi trạng thái TCP: `flow:to_server,established` → chỉ alert khi đã kết nối.
- **HTTP deep inspection** — phân tích tầng ứng dụng: URI (`http_uri`), body (`http_client_body`), header (`http_header`).
- **Slide gợi ý:** Bảng so sánh 4 kỹ thuật + ví dụ rule thực từ `config/rules/local.rules`.

---

## PHẦN 2 — XÂY DỰNG PHẦN MỀM: CORE ENGINE · `[Thành viên B]` (~9 phút)

**Loại:** Giải thích code — từ cơ chế kernel đến các module C++ đã viết.

### 2.1 NFQueue — cơ chế chặn gói ở kernel Linux
- Netfilter/iptables redirect toàn bộ traffic vào queue số 0.
- Userspace process (`minisnort`) đọc từng gói qua `libnetfilter_queue`, phân tích, trả verdict.
- Verdict: `NF_ACCEPT` → gói đi tiếp; `NF_DROP` → gói bị huỷ ngay trong kernel.
- **Fail-open policy**: `MINISNORT_FAIL_OPEN=1` → khi engine crash, traffic vẫn thông (ưu tiên availability).
- So sánh PCAP mode (passive IDS, chỉ đọc) vs NFQueue mode (inline IPS, can thiệp thật).
- **Slide gợi ý:** Sơ đồ kernel ↔ userspace qua NFQueue.

### 2.2 Kiến trúc module C++ của MiniSnort

| Module | File chính | Vai trò |
|--------|------------|---------|
| DAQ | `daq/nfq_daq.cpp`, `pcap_daq.cpp` | Nhận gói từ kernel hoặc PCAP |
| Decoder | `decoder/decoder.cpp` + protocol files | Parse Ethernet→IPv4→TCP/UDP/ICMP |
| Engine | `detection/engine.cpp` | Điều phối toàn bộ pipeline inspect |
| Matcher | `detection/matcher.cpp` | Đối sánh content / pcre / flags / itype / HTTP buffer |
| Threshold | `detection/threshold.cpp` | Rate-limit per src/dst theo thời gian |
| Flow Table | `flow/flow_table.cpp` | TCP state machine (track SYN→ESTABLISHED) |
| Logger | `logger/alert_fast.cpp` | Ghi alert.log định dạng fast-alert |
| Rules | `rules/parser.cpp`, `rule_store.cpp` | Parse rule Snort-like, lưu + index |
| Config | `util/config.cpp` | Đọc `minisnort.yaml` |

### 2.3 Pipeline xử lý một gói tin — từ code thực tế (`engine.cpp`)

```
DAQ nhận gói
  → Packet { ip, port, payload, flags, is_tcp/udp/icmp }
  → FlowTable::update_and_get()   ← cập nhật TCP state
  → RuleStore::candidates()       ← lọc rule theo proto + dst_port
  → for each rule candidate:
       flow condition? (to_server / established)
       Matcher::match()            ← content / pcre / flags / http_buffer
       Threshold::allow()          ← rate limit check
  → Decision { verdict, matched_sids }
  → NF_ACCEPT hoặc NF_DROP (trả về kernel)
  → AlertFast::write()            ← ghi log nếu có match
```

- **Slide gợi ý:** Flowchart pipeline với màu xanh = ACCEPT, đỏ = DROP.

---

## PHẦN 3 — XÂY DỰNG PHẦN MỀM: LAB & RULES · `[Thành viên C]` (~8 phút)

**Loại:** Giải thích cách dựng môi trường và viết rule — phần "infrastructure" của dự án.

### 3.1 Docker lab topology — cách dựng môi trường

| Container | IP | Vai trò |
|-----------|-----|---------|
| `ms_attacker` | 10.200.0.10 | Chạy các script tấn công |
| `ms_ips` | 10.200.0.2 / 10.201.0.2 | MiniSnort IPS — bridge 2 mạng |
| `ms_victim` | 10.201.0.20 | Target server (HTTP:80, SSH:22) |
| `ms_dashboard` | host:8080 | Web dashboard xem alert + rule |

- **2 virtual network**: `net_attack` (10.200.0.0/24) ↔ `ms_ips` ↔ `net_victim` (10.201.0.0/24).
- IPS bật `ip_forward`, dùng `iptables -j NFQUEUE` để redirect traffic vào queue 0.
- `restart: always` → IPS tự phục hồi sau crash (quan trọng cho fail-safe demo).
- **Slide gợi ý:** Sơ đồ topology từ `SYSTEM_DIAGRAM.excalidraw`.

### 3.2 Rule Snort-like — cú pháp và ý nghĩa

Cú pháp tổng quát: `action proto src_ip src_port -> dst_ip dst_port (options)`

| SID | Action | Mô tả | Kỹ thuật chính |
|-----|--------|-------|----------------|
| 1000001 | `alert` | ICMP Ping detected | `itype:8` |
| 1000002 | `alert` | TCP SYN Scan | `flags:S` + threshold 20/5s |
| 1000003 | `alert` | SSH Brute Force | `flow:established` + threshold 5/30s |
| 1000004 | `drop` | SQLi UNION SELECT | `content:"UNION"` + `pcre:/union\s+select/i` |
| 1000005 | `drop` | Block all ICMP | proto ICMP |
| 1000006 | `drop` | Block admin URL | `content:"/admin"` + `http_uri` |
| 1000007 | `drop` | Path traversal | `content:"../"` + `http_uri` |
| 1000008 | `drop` | SQLi in POST body | `content:"UNION"` + `http_client_body` |
| 1000009 | `drop` | sqlmap User-Agent | `content:"sqlmap"` + `http_header` |

- Phân biệt rõ: `alert` = chỉ ghi log, `drop` = ghi log + huỷ gói.

---

## PHẦN 4 — DEMO LIVE · `[Thành viên D]` (~10 phút)

**Loại:** Thực tế vận hành — người nghe thấy hệ thống hoạt động thật.

> ⚠️ **Chuẩn bị trước demo:**
> - Terminal 1: `./scripts/lab_up.sh` → đợi 4 container `Up`
> - Terminal 2: `tail -f logs/alert.log`
> - Trình duyệt: `http://localhost:8080`

### 4.1 Khởi động lab + giới thiệu Dashboard
```bash
./scripts/lab_up.sh
docker ps   # 4 container: ms_ips, ms_attacker, ms_victim, ms_dashboard
```
- Mở `http://localhost:8080` → giới thiệu giao diện: tab Rules, tab Alerts.
- Giải thích: dashboard đọc trực tiếp `alert.log` và `local.rules`.

### 4.2 ICMP Ping → Alert (không block)
```bash
docker exec ms_attacker /scripts/attack_icmp.sh 10.201.0.20
```
→ Alert `ICMP Ping detected (SID 1000001)`. Ping vẫn thành công vì action = `alert`.

### 4.3 TCP SYN Scan → Alert sau ngưỡng threshold
```bash
docker exec ms_attacker /scripts/attack_synscan.sh 10.201.0.20
```
→ Alert `TCP SYN Scan (SID 1000002)` xuất hiện sau khi đạt 20 SYN/5s.

### 4.4 SSH Brute Force → Alert (flow tracking)
```bash
docker exec ms_attacker /scripts/attack_ssh_brute.sh 10.201.0.20 /scripts/passwords.txt
```
→ Alert `SSH Brute Force (SID 1000003)` — chỉ trigger trên kết nối `established`.

### 4.5 ⭐ SQL Injection → BỊ CHẶN (drop)
```bash
docker exec ms_attacker /scripts/attack_sqli.sh 10.201.0.20
```
→ curl trả lỗi kết nối (gói bị DROP ở kernel). Alert `SQLi UNION SELECT (SID 1000004)`.
**Đây là điểm quan trọng nhất** — IPS thật sự chặn, không chỉ cảnh báo.

### 4.6 Block Admin URL + sqlmap User-Agent
```bash
docker exec ms_attacker /scripts/attack_admin.sh 10.201.0.20
docker exec ms_attacker /scripts/attack_sqlmap.sh 10.201.0.20
```
→ `/admin` và sqlmap User-Agent bị DROP ngay.

### 4.7 [Fallback] Chạy toàn bộ 1 lần
```bash
docker exec ms_attacker /scripts/run_all_demo.sh 10.201.0.20 /var/log/minisnort/alert.log
```

---

## 📝 CHECKLIST CHUẨN BỊ TRƯỚC NGÀY THUYẾT TRÌNH

| Hạng mục | Người chịu trách nhiệm | ✓ |
|----------|------------------------|---|
| Slide lý thuyết (Phần 1) — IDS/IPS, 4 kỹ thuật | `[Thành viên A]` | ☐ |
| Slide NFQueue + sơ đồ module + pipeline flowchart | `[Thành viên B]` | ☐ |
| Slide Docker topology + rule table | `[Thành viên C]` | ☐ |
| Lab Docker test chạy được trên máy demo | `[Thành viên D]` | ☐ |
| `lab_up.sh` → 4 container healthy | `[Thành viên D]` | ☐ |
| `tail -f logs/alert.log` hiển thị đúng | `[Thành viên D]` | ☐ |
| `http://localhost:8080` accessible | `[Thành viên D]` | ☐ |
| Chạy thử `run_all_demo.sh` 1 lần đầy đủ | `[Thành viên D]` | ☐ |
| Xuất `SYSTEM_DIAGRAM.excalidraw` ra ảnh cho slide | Cả nhóm | ☐ |

---

## 🗂️ TÀI LIỆU THAM KHẢO

| File | Mô tả | Phần dùng |
|------|-------|-----------|
| `HANDOFF.md` | Tiến độ sprint, fix đã áp dụng | Tham khảo |
| `docker-compose.yml` | Topology Docker lab | Phần 3.1 |
| `config/minisnort.yaml` | Cấu hình runtime IPS | Phần 2.2 |
| `config/rules/local.rules` | Tập rule phát hiện | Phần 1.2 / 3.2 |
| `src/main.cpp` | Entry point | Phần 2.2 |
| `src/detection/engine.cpp` | Core engine | Phần 2.3 |
| `src/daq/nfq_daq.cpp` | NFQueue inline mode | Phần 2.1 |
| `src/flow/flow_table.cpp` | TCP state machine | Phần 2.2 |
| `dashboard/server.py` | Web dashboard backend | Phần 4.1 |
| `scripts/run_all_demo.sh` | Script chạy toàn bộ demo | Phần 4.7 |
| `SYSTEM_DIAGRAM.excalidraw` | Sơ đồ kiến trúc hệ thống | Phần 1.1 / 2.2 / 3.1 |

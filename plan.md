# MiniSnort — Mô phỏng IPS giống Snort 3 bằng C++ trên Docker

> **Đề tài:** Triển khai hệ thống IDS/IPS lấy cảm hứng từ Snort 3, viết bằng C++ thuần, chạy thật trên Linux. Phát hiện ICMP ping, port scanning, SSH brute force, SQL Injection và chặn gói tin bằng rule `drop` ở chế độ inline.
>
> **Môi trường:** Toàn bộ 3 tác nhân (Attacker, IPS, Victim) chạy trong Docker container, kết nối qua 2 docker network để mô phỏng topology 2 vùng mạng.
>
> **Tài liệu này dành cho Claude Code.** Mỗi sprint là một đơn vị công việc độc lập, có tiêu chí "done" rõ ràng và có thể chạy/test được. Khi bắt đầu một sprint mới, đọc lại mục tương ứng và mục **Conventions** ở cuối file.
>
> **Hai phase:**
> - **Phase 1 — MVP (Sprint 0–5):** đủ chạy demo 6 kịch bản, đáp ứng yêu cầu đề tài.
> - **Phase 2 — Nâng cao (Sprint 6–8):** Aho-Corasick multi-pattern, HTTP preprocessor đầy đủ, hot-reload rule. Làm sau khi đã pass demo MVP.

---

## 0. Mục tiêu & phạm vi

### Mục tiêu kỹ thuật
- Viết engine IPS bằng **C++17**, build bằng **CMake**, chạy được trên Ubuntu 22.04+.
- Hỗ trợ 2 chế độ:
  - **IDS (passive):** sniff bằng `libpcap`, chỉ alert.
  - **IPS (inline):** nhận packet qua `libnetfilter_queue` (NFQUEUE), đưa ra verdict `ACCEPT` hoặc `DROP`.
- Parse được subset của Snort 3 rule syntax (xem mục 3).
- Phát hiện được 6 kịch bản trong bảng demo (xem mục 9).
- **Toàn bộ lab chạy bằng `docker compose up`**, không cần VirtualBox/VMware.

### Ngoài phạm vi
- Không làm web UI quản trị.
- Không tích hợp SIEM thật (chỉ log ra file + stdout, format giống `alert_fast`).
- Không tối ưu hiệu năng cấp production (không Hyperscan, không multi-thread phức tạp).
- Không hỗ trợ IPv6 trong MVP.

---

## 1. Stack & dependencies

```
Ngôn ngữ        : C++17
Build           : CMake >= 3.16, Ninja
Compiler        : g++ >= 11
Container       : Docker >= 24, docker compose v2
Base image      : ubuntu:22.04
Host OS         : Linux có hỗ trợ NFQUEUE kernel module (mặc định có)
```

**Dependencies trong container IPS** (cài trong Dockerfile):
```
build-essential cmake ninja-build pkg-config
libpcap-dev libnetfilter-queue-dev libnfnetlink-dev
libpcre2-dev iptables tcpdump
```

**Dependencies trong container Attacker:**
```
nmap hydra curl wget iputils-ping sqlmap
```

**Dependencies trong container Victim:**
```
openssh-server apache2 php php-mysql mysql-server
+ DVWA (Damn Vulnerable Web Application) để test SQLi/admin URL
```

**Thư viện C++ third-party** (FetchContent trong CMake):
- `nlohmann/json` — config & log JSON.
- `spdlog` — logging.
- `Catch2 v3` — unit test.

---

## 2. Kiến trúc tổng thể

```
                ┌──────────────────────────────────────────────┐
                │                MiniSnort Engine               │
                │                                                │
   raw packet   │  ┌─────────┐   ┌─────────┐   ┌─────────────┐ │
  ──────────▶  │  │   DAQ   │──▶│ Decoder │──▶│   Flow Mgr   │ │
  (pcap/nfq)   │  └─────────┘   └─────────┘   └──────┬───────┘ │
                │                                     │          │
                │                                     ▼          │
                │                          ┌──────────────────┐  │
                │                          │ Detection Engine │  │
                │                          │  (rule matcher)  │  │
                │                          └────┬─────────┬───┘  │
                │                               │         │      │
                │            ┌──────────────────┘         │      │
                │            ▼                            ▼      │
                │      ┌──────────┐               ┌──────────┐   │
                │      │  Logger  │               │ Verdict  │   │
                │      │  (alert) │               │ (ACCEPT/ │   │
                │      └──────────┘               │   DROP)  │   │
                │                                 └────┬─────┘   │
                └──────────────────────────────────────┼─────────┘
                                                       ▼
                                          ┌──────────────────────┐
                                          │ NFQUEUE → kernel sees│
                                          │  ACCEPT or DROP      │
                                          └──────────────────────┘
```

**Mapping với Snort 3 thật:**

| Snort 3                  | MiniSnort                    |
|--------------------------|------------------------------|
| DAQ modules              | `src/daq/` (pcap, nfq)       |
| Codec plugins            | `src/decoder/`               |
| Stream/flow inspectors   | `src/flow/`                  |
| Detection engine + AC    | `src/detection/`             |
| IPS rules                | `src/rules/` (parser)        |
| Logger plugins           | `src/logger/`                |

---

## 3. Cú pháp rule hỗ trợ (subset Snort 3)

Format: `<action> <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> ( <options> )`

**Action:** `alert` | `drop` | `pass` | `log`
**Proto:** `tcp` | `udp` | `icmp` | `ip`
**IP/port:** `any`, IP cụ thể, CIDR, biến (`$HOME_NET`, `$EXTERNAL_NET`).

**Keyword option phải hỗ trợ:**

| Keyword          | Ý nghĩa                                                  |
|------------------|----------------------------------------------------------|
| `msg:"..."`      | Thông điệp alert                                          |
| `sid:N`          | Signature ID                                              |
| `rev:N`          | Revision                                                  |
| `content:"..."`  | Match chuỗi trong payload (Boyer-Moore)                   |
| `nocase`         | Case-insensitive cho `content` ngay trước                 |
| `pcre:"/.../i"`  | Regex (PCRE2)                                             |
| `flags:S`        | TCP flags                                                 |
| `itype:8`        | ICMP type                                                 |
| `flow:to_server,established` | Hướng + trạng thái flow                       |
| `threshold:...`  | Rate limit alert                                          |
| `http_uri`       | Giới hạn match `content` trong URI HTTP request           |

**6 rule demo** (`config/rules/local.rules`):

```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; itype:8; sid:1000001; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"TCP SYN Scan"; flags:S; \
  threshold:type threshold, track by_src, count 20, seconds 5; sid:1000002; rev:1;)

alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server,established; \
  threshold:type threshold, track by_src, count 5, seconds 30; sid:1000003; rev:1;)

drop tcp any any -> $HOME_NET 80 (msg:"SQLi UNION SELECT"; content:"UNION"; nocase; \
  content:"SELECT"; nocase; pcre:"/union\s+select/i"; sid:1000004; rev:1;)

drop icmp any any -> $HOME_NET any (msg:"Block all ICMP"; sid:1000005; rev:1;)

drop tcp any any -> $HOME_NET 80 (msg:"Block admin URL"; content:"/admin"; http_uri; \
  sid:1000006; rev:1;)
```

---

## 4. Cấu trúc thư mục dự án

```
minisnort/
├── CMakeLists.txt
├── README.md
├── PLAN.md                    ← file này
├── docker-compose.yml         ← orchestration 3 container
├── docker/
│   ├── ips/Dockerfile         ← image build minisnort
│   ├── attacker/Dockerfile    ← Kali-like với nmap/hydra/sqlmap
│   ├── victim/Dockerfile      ← Ubuntu + SSH + Apache + DVWA
│   └── victim/init-dvwa.sh
├── third_party/               ← (FetchContent tự kéo)
├── config/
│   ├── minisnort.yaml
│   └── rules/
│       └── local.rules        ← 6 rule demo
├── src/
│   ├── main.cpp
│   ├── core/
│   │   ├── packet.h
│   │   ├── verdict.h
│   │   └── engine.{h,cpp}
│   ├── daq/
│   │   ├── i_daq.h
│   │   ├── pcap_daq.{h,cpp}
│   │   └── nfq_daq.{h,cpp}
│   ├── decoder/
│   │   ├── ethernet.{h,cpp}
│   │   ├── ipv4.{h,cpp}
│   │   ├── tcp.{h,cpp}
│   │   ├── udp.{h,cpp}
│   │   └── icmp.{h,cpp}
│   ├── flow/
│   │   ├── flow_key.h
│   │   ├── flow_table.{h,cpp}
│   │   └── tcp_state.{h,cpp}
│   ├── rules/
│   │   ├── rule.h
│   │   ├── parser.{h,cpp}
│   │   └── rule_store.{h,cpp}
│   ├── detection/
│   │   ├── matcher.{h,cpp}
│   │   ├── threshold.{h,cpp}
│   │   ├── http_parser.{h,cpp}
│   │   └── engine.{h,cpp}
│   ├── logger/
│   │   ├── alert_fast.{h,cpp}
│   │   └── alert_json.{h,cpp}
│   └── util/
│       ├── ip.{h,cpp}
│       ├── log.h
│       └── config.{h,cpp}
├── tests/
│   ├── CMakeLists.txt
│   ├── test_decoder.cpp
│   ├── test_parser.cpp
│   ├── test_matcher.cpp
│   ├── test_threshold.cpp
│   ├── test_flow.cpp
│   └── pcap_samples/
├── logs/                      ← mount vào container IPS, persist alert log
└── scripts/
    ├── lab_up.sh              ← docker compose up + setup iptables trong IPS
    ├── lab_down.sh
    ├── attack_icmp.sh         ← chạy trong attacker
    ├── attack_synscan.sh
    ├── attack_ssh_brute.sh
    ├── attack_sqli.sh
    └── attack_admin.sh
```

---

## 5. Topology Docker

### 5.1. Sơ đồ network

```
┌────────────────────────────────────────────────────────────┐
│                       docker host                           │
│                                                             │
│   ┌─────────────────┐   net_attack   ┌────────────────┐    │
│   │   attacker      │  172.20.0.0/24 │     ips        │    │
│   │  172.20.0.10   ├─────────────────┤ 172.20.0.2     │    │
│   │ (kali-tools)    │                │  (eth0)        │    │
│   └─────────────────┘                │                │    │
│                                      │ NFQUEUE engine │    │
│                                      │  minisnort     │    │
│                                      │                │    │
│                                      │ 172.21.0.2     │    │
│   ┌─────────────────┐                │  (eth1)        │    │
│   │     victim      │  net_victim    │                │    │
│   │  172.21.0.20   ├─────────────────┤                │    │
│   │ SSH/Apache/DVWA │  172.21.0.0/24 │                │    │
│   └─────────────────┘                └────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

**Lý do tách 2 network:** để tất cả traffic Attacker ↔ Victim **phải đi qua** container IPS, mô phỏng đúng vị trí inline. Container IPS là gateway của cả 2 mạng.

### 5.2. Routing logic

- `attacker` có route mặc định: gateway = `172.20.0.2` (eth0 của IPS).
- `victim` có route mặc định: gateway = `172.21.0.2` (eth1 của IPS).
- IPS bật `net.ipv4.ip_forward=1`, NAT off (lab kín).
- IPS có iptables rule: tất cả gói FORWARD đi vào NFQUEUE 0 → MiniSnort xử lý.

### 5.3. Capabilities Docker cần cấp

Container IPS cần `NET_ADMIN`, `NET_RAW`, và load module `nfnetlink_queue` từ host:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
sysctls:
  - net.ipv4.ip_forward=1
```

> **Note quan trọng:** module `nfnetlink_queue` của kernel chia sẻ giữa host và container. Trên host trước khi chạy lab, nên `sudo modprobe nfnetlink_queue`. Trên macOS/Windows phải dùng Docker Desktop với WSL2 hoặc Linux VM thật, vì Docker Desktop trên macOS không expose được netfilter của Linux kernel cho container đầy đủ.

---

## 6. docker-compose.yml (template)

> Claude Code: tạo file này ở Sprint 0. Đây là phác thảo chuẩn.

```yaml
services:
  ips:
    build: ./docker/ips
    container_name: ms_ips
    hostname: ips
    cap_add: [NET_ADMIN, NET_RAW]
    sysctls:
      net.ipv4.ip_forward: "1"
    volumes:
      - ./:/workspace
      - ./logs:/var/log/minisnort
    networks:
      net_attack:
        ipv4_address: 172.20.0.2
      net_victim:
        ipv4_address: 172.21.0.2
    command: /workspace/scripts/ips_entrypoint.sh
    tty: true

  attacker:
    build: ./docker/attacker
    container_name: ms_attacker
    hostname: attacker
    cap_add: [NET_RAW, NET_ADMIN]
    volumes:
      - ./scripts:/scripts:ro
      - ./logs/attacker:/var/log/attacker
    networks:
      net_attack:
        ipv4_address: 172.20.0.10
    depends_on: [ips]
    command: /scripts/attacker_entrypoint.sh
    tty: true

  victim:
    build: ./docker/victim
    container_name: ms_victim
    hostname: victim
    networks:
      net_victim:
        ipv4_address: 172.21.0.20
    depends_on: [ips]
    ports: []  # không expose ra host, chỉ qua IPS
    tty: true

networks:
  net_attack:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  net_victim:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

**Entrypoint script `scripts/ips_entrypoint.sh`** (chạy khi container IPS start):

```bash
#!/bin/bash
set -e
# Đảm bảo route đúng (compose đã set, nhưng phòng trường hợp)
sysctl -w net.ipv4.ip_forward=1
# Flush rồi đẩy mọi packet FORWARD vào NFQUEUE 0
iptables -F FORWARD
iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
# --queue-bypass: nếu MiniSnort chưa chạy, ACCEPT mặc định, để mạng không chết
# Build nếu chưa có binary
if [ ! -x /workspace/build/minisnort ]; then
  cd /workspace && cmake -S . -B build -G Ninja && ninja -C build
fi
# Chạy MiniSnort ở chế độ IPS
exec /workspace/build/minisnort \
  --mode ips --queue 0 \
  --rules /workspace/config/rules/local.rules \
  --config /workspace/config/minisnort.yaml \
  --log /var/log/minisnort/alert.log
```

**Entrypoint script `scripts/attacker_entrypoint.sh`:**

```bash
#!/bin/bash
# Set route mặc định qua IPS để gói tới net_victim đi qua đúng đường
ip route del default 2>/dev/null || true
ip route add default via 172.20.0.2
# Giữ container chạy
exec sleep infinity
```

Victim không cần entrypoint đặc biệt; Dockerfile sẽ start sshd + apache2 + mysql, và set route default qua `172.21.0.2`.

---

## 7. Sprint roadmap

> Mỗi sprint kết thúc bằng demo chạy được + commit có tag `sprintN-done`.

### Sprint 0 — Docker lab + skeleton (1–2 ngày)

**Mục tiêu:** Lab Docker lên được, project compile trong container IPS, ping từ attacker → victim đi qua IPS thành công.

**Tasks:**
1. Tạo cấu trúc thư mục theo mục 4.
2. Viết 3 Dockerfile (`docker/ips`, `docker/attacker`, `docker/victim`).
3. Viết `docker-compose.yml` theo mục 6.
4. Viết `ips_entrypoint.sh`, `attacker_entrypoint.sh`.
5. Viết `scripts/lab_up.sh`:
   ```bash
   #!/bin/bash
   set -e
   sudo modprobe nfnetlink_queue || true
   docker compose build
   docker compose up -d
   echo "Wait 5s for services..."; sleep 5
   docker compose ps
   ```
6. Viết `scripts/lab_down.sh`: `docker compose down -v`.
7. `CMakeLists.txt` root + `src/CMakeLists.txt`, build ra binary `minisnort`.
8. `FetchContent` cho spdlog, nlohmann_json, Catch2.
9. Hello world `pcap_daq`: in `Got packet, len=N`.
10. Hello world `nfq_daq`: nhận packet từ NFQUEUE, log, ACCEPT tất.
11. README.md hướng dẫn `./scripts/lab_up.sh` và `docker exec -it ms_attacker bash`.

**Done khi:**
- `./scripts/lab_up.sh` chạy không lỗi, 3 container `Up`.
- `docker exec -it ms_attacker ping -c 3 172.21.0.20` thành công.
- `docker exec -it ms_ips tail -f /var/log/minisnort/alert.log` thấy MiniSnort log mỗi gói qua.
- `docker exec -it ms_attacker curl http://172.21.0.20` trả về HTML từ Apache.

---

### Sprint 1 — Decoder + Packet model (2–3 ngày)

**Mục tiêu:** Parse Ethernet/IPv4/TCP/UDP/ICMP thành struct `Packet` đầy đủ.

**Tasks:**
1. Định nghĩa `core/packet.h`:
   ```cpp
   struct Packet {
     const uint8_t* raw;     size_t raw_len;
     uint8_t  l3_proto;
     uint32_t src_ip, dst_ip;
     uint16_t src_port, dst_port;
     uint8_t  tcp_flags;
     uint8_t  icmp_type, icmp_code;
     const uint8_t* payload; size_t payload_len;
     uint64_t timestamp_us;
     uint32_t nfq_packet_id;  // 0 nếu IDS mode
   };
   ```
2. Implement decoder từng layer, bounds-check chặt (không crash với gói rách/cụt).
3. Khi `--mode ids -i eth0`, log mỗi gói:
   `[12:34:56.789] TCP 172.20.0.10:54321 -> 172.21.0.20:22 flags=S len=60`
4. Unit test `test_decoder` với 5+ pcap mẫu (HTTP, SSH handshake, ICMP echo, DNS, ARP).

**Done khi:**
- `ctest --test-dir build` pass `test_decoder`.
- Trong container IPS: `./build/minisnort --mode ids -i eth0` (sniff `net_attack`) in summary đúng cho ping/curl/ssh từ attacker.

---

### Sprint 2 — Rule parser + RuleStore (3–4 ngày)

**Mục tiêu:** Parse `local.rules` → `vector<Rule>`, index để lookup nhanh.

**Tasks:**
1. Định nghĩa `rules/rule.h`:
   ```cpp
   enum class Action { ALERT, DROP, PASS, LOG };
   struct ContentOpt  { std::string pattern; bool nocase; bool http_uri; };
   struct PcreOpt     { std::string regex;   bool nocase; };
   struct ThresholdOpt {
     enum Track { BY_SRC, BY_DST }; Track track;
     int count; int seconds;
   };
   struct Rule {
     Action action; uint8_t proto;
     IpMatcher src_ip, dst_ip;
     PortMatcher src_port, dst_port;
     std::string msg; uint32_t sid; uint32_t rev;
     std::vector<ContentOpt> contents;
     std::optional<PcreOpt>  pcre;
     std::optional<uint8_t>  tcp_flags_required;
     std::optional<uint8_t>  icmp_type;
     std::optional<ThresholdOpt> threshold;
     bool flow_to_server = false;
     bool flow_established = false;
   };
   ```
2. Lexer/parser:
   - Tách header và options trong dấu `()`.
   - Parse cặp `key:value;`.
   - Hỗ trợ biến `$HOME_NET` từ config (mặc định `172.21.0.0/24`).
   - Báo lỗi rõ ràng kèm số dòng.
3. `RuleStore`: hash map `{proto, dst_port|ANY} → vector<Rule*>`.
4. Unit test `test_parser` với 6 rule demo + 5 rule sai cú pháp.

**Done khi:**
- `test_parser` pass.
- Khi load `local.rules`, log: `Loaded 6 rules: SIDs [1000001..1000006]`.

---

### Sprint 3 — Detection engine cơ bản (3–4 ngày)

**Mục tiêu:** Match được 4 kịch bản đơn giản: ICMP ping (1000001), Block all ICMP (1000005), SQLi (1000004), Block admin URL (1000006).

**Tasks:**
1. `detection/matcher.cpp`:
   - `match_content` Boyer-Moore (dùng `std::boyer_moore_searcher` của C++17).
   - `match_pcre` với PCRE2.
   - `match_flags`, `match_itype`.
2. `detection/http_parser.cpp`:
   - Detect HTTP request line: `GET /admin HTTP/1.1\r\n`.
   - Extract URI, method. Đủ cho `http_uri`.
3. `detection/engine.cpp`:
   - Vòng lặp: với mỗi packet → lookup `RuleStore` → chạy matcher → emit alert + verdict.
4. Logger `alert_fast` format Snort:
   ```
   10/26-12:34:56.789012  [**] [1:1000001:1] "ICMP Ping detected" [**] {ICMP} 172.20.0.10 -> 172.21.0.20
   ```
5. Verdict logic:
   - IDS mode: luôn `ACCEPT`.
   - IPS mode: rule `drop` match → `DROP`, ngược lại `ACCEPT`.

**Done khi (chạy trong lab Docker):**
- `docker exec ms_attacker ping -c 3 172.21.0.20` → có alert sid 1000001 trong `logs/alert.log`, gói vẫn qua.
- Sửa rule 1000005 enable → ping bị DROP, alert sid 1000005.
- `docker exec ms_attacker curl http://172.21.0.20/admin` → DROP, alert sid 1000006.
- `docker exec ms_attacker curl 'http://172.21.0.20/?q=1+UNION+SELECT+name+FROM+users'` → DROP, alert sid 1000004.
- `test_matcher` pass.

---

### Sprint 4 — Flow tracking + Threshold (3–4 ngày)

**Mục tiêu:** Match 2 kịch bản còn lại — TCP SYN Scan (1000002) và SSH Brute Force (1000003).

**Tasks:**
1. `flow/flow_table.cpp`:
   - Key 5-tuple normalize 2 chiều cùng key.
   - State TCP đơn giản: `NEW`, `SYN_SENT`, `ESTABLISHED`, `CLOSED`.
   - Cleanup flow idle > 5 phút mỗi 30s.
2. `flow:to_server,established`:
   - `to_server` = packet đi từ initiator của handshake.
   - `established` = đã có SYN/SYN-ACK/ACK.
3. `detection/threshold.cpp`:
   - Map `(sid, track_key) → deque<timestamp>` sliding window.
   - Đạt `count` trong `seconds` → trigger alert, reset.
4. Tích hợp engine: rule có `threshold` chỉ alert khi đủ điều kiện.

**Done khi:**
- `docker exec ms_attacker nmap -sS -p 1-200 172.21.0.20` → alert sid 1000002 sau ~20 SYN/5s.
- `docker exec ms_attacker hydra -l root -P /scripts/passwords.txt ssh://172.21.0.20` → alert sid 1000003 sau 5 lần thử/30s.
- `test_threshold`, `test_flow` pass.

---

### Sprint 5 — Demo, ghi nhận kết quả, báo cáo (2–3 ngày)

**Mục tiêu:** Đóng gói gọn, script demo lặp lại, điền bảng kết quả.

**Tasks:**
1. Hoàn thiện 6 attack script trong `scripts/`:
   - `attack_icmp.sh`: `ping -c 5 172.21.0.20`.
   - `attack_synscan.sh`: `nmap -sS -p 1-1000 172.21.0.20`.
   - `attack_ssh_brute.sh`: `hydra -l root -P passwords.txt -t 4 ssh://172.21.0.20`.
   - `attack_sqli.sh`: `curl "http://172.21.0.20/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit"`.
   - `attack_admin.sh`: `curl http://172.21.0.20/admin`.
   - `attack_block_icmp.sh`: ping (sau khi enable sid 1000005).
2. Script `scripts/run_all_demo.sh`: chạy lần lượt 6 kịch bản, sau mỗi kịch bản `sleep 3`, in ra log alert tương ứng.
3. Mỗi kịch bản: chụp ảnh log `/logs/alert.log` + output của attacker.
4. Điền bảng kết quả demo (mục 9).
5. Viết phần báo cáo: kiến trúc, code map, hạn chế (chưa có Aho-Corasick / HTTP đầy đủ / hot reload — đã có roadmap Sprint 6–8), hướng phát triển xa hơn (Hyperscan, multi-thread, IPv6, file inspector, SSL/TLS).
6. Tag git `v1.0-mvp`.

**Done khi:**
- `./scripts/lab_up.sh && docker exec ms_attacker /scripts/run_all_demo.sh` chạy hết, không lỗi.
- 6/6 dòng bảng kết quả có dấu ✓.
- README có hướng dẫn reproduce 100%.
- **Tag git: `v1.0-mvp`. Đến đây đề tài đã đáp ứng yêu cầu cơ bản. Sprint 6–8 là nâng cao.**

---

## 7B. Phase 2 — Sprint nâng cao

> 3 sprint sau MVP để đưa engine tiệm cận Snort 3 thật. Có thể chọn làm 1, 2, hoặc cả 3 tuỳ thời gian.

### Sprint 6 — Aho-Corasick multi-pattern matching (3–4 ngày)

**Vấn đề Sprint 3 chưa giải quyết:** ở MVP, với mỗi packet ta lookup `RuleStore` được 1 nhóm rule, rồi loop từng rule và chạy Boyer-Moore cho từng `content` riêng lẻ. Với N rule có chứa pattern `content`, mỗi packet phải chạy `O(N × |payload|)` lần search. Khi rule set lên hàng nghìn (chuẩn Snort), cách này không scale.

**Mục tiêu Sprint 6:** xây fast-pattern matcher dùng Aho-Corasick — quét payload **một lần duy nhất** để biết tất cả pattern xuất hiện. Đây là chính xác cách Snort 3 dùng `mpse` (Multi-Pattern Search Engine).

**Khái niệm "fast pattern":**
- Trong Snort, mỗi rule có thể có nhiều `content`, nhưng engine chỉ chọn **một** làm "fast pattern" (thường là pattern dài nhất / hiếm gặp nhất).
- Tất cả fast pattern được nạp vào 1 cây Aho-Corasick chung.
- Khi packet đến: chạy AC trên payload → ra danh sách rule "ứng viên" (có ít nhất 1 fast pattern khớp) → mới chạy full match (các content khác + pcre + flags + threshold) trên ứng viên đó.

**Tasks:**

1. **Tạo module `detection/mpse/`** (Multi-Pattern Search Engine):
   ```
   src/detection/mpse/
   ├── i_mpse.h           ← interface chung (cho phép swap AC ↔ Hyperscan sau)
   ├── ac_node.h          ← node của trie
   ├── aho_corasick.h
   └── aho_corasick.cpp
   ```

2. **Implement Aho-Corasick:**
   - `add_pattern(const std::string& pat, uint32_t pattern_id)` — thêm pattern, nhận về id để map ngược về rule.
   - `compile()` — build goto + failure links (BFS).
   - `search(const uint8_t* buf, size_t len, std::vector<uint32_t>& hits)` — quét, trả về danh sách `pattern_id` đã match (có thể có duplicate nếu pattern xuất hiện nhiều vị trí — caller tự dedupe nếu cần).
   - Hỗ trợ `nocase`: lúc add pattern, normalize lowercase và lúc search cũng lowercase từng byte. Tạo 2 instance AC riêng (case-sensitive và case-insensitive) để không làm chậm matching case-sensitive.
   - Bounds-check, không crash với buffer rỗng.

3. **Chọn fast pattern cho mỗi rule:**
   - Trong `RuleStore::compile()` (hàm mới, gọi sau khi load rule):
     - Với mỗi rule có ít nhất 1 `content`: chọn content có pattern dài nhất làm fast pattern.
     - Add fast pattern vào AC, lưu mapping `pattern_id → rule_idx`.
   - Rule không có `content` (chỉ pcre / flags / itype) → bỏ qua AC, evaluate trực tiếp như cũ (nhóm này nhỏ).

4. **Refactor `detection::engine`:**
   ```
   for each packet:
     hits = mpse.search(payload)         // 1 lần
     candidate_rules = unique(hits → rule_idx)
     for r in candidate_rules:
       if full_match(r, packet):         // các content khác + pcre + ...
         emit_alert(r); update_verdict(r)
     for r in rules_without_content:     // ICMP itype=8, pure flags, ...
       if full_match(r, packet):
         emit_alert(r); update_verdict(r)
   ```

5. **Benchmark:**
   - Viết script `scripts/bench_mpse.sh`: dùng `tcpreplay` chạy 1 pcap 100k packet với 2 cấu hình rule (50 rule, 500 rule).
   - Đo throughput (packet/giây) trước và sau khi đổi sang AC.
   - Mục tiêu: với 500 rule, AC nhanh hơn naive ≥ 5×.

6. **Unit test `tests/test_mpse.cpp`:**
   - Add 10 pattern, search trên buffer chứa 0/1/nhiều pattern → đúng số match, đúng id.
   - Test nocase.
   - Test pattern là prefix của nhau (`he`, `hers`, `his`) — failure link phải đúng.
   - Test pattern rỗng → reject ở `add_pattern`.
   - Test `compile()` gọi 2 lần → idempotent.

**Done khi:**
- `test_mpse` pass.
- Log khởi động hiển thị: `MPSE compiled: 6 fast patterns, 0 rules without content`.
- Demo MVP (6 kịch bản) vẫn chạy đúng — kết quả không đổi, chỉ nhanh hơn.
- `scripts/bench_mpse.sh` báo cáo speedup ≥ 5× với 500 rule.

---

### Sprint 7 — HTTP preprocessor đầy đủ (3–4 ngày)

**Vấn đề Sprint 3 chưa giải quyết:** ở MVP, `http_parser` chỉ tìm dòng request đầu tiên (`GET /admin HTTP/1.1`) trong **một packet**. Thực tế HTTP có nhiều thứ phá vỡ giả định này:
- HTTP request có thể bị chia qua nhiều packet TCP (kẻ tấn công cố tình split).
- Body có thể `Transfer-Encoding: chunked`.
- Body có thể `Content-Encoding: gzip`/`deflate`.
- Header có thể có thứ tự khác nhau, có khoảng trắng thừa, có duplicate.
- URL có thể được encode (`%2Fadmin` thay vì `/admin`) hoặc dùng path traversal (`/foo/../admin`).
- Pipelining: nhiều request liên tiếp trong 1 connection.

**Mục tiêu Sprint 7:** xây HTTP inspector **stateful theo flow**, normalize URI, decode body, expose các "buffer" chuẩn để rule match (`http_uri`, `http_header`, `http_method`, `http_client_body`) — đúng mô hình của Snort 3 `http_inspect`.

**Tasks:**

1. **Module mới `detection/http_inspect/`:**
   ```
   src/detection/http_inspect/
   ├── http_state.h       ← per-flow HTTP parsing state
   ├── http_buffers.h     ← struct HttpBuffers { uri, method, headers, body, ... }
   ├── http_normalize.{h,cpp}  ← URL decode, path canonicalize
   ├── chunked.{h,cpp}    ← decode chunked transfer
   ├── gzip.{h,cpp}       ← inflate gzip/deflate (dùng zlib)
   └── http_inspect.{h,cpp}    ← main entry: feed(packet, flow) → optional<HttpBuffers>
   ```

2. **HTTP state machine theo flow:**
   - Lifecycle: `IDLE → REQ_LINE → REQ_HEADERS → REQ_BODY → RESP_LINE → RESP_HEADERS → RESP_BODY → IDLE`.
   - Reassembly: append payload TCP vào buffer của flow (có cap, ví dụ 64KB; quá thì drop và set flag `oversize`, không alert nhầm).
   - Phát hiện ranh giới `\r\n\r\n` để chuyển state.

3. **URI normalization:**
   - URL-decode: `%2F` → `/`, `%2e` → `.`. Decode tối đa 2 lần để bắt double encoding.
   - Path canonicalize: `/foo/./bar` → `/foo/bar`, `/foo/../bar` → `/bar`, `//` → `/`.
   - Lowercase nếu rule có `nocase` (giữ nguyên bản gốc + bản normalize trong buffer; matcher chọn buffer phù hợp).

4. **Body decode:**
   - `Content-Length`: đọc đúng N byte.
   - `Transfer-Encoding: chunked`: parse từng chunk `<size hex>\r\n<data>\r\n`, tới `0\r\n\r\n` thì kết thúc.
   - `Content-Encoding: gzip` hoặc `deflate`: chạy `inflate()` của zlib lên body. Cap kích thước sau decompress (chống zip bomb, ví dụ max 1MB).

5. **Mở rộng rule keyword:**
   - `http_method` — match content trong method (`GET`, `POST`, ...).
   - `http_header` — match trong toàn bộ block header.
   - `http_client_body` — match trong body request đã decode.
   - `http_uri` (đã có ở MVP) — giờ match trên URI đã normalize, không phải raw.
   - Cập nhật `parser.cpp` để parse các keyword này.

6. **Tích hợp với detection engine:**
   - Khi packet TCP qua port 80/8080: `http_inspect.feed(pkt, flow)` → nếu trả về `HttpBuffers` (đã parse xong 1 request hoàn chỉnh) → set vào context để matcher có thể truy cập đúng buffer.
   - AC fast pattern (Sprint 6) cũng được chạy lên các HTTP buffer riêng (mỗi buffer có instance AC riêng nếu cần — Snort gọi là "rule groups").

7. **Add 3 rule mới để test (`config/rules/local.rules`):**
   ```
   drop tcp any any -> $HOME_NET 80 (msg:"Path traversal"; content:"../"; http_uri; sid:1000007;)
   drop tcp any any -> $HOME_NET 80 (msg:"SQLi in body"; content:"UNION"; nocase; \
     http_client_body; pcre:"/union\s+select/i"; sid:1000008;)
   drop tcp any any -> $HOME_NET 80 (msg:"Suspicious User-Agent"; content:"sqlmap"; nocase; \
     http_header; sid:1000009;)
   ```

8. **Attack script mới:**
   - `scripts/attack_traversal.sh`: `curl 'http://172.21.0.20/foo/%2e%2e/admin'` — phải bị chặn bởi sid 1000006 nhờ URI normalize.
   - `scripts/attack_sqli_body.sh`: `curl -X POST -d "id=1' UNION SELECT ..." http://172.21.0.20/login` — bị chặn bởi 1000008.
   - `scripts/attack_sqlmap.sh`: chạy `sqlmap` thật → header `User-Agent: sqlmap/...` bị chặn bởi 1000009.

9. **Unit test `tests/test_http_inspect.cpp`:**
   - Request bị split qua 3 packet → reassembly đúng, ra đủ HttpBuffers.
   - URI có `%2F` và `..` → normalize đúng.
   - Body chunked với 4 chunk → ghép đúng.
   - Body gzip → decompress đúng.
   - Pipelining: 2 request liên tiếp trong cùng 1 stream → ra 2 lần HttpBuffers độc lập.
   - Oversize buffer → set flag, không crash.
   - Zip bomb (gzip 100KB → 100MB) → cap, không OOM.

**Done khi:**
- `test_http_inspect` pass.
- 3 rule mới (1000007–1000009) hoạt động đúng trên 3 attack script tương ứng.
- Demo cũ (sid 1000006 admin URL) vẫn pass — kể cả khi attacker dùng `%2Fadmin` hay `/foo/../admin`.
 
---

### Sprint 8 — Hot reload rule (không restart) (2–3 ngày)

**Vấn đề:** mỗi lần đổi `local.rules` ở MVP, phải `docker compose restart ms_ips`, nghĩa là mất kết nối TCP đang dở, mất state flow, gói bị treo trong NFQUEUE → lab demo không mượt, production thì không chấp nhận được.

**Mục tiêu Sprint 8:** SIGHUP để reload rule, **không drop packet, không reset flow table, không restart**. Đây là tính năng "live reload" mà Snort 3 hỗ trợ qua `--enable-reload`.

**Tasks:**

1. **Phân tách rõ "stateful" và "stateless" trong engine:**
   - Stateful (giữ nguyên khi reload): `flow_table`, `threshold` counters, NFQ socket, log file handle.
   - Stateless (build lại khi reload): `RuleStore`, `MPSE` (Aho-Corasick tree), parsed rule.

2. **Refactor cho thread-safe access:**
   - Engine giữ con trỏ `std::shared_ptr<const RuleSet>` (RuleSet = bundle gồm RuleStore + MPSE).
   - Hot path detection: `auto rs = current_ruleset_.load();` (atomic load) → dùng `rs` đến hết packet.
   - Reload: build `RuleSet` mới ở thread riêng → atomic store con trỏ mới → con trỏ cũ tự destroy khi không packet nào còn ref.
   - Dùng `std::atomic<std::shared_ptr<RuleSet>>` (C++20 atomic shared_ptr) — **nhưng plan đã chốt C++17**. Dùng workaround: `std::shared_ptr` + `std::atomic_load`/`std::atomic_store` (deprecated nhưng còn dùng được trong C++17), hoặc tự bọc trong RCU đơn giản (hai con trỏ + reader counter).

3. **Signal handler:**
   - Sửa `main.cpp`: cài handler cho `SIGHUP` chỉ set 1 flag atomic `reload_requested = true`. KHÔNG làm gì nặng trong handler (async-signal-safe).
   - Trong main loop của engine, mỗi iteration check flag, nếu set → enqueue reload job, clear flag.

4. **Reload pipeline:**
   ```
   on SIGHUP:
     1. Parse rules từ file lại
     2. Build RuleStore mới
     3. Compile MPSE mới
     4. Validate (parse có lỗi → log error, KHÔNG swap, giữ nguyên rule cũ)
     5. Atomic swap con trỏ
     6. Log: "Rule reload OK: N rules loaded, took X ms"
   ```
   - Toàn bộ làm ở thread riêng, không block hot path.

5. **Threshold state khi reload:**
   - SID giữ nguyên giá trị → giữ counter cũ.
   - SID bị xoá → drop counter.
   - SID mới → counter mặc định 0.
   - Implement bằng cách so SID trước-sau trong reload finalize step.

6. **Flow table khi reload:** không đụng vào, giữ nguyên hoàn toàn.

7. **CLI hỗ trợ:**
   - `kill -HUP <pid>` từ trong container IPS.
   - Tiện hơn: script `scripts/reload_rules.sh`:
     ```bash
     #!/bin/bash
     PID=$(docker exec ms_ips pidof minisnort)
     docker exec ms_ips kill -HUP $PID
     ```

8. **Unit test `tests/test_reload.cpp`:**
   - Load 6 rule, parse OK, build RuleSet v1.
   - Sửa file: thêm rule 1000010, đổi sid 1000006 message.
   - Trigger reload → RuleSet v2 active. Rule mới có hiệu lực, rule cũ updated.
   - Sửa file thành rule sai cú pháp → trigger reload → giữ nguyên RuleSet v1, log error rõ ràng (không crash, không silent fail).
   - Test concurrency: 1 thread liên tục `detect()`, 1 thread reload 100 lần — không crash, không leak (chạy với valgrind/ASAN).

9. **Demo:**
   - `./scripts/lab_up.sh`
   - `docker exec ms_attacker ping -c 100 172.21.0.20 &` — chạy ping liên tục.
   - Trong khi đó: sửa `config/rules/local.rules` đổi 1000001 từ `alert` thành `drop`.
   - `./scripts/reload_rules.sh`.
   - Quan sát: ping trước reload → vẫn thông + alert; ping sau reload → bị drop ngay; **không có gói nào bị treo, ping không bị mất kết nối ICMP "lạc" do flow reset**.

**Done khi:**
- `test_reload` pass, ASAN clean.
- Demo trên hoạt động đúng — quay video làm bằng chứng.
- Reload với rule sai cú pháp: log rõ, engine vẫn chạy với rule cũ.
- Đo: thời gian reload với 1000 rule < 200ms.

---

## 8. Conventions cho Claude Code

Khi code, tuân thủ:

- **C++17** thuần, không dùng C++20 feature (concepts, ranges, coroutine).
- **RAII chặt chẽ**: mỗi resource (pcap handle, nfq handle, file) wrap trong class có destructor.
- **Không exception trong hot path** (decoder, matcher); dùng `bool` hoặc `std::optional`. Exception chỉ dùng khi parse config/rule khởi động.
- **Logging**: dùng spdlog với 2 logger: `core` (info/debug runtime) và `alert` (output ra alert.log + stdout). KHÔNG `std::cout` rải rác.
- **Test trước khi merge sprint**: mỗi sprint có file test tương ứng, `ctest` phải pass.
- **Commit message**: `[sprintN] <module>: <action>`. Ví dụ: `[sprint2] rules: add content option parser`.
- **Format**: `clang-format` style Google, max 100 cols.
- **Header guard**: `#pragma once`.
- **Namespace gốc**: `minisnort::`. Sub: `minisnort::daq`, `minisnort::decoder`, v.v.
- **Khi build trong Docker**: luôn build trong thư mục `build/` (đã `.gitignore`).
- **Khi test với traffic thật**: dùng `docker exec` từ host, không exec trong container IPS để giữ log sạch.

### Checklist mỗi khi Claude Code bắt đầu sprint mới

1. Đọc lại mục sprint tương ứng.
2. Đọc mục **Conventions**.
3. Check git status, commit/stash thay đổi cũ nếu có.
4. Tạo branch `sprintN`.
5. Implement task theo thứ tự, mỗi task = 1 commit.
6. Chạy `ctest` và demo command trong "Done khi".
7. Tạo PR / merge vào main, tag `sprintN-done`.

---

## 9. Bảng ghi nhận kết quả demo (điền ở Sprint 5)

| STT | Kịch bản          | Rule SID | Lệnh attack                                                  | Kết quả IDS | Kết quả IPS | Log |
|-----|-------------------|----------|--------------------------------------------------------------|-------------|-------------|-----|
| 1   | ICMP Ping         | 1000001  | `ping -c 5 172.21.0.20`                                       | Có alert    | Không chặn (rule là `alert`) | `logs/icmp_ping.png` |
| 2   | TCP SYN Scan      | 1000002  | `nmap -sS -p 1-1000 172.21.0.20`                              | Có alert    | Không chặn  | `logs/synscan.png` |
| 3   | SSH Brute Force   | 1000003  | `hydra -l root -P pw.txt ssh://172.21.0.20`                   | Có alert    | Không chặn  | `logs/ssh_brute.png` |
| 4   | SQL Injection     | 1000004  | `curl "http://172.21.0.20/?id=1' UNION SELECT ..."`           | Có alert    | Chặn        | `logs/sqli.png` |
| 5   | Block ICMP        | 1000005  | `ping -c 5 172.21.0.20` (sau khi enable rule)                 | Có alert    | Chặn        | `logs/block_icmp.png` |
| 6   | Block admin URL   | 1000006  | `curl http://172.21.0.20/admin`                               | Có alert    | Chặn        | `logs/block_admin.png` |

---

## 10. Hướng phát triển sau Phase 2

> Những thứ đã có kế hoạch (Aho-Corasick, HTTP preprocessor, hot reload) nằm ở Sprint 6–8. Mục này dành cho việc xa hơn nữa.

- **Hyperscan thay cho Aho-Corasick tự code**: Intel Hyperscan dùng SIMD, có thể nhanh gấp nhiều lần. Module `mpse` đã có interface `IMpse` (Sprint 6) nên chỉ cần thêm `hyperscan_mpse.cpp`.
- **Multi-threading**: 1 thread DAQ, N thread detection, queue lock-free (moodycamel ConcurrentQueue). Cần làm cẩn thận với flow table — shard theo hash 5-tuple.
- **Hỗ trợ IPv6** (decoder + rule syntax + flow key).
- **Output JSON / EVE-style log** → tích hợp Elastic / Wazuh / Suricata-compatible viewer.
- **TLS/SSL inspector**: parse SNI, certificate fingerprint (không decrypt) — đủ để alert khi truy cập domain bất thường.
- **File inspector**: extract file từ HTTP/SMTP/FTP, hash MD5/SHA256, match với threat intel.
- **Performance bench thật**: `tcpreplay` 1 Gbps trên pcap MAWI hoặc CIC-IDS-2017 dataset, đo packet loss và CPU.
- **Rule community**: download Emerging Threats Open ruleset (~30k rule), benchmark engine.

---

## 11. Tham khảo

**Cơ bản (Phase 1):**
- Snort 3 architecture: https://www.snort.org/documents
- libnetfilter_queue: https://www.netfilter.org/projects/libnetfilter_queue/
- libpcap tutorial: https://www.tcpdump.org/pcap.html
- DVWA: https://github.com/digininja/DVWA
- Boyer-Moore trong C++17: `std::boyer_moore_searcher`

**Nâng cao (Phase 2):**
- Aho-Corasick paper gốc: Aho & Corasick, "Efficient string matching: an aid to bibliographic search" (1975).
- Snort 3 `mpse` source: https://github.com/snort3/snort3/tree/master/src/search_engines
- Snort 3 `http_inspect`: https://github.com/snort3/snort3/tree/master/src/service_inspectors/http_inspect
- RFC 7230 (HTTP/1.1 Message Syntax) — chuẩn để parse chunked, header.
- RFC 1952 (gzip) + zlib manual: https://zlib.net/manual.html
- Hyperscan: https://www.hyperscan.io/
- C++17 `std::atomic_load(shared_ptr)`: https://en.cppreference.com/w/cpp/memory/shared_ptr/atomic
- Snort 3 reload mechanism: tìm "Reload" trong Snort 3 manual.
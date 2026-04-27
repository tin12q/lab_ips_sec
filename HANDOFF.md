# HANDOFF TỔNG HỢP — LAB IPS (`lab_ips_sec`)

## 1) Tổng quan trạng thái

- Nhánh hiện tại: `main`
- Mục tiêu đã thực hiện: hoàn tất Sprint 3–5 theo hướng ổn định runtime IPS, correctness detection pipeline, và evidence capture.
- Sprint 6 đã được khởi động theo vòng lặp đệ quy (run → triage → fix tối thiểu → rerun full-suite).

---

## 2) Tiến độ theo sprint

## Sprint 3 — Hoàn tất

### Nội dung đã làm
- Implement + wire `AlertFast` logger vào runtime.
- Mở rộng config parser cho logging:
  - `logging.alert_file`
  - `logging.level`
- Tích hợp alert emit trong DAQ path (PCAP + NFQ).
- Tăng khả năng quan sát fail-open/fail-path trong NFQ.

### Kết quả
- Build và test pass.
- Evidence có trong `logs/evidence/sprint3/*`.

---

## Sprint 4 — Hoàn tất

### Nội dung đã làm
- Bổ sung flow tracking/TCP state.
- Bổ sung threshold logic (`count/seconds`, `track by_src/by_dst`).
- Tích hợp flow + threshold vào `Engine::inspect` giữ nguyên pass-over-drop semantics.
- Sửa timestamp propagation từ DAQ để threshold hoạt động đúng runtime.
- Thêm test cho flow/threshold/engine.

### Kết quả
- CTest pass toàn bộ (mốc sprint4: 44/44; về sau suite tăng).
- Evidence có trong `logs/evidence/sprint4/*`.

---

## Sprint 5 — Gate A đã đóng

### Sự cố chính
- `ms_ips` bị `Exited (137)` gây downtime và lỗi `No route to host` trong một số capture run.
- Nmap host discovery fail khi phụ thuộc ICMP.

### Fix chính đã áp dụng
- `scripts/ips_entrypoint.sh`:
  - Startup build + fallback binary.
  - Runtime snapshot deterministic (`runtime_snapshot.txt`).
  - Ghi state startup: timestamp/fail-open/iptables/route.
- `docker-compose.yml`:
  - tăng khả năng tự phục hồi container IPS bằng restart policy.
- `scripts/attack_synscan.sh`:
  - đổi scan sang `nmap -Pn` để không phụ thuộc ICMP host discovery.
- Security hardening config path:
  - `logging.alert_file` bắt buộc absolute path.
  - chặn path traversal `..`.
- Dev hardening parser:
  - cho phép/resolve biến port (ví dụ `$HTTP_PORT`) trước validation.

### Evidence đã có
- Bundle ổn định cuối Sprint 5:
  - `logs/evidence/sprint5_gateA_final/`
  - gồm:
    - `runtime_health.txt`
    - `runtime_snapshot.txt`
    - `connectivity.txt`
    - `attacks.txt`
    - `alert_tail.txt`
    - `ips_logs_tail.txt`

---

## Sprint 6 — Đang chạy

## Cách chạy hiện tại
- Team đang dùng recursive loop:
  1) Build/test + compose up + health checks
  2) Attack simulation + evidence capture
  3) Phân loại lỗi: runtime / routing / detection / security
  4) Áp fix tối thiểu
  5) Rerun full loop đến khi sạch bug

## Tình trạng mới nhất
- Dev loop report:
  - Build pass
  - CTest pass 48/48
  - Parser/engine/flow targeted tests pass
- Security gate active:
  - theo dõi drift fail-open default
  - theo dõi evidence integrity + enforcement visibility

---

## 3) Commit đã tạo trong phiên

- `3d0f5e3` — `fix: harden IPS startup and host discovery`
  - gồm hardening startup path và host discovery fix (`nmap -Pn`).

---

## 4) File thay đổi quan trọng

### Runtime/Ops
- `docker-compose.yml`
- `scripts/ips_entrypoint.sh`
- `scripts/attacker_entrypoint.sh`
- `scripts/attack_synscan.sh`

### Detection/Engine/Flow/Threshold
- `src/detection/engine.cpp`, `src/detection/engine.h`
- `src/detection/matcher.cpp`, `src/detection/matcher.h`
- `src/flow/*`
- `src/detection/threshold.*`
- `src/daq/nfq_daq.*`
- `src/daq/pcap_daq.*`

### Config/Logging
- `src/util/config.cpp`, `src/util/config.h`
- `src/logger/alert_fast.*`
- `config/minisnort.yaml`

### Tests
- `tests/test_parser.cpp`
- `tests/test_engine.cpp`
- `tests/test_flow.cpp`
- `tests/test_matcher.cpp`
- `tests/CMakeLists.txt`

---

## 5) Lưu ý vận hành & demo

1. Không dùng ICMP ping làm tiêu chí reachability duy nhất (có thể bị drop theo policy).
2. Nmap nên dùng `-Pn` cho host discovery trong lab này.
3. Chỉ đọc `runtime_snapshot.txt` sau khi IPS startup hoàn tất để tránh stale snapshot.
4. Ưu tiên đánh giá bằng full-loop thay vì partial checks.

---

## 6) Acceptance criteria đề xuất cho Sprint 6

- IPS không crash/restart bất thường trong soak window.
- Đường attacker → ips → victim ổn định (ít nhất TCP 22/80).
- CTest full-suite pass ổn định.
- Strict profile: traffic độc hại bị block + có alert tương ứng.
- Fail-open profile (khi bật explicit): duy trì availability khi inspection path unavailable.
- Evidence bundle đầy đủ và tái lập được trong một iteration sạch.

---

## 7) Next step khuyến nghị

1. Chạy Sprint 6 iteration tiếp theo theo full-loop.
2. Tạo bundle cuối: `logs/evidence/sprint6_final/*`.
3. Chốt sign-off Sprint 6 sau khi có một run sạch đáp ứng toàn bộ acceptance criteria.

# HANDOUT THỰC HÀNH MINI SNORT (TIẾNG VIỆT)

## 1) Mục tiêu buổi lab

Buổi lab này giúp bạn:
- Dựng môi trường mô phỏng IDS/IPS theo kiến trúc tương tự Snort 3 bằng Docker.
- Chạy được binary `minisnort` trong container IPS.
- Xác minh build/test cho phần Sprint 0–1.
- Theo dõi log theo thời gian thực và lưu bằng chứng (evidence) phục vụ demo/báo cáo.

> Trạng thái hiện tại của dự án: đã có nền Sprint 0 và decoder Sprint 1.

---

## 2) Topology lab

Ba container chính:
- `ms_attacker` (máy tấn công)
- `ms_ips` (máy IPS chạy MiniSnort)
- `ms_victim` (máy nạn nhân)

Hai mạng Docker:
- `net_attack` (Attacker ↔ IPS)
- `net_victim` (IPS ↔ Victim)

Traffic Attacker đi đến Victim sẽ qua IPS để phân tích/chặn.

---

## 3) Cấu trúc file quan trọng

- `docker-compose.yml`: định nghĩa topology 3 container.
- `scripts/lab_up.sh`, `scripts/lab_down.sh`: bật/tắt lab.
- `scripts/ips_entrypoint.sh`: cấu hình iptables/NFQUEUE và chạy `minisnort`.
- `config/minisnort.yaml`: cấu hình runtime.
- `config/rules/local.rules`: rule demo.
- `src/`: mã nguồn C++.
- `tests/test_decoder.cpp`: test cho Sprint 1.
- `logs/evidence/sprint0|sprint1/`: thư mục lưu log bằng chứng.

---

## 4) Yêu cầu môi trường

- Docker + Docker Compose.
- CMake + compiler C++17.
- Môi trường Linux là tốt nhất cho NFQUEUE/inline IPS.

> Lưu ý quan trọng: trên macOS Docker Desktop, hành vi NFQUEUE có thể khác Linux thật. Nếu cần chứng minh chặn gói inline chuẩn, nên kiểm chứng lại trên Linux host/VM.

---

## 5) Quy trình chạy lab (Sprint 0–1)

### Bước 1: Khởi động lab

```bash
./scripts/lab_up.sh
```

### Bước 2: Kiểm tra trạng thái container

```bash
docker compose ps
```

Kỳ vọng: `ms_ips`, `ms_attacker`, `ms_victim` đều ở trạng thái Up.

### Bước 3: Vào attacker để test nhanh

```bash
docker exec -it ms_attacker bash
```

Ví dụ kiểm tra kết nối:

```bash
ping -c 3 172.21.0.20
curl http://172.21.0.20
```

### Bước 4: Build + test trên host

```bash
cmake -S . -B build-verify -G "Unix Makefiles"
cmake --build build-verify -j 4
ctest --test-dir build-verify --output-on-failure
```

Kỳ vọng hiện tại: test decoder pass (5/5).

### Bước 5: Tắt lab

```bash
./scripts/lab_down.sh
```

---

## 6) Theo dõi log realtime và lưu evidence

### 6.1 Theo dõi realtime

```bash
./scripts/tail_evidence.sh sprint1
```

### 6.2 Capture output vào file evidence

Script:
- `scripts/verify_capture.sh`

Ví dụ chỉ capture test cho Sprint 1:

```bash
./scripts/verify_capture.sh sprint1 "" \
  "ctest --test-dir /Users/tin12q/Projects/lab_ips_sec/build-verify --output-on-failure" \
  "" "" ""
```

Các file sẽ được ghi vào:
- `logs/evidence/sprint1/build.txt`
- `logs/evidence/sprint1/test.txt`
- `logs/evidence/sprint1/runtime.txt`
- `logs/evidence/sprint1/attacks.txt`
- `logs/evidence/sprint1/alerts.txt`

---

## 7) Nội dung kỹ thuật đã hoàn thành (đến Sprint 1)

### Sprint 0
- Dựng skeleton project C++ + CMake.
- Tạo Dockerfiles và `docker-compose.yml` cho 3 container.
- Có entrypoint cho IPS/Attacker.
- Có cấu hình và rule mẫu.
- Binary `minisnort` build được.

### Sprint 1
- Hoàn thiện `Packet` model.
- Decoder Ethernet/IPv4/TCP/UDP/ICMP với kiểm tra bounds.
- Có hàm tóm tắt packet (`summarizePacket`).
- Unit test decoder pass.

---

## 8) Lưu ý khi demo

- Mặc định entrypoint IPS đang chạy NFQUEUE theo hướng fail-closed; có thể bật fail-open bằng biến môi trường `MINISNORT_FAIL_OPEN=1`.
- Nếu demo inline IPS gặp khác biệt trên macOS, chuyển sang Linux VM để có kết quả sát thực tế netfilter/NFQUEUE.
- Luôn lưu evidence theo từng sprint để dễ viết báo cáo.

---

## 9) Checklist nộp bài (gợi ý)

- [ ] `docker compose ps` có đủ 3 container Up.
- [ ] Build thành công.
- [ ] `ctest` pass.
- [ ] Có evidence file cho sprint tương ứng.
- [ ] Có ảnh/chụp terminal cho phần demo quan trọng.

---

## 10) Bước tiếp theo

Bắt đầu Sprint 2:
- Parse rule Snort subset.
- RuleStore index theo proto/port.
- Unit test parser (đúng/sai cú pháp).

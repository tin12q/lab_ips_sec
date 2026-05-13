# BÁO CÁO MÔN HỌC
## Đề tài: Thiết kế và triển khai hệ thống MiniSnort IPS trong môi trường Docker Lab

---

## 1. Overview (Tổng quan đề tài)
Trong bối cảnh các cuộc tấn công mạng ngày càng phổ biến, việc chỉ phát hiện mà không ngăn chặn là chưa đủ đối với nhiều hệ thống thực tế. Vì vậy, nhóm chọn xây dựng một mô hình **Intrusion Prevention System (IPS)** có khả năng phân tích gói tin theo thời gian thực và đưa ra hành động phù hợp.

Mục tiêu chính của đề tài:
- Xây dựng hệ thống IPS hoạt động **inline** trên Linux.
- Phát hiện các hành vi tấn công phổ biến bằng rule engine kiểu Snort.
- Thực thi hành động `alert` hoặc `drop` trực tiếp trên luồng mạng.
- Cung cấp dashboard để theo dõi luật và cảnh báo runtime.

Phạm vi thực hiện trong Docker Lab gồm 4 thành phần: attacker, IPS, victim, dashboard.

---

## 2. Why Choosing (Lý do chọn đề tài)
Nhóm chọn đề tài này vì các lý do sau:
- IPS là hướng phòng thủ chủ động, có tính ứng dụng cao trong vận hành hệ thống thật.
- Đề tài bám sát kiến thức môn học: mạng máy tính, bảo mật mạng, lập trình hệ thống.
- Có thể kiểm chứng trực quan bằng demo tấn công–phòng thủ trong lab.
- Có giá trị mở rộng cho nghiên cứu nâng cao như tối ưu hiệu năng, tích hợp SIEM, hoặc kết hợp machine learning.

---

## 3. Theory (Cơ sở lý thuyết)

### 3.1 IDS và IPS
- **IDS (Intrusion Detection System):** chỉ phát hiện và cảnh báo, không chặn lưu lượng.
- **IPS (Intrusion Prevention System):** phát hiện và ngăn chặn trực tiếp, thường triển khai inline.

### 3.2 Netfilter và NFQueue trong Linux
- Netfilter là framework xử lý packet trong Linux kernel.
- NFQueue cho phép chuyển packet từ kernel sang userspace để phân tích.
- Sau khi phân tích, chương trình trả verdict:
  - `NF_ACCEPT`: cho phép packet đi tiếp.
  - `NF_DROP`: loại bỏ packet.

### 3.3 Kỹ thuật phát hiện áp dụng
- **Signature matching:** so khớp mẫu tấn công theo `content`, `pcre`, `flags`, `itype`.
- **Flow tracking:** theo dõi trạng thái kết nối TCP (ví dụ `established`).
- **Threshold/rate limiting:** phát hiện hành vi bất thường theo tần suất (SYN scan, brute force).
- **HTTP inspection:** kiểm tra URI, header, body để nhận diện SQLi/path traversal.

---

## 4. Architecture (Kiến trúc hệ thống)

### 4.1 Topology
- `ms_attacker` (10.200.0.10): mô phỏng tấn công.
- `ms_ips` (10.200.0.2 / 10.201.0.2): node IPS bridge 2 mạng.
- `ms_victim` (10.201.0.20): dịch vụ mục tiêu.
- `ms_dashboard` (host:8080): giao diện giám sát.

### 4.2 Luồng xử lý gói tin
1. DAQ nhận packet từ NFQueue.
2. Decoder parse giao thức Ethernet/IP/TCP/UDP/ICMP.
3. Engine chọn tập rule ứng viên theo protocol/port.
4. Matcher kiểm tra điều kiện nội dung, regex, flow, threshold.
5. Trả verdict ACCEPT/DROP về kernel.
6. Logger ghi cảnh báo vào `alert.log`.

### 4.3 Chính sách vận hành
- Hỗ trợ fail-open có kiểm soát để ưu tiên tính sẵn sàng khi inspection gặp lỗi.

---

## 5. Technology (Công nghệ sử dụng)
- **C++:** triển khai lõi IPS (DAQ, decoder, detection engine, rule engine).
- **Python:** backend dashboard.
- **JavaScript/HTML/CSS:** frontend dashboard.
- **Bash:** script tự động dựng lab và chạy kịch bản tấn công.
- **Docker + Docker Compose:** mô phỏng môi trường mạng đa container.
- **Linux Netfilter/NFQueue/iptables:** cơ chế chặn packet inline.
- **CTest:** kiểm thử logic parser, matcher, flow, threshold, engine.

---

## 6. Code Implementation (Triển khai mã nguồn)

### 6.1 Các module chính
- `src/daq/`: nhận packet từ NFQueue hoặc PCAP.
- `src/decoder/`: parse packet thành cấu trúc dữ liệu chuẩn.
- `src/detection/engine.cpp`: điều phối pipeline phát hiện.
- `src/detection/matcher.cpp`: đối sánh điều kiện rule.
- `src/flow/`: quản lý trạng thái kết nối TCP.
- `src/detection/threshold.cpp`: phát hiện theo ngưỡng tần suất.
- `src/rules/`: parser và rule store.
- `src/logger/alert_fast.cpp`: ghi alert dạng fast log.

### 6.2 Rule tiêu biểu trong hệ thống
- Alert ICMP Ping.
- Alert TCP SYN scan theo threshold.
- Alert SSH brute force theo flow + threshold.
- Drop SQL Injection `UNION SELECT`.
- Drop truy cập `/admin`.
- Drop path traversal `../`.
- Drop user-agent `sqlmap`.

### 6.3 Điểm kỹ thuật nổi bật
- Candidate filtering giúp giảm chi phí matching.
- Kết hợp flow + threshold giảm false positive.
- Tách module rõ ràng giúp dễ test, dễ bảo trì.

---

## 7. Demo (Thực nghiệm)

### 7.1 Chuẩn bị
```bash
./scripts/lab_up.sh
tail -f logs/alert.log
```
Mở dashboard tại: `http://localhost:8080`

### 7.2 Kịch bản demo
1. **ICMP ping** → sinh alert, không block.
2. **SYN scan** vượt ngưỡng → sinh alert.
3. **SSH brute force** → alert theo trạng thái kết nối.
4. **SQL injection** → packet bị drop, request lỗi.
5. **Admin URL/sqlmap UA** → bị drop ngay.

### 7.3 Kết quả quan sát
- Alert hiển thị đầy đủ SID, message, timestamp.
- Các traffic độc hại thuộc chính sách block bị chặn ngay tại kernel.

---

## 8. Evaluation (Đánh giá)

### 8.1 Ưu điểm
- Mô hình IPS inline hoạt động thực, không chỉ mô phỏng lý thuyết.
- Rule engine linh hoạt, hỗ trợ nhiều kiểu điều kiện.
- Lab Docker dễ tái lập để demo và kiểm thử.

### 8.2 Hạn chế
- Chưa benchmark sâu throughput/latency ở tải lớn.
- Rule set còn giới hạn, chưa tích hợp threat intel ngoài.

### 8.3 Hướng phát triển
- Tối ưu hiệu năng xử lý packet.
- Mở rộng rule parser cho nhiều option nâng cao hơn.
- Đẩy alert lên hệ thống tập trung (ELK/SIEM).

---

## 9. Conclusion (Kết luận)
Đề tài đã xây dựng thành công một hệ thống MiniSnort IPS có khả năng phát hiện và ngăn chặn tấn công trong môi trường lab. Kết quả thực nghiệm chứng minh pipeline hoạt động đúng mục tiêu, đồng thời tạo nền tảng tốt cho các nghiên cứu mở rộng theo hướng production-like trong tương lai.

---

## 10. Tài liệu tham khảo
- Tài liệu Linux Netfilter/NFQueue.
- Tài liệu Snort rule syntax.
- Mã nguồn và script trong dự án `lab_ips_sec`.

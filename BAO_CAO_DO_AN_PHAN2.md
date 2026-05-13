# BÁO CÁO ĐỒ ÁN - PHẦN 2 (Tiếp theo)

## 5.7. Phân tích hạn chế của hệ thống

Bên cạnh những ưu điểm, hệ thống cũng có những hạn chế cần được nhận diện và hiểu rõ.

Hạn chế lớn nhất là single-threaded architecture. Hệ thống chỉ sử dụng một thread để xử lý tất cả packets, nghĩa là packets phải được xử lý tuần tự. Điều này tạo ra bottleneck nghiêm trọng cho throughput. Trong khi CPU hiện đại có nhiều cores, hệ thống chỉ utilize một core. Kết quả là throughput giới hạn ở khoảng 1,000 packets per second, tương đương 12 Mbps với packet size trung bình. Con số này quá thấp cho production environments nơi traffic thường ở mức gigabit. Để so sánh, Snort 3 với multi-threading có thể handle hàng trăm nghìn packets per second. Single-threaded design cũng nghĩa là một packet phức tạp requiring extensive processing có thể block processing của tất cả packets khác, causing latency spikes.

Protocol support còn rất hạn chế. Hệ thống chỉ hỗ trợ IPv4, TCP, UDP, và ICMP. Không có support cho IPv6, mặc dù IPv6 adoption đang tăng nhanh. Không có support cho các protocols khác như SCTP, GRE, ESP, AH. Không có support cho encapsulation protocols như VLAN, MPLS, GRE tunnels. Không có support cho fragmented IP packets - fragmented packets sẽ không được reassemble và có thể bypass detection. Không có application layer protocol parsers ngoài HTTP basic parsing - không có DNS, FTP, SMTP, SSH protocol analysis. Những limitations này nghĩa là nhiều attacks targeting những protocols không được detect.

Rule syntax chưa đầy đủ so với Snort. Nhiều Snort options không được support như flowbits cho stateful detection across multiple packets, byte_test và byte_jump cho binary protocol inspection, dsize cho packet size checking, ttl và tos cho IP header fields, seq và ack cho TCP sequence numbers, isdataat cho checking data availability at offset, metadata và reference cho rule documentation. Không có support cho rule variables ngoài port variables. Không có support cho rule includes và rule chaining. Những limitations này nghĩa là không thể import Snort community rules directly và phải rewrite chúng, losing benefit của large existing rule database.

Pattern matching chưa được optimize. Content matching sử dụng simple string search algorithm với complexity O(n\*m). Không có advanced algorithms như Boyer-Moore, Aho-Corasick, hoặc Hyperscan được sử dụng trong production IDS/IPS. Với nhiều content patterns, search time scale linearly. PCRE regex matching cũng có thể expensive, đặc biệt với complex patterns hoặc backtracking. Không có pattern compilation optimization hoặc caching. Kết quả là pattern matching có thể become bottleneck khi có nhiều rules với nhiều patterns.

Không có preprocessors, một component quan trọng của Snort. Preprocessors thực hiện normalization và reassembly trước khi detection. Frag3 preprocessor reassemble fragmented IP packets, preventing fragmentation-based evasion. Stream5 preprocessor reassemble TCP streams, allowing detection trên reassembled data thay vì individual packets. HTTP inspect preprocessor normalize HTTP traffic, handling various encodings và evasion techniques. Không có những preprocessors này, hệ thống vulnerable đến nhiều evasion techniques mà attackers có thể sử dụng để bypass detection.

Logging capabilities còn đơn giản. Chỉ có fast alert format được support. Không có full packet logging capability - không thể capture full packets cho forensic analysis. Không có JSON output format mà nhiều SIEM systems expect. Không có syslog output cho centralized logging. Không có database output cho structured storage. Alert log là plain text file, khó query và analyze programmatically. Không có log rotation mechanism - log file có thể grow indefinitely. Những limitations này make integration với enterprise security infrastructure khó khăn.

Rule management còn primitive. Rules phải được edit manually trong text file. Không có rule versioning hoặc change tracking. Không có rule testing framework để verify rules trước khi deploy. Không có rule performance profiling để identify slow rules. Không có automatic rule updates từ threat intelligence feeds. Không có rule categories hoặc tagging system cho organization. Không có rule enable/disable mechanism ngoài commenting out. Với large rule sets, management become cumbersome và error-prone.

Performance monitoring capabilities thiếu. Không có built-in metrics collection. Không có visibility vào packets per second, bytes per second, drop rate, hoặc queue depth. Không có per-rule performance metrics để identify expensive rules. Không có alerting khi system overload. Không có profiling tools để identify bottlenecks. Operators phải rely trên external tools như docker stats hoặc system monitoring tools, không có IPS-specific insights.

High availability features không tồn tại. Hệ thống là single point of failure. Không có failover mechanism - nếu IPS fail, traffic stop hoặc bypass IPS completely. Không có load balancing capability - không thể distribute traffic across multiple IPS instances. Không có state synchronization - nếu failover xảy ra, flow state và threshold counters lost. Cho production deployment, những features này essential nhưng completely absent.

Security hardening chưa đầy đủ. IPS process phải chạy với root privileges để access NFQueue, violating principle of least privilege. Không có input sanitization cho tất cả inputs - potential cho injection attacks. Không có rate limiting cho alert generation - attacker có thể flood alerts để hide real attacks hoặc cause disk full. Không có protection against resource exhaustion attacks. Config file không được encrypted - sensitive information có thể exposed. Những security issues này make system itself vulnerable.

Scalability fundamentally limited. Single-threaded architecture không scale với more CPU cores. Memory usage scale linearly với number of flows và threshold counters, có thể become issue với very large numbers of concurrent connections. Rule evaluation time scale với number of rules. Không có distributed architecture option. Hệ thống designed cho small-scale deployment, không thể scale đến enterprise levels.

Testing coverage, mặc dù good, vẫn có gaps. Không có performance regression tests. Không có stress tests với extreme loads. Không có chaos engineering tests với random failures. Không có security tests như fuzzing hoặc penetration testing. Không có long-term stability tests (days hoặc weeks). Những additional tests sẽ provide more confidence cho production readiness.

Documentation, mặc dù comprehensive cho setup và usage, thiếu một số areas. Không có detailed architecture documentation với diagrams. Không có API documentation cho code modules. Không có troubleshooting guide cho common issues. Không có performance tuning guide. Không có security best practices guide. Những documentation gaps make system harder để maintain và operate.

User interface của dashboard, mặc dù functional, còn basic. Không có advanced filtering hoặc search capabilities cho alerts. Không có visualization cho attack patterns hoặc trends. Không có drill-down capabilities cho detailed analysis. Không có export functionality cho reports. Không có user authentication hoặc access control. Không có mobile-responsive design. Dashboard serve basic monitoring needs nhưng lack advanced features của enterprise security consoles.

---

## PHẦN VI: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 6.1. Tổng kết đề tài

Đề tài "Thiết kế và triển khai hệ thống MiniSnort IPS trong môi trường Docker Lab" đã đạt được những mục tiêu đề ra ban đầu. Chúng tôi đã successfully xây dựng một hệ thống Intrusion Prevention System hoạt động thực tế, có khả năng phát hiện và ngăn chặn các cuộc tấn công mạng trong môi trường lab.

Về mặt kỹ thuật, hệ thống demonstrate understanding sâu về các concepts cơ bản của IPS. Pipeline xử lý gói tin từ kernel space đến userspace, từ raw bytes đến structured data, từ detection đến action, đã được implement hoàn chỉnh. Các kỹ thuật phát hiện khác nhau - signature-based, stateful, threshold-based, HTTP inspection - đã được integrate thành một detection engine cohesive. Inline blocking capability đã được prove through actual testing với 100% success rate.

Về mặt phần mềm, codebase demonstrate good software engineering practices. Module hóa rõ ràng, code quality cao, testing comprehensive, documentation đầy đủ. Hệ thống không chỉ work mà còn maintainable và extensible. Architecture cho phép future enhancements mà không require major rewrites.

Về mặt triển khai, Docker-based lab environment provide excellent platform cho testing và demonstration. Môi trường isolated, reproducible, và easy to setup. Attack scenarios cover range of common attacks, demonstrating system capabilities effectively.

Về mặt giáo dục, project provide invaluable learning experience. Hands-on implementation của IPS concepts solidify theoretical knowledge. Working với multiple technologies - C++, Linux networking, Docker, web development - broaden technical skills. Challenges encountered và overcome provide practical problem-solving experience.

Testing results validate system effectiveness. Unit tests với 100% pass rate confirm correctness của individual modules. Integration tests demonstrate successful interaction giữa modules. System tests với real attacks prove actual detection và blocking capabilities. Performance tests establish baseline metrics và identify limitations. Stability tests confirm reliability cho extended operation.

Tuy nhiên, hệ thống cũng có những limitations rõ ràng. Performance không đủ cho high-throughput environments. Protocol support limited. Feature set chưa complete so với production IPS systems. Những limitations này acceptable cho một academic project nhưng prevent production deployment.

Quan trọng nhất, project achieve primary goal: understanding how IPS works. Bằng cách build từ ground up, chúng tôi gain deep insight vào challenges và trade-offs trong IPS design. Experience này invaluable cho future work trong security field.

### 6.2. Đóng góp của đề tài

Đề tài mang lại nhiều đóng góp có giá trị trên nhiều aspects.

Về mặt học thuật, đề tài provide một implementation reference cho IPS concepts. Không giống textbooks chỉ describe theory, project này show actual working code. Students và researchers có thể study codebase để understand implementation details. Architecture và design decisions được document, providing insights vào engineering trade-offs.

Về mặt kỹ thuật, project demonstrate feasibility của building IPS với modern C++ và Linux technologies. Code quality và testing practices serve như examples của good software engineering. Module architecture show how to structure complex system cho maintainability. Docker deployment show modern approach đến lab environments.

Về mặt giáo dục, project serve như excellent learning resource. Complete lab environment cho phép hands-on experimentation. Attack scenarios provide practical examples của security concepts. Documentation enable self-study. Project có thể được used trong security courses như lab assignment hoặc reference implementation.

Về mặt cộng đồng, nếu open-sourced, project có thể benefit others interested trong IPS development. Codebase có thể serve như starting point cho similar projects. Issues encountered và solutions found có thể help others avoid same pitfalls. Community contributions có thể improve và extend system.

### 6.3. Bài học kinh nghiệm

Qua quá trình thực hiện đề tài, chúng tôi học được nhiều bài học quý giá.

Về technical skills, project significantly improve programming abilities. Working với C++ system programming, Linux APIs, networking protocols deepen technical knowledge. Debugging complex issues như packet parsing errors, race conditions, memory leaks develop troubleshooting skills. Performance optimization attempts teach về profiling và bottleneck identification.

Về software engineering, project reinforce importance của good practices. Module hóa make development và testing much easier. Unit testing catch bugs early, saving debugging time later. Code reviews improve code quality. Documentation prove essential khi revisiting code after time. Version control enable safe experimentation. Những practices này applicable đến any software project.

Về project management, experience teach về planning và execution. Breaking down large project thành manageable modules essential. Setting milestones help track progress. Prioritizing features based trên importance và difficulty optimize resource usage. Regular testing prevent accumulation của bugs. Những lessons applicable đến future projects.

Về problem-solving, project present many challenges requiring creative solutions. NFQueue integration issues require deep dive vào Linux networking. Performance bottlenecks require profiling và optimization. Docker networking complexities require understanding của container networking. Each challenge overcome build confidence và problem-solving abilities.

Về collaboration, nếu làm team, project teach về teamwork. Dividing work based trên strengths optimize productivity. Communication essential để coordinate efforts. Code reviews facilitate knowledge sharing. Resolving conflicts require compromise. Những skills essential trong professional environment.

Về time management, project teach về balancing multiple tasks. Development, testing, documentation, và presentation preparation all compete cho time. Prioritization essential. Avoiding perfectionism và knowing when good enough important. Meeting deadlines require discipline.

### 6.4. Hướng phát triển tương lai

Hệ thống có nhiều hướng phát triển tiềm năng để improve capabilities và expand use cases.

Hướng phát triển ngắn hạn tập trung vào addressing immediate limitations. Multi-threading implementation là priority cao nhất để improve throughput. Có thể sử dụng thread pool pattern với một thread cho packet acquisition, multiple worker threads cho detection, và một thread cho logging. Thread-safe data structures cần được implement cho shared state như flow table và threshold counters. Synchronization overhead cần được minimize để avoid bottlenecks.

Pattern matching optimization là another high-priority improvement. Implementing Aho-Corasick algorithm cho multi-pattern matching có thể dramatically reduce content matching time. Hyperscan library, developed bởi Intel, provide highly optimized regex matching và có thể integrate. Pattern compilation và caching có thể avoid redundant work. Những optimizations có thể improve detection performance by orders of magnitude.

Protocol support expansion enable detection của more attack types. IPv6 support increasingly important as IPv6 adoption grows. DNS protocol parser enable detection của DNS tunneling và exfiltration. TLS/SSL inspection, mặc dù challenging, enable detection của encrypted attacks. Application protocol parsers cho FTP, SMTP, SSH provide deeper visibility. Fragmentation reassembly prevent evasion attacks.

Rule syntax enhancements improve expressiveness. Flowbits enable stateful detection across multiple packets, essential cho detecting multi-stage attacks. Byte_test và byte_jump enable binary protocol inspection. Additional HTTP modifiers như http_cookie, http_method enable more precise web attack detection. Rule variables và includes improve rule organization. Metadata fields improve rule documentation.

Preprocessor implementation significantly improve detection accuracy. IP fragmentation reassembly prevent fragmentation-based evasion. TCP stream reassembly enable detection trên complete streams rather than fragments. HTTP normalization handle various encodings và evasion techniques. Protocol anomaly detection catch violations của protocol specifications. Những preprocessors essential cho production-grade IPS.

Hướng phát triển trung hạn focus trên advanced features và enterprise capabilities. Machine learning integration có thể enable anomaly-based detection. ML models có thể được trained trên normal traffic patterns và detect deviations. Behavioral analysis có thể identify insider threats hoặc compromised accounts. ML-based detection complement signature-based detection, catching zero-day attacks.

Threat intelligence integration keep system updated với latest threats. Automatic rule updates từ threat feeds ensure protection against new attacks. Integration với threat intelligence platforms như MISP provide context về attacks. IP reputation services enable blocking của known malicious IPs. File hash checking enable detection của known malware.

Advanced logging và analytics improve visibility. JSON output format enable integration với SIEM systems. Full packet capture provide forensic evidence. Database storage enable complex queries. Log aggregation và correlation identify attack patterns. Visualization dashboards provide intuitive security insights. Alerting mechanisms notify administrators của critical events.

Rule management improvements make system easier to operate. Web-based rule editor với syntax validation improve usability. Rule testing framework enable validation trước deployment. Rule performance profiling identify expensive rules. Rule versioning track changes over time. Rule categories và tagging improve organization. Automatic rule optimization suggest improvements.

Hướng phát triển dài hạn envision enterprise-grade system. High availability architecture với active-passive hoặc active-active failover ensure uptime. State synchronization giữa nodes maintain consistency. Load balancing distribute traffic across multiple IPS instances. Health monitoring và automatic failover minimize downtime. Geo-distributed deployment provide global coverage.

Distributed architecture enable massive scale. Manager-sensor architecture với centralized management và distributed sensors. Horizontal scaling add capacity by adding sensors. Cloud-native deployment trên Kubernetes enable elastic scaling. Hardware acceleration với DPDK hoặc GPU enable multi-gigabit throughput. Những capabilities essential cho protecting large enterprise networks.

Advanced integration expand ecosystem. SOAR platform integration enable automated response actions. Ticketing system integration streamline incident management. Identity management integration provide user context. Network access control integration enable dynamic quarantine. Firewall integration enable coordinated defense. API-first design enable custom integrations.

Research directions explore cutting-edge techniques. Deep learning models cho advanced threat detection. Adversarial machine learning để defend against evasion. Encrypted traffic analysis without decryption. Behavioral biometrics cho user authentication. Deception technologies như honeypots. Những research areas push boundaries của security technology.

### 6.5. Lời kết

Đề tài "Thiết kế và triển khai hệ thống MiniSnort IPS" là một journey đầy thách thức nhưng cũng rất bổ ích. Từ việc nghiên cứu lý thuyết về IPS, thiết kế kiến trúc hệ thống, implement từng module, debug countless issues, đến cuối cùng là seeing system successfully detect và block attacks - mỗi bước đều mang lại valuable learning experiences.

Hệ thống chúng tôi xây dựng, mặc dù có limitations, đã successfully demonstrate core concepts của IPS. Nó prove rằng với understanding đúng về networking, security, và software engineering, có thể build một security system từ ground up. Project không chỉ là về code mà còn về understanding - understanding về how packets flow through network stack, how attacks work, how detection algorithms operate, how systems fail và recover.

Những kiến thức và kỹ năng gained từ project này sẽ invaluable trong career paths liên quan đến security, networking, hoặc systems programming. Experience của building something complex từ scratch, encountering real-world problems, và finding solutions build confidence và competence không thể gain từ chỉ đọc textbooks.

Chúng tôi hy vọng rằng project này, với documentation đầy đủ và code quality tốt, có thể serve như resource hữu ích cho others interested trong IPS development. Nếu project inspire hoặc help someone trong learning journey của họ, đó sẽ là greatest achievement.

Security là một field constantly evolving, với new threats emerging every day. Systems như IPS play crucial role trong defending against những threats này. Mặc dù MiniSnort IPS không ready cho production deployment, nó represent một step trong understanding và contributing đến field of network security. Với continued development và improvements, có thể một ngày nó evolve thành something truly production-worthy.

Cuối cùng, chúng tôi muốn express gratitude đến instructors, mentors, và peers đã support project này. Their guidance, feedback, và encouragement essential cho success của project. Chúng tôi cũng grateful cho open-source community đã create wonderful tools và libraries mà project này build upon.

Network security là responsibility của tất cả chúng ta. Mỗi contribution, dù lớn hay nhỏ, help make Internet safer cho everyone. Chúng tôi proud đã contribute một small piece đến puzzle này.

---

**Ngày hoàn thành:** 12 tháng 5 năm 2026  
**Nhóm thực hiện:** MiniSnort IPS Development Team

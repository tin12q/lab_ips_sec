# SYSTEM DESIGN & ARCHITECTURE

## Overall System Architecture

The MiniSnort IPS system is designed with a modular, layered architecture deployed entirely in Docker containers. The system consists of four main components that interact to create a complete lab environment for demonstrating intrusion detection and prevention capabilities.

**[Figure 1: MiniSnort IPS System Architecture Diagram]**

The architecture includes:

**Attacker Container (ms_attacker - 10.200.0.10)**: Simulates the attacker in testing scenarios. Built on Kali Linux with pre-installed attack tools including nmap for network scanning, hydra for brute force attacks, curl for HTTP testing, and custom attack scripts. Connected to the attack network with static IP and default gateway pointing to the IPS container.

**IPS Container (ms_ips - 10.200.0.2 / 10.201.0.2)**: The core component running the MiniSnort program compiled from C++ source code. Features two network interfaces acting as a bridge between networks. Inside the container, iptables redirects all forwarded traffic to NFQueue where MiniSnort analyzes each packet. Configuration files, rules, and logs are mounted from the host for easy management.

**Victim Container (ms_victim - 10.201.0.20)**: Simulates the target system running Ubuntu with HTTP server (port 80) hosting a vulnerable web application and SSH server (port 22) for brute force testing. Intentionally configured with security vulnerabilities to demonstrate IPS detection capabilities.

**Dashboard Container (ms_dashboard - localhost:8080)**: Provides a web interface for monitoring and management. Python Flask backend serves REST APIs to read alert logs and rules. Frontend uses HTML/CSS/JavaScript with a Neon Cyberpunk theme for real-time alert monitoring and rule management.

**Traffic Flow and Inline Blocking Mechanism**

When the attacker sends a packet to the victim, it first arrives at the IPS container's eth0 interface. The Linux kernel routing decides to forward the packet to eth1, but before forwarding, iptables intercepts it using the NFQUEUE target at the FORWARD hook. The packet is placed in NFQueue and the kernel waits for a verdict. MiniSnort reads the packet, performs analysis including protocol decoding, rule matching, flow state checking, and threshold evaluation. Based on the analysis, MiniSnort returns either NF_ACCEPT (allow packet to continue) or NF_DROP (discard packet). If a rule matches, an alert is logged. This mechanism ensures true inline operation where no malicious packet can bypass the IPS.

---

## System Components

### Packet Capture Module (DAQ)

The Data Acquisition module serves as the system entry point, responsible for collecting packets from various sources. Designed using the Strategy Pattern, it allows flexible switching between acquisition methods.

**NFQ DAQ** is the primary mode for production IPS, using libnetfilter_queue to interact with the Linux kernel's NFQueue mechanism. It registers a callback function that kernel invokes for each new packet, receives raw packet data and metadata, passes it to the detection pipeline, and returns the verdict to kernel for enforcement. This mode enables true inline blocking capability.

**PCAP DAQ** is used for testing and offline analysis, using libpcap to read packets from PCAP files or network interfaces in promiscuous mode. Useful for replaying captured attacks, testing new rules, and analyzing traffic patterns without requiring a live environment. However, it lacks blocking capability as it only reads traffic copies.

The DAQ abstraction hides implementation differences, providing unified methods like start, stop, and packet callbacks, allowing other modules to process normalized Packet objects without concerning the data source.

### Decoder Module

The Decoder transforms raw packet bytes into structured data through layered parsing following the OSI model.

**Layer 2 (Ethernet)**: Parses the first 14 bytes to extract destination MAC, source MAC, and EtherType. Only IPv4 (0x0800) is currently supported.

**Layer 3 (IPv4)**: Parses 20+ bytes to extract version, header length, ToS, total length, identification, flags, TTL, protocol number (6=TCP, 17=UDP, 1=ICMP), checksum, source IP, and destination IP. Performs validation and converts from network to host byte order.

**Layer 4 (Transport)**: For TCP, extracts ports, sequence numbers, flags (SYN, ACK, FIN, RST, PSH, URG), window size. For UDP, extracts ports and length. For ICMP, extracts type and code.

The remaining data after headers is the payload, stored with a pointer and length for content matching and HTTP inspection. The result is a Packet object containing all parsed information ready for detection. The decoder handles errors gracefully, rejecting malformed packets without crashing.

### Rules Engine

The Rules Engine consists of Parser and RuleStore components.

**Parser** reads rule files using Snort-like syntax and converts them into Rule objects. It performs tokenization handling quoted strings and escaped characters, parses rule headers (action, protocol, addresses, ports, direction), parses options within parentheses, validates syntax and semantics, and creates Rule objects in memory. Supported options include msg, sid, priority, classtype, content, nocase, distance, pcre, http_uri, http_header, flags, itype, flow, and threshold.

**RuleStore** stores Rule objects and provides efficient querying through multiple indexes. It maintains a protocol index mapping protocol numbers to rule lists and a protocol+port index for faster filtering. The getCandidates method queries with packet protocol and destination port, returning only relevant rules. This dramatically reduces the number of rules to evaluate per packet, improving performance significantly.

### Flow Table

The Flow Table manages TCP connection states, implementing the TCP state machine per RFC 793. It uses a 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) as the flow key with a custom hash function. Each flow entry contains the current state (CLOSED, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSE_WAIT), last seen timestamp, and packet/byte counters.

State transitions are determined by TCP flags. For example, CLOSED + SYN → SYN_SENT, SYN_SENT + SYN+ACK → ESTABLISHED. The table implements timeout mechanisms to evict inactive flows after 60 seconds and LRU eviction when full, preventing memory exhaustion.

Flow information is used in detection for rules with flow conditions like "flow:established" which only match packets in ESTABLISHED state, or "flow:to_server" which only match client-to-server traffic, reducing false positives by understanding connection context.

### Threshold Manager

The Threshold Manager tracks event frequency to detect behavioral anomalies using a sliding window algorithm. It maintains counters for each combination of rule SID and tracking key (source IP or destination IP based on configuration). Each counter stores timestamps of events within a time window.

When a new event occurs, the manager filters the timestamp list to keep only those within the window, adds the current timestamp, and checks if the count exceeds the threshold. If exceeded, the rule triggers and the counter resets. This approach effectively detects attacks based on behavior patterns such as port scans, brute force attempts, and DoS attacks.

### Detection Engine

The Detection Engine is the central coordinator connecting all modules. It receives Packet objects from the Decoder, updates flow state via Flow Table, queries RuleStore for candidate rules, evaluates each rule by checking flow conditions, content/pcre/flags matching, and threshold conditions. Matched rules are collected and verdict is decided based on action precedence: pass > drop > alert. All matched rules are logged, and the final verdict is returned to the kernel.

### Matcher Module

The Matcher performs packet comparison against rule conditions. It supports content matching (string search in payload with case-sensitive/insensitive options), PCRE matching (regex patterns using PCRE2 library), TCP flags matching (checking specific flag combinations), ICMP type matching, and HTTP inspection (parsing HTTP requests to extract method, URI, headers, and body, then applying content matching only on specified parts like http_uri or http_header).

### Logger Module

The Logger records security events in Fast Alert format, similar to Snort. Each alert includes a header with SID and message, classification and priority, timestamp and IP addresses with ports, and protocol-specific information. The logger uses buffered I/O to optimize performance and ensures thread-safety for potential future multi-threading support.

**[Figure 2: System Components Interaction Diagram]**

---

## Data Flow Design

The packet processing pipeline consists of eight sequential steps:

**Step 1 - Packet Acquisition**: Kernel places packet in NFQueue, DAQ callback is triggered, raw bytes are extracted.

**Step 2 - Packet Decoding**: Raw bytes are parsed through Ethernet, IP, and transport layer headers, fields are extracted into Packet struct, validation is performed.

**Step 3 - Flow Tracking**: 5-tuple flow key is computed, flow entry is looked up or created, TCP state machine is updated, flow information is returned.

**Step 4 - Rule Candidate Selection**: RuleStore is queried with protocol and destination port, filtered list of relevant rules is returned, dramatically reducing evaluation overhead.

**Step 5 - Rule Evaluation**: For each candidate rule, flow conditions are checked first, then content/pcre/flags matching is performed, threshold conditions are evaluated, and matched rules are collected.

**Step 6 - Verdict Decision**: Action precedence is applied (pass > drop > alert), if any pass rule matched, verdict is ACCEPT, if any drop rule matched without pass, verdict is DROP, if only alert rules matched, verdict is ACCEPT.

**Step 7 - Logging**: Each matched rule generates an alert entry, formatted in Fast Alert format, written to alert.log file with buffering.

**Step 8 - Verdict Return**: Verdict is returned to kernel via NFQueue API, kernel executes the action (forward or drop packet), pipeline completes and waits for next packet.

**[Figure 3: Packet Processing Pipeline Flowchart]**

---

## Design Decisions and Trade-offs

### Single-threaded vs Multi-threaded Architecture

**Decision**: Single-threaded architecture was chosen for simplicity and deterministic behavior. This approach eliminates synchronization overhead, avoids race conditions and deadlocks, and makes debugging easier. However, it limits throughput to approximately 1,000 packets per second and doesn't utilize multiple CPU cores. For a lab environment and educational purposes, this trade-off is acceptable. Future enhancements could include thread pools with worker threads for detection and lock-free data structures for shared state.

### Userspace vs Kernel Module Implementation

**Decision**: Userspace implementation with NFQueue was selected for development ease and safety. Userspace allows use of rich libraries (C++ STL, PCRE2, spdlog), easier debugging, and crashes don't affect kernel stability. The trade-off is higher latency due to context switching between kernel and userspace, and lower throughput compared to kernel modules. However, for educational purposes and rapid development, userspace is the better choice.

### Signature-based vs Anomaly-based Detection

**Decision**: Primarily signature-based detection with threshold-based components was implemented. Signature-based detection provides high accuracy for known attacks, low false positive rates, and rules that are easy to understand and customize. The limitation is inability to detect zero-day attacks and requirement for regular rule updates. Threshold-based detection complements this by catching behavioral anomalies. Future enhancements could integrate machine learning for anomaly detection.

### Inline Blocking vs Passive Monitoring

**Decision**: Inline blocking (IPS mode) was chosen to demonstrate active defense capabilities. This allows real-time attack prevention without human intervention and ensures malicious packets never reach the victim. The trade-off is that IPS becomes a single point of failure and false positives can block legitimate traffic. Mitigation strategies include fail-open mechanisms, careful rule tuning, and extensive testing before deployment.

### Docker vs Bare Metal Deployment

**Decision**: Docker-based deployment was selected for reproducibility and portability. Docker provides easy setup on any machine, isolated components in containers, and infrastructure as code through Dockerfiles. The slight performance overhead from containerization is acceptable for a lab environment. This approach is perfect for educational purposes, demonstrations, and easy distribution.

### Fast Alert vs Full Packet Logging

**Decision**: Fast Alert format was chosen for lightweight logging with minimal performance impact. It provides human-readable output with essential information and low disk space usage. The limitation is lack of full packet data for forensic analysis. Future enhancements could add PCAP logging options and JSON format for SIEM integration.

### Static vs Dynamic Rule Loading

**Decision**: Static rule loading at startup was implemented for simplicity and predictability. Rules don't change during runtime, eliminating race conditions from concurrent updates. The trade-off is requiring restart to apply rule changes, causing brief downtime. Future enhancements could include SIGHUP handlers for reload without restart and file watching with inotify.

### Fail-Safe Mechanisms

The system implements several fail-safe mechanisms to ensure reliability. The fail-open policy uses iptables "--queue-bypass" flag so if the queue is full or no listener exists, packets are automatically accepted, prioritizing availability over security. Container auto-restart is configured with "restart: always" in Docker Compose, minimizing downtime if MiniSnort crashes. Input validation is performed on all external inputs (packets, configs, rules) with graceful error handling. Resource limits include flow table maximum size with LRU eviction, threshold counter timeouts, and alert log rotation to prevent resource exhaustion.

**[Figure 4: Design Trade-offs Matrix]**

---

This architecture balances simplicity for educational purposes with practical functionality to demonstrate core IPS concepts. The modular design allows easy extension and modification while maintaining clear separation of concerns across components.

# VISUAL ELEMENTS SUGGESTIONS FOR PROJECT REPORT

## Overview

This document provides detailed suggestions for tables, charts, diagrams, and screenshots to enhance the visual presentation of the MiniSnort IPS project report.

---

## PART V: EVALUATION AND RESULTS

### Section 5.2: Unit Testing Results

#### Figure 5.1: Test Execution Time by Module (Bar Chart)

**Type:** Horizontal bar chart  
**Data:**

- Decoder: 0.37s
- Parser: 1.17s
- RuleStore: 0.36s
- Config Loader: 0.68s
- Matcher: 0.63s
- Threshold: 0.42s
- Detection Engine: 0.80s

**Visualization:** Each bar colored differently, with time labels at the end of bars.

#### Figure 5.2: Test Distribution Across Modules (Pie Chart)

**Type:** Pie chart  
**Data:**

- Decoder: 5 tests (10.2%)
- Parser: 8 tests (16.3%)
- RuleStore: 3 tests (6.1%)
- Config Loader: 8 tests (16.3%)
- Matcher: 9 tests (18.4%)
- Threshold: 6 tests (12.2%)
- Detection Engine: 10 tests (20.4%)

**Visualization:** Color-coded slices with percentages and labels.

---

### Section 5.3: Integration Testing Results

#### Figure 5.3: Attack Timeline and IPS Responses

**Type:** Timeline diagram  
**Content:**

```
Time →
0s    [ICMP Ping] → IPS detects → 69 alerts → Allowed
10s   [SYN Scan] → IPS detects → 200 alerts → Allowed
30s   [SSH Brute Force] → IPS detects → 1549 alerts → Allowed
60s   [SQL Injection] → IPS detects → BLOCKED ❌
90s   [Admin URL] → IPS detects → BLOCKED ❌
120s  [ICMP Block] → IPS detects → BLOCKED ❌
```

#### Figure 5.4: Traffic Flow Diagram

**Type:** Network flow diagram  
**Content:**

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Attacker   │────────▶│  MiniSnort   │────────▶│   Victim    │
│ 10.200.0.10 │  Attack │  IPS Bridge  │ Allowed │ 10.201.0.20 │
└─────────────┘         │              │         └─────────────┘
                        │  ✓ Detect    │
                        │  ✓ Analyze   │
                        │  ✓ Block/    │
                        │    Allow     │
                        └──────────────┘
                              │
                              ▼
                        ┌──────────────┐
                        │  Alert Log   │
                        │  Dashboard   │
                        └──────────────┘
```

#### Figure 5.5: Attack Detection Success Rate

**Type:** Stacked bar chart  
**Data:**

- ICMP Ping: 100% detected
- SYN Scan: 100% detected
- SSH Brute Force: 100% detected
- SQL Injection: 100% detected + 100% blocked
- Admin URL: 100% detected + 100% blocked
- ICMP Block: 100% detected + 100% blocked

---

### Section 5.4: Performance Testing Results

#### Figure 5.6: Throughput vs CPU Usage

**Type:** Line graph with dual Y-axis  
**X-axis:** Packets per second (0 - 2000 pps)  
**Y-axis 1:** CPU Usage (0-100%)  
**Y-axis 2:** Packet Loss Rate (0-100%)  
**Lines:**

- CPU Usage: Increases from 5% → 100%
- Packet Loss: Stays at 0% until 1000 pps, then increases

#### Figure 5.7: CPU Time Distribution by Component

**Type:** Pie chart  
**Data:**

- Content Matching: 30%
- PCRE Regex: 25%
- Packet Acquisition: 10%
- Decoding: 5%
- Logging: 5%
- Flow/Threshold: 5%
- Other: 20%

#### Figure 5.8: Latency Comparison

**Type:** Bar chart  
**Data:**

- Baseline (no IPS): 0.15 ms
- With IPS (idle): 1.2 ms
- With IPS (moderate load): 3.5 ms
- With IPS (high load): 5.0 ms

#### Figure 5.9: Memory Usage Over Time

**Type:** Line graph  
**X-axis:** Time (0-3 hours)  
**Y-axis:** Memory (MB)  
**Line:** Stable at 50-70 MB with minor fluctuations

---

### Section 5.5: Stability Testing Results

#### Figure 5.10: 3-Hour Stability Test Timeline

**Type:** Timeline with events  
**Content:**

```
0:00  ├─ System Start
0:15  ├─ First Attack Wave (100 packets)
0:30  ├─ Memory Check: 55 MB ✓
1:00  ├─ Second Attack Wave (500 packets)
1:30  ├─ Memory Check: 58 MB ✓
2:00  ├─ Third Attack Wave (1000 packets)
2:30  ├─ Memory Check: 62 MB ✓
3:00  └─ System Stop - No crashes ✓
```

#### Figure 5.11: Container Health Dashboard

**Type:** Screenshot mockup  
**Content:**

- Container status: Running (green)
- Uptime: 3h 15m 42s
- Restarts: 0
- CPU: 18%
- Memory: 62 MB / 2 GB
- Network I/O: 1.2 MB/s

---

### Section 5.6: System Strengths

#### Figure 5.12: Strength Ratings Spider Chart

**Type:** Radar/spider chart  
**Axes (0-10 scale):**

- Architecture: 9
- Code Quality: 9
- Testing: 10
- IPS Capability: 9
- Rule Engine: 8
- Performance: 6
- Reliability: 9
- Documentation: 9
- Usability: 8

#### Figure 5.13: Module Architecture Diagram

**Type:** Component diagram  
**Content:**

```
┌─────────────────────────────────────────────────┐
│              MiniSnort IPS Core                 │
├─────────────────────────────────────────────────┤
│  ┌──────┐  ┌─────────┐  ┌────────┐  ┌────────┐│
│  │ DAQ  │→ │ Decoder │→ │ Engine │→ │ Logger ││
│  └──────┘  └─────────┘  └────────┘  └────────┘│
│                              ↓                   │
│  ┌──────────┐  ┌─────────┐  ┌──────────┐      │
│  │ RuleStore│  │ Matcher │  │FlowTable │      │
│  └──────────┘  └─────────┘  └──────────┘      │
│                              ↓                   │
│              ┌───────────────────┐              │
│              │ Threshold Manager │              │
│              └───────────────────┘              │
└─────────────────────────────────────────────────┘
```

#### Figure 5.14: Dashboard Screenshot

**Type:** Actual screenshot or mockup  
**Content:**

- Real-time alert feed with neon colors
- Rule list panel
- Statistics panel (total alerts, rules loaded)
- Neon cyberpunk theme

---

### Section 5.7: System Limitations

#### Figure 5.15: Throughput Comparison

**Type:** Bar chart  
**Data:**

- MiniSnort: 1K pps (12 Mbps)
- Snort 2.x: 10K pps (120 Mbps)
- Snort 3.x: 100K pps (1.2 Gbps)
- Suricata: 150K pps (1.8 Gbps)
- Production Req: 50K pps (600 Mbps)

**Visualization:** Bars with different colors, production requirement shown as a red line.

#### Figure 5.16: Feature Completeness Heatmap

**Type:** Heatmap matrix  
**Rows:** Features (Multi-threading, IPv6, Preprocessors, etc.)  
**Columns:** MiniSnort, Snort 2.x, Snort 3.x, Suricata  
**Colors:**

- Green: Fully implemented
- Yellow: Partially implemented
- Red: Not implemented

#### Figure 5.17: Bottleneck Analysis

**Type:** Flow diagram with bottleneck highlight  
**Content:**

```
Packet → [NFQueue] → [Single Thread] ← BOTTLENECK!
                           ↓
                    [Process Queue]
                           ↓
                    [Verdict Return]
```

---

## PART VI: CONCLUSION AND FUTURE DIRECTIONS

### Section 6.4: Future Development

#### Figure 6.1: Development Gantt Chart

**Type:** Gantt chart  
**Timeline:** 12 months  
**Tasks:**

- Month 1-3: Multi-threading, Pattern optimization, IPv6
- Month 3-6: Preprocessors, ML integration, Advanced logging
- Month 6-12: HA/Failover, Distributed architecture, Cloud deployment

#### Figure 6.2: Roadmap Visualization

**Type:** Roadmap diagram  
**Content:**

```
Current State          Short-term (3mo)       Medium-term (6mo)      Long-term (12mo)
─────────────────────────────────────────────────────────────────────────────────
[Lab IPS]         →   [Optimized IPS]    →   [Production IPS]   →   [Enterprise IPS]
- Single thread       - Multi-thread          - Preprocessors         - HA/Failover
- 1K pps             - 10-20K pps            - ML detection          - Load balancing
- Basic rules        - IPv6 support          - Threat intel          - Cloud-native
                     - Fast matching         - Advanced logging      - Multi-gigabit
```

#### Figure 6.3: Expected Throughput Improvements

**Type:** Bar chart with progression  
**Data:**

- Current: 1K pps
- - Multi-threading: 10K pps
- - Aho-Corasick: 20K pps
- - Hyperscan: 50K pps
- - DPDK: 500K pps
- - GPU: 1M pps

#### Figure 6.4: Architecture Evolution

**Type:** Three-panel architecture diagram  
**Panel 1 - Current:**

```
Single Container
├─ Single Thread
└─ NFQueue
```

**Panel 2 - Short-term:**

```
Single Container
├─ Thread Pool (N workers)
├─ Optimized Matching
└─ NFQueue
```

**Panel 3 - Long-term:**

```
Distributed System
├─ Manager Node
├─ Multiple Sensor Nodes
│  ├─ Multi-threaded
│  ├─ DPDK/GPU
│  └─ State Sync
└─ Load Balancer
```

---

## Additional Visual Suggestions

### Screenshots to Include:

1. **Docker Lab Setup**
   - Terminal showing `docker-compose up` output
   - `docker ps` showing 4 running containers

2. **Attack Execution**
   - Terminal showing nmap scan output
   - Terminal showing curl SQL injection attempt
   - Terminal showing blocked response

3. **Alert Log**
   - Tail of alert.log showing formatted alerts
   - Highlighting different alert types

4. **Dashboard Views**
   - Main dashboard with alert feed
   - Rule editor view
   - Statistics panel

5. **Testing Output**
   - CTest output showing all tests passed
   - Build output showing compilation success

### Diagrams to Create:

1. **Packet Processing Pipeline**
   - Detailed flowchart from packet arrival to verdict

2. **TCP State Machine**
   - State diagram showing flow tracking

3. **Threshold Sliding Window**
   - Visual representation of sliding window algorithm

4. **Docker Network Topology**
   - Network diagram showing two networks and IPS bridge

5. **Rule Matching Process**
   - Flowchart showing candidate selection and matching

---

## Tools for Creating Visuals

### Recommended Tools:

1. **Charts/Graphs:**
   - Python matplotlib/seaborn
   - Excel/Google Sheets
   - Chart.js (for web-based)
   - Plotly

2. **Diagrams:**
   - draw.io (diagrams.net)
   - Lucidchart
   - PlantUML
   - Mermaid

3. **Architecture Diagrams:**
   - Excalidraw
   - Cloudcraft
   - Diagrams.net

4. **Screenshots:**
   - Built-in OS screenshot tools
   - Lightshot
   - Snagit

5. **Mockups:**
   - Figma
   - Adobe XD
   - Balsamiq

---

## Color Scheme Suggestions

### For Consistency:

**Primary Colors:**

- Success/Pass: #00FF00 (Green)
- Warning/Medium: #FFFF00 (Yellow)
- Error/Critical: #FF0000 (Red)
- Info: #00FFFF (Cyan)
- Neutral: #808080 (Gray)

**Neon Cyberpunk Theme (matching dashboard):**

- Background: #0a0e27
- Primary: #00ffff (Cyan)
- Secondary: #ff00ff (Magenta)
- Accent: #00ff00 (Green)
- Text: #ffffff (White)

---

## Export Formats

**For Report:**

- PNG (300 DPI for print)
- SVG (for scalable diagrams)
- PDF (for complex diagrams)

**Dimensions:**

- Full-width figures: 1200px wide
- Half-width figures: 600px wide
- Maintain 16:9 or 4:3 aspect ratio

# IPS Alert Log Issue - Root Cause & Solution

## Problem
Dashboard không hiển thị alerts vì IPS không nhận traffic để inspect.

## Root Cause
Docker bridge mặc định forward traffic giữa containers ở layer 2, **không đi qua FORWARD chain** của IPS container nơi NFQUEUE rule đang đợi.

Evidence:
- `iptables -L FORWARD -n -v` trong IPS: counter = 11 packets (không tăng khi ping)
- `/var/log/minisnort/alert.log`: 0 bytes
- Dashboard API `/api/alerts/live`: `{"lines": [], "size": 0}`

## Solution Required
Lab này cần **true routing mode**, không phải bridge mode. Traffic phải đi qua netfilter FORWARD chain của IPS.

## Recommended Fix
Sử dụng **iptables BROUTING** hoặc **ebtables** ở host level để force traffic vào FORWARD chain, HOẶC chuyển sang **macvlan network driver**.

## Current Status
- ✅ IPS startup script fixed (NFQUEUE rule setup correctly)
- ✅ Dashboard UI/API working correctly
- ❌ Network topology không force traffic qua IPS netfilter
- ❌ Cần thay đổi docker-compose network config hoặc thêm host-level routing

## Next Steps
1. Thêm ebtables rules ở host để redirect traffic vào FORWARD chain
2. HOẶC: Chuyển sang macvlan driver với explicit gateway routing
3. Test lại với ping và verify alert.log có nội dung
4. Verify dashboard hiển thị alerts real-time

#!/usr/bin/env bash
# Fix script to enable IPS packet inspection via host-level iptables

set -euo pipefail

echo "[fix] Enabling IPS packet inspection via host iptables..."

# Get bridge interface names
BRIDGE_ATTACK=$(docker network inspect lab_ips_sec_net_attack -f '{{.Id}}' | cut -c1-12)
BRIDGE_VICTIM=$(docker network inspect lab_ips_sec_net_victim -f '{{.Id}}' | cut -c1-12)

echo "[fix] Attack bridge: br-${BRIDGE_ATTACK}"
echo "[fix] Victim bridge: br-${BRIDGE_VICTIM}"

# Enable bridge-nf-call-iptables to force bridge traffic through iptables
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1

echo "[fix] Bridge netfilter enabled"
echo "[fix] Now traffic between Docker networks will go through iptables FORWARD chain"
echo ""
echo "Test with: docker exec ms_attacker ping -c 3 10.201.0.20"
echo "Check alerts: docker exec ms_ips tail /var/log/minisnort/alert.log"
echo "Dashboard: http://127.0.0.1:8080"

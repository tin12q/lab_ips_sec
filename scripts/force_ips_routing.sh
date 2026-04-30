#!/usr/bin/env bash
# Force traffic between Docker networks to route through IPS container netfilter
set -euo pipefail

echo "[force_routing] Configuring cross-network routing through IPS..."

# Get bridge interface names
BRIDGE_ATTACK=$(docker network inspect lab_ips_sec_net_attack -f '{{.Id}}' | cut -c1-12)
BRIDGE_VICTIM=$(docker network inspect lab_ips_sec_net_victim -f '{{.Id}}' | cut -c1-12)

echo "[force_routing] Attack bridge: br-${BRIDGE_ATTACK}"
echo "[force_routing] Victim bridge: br-${BRIDGE_VICTIM}"

# Enable bridge netfilter to force bridge traffic through iptables
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1

# Add ebtables rules to force traffic into FORWARD chain
sudo ebtables -t broute -F
sudo ebtables -t broute -A BROUTING -p ipv4 --ip-dst 10.201.0.0/24 -i br-${BRIDGE_ATTACK} -j DROP
sudo ebtables -t broute -A BROUTING -p ipv4 --ip-dst 10.200.0.0/24 -i br-${BRIDGE_VICTIM} -j DROP

echo "[force_routing] Bridge routing configured"
echo "[force_routing] Traffic will now traverse IPS container's FORWARD chain"

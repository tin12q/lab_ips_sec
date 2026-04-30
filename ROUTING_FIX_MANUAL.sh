#!/usr/bin/env bash
# Manual steps to enable IPS packet inspection
# Run these commands on the host with sudo

set -euo pipefail

echo "=== IPS Routing Fix ==="
echo ""
echo "The IPS container is running but traffic between Docker networks"
echo "bypasses its netfilter FORWARD chain. To fix this, run these commands"
echo "on the HOST (not in containers):"
echo ""
echo "# Enable bridge netfilter"
echo "sudo sysctl -w net.bridge.bridge-nf-call-iptables=1"
echo ""
echo "# Get bridge IDs"
echo "BRIDGE_ATTACK=\$(docker network inspect lab_ips_sec_net_attack -f '{{.Id}}' | cut -c1-12)"
echo "BRIDGE_VICTIM=\$(docker network inspect lab_ips_sec_net_victim -f '{{.Id}}' | cut -c1-12)"
echo ""
echo "# Force cross-network traffic into iptables FORWARD chain"
echo "sudo iptables -I FORWARD -i br-\${BRIDGE_ATTACK} -o br-\${BRIDGE_VICTIM} -j ACCEPT"
echo "sudo iptables -I FORWARD -i br-\${BRIDGE_VICTIM} -o br-\${BRIDGE_ATTACK} -j ACCEPT"
echo ""
echo "After running these commands, test with:"
echo "  docker exec ms_attacker ping -c 3 10.201.0.20"
echo "  docker exec ms_ips tail /var/log/minisnort/alert.log"
echo "  curl http://127.0.0.1:8080/api/alerts/live"

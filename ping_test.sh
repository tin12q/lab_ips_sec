#!/bin/bash
# Simple continuous ping script to generate ICMP alerts

VICTIM_IP=$(docker exec ms_victim hostname -i | awk '{print $1}')

echo "=== Continuous Ping Test ==="
echo "Target: $VICTIM_IP"
echo "Press Ctrl+C to stop"
echo ""

docker exec -it ms_attacker ping $VICTIM_IP

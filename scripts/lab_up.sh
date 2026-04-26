#!/usr/bin/env bash
set -euo pipefail

modprobe nfnetlink_queue || true
docker compose build
docker compose up -d
echo "Wait 5s for services..."
sleep 5
docker compose ps

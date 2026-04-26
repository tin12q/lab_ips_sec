#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/tail_evidence.sh sprint0

SPRINT="${1:-sprint0}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT_DIR/logs/evidence/$SPRINT"

if [[ ! -d "$DIR" ]]; then
  echo "Missing evidence directory: $DIR"
  exit 1
fi

touch \
  "$DIR/build.txt" \
  "$DIR/test.txt" \
  "$DIR/runtime.txt" \
  "$DIR/attacks.txt" \
  "$DIR/alerts.txt"

echo "Tailing evidence files in: $DIR"
exec tail -n 50 -f \
  "$DIR/build.txt" \
  "$DIR/test.txt" \
  "$DIR/runtime.txt" \
  "$DIR/attacks.txt" \
  "$DIR/alerts.txt"

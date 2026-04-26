#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/verify_capture.sh sprint0 \
#     "<build_cmd>" "<test_cmd>" "<runtime_cmd>" "<attacks_cmd>" "<alerts_cmd>"
#
# Any command can be omitted by passing an empty string "".

SPRINT="${1:-sprint0}"
BUILD_CMD="${2:-}"
TEST_CMD="${3:-}"
RUNTIME_CMD="${4:-}"
ATTACKS_CMD="${5:-}"
ALERTS_CMD="${6:-}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/logs/evidence/$SPRINT"

mkdir -p "$OUT_DIR"

run_and_capture() {
  local label="$1"
  local cmd="$2"
  local outfile="$OUT_DIR/${label}.txt"

  {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${label} capture start"
    if [[ -n "$cmd" ]]; then
      echo "$ $cmd"
      bash -lc "$cmd"
      status=$?
      echo "exit_code=$status"
    else
      echo "No command provided for ${label}."
      echo "Set it as argument when calling verify_capture.sh."
    fi
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ${label} capture end"
  } >"$outfile" 2>&1

  echo "Wrote: $outfile"
}

run_and_capture "build" "$BUILD_CMD"
run_and_capture "test" "$TEST_CMD"
run_and_capture "runtime" "$RUNTIME_CMD"
run_and_capture "attacks" "$ATTACKS_CMD"
run_and_capture "alerts" "$ALERTS_CMD"

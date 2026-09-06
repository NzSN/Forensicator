#!/usr/bin/env bash
# Bounded gates for the active timeline, execution-point and proxy contracts.
set -euo pipefail

timeline_repo="$(cd "$(dirname "$0")/.." && pwd)"
timeline_logs="${FORENSICATOR_TLA_LOG_DIR:-$timeline_repo/tmp/timeline-specs}"
mkdir -p "$timeline_logs"
cd "$timeline_repo"
command -v apalache-mc >/dev/null

check_model() {
  local model="$1" length="$2"
  local log="$timeline_logs/$model.log"
  printf 'Checking %s through %s transitions\n' "$model" "$length"
  if ! apalache-mc check --features=no-rows --length="$length" \
      --config="specs/$model.cfg" "specs/$model.tla" >"$log" 2>&1; then
    tail -40 "$log"
    return 1
  fi
  printf 'PASS %s (log: %s)\n' "$model" "$log"
}

check_model Timeline 10
check_model ExecutionState 10
check_model Snapshot 6
check_model SnapshotRegression 8
# The full proxy state machine includes watchpoint/cursor setup. Its direct
# loaded-trace regression reaches both fallback branches without setup steps.
check_model JigSawSpawner 6
check_model JigSawSpawnerRegression 4
check_model ObservationScopes 6
check_model StackRecovery 8

apalache-mc typecheck --features=no-rows specs/SnapshotMBT.tla \
  >"$timeline_logs/SnapshotMBT-typecheck.log" 2>&1
printf 'PASS SnapshotMBT compatibility entry typecheck\n'

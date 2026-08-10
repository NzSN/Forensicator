#!/bin/bash
# Conformance gate: Rust forensicator (golden oracle) vs Lean forensicator.
# Both must produce identical JSON (normalized with jq -S) and zero anomalies.
#
# Env: PATH must include elan shims: export PATH="$HOME/.elan/bin:$PATH"
#   FORENSICATOR_RUST   — Rust repo (default $HOME/Repos/Forensicator)
#   FORENSICATOR_CASE_DIR — fixtures (default $FORENSICATOR_RUST/Case)
set -u
export PATH="$HOME/.elan/bin:$PATH"
LEAN_REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUST="${FORENSICATOR_RUST:-$HOME/Repos/Forensicator}"
CASES="${FORENSICATOR_CASE_DIR:-$RUST/Case}"
RUST_BIN="$RUST/target/debug/forensicator-cli"
LEAN_BIN="$LEAN_REPO/.lake/build/bin/forensicator"

fail=0

if [ ! -x "$RUST_BIN" ]; then
  echo "== building Rust oracle =="
  cargo build --manifest-path "$RUST/Cargo.toml" -p forensicator-cli || exit 1
fi
if [ ! -x "$LEAN_BIN" ]; then
  echo "== building lean =="
  (cd "$LEAN_REPO" && lake build) || exit 1
fi

check() { # name, args...
  local name="$1"; shift
  local r_out l_out
  r_out="$("$RUST_BIN" "$@" 2>&1)"; local r_code=$?
  l_out="$("$LEAN_BIN" "$@" 2>&1)"; local l_code=$?
  if [ "$r_code" -ne "$l_code" ]; then
    echo "FAIL $name: exit codes rust=$r_code lean=$l_code"; fail=1; return
  fi
  if [ "$r_out" = "$l_out" ]; then
    echo "ok   $name"
    return
  fi
  # JSON mode: normalize (sorted keys) before diffing
  local rj lj
  rj="$(printf '%s' "$r_out" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))' 2>/dev/null)"
  lj="$(printf '%s' "$l_out" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))' 2>/dev/null)"
  if [ -n "$rj" ] && [ "$rj" = "$lj" ]; then
    echo "ok   $name (json-normalized)"
  else
    echo "FAIL $name"
    diff <(printf '%s\n' "$r_out") <(printf '%s\n' "$l_out") | head -10
    fail=1
  fi
}

T="$CASES/ttfx/minimal.ttfx"
check "trace minimal" trace "$T"
check "trace minimal json" trace "$T" --json
check "trace minimal --pos 1" trace "$T" --pos 1
check "trace minimal --pos 1 json" trace "$T" --pos 1 --json
check "trace minimal --writes" trace "$T" --writes 0x1004 2
check "trace minimal --writes json" trace "$T" --writes 0x1004 2 --json

# anomaly-free requirement
ANOM="$("$LEAN_BIN" trace "$T" --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["anomalies"]))')"
if [ "$ANOM" != "0" ]; then echo "FAIL: lean reported $ANOM anomalies on minimal.ttfx"; fail=1; fi

# encoder cross-check: Lean-encoded fixture must decode cleanly under the Rust oracle
EMIT="$(mktemp -d)/lean-minimal.ttfx"
"$LEAN_REPO/.lake/build/bin/forensicator-test" --emit "$EMIT" || { echo "FAIL: emit"; exit 1; }
r_orig="$("$RUST_BIN" trace "$T" --json)"
r_emit="$("$RUST_BIN" trace "$EMIT" --json)"
nj() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'; }
if [ "$(printf '%s' "$r_orig" | nj)" = "$(printf '%s' "$r_emit" | nj)" ]; then
  echo "ok   encoder cross-check (rust decodes lean-encoded bytes identically)"
else
  echo "FAIL: rust decode of lean-encoded fixture differs"; fail=1
fi

if [ "$fail" -ne 0 ]; then echo "== CONFORMANCE FAILED =="; exit 1; fi
echo "== CONFORMANCE PASS =="

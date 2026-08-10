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

# minidump fixtures (Task 5): --quiet is byte-exact; --json compares with the
# diagnosis key stripped until the cause analyzer lands (Task 8)
njstrip() { python3 -c 'import json,sys; d=json.load(sys.stdin); d.pop("diagnosis", None); print(json.dumps(d, sort_keys=True))'; }
for d in "$CASES"/minidump "$CASES"/minidump_v2 "$CASES"/fulldump; do
  f=$(ls "$d"/*.dmp)
  check "inspect quiet $(basename $d)" inspect "$f" --quiet
  r_json="$("$RUST_BIN" inspect "$f" --json | njstrip)"
  l_json="$("$LEAN_BIN" inspect "$f" --json | njstrip)"
  if [ "$r_json" = "$l_json" ]; then
    echo "ok   inspect json $(basename $d) (sans diagnosis)"
  else
    echo "FAIL inspect json $(basename $d)"; fail=1
  fi
done

if [ "$fail" -ne 0 ]; then echo "== CONFORMANCE FAILED =="; exit 1; fi

# analyzers (Task 7): per-plugin JSON parity. shapes compares the member-count
# multiset (Rust assigns group ids in HashMap order — nondeterministic on ties).
# arrays on fulldump is excluded: quadratic in BOTH implementations (>30 min).
njfull() { python3 -c '
import json, sys
d = json.load(sys.stdin)
for o in d.get("plugins", []):
    if isinstance(o.get("shape_clusters"), list):
        o["shape_clusters"] = sorted(g["member_count"] for g in o["shape_clusters"])
print(json.dumps(d, sort_keys=True))'; }

analyze_check() { # name, dump, plugin
  local name="$1" f="$2" plug="$3"
  local rj lj
  rj="$("$RUST_BIN" analyze "$f" --plugin "$plug" --json | njfull)"
  lj="$("$LEAN_BIN" analyze "$f" --plugin "$plug" --json | njfull)"
  if [ "$rj" = "$lj" ]; then echo "ok   analyze $name $plug"
  else echo "FAIL analyze $name $plug"; fail=1; fi
}

for d in minidump minidump_v2; do
  f=$(ls "$CASES/$d"/*.dmp)
  for plug in strings vtables lists arrays chunks shapes; do
    analyze_check "$(basename $d)" "$f" "$plug"
  done
done
f=$(ls "$CASES"/fulldump/*.dmp)
for plug in strings vtables lists chunks shapes; do
  analyze_check "fulldump" "$f" "$plug"
done
check "list-plugins" list-plugins

if [ "$fail" -ne 0 ]; then echo "== CONFORMANCE FAILED =="; exit 1; fi
echo "== CONFORMANCE PASS =="

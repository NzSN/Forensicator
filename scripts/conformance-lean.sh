#!/bin/bash
# Conformance gate: Lean-only golden regression (post-pivot 2026-08-13).
# The Rust oracle and the eager .ttfx v1 path are gone; the gate compares
# the Lean binary against captured goldens in Case/golden/ (untracked, like
# the fixtures; regenerate with scripts/capture-goldens.sh from a
# known-good build).
#
# Checks:
#   - inspect/analyze/match/list-plugins/shell vs goldens (byte-exact text,
#     key-sorted JSON, njfull for analyze)
#   - forensicator-test guard suite + FORENSICATOR_CASE_DIR minidump fuzz
#   - negative guard: the binary must NOT accept .ttfx input (trace
#     subcommand gone; shell/load rejects the .ttfx magic with an explicit
#     "ttfx removed" error)
#
# Env: PATH must include elan shims: export PATH="$HOME/.elan/bin:$PATH"
#   FORENSICATOR_CASE_DIR — fixtures (default $LEAN_REPO/Case)
set -u
export PATH="$HOME/.elan/bin:$PATH"
LEAN_REPO="$(cd "$(dirname "$0")/.." && pwd)"
CASES="${FORENSICATOR_CASE_DIR:-$LEAN_REPO/Case}"
GOLDEN="$CASES/golden"
LEAN_BIN="$LEAN_REPO/.lake/build/bin/forensicator"

fail=0

if [ ! -x "$LEAN_BIN" ]; then
  echo "== building lean =="
  (cd "$LEAN_REPO" && lake build) || exit 1
fi

nj() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'; }
njfull() { python3 -c '
import json, sys
d = json.load(sys.stdin)
for o in d.get("plugins", []):
    if isinstance(o.get("shape_clusters"), list):
        o["shape_clusters"] = sorted(g["member_count"] for g in o["shape_clusters"])
print(json.dumps(d, sort_keys=True))'; }

golden() { # name, normalizer, args...
  local name="$1" norm="$2"; shift 2
  local out rc
  if [ -n "${CHECK_STDIN:-}" ]; then
    out="$(printf '%s' "$CHECK_STDIN" | "$LEAN_BIN" "$@" 2>&1)"; rc=$?
  else
    out="$("$LEAN_BIN" "$@" 2>&1)"; rc=$?
  fi
  if [ "$rc" -ne 0 ]; then echo "FAIL $name: exit code $rc"; fail=1; return; fi
  if [ "$norm" != "text" ]; then out="$(printf '%s' "$out" | $norm 2>/dev/null)"; fi
  local want="$(cat "$GOLDEN/$name")"
  if [ "$out" = "$want" ]; then echo "ok   golden $name"
  else echo "FAIL golden $name"; diff <(printf '%s\n' "$want") <(printf '%s\n' "$out") | head -10; fail=1; fi
}

if [ ! -d "$GOLDEN" ]; then
  echo "FAIL: no goldens at $GOLDEN — run scripts/capture-goldens.sh first"; exit 1
fi

# inspect: byte-exact --quiet, key-sorted --json
for d in minidump minidump_v2 fulldump; do
  f=$(ls "$CASES/$d"/*.dmp)
  golden "inspect-quiet-$d.txt" text inspect "$f" --quiet
  golden "inspect-json-$d.json" nj inspect "$f" --json
done

# analyze: per-plugin + full-pipeline, njfull
for d in minidump minidump_v2; do
  f=$(ls "$CASES/$d"/*.dmp)
  for plug in cause strings vtables lists arrays chunks shapes v8; do
    golden "analyze-$d-$plug.json" njfull analyze "$f" --plugin "$plug" --json
  done
  golden "analyze-$d-FULL.json" njfull analyze "$f" --json
done
f=$(ls "$CASES"/fulldump/*.dmp)
for plug in cause strings vtables lists chunks shapes v8; do
  golden "analyze-fulldump-$plug.json" njfull analyze "$f" --plugin "$plug" --json
done

golden "list-plugins.txt" text list-plugins

# match: dump ↔ exe/PDB identity (text, json, exit code)
MF=$(ls "$CASES"/minidump/*.dmp)
ME="$CASES/minidump/electron.exe"
MP="$CASES/minidump/electron.exe.pdb"
golden "match-text.txt" text match "$MF" --exe "$ME" --pdb "$MP"
golden "match-json.json" nj match "$MF" --exe "$ME" --pdb "$MP" --json
"$LEAN_BIN" match "$MF" --exe "$ME" --pdb "$MP" >/dev/null 2>&1
if [ "$?" = "$(cat "$GOLDEN/match-exit-code.txt")" ]; then
  echo "ok   golden match-exit-code"
else
  echo "FAIL golden match-exit-code"; fail=1
fi

# shell: scripted REPL parity against the dump fixture
printf 'inspect --quiet\nmatch\nquit\n' > /tmp/shellscript_dump.txt
CHECK_STDIN="$(cat /tmp/shellscript_dump.txt)" golden "shell-dump-script.txt" text shell "$(ls "$CASES"/minidump_v2/*.dmp)"

# in-process guard suite + FORENSICATOR_CASE_DIR minidump prefix/mutation fuzz
echo "== forensicator-test guard suite =="
FORENSICATOR_CASE_DIR="$CASES" "$LEAN_REPO/.lake/build/bin/forensicator-test" || { echo "FAIL: guard suite"; fail=1; }

# negative guard: .ttfx must be rejected everywhere (pins the excision)
TTFX_FIX="$(mktemp -d)/reject.ttfx"
printf '\x54\x54\x46\x58\x01\x00\x00\x00' > "$TTFX_FIX"
out="$("$LEAN_BIN" trace "$TTFX_FIX" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then echo "FAIL: 'trace' still accepts .ttfx"; fail=1; else echo "ok   negative: trace rejects .ttfx (rc=$rc)"; fi
out="$("$LEAN_BIN" shell "$TTFX_FIX" </dev/null 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -q "ttfx removed"; then
  echo "FAIL: shell/load accepts .ttfx (rc=$rc): $out"; fail=1
else
  echo "ok   negative: shell rejects .ttfx with 'ttfx removed'"
fi

if [ "$fail" -ne 0 ]; then echo "== CONFORMANCE FAILED =="; exit 1; fi
echo "== CONFORMANCE PASS =="

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

# opt-in live proxy gate (plan C6; OFF by default): scripted lazy session
# against the fixture trace, spot-comparing banner/writes/payloads against
# the known fixture values recorded in the design's Implementation notes.
# Requires: FORENSICATOR_PROXY_RUN=<trace path> (e.g.
# D:/Codebase/TTFX/traces/hostname01.run) plus a transport —
# FORENSICATOR_PROXY_SSH=windows-dev (rides ssh stdio) or a local
# FORENSICATOR_PROXY_EXE interop path.
if [ -z "${FORENSICATOR_PROXY_RUN:-}" ]; then
  echo "skip proxy live gate (FORENSICATOR_PROXY_RUN unset)"
else
  echo "== proxy live gate ($FORENSICATOR_PROXY_RUN) =="
  session="$(printf '%s\n' \
      'seek 0x1A60AD500000003' \
      'writes 0x9F4C2BF388 8' \
      'seek 0x1A613E1000016C2' \
      'writes 0x9F4C2BF3B0 8' \
      'writes 0x9F4C2BDB60 8' \
      'quit' | timeout 900 "$LEAN_BIN" shell --proxy "$FORENSICATOR_PROXY_RUN" 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL proxy gate: session rc=$rc"; fail=1
  else
    if printf '%s' "$session" | grep -qF \
        "loaded $(basename "$FORENSICATOR_PROXY_RUN"): trace (lazy via proxy), frontier 0x1A613E1000016C2, 3 threads, 20 events"; then
      echo "ok   proxy gate: handshake banner"
    else echo "FAIL proxy gate: banner"; printf '%s\n' "$session" | head -3; fail=1; fi
    # eager-.ttfx payload for write (0x1A60AD500000003, 0x9F4C2BF388)
    if printf '%s' "$session" | grep -qF \
        "@0x1A60AD500000003  [0x9F4C2BF388, 0x9F4C2BF390)  [1E, 5C, 16, BA, F8, 7F, 00, 00]  <-- last writer"; then
      echo "ok   proxy gate: write payload == eager .ttfx"
    else echo "FAIL proxy gate: payload"; fail=1; fi
    # fixture write-count spot checks (overlapping-record counts pinned by
    # the eager WRITES section; occurrence-grep, the prompt has no newline)
    n="$(printf '%s\n' "$session" | grep -oE '@0x[0-9A-F]+  \[0x9F4C2BF3B[04],' | wc -l)"
    if [ "$n" = "39" ]; then echo "ok   proxy gate: hot-VA write count (39)"
    else echo "FAIL proxy gate: write count $n ≠ 39"; fail=1; fi
    n="$(printf '%s\n' "$session" | grep -oE '@0x[0-9A-F]+  \[0x9F4C2BDB6[02468],' | wc -l)"
    if [ "$n" = "1287" ]; then echo "ok   proxy gate: P3-page write count (1287)"
    else echo "FAIL proxy gate: P3 write count $n ≠ 1287"; fail=1; fi
    # P3 documented limitation: the probe-verified never-readable record's
    # payload exists only in the eager .ttfx (probe_page.py, design notes)
    if printf '%s' "$session" | grep -qF \
        "@0x1A60DBE00002057  [0x9F4C2BDB60, 0x9F4C2BDB68)  <uncommitted>"; then
      echo "ok   proxy gate: P3 record fails closed"
    else echo "FAIL proxy gate: P3 record"; fail=1; fi
  fi
fi

if [ "$fail" -ne 0 ]; then echo "== CONFORMANCE FAILED =="; exit 1; fi
echo "== CONFORMANCE PASS =="

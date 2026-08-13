#!/bin/bash
# Capture Lean-only golden outputs into Case/golden/ (untracked, like the
# fixtures). One-off migration tool: captures the last gate-verified state
# (commit 3163121, 44-check PASS) before the eager .ttfx path is excised.
# Normalizers mirror conformance-lean.sh exactly: byte-exact for --quiet /
# text output, key-sorted (sort_keys=True) for --json, njfull additionally
# sorts shape_clusters to the member-count multiset (Rust group-id order was
# nondeterministic on ties).
#
# Env: PATH must include elan shims: export PATH="$HOME/.elan/bin:$PATH"
#   FORENSICATOR_CASE_DIR — fixtures (default $LEAN_REPO/Case)
set -u
export PATH="$HOME/.elan/bin:$PATH"
LEAN_REPO="$(cd "$(dirname "$0")/.." && pwd)"
CASES="${FORENSICATOR_CASE_DIR:-$LEAN_REPO/Case}"
OUT="${GOLDEN_DIR:-$CASES/golden}"
LEAN_BIN="$LEAN_REPO/.lake/build/bin/forensicator"

nj() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'; }
njfull() { python3 -c '
import json, sys
d = json.load(sys.stdin)
for o in d.get("plugins", []):
    if isinstance(o.get("shape_clusters"), list):
        o["shape_clusters"] = sorted(g["member_count"] for g in o["shape_clusters"])
print(json.dumps(d, sort_keys=True))'; }

capture() { # name, file
  local name="$1" f="$2"
  mkdir -p "$OUT"
  printf '%s' "$f" > "$OUT/$name"
  echo "golden $name"
}

if [ ! -x "$LEAN_BIN" ]; then
  echo "== building lean =="
  (cd "$LEAN_REPO" && lake build) || exit 1
fi

for d in minidump minidump_v2 fulldump; do
  f=$(ls "$CASES/$d"/*.dmp)
  name=$(basename "$d")
  capture "inspect-quiet-$name.txt" "$("$LEAN_BIN" inspect "$f" --quiet 2>&1)"
  capture "inspect-json-$name.json" "$("$LEAN_BIN" inspect "$f" --json 2>&1 | nj)"
done

for d in minidump minidump_v2; do
  f=$(ls "$CASES/$d"/*.dmp)
  for plug in cause strings vtables lists arrays chunks shapes v8; do
    capture "analyze-$(basename $d)-$plug.json" "$("$LEAN_BIN" analyze "$f" --plugin "$plug" --json 2>&1 | njfull)"
  done
  capture "analyze-$(basename $d)-FULL.json" "$("$LEAN_BIN" analyze "$f" --json 2>&1 | njfull)"
done
f=$(ls "$CASES"/fulldump/*.dmp)
for plug in cause strings vtables lists chunks shapes v8; do
  capture "analyze-fulldump-$plug.json" "$("$LEAN_BIN" analyze "$f" --plugin "$plug" --json 2>&1 | njfull)"
done

capture "list-plugins.txt" "$("$LEAN_BIN" list-plugins 2>&1)"

MF=$(ls "$CASES"/minidump/*.dmp)
ME="$CASES/minidump/electron.exe"
MP="$CASES/minidump/electron.exe.pdb"
capture "match-text.txt" "$("$LEAN_BIN" match "$MF" --exe "$ME" --pdb "$MP" 2>&1)"
capture "match-json.json" "$("$LEAN_BIN" match "$MF" --exe "$ME" --pdb "$MP" --json 2>&1 | nj)"
"$LEAN_BIN" match "$MF" --exe "$ME" --pdb "$MP" >/dev/null 2>&1
capture "match-exit-code.txt" "$?"

printf 'inspect --quiet\nmatch\nquit\n' > /tmp/shellscript_dump.txt
capture "shell-dump-script.txt" "$(cat /tmp/shellscript_dump.txt | "$LEAN_BIN" shell "$(ls "$CASES"/minidump_v2/*.dmp)" 2>&1)"

echo "== goldens captured: $(ls "$OUT" | wc -l) files in $OUT =="

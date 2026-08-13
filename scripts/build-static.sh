#!/usr/bin/env bash
# Build a fully static forensicator binary (no dynamic libc/glibc deps).
# Output: .lake/build/bin/forensicator-static
set -euo pipefail

export PATH="$HOME/.elan/bin:$PATH"

lake build forensicator

LEAN_PREFIX="$(lean --print-prefix)"
CLANG="$LEAN_PREFIX/bin/clang"
GLIBC_DIR="$LEAN_PREFIX/lib/glibc"
RSP=".lake/build/bin/forensicator.rsp"
TMP_RSP="$(mktemp)"
trap 'rm -f "$TMP_RSP"' EXIT

# Lake links against shared glibc by default. Rewrite the rsp so everything
# links static: drop the --sysroot (which hides the system static libc.a), the
# glibc search dir and the dynamic-loader / libc flag block, then pin the final
# -lLake/-lgmp/... group back under -Bstatic. The rsp is one arg per line, so
# flag/value pairs are handled with a small state machine.
awk -v sysroot="$LEAN_PREFIX" -v glibc="$GLIBC_DIR" '
  BEGIN { skip = 0; holdL = 0 }
  /^"--sysroot"$/ { skip = 1; next }
  skip { skip = 0; next }
  /^"-L"$/ { holdL = 1; print; next }
  holdL { holdL = 0; if ($0 ~ glibc) next; print; next }
  /^"-Wl,-Bdynamic"$/ { print "\"-Wl,-Bstatic\""; next }
  /^"-(lc|lc_nonshared|l:ld.so|lpthread_nonshared|lpthread|ldl|lrt|lm|pthread)"$/ { next }
  /^"-Wl,--as-needed"$/ || /^"-Wl,--no-as-needed"$/ { next }
  { print }
' "$RSP" > "$TMP_RSP"

"$CLANG" -o .lake/build/bin/forensicator-static @"$TMP_RSP" -static

echo "built .lake/build/bin/forensicator-static"
file .lake/build/bin/forensicator-static | sed 's/.*: //'

# CLI: One-shot Subcommands and Interactive Shell

Code: `Main.lean` (argument parsing + one-shot subcommands),
`Forensicator/Session.lean` (the REPL).

## One-shot subcommands

```
forensicator inspect <dump.dmp>           # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # analyzer pipeline (--plugin a,b --json --symbols <pdb_dir>)
forensicator match <dump.dmp>             # dump ↔ build artifacts (--exe, --pdb, --json; exit 2 on mismatch)
forensicator list-plugins                 # registered analyzers
forensicator shell <dump.dmp>             # interactive session (--symbols <pdb_dir>)
forensicator shell --proxy <trace.run>    # lazy TTD trace session via ttfx-proxy (see below)
```

Trace note (2026-08-13): the `trace <trace.ttfx>` subcommand and `.ttfx`
session loading are removed with the eager path; `shell`/`load` reject the
TTFX magic with an explicit "ttfx removed" error. Trace sessions attach
through the lazy proxy: `shell --proxy <trace.run>` (or `load --proxy` from
an existing session) spawns `ttfx-proxy.exe` (protocol v1,
`Forensicator/Trace/`), performs the HELLO handshake, and serves the eager
skeleton + lazy memory (design:
`docs/trace/2026-08-12-lazy-trace-proxy-design.md`). Transport:
`FORENSICATOR_PROXY_EXE` (local interop path) or
`FORENSICATOR_PROXY_SSH=<host>` (the binary stdio protocol rides the ssh
pipes; `FORENSICATOR_PROXY_EXE` then names the *remote* exe). v1 is blocking
with no read timeout — a hung proxy hangs the session (Ctrl-C is the
remedy).

`analyze` supplements stack-only dumps with on-disk module bytes discovered
next to the dump (`Util/Image.lean`), then runs the pipeline. `--symbols`
swaps in a symbolizing pipeline whose `v8` analyzer resolves native frames via
PDBs (accepted only on RSDS GUID+age match — `Util/Pdb.lean`).

## Interactive shell (`Session.lean`)

Hand-rolled REPL over `IO` — no line-editing dependencies (the package is
dependency-free). Lines are tokenized and dispatched by a simple matcher;
parity boundary: clap's `help`/error text from the Rust era is not
reproduced (a simpler usage error is printed), and `error: …` wording is
intentionally ungated.

### Design: one code path, two modes

Handlers are split into *load* vs *execute* (the same `inspect`/`analyze`/
`match` logic backs both the one-shot subcommands and the session against its
loaded state). There is no behavioral fork between modes.

### Session state

```lean
inductive Target where
  | dump (s1 : Dump × AddressSpace × DumpKind) (images : Nat)
  | trace (t : Trace) (cursor : Position)

structure Session where
  path : String
  target : Target
  symbols : Option String      -- PDB dir; 'symbols <dir>' / 'symbols off'
  proxy : Option Trace.ProxySession := none   -- live lazy proxy, if attached
```

`load` (and initial open) sniffs the first 4 bytes: TTFX magic → explicit
"ttfx removed" error (the eager trace path is gone); otherwise minidump
session (`Session.open`). `load --proxy <trace.run>` instead attaches a
trace session (`Session.openProxy`): spawn + handshake builds the
`Target.trace` skeleton (threads/events/frontier), and memory/index facts
fill lazily through the proxy (two-phase commands). A session-fatal proxy
error (framing violation, ERROR frame, EOF) poisons the session — commands
report it and never fudge (fail closed, plan C4). In a dump session the
cursor commands error with "not a trace session (…)".

### Command surface

| Group | Commands |
|---|---|
| Analysis | `inspect [--json --quiet]`, `analyze [--plugin --json]`, `match --exe/--pdb`, `list-plugins` |
| Session | `load [--proxy] <path>`, `symbols [dir|off]`, `quit` (Ctrl-D also exits) |
| Trace cursor | `seek <pos>`, `t+`/`forward`, `t-`/`back`, `position`, `writes <va> <len>`, `intervals` |

Positions accept decimal or `0x` hex. Cursor movement enforces CursorBounded:
seeking past the frontier is an error, not a clamp. The prompt reflects
session state (`forensicator[file.dmp]>`, `forensicator[trace.run @ pos/frontier]>`).

On a lazy trace session the cursor commands are two-phase (plan C1):
`writes` fetches the write-index window for the range (then resolves
payloads through the jigsaw cache, `<uncommitted>` when the page is not
readable — a fact, not an error); `inspect`/`analyze`/`match` at the cursor
run the D4 two-phase snapshot (full index once → closure pages ∪ probed
pages → batch fetch at the cursor → pure materialization).

The cursor commands map 1:1 to `Timeline.tla` actions (`Seek`, `Advance`,
`Retreat`) and to WinDbg idioms (`!tt`, `t+`/`t-`,
`dx TTD.Memory(va, va+len, "w")`).

## Adding a session command

1. Add a dispatch arm in `Main.lean`'s session dispatcher (aliases are
   alternate patterns, e.g. `"t+" :: _ | "forward" :: _`).
2. Use the session's current snapshot for analysis commands or the
   `Target.trace` cursor for cursor commands (the latter errors cleanly in
   dump sessions). For analysis commands use `Session.currentIO` — it runs
   the two-phase snapshot on lazy trace sessions.

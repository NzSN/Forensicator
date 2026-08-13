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
```

Trace note (2026-08-13): the `trace <trace.ttfx>` subcommand and `.ttfx`
session loading are removed with the eager path; `shell`/`load` reject the
TTFX magic with an explicit "ttfx removed" error. Trace sessions return when
the Lean proxy client lands (design:
`docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md`).

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
```

`load` (and initial open) sniffs the first 4 bytes: TTFX magic → explicit
"ttfx removed" error (the eager trace path is gone); otherwise minidump
session (`Session.open`). Snapshot commands operate on the loaded dump.
`Target.trace` stays in the type — trace cursor commands
(`seek`/`t+`/`t-`/`position`/`writes`/`intervals`) remain in the dispatcher
but no loader can construct a trace session until the Lean proxy client
lands; in a dump session they error with "not a trace session (…)".

### Command surface

| Group | Commands |
|---|---|
| Analysis | `inspect [--json --quiet]`, `analyze [--plugin --json]`, `match --exe/--pdb`, `list-plugins` |
| Session | `load <path>`, `symbols [dir|off]`, `quit` (Ctrl-D also exits) |
| Trace cursor (pending the Lean client) | `seek <pos>`, `t+`/`forward`, `t-`/`back`, `position`, `writes <va> <len>`, `intervals` |

Positions accept decimal or `0x` hex. Cursor movement enforces CursorBounded:
seeking past the frontier is an error, not a clamp. The prompt reflects
session state (`forensicator[file.dmp]>`).

The cursor commands map 1:1 to `Timeline.tla` actions (`Seek`, `Advance`,
`Retreat`) and to WinDbg idioms (`!tt`, `t+`/`t-`,
`dx TTD.Memory(va, va+len, "w")`).

## Adding a session command

1. Add a dispatch arm in `Main.lean`'s session dispatcher (aliases are
   alternate patterns, e.g. `"t+" :: _ | "forward" :: _`).
2. Use the session's current snapshot for analysis commands or the
   `Target.trace` cursor for cursor commands (the latter errors cleanly in
   dump sessions).

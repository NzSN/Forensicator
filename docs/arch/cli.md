# CLI: One-shot Subcommands and Interactive Shell

Code: `forensicator-cli/src/main.rs`, `forensicator-cli/src/session.rs`.

## One-shot subcommands

```
forensicator inspect <dump.dmp>           # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # analyzer pipeline (--plugin a,b --json --symbols <pdb_dir>)
forensicator match <dump.dmp>             # dump ↔ build artifacts (--exe, --pdb, --json; exit 2 on mismatch)
forensicator list-plugins                 # registered analyzers
forensicator trace <trace.ttfx>           # trace summary (--pos <p>, --writes <va> <len>, --json)
forensicator shell <dump.dmp|trace.ttfx>  # interactive session (--symbols <pdb_dir>)
```

`analyze` supplements stack-only dumps with on-disk module bytes discovered
next to the dump (`ImageSet::discover`), then runs the pipeline. `--symbols`
swaps in a symbolizing pipeline whose `v8` analyzer resolves native frames via
PDBs (accepted only on RSDS GUID+age match).

## Interactive shell (`session.rs`)

Hand-rolled REPL over `std::io` — no line-editing dependencies (repo's
minimal-deps convention). Each line is tokenized (quote-aware) and parsed by a
dedicated clap parser (`SessionCli`, `no_binary_name`), so help and errors come
from clap exactly as in one-shot mode.

### Design: one code path, two modes

Handlers are split into *load* vs *execute* (`print_inspect(&Dump)`,
`match_dump(&Dump)`, `run_analyze(&S1Output)`, `supplement_images(&mut S1Output)`).
One-shot subcommands are thin wrappers; the session reuses the same functions
against its loaded state. There is no behavioral fork between modes.

### Session state

```rust
pub struct Session {
    path: String,
    target: Target,               // Dump(Box<S1Output>) | Trace(TraceCursor)
    symbols: Option<String>,      // PDB dir; 'symbols <dir>' / 'symbols off'
    images: usize,                // supplemented module images
}
struct TraceCursor { trace: Trace, cursor: Position }
```

`load` (and initial open) sniffs the first 4 bytes: `TTFX` magic → trace
session; otherwise minidump session. `Session::current_s1()` returns the
command input: the dump itself, or `trace.snapshot(cursor)` re-wrapped as
`S1Output`.

### Command surface

| Group | Commands |
|---|---|
| Analysis (both modes) | `inspect [--json --quiet]`, `analyze [--plugin --json]`, `match --exe/--pdb`, `list-plugins` |
| Session | `load <path>`, `symbols [dir|off]`, `quit` (Ctrl-D also exits) |
| Trace cursor | `seek <pos>`, `t+`, `t-`, `position`, `writes <va> <len>`, `intervals` |

Positions accept decimal or `0x` hex. Cursor movement enforces CursorBounded:
seeking past the frontier is an error, not a clamp. The prompt reflects state:
`forensicator[file.dmp]>` vs `forensicator[trace.ttfx @ 0x2/0x2]>`.

The cursor commands map 1:1 to `Timeline.tla` actions (`Seek`, `Advance`,
`Retreat`) and to WinDbg idioms (`!tt`, `t+`/`t-`,
`dx TTD.Memory(va, va+len, "w")`).

## Adding a session command

1. Add a variant to `SessionCommands` (clap derive; aliases via
   `#[command(alias = "…")]`).
2. Handle it in `Session::dispatch`; use `self.current_s1()` for snapshot
   commands or `self.trace_mut()` for cursor commands (the latter errors
   cleanly in dump sessions).

# Forensicator

Forensic analysis of Windows x64 minidumps and TTD-style execution traces. Custom hand-written parsers, pointer graph inference, structure recovery, V8 JavaScript stack analysis, and crash-cause diagnosis — all over a formal (TLA+) contract.

## Architecture

**Workspace:** `forensicator-core` (lib) + `forensicator-cli` (bin)

**Two input formats, one analysis pipeline:**
1. **Minidump (`.dmp`)** — validate header → stream directory → per-stream decoders → typed `Dump` with provenance; regions → sorted, non-overlapping `AddressSpace` (Image/Stack/Private/Mapped/Other)
2. **Trace (`.ttfx`)** — our versioned container for TTD trace data (initial memory + append-only write/event logs + thread/call intervals). `Trace::snapshot(t)` materializes any position into the same `(Dump, AddressSpace)` pair, so analyzers run unchanged at any recorded instant

3. **Analyze** — pluggable analyzer pipeline: crash-cause diagnosis plus detectors for strings, vtables, linked lists, arrays, heap chunks, shape clusters, and V8 JavaScript frames

Microsoft `.run` files are never parsed directly; a Windows-side extractor (TTDReplay SDK) emits `.ttfx`. The trace semantics are pinned by `specs/Timeline.tla` (Apalache-verified).

## CLI

```
forensicator inspect <dump.dmp>           # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # run analyzer pipeline (--plugin, --json, --symbols)
forensicator match <dump.dmp>             # verify dump ↔ build artifacts (--exe, --pdb, --json)
forensicator list-plugins                 # list available analyzers
forensicator shell <dump.dmp|trace.ttfx>  # interactive session
forensicator trace <trace.ttfx>           # trace summary + queries (--pos, --writes <va> <len>, --json)
```

**Interactive shell** — load once, then run commands repeatedly: `inspect`, `analyze`, `match`, `load`, `symbols <dir>`. On a `.ttfx` trace the session owns a cursor: `seek <pos>`, `t+`, `t-`, `position`, `writes <va> <len>` (who wrote this address), `intervals` — with `inspect`/`analyze` operating on the snapshot at the cursor. Positions are bounded by the trace frontier; no travel to unrecorded time.

**`--symbols <pdb_dir>`** enables PDB-based symbol resolution (V8 analyzer); a PDB is only accepted when its GUID matches the dump's RSDS record.

**`match`** verifies that a dump corresponds to a given build: each `--exe` is paired to a dump module by basename and each `--pdb` by the module's recorded pdb_name, then RSDS **GUID + age** (and PE checksum, when present) are compared. Exit code `0` = no mismatch, `2` = mismatch or module not found.

```
$ forensicator match dump.dmp --exe electron.exe --pdb electron.exe.pdb
EXE electron.exe ↔ module D:\...\electron.exe
  guid      MATCH     file=a8ab322e-...  dump=a8ab322e-...
  age       MATCH     file=1  dump=1
  checksum  UNKNOWN   file=0x00000000  dump=-  (dump module checksum is 0)
PDB electron.exe.pdb ↔ module D:\...\electron.exe
  guid      MATCH     file=a8ab322e-...  dump=a8ab322e-...
  age       MATCH     file=1  dump=1
overall: MATCH
```

`inspect --json` exposes the same identity fields per module (`codeview_guid`, `pdb_name`, `checksum`).

## Analyzer Plugins

| Plugin | Description |
|--------|-------------|
| `cause` | Diagnoses crash cause (V8 CHECK/OOM, stack overflow, Smi type confusion, corrupted code pointer, …) from the exception stream and V8 heap metadata |
| `strings` | Scans committed memory for null-terminated strings (ASCII, UTF-16LE) |
| `vtables` | Finds aligned function pointers forming vtables in Image regions |
| `lists` | Chases pointer chains to find linked lists in heap memory |
| `arrays` | Groups pointer targets with regular stride into arrays |
| `chunks` | Identifies heap allocation chunks by pointer density |
| `shapes` | Clusters heap nodes by structural signature |
| `v8` | Recovers JS stack traces by walking native stacks and classifying V8 frames |

## Pointer Patterns

Built-in presets for pointer scanning:

| Pattern | Description |
|---------|-------------|
| `all_strict` | 8-byte aligned, canonical x64 addresses |
| `all_loose` | 4-byte aligned, wider match radius |
| `saved_frame_pointers` | Stack-to-stack frame pointer chains |
| `vtables` | Module data to Image region function pointers |
| `heap_references` | Heap-to-heap pointer references |

## Development

| Command | What |
|---------|------|
| `cargo build` | Build all |
| `cargo test -p forensicator-core` | Run core tests |
| `cargo test -p forensicator-cli` | Run CLI tests |
| `cargo test --workspace` | Full test suite |
| `cargo clippy --all-targets` | Lint |
| `cargo fmt --all` | Format |
| `MIRROR_BIN=... APALACHE_MC=... cargo test --test mbt_xxx -- --nocapture` | Model-based tests (opt-in) |

**Requirements:** Rust ≥ 1.85 (edition 2024). Pure Rust with no OS APIs — analyzes Windows minidumps but builds and runs on Linux and Windows hosts alike (`x86_64-pc-windows-gnu` checked).

## TLA+ Model-Based Testing

`specs/` contains TLA+ specifications for the parse pipeline, address space, architecture model, symbol resolution, crash-cause diagnosis, and the trace timeline (`Timeline.tla` — the formal contract for `.ttfx`). MBT integration tests in `forensicator-core/tests/` validate the implementation against these specs using `mirrorrust` and Apalache — opt-in, require `MIRROR_BIN` and `APALACHE_MC` environment variables.

## License

MIT

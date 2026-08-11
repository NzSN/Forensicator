---
name: forensicator
description: Use when working in the Forensicator repo (Rust minidump forensics for Electron/V8 crashes) — running `forensicator-cli inspect/analyze` on .dmp files, interpreting the `cause` analyzer's crash diagnosis, adding analyzers, or extending the custom V8HE minidump stream. Triggers on forensicator, minidump, .dmp, crash diagnosis, V8HE, CrashCauseAnalyzer.
---

# Forensicator

Rust 2024 workspace for forensic analysis of Windows x64 minidumps from Electron/Chromium processes, with V8-specific crash-cause diagnosis. Two crates: `forensicator-core` (lib) + `forensicator-cli` (bin, binary name `forensicator-cli`).

## Build & test

```bash
cargo build                          # build workspace
cargo test --workspace               # full suite (MBT tests auto-skip)
cargo test -p forensicator-core -- analyzer::cause   # one module
cargo clippy --all-targets && cargo fmt --all        # always run before committing
```

MBT tests need `MIRROR_BIN` + `APALACHE_MC`; without them they print a skip message and pass. Never try to force-run them.

## Analyzing a dump

```bash
./target/debug/forensicator-cli inspect <dump.dmp>            # structure + Diagnosis line
./target/debug/forensicator-cli inspect <dump.dmp> --json     # includes "diagnosis" object
./target/debug/forensicator-cli analyze <dump.dmp> --plugin cause --json
./target/debug/forensicator-cli analyze <dump.dmp> --symbols <pdb_dir>   # V8 stack with symbols
./target/debug/forensicator-cli list-plugins
```

Test fixtures: `Case/minidump/` (stack-only Crashpad dumps), `Case/minidump_v2/` (instrumented-handler dump + matching `electron.exe` + `.pdb`), `Case/fulldump/` (1.2 GB full dump — slow: `inspect` builds a full AddressSpace when an exception is present; prefer `analyze` or expect minutes).

## Interpreting the `cause` analyzer verdict

`crash_diagnosis` = `{ verdict, confidence, evidence[], fault_va, access, fatal_message, alternatives[] }`. Verdicts:

| Verdict | Meaning |
|---|---|
| `V8CheckFailure` | V8's own invariant fired (0x80000003 / int3 / ud2 / captured fatal message) — not memory corruption |
| `V8OutOfMemory` | OOM handler message, or allocation top≈limit with fault at top |
| `StackOverflow` | 0xC00000FD, or AV inside a PAGE_GUARD region |
| `SmiTypeConfusion` | JIT bug signature: faulting base register holds a compressed Smi dereferenced as pointer |
| `V8ObjectAccess{instance_type}` | AV on `object+disp` inside the pointer-compression cage; instance_type names the object kind |
| `CorruptedCodePointer` | RIP outside all modules, unmapped or non-executable — smashed return address/vtable/callback |
| `WasmGuardFault` | AV inside a ≥1 GiB reserved guard region near RX code — wasm trap-handler miss |
| `NullDeref` / `WildAccess` | plain AV in null page / elsewhere with no V8 correlation |
| `NoException` / `Unknown` | no exception stream / nothing fired (fail-closed) |

`alternatives` lists lower-ranked rules that also fired. `fatal_message` (V8HE v2, `v8_fatal_message` annotation, or stack scan) is the ground truth when present.

## Conventions that matter

- **Hand-written parser** (`forensicator-core/src/parse/`) — no external parse crate. Keep it that way.
- **Fail closed**: every decoder/analyzer returns `None`/`Unknown` on inconsistency, never guesses. Match this discipline in new code.
- **Provenance**: decoded facts carry `{stream_type, file_offset, rva}` (`error::Provenance`).
- **Version-pinned V8 internals**: all V8 offsets live in `v8layout.rs` (`V8Layout`); never hardcode an offset in an analyzer. Add a new `V8Layout::vX_Y()` per V8 release, keyed via `for_v8_version` / `detect`.
- **Shared V8 knowledge**: heap-object walking in `v8obj.rs`, instruction decoding in `disasm.rs` — analyzers consume these; do not duplicate.
- Designs in `docs/superpowers/specs/`, plans in `docs/superpowers/plans/` (date-prefixed). Commits follow plan task checkboxes.
- `Cargo.lock` is gitignored. `states/`, `**/specs/` TLA artifacts are gitignored but `specs/*.tla` sources are committed.
- `.vscode/settings.json` holds a `DEEPSEEK_API_KEY` — never commit it.

## Adding an analyzer

1. Create `forensicator-core/src/analyzer/<name>.rs` implementing `Analyzer` (`name()`, `description()`, `analyze(&Dump, &AddressSpace) -> AnalyzerOutput`). Emit findings in `out.custom` as `serde_json` values.
2. Register in `Pipeline::default_pipeline()` (`analyzer.rs`) and in the `--symbols` pipeline in `forensicator-cli/src/main.rs`; bump the `pipeline_registered_count_matches_tla_spec` test.
3. Unit-test with synthetic `Dump` + `AddressSpace` fixtures (see `analyzer/cause.rs` tests / `V8HeapBuilder` in `analyzer/v8.rs` tests).

## Custom V8HE stream (instrumented-handler dumps)

Stream type `0x45483856` (`parse/v8heap.rs`). v1: header + heap regions ingested as ordinary memory. v2 adds a 32-byte extension (alloc top/limit, `gc_state`, `last_gc_reason`, fatal message) → `Dump.v8heap_ext`, consumed by `cause` rules 1/7. When changing the wire format, bump `version`, keep decoding truncation-tolerant, and sync the handler's `v8_heap_format.h`.

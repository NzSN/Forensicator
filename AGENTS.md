# Forensicator — AGENTS.md

Rust workspace (edition 2024) for forensic analysis of Windows x64 minidumps. Custom hand-written parser, pointer graph inference, structure recovery.

## Commands

| What | How |
|------|-----|
| Build all | `cargo build` |
| Run core tests | `cargo test -p forensicator-core` |
| Run specific module tests | `cargo test -p forensicator-core -- <module>::tests` (e.g. `recover::strings::tests`) |
| Run CLI tests | `cargo test -p forensicator-cli` |
| Full test suite | `cargo test --workspace` |
| Lint | `cargo clippy --all-targets` |
| Format | `cargo fmt --all` |
| MBT (model-based tests) | `MIRROR_BIN=... APALACHE_MC=... cargo test --test mbt_xxx -- --nocapture` (see MBT section below) |

## Architecture

**Two crates** in workspace: `forensicator-core` (lib) + `forensicator-cli` (bin, depends on core).

**Pipeline (S1 → S2):**
1. **Parse** — validate minidump header → stream directory → per-stream decoders → typed `Dump` with provenance
2. **AddressSpace** — sorted, non-overlapping memory regions with `RegionClass` classification (Image/Stack/Private/Mapped/Other)
3. **Analyze** — pluggable `Analyzer` pipeline: `cause` (crash-cause diagnosis), `strings`, `vtables`, `lists`, `arrays`, `chunks`, `shapes`, `v8` (JS stack recovery)

**`pipeline` module** — global workflow orchestrator (`Forensicator` struct) mirroring `specs/Forensicator.tla`. Composes `open()` → `analyze()` → `run_full()`.

**Utility modules** — `disasm` (iced-x86 window decode + `InstrKind` classification), `v8obj` (cage-aware object walking: decompress/smi/instance_type/strings), `v8layout` (version-pinned V8 offsets), `symbolizer` (PDB), `unwind` (.pdata), `image` (on-disk module backing).

## Key conventions

- **No external parse crate** — minidump parser is hand-written in `forensicator-core/src/parse/`
- **All outputs have confidence scores** — iterative inference, not certainty
- **Provenance tracking** — every decoded fact records stream_type + file_offset + rva
- **`edition = "2024"`** — requires Rust ≥1.85; no rust-toolchain.toml (no CI either, only `master` branch)
- **`Cargo.lock` is in `.gitignore`** — not committed (workspace as library pattern)
- **Minimal deps:** `serde_json` (core+cli), `clap` (cli); `minidumper` + `mirrorrust` + `num-bigint` + `num-traits` are dev-only

## CLI subcommands

```
forensicator inspect <dump.dmp>        # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>        # run analyzers (--plugin, --json, --symbols <pdb_dir>)
forensicator match <dump.dmp>          # verify dump ↔ exe/PDB build artifacts (--exe, --pdb, --json)
forensicator list-plugins              # list registered analyzers
forensicator shell <dump.dmp|trace.ttfx>  # interactive session (inspect/analyze/match/load/symbols/seek/t+/t-/writes/intervals/quit)
forensicator trace <trace.ttfx>        # trace summary + queries (--pos, --writes <va> <len>, --json)
```

## TTD trace support (.ttfx)

`specs/Timeline.tla` is the formal contract (Apalache-verified); design in `docs/superpowers/specs/2026-08-07-timeline-design.md`. `.ttfx` is our own versioned container for TTD trace data (initial memory + write/event logs + thread/call intervals), emitted by a Windows-side extractor from TTDReplay — `.run` files are never parsed directly. Core: `model::trace::Trace` (views `value_at`/`last_writer`/`writes_between`/`exceptions_at`/`snapshot(t)`), decoder `parse/ttfx.rs` (Timeline invariants → anomalies). Fixture: `Case/ttfx/minimal.ttfx` (regenerate: `cargo test -p forensicator-core --lib -- parse::ttfx --ignored`).

## Built-in pointer patterns

`all_strict`, `all_loose`, `saved_frame_pointers`, `vtables`, `heap_references`

## TLA+ model-based testing

`specs/` contains TLA+ specs (AddressSpace, Arch, Model, etc.) with corresponding `forensicator-core/tests/mbt_*.rs` integration tests via `mirrorrust`. MBT tests are **opt-in** (require `MIRROR_BIN` + `APALACHE_MC` env vars). State traces in `states/` are TLA+ model-checking output, excluded from git.

MBT test files: `mbt_address_space.rs`, `mbt_arch.rs`, `mbt_model.rs`, `mbt_forensicator.rs`, `mbt_crash_cause.rs` (spec-only stub), `mbt_timeline.rs` (spec-only stub), `mbt_snapshot.rs` (spec-only stub). Each auto-skips with a message when `MIRROR_BIN` is unset, so `cargo test --workspace` always passes.

## Custom minidump streams

**V8HE** (stream type `0x45483856`, emitted by the instrumented handler): cage base + isolate VA + captured V8 heap regions, ingested as ordinary memory ranges. Version 2 adds a 32-byte extension after the header — allocation top/limit, `gc_state`, `last_gc_reason`, and a fatal-message string — decoded into `Dump.v8heap_ext` and consumed by the `cause` analyzer's OOM/CHECK rules.

## Development approach

Superpowers-driven: plans in `docs/superpowers/plans/`, designs in `docs/superpowers/specs/`. Commits follow plan task checkboxes.

## Gotchas

- `.gitignore` also excludes `**/specs/`, `**/states/`, `**/_apalache-out` (TLA+ build artifacts)
- `.vscode/settings.json` contains a `DEEPSEEK_API_KEY` env — do not commit
- `recover_all()` calls `ShapeClusterer::cluster()` directly (not via `StructureDetector` trait)
- `PointerGraph` has `max_nodes` (1M) and `max_edges` (10M) caps

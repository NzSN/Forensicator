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

**Pipeline (S1 → S2 → S3):**
1. **Parse** — validate minidump header → stream directory → per-stream decoders → typed `Dump` with provenance
2. **AddressSpace** — sorted, non-overlapping memory regions with `RegionClass` classification (Image/Stack/Private/Mapped/Other)
3. **Scan** — 8-byte stride pointer scanning with configurable `PointerPattern` matchers → `CandidatePointer` + `Root` extraction
4. **Graph** — `build_graph()` produces `PointerGraph` (dual adjacency, va→node map, capacity caps)
5. **Query** — `GraphQuery` provides BFS reachability, path-to-root, DOT/JSON export, degree/confidence distributions
6. **Recover** — 6 trait-based detectors: StringDetector, VTableDetector, ListDetector, ArrayDetector, ChunkDetector, ShapeClusterer → unified `StructureCatalog`

**`pipeline` module** — global workflow orchestrator (`Forensicator` struct) mirroring `specs/Forensicator.tla`. Composes all stages into `open()` → `s2()` → `s3()` → `run_full()`.

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
forensicator scan <dump.dmp>           # pointer candidate scan (--pattern, --json)
forensicator graph <dump.dmp>          # build pointer graph (--dot, --json, --min-conf)
forensicator query <dump.dmp>          # reachability queries (--reachable, --stats)
forensicator patterns list|show        # list/show pointer patterns
forensicator recover <dump.dmp>        # structure recovery (--strings, --vtables, --lists, --arrays, --chunks, --shapes, --all, --json)
```

## Built-in pointer patterns

`all_strict`, `all_loose`, `saved_frame_pointers`, `vtables`, `heap_references`

## TLA+ model-based testing

`specs/` contains TLA+ specs (AddressSpace, Arch, Model, etc.) with corresponding `forensicator-core/tests/mbt_*.rs` integration tests via `mirrorrust`. MBT tests are **opt-in** (require `MIRROR_BIN` + `APALACHE_MC` env vars). State traces in `states/` are TLA+ model-checking output, excluded from git.

MBT test files: `mbt_address_space.rs`, `mbt_arch.rs`, `mbt_model.rs`, `mbt_forensicator.rs`. Each auto-skips with a message when `MIRROR_BIN` is unset, so `cargo test --workspace` always passes.

## Development approach

Superpowers-driven: plans in `docs/superpowers/plans/`, designs in `docs/superpowers/specs/`. Commits follow plan task checkboxes.

## Gotchas

- `.gitignore` also excludes `**/specs/`, `**/states/`, `**/_apalache-out` (TLA+ build artifacts)
- `.vscode/settings.json` contains a `DEEPSEEK_API_KEY` env — do not commit
- `recover_all()` calls `ShapeClusterer::cluster()` directly (not via `StructureDetector` trait)
- `PointerGraph` has `max_nodes` (1M) and `max_edges` (10M) caps

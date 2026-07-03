# Forensicator

Forensic analysis of Windows x64 minidumps. Custom hand-written parser, pointer graph inference, structure recovery, and V8 JavaScript stack analysis.

## Architecture

**Workspace:** `forensicator-core` (lib) + `forensicator-cli` (bin)

**Pipeline (S1 → S2):**
1. **Parse** — validate minidump header → stream directory → per-stream decoders → typed `Dump` with provenance
2. **AddressSpace** — sorted, non-overlapping memory regions classified as Image/Stack/Private/Mapped/Other
3. **Analyze** — pluggable analyzer pipeline: 7 detectors scan memory for structures, strings, vtables, linked lists, arrays, heap chunks, shape clusters, and V8 JavaScript frames

## CLI

```
forensicator inspect <dump.dmp>        # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>        # run analyzer pipeline (--plugin, --json, --symbols)
forensicator list-plugins              # list available analyzers
```

**`--symbols <pdb_dir>`** enables PDB-based symbol resolution (V8 analyzer).

## Analyzer Plugins

| Plugin | Description |
|--------|-------------|
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

**Requirements:** Rust ≥ 1.85 (edition 2024).

## TLA+ Model-Based Testing

`specs/` contains TLA+ specifications for the parse pipeline, address space, architecture model, and symbol resolution. MBT integration tests in `forensicator-core/tests/` validate the implementation against these specs using `mirrorrust` and Apalache — opt-in, require `MIRROR_BIN` and `APALACHE_MC` environment variables.

## License

MIT

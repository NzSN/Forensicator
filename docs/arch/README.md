# Forensicator Architecture

Lean 4 (v4.33.0) package for forensic analysis of Windows x64 minidumps and
TTD-style execution traces, focused on Electron/Chromium (V8) crashes.
Zero Lean dependencies (no mathlib/batteries); all parsing is hand-written;
the TLA+ specs in `specs/` are mechanized as proved theorems about the
shipping functions. Build: `lake build`; gate: `scripts/conformance-lean.sh`.

**Layout:** `Forensicator/` (library) + `Main.lean` (CLI) + `Test/`
(guard-suite binary `forensicator-test`).

## Documents

| Doc | Covers |
|---|---|
| [parse-pipeline.md](parse-pipeline.md) | S1: minidump parsing, `Dump`, `AddressSpace`, provenance, V8HE custom stream |
| [analyzers.md](analyzers.md) | S2: `Analyzer` framework, the 8 built-in analyzers, shared utilities |
| [timeline.md](timeline.md) | TTD support: `Timeline.tla`, `Trace` model, `.ttfx` container, proxy boundary |
| [ttfx-format.md](ttfx-format.md) | `.ttfx` v1 byte-level reference: sections, payload pool, anomalies, worked fixture dump |
| [cli.md](cli.md) | One-shot subcommands and the interactive `shell` session (trace cursor) |
| [verification.md](verification.md) | TLA+ specs, Lean theorems, fixtures, golden gate |

## Module map (Lean port ↔ Rust era)

| Lean (current) | Rust (removed 2026-08-13) |
|---|---|
| `Forensicator/Parse/Minidump.lean`, `Parse/Cursor.lean` | `forensicator-core/src/parse/*` (header, directory, per-stream decoders) |
| ~~`Forensicator/Parse/Ttfx.lean`~~ (removed with the eager trace path, 2026-08-13) | `forensicator-core/src/parse/ttfx.rs` |
| `Forensicator/Model/{Types,Structs,Dump,Trace}.lean` | `forensicator-core/src/model.rs`, `model/trace.rs` |
| `Forensicator/Pipeline.lean` | `forensicator-core/src/pipeline.rs` |
| `Forensicator/Analyzer/{Analyzer,Registry,Scan,Cause,Strings,Vtables,Lists,Arrays,Chunks,Shapes,V8}.lean` | `forensicator-core/src/analyzer{,/*}.rs` |
| `Forensicator/Util/{Disasm,V8Layout,Pdb,Unwind,Image,Pattern,Bytes,Text,Json}.lean` | `disasm`, `v8layout`, `symbolizer`, `unwind`, `image` modules + `serde_json` |
| `Forensicator/Session.lean`, `Main.lean` | `forensicator-cli/src/{session,main}.rs` |
| `Forensicator/Spec/{AddressSpace,Timeline}.lean` (proved theorems) | `tests/mbt_*.rs` (mirrorrust MBT drivers) |

Deliberate divergences from the Rust era are documented in-file: Nat-lifted
address arithmetic; a native x86-64 disasm subset instead of iced-x86; a
minimal MSF-7 PDB reader instead of the `pdb` crate; the `find_ept_base`
debug-overflow panic reproduced on fulldump.

## System overview

```
        inputs                              library                                 outputs
┌──────────────────┐   ┌─────────────────────────────────────────┐
│ .dmp (minidump)  │──▶│ Parse/Minidump ─▶ Dump (facts + prov.)  │
└──────────────────┘   │   + Pipeline.buildAddressSpace          │     ┌──────────────┐
                       │                = dump + space           │────▶│ text / JSON  │
                       │                     │                   │     │ StructureCat.│
                       │ Analyzer.runPipeline (8 analyzers, ──────┘     └──────────────┘
                       │   total) ▲
                       └──────────┼──────────────────────────────┘
                                  │   Main.lean + Session.lean
   trace (follow-up):             │   one-shot subcommands + interactive shell
   Windows proxy + Lean client ───┘   (shell owns the trace cursor)
   (specs/JigSawSpawner.tla;
    Trace.snapshot(t) materializes
    any position into dump+space)
```

Key structural property: **analyzers are pure read-only functions of one
snapshot** (`Dump → AddressSpace → AnalyzerOutput`). Time travel adds no
analyzer changes — `Trace.snapshot t` materializes any trace position into
that same pair (`Model/Trace.lean`; the proxy client that will construct
traces at runtime is a follow-up — the eager `.ttfx` path was removed
2026-08-13).

## Cross-cutting conventions

- **Fail closed**: decoders and analyzers return `none`/`Unknown`/`Anomaly` on
  inconsistency, never guess; the library is `sorry`/`partial`/`panic!`-free,
  so there is no panic-isolation branch at all.
- **Provenance**: every decoded fact records `{streamType, fileOffset, rva}`;
  trace facts use pseudo stream-type `TTFX_STREAM_TYPE`.
- **Confidence**: all inferred structures carry confidence scores.
- **Versioned wire formats**: V8HE and TTFX are versioned, additive,
  truncation-tolerant; a version bump signals a breaking layout change.
- **Spec-backed**: TLA+ specs (`specs/`) are mechanized as Lean theorems over
  the shipping functions (`Forensicator/Spec/`, plus theorems in
  `Pipeline.lean`, `Model/Trace.lean`); code comments link the two.

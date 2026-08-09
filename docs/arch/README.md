# Forensicator Architecture

Rust 2024 workspace for forensic analysis of Windows x64 minidumps and
TTD-style execution traces, focused on Electron/Chromium (V8) crashes.

**Workspace:** `forensicator-core` (lib) + `forensicator-cli` (bin, depends on core).
Minimal deps (`clap`, `serde_json`, `uuid`, dev-only `mirrorrust`); all parsing is
hand-written; builds and runs on Linux and Windows hosts.

## Documents

| Doc | Covers |
|---|---|
| [parse-pipeline.md](parse-pipeline.md) | S1: minidump parsing, `Dump`, `AddressSpace`, provenance, V8HE custom stream |
| [analyzers.md](analyzers.md) | S2: `Analyzer` trait, `Pipeline`, the 8 built-in analyzers, shared utilities |
| [timeline.md](timeline.md) | TTD support: `Timeline.tla`, `Trace` model, `.ttfx` container, extractor boundary |
| [ttfx-format.md](ttfx-format.md) | `.ttfx` v1 byte-level reference: sections, payload pool, anomalies, worked fixture dump |
| [cli.md](cli.md) | One-shot subcommands and the interactive `shell` session (trace cursor) |
| [verification.md](verification.md) | TLA+ specs, model-based tests, fixtures, test strategy |

## System overview

```
        inputs                              core                                    outputs
┌──────────────────┐   ┌─────────────────────────────────────────┐
│ .dmp (minidump)  │──▶│ parse/ ──▶ Dump (facts + provenance)    │
└──────────────────┘   │            + AddressSpace (regions)     │     ┌──────────────┐
                       │                    = S1Output           │────▶│ text / JSON  │
┌──────────────────┐   │                     │                   │     │ StructureCat.│
│ .ttfx (TTD trace)│──▶│ parse/ttfx ──▶  Trace ──snapshot(t)─────┘     └──────────────┘
└──────────────────┘   │                    ▼                             ▲
        ▲              │ analyzer::Pipeline (8 analyzers, panic-isolated)─┘
        │              └─────────────────────────────────────────┘
        │                                ▲
   Windows extractor                     │  forensicator-cli
   (TTDReplay SDK, separate)      one-shot subcommands + interactive shell
                                  (shell owns the trace cursor)
```

Key structural property: **analyzers are pure read-only functions of one
snapshot** (`&Dump, &AddressSpace`). Time travel adds no analyzer changes —
`snapshot(t)` materializes any trace position into that same pair.

## Cross-cutting conventions

- **Fail closed**: decoders and analyzers return `None`/`Unknown`/`Anomaly` on
  inconsistency, never guess and never panic (analyzer panics are additionally
  caught by the pipeline and recorded as error entries).
- **Provenance**: every decoded fact records `{stream_type, file_offset, rva}`;
  trace facts use pseudo stream-type `TTFX`.
- **Confidence**: all inferred structures carry confidence scores.
- **Versioned wire formats**: V8HE and TTFX are versioned, additive,
  truncation-tolerant; a version bump signals a breaking layout change.
- **Spec-backed**: core semantics live in TLA+ (`specs/`), mirrored by opt-in
  model-based tests; code comments link modules to their spec counterparts.

# Verification: Specs, MBT, Fixtures, Tests

## TLA+ specifications (`specs/`)

| Spec | Models | Checked by |
|---|---|---|
| `Forensicator.tla` | Root workflow composition (S1 parse latches → S2 analyzer pipeline) | Apalache |
| `Model.tla` | Decoded `Dump` facts (append-only, provenance, bounded counts) | Apalache |
| `ParsePipeline.tla` | S1 phase machine (Init→…→Built/Done/Fatal) | Apalache |
| `AddressSpace.tla` | Region map invariants (`NoOverlap`, classify totality) | TLC + Apalache |
| `Arch.tla` | Exception CONTEXT register file | Apalache |
| `Symbolizer.tla` | Module/symbol tables, sorted resolution | Apalache |
| `CrashCause.tla` | Verdict discipline (classify → fire rules → decide; verdicts justified by fired rules) | Apalache |
| `Timeline.tla` | TTD trace semantics: ordered logs, cursor bounds, snapshot consistency, call nesting | Apalache (depth 10) + TLC simulation |

Conventions: tiny model-checking bounds, flat parallel sequences, `@type`
annotations, constant quantifier domains with `Len` guards (Apalache's
dynamic-range limitation), safety invariants only. Code modules cite their
spec counterparts in comments (e.g. `pipeline.rs` stage methods ↔
`Forensicator.tla` actions; `model/trace.rs` ↔ `Timeline.tla` variables).

## Model-based tests (`forensicator-core/tests/mbt_*.rs`)

`mbt_address_space`, `mbt_arch`, `mbt_model`, `mbt_forensicator` replay
Apalache counterexample/witness traces against the Rust implementation via
`mirrorrust`. `mbt_crash_cause` and `mbt_timeline` are spec-only stubs
(replay not yet wired). All **auto-skip** when `MIRROR_BIN` is unset, so
`cargo test --workspace` always passes; opt in with
`MIRROR_BIN=... APALACHE_MC=... cargo test --test mbt_xxx -- --nocapture`.

## Unit and property-style tests

- Synthetic builders (`Dump`, `AddressSpace`, `Trace`, `V8HeapBuilder`) —
  no live dumps needed.
- `model::trace::tests::snapshot_consistent_with_brute_force` — the
  Timeline.tla `SnapshotConsistent` invariant as a deterministically-seeded
  exhaustive check over a fixture trace.
- `parse/ttfx` round-trip plus one test per anomaly path (out-of-order,
  beyond-frontier, crossing calls, unknown thread, inverted interval,
  truncation).

## Golden fixtures (`Case/`, gitignored except where forced)

| Fixture | Content |
|---|---|
| `Case/minidump/` | stack-only Crashpad dumps |
| `Case/minidump_v2/` | instrumented-handler dump + matching `electron.exe` + `.pdb` |
| `Case/fulldump/` | 1.2 GB full dump (slow; prefer `analyze` over `inspect`) |
| `Case/ttfx/minimal.ttfx` | committed (force-added) hand-built trace: 2 regions, 2 writes, 2 events, 1 thread, 2 calls. Regenerate: `cargo test -p forensicator-core --lib -- parse::ttfx --ignored` |

## Commands

```
cargo test --workspace          # everything (MBT auto-skips)
cargo test -p forensicator-core -- model::trace
cargo clippy --all-targets && cargo fmt --all
```

## Known spec hygiene issues

- `specs/Forensicator.cfg` references a nonexistent `RootInvariant` (the
  invariant is `ForensicatorInvariant`).
- `specs/PointerGraph.cfg` is orphaned — its spec was removed in `bf94b03`.
- `specs/ParsePipeline.tla`'s `INSTANCE Model WITH` predates Model's
  `ann_key`/`ann_val` variables and may not check as-is.

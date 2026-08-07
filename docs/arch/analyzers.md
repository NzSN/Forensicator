# S2: Analyzer Framework

Spec: `specs/Forensicator.tla` (S2 half), `specs/CrashCause.tla`.
Code: `forensicator-core/src/analyzer.rs`, `forensicator-core/src/analyzer/`.

## Contract

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput;
}
```

Analyzers are **pure, read-only, single-snapshot** functions. They never mutate
state, never see each other, and never perform I/O. This purity is the seam the
TTD support exploits: `Trace::snapshot(t)` produces a `(Dump, AddressSpace)`
for any position and the whole framework runs unmodified at any instant.

## Pipeline (`analyzer.rs:86`)

`Pipeline::default_pipeline()` registers the 8 built-ins in fixed order:
`cause`, `strings`, `vtables`, `lists`, `arrays`, `chunks`, `shapes`, `v8`.
`Pipeline::run(dump, space, filter)`:

- optional name filter (`--plugin a,b`)
- each analyzer runs inside `catch_unwind` — a panic becomes an
  `AnalyzerOutput` with a `"error"` custom entry, never a crash
- outputs collect into `StructureCatalog { outputs }` with per-type accessors
  (`all_strings()`, `all_vtables()`, …)

`AnalyzerOutput` carries typed vectors (`strings`, `vtables`, `linked_lists`,
`arrays`, `chunks`, `shape_clusters`) plus free-form
`custom: Vec<(String, serde_json::Value)>` for analyzer-specific structures
(crash diagnosis, v8 frames).

## Built-in analyzers

| Plugin | File | What it computes |
|---|---|---|
| `cause` | `analyzer/cause.rs` | Crash-cause verdict: fuses exception semantics, disassembly classification, MemoryInfo fault-site analysis, cage/register correlation, V8HE v2 facts → ranked rules → `{ verdict, confidence, evidence[], fault_va, alternatives[] }` |
| `strings` | `analyzer/strings.rs` | Null-terminated ASCII / UTF-16LE strings in committed memory |
| `vtables` | `analyzer/vtables.rs` | Aligned function-pointer runs in Image-region data |
| `lists` | `analyzer/lists.rs` | Linked lists via pointer-chain chasing |
| `arrays` | `analyzer/arrays.rs` | Regular-stride pointer-target groups |
| `chunks` | `analyzer/chunks.rs` | Heap allocation chunks by pointer density |
| `shapes` | `analyzer/shapes.rs` | Heap nodes clustered by structural signature (offset→class edges) |
| `v8` | `analyzer/v8.rs` | JS stack recovery: walks native stacks, classifies V8 frames (JS / optimized-JS / builtin / exit), resolves JS function names + script lines via the isolate; optional PDB symbolization of native frames |

### cause verdicts

`V8CheckFailure`, `V8OutOfMemory`, `StackOverflow`, `SmiTypeConfusion`,
`V8ObjectAccess{instance_type}`, `CorruptedCodePointer`, `WasmGuardFault`,
`NullDeref`, `WildAccess`, `NoException`, `Unknown` — ranked by confidence with
`alternatives[]` listing lower-ranked rules that also fired. Fail-closed:
`Unknown` when nothing fires. Spec: `specs/CrashCause.tla` (classify → fire
rules → decide; verdicts must be justified by fired rules).

## Shared utilities (consumed, never duplicated, by analyzers)

| Module | Provides |
|---|---|
| `disasm.rs` | iced-x86 window decoding + instruction classification (int3/ud2/data-access shapes) |
| `v8obj.rs` | cage-aware V8 heap-object walking (decompress, smi, instance_type, strings) |
| `v8layout.rs` | version-pinned V8 offsets (`V8Layout`); all V8 offsets live here, never hardcoded in analyzers |
| `symbolizer.rs` | PDB parsing + address→symbol; GUID must match the module's RSDS record |
| `unwind.rs` | .pdata-based x64 unwinding |
| `image.rs` | on-disk module backing (ImageFile/ImageSet) for stack-only dumps |

## Adding an analyzer

1. `analyzer/<name>.rs` implementing `Analyzer`; findings as typed vectors or
   `custom` JSON.
2. Register in `Pipeline::default_pipeline()` and in the `--symbols` pipeline
   in `forensicator-cli/src/main.rs`; bump the pipeline-count test.
3. Unit-test with synthetic `Dump`/`AddressSpace` fixtures (see
   `analyzer/cause.rs` tests, `V8HeapBuilder` in `analyzer/v8.rs` tests).

Deferred (design exists): a `TemporalAnalyzer` trait for cross-position
queries over `Trace` — separate from `Analyzer`, since it needs the timeline.

# S2: Analyzer Framework

Spec: `specs/Forensicator.tla` (S2 half), `specs/CrashCause.tla`.
Code: `Forensicator/Analyzer/Analyzer.lean` (framework),
`Forensicator/Analyzer/Registry.lean` (default pipeline),
`Forensicator/Analyzer/*.lean` (the built-ins).

## Contract

```lean
structure Analyzer where
  name : String
  description : String
  run : Dump → AddressSpace → AnalyzerOutput
```

Analyzers are **pure, total, read-only, single-snapshot** functions. They
never mutate state, never see each other, and never perform I/O. This purity
is the seam the TTD support exploits: `Trace.snapshot t` produces a
`(Dump, AddressSpace)` for any position and the whole framework runs
unmodified at any instant.

Lean has no `catch_unwind` and needs none: the ported analyzers are total
(all indexing bounds-guarded), so the Rust pipeline's panic-isolation branch
is unreachable — a panic becomes a *compile-time* impossibility, not a
runtime error entry.

## Pipeline (`Analyzer/Analyzer.lean`, `Registry.lean`)

`defaultPipeline` registers the 8 built-ins in fixed order: `cause`,
`strings`, `vtables`, `lists`, `arrays`, `chunks`, `shapes`, `v8`.
`runPipeline analyzers dump space filter`:

- optional name filter (`--plugin a,b`)
- outputs collect into `StructureCatalog { outputs }` with per-type accessors
  (`allStrings`, `allVtables`, …)

`AnalyzerOutput` carries typed lists (`strings`, `vtables`, `linkedLists`,
`arrays`, `chunks`, `shapeClusters`) plus free-form
`custom : List (String × Json)` for analyzer-specific structures (crash
diagnosis, v8 frames). JSON is `Util/Json.lean` (no serde).

## Built-in analyzers

| Plugin | File | What it computes |
|---|---|---|
| `cause` | `Analyzer/Cause.lean` | Crash-cause verdict: fuses exception semantics, disassembly classification, MemoryInfo fault-site analysis, cage/register correlation, V8HE v2 facts → ranked rules → `{ verdict, confidence, evidence[], fault_va, alternatives[] }` |
| `strings` | `Analyzer/Strings.lean` | Null-terminated ASCII / UTF-16LE strings in committed memory |
| `vtables` | `Analyzer/Vtables.lean` | Aligned function-pointer runs in Image-region data |
| `lists` | `Analyzer/Lists.lean` | Linked lists via pointer-chain chasing |
| `arrays` | `Analyzer/Arrays.lean` | Regular-stride pointer-target groups |
| `chunks` | `Analyzer/Chunks.lean` | Heap allocation chunks by pointer density |
| `shapes` | `Analyzer/Shapes.lean` | Heap nodes clustered by structural signature (offset→class edges) |
| `v8` | `Analyzer/V8.lean` | JS stack recovery: walks native stacks, classifies V8 frames (JS / optimized-JS / builtin / exit), resolves JS function names + script lines via the isolate; optional PDB symbolization of native frames |

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
| `Util/Disasm.lean` | native x86-64 window decoder + instruction classification (int3/ud2/data-access/indirect shapes) — a deliberate subset covering exactly what the cause rules consume; no iced-x86 FFI |
| `Analyzer/V8.lean` + `Util/V8Layout.lean` | cage-aware V8 heap-object walking (decompress, smi, instance_type, strings); version-pinned V8 offsets — all V8 offsets live in V8Layout, never hardcoded in analyzers |
| `Util/Pdb.lean` | minimal MSF-7 PDB reader — identity (GUID+age) for `match`; GUID must match the module's RSDS record |
| `Util/Unwind.lean` | .pdata-based x64 unwinding |
| `Util/Image.lean` | on-disk module backing (PE parse, VA→file offset) for stack-only dumps |
| `Util/Pattern.lean` | built-in pointer patterns (`all_strict`, `saved_frame_pointers`, …) |

## Adding an analyzer

1. `Forensicator/Analyzer/<Name>.lean` defining an `Analyzer`; findings as
   typed lists or `custom` JSON.
2. Register in `Analyzer/Registry.lean`'s `defaultPipeline` (and the
   `--symbols` pipeline in `Main.lean`); bump the pipeline-count guard in
   `Test/Spec.lean`.
3. Test with synthetic `Dump`/`AddressSpace` fixtures in the guard suite
   (`Test/Spec.lean`; the `v8` tests build synthetic cages).

Deferred (design exists): a temporal-analyzer interface for cross-position
queries over `Trace` — separate from `Analyzer`, since it needs the timeline.

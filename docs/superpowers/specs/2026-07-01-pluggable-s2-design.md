# Pluggable S2 — Design Spec

## Status
Approved, pending implementation plan.

## Summary
Collapse the current 3-stage pipeline (S1→Scan→Graph→Recover) into 2 stages:
- **S1**: unchanged — parse minidump → `Dump` + `AddressSpace`
- **S2**: pluggable analyzer framework — trait-based observers produce a unified `StructureCatalog`

All 6 existing detectors become built-in analyzers. A shared `pointer_scan()` utility replaces the mandatory scan→graph→query pipeline.

## Motivation
The current Scan→Graph→Query→Recover pipeline is rigid. Every analysis path must go through pointer scanning and graph construction even when a detector (e.g., string scanner) doesn't need it. The 6-stage linear pipeline couples detectors to the graph representation. A plugin model allows each analyzer to consume only what it needs and lets users add custom analyzers without modifying core.

## Scope
- **In**: new `analyzer/` module with `Analyzer` trait, `Pipeline`, `AnalyzerOutput`, `StructureCatalog`
- **In**: 6 ported built-in analyzers (strings, vtables, lists, arrays, chunks, shapes)
- **In**: shared `pointer_scan()` utility for detectors that need pointer-edge data
- **In**: new `analyze` + `list-plugins` CLI subcommands
- **Out**: `scan/`, `graph/`, `query/`, `recover/` modules removed; `pattern/` module stays as utility
- **Out**: CLI subcommands `scan`, `graph`, `query`, `recover` removed

## Architecture

```
S1:  .dmp file  →  parse  →  Dump + AddressSpace
S2:  (Dump, AddressSpace)  →  [Analyzer*]  →  StructureCatalog
```

### Module layout

```
forensicator-core/src/
├── analyzer/
│   ├── mod.rs          # Analyzer trait, Pipeline, AnalyzerOutput, StructureCatalog
│   ├── scan.rs         # shared pointer_scan() utility
│   ├── strings.rs      # StringAnalyzer
│   ├── vtables.rs      # VTableAnalyzer
│   ├── lists.rs        # ListAnalyzer
│   ├── arrays.rs       # ArrayAnalyzer
│   ├── chunks.rs       # ChunkAnalyzer
│   └── shapes.rs       # ShapeAnalyzer
├── arch.rs             # (unchanged)
├── error.rs            # (unchanged)
├── model.rs            # (trimmed: remove scan/graph/query-only types)
├── parse/              # (unchanged)
├── pattern/            # (kept as utility, PointerPattern used by pointer_scan())
├── pipeline.rs         # (rewritten: Forensicator struct with 2-stage API)
├── space.rs            # (unchanged)
└── lib.rs
```

### Core trait

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str { "no description" }
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput;
}
```

### AnalyzerOutput

A single struct with typed fields for all 6 built-in analyzer kinds plus a `custom` bucket for user-defined plugins. Each analyzer fills only the fields relevant to its output type — the rest remain as empty `Vec`s.

```rust
pub struct AnalyzerOutput {
    pub plugin_name: String,
    pub strings: Vec<StructString>,
    pub vtables: Vec<StructVTable>,
    pub linked_lists: Vec<StructLinkedList>,
    pub arrays: Vec<StructArray>,
    pub chunks: Vec<StructChunk>,
    pub shape_clusters: Vec<ShapeGroup>,
    pub custom: Vec<(String, serde_json::Value)>,
}
```

### StructureCatalog

Wraps all `AnalyzerOutput`s. Provides convenience accessors per-type.

```rust
pub struct StructureCatalog {
    pub outputs: Vec<AnalyzerOutput>,
}

impl StructureCatalog {
    pub fn all_strings(&self) -> impl Iterator<Item = &StructString>;
    pub fn all_vtables(&self) -> impl Iterator<Item = &StructVTable>;
    // ... per-type accessors
}
```

### Pipeline

Owns a `Vec<Box<dyn Analyzer>>`. `register()` appends. `run()` iterates:

```rust
pub struct Pipeline {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Pipeline {
    pub fn new() -> Self;
    pub fn register(&mut self, a: impl Analyzer + 'static) -> &mut Self;
    pub fn default_pipeline() -> Self;  // registers all 6 built-in analyzers
    pub fn run(&self, dump: &Dump, space: &AddressSpace, filter: &[&str]) -> StructureCatalog;
}
```

`run()` iterates registered analyzers in insertion order. If `filter` is non-empty, only analyzers whose `name()` matches an entry are executed. Each analyzer produces an `AnalyzerOutput`; all outputs are collected into a `StructureCatalog`.

## Shared pointer_scan() utility

```rust
pub fn pointer_scan(
    space: &AddressSpace,
    dump: &Dump,
    patterns: &[PointerPattern],
) -> Vec<CandidatePointer>;
```

Returns a flat list of `CandidatePointer`s with confidence scores. This is a pure function, not a stage. The `ListAnalyzer`, `ArrayAnalyzer`, `ChunkAnalyzer`, and `ShapeAnalyzer` call it internally with their preferred pattern set. The `StringAnalyzer` and `VTableAnalyzer` do not use it.

`CandidatePointer` is simplified: source_va, target_va, confidence, source_ctx, target_ctx. No roots extraction (roots only made sense for graph traversal, which is removed).

## model.rs changes

**Removed**: `Root`, `ScanResult`, `PointerGraph`, `GraphNode`, `GraphEdge`, `NodeIndex`, `EdgeIndex`, `EdgePath`, `EdgePredicate`, `ShapeSignature`, `ShapeClusters`. The `PointerPattern` and `ValueMatcher` stay (used by `pointer_scan()`).

**Kept**: `Dump`, `SystemInfo`, `Module`, `Thread`, `MemoryRegionInfo`, `Protection`, `MemState`, `MemType`, `RegionClass`, `SourceContext`, `TargetContext`, `CandidatePointer`, `StructString`, `StructVTable`, `StructLinkedList`, `StructArray`, `StructChunk`, `ShapeGroup`.

`StructureCatalog` moves to `analyzer/mod.rs`.

## Built-in analyzers

| Analyzer | Description | Uses pointer_scan? |
|----------|-------------|--------------------|
| `StringAnalyzer` | Scans committed memory for null-terminated strings (ASCII, UTF-16LE, UTF-16BE) | No |
| `VTableAnalyzer` | Scans Image-region data for aligned function pointers forming vtables | No |
| `ListAnalyzer` | Chases pointer chains through candidate pointers to find linked lists | Yes |
| `ArrayAnalyzer` | Groups pointer targets with regular stride into arrays | Yes |
| `ChunkAnalyzer` | Identifies heap allocation chunks by pointer density in Private regions | Yes |
| `ShapeAnalyzer` | Clusters heap nodes by structural signature (offset→target_class edges) | Yes |

Each is a unit struct that implements `Analyzer`. The detector logic from the old `recover/` submodules is ported directly, with the key change that graph/query dependencies are replaced by calling `pointer_scan()`.

## pipeline.rs rewrite

`Forensicator` retains `s1()` / `open()` as-is. The old `s2()`, `s3()`, `run_full()` are replaced:

```rust
impl Forensicator {
    pub fn open(path: impl AsRef<Path>) -> Result<S1Output, FatalError> { /* unchanged */ }

    /// Run the S2 pipeline: all (or filtered) analyzers against S1 output.
    pub fn analyze(
        s1: &S1Output,
        pipeline: &Pipeline,
        filter: &[&str],
    ) -> StructureCatalog {
        pipeline.run(&s1.dump, &s1.space, filter)
    }

    pub fn run_full(
        path: impl AsRef<Path>,
        pipeline: &Pipeline,
        filter: &[&str],
    ) -> Result<(S1Output, StructureCatalog), Box<dyn std::error::Error>> {
        let s1 = Self::open(path)?;
        let cat = Self::analyze(&s1, pipeline, filter);
        Ok((s1, cat))
    }
}
```

## CLI changes

```
forensicator inspect <dump.dmp>           # S1: structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # S1+S2: run default pipeline (--json)
forensicator analyze <dump.dmp> --plugin strings,vtables      # run subset
forensicator list-plugins                  # enumerate registered analyzers
```

Removed subcommands: `scan`, `graph`, `query`, `recover`, `patterns`.

### `forensicator analyze`

Runs `Pipeline::default_pipeline()` (all 6 built-ins) unless `--plugin` filters to a subset. With `--json`, outputs:

```json
{
  "plugins": [
    {
      "name": "strings",
      "count": 1234,
      "strings": [{"va": "0x...", "encoding": "ASCII", "content": "..."}],
      "vtables": null,
      "linked_lists": null,
      "arrays": null,
      "chunks": null,
      "shape_clusters": null,
      "custom": null
    }
  ]
}
```

Without `--json`, prints a human-readable summary per plugin (count, distribution).

### `forensicator list-plugins`

Prints name + description for each built-in analyzer. If user-registered analyzers are added via a hypothetical config/extension mechanism in the future, they'd appear here too.

## Error handling

Each `analyze()` call runs independently. If one analyzer panics (caught by `std::panic::catch_unwind`), the pipeline logs an error section in the output and continues to the next analyzer. Fatal errors are only from S1 (file I/O, bad magic, etc.).

## Testing strategy

- Unit tests for each built-in analyzer with synthetic AddressSpaces and Dumps
- Integration test for `Pipeline::default_pipeline()` against a known minidump (existing test dump in repo)
- Regression: existing parse/space/model tests pass unchanged
- MBT tests updated to reflect 2-stage model

## Open questions

None — all design decisions captured above.

# Forensicator — Workflow Specification

## Overview

Forensicator analyzes Windows x64 minidump (`.dmp`) files through a two-stage pipeline: **Parse** (S1) followed by an extensible set of **Analyzers** (S2).

```
.dmp file ──[S1: Parse]──> Dump + AddressSpace ──[S2: Pipeline.run(analyzers)]──> StructureCatalog
```

---

## Stage 1 — Parse

**Input:** A Windows x64 minidump file path.

**Process:** `Forensicator::open(path)` or `Forensicator::s1(path)`:

1. **Header validation** — reads the 32-byte header, verifies magic (`MDMP`), extracts stream directory RVA.
2. **Stream directory** — locates the directory, decodes each stream entry (type, data RVA, data size).
3. **Stream decoders** — per stream type:
   - `SystemInfoStream` → `SystemInfo` (OS, CPU, version)
   - `ModuleListStream` → `Vec<Module>` (name, base VA, size, codeview GUID, PDB path)
   - `ThreadListStream` → `Vec<Thread>` (TID, stack range, TEB VA, register context)
   - `MemoryListStream` / `Memory64ListStream` → `Vec<MemoryRegionInfo>` (VA, size, raw data, protection, state, type, class)
   - `ExceptionStream` → `ExceptionInfo` (code, address, faulting thread)
4. **Dump assembly** — all decoded facts collected into a `Dump` struct. Non-fatal decode issues recorded as `Anomaly` entries.
5. **Address space** — `Forensicator::build_address_space(&dump)` transfers each `MemoryRegionInfo` into a sorted, non-overlapping `AddressSpace` keyed by VA. Each region carries its raw byte data, protection flags, state, and `RegionClass` classification.

**Output:** `S1Output { dump: Dump, space: AddressSpace }`

**Error semantics:** Fatal errors (bad magic, truncated file, I/O failure) return `Err(FatalError)`. Non-fatal anomalies are recorded on `Dump.anomalies`.

---

## Stage 2 — Analysis Pipeline

**Input:** `&S1Output` (or equivalently `&Dump` + `&AddressSpace`).

**Process:** A `Pipeline` holds an ordered list of `Box<dyn Analyzer>`. `Pipeline::run(dump, space, filter)` iterates each analyzer:

1. If `filter` is non-empty, skip analyzers whose `name()` is not in the filter.
2. Call `analyzer.analyze(dump, space)` inside `std::panic::catch_unwind`.
3. Collect each analyzer's `AnalyzerOutput` into a `StructureCatalog`.
4. If an analyzer panics, record an error entry in that analyzer's `AnalyzerOutput.custom` and continue.

**Output:** `StructureCatalog { outputs: Vec<AnalyzerOutput> }`

### Analyzer Trait

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn analyze(&self, dump: &Dump, space: &AddressSpace) -> AnalyzerOutput;
}
```

A user implements this trait on any type, registers it on a `Pipeline` via `pipeline.register(my_analyzer)`, and it runs alongside the built-in analyzers.

### AnalyzerOutput

```rust
pub struct AnalyzerOutput {
    pub plugin_name: String,
    pub strings: Vec<StructString>,           // StringAnalyzer fills this
    pub vtables: Vec<StructVTable>,           // VTableAnalyzer fills this
    pub linked_lists: Vec<StructLinkedList>,   // ListAnalyzer fills this
    pub arrays: Vec<StructArray>,             // ArrayAnalyzer fills this
    pub chunks: Vec<StructChunk>,             // ChunkAnalyzer fills this
    pub shape_clusters: Vec<ShapeGroup>,       // ShapeAnalyzer fills this
    pub custom: Vec<(String, serde_json::Value)>, // user analyzers write here
}
```

Each analyzer fills only the fields relevant to its output. The `custom` bucket is for user-defined analyzers that produce data not matching any built-in struct.

### Shared Utility: pointer_scan()

```rust
pub fn pointer_scan(space: &AddressSpace, dump: &Dump, patterns: &[PointerPattern])
    -> Vec<CandidatePointer>;
```

Walks committed regions at 8-byte stride, reads each qword, applies value matchers from `PointerPattern` (alignment, canonical x64, bitmask, range, etc.), computes a confidence score, classifies source/target context, and returns a flat list of `CandidatePointer { source_va, target_va, source_ctx, target_ctx, confidence }`.

This is a pure function, not a stage. Analyzers that need pointer-relationship data call it with their preferred pattern set.

---

## Built-in Analyzers

| Analyzer | Output type | Uses pointer_scan? | Algorithm |
|----------|-------------|-------------------|-----------|
| `StringAnalyzer` | `StructString` | No | Scans committed region data for null-terminated ASCII and UTF-16LE strings with configurable min/max length and non-printable ratio threshold. |
| `VTableAnalyzer` | `StructVTable` | No | Scans Image-region data for runs of aligned values that target Image-region VAs (function pointers). Groups consecutive method pointers into vtables. |
| `ListAnalyzer` | `StructLinkedList` | Yes (heap_references) | Builds an adjacency map from candidate pointers, then greedily chains through best-confidence edges to find linked lists. |
| `ArrayAnalyzer` | `StructArray` | Yes (heap_references) | Extracts unique source VAs from candidates, sorts them, finds elements with regular stride, matching out-degree, and matching region class. |
| `ChunkAnalyzer` | `StructChunk` | Yes (heap_references) | Segments Private regions by pointer-density gaps. Classifies empty/zero regions as free chunks. |
| `ShapeAnalyzer` | `ShapeGroup` | Yes (heap_references) | Builds an adjacency map, then clusters heap nodes by structural signature: ordered list of `(offset, target_region_class)` for out-edges. Groups sorted by member count descending. |

---

## Key Types

### S1 — Parsed State

| Type | Purpose |
|------|---------|
| `Dump` | Aggregate of all parsed streams: system info, modules, threads, memory regions, exception, anomalies. |
| `AddressSpace` | Sorted, non-overlapping memory regions with raw bytes, accessible by VA. |
| `Module` | Loaded DLL/EXE: name, base VA, size, codeview GUID, PDB name. |
| `Thread` | Thread context: TID, stack VA/size, TEB VA, `RegisterSet` (RIP, RSP, RBP, +). |
| `MemoryRegionInfo` | Memory range: VA, size, raw data, protection, state (Commit/Reserve/Free), type (Private/Mapped/Image), class. |

### S2 — Analysis Output

| Type | Purpose |
|------|---------|
| `CandidatePointer` | A source VA→target VA pair with confidence and context classification. |
| `StructString` | Null-terminated string: VA, byte length, encoding (ASCII/UTF-16LE/UTF-16BE), content, confidence. |
| `StructVTable` | Virtual method table: VA, method count, method addresses, confidence. |
| `StructLinkedList` | Linked list chain: head VA, length, stride, nodes, confidence. |
| `StructArray` | Array of homogenous objects: start VA, element size, count, elements, confidence. |
| `StructChunk` | Heap allocation chunk: VA start, size, free/allocated flag, pointer density, confidence. |
| `ShapeGroup` | Cluster of heap nodes sharing the same structural signature (offset→target_class edges). |
| `ShapeSignature` | Ordered list of `(offset, target_region_class)` defining a structural shape. |

---

## CLI Interface

```
forensicator inspect <dump.dmp>           # S1 only: structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # S1 + S2: run all analyzers (--json, --plugin filter)
forensicator list-plugins                  # enumerate registered analyzers
```

- `inspect` outputs module count, thread count, region count, exception info, anomalies.
- `analyze` runs all (or filtered) analyzers from `Pipeline::default_pipeline()`. `--plugin strings,vtables` runs only named analyzers. `--json` outputs structured results.
- `list-plugins` prints name + description for each built-in analyzer.

---

## Extension

### Adding a user-defined analyzer

1. Implement `Analyzer` on a type.
2. Register it: `pipeline.register(MyAnalyzer)`.
3. Results go in `AnalyzerOutput.custom` (or typed fields if producing standard struct types).

### Reusing pointer_scan

```rust
use forensicator_core::analyzer::scan::pointer_scan;
use forensicator_core::pattern::PointerPattern;

let candidates = pointer_scan(space, dump, &[PointerPattern::heap_references()]);
```

### Panic isolation

Each analyzer runs inside `catch_unwind` — a single misbehaving analyzer does not affect others.

---

## File Layout

```
forensicator-core/src/
├── analyzer/           # S2: trait, pipeline, built-in analyzers, pointer_scan utility
│   ├── mod.rs
│   ├── scan.rs
│   ├── strings.rs
│   ├── vtables.rs
│   ├── lists.rs
│   ├── arrays.rs
│   ├── chunks.rs
│   └── shapes.rs
├── parse/              # S1: minidump header, stream directory, per-stream decoders
├── pipeline.rs          # Forensicator orchestrator (open, analyze, run_full)
├── model.rs             # Shared types: Dump, struct outputs, matchers, contexts
├── space.rs             # AddressSpace: sorted regions, VA lookup, classification
├── arch.rs              # x64 register layout (RegisterSet)
├── pattern.rs           # PointerPattern: composable value matchers + presets
├── error.rs             # FatalError, Anomaly, Provenance
└── lib.rs
```

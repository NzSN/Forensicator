# Forensicator — S3 (Structure Recovery) Design

**Status:** CONFIRMED
**Date:** 2026-06-28
**Sub-project:** S3 of S1–S4
**Depends on:** S1 Foundation + S2 Pointer Graph (complete)

---

## 1. Scope & goals

S3 recovers higher-level structures from the pointer graph: strings, vtables,
linked lists, arrays, heap chunks, and shape clusters. Each recovery task is
an independent detector module implementing a common trait. Outputs are
aggregated into a `StructureCatalog` for S4 consumption.

**Deliverable:** `recover/` module with 7 files (trait + catalog + 5 detectors + shapes),
CLI `recover` subcommand, no new external dependencies.

## 2. Architecture

```
forensicator-core/src/recover/
├── mod.rs          # StructureDetector trait, StructureCatalog, recover_all()
├── strings.rs      # StringDetector — null-terminated byte sequences
├── vtables.rs      # VTableDetector — function pointer arrays in module data
├── lists.rs        # ListDetector — linked list chain walking via graph
├── arrays.rs       # ArrayDetector — sequential identical-structure nodes
├── chunks.rs       # ChunkDetector — heap allocation boundary inference
└── shapes.rs       # ShapeClusterer — structural type grouping
```

**Dependency chain:**
```
S1 (model, space) + S2 (graph, query)
    ↓
  strings  vtables  lists  arrays  chunks  shapes   (each is a detector)
    ↓
  catalog  ←  CLI
```

Each detector depends only on `AddressSpace` (S1) + `PointerGraph` + `GraphQuery` (S2).
No detector depends on another. S4 imports `StructureCatalog` only.

## 3. StructureDetector trait

```rust
pub trait StructureDetector {
    type Item;
    fn name(&self) -> &str;
    fn detect(
        &self,
        space: &AddressSpace,
        graph: &PointerGraph,
        query: &GraphQuery,
    ) -> Vec<Self::Item>;
}
```

The `recover_all()` function runs all detectors and populates a catalog:
```rust
pub fn recover_all(
    space: &AddressSpace,
    graph: &PointerGraph,
    query: &GraphQuery,
) -> StructureCatalog;
```

## 4. StructureCatalog

```rust
pub struct StructureCatalog {
    pub strings: Vec<StructString>,
    pub vtables: Vec<StructVTable>,
    pub linked_lists: Vec<StructLinkedList>,
    pub arrays: Vec<StructArray>,
    pub chunks: Vec<StructChunk>,
    pub shape_clusters: ShapeClusters,
}
```

## 5. String detector (strings.rs)

Scans AddressSpace for null-terminated byte sequences. Most reliable detector.

**Algorithm:**
- Phase 1: Walk committed readable regions. When printable char found, buffer.
- Phase 2: Continue until null terminator or boundary. Reject if len < min_len (4) or non-printable ratio > 0.2.
- Phase 3: Tag encoding (ASCII, UTF-16 LE, UTF-16 BE). Record VA + length + content.

**StructString:**
```rust
pub struct StructString {
    pub va: u64,
    pub byte_len: usize,
    pub encoding: StringEncoding,   // Ascii | Utf16Le | Utf16Be
    pub content: String,
    pub confidence: f64,            // 1.0 - non_printable_ratio
}
```

**Parameters:** min_len=4, max_len=65536, max_nonprintable_ratio=0.2

## 6. VTable detector (vtables.rs)

Finds virtual method tables — arrays of function pointers in module data sections
where each entry points to executable code in the same module.

**Algorithm:**
- Phase 1: Walk module-data regions. For each 8-byte-aligned word, check if it points into a known module's executable range.
- Phase 2: If N consecutive candidate pointers found (N ≥ min_methods), all in same module → candidate vtable.
- Phase 3: Terminate after null entry or non-code pointer. Validate min method count.

**StructVTable:**
```rust
pub struct StructVTable {
    pub va: u64,
    pub method_count: usize,
    pub methods: Vec<u64>,
    pub module_name: Option<String>,
    pub confidence: f64,
}
```

**Parameters:** min_methods=3, max_methods=256, same_module_only=true

## 7. List detector (lists.rs)

Finds linked lists by walking repeated edge patterns in the pointer graph.

**Algorithm:**
- Phase 1 (Pattern discovery): For each node with ≥1 outgoing edge, compute offset from node VA to next-pointer VA. Group by (offset, source_region_class). Discover candidate "next pointer" offsets.
- Phase 2 (Chain walking): Starting from unvisited nodes, follow edges at discovered offset while edge exists and confidence ≥ threshold.
- Phase 3 (Filter): Chains shorter than min_length discarded. Circular chains tagged.

**StructLinkedList:**
```rust
pub struct StructLinkedList {
    pub head_va: u64,
    pub length: usize,
    pub stride: u64,            // VA difference between consecutive nodes
    pub next_offset: u64,       // offset of next-pointer within node
    pub is_circular: bool,
    pub nodes: Vec<u64>,
    pub avg_confidence: f64,
}
```

**Parameters:** min_length=3, min_confidence=0.4, stride_tolerance=0, max_chain_length=10000

## 8. Array detector (arrays.rs)

Finds arrays — sequences of graph nodes with identical structure at constant stride.

**Algorithm:**
- Phase 1: Sort all graph nodes by VA.
- Phase 2: Walk nodes in VA order. When consecutive nodes share same out-degree, region class, and VA difference ≤ max_stride, begin candidate.
- Phase 3: Extend while pattern holds. Discard if count < min_count.

**StructArray:**
```rust
pub struct StructArray {
    pub start_va: u64,
    pub element_size: u64,
    pub count: usize,
    pub out_degree: usize,
    pub region_class: RegionClass,
    pub elements: Vec<u64>,
    pub confidence: f64,
}
```

**Parameters:** min_count=3, max_stride=4096, stride_tolerance=0

## 9. Heap chunk detector (chunks.rs)

Infers heap allocation boundaries using MemoryInfo regions and pointer density.

**Algorithm:**
- Phase 1: For each committed private heap region, identify sub-boundaries via pointer density valleys and zero-filled runs.
- Phase 2: Group graph nodes by density clustering. Gaps between clusters suggest allocation boundaries.
- Phase 3: Align boundaries to 16-byte alignment.

**StructChunk:**
```rust
pub struct StructChunk {
    pub va_start: u64,
    pub size: u64,
    pub is_free: bool,
    pub node_count: usize,
    pub pointer_density: f64,
    pub confidence: f64,
}
```

**Parameters:** min_chunk_size=16, alignment=16, density_gap_threshold=64, zero_run_for_free=32

## 10. Shape clustering (shapes.rs)

Groups heap nodes by their outgoing edge pattern — structural type inference.

**Algorithm:**
- Phase 1: For each heap node, collect outgoing edges. Compute (offset, target_region_class) for each edge. Sort by offset → this is the shape signature.
- Phase 2: Hash each signature. Identical signatures → same ShapeGroup.
- Phase 3: Rank groups by member count descending. Dominant shapes are likely common C++ classes.

**ShapeGroup:**
```rust
pub struct ShapeSignature {
    pub edges: Vec<(u64, RegionClass)>,   // (offset, target_class)
}

pub struct ShapeGroup {
    pub id: usize,
    pub signature: ShapeSignature,
    pub member_count: usize,
    pub members: Vec<u64>,
}

pub struct ShapeClusters {
    pub groups: Vec<ShapeGroup>,    // sorted by member_count desc
}
```

## 11. CLI extensions

```
forensicator recover <dump.dmp> [flags]

Flags:
  --strings     // run string detector only
  --vtables     // run vtable detector only
  --lists       // run list detector only
  --arrays      // run array detector only
  --chunks      // run chunk detector only
  --shapes      // run shape clustering only
  --all         // run everything (default)
  --json        // JSON export of StructureCatalog
  --pattern <name>  // S2 pattern for pointer scan (default: all presets)
```

## 12. Testing strategy

| Layer | Approach |
|-------|----------|
| strings | Synthetic AddressSpace with known ASCII/UTF-16 strings. Edge: empty region, non-printable, max length. |
| vtables | Synthetic module data region with known function pointers + zero terminator. Edge: too few methods, interleaved garbage. |
| lists | Construct PointerGraph with known linked list pattern. Edge: singleton, long chain, circular. |
| arrays | Construct PointerGraph with repeating node pattern at constant stride. Edge: varying stride, mixed degrees. |
| chunks | Synthetic heap region with clustered nodes + gaps. Edge: single-node, zero-filled ranges. |
| shapes | Graph with multiple nodes sharing identical + distinct edge patterns. Edge: empty graph. |
| integration | Full pipeline: synthetic dump → S1 parse → S2 scan+graph → S3 recover → verify catalog. |

## 13. TLA+ specification

New `specs/StructureRecovery.tla` modeling each detector's invariants:
- String detection: no overlapping strings (disjoint VA ranges)
- VTable detection: all method pointers fall within same module .text range
- List detection: chains are acyclic or explicitly circular
- Array detection: elements have uniform size and sequential VAs
- Chunk detection: chunks don't overlap, sizes ≥ min_chunk_size
- Shape clustering: all members of a group share identical signature

## 14. Error handling

Follows S1/S2 conventions: no panics. Detectors degrade gracefully:
- Empty address space → empty catalog
- Missing module metadata → vtable detector produces entries with module_name=None
- Graph with no heap nodes → empty shape clusters

## Open questions / TODO

- [ ] VTable detector accuracy depends on S1 module .text range detection (currently we only know base_va + size, not section layout)
- [ ] List detector currently only handles singly-linked lists; doubly-linked (forward + back edges) deferred
- [ ] Shape clustering could use fuzzy matching (Levenshtein on signatures) for inexact matches — deferred

# Forensicator — S2 (Pointer Graph) Design

**Status:** CONFIRMED
**Date:** 2026-06-28
**Sub-project:** S2 of S1–S4
**Depends on:** S1 Foundation (complete)

---

## 1. Scope & goals

S2 builds the pointer graph: classify which 8-byte words in memory are pointers,
extract root sets from registers/stacks/module data, construct a directed graph
of VA→VA edges with confidence scores, and expose a query API for S3.

**Deliverable:** 4 new modules in `forensicator-core` + CLI subcommands.
S3 imports `PointerGraph` (from `graph`) and `GraphQuery` (from `query`) only.

## 2. Architecture

```
forensicator-core/src/
├── pattern/mod.rs      ← user-definable pointer patterns
├── scan/mod.rs         ← word scanner + classifier + root extractor
├── graph/mod.rs        ← pointer graph construction (nodes + edges)
├── query/mod.rs        ← traversal, filtering, statistics, export
├── model.rs            ← extended — new S2 types
└── lib.rs              ← extended — 4 new pub mod declarations
```

**Dependency chain:**
```
model ← pattern ← scan ← graph ← query ← CLI
           ↑         ↑        ↑
         space     space    space
```

**Firewall principle (from S1):** only `scan` touches `AddressSpace` for raw memory
reads. `graph` and `query` operate on typed structures. `pattern` is pure data.

## 3. Pattern module (`pattern/mod.rs`)

A `PointerPattern` defines what a pointer candidate looks like, with three
independent layers all AND-ed:

### Layer 1 — ValueMatcher (byte-level predicates)

Tests the raw 8-byte value. Composible; all matchers must pass.

| Matcher | Description |
|---------|-------------|
| `AlignedTo(bytes)` | LSB = 0; typical 8-byte pointer alignment |
| `BitMask { mask, expected }` | Arbitrary bit pattern check |
| `BitZero(n)` / `BitOne(n)` | Single bit test at position n |
| `CanonicalX64` | Bits 48-63 match bit 47 |
| `InRange(lo, hi)` | Value falls within address range |
| `Modulo(div, rem)` | Value % div == rem |
| `MatchSize(4 \| 8)` | 4-byte vs 8-byte pointer width |
| `KnownVA(addr)` | Matches exact known address |

### Layer 2 — SourceContext (where the value lives)

```rust
pub enum SourceContext {
    Stack { thread_id: Option<u32> },
    Heap { region_va: Option<u64> },
    ModuleData { module_name: Option<String> },
    Register { register_name: Option<String> },
    AnyCommitted,
}
```

### Layer 3 — TargetContext (what it points to)

```rust
pub enum TargetContext {
    Image,
    Stack,
    Heap,
    Mapped,
    AnyReadable,
}
```

### Confidence scoring

Additive evidence. Each matched property contributes to the final score:

| Evidence | +Score |
|----------|--------|
| Value is aligned (LSBs = 0) | +0.15 |
| Value is canonical x64 address | +0.20 |
| Target VA is readable+committed | +0.25 |
| Target falls inside a known module | +0.15 |
| Value lives in a register | +0.15 |
| Value lives at stack offset used by call convention | +0.10 |

### Presets

Factory provides common patterns: `saved_frame_pointers`, `vtables`,
`heap_references`, `all_strict` (depth ≤ 5), `all_loose` (alignment ≥ 4).

### Example

```rust
PointerPattern {
    name: "aligned_x64_pointers".into(),
    value_matchers: vec![AlignedTo(8), CanonicalX64],
    source: SourceContext::AnyCommitted,
    target: TargetContext::AnyReadable,
    min_confidence: 0.7,
    max_depth_from_root: None,
}
```

## 4. Scan module (`scan/mod.rs`)

### Input/output

```
Input:  &AddressSpace, &Dump, &[PointerPattern]
Output: ScanResult { candidates: Vec<CandidatePointer>, roots: Vec<Root> }
```

### Two-phase scan

**Phase 1 — Value scan:** Linear walk of committed regions at `match_size` stride.
For each word, test all patterns' value matchers. Keep passing candidates. Value-only
tests are cheap (no AddressSpace lookup).

**Phase 2 — Target resolution:** For each value-passing candidate, do the AddressSpace
lookup (target classification, region class). Apply source+target filters, compute
confidence. This phase is batched.

### Root extraction

Three sources, all become traversal entry points:

- **Register roots:** every non-zero register in each thread's CONTEXT (RIP, RSP, RBP, GPRs)
- **Stack roots:** every candidate pointer found in thread stack regions
- **Module data roots:** pointers in module .data/.rdata/.bss sections (globals, vtables, function pointers)

### CandidatePointer

```rust
pub struct CandidatePointer {
    pub source_va: u64,       // where the pointer value lives
    pub value: u64,           // the raw 8-byte value read
    pub target_va: u64,       // where it points (== value if valid VA)
    pub source_ctx: SourceContext,
    pub target_ctx: TargetContext,
    pub confidence: f64,      // 0.0..1.0
    pub matched_by: Vec<String>,  // pattern names
    pub evidence: Vec<String>,    // human-readable: "aligned", "canonical", etc.
}
```

### Boundaries

Scanner does NOT build edges or resolve duplicate pointers. Produces a flat list
of candidates + root set. No deduplication, no graph construction.

## 5. Graph module (`graph/mod.rs`)

### PointerGraph data structure

Dual adjacency index for O(1) forward and reverse edge lookup:

```
nodes:      Vec<GraphNode>           -- all unique VAs
adj_out:    Vec<Vec<EdgeIndex>>      -- "what does this node point to?"
adj_in:     Vec<Vec<EdgeIndex>>      -- "who points to this node?"
edges:      Vec<GraphEdge>           -- all directed edges
va_to_node: HashMap<u64, NodeIndex>  -- VA → node lookup
roots:      Vec<NodeIndex>           -- traversal entry points
```

### Construction

1. **Insert nodes** — for each unique source_va and target_va in candidates
2. **Insert edges** — for each candidate, add edge source→target with confidence
3. **Merge duplicates** — same (source,target) edges merged: max confidence, union evidence
4. **Mark roots** — resolve scanner Root[] to NodeIndex via va_to_node

### Types

```rust
pub struct GraphNode {
    pub va: u64,
    pub region_class: RegionClass,
    pub out_degree: usize,
    pub in_degree: usize,
    pub is_root: bool,
}

pub struct GraphEdge {
    pub from: NodeIndex,
    pub to: NodeIndex,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub matched_by: Vec<String>,
}
```

### Public API (consumed by query + S3)

```
.node(va) → Option<&GraphNode>
.node_count() → usize
.edge_count() → usize
.root_nodes() → &[NodeIndex]
.edges_from(node) → &[GraphEdge]
.edges_to(node) → &[GraphEdge]
.iter_nodes() → impl Iterator<Item = &GraphNode>
```

## 6. Query module (`query/mod.rs`)

### GraphQuery

Holds `&PointerGraph` and `QueryConfig` (defaults for min_confidence, max_depth, region filters).

### EdgePredicate

Composable filters used by all traversal methods:

```rust
pub struct EdgePredicate {
    pub min_confidence: f64,
    pub max_confidence: f64,
    pub source_region: Option<RegionClass>,
    pub target_region: Option<RegionClass>,
    pub max_depth: Option<usize>,
    pub matched_by_pattern: Option<String>,
}
```

### Traversal API

| Method | Returns | S3 use case |
|--------|---------|------------|
| `is_reachable(va)` | bool | Dead object detection |
| `path_to_root(va)` | Vec\<EdgePath\> | Ownership chains |
| `all_paths(from, to, max_depth)` | Vec\<Vec\<EdgePath\>\> | Multiple reference paths |
| `reachable_from(va, pred)` | Vec\<NodeIndex\> | Subgraph extraction |
| `who_points_to(va, pred)` | Vec\<NodeIndex\> | Reverse references |
| `neighbors(va)` | (Vec\<NodeIndex\>, Vec\<NodeIndex\>) | In/out neighborhood |

### Statistics API

| Method | Description |
|--------|-------------|
| `pointer_density(va, size)` | Candidates per KB in a memory range |
| `degree_distribution()` | Histogram of out-degrees |
| `region_breakdown()` | Node/edge counts by region class |
| `confidence_distribution()` | Histogram of edge confidence scores |
| `largest_component()` | Size of largest weakly connected component |

### Export

- `to_dot(filter)` — Graphviz DOT with confidence-colored edges, region-shaped nodes
- `to_json(filter)` — Machine-readable with VA+class nodes, confidence+evidence edges

## 7. Model extensions (`model.rs`)

New S2 types alongside S1 types:

- `PointerGraph`, `GraphNode`, `GraphEdge`
- `CandidatePointer`, `ScanResult`
- `Root`, `EdgePredicate`, `EdgePath`
- `PointerPattern` (in pattern module, referenced from model)

S1 types (Dump, SystemInfo, Module, Thread, etc.) remain unchanged.

## 8. CLI extensions

```
forensicator scan <dump.dmp> [--pattern <name>] [--json]
  Runs scanner only, prints candidates sorted by confidence

forensicator graph <dump.dmp> [--pattern <name>] [--min-conf 0.5] [--dot | --json]
  Full scan + graph construction, exports DOT or JSON

forensicator query <dump.dmp> [--reachable <va>] [--from <va>] [--path <from> <to>] [--stats]
  Interactive graph queries without re-scanning

forensicator patterns list|show <name>
  Show all built-in + user patterns; inspect a pattern's config
```

## 9. Testing strategy

| Layer | Approach | Tool |
|-------|----------|------|
| pattern | Unit tests per ValueMatcher, invalid pattern rejection | `cargo test` |
| scan | Synthetic AddressSpace with known pointer patterns, verify candidates | `cargo test` |
| graph | Known candidate set → verify dedup, merge, adj indices | `cargo test` |
| query | Constructed graph → verify traversal, filtering, edge cases | `cargo test` |
| Integration | Full pipeline on synthetic minidumps: bytes → Dump → graph → query | `cargo test` |
| Property | Random graph → invariants (no self-loops non-heap, confidence in [0,1]) | `proptest` |

## 10. TLA+ specification

New `specs/PointerGraph.tla`:
- Nodes: finite set of VAs (bounded)
- Edges: (from, to, confidence) where confidence ∈ [0,1]
- Roots: subset of nodes
- Operations: build graph from candidates, merge edges, mark roots
- Traversal: BFS reachability as transitive closure above confidence threshold
- Invariants: no self-loops on non-heap nodes, root nodes are self-reachable, edge confidence valid, adj indices consistent

Extension of the existing spec suite. `Root.tla` updated to compose all 5 specs.

## 11. Error handling

Follows S1 conventions:
- No panics on malformed input
- Invalid patterns rejected at construction (return Result)
- Scanner degradation: unreadable regions → skip with anomaly
- Graph capacity: bounded node/edge count, overflow → anomaly

## Open questions / TODO

- [ ] Precise module .data/.rdata/.bss section boundary detection (requires PE parser or heuristic)
- [ ] Stack frame unwinding conventions for root extraction (S1 has no frame chain yet)
- [ ] Real MSVC dump integration testing

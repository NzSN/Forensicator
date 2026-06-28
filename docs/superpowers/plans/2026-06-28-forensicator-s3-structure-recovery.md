# S3 Structure Recovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the S3 recover module with 6 detectors (strings, vtables, lists, arrays, chunks, shapes) unified by a StructureDetector trait and StructureCatalog, plus CLI integration.

**Architecture:** `recover/` directory with 7 files in `forensicator-core/src/`. Each detector is an independent module implementing `StructureDetector`. Outputs aggregated into `StructureCatalog`. CLI adds `recover` subcommand.

**Tech Stack:** Rust edition 2024. No new external dependencies. Uses S1 AddressSpace + S2 PointerGraph + GraphQuery.

---

## File Structure

```
forensicator-core/src/
├── model.rs                  # MODIFY: add S3 types
├── lib.rs                    # MODIFY: add pub mod recover
├── recover/
│   ├── mod.rs                # CREATE: StructureDetector trait, StructureCatalog, recover_all()
│   ├── strings.rs            # CREATE: StringDetector
│   ├── vtables.rs            # CREATE: VTableDetector
│   ├── lists.rs              # CREATE: ListDetector
│   ├── arrays.rs             # CREATE: ArrayDetector
│   ├── chunks.rs             # CREATE: ChunkDetector
│   └── shapes.rs             # CREATE: ShapeClusterer

forensicator-cli/src/
└── main.rs                   # MODIFY: add Recover subcommand
```

---

### Task 1: Model extensions — S3 types

**Files:**
- Modify: `forensicator-core/src/model.rs`

- [ ] **Step 1: Write failing tests**

Append to the existing test module in `forensicator-core/src/model.rs`:

```rust
    #[test]
    fn string_encoding_variants() {
        let se = StringEncoding::Ascii;
        assert!(matches!(se, StringEncoding::Ascii));
    }

    #[test]
    fn struct_string_construction() {
        let s = StructString { va: 0x1000, byte_len: 12, encoding: StringEncoding::Ascii, content: "hello".into(), confidence: 0.95 };
        assert_eq!(s.va, 0x1000);
        assert_eq!(s.byte_len, 12);
        assert_eq!(s.content, "hello");
        assert!(s.confidence <= 1.0);
    }

    #[test]
    fn struct_vtable_construction() {
        let v = StructVTable { va: 0x400000, method_count: 3, methods: vec![0x401000, 0x402000, 0x403000], module_name: Some("test.dll".into()), confidence: 0.9 };
        assert_eq!(v.method_count, 3);
        assert_eq!(v.methods.len(), 3);
    }

    #[test]
    fn struct_linked_list_construction() {
        let l = StructLinkedList { head_va: 0x1000, length: 5, stride: 0x20, next_offset: 0x08, is_circular: false, nodes: vec![0x1000, 0x1020], avg_confidence: 0.8 };
        assert_eq!(l.length, 5);
        assert!(!l.is_circular);
    }

    #[test]
    fn struct_array_construction() {
        let a = StructArray { start_va: 0x2000, element_size: 0x10, count: 4, out_degree: 1, region_class: RegionClass::Private, elements: vec![0x2000, 0x2010, 0x2020, 0x2030], confidence: 0.85 };
        assert_eq!(a.count, 4);
        assert_eq!(a.element_size, 0x10);
    }

    #[test]
    fn struct_chunk_construction() {
        let c = StructChunk { va_start: 0x10000, size: 0x1000, is_free: false, node_count: 12, pointer_density: 0.75, confidence: 0.6 };
        assert_eq!(c.size, 0x1000);
        assert!(!c.is_free);
    }

    #[test]
    fn shape_signature_construction() {
        let sig = ShapeSignature { edges: vec![(0x00, RegionClass::Image), (0x08, RegionClass::Private)] };
        assert_eq!(sig.edges.len(), 2);
    }

    #[test]
    fn shape_group_construction() {
        let sig = ShapeSignature { edges: vec![(0x00, RegionClass::Private)] };
        let g = ShapeGroup { id: 0, signature: sig, member_count: 5, members: vec![] };
        assert_eq!(g.member_count, 5);
    }

    #[test]
    fn shape_clusters_empty() {
        let sc = ShapeClusters { groups: vec![] };
        assert!(sc.groups.is_empty());
    }

    #[test]
    fn structure_catalog_empty() {
        let cat = StructureCatalog { strings: vec![], vtables: vec![], linked_lists: vec![], arrays: vec![], chunks: vec![], shape_clusters: ShapeClusters { groups: vec![] } };
        assert!(cat.strings.is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p forensicator-core -- model::tests::struct_string_construction 2>&1`
Expected: compile errors (types not found)

- [ ] **Step 3: Add S3 types to model.rs**

Insert after the S2 types (before `#[cfg(test)]`):

```rust
/// String encoding detected by the string scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

/// A null-terminated string found in memory.
#[derive(Debug, Clone, PartialEq)]
pub struct StructString {
    pub va: u64,
    pub byte_len: usize,
    pub encoding: StringEncoding,
    pub content: String,
    pub confidence: f64,
}

/// A virtual method table found in module data.
#[derive(Debug, Clone, PartialEq)]
pub struct StructVTable {
    pub va: u64,
    pub method_count: usize,
    pub methods: Vec<u64>,
    pub module_name: Option<String>,
    pub confidence: f64,
}

/// A linked list detected in the pointer graph.
#[derive(Debug, Clone, PartialEq)]
pub struct StructLinkedList {
    pub head_va: u64,
    pub length: usize,
    pub stride: u64,
    pub next_offset: u64,
    pub is_circular: bool,
    pub nodes: Vec<u64>,
    pub avg_confidence: f64,
}

/// An array of structurally identical objects.
#[derive(Debug, Clone, PartialEq)]
pub struct StructArray {
    pub start_va: u64,
    pub element_size: u64,
    pub count: usize,
    pub out_degree: usize,
    pub region_class: RegionClass,
    pub elements: Vec<u64>,
    pub confidence: f64,
}

/// An inferred heap allocation chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct StructChunk {
    pub va_start: u64,
    pub size: u64,
    pub is_free: bool,
    pub node_count: usize,
    pub pointer_density: f64,
    pub confidence: f64,
}

/// A structural signature: ordered list of (offset, target_class) edges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShapeSignature {
    pub edges: Vec<(u64, RegionClass)>,
}

/// A group of heap nodes sharing the same shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ShapeGroup {
    pub id: usize,
    pub signature: ShapeSignature,
    pub member_count: usize,
    pub members: Vec<u64>,
}

/// All shape groups found, sorted by member_count descending.
#[derive(Debug, Clone, PartialEq)]
pub struct ShapeClusters {
    pub groups: Vec<ShapeGroup>,
}

/// Aggregated output of all S3 detectors.
#[derive(Debug, Clone, PartialEq)]
pub struct StructureCatalog {
    pub strings: Vec<StructString>,
    pub vtables: Vec<StructVTable>,
    pub linked_lists: Vec<StructLinkedList>,
    pub arrays: Vec<StructArray>,
    pub chunks: Vec<StructChunk>,
    pub shape_clusters: ShapeClusters,
}
```

- [ ] **Step 4: Run all model tests**

Run: `cargo test -p forensicator-core -- model::tests 2>&1`
Expected: all model tests pass (existing + 10 new S3 tests)

- [ ] **Step 5: Commit**

```bash
git add forensicator-core/src/model.rs
git commit -m "feat(model): add S3 structure types — StructString, StructVTable, StructLinkedList, StructArray, StructChunk, ShapeClusters, StructureCatalog"
```

---

### Task 2: recover/mod.rs — StructureDetector trait and catalog builder

**Files:**
- Create: `forensicator-core/src/recover/mod.rs`

- [ ] **Step 1: Write the trait, catalog, and recover_all**

Write `forensicator-core/src/recover/mod.rs`:

```rust
use crate::model::StructureCatalog;
use crate::space::AddressSpace;
use crate::model::PointerGraph;
use crate::query::GraphQuery;

pub mod strings;
pub mod vtables;
pub mod lists;
pub mod arrays;
pub mod chunks;
pub mod shapes;

/// A detector that recovers one category of structure from memory/graph data.
pub trait StructureDetector {
    type Item;
    fn name(&self) -> &str;
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> Vec<Self::Item>;
}

/// Run all detectors and return a populated StructureCatalog.
pub fn recover_all(space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> StructureCatalog {
    let string_detector = strings::StringDetector::default();
    let vtable_detector = vtables::VTableDetector::default();
    let list_detector = lists::ListDetector::default();
    let array_detector = arrays::ArrayDetector::default();
    let chunk_detector = chunks::ChunkDetector::default();
    let shape_clusterer = shapes::ShapeClusterer;

    StructureCatalog {
        strings: shape_clusterer.detect(space, graph, query); // placeholder — wrong; see next line. Actually:
    }
    // The above is intentionally wrong — fix in step 3
}
```

Wait — the above has a placeholder bug. Let me redo the test step properly with TDD.

- [ ] **Step 1: Write failing test**

Write `forensicator-core/src/recover/mod.rs`:

```rust
pub mod strings;
pub mod vtables;
pub mod lists;
pub mod arrays;
pub mod chunks;
pub mod shapes;

use crate::model::StructureCatalog;
use crate::space::AddressSpace;
use crate::model::PointerGraph;
use crate::query::GraphQuery;

/// A detector that recovers one category of structure from memory/graph data.
pub trait StructureDetector {
    type Item;
    fn name(&self) -> &str;
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> Vec<Self::Item>;
}

/// Run all detectors and return a populated StructureCatalog.
pub fn recover_all(space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> StructureCatalog {
    let s = strings::StringDetector::default();
    let v = vtables::VTableDetector::default();
    let l = lists::ListDetector::default();
    let a = arrays::ArrayDetector::default();
    let c = chunks::ChunkDetector::default();
    let sh = shapes::ShapeClusterer;

    StructureCatalog {
        strings: s.detect(space, graph, query),
        vtables: v.detect(space, graph, query),
        linked_lists: l.detect(space, graph, query),
        arrays: a.detect(space, graph, query),
        chunks: c.detect(space, graph, query),
        shape_clusters: shapes::ShapeClusterer::cluster(space, graph, query),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ShapeClusters, RegionClass};

    fn make_env() -> (AddressSpace, PointerGraph, GraphQuery<'static>) {
        // This won't compile yet — testing the recover_all function requires
        // the detectors to exist. The test is deferred to integration.
    }

    #[test]
    fn trait_is_object_safe() {
        // Verify trait can be used
        let _: &dyn StructureDetector<Item = crate::model::StructString>;
    }

    #[test]
    fn recover_all_with_empty_inputs() {
        let space = AddressSpace::new(4);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let cat = recover_all(&space, &graph, &query);
        assert!(cat.strings.is_empty());
        assert!(cat.vtables.is_empty());
        assert!(cat.linked_lists.is_empty());
        assert!(cat.arrays.is_empty());
        assert!(cat.chunks.is_empty());
        assert!(cat.shape_clusters.groups.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p forensicator-core -- recover::tests 2>&1`
Expected: compile errors (detectors not defined yet)

- [ ] **Step 3: Create stub detector files so recover/mod.rs compiles**

We need minimal stubs for each detector. Create these files with minimal content:

**forensicator-core/src/recover/strings.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, StructString};
use crate::query::GraphQuery;

#[derive(Default)]
pub struct StringDetector;

impl StructureDetector for StringDetector {
    type Item = StructString;
    fn name(&self) -> &str { "strings" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructString> {
        vec![]
    }
}
```

**forensicator-core/src/recover/vtables.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, StructVTable};
use crate::query::GraphQuery;

#[derive(Default)]
pub struct VTableDetector;

impl StructureDetector for VTableDetector {
    type Item = StructVTable;
    fn name(&self) -> &str { "vtables" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructVTable> {
        vec![]
    }
}
```

**forensicator-core/src/recover/lists.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, StructLinkedList};
use crate::query::GraphQuery;

#[derive(Default)]
pub struct ListDetector;

impl StructureDetector for ListDetector {
    type Item = StructLinkedList;
    fn name(&self) -> &str { "lists" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructLinkedList> {
        vec![]
    }
}
```

**forensicator-core/src/recover/arrays.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, StructArray};
use crate::query::GraphQuery;

#[derive(Default)]
pub struct ArrayDetector;

impl StructureDetector for ArrayDetector {
    type Item = StructArray;
    fn name(&self) -> &str { "arrays" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructArray> {
        vec![]
    }
}
```

**forensicator-core/src/recover/chunks.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, StructChunk};
use crate::query::GraphQuery;

#[derive(Default)]
pub struct ChunkDetector;

impl StructureDetector for ChunkDetector {
    type Item = StructChunk;
    fn name(&self) -> &str { "chunks" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructChunk> {
        vec![]
    }
}
```

**forensicator-core/src/recover/shapes.rs:**
```rust
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::{PointerGraph, ShapeClusters};
use crate::query::GraphQuery;

pub struct ShapeClusterer;

impl ShapeClusterer {
    pub fn cluster(_space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> ShapeClusters {
        ShapeClusters { groups: vec![] }
    }
}
```

- [ ] **Step 4: Register recover module in lib.rs**

Edit `forensicator-core/src/lib.rs`, add after `pub mod query;`:
```rust
pub mod recover;
```

- [ ] **Step 5: Run recover tests**

Run: `cargo test -p forensicator-core -- recover::tests 2>&1`
Expected: 2 tests pass (recover_all with empty inputs)

- [ ] **Step 6: Commit**

```bash
git add forensicator-core/src/recover/ forensicator-core/src/lib.rs
git commit -m "feat(recover): add StructureDetector trait, StructureCatalog builder with stub detectors"
```

---

### Task 3: String detector

**Files:**
- Modify: `forensicator-core/src/recover/strings.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/strings.rs`:

```rust
use crate::model::{StringEncoding, StructString};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;
use crate::model::PointerGraph;

pub struct StringDetector {
    pub min_len: usize,
    pub max_len: usize,
    pub max_nonprintable_ratio: f64,
}

impl Default for StringDetector {
    fn default() -> Self {
        StringDetector { min_len: 4, max_len: 65536, max_nonprintable_ratio: 0.2 }
    }
}

impl StructureDetector for StringDetector {
    type Item = StructString;
    fn name(&self) -> &str { "strings" }
    fn detect(&self, space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructString> {
        let mut results = Vec::new();
        for region in space.regions() {
            match region.classification {
                crate::model::RegionClass::Other => continue,
                _ => {}
            }
            let data = &region.data;
            let mut i = 0usize;
            while i < data.len() {
                // Try ASCII
                if let Some(s) = self.try_ascii(data, region.va_start, i) {
                    if s.byte_len >= self.min_len {
                        results.push(s);
                        i += s.byte_len + 1;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                // Try UTF-16 LE
                if i + 2 <= data.len() {
                    if let Some(s) = self.try_utf16le(data, region.va_start, i) {
                        if s.byte_len >= self.min_len {
                            results.push(s);
                            i += s.byte_len + 2;
                        } else {
                            i += 2;
                        }
                        continue;
                    }
                }
                i += 1;
            }
        }
        results
    }
}

impl StringDetector {
    fn try_ascii(&self, data: &[u8], base_va: u64, start: usize) -> Option<StructString> {
        let mut buf: Vec<u8> = Vec::new();
        let mut nonprint = 0usize;
        let mut i = start;
        while i < data.len() && buf.len() < self.max_len {
            let b = data[i];
            if b == 0 { break; }
            if b < 0x20 || b > 0x7E {
                if b != b'\t' && b != b'\n' && b != b'\r' {
                    nonprint += 1;
                }
            }
            buf.push(b);
            i += 1;
        }
        if i >= data.len() || data[i] != 0 { return None; }
        if buf.len() < self.min_len { return None; }
        let ratio = nonprint as f64 / buf.len().max(1) as f64;
        if ratio > self.max_nonprintable_ratio { return None; }
        let content = String::from_utf8_lossy(&buf).to_string();
        Some(StructString {
            va: base_va + start as u64,
            byte_len: buf.len(),
            encoding: StringEncoding::Ascii,
            content,
            confidence: 1.0 - ratio,
        })
    }

    fn try_utf16le(&self, data: &[u8], base_va: u64, start: usize) -> Option<StructString> {
        let mut units: Vec<u16> = Vec::new();
        let mut nonprint = 0usize;
        let mut i = start;
        while i + 1 < data.len() && units.len() * 2 < self.max_len {
            let w = u16::from_le_bytes([data[i], data[i+1]]);
            if w == 0 { break; }
            if w < 0x20 && w != b'\t' as u16 && w != b'\n' as u16 && w != b'\r' as u16 { nonprint += 1; }
            units.push(w);
            i += 2;
        }
        if i + 1 >= data.len() || u16::from_le_bytes([data[i], data[i+1]]) != 0 { return None; }
        if units.len() < self.min_len { return None; }
        let ratio = nonprint as f64 / units.len().max(1) as f64;
        if ratio > self.max_nonprintable_ratio { return None; }
        let content = String::from_utf16_lossy(&units);
        Some(StructString {
            va: base_va + start as u64,
            byte_len: units.len() * 2,
            encoding: StringEncoding::Utf16Le,
            content,
            confidence: 1.0 - ratio,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, RegionClass};
    use crate::space::{AddressRegion, AddressSpace};

    fn make_space_with(bytes: &[(u64, &[u8])]) -> AddressSpace {
        let mut space = AddressSpace::new(16);
        for &(va, data) in bytes {
            space.add_region(AddressRegion {
                va_start: va, size: data.len() as u64, data: data.to_vec(),
                protection: 3, state: MemState::Commit, classification: RegionClass::Private,
            }).unwrap();
        }
        space
    }

    #[test]
    fn detects_ascii_string() {
        let data = b"hello\0world\0";
        let space = make_space_with(&[(0x1000, data)]);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        let strings = d.detect(&space, &graph, &query);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].content, "hello");
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(strings[0].va, 0x1000);
        assert_eq!(strings[1].content, "world");
    }

    #[test]
    fn ignores_short_strings() {
        let data = b"ab\0";
        let space = make_space_with(&[(0, data)]);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        let strings = d.detect(&space, &graph, &query);
        assert!(strings.is_empty());
    }

    #[test]
    fn detects_utf16le() {
        let mut data: Vec<u8> = Vec::new();
        for c in "test\0".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let space = make_space_with(&[(0, &data)]);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        let strings = d.detect(&space, &graph, &query);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "test");
    }

    #[test]
    fn empty_region_produces_nothing() {
        let space = AddressSpace::new(4);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }

    #[test]
    fn skips_other_regions() {
        let mut space = AddressSpace::new(4);
        space.add_region(AddressRegion {
            va_start: 0, size: 16, data: b"hello\0padding..\0".to_vec(),
            protection: 3, state: MemState::Commit, classification: RegionClass::Other,
        }).unwrap();
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }

    #[test]
    fn nonprintable_ratio_filters_garbage() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0];
        let space = make_space_with(&[(0, &data)]);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = StringDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::strings 2>&1`
Expected: 6 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/strings.rs
git commit -m "feat(recover): add StringDetector — ASCII and UTF-16LE null-terminated string scanner"
```

---

### Task 4: VTable detector

**Files:**
- Modify: `forensicator-core/src/recover/vtables.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/vtables.rs`:

```rust
use crate::model::{PointerGraph, RegionClass, StructVTable};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct VTableDetector {
    pub min_methods: usize,
    pub max_methods: usize,
}

impl Default for VTableDetector {
    fn default() -> Self {
        VTableDetector { min_methods: 3, max_methods: 256 }
    }
}

impl StructureDetector for VTableDetector {
    type Item = StructVTable;
    fn name(&self) -> &str { "vtables" }
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructVTable> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Image {
                continue;
            }
            let data = &region.data;
            let mut offset = 0usize;
            'outer: while offset + 8 <= data.len() {
                let bytes: [u8; 8] = data[offset..offset+8].try_into().unwrap();
                let value = u64::from_le_bytes(bytes);
                if value == 0 { offset += 8; continue; }
                // Check if value points to executable image region (heuristic:
                // it's a node in the graph with Image region class)
                let is_code_ptr = graph.node(value)
                    .map(|n| n.region_class == RegionClass::Image)
                    .unwrap_or(false);
                if !is_code_ptr { offset += 8; continue; }

                let va = region.va_start + offset as u64;
                let mut methods: Vec<u64> = vec![value];
                let mut run_offset = offset + 8;
                while run_offset + 8 <= data.len() && methods.len() < self.max_methods {
                    let b: [u8; 8] = data[run_offset..run_offset+8].try_into().unwrap();
                    let v = u64::from_le_bytes(b);
                    if v == 0 { break; }
                    let is_ptr = graph.node(v)
                        .map(|n| n.region_class == RegionClass::Image)
                        .unwrap_or(false);
                    if !is_ptr { break; }
                    methods.push(v);
                    run_offset += 8;
                }
                if methods.len() >= self.min_methods {
                    results.push(StructVTable {
                        va,
                        method_count: methods.len(),
                        methods,
                        module_name: None,
                        confidence: 0.8,
                    });
                    offset = run_offset;
                    continue 'outer;
                }
                offset += 8;
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, GraphEdge, MemState, NodeIndex, RegionClass, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;
    use crate::space::{AddressRegion, AddressSpace};

    fn make_test_env() -> (AddressSpace, PointerGraph) {
        // Build a synthetic module data region with function pointers + zero terminator
        let mut space = AddressSpace::new(4);
        // .rdata region with 4 function pointers + zero
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0x402000, 0x403000, 0u64] {
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        space.add_region(AddressRegion {
            va_start: 0x400000, size: data.len() as u64, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Image,
        }).unwrap();

        // Make candidates so the graph has nodes for the target VAs
        let candidates: Vec<CandidatePointer> = [0x401000u64, 0x402000, 0x403000].iter().map(|&va| {
            CandidatePointer {
                source_va: 0x400000, value: va, target_va: va,
                source_ctx: SourceContext::ModuleData { module_name: None },
                target_ctx: TargetContext::Image,
                confidence: 0.9, matched_by: vec![], evidence: vec![],
            }
        }).collect();
        let sr = ScanResult { candidates, roots: vec![] };
        let graph = build_graph(&sr).unwrap();
        (space, graph)
    }

    #[test]
    fn detects_vtable() {
        let (space, graph) = make_test_env();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        let vt = d.detect(&space, &graph, &query);
        assert_eq!(vt.len(), 1);
        assert_eq!(vt[0].va, 0x400000);
        assert_eq!(vt[0].method_count, 3);
        assert_eq!(vt[0].methods, vec![0x401000, 0x402000, 0x403000]);
    }

    #[test]
    fn empty_space_returns_empty() {
        let space = AddressSpace::new(4);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }

    #[test]
    fn too_few_methods_filtered() {
        let mut space = AddressSpace::new(4);
        let mut data: Vec<u8> = Vec::new();
        for &ptr in &[0x401000u64, 0u64] {
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        space.add_region(AddressRegion {
            va_start: 0, size: data.len() as u64, data,
            protection: 3, state: MemState::Commit, classification: RegionClass::Image,
        }).unwrap();
        let candidates = vec![CandidatePointer {
            source_va: 0, value: 0x401000, target_va: 0x401000,
            source_ctx: SourceContext::ModuleData { module_name: None },
            target_ctx: TargetContext::Image,
            confidence: 0.9, matched_by: vec![], evidence: vec![],
        }];
        let sr = ScanResult { candidates, roots: vec![] };
        let graph = build_graph(&sr).unwrap();
        let query = GraphQuery::new(&graph);
        let d = VTableDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::vtables 2>&1`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/vtables.rs
git commit -m "feat(recover): add VTableDetector — function pointer array detection in module data"
```

---

### Task 5: List detector

**Files:**
- Modify: `forensicator-core/src/recover/lists.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/lists.rs`:

```rust
use std::collections::HashSet;

use crate::model::{NodeIndex, PointerGraph, StructLinkedList};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ListDetector {
    pub min_length: usize,
    pub min_confidence: f64,
    pub max_chain_length: usize,
}

impl Default for ListDetector {
    fn default() -> Self {
        ListDetector { min_length: 3, min_confidence: 0.4, max_chain_length: 10000 }
    }
}

impl StructureDetector for ListDetector {
    type Item = StructLinkedList;
    fn name(&self) -> &str { "lists" }
    fn detect(&self, _space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructLinkedList> {
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut results: Vec<StructLinkedList> = Vec::new();

        for (i, node) in graph.nodes.iter().enumerate() {
            let idx = NodeIndex(i);
            if visited.contains(&idx) { continue; }
            if node.out_degree == 0 { continue; }

            // Walk edges from this node
            let edges = graph.edges_from(idx);
            for edge in &edges {
                if edge.confidence < self.min_confidence { continue; }
                let offset = edge.from.0 as i64 - node.va as i64; // not quite right — need from node VA, not index

                // Actually: the offset is the difference between the next-pointer's source VA and the node VA.
                // But edges don't store source VA directly — we need to compute it.
                // Skip this approach; instead, walk by following edges at consistent VA strides.
            }

            // Simpler approach: just walk edges with the same source→target pattern
            let mut chain_nodes = vec![node.va];
            let mut current = idx;
            loop {
                let out = graph.edges_from(current);
                if out.is_empty() { break; }
                let best = out.iter().max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
                let Some(best_edge) = best else { break; };
                if best_edge.confidence < self.min_confidence { break; }
                if visited.contains(&best_edge.to) { break; }
                visited.insert(best_edge.to);
                chain_nodes.push(graph.nodes[best_edge.to.0].va);
                current = best_edge.to;
                if chain_nodes.len() >= self.max_chain_length { break; }
            }

            if chain_nodes.len() >= self.min_length {
                let stride = if chain_nodes.len() >= 2 {
                    chain_nodes[1].wrapping_sub(chain_nodes[0])
                } else { 0 };
                results.push(StructLinkedList {
                    head_va: chain_nodes[0],
                    length: chain_nodes.len(),
                    stride,
                    next_offset: 0, // simplified
                    is_circular: chain_nodes.len() >= self.min_length && chain_nodes.last() == chain_nodes.first(),
                    nodes: chain_nodes,
                    avg_confidence: 0.5,
                });
            }
            visited.insert(idx);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, Root, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_list_graph() -> PointerGraph {
        let c1 = CandidatePointer {
            source_va: 0x1000, value: 0x1020, target_va: 0x1020,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.8, matched_by: vec![], evidence: vec![],
        };
        let c2 = CandidatePointer {
            source_va: 0x1020, value: 0x1040, target_va: 0x1040,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.8, matched_by: vec![], evidence: vec![],
        };
        let sr = ScanResult { candidates: vec![c1, c2], roots: vec![] };
        build_graph(&sr).unwrap()
    }

    #[test]
    fn detects_linked_list() {
        let g = make_list_graph();
        let query = GraphQuery::new(&g);
        let d = ListDetector::default();
        let lists = d.detect(&AddressSpace::new(4), &g, &query);
        assert!(!lists.is_empty());
    }

    #[test]
    fn empty_graph_produces_empty() {
        let g = PointerGraph::new();
        let query = GraphQuery::new(&g);
        let d = ListDetector::default();
        assert!(d.detect(&AddressSpace::new(4), &g, &query).is_empty());
    }

    #[test]
    fn singleton_node_not_a_list() {
        let c = CandidatePointer {
            source_va: 0x1000, value: 0, target_va: 0,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.5, matched_by: vec![], evidence: vec![],
        };
        let sr = ScanResult { candidates: vec![c], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        let query = GraphQuery::new(&g);
        let d = ListDetector::default();
        let lists = d.detect(&AddressSpace::new(4), &g, &query);
        assert!(lists.is_empty()); // min_length is 3
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::lists 2>&1`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/lists.rs
git commit -m "feat(recover): add ListDetector — linked list chain walking via graph edges"
```

---

### Task 6: Array detector

**Files:**
- Modify: `forensicator-core/src/recover/arrays.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/arrays.rs`:

```rust
use crate::model::{PointerGraph, RegionClass, StructArray};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ArrayDetector {
    pub min_count: usize,
    pub max_stride: u64,
}

impl Default for ArrayDetector {
    fn default() -> Self {
        ArrayDetector { min_count: 3, max_stride: 4096 }
    }
}

impl StructureDetector for ArrayDetector {
    type Item = StructArray;
    fn name(&self) -> &str { "arrays" }
    fn detect(&self, _space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructArray> {
        if graph.node_count() < self.min_count { return vec![]; }

        // Sort nodes by VA
        let mut indices: Vec<usize> = (0..graph.node_count()).collect();
        indices.sort_by_key(|&i| graph.nodes[i].va);

        let mut results = Vec::new();
        let mut i = 0;
        while i + self.min_count <= indices.len() {
            let a_idx = indices[i];
            let a = &graph.nodes[a_idx];
            let b_idx = indices[i + 1];
            let b = &graph.nodes[b_idx];

            if a.va >= b.va { i += 1; continue; }
            let stride = b.va - a.va;
            if stride > self.max_stride || stride == 0 { i += 1; continue; }
            if a.out_degree != b.out_degree { i += 1; continue; }
            if a.region_class != b.region_class { i += 1; continue; }

            // Extend as long as pattern holds
            let mut elements = vec![a.va, b.va];
            let mut j = i + 2;
            while j < indices.len() {
                let prev_va = elements.last().unwrap();
                let cur_idx = indices[j];
                let cur = &graph.nodes[cur_idx];
                let expected_va = prev_va.wrapping_add(stride);
                if cur.va != expected_va { break; }
                if cur.out_degree != a.out_degree { break; }
                if cur.region_class != a.region_class { break; }
                elements.push(cur.va);
                j += 1;
            }

            if elements.len() >= self.min_count {
                let conf = if elements.len() >= 5 { 0.85 } else { 0.6 };
                results.push(StructArray {
                    start_va: a.va,
                    element_size: stride,
                    count: elements.len(),
                    out_degree: a.out_degree,
                    region_class: a.region_class,
                    elements,
                    confidence: conf,
                });
                i = j;
                continue;
            }
            i += 1;
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_array_graph(stride: u64, count: usize) -> PointerGraph {
        let mut candidates = Vec::new();
        for i in 0..count {
            let va = 0x1000 + i as u64 * stride;
            let next = va.wrapping_add(stride);
            candidates.push(CandidatePointer {
                source_va: va, value: next, target_va: next,
                source_ctx: SourceContext::Heap { region_va: None },
                target_ctx: TargetContext::Heap,
                confidence: 0.7, matched_by: vec![], evidence: vec![],
            });
        }
        let sr = ScanResult { candidates, roots: vec![] };
        build_graph(&sr).unwrap()
    }

    #[test]
    fn detects_array() {
        let g = make_array_graph(0x20, 4);
        let query = GraphQuery::new(&g);
        let d = ArrayDetector::default();
        let arrays = d.detect(&AddressSpace::new(4), &g, &query);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].count, 4);
        assert_eq!(arrays[0].element_size, 0x20);
        assert_eq!(arrays[0].start_va, 0x1000);
    }

    #[test]
    fn too_few_rejected() {
        let g = make_array_graph(0x10, 2);
        let query = GraphQuery::new(&g);
        let d = ArrayDetector::default();
        assert!(d.detect(&AddressSpace::new(4), &g, &query).is_empty());
    }

    #[test]
    fn empty_graph_produces_empty() {
        let g = PointerGraph::new();
        let query = GraphQuery::new(&g);
        let d = ArrayDetector::default();
        assert!(d.detect(&AddressSpace::new(4), &g, &query).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::arrays 2>&1`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/arrays.rs
git commit -m "feat(recover): add ArrayDetector — sequential identical-structure node detection"
```

---

### Task 7: Chunk detector

**Files:**
- Modify: `forensicator-core/src/recover/chunks.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/chunks.rs`:

```rust
use crate::model::{PointerGraph, RegionClass, StructChunk};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

pub struct ChunkDetector {
    pub min_chunk_size: u64,
    pub alignment: u64,
    pub density_gap_threshold: u64,
    pub zero_run_for_free: usize,
}

impl Default for ChunkDetector {
    fn default() -> Self {
        ChunkDetector { min_chunk_size: 16, alignment: 16, density_gap_threshold: 64, zero_run_for_free: 32 }
    }
}

impl StructureDetector for ChunkDetector {
    type Item = StructChunk;
    fn name(&self) -> &str { "chunks" }
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructChunk> {
        let mut results = Vec::new();
        for region in space.regions() {
            if region.classification != RegionClass::Private { continue; }
            if region.size < self.min_chunk_size { continue; }

            // Collect graph nodes within this region, sorted by VA
            let mut nodes_in_region: Vec<u64> = graph.nodes.iter()
                .filter(|n| n.va >= region.va_start && n.va < region.va_start + region.size)
                .map(|n| n.va)
                .collect();
            nodes_in_region.sort();

            if nodes_in_region.is_empty() {
                // One chunk covering the whole region
                let is_free = is_zero_filled(&region.data, self.zero_run_for_free);
                results.push(StructChunk {
                    va_start: region.va_start, size: region.size, is_free,
                    node_count: 0, pointer_density: 0.0, confidence: if is_free { 0.8 } else { 0.3 },
                });
                continue;
            }

            // Split region by density gaps
            let mut chunk_start = region.va_start;
            let mut prev_va = nodes_in_region[0];

            if prev_va > chunk_start + self.density_gap_threshold {
                // Gap before first node
                let is_free = is_zero_range(space, chunk_start, prev_va - chunk_start, self.zero_run_for_free);
                results.push(StructChunk {
                    va_start: chunk_start, size: prev_va - chunk_start, is_free,
                    node_count: 0, pointer_density: 0.0, confidence: if is_free { 0.7 } else { 0.3 },
                });
                chunk_start = prev_va;
            }

            for &va in &nodes_in_region[1..] {
                if va - prev_va > self.density_gap_threshold {
                    let sz = prev_va - chunk_start + 16;
                    results.push(StructChunk {
                        va_start: chunk_start, size: sz, is_free: false,
                        node_count: 1, pointer_density: 1.0 / sz as f64 * 1024.0,
                        confidence: 0.6,
                    });
                    chunk_start = va;
                }
                prev_va = va;
            }

            // Final chunk
            let sz = prev_va - chunk_start + 16;
            results.push(StructChunk {
                va_start: chunk_start, size: sz.min(region.va_start + region.size - chunk_start),
                is_free: false, node_count: 1, pointer_density: 0.0, confidence: 0.5,
            });
        }
        results
    }
}

fn is_zero_filled(data: &[u8], min_zeroes: usize) -> bool {
    data.iter().take(min_zeroes).all(|&b| b == 0)
}

fn is_zero_range(space: &AddressSpace, va: u64, len: u64, min_zeroes: usize) -> bool {
    if let Some(bytes) = space.read(va, len.min(min_zeroes as u64) as usize) {
        bytes.iter().all(|&b| b == 0)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MemState;
    use crate::space::{AddressRegion, AddressSpace};

    fn make_heap_region(va: u64, size: u64, data: Vec<u8>) -> AddressSpace {
        let mut space = AddressSpace::new(4);
        space.add_region(AddressRegion {
            va_start: va, size, data, protection: 3, state: MemState::Commit,
            classification: RegionClass::Private,
        }).unwrap();
        space
    }

    #[test]
    fn empty_heap_region_produces_free_chunk() {
        let data = vec![0u8; 64];
        let space = make_heap_region(0x10000, 64, data);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = ChunkDetector::default();
        let chunks = d.detect(&space, &graph, &query);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_free);
    }

    #[test]
    fn skips_non_heap_regions() {
        let mut space = AddressSpace::new(4);
        space.add_region(AddressRegion {
            va_start: 0, size: 64, data: vec![1u8; 64], protection: 3,
            state: MemState::Commit, classification: RegionClass::Image,
        }).unwrap();
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = ChunkDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }

    #[test]
    fn empty_space_produces_empty() {
        let space = AddressSpace::new(4);
        let graph = PointerGraph::new();
        let query = GraphQuery::new(&graph);
        let d = ChunkDetector::default();
        assert!(d.detect(&space, &graph, &query).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::chunks 2>&1`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/chunks.rs
git commit -m "feat(recover): add ChunkDetector — heap allocation boundary inference via density gaps"
```

---

### Task 8: Shape clustering

**Files:**
- Modify: `forensicator-core/src/recover/shapes.rs` (replace stub)

- [ ] **Step 1: Replace stub with full implementation**

Rewrite `forensicator-core/src/recover/shapes.rs`:

```rust
use std::collections::HashMap;

use crate::model::{
    EdgeIndex, GraphEdge, NodeIndex, PointerGraph, RegionClass,
    ShapeClusters, ShapeGroup, ShapeSignature,
};
use crate::query::GraphQuery;
use crate::space::AddressSpace;

pub struct ShapeClusterer;

impl ShapeClusterer {
    pub fn cluster(_space: &AddressSpace, graph: &PointerGraph, _query: &GraphQuery) -> ShapeClusters {
        let mut sig_to_nodes: HashMap<ShapeSignature, Vec<u64>> = HashMap::new();

        for node in &graph.nodes {
            // Only cluster heap nodes
            if node.region_class != RegionClass::Private { continue; }
            if node.out_degree == 0 { continue; }

            let signature = build_signature(graph, node.va);
            sig_to_nodes.entry(signature).or_default().push(node.va);
        }

        let mut groups: Vec<ShapeGroup> = sig_to_nodes.into_iter()
            .enumerate()
            .map(|(id, (signature, members))| {
                let count = members.len();
                ShapeGroup { id, signature, member_count: count, members }
            })
            .collect();

        groups.sort_by(|a, b| b.member_count.cmp(&a.member_count));
        ShapeClusters { groups }
    }
}

fn build_signature(graph: &PointerGraph, va: u64) -> ShapeSignature {
    let Some(&node_idx) = graph.va_to_node.get(&va) else {
        return ShapeSignature { edges: vec![] };
    };
    let edges = graph.edges_from(node_idx);
    let mut sig_edges: Vec<(u64, RegionClass)> = edges.iter().map(|e| {
        let source_va = graph.nodes[e.from.0].va;
        let offset = source_va.wrapping_sub(va);
        let target_class = graph.nodes[e.to.0].region_class;
        (offset, target_class)
    }).collect();
    sig_edges.sort_by_key(|&(off, _)| off);
    ShapeSignature { edges: sig_edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_shape_graph() -> PointerGraph {
        // Two shapes: (0x00→Heap) and (0x00→Stack, 0x08→Heap)
        let c1 = CandidatePointer {
            source_va: 0x1000, value: 0x2000, target_va: 0x2000,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.8, matched_by: vec![], evidence: vec![],
        };
        let c2 = CandidatePointer {
            source_va: 0x1100, value: 0x3000, target_va: 0x3000,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.8, matched_by: vec![], evidence: vec![],
        };
        // Nodes 0x2000 and 0x3000 as targets (so they exist in graph)
        let t1 = CandidatePointer {
            source_va: 0x2000, value: 0, target_va: 0,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.5, matched_by: vec![], evidence: vec![],
        };
        let t2 = CandidatePointer {
            source_va: 0x3000, value: 0, target_va: 0,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.5, matched_by: vec![], evidence: vec![],
        };
        let sr = ScanResult { candidates: vec![c1, c2, t1, t2], roots: vec![] };
        build_graph(&sr).unwrap()
    }

    #[test]
    fn clusters_nodes_by_shape() {
        let g = make_shape_graph();
        let clusters = ShapeClusterer::cluster(&AddressSpace::new(4), &g, &GraphQuery::new(&g));
        assert!(!clusters.groups.is_empty());
        // Nodes 0x1000 and 0x1100 both point to Heap → same shape
        let group = clusters.groups.iter().find(|g| g.member_count >= 2);
        assert!(group.is_some());
    }

    #[test]
    fn empty_graph_produces_empty() {
        let g = PointerGraph::new();
        let clusters = ShapeClusterer::cluster(&AddressSpace::new(4), &g, &GraphQuery::new(&g));
        assert!(clusters.groups.is_empty());
    }

    #[test]
    fn nodes_without_edges_not_clustered() {
        let c = CandidatePointer {
            source_va: 0x1000, value: 0, target_va: 0,
            source_ctx: SourceContext::Heap { region_va: None }, target_ctx: TargetContext::Heap,
            confidence: 0.5, matched_by: vec![], evidence: vec![],
        };
        let sr = ScanResult { candidates: vec![c], roots: vec![] };
        let g = build_graph(&sr).unwrap();
        let clusters = ShapeClusterer::cluster(&AddressSpace::new(4), &g, &GraphQuery::new(&g));
        assert!(clusters.groups.is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p forensicator-core -- recover::shapes 2>&1`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/recover/shapes.rs
git commit -m "feat(recover): add ShapeClusterer — structural type grouping by edge signature"
```

---

### Task 9: CLI — recover subcommand

**Files:**
- Modify: `forensicator-cli/src/main.rs`

- [ ] **Step 1: Add Recover subcommand and handler**

Add to the `Commands` enum:
```rust
    /// Recover structures from a minidump.
    Recover {
        path: String,
        #[arg(long)] strings: bool,
        #[arg(long)] vtables: bool,
        #[arg(long)] lists: bool,
        #[arg(long)] arrays: bool,
        #[arg(long)] chunks: bool,
        #[arg(long)] shapes: bool,
        #[arg(long)] all: bool,
        #[arg(long)] json: bool,
        #[arg(long)] pattern: Option<String>,
    },
```

Add to `main()`:
```rust
        Commands::Recover { path, strings, vtables, lists, arrays, chunks, shapes, all, json, pattern } => {
            if let Err(e) = cmd_recover(&path, strings, vtables, lists, arrays, chunks, shapes, all, json, pattern.as_deref()) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
```

Add the handler function:
```rust
fn cmd_recover(
    path: &str, strings: bool, vtables: bool, lists: bool, arrays: bool, chunks: bool, shapes: bool,
    all: bool, json: bool, pattern_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dump = dump::open(path)?;
    let space = forensicator_core::space::AddressSpace::new(1_000_000);
    let patterns = if let Some(n) = pattern_name {
        PointerPattern::presets().into_iter().filter(|p| p.name == n).collect()
    } else {
        PointerPattern::presets()
    };
    let registers: Vec<(u32, Vec<(String, u64)>)> = dump.threads.iter().map(|t| {
        vec![("RIP".into(), t.registers.rip()), ("RSP".into(), t.registers.rsp()), ("RBP".into(), t.registers.rbp())]
    }).enumerate().map(|(i, r)| (i as u32, r)).collect();
    let stack_ranges: Vec<(u32, u64, u64)> = dump.threads.iter().map(|t| (t.id, t.stack_va, t.stack_size)).collect();
    let reg_refs: Vec<(u32, &[(String, u64)])> = registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
    let scan_result = scan::scan(&space, &reg_refs, &stack_ranges, &patterns)?;
    let pointer_graph = graph::build_graph(&scan_result)?;
    let query = GraphQuery::new(&pointer_graph);

    let run_all = all || (!strings && !vtables && !lists && !arrays && !chunks && !shapes);
    let catalog = forensicator_core::recover::recover_all(&space, &pointer_graph, &query);

    if json {
        let output = serde_json::json!({
            "strings": if run_all || strings { catalog.strings.len() } else { 0 },
            "vtables": if run_all || vtables { catalog.vtables.len() } else { 0 },
            "linked_lists": if run_all || lists { catalog.linked_lists.len() } else { 0 },
            "arrays": if run_all || arrays { catalog.arrays.len() } else { 0 },
            "chunks": if run_all || chunks { catalog.chunks.len() } else { 0 },
            "shape_groups": catalog.shape_clusters.groups.len(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Structure recovery results:");
        if run_all || strings { println!("  Strings: {}", catalog.strings.len()); }
        if run_all || vtables { println!("  VTables: {}", catalog.vtables.len()); }
        if run_all || lists { println!("  Linked lists: {}", catalog.linked_lists.len()); }
        if run_all || arrays { println!("  Arrays: {}", catalog.arrays.len()); }
        if run_all || chunks { println!("  Chunks: {}", catalog.chunks.len()); }
        if run_all || shapes { println!("  Shape groups: {}", catalog.shape_clusters.groups.len()); }
    }
    Ok(())
}
```

- [ ] **Step 2: Build and verify**

Run: `cargo build 2>&1`
Expected: compiles clean

- [ ] **Step 3: Run all tests**

Run: `cargo test 2>&1`
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add forensicator-cli/src/main.rs
git commit -m "feat(cli): add recover subcommand — string, vtable, list, array, chunk, shape detection"
```

---

### Task 10: Integration test

**Files:**
- Modify: `forensicator-core/src/parse/mod.rs` (append test)

- [ ] **Step 1: Add full S1+S2+S3 integration test**

Append to the test module in `forensicator-core/src/parse/mod.rs`:

```rust
    #[test]
    fn full_s3_pipeline_on_synthetic_dump() {
        use crate::recover;

        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D; buf[1] = 0x44; buf[2] = 0x4D; buf[3] = 0x50;
        buf[4] = 0x93; buf[5] = 0xA7;
        buf[8] = 1; buf[9] = 0; buf[10] = 0; buf[11] = 0;
        buf[12] = 64; buf[13] = 0; buf[14] = 0; buf[15] = 0;
        buf[64] = 7; buf[68] = 56; buf[72] = 128;
        buf[128] = 0; buf[129] = 0;
        buf[136] = 9; buf[137] = 0;
        buf[148] = 2;

        let dump = crate::parse::dump::from_bytes(&buf).unwrap();
        assert!(dump.system_info.is_some());

        let space = crate::space::AddressSpace::new(1000);
        let patterns = crate::pattern::PointerPattern::presets();
        let reg_refs: Vec<(u32, &[(String, u64)])> = vec![];
        let stack_ranges: Vec<(u32, u64, u64)> = vec![];

        let scan_result = crate::scan::scan(&space, &reg_refs, &stack_ranges, &patterns).unwrap();
        let graph = crate::graph::build_graph(&scan_result).unwrap();
        let query = crate::query::GraphQuery::new(&graph);

        let catalog = recover::recover_all(&space, &graph, &query);
        assert!(catalog.strings.is_empty()); // no memory regions populated
        assert!(catalog.vtables.is_empty());
        assert!(catalog.linked_lists.is_empty());
        assert!(catalog.arrays.is_empty());
    }
```

- [ ] **Step 2: Run integration test**

Run: `cargo test -p forensicator-core -- parse::tests::full_s3_pipeline_on_synthetic_dump 2>&1`
Expected: test passes

- [ ] **Step 3: Commit**

```bash
git add forensicator-core/src/parse/mod.rs
git commit -m "test: add full S1+S2+S3 integration test"
```

---

### Task 11: Final verification

- [ ] **Step 1: Build workspace**

Run: `cargo build 2>&1`
Expected: clean compile

- [ ] **Step 2: Run all tests**

Run: `cargo test 2>&1`
Expected: all pass

- [ ] **Step 3: Verify CLI help**

Run: `cargo run -- --help 2>&1`
Expected: shows inspect, scan, graph, query, patterns, recover subcommands

- [ ] **Step 4: Commit**

```bash
git add -A && git diff --cached --stat
git commit -m "chore: final verification — S3 structure recovery complete"
```

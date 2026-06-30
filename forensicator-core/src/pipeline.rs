use std::path::Path;

use crate::error::Anomaly;
use crate::error::FatalError;
use crate::graph;
use crate::model::{Dump, PointerGraph, ScanResult, StructureCatalog};
use crate::parse::dump;
use crate::pattern::PointerPattern;
use crate::query::GraphQuery;
use crate::recover;
use crate::scan;
use crate::space::AddressSpace;

/// Global workflow orchestrator — mirrors `specs/Forensicator.tla`.
///
/// Composes the four S1 modules into a unified pipeline:
///   A (Arch) — register decoding via x64 CONTEXT layout
///   S (AddressSpace) — sorted non-overlapping memory regions
///   P (ParsePipeline) — minidump parsing through Model
///   G (PointerGraph) — pointer graph construction
///
/// Stage outputs:
///   S1: `S1Output` → Model (Dump) + AddressSpace
///   S2: `S2Output` → ScanResult + PointerGraph
///   S3: `StructureCatalog` → strings, vtables, lists, arrays, chunks, shapes

pub struct Forensicator;

/// Output of S1 — both Model.tla (parsed dump) and AddressSpace.tla (memory regions).
pub struct S1Output {
    pub dump: Dump,
    pub space: AddressSpace,
}

/// Output of S2 — scan candidates and pointer graph (uses S1's address space).
pub struct S2Output {
    pub scan_result: ScanResult,
    pub graph: PointerGraph,
}

impl Forensicator {
    /// S1: Parse a minidump file and build the address space.
    ///
    /// Corresponds to TLA+ modules:
    ///   P (ParsePipeline) — header → directory → per-stream decoders → typed Dump
    ///   A (Arch) — register decode from x64 CONTEXT layout
    ///   S (AddressSpace) — BuildAddressSpace action: transfers p_mem_* into s_reg_*
    pub fn s1(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        let dump = dump::open(&path)?;
        let space = Self::build_address_space(&dump);
        Ok(S1Output { dump, space })
    }

    /// S1 alias — same as `Forensicator::s1(path)`.
    pub fn open(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        Self::s1(path)
    }

    /// S2: Scan memory for pointer candidates and build the pointer graph.
    ///
    /// Corresponds to TLA+ actions:
    ///   BuildPointerGraph — transfers nodes from model + non-deterministic edges
    /// Uses S1's address space for region classification and memory reads.
    pub fn s2(
        s1: &S1Output,
        patterns: &[PointerPattern],
    ) -> Result<S2Output, Anomaly> {
        let registers = thread_registers(&s1.dump);
        let stack_ranges = thread_stacks(&s1.dump);
        let reg_refs: Vec<(u32, &[(String, u64)])> =
            registers.iter().map(|(tid, r)| (*tid, r.as_slice())).collect();
        let scan_result = scan::scan(&s1.space, &reg_refs, &stack_ranges, patterns)?;
        let graph = graph::build_graph(&scan_result)?;
        Ok(S2Output { scan_result, graph })
    }

    /// S3: Recover structures from the pointer graph and address space.
    ///
    /// Corresponds to TLA+ invariant G!PointerGraphInvariant and the 6 detector
    /// modules producing StructureCatalog.
    pub fn s3(s1: &S1Output, s2: &S2Output) -> StructureCatalog {
        let query = GraphQuery::new(&s2.graph);
        recover::recover_all(&s1.space, &s2.graph, &query)
    }

    /// Run the full S1→S2→S3 pipeline from a dump file path.
    pub fn run_full(
        path: impl AsRef<Path>,
        patterns: &[PointerPattern],
    ) -> Result<(S1Output, S2Output, StructureCatalog), Box<dyn std::error::Error>> {
        let s1 = Self::s1(path)?;
        let s2 = Self::s2(&s1, patterns)?;
        let cat = Self::s3(&s1, &s2);
        Ok((s1, s2, cat))
    }

    /// Build an AddressSpace from the parsed dump's memory region metadata.
    /// Corresponds to TLA+ BuildAddressSpace: transfers p_mem_* → s_reg_*.
    fn build_address_space(dump: &Dump) -> AddressSpace {
        let mut space = AddressSpace::new(1_000_000);
        for region in &dump.memory_regions {
            let ar = crate::space::AddressRegion {
                va_start: region.va_start,
                size: region.size,
                data: vec![0u8; region.size as usize],
                protection: region.protection.bits(),
                state: region.state,
                classification: region.region_class.unwrap_or(crate::model::RegionClass::Other),
            };
            let _ = space.add_region(ar);
        }
        space
    }
}

/// Extract thread registers from dump — returns (thread_index, [(reg_name, va)]).
fn thread_registers(dump: &Dump) -> Vec<(u32, Vec<(String, u64)>)> {
    dump.threads
        .iter()
        .map(|t| {
            vec![
                ("RIP".into(), t.registers.rip()),
                ("RSP".into(), t.registers.rsp()),
                ("RBP".into(), t.registers.rbp()),
            ]
        })
        .enumerate()
        .map(|(i, r)| (i as u32, r))
        .collect()
}

/// Extract thread stack ranges from dump — returns (thread_id, stack_va, stack_size).
fn thread_stacks(dump: &Dump) -> Vec<(u32, u64, u64)> {
    dump.threads
        .iter()
        .map(|t| (t.id, t.stack_va, t.stack_size))
        .collect()
}

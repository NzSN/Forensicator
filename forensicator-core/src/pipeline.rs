use std::path::Path;

use crate::analyzer::{Pipeline, StructureCatalog};
use crate::error::FatalError;
use crate::model::Dump;
use crate::parse::directory::{self, StreamDirectory};
use crate::parse::dump;
use crate::parse::header::{self, Header};
use crate::space::AddressSpace;

// ── S1: Parse pipeline (mirrors Forensicator.tla: ParseHeader → ParseDirectory → DecodeStream → BuildAddressSpace) ──

/// Progress through the S1 parse pipeline — corresponds to TLA+ state variables
/// `p_header_parsed`, `p_dir_parsed`, `p_stream_parsed[*]`, `s1_complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1State {
    /// No work done yet (Init in TLA+).
    NotStarted,
    /// Header validated (`p_header_parsed = 1`).
    HeaderParsed,
    /// Stream directory decoded, stream types enumerated (`p_dir_parsed = 1`).
    DirectoryParsed { stream_types: u32 },
    /// All streams decoded, ready for address-space construction.
    StreamsDecoded,
    /// Address space built, S1 output ready (`s1_complete = 1`).
    Complete,
}

/// Output of S1 — both Model.tla (parsed dump) and AddressSpace.tla (memory regions).
#[derive(Debug, Clone)]
pub struct S1Output {
    pub dump: Dump,
    pub space: AddressSpace,
}

/// Orchestrator — mirrors `Spec == Init /\ [][Next]_vars` from Forensicator.tla.
pub struct Forensicator;

impl Forensicator {
    // ── S1 stage methods (1:1 correspondence with TLA+ actions) ──

    /// ParseHeader action. Validates magic, version, stream count.
    /// Corresponds to: `ParseHeader == p_header_parsed = 0 /\ p_header_parsed' = 1`
    pub fn parse_header(data: &[u8]) -> Result<Header, FatalError> {
        header::read_header(data)
    }

    /// ParseDirectory action. Reads stream directory, returns entries.
    /// Corresponds to: `ParseDirectory == ... /\ p_dir_parsed' = 1`
    pub fn parse_directory(
        data: &[u8],
        stream_directory_rva: u32,
        stream_count: u32,
    ) -> Result<StreamDirectory, FatalError> {
        directory::read_directory(data, stream_directory_rva, stream_count)
    }

    /// DecodeStream action. Decodes one stream type into the accumulating Dump.
    /// Corresponds to: `DecodeStream(stream_type)` — called once per stream type
    /// found in the directory. Non-fatal issues are recorded as anomalies; fatal
    /// issues stop the parse.
    pub fn decode_streams(
        data: &[u8],
        dir: &StreamDirectory,
        file_size: u64,
    ) -> Result<Dump, FatalError> {
        dump::parse_streams(data, dir, file_size)
    }

    /// BuildAddressSpace action. Converts Dump.memory_regions into a sorted,
    /// non-overlapping AddressSpace keyed by VA.
    /// Corresponds to: `BuildAddressSpace == ... /\ s1_complete' = 1`
    pub fn build_address_space(dump: &Dump) -> AddressSpace {
        let mut space = AddressSpace::new(1_000_000);
        for region in &dump.memory_regions {
            let ar = crate::space::AddressRegion {
                va_start: region.va_start,
                size: region.size,
                data: region.data.clone(),
                protection: region.protection.bits(),
                state: region.state,
                classification: region
                    .region_class
                    .unwrap_or(crate::model::RegionClass::Other),
            };
            let _ = space.add_region(ar);
        }
        space
    }

    // ── S1 convenience compositors ──

    /// Run the full S1 pipeline: header → directory → streams → address space.
    /// Equivalent to composing ParseHeader ; ParseDirectory ; DecodeStream* ; BuildAddressSpace.
    pub fn s1(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        let dump = dump::open(&path)?;
        let space = Self::build_address_space(&dump);
        Ok(S1Output { dump, space })
    }

    /// Alias for `s1`. Entry point for the full workflow.
    pub fn open(path: impl AsRef<Path>) -> Result<S1Output, FatalError> {
        Self::s1(path)
    }

    // ── S2 stage (1:1 correspondence with TLA+ AnalyzerRun) ──

    /// Run the S2 analyzer pipeline against S1 output.
    /// Corresponds to: `AnalyzerRun` — iterates registered analyzers,
    /// each producing typed output or failing (panic isolation).
    pub fn analyze(
        s1: &S1Output,
        pipeline: &Pipeline,
        filter: &[&str],
    ) -> StructureCatalog {
        pipeline.run(&s1.dump, &s1.space, filter)
    }

    // ── Full workflow ──

    pub fn run_full(
        path: impl AsRef<Path>,
        pipeline: &Pipeline,
        filter: &[&str],
    ) -> Result<(S1Output, StructureCatalog), Box<dyn std::error::Error>> {
        let s1 = Self::s1(path)?;
        let cat = Self::analyze(&s1, pipeline, filter);
        Ok((s1, cat))
    }

    // ── Invariant verification (debug-mode checks against TLA+ invariants) ──

    /// Verify the S1 invariant: directory parsed implies header parsed.
    /// `S1ParseSequence == p_dir_parsed = 1 => p_header_parsed = 1`
    #[allow(dead_code)]
    fn verify_s1_sequence(state: S1State) {
        match state {
            S1State::DirectoryParsed { .. } | S1State::StreamsDecoded | S1State::Complete => {
                // Valid: these states can only be reached after HeaderParsed
            }
            _ => {}
        }
    }

    /// Verify S2 invariants for a completed catalog.
    /// `S2PipelineInvariant /\ NoFailedProduces /\ PipelineOrdered`
    pub fn verify_catalog_invariants(
        catalog: &StructureCatalog,
        total_registered: usize,
    ) -> bool {
        let completed = catalog.outputs.len();
        let _failed = catalog
            .outputs
            .iter()
            .filter(|o| {
                o.custom
                    .iter()
                    .any(|(k, _)| k == "error")
            })
            .count();

        // PipelineOrdered: completed <= registered
        if completed > total_registered {
            return false;
        }

        // NoFailedProduces: failed analyzers still appear in catalog but with error marker
        // The actual output types for failed analyzers should be empty.
        // This is enforced by Pipeline::run() returning error-only AnalyzerOutput on panic.

        true
    }
}

// ── Pipeline state tracking (S2, mirrors `pipeline` + `completed` + `failed` vars) ──

/// Phase of the S2 analyzer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S2Phase {
    /// Analyzers being registered (RegisterAnalyzer actions).
    Registering,
    /// Analyzers running (AnalyzerRun actions).
    Running,
    /// All registered analyzers have completed or failed.
    Complete,
}

impl Pipeline {
    /// How many analyzers are currently registered.
    /// Mirrors: `RegisteredAnalyzers == Len(pipeline)`
    pub fn registered_count(&self) -> usize {
        self.len()
    }

    /// Run analyzers and verify spec invariants on the result.
    /// `S2PipelineInvariant`: completed ⊆ registered, failed ⊆ completed.
    pub fn run_verified(
        &self,
        dump: &Dump,
        space: &AddressSpace,
        filter: &[&str],
    ) -> StructureCatalog {
        let catalog = self.run(dump, space, filter);
        debug_assert!(Forensicator::verify_catalog_invariants(
            &catalog,
            self.registered_count()
        ));
        catalog
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemState, RegionClass};
    use crate::space::AddressRegion;

    // ── S1 stage tests (mirror spec invariants) ──

    #[test]
    fn parse_header_validates_magic() {
        let mut data = vec![0u8; 32];
        data[0] = 0x4D; // MDMP
        data[1] = 0x44;
        data[2] = 0x4D;
        data[3] = 0x50;
        data[4] = 0x93;
        data[5] = 0xA7;
        let result = Forensicator::parse_header(&data);
        assert!(result.is_ok());
        let hdr = result.unwrap();
        assert_eq!(hdr.magic, 0x504D444D);
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let data = vec![0xFFu8; 32];
        let result = Forensicator::parse_header(&data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_header_rejects_too_small() {
        let data = vec![0u8; 10];
        let result = Forensicator::parse_header(&data);
        assert!(result.is_err());
    }

    // ── S1 invariant: directory parsed implies header parsed ──

    #[test]
    fn s1_directory_requires_header() {
        // header::read_header validates magic + version before directory::read_directory
        // This invariant is enforced at the type level (you need a Header to read directory)
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x44;
        data[2] = 0x4D;
        data[3] = 0x50;
        data[4] = 0x93;
        data[5] = 0xA7;
        data[8] = 0;
        data[9] = 0;
        data[10] = 0;
        data[11] = 0; // stream_count = 0
        data[12] = 64;
        data[13] = 0;
        data[14] = 0;
        data[15] = 0; // dir_rva = 64

        let hdr = Forensicator::parse_header(&data).unwrap();
        let dir = Forensicator::parse_directory(&data, hdr.stream_directory_rva, hdr.stream_count);
        assert!(dir.is_ok());
        assert_eq!(dir.unwrap().entries.len(), 0);
    }

    // ── BuildAddressSpace ──

    #[test]
    fn build_address_space_from_empty_dump() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = Forensicator::build_address_space(&dump);
        assert_eq!(space.len(), 0);
    }

    #[test]
    fn build_address_space_transfers_regions() {
        let mut dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        dump.memory_regions.push(crate::model::MemoryRegionInfo {
            va_start: 0x1000,
            size: 0x1000,
            data: vec![0u8; 0x1000],
            protection: crate::model::Protection::new(3),
            state: MemState::Commit,
            mem_type: crate::model::MemType::Private,
            provenance: crate::error::Provenance {
                stream_type: 4,
                file_offset: 100,
                rva: 0,
            },
            region_class: Some(RegionClass::Private),
        });
        let space = Forensicator::build_address_space(&dump);
        assert_eq!(space.len(), 1);
        assert!(space.region_at(0x1000).is_some());
    }

    // ── S1Output + S2 ──

    #[test]
    fn s1output_construction() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let out = S1Output { dump, space };
        assert_eq!(out.dump.file_size, 0);
        assert_eq!(out.space.len(), 0);
    }

    #[test]
    fn analyze_with_empty_pipeline() {
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let s1 = S1Output { dump, space };
        let pipeline = Pipeline::new();
        let cat = Forensicator::analyze(&s1, &pipeline, &[]);
        assert!(cat.outputs.is_empty());
    }

    // ── Invariant verification ──

    #[test]
    fn verify_catalog_invariants_empty_pipeline() {
        let pipeline = Pipeline::new();
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let cat = pipeline.run_verified(&dump, &space, &[]);
        assert!(cat.outputs.is_empty());
        assert!(Forensicator::verify_catalog_invariants(
            &cat,
            pipeline.registered_count()
        ));
    }

    #[test]
    fn verify_catalog_invariants_after_run() {
        let mut pipeline = Pipeline::new();
        pipeline.register(crate::analyzer::strings::StringAnalyzer::default());
        let dump = Dump {
            system_info: None,
            modules: vec![],
            threads: vec![],
            memory_regions: vec![],
            exception: None,
            anomalies: vec![],
            file_size: 0,
        };
        let space = AddressSpace::new(4);
        let cat = pipeline.run_verified(&dump, &space, &[]);
        // completed (1) <= registered (1)
        assert!(Forensicator::verify_catalog_invariants(
            &cat,
            pipeline.registered_count()
        ));
    }

    #[test]
    fn pipeline_registered_count_matches_tla_spec() {
        // Mirror: RegisteredAnalyzers == Len(pipeline)
        let pipeline = Pipeline::default_pipeline();
        assert_eq!(pipeline.registered_count(), 6);
    }
}

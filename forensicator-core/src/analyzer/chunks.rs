use crate::analyzer::{Analyzer, AnalyzerOutput};
use crate::model::Dump;
use crate::space::AddressSpace;

pub struct ChunkAnalyzer;

impl Default for ChunkAnalyzer {
    fn default() -> Self { ChunkAnalyzer }
}

impl Analyzer for ChunkAnalyzer {
    fn name(&self) -> &str { "chunks" }
    fn analyze(&self, _dump: &Dump, _space: &AddressSpace) -> AnalyzerOutput {
        AnalyzerOutput::new("chunks")
    }
}

use crate::model::{PointerGraph, StructChunk};
use crate::query::GraphQuery;
use crate::recover::StructureDetector;
use crate::space::AddressSpace;

#[derive(Default)]
pub struct ChunkDetector;

impl StructureDetector for ChunkDetector {
    type Item = StructChunk;
    fn name(&self) -> &str { "chunks" }
    fn detect(&self, _space: &AddressSpace, _graph: &PointerGraph, _query: &GraphQuery) -> Vec<StructChunk> {
        vec![]
    }
}

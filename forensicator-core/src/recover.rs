use crate::analyzer::StructureCatalog;
use crate::model::PointerGraph;
use crate::query::GraphQuery;
use crate::space::AddressSpace;

pub fn recover_all(
    _space: &AddressSpace,
    _graph: &PointerGraph,
    _query: &GraphQuery,
) -> StructureCatalog {
    StructureCatalog::empty()
}

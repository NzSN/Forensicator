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

pub trait StructureDetector {
    type Item;
    fn name(&self) -> &str;
    fn detect(&self, space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> Vec<Self::Item>;
}

pub fn recover_all(space: &AddressSpace, graph: &PointerGraph, query: &GraphQuery) -> StructureCatalog {
    let s = strings::StringDetector::default();
    let v = vtables::VTableDetector::default();
    let l = lists::ListDetector::default();
    let a = arrays::ArrayDetector::default();
    let c = chunks::ChunkDetector::default();

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

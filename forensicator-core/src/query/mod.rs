use std::collections::VecDeque;

use crate::model::{
    EdgeIndex, EdgePath, EdgePredicate, GraphEdge, NodeIndex,
    PointerGraph, RegionClass,
};

/// Query engine over a PointerGraph.
pub struct GraphQuery<'g> {
    graph: &'g PointerGraph,
    config: EdgePredicate,
}

impl<'g> GraphQuery<'g> {
    pub fn new(graph: &'g PointerGraph) -> Self {
        GraphQuery { graph, config: EdgePredicate::default() }
    }

    pub fn with_config(mut self, config: EdgePredicate) -> Self {
        self.config = config;
        self
    }

    /// Check if `va` is reachable from any root.
    pub fn is_reachable(&self, va: u64) -> bool {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return false; };
        self.reachable_from_any_root(node)
    }

    /// Find all nodes reachable from any root (BFS), filtered by predicate.
    pub fn reachable_all(&self) -> Vec<NodeIndex> {
        let mut visited = vec![false; self.graph.node_count()];
        let mut result = Vec::new();
        for &root in &self.graph.roots {
            self.bfs_from(root, &mut visited, &mut result, None);
        }
        result
    }

    /// Find a path from `va` to the nearest root.
    pub fn path_to_root(&self, va: u64) -> Vec<EdgePath> {
        let Some(&target) = self.graph.va_to_node.get(&va) else { return vec![]; };

        let mut visited = vec![false; self.graph.node_count()];
        let mut queue = VecDeque::new();
        let mut parent: Vec<Option<(NodeIndex, EdgeIndex)>> = vec![None; self.graph.node_count()];

        visited[target.0] = true;
        queue.push_back(target);

        while let Some(curr) = queue.pop_front() {
            if self.graph.nodes[curr.0].is_root {
                let mut path_nodes = vec![curr];
                let mut path_edges = Vec::new();
                let mut walk = curr;
                while walk != target {
                    let (prev, edge) = parent[walk.0].expect("parent must exist");
                    path_nodes.push(prev);
                    path_edges.push(edge);
                    walk = prev;
                }

                let total_conf: f64 = path_edges.iter()
                    .map(|&ei| self.graph.edges[ei.0].confidence)
                    .product();
                return vec![EdgePath { nodes: path_nodes, edges: path_edges, total_confidence: total_conf }];
            }
            for &ei in &self.graph.adj_in[curr.0] {
                let edge = &self.graph.edges[ei.0];
                let prev = edge.from;
                if !visited[prev.0] && self.config.matches(edge) {
                    visited[prev.0] = true;
                    parent[prev.0] = Some((curr, ei));
                    queue.push_back(prev);
                }
            }
        }
        vec![]
    }

    /// Find all nodes reachable from `va` (BFS forward).
    pub fn reachable_from(&self, va: u64) -> Vec<NodeIndex> {
        let Some(&start) = self.graph.va_to_node.get(&va) else { return vec![]; };
        let mut visited = vec![false; self.graph.node_count()];
        let mut result = Vec::new();
        self.bfs_from(start, &mut visited, &mut result, None);
        result
    }

    /// Find all nodes that point to `va`.
    pub fn who_points_to(&self, va: u64) -> Vec<NodeIndex> {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return vec![]; };
        self.graph.adj_in[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].from)
            .filter(|&n| {
                if let Some(edge) = self.edge_between(n, node) {
                    self.config.matches(edge)
                } else {
                    false
                }
            })
            .collect()
    }

    /// Get in/out neighbors of a node.
    pub fn neighbors(&self, va: u64) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
        let Some(&node) = self.graph.va_to_node.get(&va) else { return (vec![], vec![]); };
        let in_n: Vec<NodeIndex> = self.graph.adj_in[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].from)
            .collect();
        let out_n: Vec<NodeIndex> = self.graph.adj_out[node.0].iter()
            .map(|&ei| self.graph.edges[ei.0].to)
            .collect();
        (in_n, out_n)
    }

    /// Pointer density: count of nodes (simplified).
    pub fn pointer_density(&self, _va: u64, _size: u64) -> f64 {
        self.graph.node_count() as f64
    }

    /// Degree distribution histogram.
    pub fn degree_distribution(&self) -> Vec<(usize, usize)> {
        let max_deg = self.graph.nodes.iter().map(|n| n.out_degree).max().unwrap_or(0);
        let mut buckets = vec![0usize; max_deg + 1];
        for n in &self.graph.nodes {
            if n.out_degree <= max_deg {
                buckets[n.out_degree] += 1;
            }
        }
        buckets.into_iter().enumerate().filter(|(_, c)| *c > 0).collect()
    }

    /// Node/edge counts by region class.
    pub fn region_breakdown(&self) -> Vec<(RegionClass, usize, usize)> {
        let mut map: std::collections::HashMap<RegionClass, (usize, usize)> = std::collections::HashMap::new();
        for n in &self.graph.nodes {
            let e = map.entry(n.region_class).or_insert((0, 0));
            e.0 += 1;
        }
        for edge in &self.graph.edges {
            let n = &self.graph.nodes[edge.from.0];
            if let Some(e) = map.get_mut(&n.region_class) {
                e.1 += 1;
            }
        }
        let mut result: Vec<_> = map.into_iter().map(|(k, (n, e))| (k, n, e)).collect();
        result.sort_by_key(|&(ref c, _, _)| *c as u8);
        result
    }

    /// Confidence distribution.
    pub fn confidence_distribution(&self) -> Vec<(usize, usize)> {
        let levels = [0.0, 0.2, 0.4, 0.6, 0.8];
        let mut buckets = vec![0usize; levels.len()];
        for edge in &self.graph.edges {
            for (i, &threshold) in levels.iter().enumerate().rev() {
                if edge.confidence >= threshold {
                    buckets[i] += 1;
                    break;
                }
            }
        }
        buckets.into_iter().enumerate().collect()
    }

    /// Export to Graphviz DOT format.
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph PointerGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        for n in &self.graph.nodes {
            let shape = match n.region_class {
                RegionClass::Image => "box",
                RegionClass::Stack => "diamond",
                RegionClass::Private => "oval",
                RegionClass::Mapped => "hexagon",
                RegionClass::Other => "ellipse",
            };
            let color = if n.is_root { "red" } else { "black" };
            dot.push_str(&format!("  n{} [label=\"0x{:X}\", shape={shape}, color={color}];\n", n.va, n.va));
        }
        for (_i, edge) in self.graph.edges.iter().enumerate() {
            let color = if edge.confidence >= 0.7 { "green" }
                else if edge.confidence >= 0.4 { "orange" }
                else { "red" };
            dot.push_str(&format!("  n{} -> n{} [color={color}, label=\"{:.2}\"];\n",
                edge.from.0, edge.to.0, edge.confidence));
        }
        dot.push_str("}\n");
        dot
    }

    /// Export to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<serde_json::Value> = self.graph.nodes.iter().map(|n| {
            serde_json::json!({
                "va": format!("0x{:X}", n.va),
                "region_class": format!("{:?}", n.region_class),
                "out_degree": n.out_degree,
                "in_degree": n.in_degree,
                "is_root": n.is_root,
            })
        }).collect();
        let edges: Vec<serde_json::Value> = self.graph.edges.iter().map(|e| {
            serde_json::json!({
                "from": format!("0x{:X}", self.graph.nodes[e.from.0].va),
                "to": format!("0x{:X}", self.graph.nodes[e.to.0].va),
                "confidence": e.confidence,
                "evidence": e.evidence,
                "matched_by": e.matched_by,
            })
        }).collect();
        serde_json::json!({ "nodes": nodes, "edges": edges })
    }

    // --- private helpers ---

    fn bfs_from(
        &self,
        start: NodeIndex,
        visited: &mut [bool],
        result: &mut Vec<NodeIndex>,
        max_depth: Option<usize>,
    ) {
        let mut queue = VecDeque::new();
        let mut depth = vec![0usize; self.graph.node_count()];
        visited[start.0] = true;
        queue.push_back(start);
        result.push(start);

        while let Some(curr) = queue.pop_front() {
            let d = depth[curr.0];
            if let Some(max) = max_depth {
                if d >= max { continue; }
            }
            for &ei in &self.graph.adj_out[curr.0] {
                let edge = &self.graph.edges[ei.0];
                let next = edge.to;
                if !visited[next.0] && self.config.matches(edge) {
                    visited[next.0] = true;
                    depth[next.0] = d + 1;
                    queue.push_back(next);
                    result.push(next);
                }
            }
        }
    }

    fn reachable_from_any_root(&self, node: NodeIndex) -> bool {
        if self.graph.roots.contains(&node) { return true; }
        let mut visited = vec![false; self.graph.node_count()];
        for &root in &self.graph.roots {
            let mut queue = VecDeque::new();
            visited[root.0] = true;
            queue.push_back(root);
            while let Some(curr) = queue.pop_front() {
                if curr == node { return true; }
                for &ei in &self.graph.adj_out[curr.0] {
                    let next = self.graph.edges[ei.0].to;
                    if !visited[next.0] && self.config.matches(&self.graph.edges[ei.0]) {
                        visited[next.0] = true;
                        queue.push_back(next);
                    }
                }
            }
            visited.fill(false);
        }
        false
    }

    fn edge_between(&self, from: NodeIndex, to: NodeIndex) -> Option<&GraphEdge> {
        if from.0 >= self.graph.adj_out.len() { return None; }
        for &ei in &self.graph.adj_out[from.0] {
            if self.graph.edges[ei.0].to == to {
                return Some(&self.graph.edges[ei.0]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidatePointer, Root, ScanResult, SourceContext, TargetContext};
    use crate::graph::build_graph;

    fn make_simple_graph() -> PointerGraph {
        let c1 = CandidatePointer {
            source_va: 0x1000, value: 0x2000, target_va: 0x2000,
            source_ctx: SourceContext::AnyCommitted, target_ctx: TargetContext::AnyReadable,
            confidence: 0.8, matched_by: vec!["test".into()], evidence: vec!["aligned".into()],
        };
        let c2 = CandidatePointer {
            source_va: 0x2000, value: 0x3000, target_va: 0x3000,
            source_ctx: SourceContext::AnyCommitted, target_ctx: TargetContext::AnyReadable,
            confidence: 0.6, matched_by: vec!["test".into()], evidence: vec!["aligned".into()],
        };
        let r = Root::Register { thread_id: 1, reg_name: "RIP".into(), va: 0x1000 };
        let sr = ScanResult {
            candidates: vec![c1, c2],
            roots: vec![r],
        };
        build_graph(&sr).unwrap()
    }

    #[test]
    fn is_reachable_from_root() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        assert!(q.is_reachable(0x1000));
        assert!(q.is_reachable(0x2000));
        assert!(q.is_reachable(0x3000));
        assert!(!q.is_reachable(0x9999));
    }

    #[test]
    fn reachable_all_from_roots() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let nodes = q.reachable_all();
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn path_to_root_finds_path() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let paths = q.path_to_root(0x3000);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes.len(), 3);
        assert_eq!(g.nodes[paths[0].nodes[0].0].va, 0x1000);
        assert_eq!(g.nodes[paths[0].nodes[2].0].va, 0x3000);
    }

    #[test]
    fn path_to_root_unreachable_is_empty() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        assert!(q.path_to_root(0x9999).is_empty());
    }

    #[test]
    fn reachable_from_node() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let nodes = q.reachable_from(0x1000);
        let vas: Vec<u64> = nodes.iter().map(|&n| g.nodes[n.0].va).collect();
        assert!(vas.contains(&0x2000));
        assert!(vas.contains(&0x3000));
    }

    #[test]
    fn who_points_to() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let ptrs = q.who_points_to(0x3000);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(g.nodes[ptrs[0].0].va, 0x2000);
    }

    #[test]
    fn neighbors_returns_in_and_out() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let (ins, outs) = q.neighbors(0x2000);
        assert_eq!(ins.len(), 1);
        assert_eq!(outs.len(), 1);
    }

    #[test]
    fn reachable_respects_confidence_filter() {
        let g = make_simple_graph();
        let filter = EdgePredicate { min_confidence: 0.7, ..Default::default() };
        let q = GraphQuery::new(&g).with_config(filter);
        assert!(q.is_reachable(0x1000));
        assert!(q.is_reachable(0x2000));
        assert!(!q.is_reachable(0x3000));
    }

    #[test]
    fn degree_distribution_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dist = q.degree_distribution();
        assert!(!dist.is_empty());
    }

    #[test]
    fn region_breakdown_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let bd = q.region_breakdown();
        assert!(!bd.is_empty());
    }

    #[test]
    fn confidence_distribution_works() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dist = q.confidence_distribution();
        assert_eq!(dist.len(), 5);
    }

    #[test]
    fn to_dot_produces_output() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let dot = q.to_dot();
        assert!(dot.contains("digraph PointerGraph"));
        assert!(dot.contains("0x1000"));
        assert!(dot.contains("0x3000"));
    }

    #[test]
    fn to_json_produces_valid_structure() {
        let g = make_simple_graph();
        let q = GraphQuery::new(&g);
        let json = q.to_json();
        assert!(json["nodes"].is_array());
        assert!(json["edges"].is_array());
    }

    #[test]
    fn empty_graph_queries_return_empty() {
        let g = PointerGraph::new();
        let q = GraphQuery::new(&g);
        assert!(!q.is_reachable(0x1000));
        assert!(q.reachable_all().is_empty());
        assert!(q.path_to_root(0x1000).is_empty());
        assert!(q.who_points_to(0x1000).is_empty());
    }
}

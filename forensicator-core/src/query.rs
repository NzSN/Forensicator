#![allow(dead_code)]

use crate::model::PointerGraph;

pub struct GraphQuery<'a> {
    graph: &'a PointerGraph,
}

impl<'a> GraphQuery<'a> {
    pub fn new(graph: &'a PointerGraph) -> Self {
        GraphQuery { graph }
    }

    pub fn to_dot(&self) -> String {
        String::from("digraph G { }")
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"nodes": [], "edges": []})
    }

    pub fn degree_distribution(&self) -> std::collections::HashMap<usize, usize> {
        std::collections::HashMap::new()
    }
}

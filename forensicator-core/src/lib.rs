//! Forensicator core library — S1→S2 pipeline.
//! Parses Windows x64 minidumps, runs pluggable analyzers.

pub mod analyzer;
pub mod arch;
pub mod error;
pub mod graph;
pub mod model;
pub mod parse;
pub mod pattern;
pub mod pipeline;
pub mod query;
pub mod recover;
pub mod scan;
pub mod space;

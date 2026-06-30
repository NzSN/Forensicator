//! Forensicator core library — S1→S2→S3 pipeline.
//! Parses Windows x64 minidumps, builds pointer graphs, recovers structures.

pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
pub mod space;
pub mod pattern;
pub mod scan;
pub mod graph;
pub mod query;
pub mod recover;
pub mod pipeline;

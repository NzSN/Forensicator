//! Forensicator core library — S1→S2 pipeline.
//! Parses Windows x64 minidumps, runs pluggable analyzers.

pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
pub mod space;
pub mod pattern;
pub mod analyzer;
pub mod pipeline;

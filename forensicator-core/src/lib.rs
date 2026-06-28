//! Forensicator core library — S1 foundation.
//! Parses Windows x64 minidumps into a typed `Dump` with provenance.

pub mod error;
pub mod arch;
pub mod model;
pub mod parse;
pub mod space;
pub mod pattern;
pub mod scan;
pub mod graph;

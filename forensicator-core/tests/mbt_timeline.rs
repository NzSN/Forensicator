//! Model-Based Testing for the TTD-style trace model using MirrorRust.
//! Validates model::trace + parse::ttfx against the TLA+ Timeline.tla
//! spec via trace replay.
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_timeline -- --nocapture

#[test]
fn mbt_timeline() {
    let _bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    // TODO: wire a StateComputer replaying Timeline.tla traces through
    // model::trace::Trace (RecordStep → append write/event, Seek/Advance/
    // Retreat → a cursor, ValueAt → Trace::value_at), mirroring
    // mbt_symbolizer.rs. Until then the spec (specs/Timeline.tla) stands as
    // the machine-checked reference.
    eprintln!("mbt_timeline: trace replay not yet wired; spec-only stub");
}

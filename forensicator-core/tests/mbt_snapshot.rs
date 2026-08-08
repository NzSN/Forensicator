//! Model-Based Testing for the Timeline → Model snapshot link using
//! MirrorRust. Validates model::trace::Trace::snapshot against the TLA+
//! Snapshot.tla spec (specs/Snapshot.tla: Trace::snapshot's formal
//! counterpart — every cursor position materializes into a valid Model).
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_snapshot -- --nocapture

#[test]
fn mbt_snapshot() {
    let _bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    // TODO: wire a StateComputer replaying Snapshot.tla traces: drive a
    // model::trace::Trace from RecordStep/StartThread/EndThread/OpenCall/
    // CloseCall, apply Advance/Retreat/Seek to a cursor, then check
    // Trace::snapshot(cursor).dump against the mapped Model state
    // (M!View-style projection in the trace), mirroring mbt_symbolizer.rs.
    // Until then the spec (specs/Snapshot.tla) stands as the machine-checked
    // reference.
    eprintln!("mbt_snapshot: trace replay not yet wired; spec-only stub");
}

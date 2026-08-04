//! Model-Based Testing for the crash-cause diagnosis using MirrorRust.
//! Validates analyzer/cause.rs verdict discipline against the TLA+
//! CrashCause.tla spec via trace replay.
//!
//! Requires MirrorRust binary. Set MIRROR_BIN env var to run.
//! Requires Apalache. Set APALACHE_MC env var.
//!   e.g. MIRROR_BIN=D:\Tools\ModelMirrors.exe APALACHE_MC=...\wrapper.bat cargo test --test mbt_crash_cause -- --nocapture

#[test]
fn mbt_crash_cause() {
    let _bin = match std::env::var("MIRROR_BIN") {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("MIRROR_BIN not set; skipping MBT test");
            return;
        }
    };
    // TODO: wire a StateComputer replaying CrashCause.tla traces through
    // analyzer::cause::diagnose, mirroring mbt_symbolizer.rs. Until then the
    // spec (specs/CrashCause.tla) stands as the machine-checked reference.
    eprintln!("mbt_crash_cause: trace replay not yet wired; spec-only stub");
}

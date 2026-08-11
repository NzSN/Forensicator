# Forensicator (Lean 4)

Forensic analysis of Windows x64 minidumps and TTD-style execution traces — hand-written parsers, pointer-graph inference, structure recovery, V8 JavaScript stack reconstruction, and crash-cause diagnosis — as a **verified Lean 4 program**. The TLA+ specs that model-checked the Rust original are Lean theorems here, proved about the shipping functions.

> **Repo layout:** `master` is the Lean 4 port (this branch). The original Rust
> implementation is preserved on branch **`rust-backup`** (worktree at
> `~/Repos/Forensicator-rust`) and serves as the golden oracle for the
> conformance gate.

## Requirements

- [Lean 4](https://leanprover-community.org) toolchain **v4.33.0** (pinned in `lean-toolchain`; via elan).
- No library dependencies (no mathlib/batteries) — core only.

## Build & test

```sh
export PATH="$HOME/.elan/bin:$PATH"
lake build                    # lib + `forensicator` / `forensicator-test` exes
lake exe forensicator-test    # guard suite (decoder/model/analyzer units + fuzz)
```

## CLI

```
forensicator inspect <dump.dmp>           # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # analyzer pipeline (--plugin, --json, --symbols)
forensicator match <dump.dmp>             # verify dump ↔ exe/PDB artifacts (--exe, --pdb, --json)
forensicator list-plugins                 # list available analyzers
forensicator shell <dump.dmp|trace.ttfx>  # interactive session
forensicator trace <trace.ttfx>           # trace summary + queries (--pos, --writes <va> <len>, --json)
```

Two input formats, one analysis pipeline: minidumps (header → stream directory → typed `Dump` with provenance → sorted non-overlapping `AddressSpace`), and `.ttfx` traces (initial memory + append-only write/event logs + intervals) whose `snapshot(t)` materializes any position into the same `(Dump, AddressSpace)` pair — analyzers run unchanged at any recorded instant.

## What's proved

Theorems over the executable code (no `sorry`/`partial`/`panic!` in the library):

| Theorem | Content |
|---|---|
| `pack_unpack` | timeline position packing round-trips (u32 halves make overflow unrepresentable) |
| `addRegion_preserves`, `regionAt_unique`, `read_within_region` | AddressSpace.tla invariant, mechanized |
| `byteFold_eq_lastCovering`, `valueAt_agrees_with_fold` | reverse-scan views ≡ spec forward fold |
| `snapshot_isSome` | every position ≤ frontier materializes (CursorBounded) |
| `decodeTtfx_writes_ordered`, `decodeTtfx_events_ordered` | anomaly-free `.ttfx` decode ⇒ `TraceOrdered` (both halves) |
| `buildAddressSpace_wellFormed` | dump→space construction always satisfies the invariant |

## Conformance gate (Rust oracle)

`scripts/conformance-lean.sh` — 43 checks: the three `Case/` dumps × inspect/analyze/match (plus full-pipeline analyze), `minimal.ttfx` trace queries, scripted shell sessions, and an encoder cross-check (Lean-encode → Rust-decode). Text output byte-exact; JSON compared key-sorted. The Rust oracle is built from the `rust-backup` worktree (`FORENSICATOR_RUST`, default `~/Repos/Forensicator-rust`).

## Deliberate divergences (documented in-file)

- **Nat-lifted address arithmetic** — removes Rust's u64-wrap edges.
- **Disassembler is a native x86-64 subset** covering the crash-cause rule forms (no iced-x86 FFI); iced's number formatting (small decimals, `h` suffix, leading-zero rule) is matched exactly.
- **Minimal MSF-7 PDB reader** for `match` (GUID/age) instead of the `pdb` crate.
- The Rust debug-build overflow panic at `v8.rs:539` was a genuine bug — fixed upstream and ported (fulldump V8 walk now resolves: 510 frames, JS-named render pipeline).
- `arrays` on the fulldump fixture is quadratic in **both** implementations (excluded from the gate).

## Layout

```
Forensicator/
  Basic.lean            # addresses, positions, provenance, anomalies
  Spec/                 # mechanized TLA+ contracts + theorems
  Parse/                # total cursor monad; ttfx + minidump stream decoders
  Model/                # Dump / Trace / analyzer structures
  Analyzer/             # cause, strings, vtables, lists, arrays, chunks, shapes, v8
  Util/                 # disasm, unwind (.pdata), v8 layout, image (PE), pdb (MSF-7), json/text
  Pipeline.lean         # dump → AddressSpace, dump-kind classification
  Session.lean          # interactive shell state
Main.lean               # CLI
Test/                   # guard runner (lake exe forensicator-test)
scripts/conformance-lean.sh
```

Design + migration plan: `docs/superpowers/specs/2026-08-10-lean4-migration-design.md`, `docs/superpowers/plans/2026-08-10-lean4-migration.md`.

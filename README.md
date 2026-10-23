# Forensicator

Forensic analysis of Windows x64 minidumps and TTD execution traces — hand-written parsers, pointer-graph inference, structure recovery, V8 JavaScript stack reconstruction, and crash-cause diagnosis — as a **verified Lean 4 program**. The TLA+ specs that model-checked the Rust original are Lean theorems here, proved about the shipping functions.

> **Repo layout (2026-08-13):** Lean-only. The Rust implementation is gone
> entirely (branch, worktree, and remote deleted). The eager `.ttfx` trace
> format is removed with it; TTD traces are consumed lazily through a
> Windows-side proxy and the shipped Lean client. See
> `docs/plans/2026-08-13-remove-eager-trace-path.md`.

## Requirements

- [Lean 4](https://leanprover-community.org) toolchain **v4.33.0** (pinned in `lean-toolchain`; via elan).
- No library dependencies (no mathlib/batteries) — core only.

## Build & test

```sh
export PATH="$HOME/.elan/bin:$PATH"
lake build                    # lib + `forensicator` / `forensicator-test` exes
lake exe forensicator-test    # guard suite (decoder/model/analyzer units + fuzz)
python3 scripts/test-execution-shell.py # deterministic proxy shell integration
python3 scripts/test-proxy-ssh.py # literal proxy paths through SSH shell layers
python3 scripts/test-stack-shell.py # capture stack/session integration
./scripts/check-timeline-specs.sh # bounded TLA+ contracts (Apalache required)
./scripts/check-workflow-spec.sh # bounded root parse/analyzer composition
./scripts/conformance-lean.sh # golden gate (~8 min: 1.2 GB fulldump checks)
```

## CLI

```
forensicator inspect <dump.dmp>           # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>           # analyzer pipeline (--plugin, --json, --symbols)
forensicator match <dump.dmp>             # verify dump ↔ exe/PDB artifacts (--exe, --pdb, --json)
forensicator list-plugins                 # list available analyzers
forensicator shell <dump.dmp>             # interactive session
forensicator shell --proxy <trace.run>    # lazy TTD trace session via the proxy
```

Two input kinds share an execution analysis interface. Minidumps are parsed as `Dump` captures and adapted into one observed point. TTD traces attach through the Windows proxy and expose lazy execution points containing address-space knowledge, exact events and thread state. Supporting module/system information stays in analysis context. `inspect` reads current knowledge; `read` acquires a targeted range; `analyze` explicitly prepares a partial region set. `events <from> <to>` and write queries support reasoning between positions. See [timeline architecture](docs/arch/timeline.md).

## What's proved

Theorems over the executable code (no `sorry`/`partial`/`panic!` in the library):

| Theorem | Content |
|---|---|
| `pack_unpack` | timeline position packing round-trips (u32 halves make overflow unrepresentable) |
| `addRegion_preserves`, `regionAt_unique`, `read_within_region` | AddressSpace.tla invariant, mechanized |
| `byteFold_eq_lastCovering`, `valueAt_agrees_with_fold` | reverse-scan views ≡ spec forward fold |
| `pointAt_isSome`, `pointAt_identity` | bounded point existence and source/position identity; not complete state recovery |
| `buildAddressSpace_wellFormed` | dump→space construction always satisfies the invariant |
| `history_agree` (+ `mergeRecords`/`mergeWindow` invariants) | jigsaw cache validity: pieces are constant over their intervals (the pure CacheSound half) |

## Conformance gate (Lean-only golden regression)

`scripts/conformance-lean.sh` compares the CLI against captured references in `Case/golden/` (byte-exact text, key-sorted JSON): the three `Case/` dumps × inspect/analyze/match, scripted shell sessions, the guard suite + minidump fuzz, and negative guards (`.ttfx` input rejected). Regenerate goldens from a known-good build with `scripts/capture-goldens.sh`. An opt-in live gate (`FORENSICATOR_PROXY_RUN=<trace.run> FORENSICATOR_PROXY_SSH=windows-dev`) replays known fixture facts through the real proxy.

## Deliberate divergences from the Rust era (documented in-file)

- **Nat-lifted address arithmetic** — removes u64-wrap edges.
- **Disassembler is a native x86-64 subset** covering the crash-cause rule forms (no iced-x86 FFI).
- **Minimal MSF-7 PDB reader** for `match` (GUID/age) instead of the `pdb` crate.
- `arrays` on the fulldump fixture is quadratic (excluded from the gate).

## Layout

```
Forensicator/
  Basic.lean            # addresses, positions, provenance, anomalies
  Spec/                 # mechanized TLA+ contracts + theorems (AddressSpace, Timeline, JigSaw)
  Parse/                # total cursor monad; minidump stream decoders
  Model/                # execution views, capture adapter, Dump / Trace records
  Trace/                # proxy client: Proto + Index + Jigsaw (pure), Client (IO.Process)
  Analyzer/             # cause, strings, vtables, lists, arrays, chunks, shapes, v8
  Util/                 # disasm, unwind (.pdata), v8 layout, image (PE), pdb (MSF-7), json/text
  Pipeline.lean         # dump → AddressSpace, dump-kind classification
  Session.lean          # interactive shell state (incl. proxy attach)
Main.lean               # CLI
Test/                   # guard runner (lake exe forensicator-test)
scripts/                # conformance-lean.sh (gate), capture-goldens.sh, build-static.sh
specs/                  # TLA+ (Apalache-checked): Timeline, ExecutionState, Snapshot, JigSawSpawner, …
```

Execution-view design: [2026-09-06 execution timeline](docs/trace/2026-09-06-execution-timeline-design.md); implementation plan: [Drafts](Drafts/2026-09-06-execution-timeline-plan.md). Transport design: `docs/trace/2026-08-12-lazy-trace-proxy-design.md`.

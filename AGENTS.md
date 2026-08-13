# Forensicator — AGENTS.md

> **Repo layout (2026-08-13):** Lean-only. The Rust implementation is gone
> entirely — worktree, local branch, and `origin/rust-backup` all deleted;
> nothing Rust remains in play. The eager `.ttfx` v1 trace path is removed
> the same day; trace support returns as the proxy-based Lean client
> (follow-up plan). See
> `docs/plans/2026-08-13-remove-eager-trace-path.md`.

Lean 4 (v4.33.0) package for forensic analysis of Windows x64 minidumps.
Custom hand-written parser, pointer graph inference, structure recovery,
crash-cause diagnosis — focused on Electron/Chromium (V8) crashes.

## Commands

| What | How |
|------|-----|
| Build all | `export PATH="$HOME/.elan/bin:$PATH" && lake build` |
| Guard suite (unit/property checks) | `.lake/build/bin/forensicator-test` (`FORENSICATOR_CASE_DIR=Case` enables the minidump fuzz) |
| Golden gate | `./scripts/conformance-lean.sh` (regenerate references: `scripts/capture-goldens.sh`) |
| Static binary | `./scripts/build-static.sh` |
| TLA+ model check | `apalache-mc check --features=no-rows --config=<Spec>.cfg specs/<Spec>.tla` |

## Architecture

**One Lean package:** `Forensicator/` (library) + `Main.lean` (CLI) +
`Test/` (guard-suite binary). Zero Lean deps (no mathlib/batteries).

**Pipeline (S1 → S2):**
1. **Parse** — `Forensicator/Parse/Minidump.lean`: validate header → stream directory → per-stream decoders → typed `Dump` with provenance
2. **AddressSpace** — `Forensicator/Spec/AddressSpace.lean`: sorted, non-overlapping regions with `RegionClass` classification (Image/Stack/Private/Mapped/Other); spec and shipping structure are the same module
3. **Analyze** — `Forensicator/Analyzer/`: pluggable `Analyzer` pipeline (`Registry.defaultPipeline`): `cause` (crash-cause diagnosis), `strings`, `vtables`, `lists`, `arrays`, `chunks`, `shapes`, `v8` (JS stack recovery)

**`Forensicator/Pipeline.lean`** — workflow orchestrator mirroring
`specs/Forensicator.tla`; proves `buildAddressSpace_wellFormed`.

**Utility modules** (`Forensicator/Util/`) — `Disasm` (native x86-64 subset
+ `InstrKind` classification, no iced-x86 FFI), `V8Layout` (version-pinned V8
offsets; V8 object walking lives in `Analyzer/V8.lean`), `Pdb` (minimal
MSF-7 reader for `match`), `Unwind` (.pdata), `Image` (on-disk module
backing), `Json`, `Pattern`, `Bytes`, `Text`.

## Key conventions

- **No external parse library** — minidump parser is hand-written
- **All outputs have confidence scores** — iterative inference, not certainty
- **Provenance tracking** — every decoded fact records streamType + fileOffset + rva
- **No `sorry`/`partial`/`panic!` in the library** — totality replaces the Rust era's `catch_unwind`
- **Zero deps** — no mathlib/batteries; JSON via `Util/Json.lean`
- **Fail closed** — decoders/analyzers return `none`/`Unknown`/anomalies on inconsistency, never guess
- **`Cargo.lock`/cargo anything: gone** — do not reintroduce Rust tooling

## CLI subcommands

```
forensicator inspect <dump.dmp>        # structural inventory (--json, --quiet)
forensicator analyze <dump.dmp>        # run analyzers (--plugin, --json, --symbols <pdb_dir>)
forensicator match <dump.dmp>          # verify dump ↔ exe/PDB build artifacts (--exe, --pdb, --json)
forensicator list-plugins              # list registered analyzers
forensicator shell <dump.dmp>          # interactive session (inspect/analyze/match/load/symbols/quit)
```

Trace commands (`seek`/`t+`/`t-`/`position`/`writes`/`intervals`) remain in
the session dispatcher against `Target.trace`, but no loader can construct a
trace session until the Lean proxy client lands — they error with "trace
support removed (…follow-up)". The `trace` subcommand and `.ttfx` loading
are removed; `shell`/`load` reject TTFX magic explicitly.

## TTD trace support (proxy-only; `.ttfx` historical)

`specs/Timeline.tla` is the formal contract (Apalache-verified);
`specs/JigSawSpawner.tla` specifies the lazy loading path (Apalache-verified,
full run green 2026-08-13). Design authority:
`docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md` (D1–D9 +
Implementation notes). The trace model + views + theorems stay in
`Forensicator/Model/Trace.lean` / `Forensicator/Spec/Timeline.lean`
(`valueAt_agrees_with_fold`, `snapshot_isSome`). The eager `.ttfx` v1
decoder/encoder/fixture were removed 2026-08-13; `docs/arch/ttfx-format.md`
is historical (kept for a possible v2 jigsaw-persistence format, design §D8).

Current state (gap D-B): trace consumption requires the Windows proxy
(`D:\Codebase\JigsawSpawner`) + the Lean client (stdio over `IO.Process`) —
the client is a follow-up plan.

## Built-in pointer patterns

`all_strict`, `all_loose`, `saved_frame_pointers`, `vtables`, `heap_references`
(`Forensicator/Util/Pattern.lean`).

## TLA+ specs

`specs/` contains TLA+ specs (AddressSpace, Arch, Model, Timeline, Snapshot,
JigSawSpawner, etc.), Apalache-checked (`--features=no-rows` for the
record-bearing ones). The Rust-side mirrorrust MBT drivers (`mbt_*.rs`) died
with the Rust tree — their role is absorbed by the mechanized theorems
(`Forensicator/Spec/`, plus in-module theorems in `Pipeline.lean`,
`Model/Trace.lean`). State traces in `states/` are model-checking output,
excluded from git.

## Verification story (Lean)

- TLA+ specs mechanized as Lean theorems about the *shipping* functions:
  `pack_unpack`, `addRegion` preservation, `regionAt_unique`,
  `valueAt_agrees_with_fold`, `snapshot_isSome`,
  `buildAddressSpace_wellFormed`. No `sorry`/`partial`/`panic!`.
- Golden gate: `scripts/conformance-lean.sh` (Lean vs `Case/golden/`:
  3 dumps × inspect/analyze/match + shell scripts; byte-exact text, JSON
  key-sorted; guard suite + minidump fuzz; negative guard: `.ttfx` rejected).
- Deliberate divergences from the Rust era, all documented in-file:
  Nat-lifted address arithmetic (kills u64-wrap edges); `arrays` on fulldump
  is quadratic; the `find_ept_base` debug overflow panic was a Rust artifact
  and is gone (checked_add equivalent); disasm is a native x86-64 subset
  covering the cause-rule forms; the PDB symbolizer is a minimal MSF-7
  reader for `match`.

## Custom minidump streams

**V8HE** (stream type `0x45483856`, emitted by the instrumented handler): cage base + isolate VA + captured V8 heap regions, ingested as ordinary memory ranges. Version 2 adds a 32-byte extension after the header — allocation top/limit, `gc_state`, `last_gc_reason`, and a fatal-message string — decoded into `Dump.v8heapExt` and consumed by the `cause` analyzer's OOM/CHECK rules.

## Development approach

Superpowers-driven: plans in `docs/superpowers/plans/` (active removal plan
in `docs/plans/`), designs in `docs/superpowers/specs/`. Commits follow plan
task checkboxes.

## Gotchas

- `.gitignore` also excludes `**/specs/`, `**/states/`, `**/_apalache-out` (TLA+ build artifacts) — note `specs/` at repo root is force-added/tracked regardless
- `.vscode/settings.json` contains a `DEEPSEEK_API_KEY` env — do not commit
- The guard suite's `--emit` fixture route died with the `.ttfx` encoder; regenerate goldens only via `scripts/capture-goldens.sh` from a known-good build

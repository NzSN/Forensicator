# Lean-only pivot: remove Rust totally, remove the eager trace path — plan (2026-08-13)

**Goal:** Forensicator is Lean-only, with **no Rust artifacts anywhere** —
no worktree, no branch (local or remote), no Rust-derived files in master,
no Rust references in active docs. The eager `.ttfx` v1 path is excised from
the Lean tree (decoder, CLI surfaces, fixture), and the conformance gate is
reworked from "Rust oracle vs Lean" to Lean-only golden regression. Trace
consumption becomes proxy-only, with the Lean client (`IO.Process` stdio,
design D7) as a follow-up plan.

**Why now:** user decision — "no rust any more, lean only", then "give up
rust totally". Partially executed by the user already (2026-08-13): the
worktree `~/Repos/Forensicator-rust` and the local `rust-backup` branch are
deleted; the uncommitted lazy-proxy work went with them. What remains of
Rust anywhere: the remote branch `origin/rust-backup` (pre-lazy code) and
Rust-era wording in master's docs. The implementation's probe-verified
findings survive in the design doc's "Implementation notes" section —
that is the only carried-forward knowledge, and it is enough: the future
Lean client is built from the design doc + `specs/JigSawSpawner.tla`, not
from Rust code.

**Design authority:** `docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md`
(D1–D9 + Implementation notes). Loading-path spec: `specs/JigSawSpawner.tla`
(Apalache-verified to depth 10).

## Scope

**Removed:**

| Component | Where |
|---|---|
| Rust implementation, all of it | ~~worktree~~ done; ~~local `rust-backup`~~ done; **`origin/rust-backup` deleted (Task 1 — the last Rust artifact)** |
| `.ttfx` v1 reader/writer | Lean: `Forensicator/Parse/Ttfx.lean` (1231 lines), its `decodeRecord_*`/`decodeEvent_*` theorems, and `encodeTtfx` |
| `Trace.initMem` loading path | Lean: `Forensicator/Model/Trace.lean` keeps the field *model-side* (spec-facing) but nothing populates it from files |
| CLI: `trace <file.ttfx>`, `shell <file.ttfx>`, `load` TTFX dispatch, `--emit` | Lean: `Main.lean`, `Forensicator/Session.lean`; `Test/Main.lean:5` `--emit` routing dies with `Test/Spec.lean`'s `emitMinimal` |
| Fixture + gate checks | `Case/ttfx/minimal.ttfx`; `scripts/conformance-lean.sh` ttfx block (6 `check`s + anomaly check), Rust-oracle emit parity, shell trace script, and every Rust-vs-Lean comparison (they become golden compares, Task 4) |
| Rust wording in active docs | `AGENTS.md` (cargo commands, rust-backup layout note, MBT section, `.ttfx` TTD section), `docs/arch/verification.md`, `docs/arch/timeline.md`, `docs/arch/ttfx-format.md`, `docs/arch/cli.md` (Task 6) |

**Stays (explicitly not "eager path" or Rust):**

- `specs/Timeline.tla`, `specs/Snapshot.tla` — model trace *semantics*,
  path-agnostic; `specs/JigSawSpawner.tla` becomes the loading-path spec.
- The `Trace` model and all views (`valueAt`, `writesBetween`, `snapshot`, …)
  and their theorems (`valueAt_agrees_with_fold`, `snapshot_isSome`,
  `regionAt_unique`, …) — semantics unchanged; only the backing store is
  deleted. `PositionOrdered`/`EventsOrdered` in `Spec/Timeline.lean` are
  model-level, stay.
- V8HE / minidump / `.dmp` ingestion — eager by nature, different feature,
  untouched.
- The Lean guard suite (`forensicator-test` + `FORENSICATOR_CASE_DIR` fuzz) —
  self-contained, stays, becomes the primary dynamic check.
- The lazy-proxy *knowledge* — design doc D1–D9 + Implementation notes
  (p+1 write visibility, P3 absent pages, page-lifecycle divergence,
  transport) — already in master; nothing else is salvaged.
- `D:\Codebase\JigsawSpawner` proxy — unchanged; it is the trace source
  (it is a Windows-side Rust binary, but it is not part of this repo and
  is the engine boundary, not an implementation of Forensicator).
- `scripts/build-static.sh` — Lean-side static build, no cargo; untouched.

## Decision points (record before Task 1)

- **D-A — No offline trace artifact for now.** Deleting `.ttfx` v1 without
  implementing design §D8's `DUMP CACHE` (v2 jigsaw persistence) means a
  trace can only be consumed with a reachable proxy. Accepted: the proxy is
  the trace source; v2 persistence is a future design if archiving becomes
  a need. `docs/arch/ttfx-format.md` is marked historical, not deleted.
- **D-B — Lean trace feature gap.** The Lean client (design D7: stdio via
  `IO.Process`, networking-free) does not exist yet. Lean loses the `trace`
  subcommand and trace sessions until the follow-up client plan lands.
  `Trace`/`Timeline` theorems that are loader-independent stay.
- **D-C — MBT is over.** The `mbt_*.rs` drivers died with the worktree;
  specs stay verified by their Lean `Spec/` theorems (existing position).
  No `mbt_jigsaw_spawner` stub — no Rust harness exists to host it.
- **D-D — Gate becomes Lean-only golden regression.** Reference outputs are
  captured **before any excision** from the last gate-verified state
  (commit `3163121`, 44 checks PASS) into `Case/golden/` (untracked, like
  the fixtures), using the gate's own normalization (byte-exact `--quiet`,
  key-sorted/diagnosis-stripped `--json`). Capturing post-excision would
  bake any Task-3 regression into the goldens — so capture is Task 2,
  strictly before Task 3. The gate then compares Lean against goldens.
  Gate is local-only anyway (no CI); goldens regenerate from a known-good
  Lean build when fixtures change.
- **D-E — Total removal, no preservation.** No preservation commit (the
  worktree is already gone; the uncommitted lazy work is discarded, its
  findings recorded in the design doc's Implementation notes).
  `origin/rust-backup` — the last Rust artifact — is deleted in Task 1.
  Historical Rust-era docs under `docs/superpowers/` (migration plan/design,
  extractor design, lazy-proxy plan/design) stay as dated history; active
  docs (`AGENTS.md`, `docs/arch/`) are scrubbed.

## Tasks

- [x] 1. **Delete the last Rust artifact: `origin/rust-backup`.**
      `git push origin --delete rust-backup`. Confirm-with-user gate:
      this is irreversible (GitHub retains unreachable objects briefly,
      but treat it as final). The local branch and worktree are already
      gone (user, 2026-08-13). Verify: `git branch -a` shows no
      `rust-backup` anywhere; `git ls-remote origin` agrees. (Completed 2026-08-13.)
- [x] 2. **Gate: capture goldens from the verified build (before excision).**
      With the tree still at the 44-check-PASS state: build the Lean
      binary, run every non-ttfx gate check (inspect `--quiet`/`--json`,
      analyze, match, shell scripts) and store the normalized outputs in
      `Case/golden/` (untracked, like the fixtures). Normalization is the
      gate's own: byte-exact for `--quiet`, key-sorted with the documented
      key-strips for `--json`. Verify: `Case/golden/` populated; re-running
      the capture is idempotent.
- [x] 3. **Lean: excise eager** (this tree). Delete
      `Forensicator/Parse/Ttfx.lean` (with its `decodeRecord_*` /
      `decodeEvent_*` / `encodeTtfx` theorems and defs); drop the
      `import Forensicator.Parse.Ttfx` edges in `Forensicator.lean` (root
      re-export) and `Session.lean`; `Main.lean`: drop the `trace`
      subcommand + `decodeTtfx` call site, and reword the trace-only
      command errors (`position`/`writes`/`intervals`/`seek`,
      `Main.lean:513–560`) from "load a .ttfx file" to the proxy/future
      client; `Session.lean`: drop the TTFX-magic `load` arm so a
      `.ttfx` fails with an explicit "ttfx removed" error, not a minidump
      magic fallthrough (`.trace` target stays — it will be constructed
      by the future Lean client); `Basic.lean` ttfx comment +
      `Test/Spec.lean` ttfx round-trip/anomaly checks + `Test/Main.lean`
      `--emit` routing removed. Delete `Case/ttfx/minimal.ttfx`. Verify:
      `lake build` green; `forensicator-test` green.
- [x] 4. **Gate: Lean-only golden regression.** `scripts/conformance-lean.sh`:
      delete the Rust-oracle build (`FORENSICATOR_RUST`), the 7 ttfx
      checks, the emit-parity block, the shell trace script, and all
      Rust-vs-Lean comparisons; compare Lean against the Task-2 goldens
      instead. Add a negative guard that *fails* if the Lean binary
      accepts a `.ttfx` — inline fixture (a file with the `.ttfx` v1
      magic header, since `minimal.ttfx` is deleted), asserting non-zero
      exit + the explicit "ttfx removed" message from Task 3. Keep the
      `forensicator-test` guard suite + fuzz block. Verify:
      `./scripts/conformance-lean.sh` green.
- [ ] 5. **Windows: tombstone the extractor.** Via r_windev (ssh
      windows-dev): `D:\Repositories\TTFX` README gets a superseded banner
      pointing at `D:\Codebase\JigsawSpawner` + the design doc; no code
      deletion (it built the fixtures that seeded the golden gate).
- [x] 6. **Docs sweep (Rust-total).** `AGENTS.md`: rewritten Lean-only —
      commands (`lake build`, `./scripts/conformance-lean.sh`,
      `forensicator-test` guard suite); delete the rust-backup repo-layout
      note, the cargo Commands table, the MBT section; TTD section
      proxy-only, `.ttfx` → historical, note the Lean trace gap (D-B).
      `docs/arch/verification.md`: rewrite — MBT table and Rust module
      citations (`pipeline.rs`, `model/trace.rs`) are Rust-era; replace
      with the Lean `Spec/` theorems + golden-gate story.
      `docs/arch/timeline.md`: loading-path paragraph → proxy; extractor
      pointer removed. `docs/arch/ttfx-format.md`: historical banner (kept
      for the v2 persistence option, D-A). `docs/arch/cli.md`: drop
      `trace` subcommand docs. `docs/timeline.md`: no change (already
      proxy-shaped).
- [ ] 7. **Follow-up plan (out of scope here): Lean client.** Implement
      from the design doc (D1–D9 + Implementation notes) and
      `specs/JigSawSpawner.tla`: stdio protocol over `IO.Process`,
      `KnownAt`/`GapAt` views, cache soundness theorems. There is no Rust
      reference to port — the design doc is the specification. Until it
      lands, the `trace`/`shell` trace story is documented as a gap (D-B).
      **Plan written: `docs/plans/2026-08-13-lean-trace-client.md`.**

## Final verification

1. `lake build` + `./scripts/conformance-lean.sh` — green, zero `.ttfx`
   acceptance (negative guard), no Rust anywhere in the gate.
2. `git branch -a` + `git ls-remote origin` — no `rust-backup` anywhere;
   `~/Repos/Forensicator-rust` gone (already).
3. `rg -n "ttfx|Ttfx" Forensicator/ Forensicator.lean Main.lean Test/` —
   historical/docs hits only; `rg -in "cargo|rust-backup|worktree|rustc"
   AGENTS.md scripts/conformance-lean.sh docs/arch/` — none.

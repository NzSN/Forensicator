# ReplayApi re-pin to the real v0.9.5 header — plan + remaining tasks (2026-08-15)

**Status: spec edits landed, model-check verification in flight.** The
spec claimed a symbol-for-symbol pin to the v0.9.5 NuGet header but had
only ever been cross-checked against the WinDbg-Samples docs tree (which
is partially AI-generated and self-contradictory). Ground-truthing
against the actual `Microsoft.TimeTravelDebugging.Apis.0.9.5.nupkg`
(the latest published version — nuget.org lists only 0.8.127 and 0.9.5;
there is no newer header to re-pin to) found one real fidelity bug and
several comment inaccuracies, all fixed in the working tree.

**Verified findings against `pkg095/sdk/include/TTD/IReplayEngine.h`:**

- **EventMask genuinely gates watchpoint stops** (the bug):
  `enum class EventMask { MemoryWatchpoint, PositionWatchpoint, Exception,
  Gap, Thread, None=0, All=…, deprecated ThreadSwitch/Fragment/Segment }`.
  The spec armed added watchpoints unconditionally and masked exceptions
  only. Fixed: `Maskable == {"MEMORY_WATCHPOINT","POSITION_WATCHPOINT",
  "EXCEPTION"}`, `WatchHits*`/`PwpHits*` gated on the mask bits,
  `SetMask` domain widened, `ReplayTypes` updated, and the three
  stop invariants gained the mask-membership conjunct
  (sound because SetMask/Add*/Remove*/SetPos all reset `cur_stop`).
- `ReplayForward/ReplayBackward(limit, stepCount)` confirmed
  (header lines 1717–1722, plus no-limit convenience overloads) — the
  spec's destination model was already right; StepCount stays abstracted.
- `QueryMemoryPolicy` five values confirmed exactly as modeled;
  docs-tree `RequireContiguous`/`AllowPartial`/`MostAccurate` are
  docs bugs. `SetDefaultMemoryPolicy` exists but is only a stored
  default for the per-query policy argument — no semantic gap.
- Per-thread `GetPosition(ThreadId)`/`GetPreviousPosition(ThreadId)`
  and watchpoint `UniqueThreadId` filters exist in v0.9.5 — now listed
  as deliberate omissions (Timeline has no schedule).
- Docs-tree bugs confirmed: `ExecuteForward/ExecuteBackward` naming
  (header: Replay*), `bool SetPosition` (header: void),
  `type-UniqueCursor.md`'s `NewCursor` out-param signature (header:
  returns `ICursor*`), `EventType` over-listing ModuleLoad/Unload/
  Custom.
- `IReplayEngineStl.h` in the package is 54 lines of RAII/factories —
  no replay semantics; explicitly scoped out per user decision
  ("semantics of replay interfaces only").
- Action renames for canonical names: `AddWatchpoint` →
  `AddMemWatchpoint`, `RemoveWatchpoint` → `RemoveMemWatchpoint`
  (the short names are deprecated aliases in the header).

## Tasks

- [x] 0. **Acquire ground truth** — download
  `Microsoft.TimeTravelDebugging.Apis.0.9.5.nupkg`, extract
  `sdk/include/TTD/*.h`, diff the replay surface against the spec's
  account (EventMask, EventType, QueryMemoryPolicy, ReplayForward
  signatures, cursor queries, watchpoint structs, ReplayResult).
- [x] 1. **Fix the EventMask fidelity bug** — mask-gate
  `WatchHitsFwd/Bwd` and `PwpHitsFwd/Bwd`; widen `SetMask` to
  `SUBSET Maskable`; extend `WatchStopsFirst`/`EventStopsFirst`/
  `PwpStopsFirst` with mask-membership conjuncts; update
  `ReplayTypes`.
- [x] 2. **Header-comment corrections** — precise pin statement
  (package-verified), thread-scoping/default-policy/GapKindMask
  omissions bullet, corrected docs-tree divergence list (EventMask page
  exonerated; SetPosition-bool and NewCursor-signature bugs added),
  STL-veneer out-of-scope note.
- [ ] 3. **Run the Apalache full check** — `apalache-mc check
  --features=no-rows --config=specs/ReplayApi.cfg specs/ReplayApi.tla`
  (TimelineInvariant + ReplayApiInvariant). The post-edit run was
  cancelled at commit time (2026-08-15) still in flight — re-run from
  scratch. If it surfaces a counterexample, fix the mask-gating
  interaction and re-run. Expected state-space growth is modest (mask
  domain 2 → 8 subsets per cursor).
- [-] 4. **Fast-config smoke pass** — deferred: subsumed by the full
  run (task 3 checks ReplayApiInvariant + TimelineInvariant); the fast
  config remains for future quick regression runs.
- [x] 5. **Refresh or drop stale state graphs** — deleted
  `specs/ReplayApi.dot` / `specs/ReplayApi.svg` (untracked, predated
  the mask-gating change; regenerable from a fresh run).
- [x] 6. **Sweep stale references** — only the deleted graphs and this
  plan mention the old action names; no spec/Lean/doc references. Also
  updated the `ReplayApi.tla` row in `docs/arch/verification.md`.
- [x] 7. **Clean scratch** — deleted `.tmp-ttd/`.
- [x] 8. **Commit + push** the spec change (per repo convention the
  in-flight Apalache run is recorded in the commit message; a failed
  run triggers a follow-up fix commit).

## Future re-pin watch

- nuget.org has nothing newer than 0.9.5 (checked 2026-08-15; the
  WinDbg-Samples samples themselves still pin 0.9.5). If Microsoft
  publishes a newer `Microsoft.TimeTravelDebugging.Apis`, diff
  `sdk/include/TTD/IReplayEngine.h` again — the docs tree's
  `ExecuteForward`/`SetPosition`-bool/`MostAccurate` shape may turn
  out to be an unreleased newer API rather than doc bugs.
- If Timeline ever records gap/thread events, add `"GAP"`/`"THREAD"`
  to `Maskable` and produce the corresponding stop reasons.

# TTFX Extractor — Windows-side TTDReplay → .ttfx design

> **Lean-port note (2026-08-13):** Rust-era document — the implementation is
> now the Lean 4 tree (`Forensicator/`, `Main.lean`, `Test/`; module map in
> `docs/arch/README.md`). Rust references below (`forensicator-core/src/…`,
> `cargo`, `tests/mbt_*`) are historical and kept as written for the record.

Date: 2026-08-09
Status: complete (2026-08-09) — all sections implemented; conformance harness
green (`scripts/conformance.sh`: extract → WSL decode, zero anomalies)
Format contract: `docs/superpowers/specs/2026-08-07-ttfx-format-spec.md` (v1)
Behavioral contract: `specs/Timeline.tla` (Apalache-verified)
Target host directory: `D:\Repositories\TTFX` (Windows; exists, empty)

## Summary

A Windows-side CLI (`ttfx-extract.exe`) that opens a TTD trace (`.run`) with
the WinDbg-installed TTD replay stack and emits a `.ttfx` container exactly as
`forensicator-core/src/parse/ttfx.rs` decodes it: INITMEM (memory at position
0), WRITES (position-ordered write log), EVENTS (exception/module load/unload),
THREADS and CALLS (intervals), plus the header `frontier`. `.run` is never
parsed; all data comes from the replay engine, so the format contract
(`§5 sections`, payload pool, u32 absolute pool offsets, `0xFFFF…` open-end
sentinel) is the only coupling between extractor and core.

Confirmed on the target machine (WSL2 interop survey, 2026-08-09):
WinDbg 1.2606.22001.0 (AppX) ships the full TTD stack at
`C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2606.22001.0_x64__8wekyb3d8bbwe\`
— `TTDReplay.dll`, `TTDReplayCPU.dll`, `TTDAnalyze.dll`, `TTD.exe`, dbgeng/
dbgmodel. No MSVC, no Windows Rust toolchain yet (both installable via winget;
see P0). Recording traces is out of scope — input is an existing `.run`.

## Non-goals

- Recording `.run` traces (`TTD.exe -attach` / WinDbg UI) — input only.
- Parsing `.run` directly (proprietary; engine access only).
- Register files / full per-position context (Timeline v2 candidate).
- Symbol resolution server-side (extractor emits module base/size/name only;
  symbolization stays on the analysis host — timeline design open question 3).
- `.ttfx` v1.1 features (filter-description annotation section) — flagged,
  not built.

## P0 findings (spike results, 2026-08-09)

Environment: Windows 11 + WSL2 interop; WinDbg 1.2606.22001.0 (AppX) and
TimeTravelDebugging 1.11.611 (AppX alias `ttd.exe`) installed; Rust
1.97.1-msvc + VS 18 Community + SDK 10.0.26100 present on Windows. Trace
fixture: `traces\hostname01.run` (hostname.exe, 188 ms; recording needs an
elevated shell — kernel monitor driver).

Proven (all via `D:\Repositories\TTFX` `examples/probe*.rs`):

1. **`.run` opens through the official dbgeng route** —
   `DebugCreate` → `IDebugClient5::OpenDumpFileWide(path.run)` →
   `WaitForEvent`. No TTDReplay.dll handshake needed; D1's COM route is
   dropped (it additionally requires a license-string handshake derived
   from obfuscated tables — not touching that).
2. **Object navigation works natively** (IModelObject key walk via
   `IHostDataModelAccess::GetDataModel` → root namespace → `Debugger`):
   Sessions → Processes → `TTD.Threads` (Id, UniqueId, Lifetime),
   `TTD.Events` (Type/Position/Module), `TTD.Lifetime` (Min/MaxPosition);
   positions are `{Sequence, Steps}` u64 key pairs; intrinsics read via
   `GetIntrinsicValueAs` (needs features `Win32_System_Ole` + `…_Variant`).
   Collections iterate via the `IIterableConcept` (`EnumerateRawValues`
   AVs on LINQ wrappers — do not use).
3. **Positioned memory read works at engine level**: `ExecuteWide("!tt 2:0")`
   then `IDebugDataSpaces4::ReadVirtual` returned the MZ header of
   hostname.exe at position 2:0. Region enumeration will use the same
   channel (`QueryVirtual` at min position).
4. **Method invocation works ONLY through the engine `dx` channel**:
   `dx @$cursession.TTD.Memory(0x0, 0x7fffffffffff, "w").Count()` →
   0x8ACE6 writes on the tiny trace; `.First()` yields a structured record
   (EventType/ThreadId/UniqueThreadId/TimeStart/TimeEnd/AccessType/IP/
   Address/Size/Value/OverwrittenValue). Parse hex fields only (SystemTime
   fields are locale-mangled text — ignore).

Broken in a standalone process (do not use):

- `IDebugHostEvaluator::EvaluateExpression` — `1+1` evaluates, any
  `Debugger.*`/`@$cursession` name fails E_FAIL (the engine never publishes
  its session context to a standalone host; `dx` works because it binds
  internally). Same failure for `IDebugHostEvaluator2`.
- `IModelMethod` QI on method objects — E_NOINTERFACE even though the
  object reports kind=ObjectMethod(8) (tried GetKeyValue, enumerator
  values, Dereference, TryCastToRuntimeType, STA and MTA).
- JS provider: `host.namespace`/`host.currentSession` are undefined
  standalone (same unpublished-context root cause); `host.evaluateExpression`
  does not exist in this provider build; the provider also crashes the V8
  isolate at process exit (DebugExtensionUnload refcount check) — avoid
  `.scriptload` entirely.
- Direct execution of package binaries (`cdb.exe`) is blocked by AppX ACLs;
  DLLs ARE readable/copyable. Staging requirement for the probe:
  `dbgeng/dbgmodel/dbgcore/dbghelp.dll` + `ttd\` subtree next to the exe.

Revised architecture (supersedes D1):

- **Channel A — IModelObject walk** (native): THREADS, EVENTS, Lifetime,
  frontier. Proven.
- **Channel B — engine memory APIs** (native): `!tt` + ReadVirtual /
  QueryVirtual — INITMEM. Proven (read path).
- **Channel C — engine `dx` text** (output-callback capture, strict
  line parser, hex fields only): WRITES via `TTD.Memory(range, "w")`,
  CALLS via `TTD.Calls(pattern)`. Proven for Memory. **CALLS are
  symbol-dependent**: `TTD.Calls("mod!fn")` needs resolvable symbols —
  hostname.exe had none (`-sympath`/`--symbols` CLI knob; degrade to an
  empty CALLS section with a warning when patterns resolve to nothing).
- Positions arrive as `Sequence`/`Steps` u64s (A) or `"E:0"` text (C) —
  D3's pack check applies to both.

The `[Unindexed]` note on our fixture: `TTD.Memory` queries still answered
correctly without an index (possibly slower on large traces; indexing via
`!index` when present is free speed).

## P4/P5 status (2026-08-09)

- CALLS: `--calls-pattern P` (repeatable) + `--sympath S`; strict parser
  over the same dx `-r2 -u` item format (nested Thread.Id picked up
  positionally). Unresolved patterns degrade to an empty CALLS section +
  note, never fatal (design D6). The fixture machine's dbghelp cannot
  reach the symbol server (WinHTTP/proxy — "no header information
  available"), so the happy path is verified only as far as graceful
  degradation; verify on a symbols-capable machine before relying on
  CALLS content.
- Conformance harness `scripts/conformance.sh` (WSL): builds the
  extractor, extracts the fixture, decodes with forensicator — **zero
  anomalies** (34 regions, 568,550 writes, 19 events, 3 threads).
- Exit noise: the JsProvider V8 isolate crashes during ExitProcess;
  main ends with TerminateProcess to skip DLL unload (documented in
  README's known issues).

## P3 status (2026-08-09)

INITMEM implemented. **All engine region-enumeration APIs fail on TTD
targets** (QueryVirtual E_FAIL; `!address` refuses ("target does not
provide full memory information"); GetNextDifferentlyValidOffsetVirtual
returns garbage). The D5 fallback is therefore primary:

- INITMEM = referenced closure: unique 4 KiB pages of write destinations +
  exception addresses, each read at the trace's min position (`!tt` +
  ReadVirtual). A page unreadable at min position was not committed then
  and is correctly absent (66 such pages on the fixture). Adjacent
  same-class pages merge into regions.
- Plus one 4 KiB header page per loaded module (Image class; full image
  backing stays host-side per the symbolizer design). Fixture: 9 Image
  regions, all with real MZ headers — matching the 9 modules materialized
  at position 0xE:0.
- prot is approximate in v1 (Image=R, closure=R|W); state=Commit.
- Fixture totals: 34 regions / 352 KiB payload; full file 17.6 MB; WSL
  decode zero anomalies; snapshot at frontier exposes 34 regions + 19
  modules.
- Attach-mode caveat: modules loaded before recording starts produce no
  ModuleLoaded events; their header pages are still captured (they read
  fine at min position), but the EVENTS module list lacks them — the
  snapshot module table is load-event-driven by format design.

Next: P4 (CALLS, symbol-dependent) or P5 (conformance harness + README).

## P2 status (2026-08-09)

WRITES implemented via channel C: `dx -r2 -u @$cursession.TTD.Memory(lo,
hi, "w")` with strict line parsing (`[0xN]` item headers, `Name : value`
fields, hex only; malformed input is a hard error). Findings:

- dx caps collection display at 100 items unless `-u` ("iterate all
  container elements") — required.
- dx `Value` on >8-byte accesses holds the **low 8 bytes** (verified
  against a positioned read: write at 1E:432 → memory `00 00 99 D2 F7 7F
  00 00` == Value LE). Policy: emit the truthful 8-byte low half, counted
  as `wide-truncated` (41,472 of 568,550 = 7% on the fixture); the high
  part is unrecorded, never fudged.
- CLI: `--writes-va 0xLO..0xHI` (repeatable), `--writes-max-count N`
  (`.Take`), `--ring N` (`.TakeLast`), `--no-writes`. Multi-range merges
  dedupe by (pos, va, data).
- Full fixture: 568,550 writes in 2m40s → 17 MB .ttfx; WSL decode zero
  anomalies (0.65 s); `--writes <va> <len>` query returns byte-exact
  values and correct last-writer attribution.
- Known cosmetic issue: the JsProvider V8 isolate crashes at process exit
  (DebugExtensionUnload refcount); output capture completes before exit so
  results are unaffected. Mitigation if it ever blocks: `process::exit(0)`
  before COM teardown.

Next: P3 (INITMEM region scan via `!tt` + QueryVirtual/ReadVirtual).

## P1 status (2026-08-09)

Landed in `D:\Repositories\TTFX`: `src/position.rs` (pack/parse + D3 check),
`src/emit.rs` (full v1 writer), `src/backend.rs` (trait + raw types),
`src/backend/dbgeng.rs` (channel A), `src/main.rs` (CLI).
`ttfx-extract traces\hostname01.run` → 1635-byte `.ttfx` (19 events,
3 threads, frontier 0x954000009BE). WSL decode (`forensicator trace`):
**zero anomalies**; snapshot at 0xE:0 has 9 modules vs 19 at frontier —
time-travel materialization works end-to-end.

Spike-hardening notes discovered in P1:

- TTD emits **sentinel positions** (`major ≥ 0xFFFFFFFF00000000`, e.g.
  `FFFFFFFFFFFFFFFE:0`) for unset lifetimes — filtered in threads/events/
  position_range; sentinel thread end → open interval.
- The alive-at-end heuristic (thread lifetime max == process lifetime max)
  fires for all 3 threads of hostname01 (plausible: process was alive when
  recording stopped).
- Exception-event schema (code/address/thread key names) is mapped
  defensively; the first exception-bearing trace will print its key list
  once for verification (none in hostname01.run — ModuleLoaded/Unloaded only).

Next: P2 (WRITES via dx channel — needs the strict line parser).

## Key decisions

### D1 — Replay backend: hybrid dbgeng channels (REVISED after P0)

~~TTDReplay.dll COM~~ → superseded by the P0 findings: the official dbgeng
stack opens `.run` directly and covers every section via channels A/B/C
(above). The `ReplayBackend` trait still isolates them:

```rust
trait ReplayBackend {
    fn position_range(&self) -> (Position, Position);           // A: Lifetime
    fn threads(&self) -> Vec<RawThread>;                        // A
    fn events(&self) -> Vec<RawEvent>;                          // A
    fn regions_at_min(&self) -> Vec<RegionInfo>;                // B: QueryVirtual scan
    fn read_memory(&mut self, pos: Position, va: u64, buf: &mut [u8]) -> Result<usize>; // B: !tt + ReadVirtual
    fn writes(&self, range: VaRange) -> Vec<RawWrite>;          // C: dx TTD.Memory
    fn calls(&self, pattern: &str) -> Vec<RawCall>;             // C: dx TTD.Calls (symbol-dependent)
}
```

### D2 — Language/toolchain: Rust + `windows`/`windows-core` on Windows

Confirmed by P0: Rust 1.97.1-msvc + VS 18 Community + SDK 10.0.26100 were
already installed on the machine. The data-model pieces need
`windows` features `Win32_System_Diagnostics_Debug*` + `Win32_System_Ole`
+ `Win32_System_Variant`; COM callbacks (output capture) use
`windows-core`'s `#[implement]` (note: the generated `Foo_Impl` trait name
applies to the `Capture_Impl` pattern). Build/run Windows-side; WSL stays
the analysis side.

### D3 — Position packing: verify, pack, hard-check

`.ttfx` `Position = (major << 32) | minor`. TTD minors are instruction counts
and are not contractually < 2³². Extractor verifies per position:
`major ≤ u32::MAX && minor ≤ u32::MAX`. On violation: **re-index** the whole
position space to a dense monotone u64 (rank by total order) and print a
loud warning (positions then no longer cross-reference WinDbg `!tt` values;
v1.1's annotation section will record the mapping). Sorting by packed value
equals sorting by (major, minor), so order is preserved either way.

### D4 — Write-log volume controls (timeline design open question 1)

Full store logs of a busy process dwarf everything else. CLI:

```
ttfx-extract <trace.run> [-o trace.ttfx]
    [--writes-va 0xSTART..0xEND]...     repeatable VA filters (default: all)
    [--writes-max-count N]              keep first N after sorting (default: unbounded)
    [--ring N]                          keep only the last N writes
    [--initmem-va 0xSTART..0xEND]...    region-content filters (default: all committed)
    [--initmem-max-bytes N]             cap total INITMEM payload (default: 512 MiB)
```

Every applied filter is printed at emit time (and becomes a v1.1 annotation).
`--ring` is the LATS window for corruption-provenance work.

### D5 — INITMEM: region scan at MinPosition, referenced-closure fallback

Primary: seek to session min position, walk the address space
(`query_region` from 0 upward), `read_memory` each committed (MEM_COMMIT)
region → INITMEM records (prot mapped to the Forensicator bitmask
R=1/W=2/X=4/GUARD=8/NO_CACHE=16; state Commit; type Private/Mapped/Image from
MEM_* — Image for module-backed). If the replay engine cannot enumerate
regions (spike finding), fallback: **referenced closure** — union of all VAs
touched by WRITES/EVENTS plus thread stack ranges, rounded to 64 KiB, read at
min position; recorded as a warning (coverage partial).

`data_off`/`name_off` are u32 → `.ttfx` v1 caps at 4 GiB. The extractor stops
with an explicit error at the cap (no silent truncation; bump format to v2
with u64 pool offsets when real traces demand it).

### D6 — Section emission mapping

| TTFX section | Source (backend call) | Notes |
|---|---|---|
| header.frontier | `position_range().1` (packed) | `≥ max(pos)` over all records (format §8) |
| INITMEM | region scan @ min pos (D5) | sorted by VA; payload appended in emission order |
| WRITES | `memory_writes(range)` per `--writes-va` (or one full pass) | sorted by packed pos (stable); `len` = access size (1–16 B typical) |
| EVENTS | `events()` | kind map: Exception→0 (code, address, thread_id), ModuleLoad→1 (base VA, size, name→pool), ModuleUnload→2 (base VA) |
| THREADS | `threads()` | lifetime start/end packed; alive at end → `end = u64::MAX` |
| CALLS | `calls(pattern)` (C) | thread id + start/end packed; TTD preserves LIFO close (CallNesting holds by construction; the decoder validates anyway). **Symbol-dependent**: patterns must resolve (PDB via `-sympath`); on failure emit an empty CALLS section + warning, never abort |

Unknown/irrelevant TTD event kinds are skipped (never emitted as unknown
kinds — the decoder anomalies on them). Thread exit while calls open:
extractor closes spans at thread end (TTD materializes no frames for dead
threads — Timeline `EndThread` discipline) and prints a warning count.

## Project layout (`D:\Repositories\TTFX`)

```
TTFX/
  Cargo.toml              # [package] ttfx-extract; windows-core/windows deps only
  src/
    main.rs               # CLI (hand-rolled args — no clap needed here) + orchestration
    backend.rs            # ReplayBackend trait + RawEvent/RawWrite/RawThread/RawCall types
    backend/ttdreplay.rs  # COM interface declarations + impl (the P0 spike target)
    position.rs           # pack/unpack/verify (D3)
    emit.rs               # .ttfx writer (section records + payload pool, format §3–§6)
  tests/
    vectors.rs            # emit.rs unit tests (round-trip shape, offsets)
  README.md               # build/run instructions (winget rustup, interop notes)
```

`emit.rs` mirrors the dev-only writer in `parse/ttfx.rs` tests (same bytes);
no code sharing across repos for v1 — the writer is ~150 lines and the format
spec is the single source of truth.

## Conformance & testing

1. **Unit** (Windows): emit.rs round-trip shape; position pack/re-index
   tables; filter logic.
2. **Golden decode** (cross-boundary, the real gate): extract
   `Case\hello.run` (a tiny notepad-style recording, ~seconds) →
   `hello.ttfx`, then on WSL `forensicator-core` decodes with **zero
   anomalies** and `snapshot(frontier)` validates
   (`Dump::validate_model()` empty). Scripted as
   `scripts/conformance.sh` on WSL invoking the extractor via interop
   (`/mnt/d/Repositories/TTFX/target/release/ttfx-extract.exe`) — manual
   harness, not CI.
3. **Spot equivalence**: for a handful of (va, t) pairs, `value_at` from
   forensicator `trace --pos` matches WinDbg `!tt` + `db` reads at the same
   position (documented manual checklist).
4. **Timeline invariants** are enforced by the decoder (anomalies); the
   extractor's goal is anomaly-free output on well-formed traces, never
   validation on the emit side beyond the D3 position check.

## Phases

0. **Spike** ✅ (2026-08-09 — findings above; probes live in `examples/`).
1. **Skeleton + cheap sections**: CLI, position.rs, emit.rs, channel A
   (threads/events/lifetime) → first `.ttfx` (INITMEM/WRITES empty or
   minimal) that the WSL decoder accepts anomaly-free.
2. **WRITES**: channel C `TTD.Memory` walk, dx line parser, filters/caps/ring (D4), ordering.
3. **INITMEM**: channel B region scan (or referenced-closure fallback), payload pool, 4 GiB cap handling.
4. **CALLS**: channel C with `--calls-pattern` (repeatable) + symbol-path knob; graceful empty-section degradation.
5. **Conformance harness** + README.

## Risks / open questions

1. **TTDReplay interface drift** across WinDbg versions — mitigated by the
   backend trait and by pinning the probed WinDbg build in README; vtable
   mismatch is caught by the P0 probe (no silent corruption: COM call would
   fault, not misdecode).
2. **Region enumeration** may not exist on the replay engine → D5 fallback
   (partial INITMEM). Impact: `value_at` returns None for never-written,
   never-captured VAs — degraded, not wrong.
3. **Minor overflow** (D3) — expected rare; re-index path keeps the format
   intact at the cost of WinDbg cross-references.
4. **Performance** of full-memory INITMEM on multi-GB traces — bounded by
   `--initmem-*` filters; TTD memory reads at position are engine-speed,
   not recorded-speed.

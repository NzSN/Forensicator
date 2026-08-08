# Snapshot.tla → Rust landing design

Date: 2026-08-08
Status: design
Spec: `specs/Snapshot.tla` (Apalache-verified, commit bd0736a)
Predecessor: `docs/superpowers/specs/2026-08-07-timeline-design.md`

## Context

`Snapshot.tla` formalizes the Timeline → Model link: `ModelAt(t)` re-indexes a
timeline position into a Model-shaped state, and three verified properties
(`SnapshotValid`, `SnapshotsAreModels`, `LinkAtCursor`) state that every
recorded position materializes into a valid time-point `Dump`.

The Rust counterpart of `ModelAt(t)` — `Trace::snapshot` (model/trace.rs:178) —
already exists. What has *not* landed:

1. **Runtime validation.** Nothing in Rust checks that a materialized snapshot
   satisfies the Model invariants (the spec's `SnapshotValid`). Decode-time
   validation exists for `.ttfx` (`parse/ttfx.rs` → anomalies), but the derived
   view is unvalidated.
2. **MBT wiring.** `forensicator-core/tests/mbt_snapshot.rs` is an auto-skipping
   stub; the spec stands as a machine-checked reference but is never replayed
   against Rust.

This design lands both, following the repo's Spec↔code 1:1 convention (every
spec operator/invariant gets a named Rust counterpart).

## Goal / Non-goals

**Goals**

- `Dump::validate_model()` — the Rust counterpart of `ModelInvariant`'s
  structural conjuncts, wired into `Trace::snapshot` as anomalies
  (degrade, not fail — the repo's usual fail-closed-into-anomalies).
- `specs/SnapshotMBT.tla` + `SnapshotMBT.cfg` — MBT harness spec (EXTENDS
  Snapshot; the verified specs stay untouched).
- `mbt_snapshot.rs` — full `StateComputer` replacing the stub, replaying
  Snapshot.tla traces through `model::trace::Trace` and comparing the
  projected `Trace::snapshot(cursor)` against the spec's `ModelAt(cursor)`.

**Non-goals**

- Modifying `Timeline.tla` / `Snapshot.tla` (both verified; SnapshotMBT only
  EXTENDS).
- Per-position register files / thread tables in snapshots (v2 candidate,
  out of scope exactly as in the timeline design).
- Multi-byte writes in MBT replay (the spec's `RecordStep` stores one cell;
  `WriteRecord.data` is exercised at length 1 only).
- The Windows extractor (separate design, unchanged).
- Byte-contents comparison in the Model projection (Model regions are
  metadata-only); byte-level faithfulness is checked separately via a
  cell-values projection (see below), which is the Rust echo of
  `SnapshotConsistent`.

## Component A — spec-mapping docs (trace.rs)

Extend the `//! Spec mapping` block in `model/trace.rs` with the Snapshot.tla
rows so the 1:1 convention is discoverable at the definition site:

| Snapshot.tla | Rust |
|---|---|
| `ModelAt(t)` | `Trace::snapshot(t)` |
| `EvUpto` / `ExcUpto` | event-log prefix scans inside `snapshot`/`exceptions_at` |
| `OpenMods` (LIFO load−unload) | module `push`/`retain` loop in `snapshot` |
| `SnapshotValid` / `SnapshotsAreModels` | `Dump::validate_model()` (Component B) + `mbt_snapshot.rs` (Component C) |
| `LinkAtCursor` | MBT-only drift guard; no Rust counterpart (by design) |

## Component B — `Dump::validate_model()` (model.rs)

```rust
impl Dump {
    /// Structural conjuncts of Model.tla ModelInvariant that Rust types do
    /// not already enforce. Snapshot.tla SnapshotValid/SnapshotsAreModels.
    /// Degrades into anomalies; never fails.
    pub fn validate_model(&self) -> Vec<Anomaly>;
}
```

Checked (each violation → one `Anomaly`, description matching Model.tla where
one exists):

- modules pairwise VA-disjoint — else `"overlapping module"` (Model.tla:225)
- `provenance.stream_type > 0` on every module/thread/region, and on
  `system_info`/`exception` when present (Model's `*Prov` helpers, `sid > 0`)
- `threads[i].stack_size > 0` (`ThreadStacksPositive`)
- annotation keys and values non-empty (`AnnValNonEmpty`)

Deliberately **not** checked: `prot ≤ 7`, `state`/`cls` domains (Rust enums and
`Protection` bitflags make them unrepresentable), and all `*CountBound`
conjuncts (verification artifacts — Model.tla:44).

Wiring: `Trace::snapshot` appends `validate_model()` results to
`snapshot.dump.anomalies` before returning. `snapshot` keeps its
`Option` — the only hard failure remains `t > frontier` (`CursorBounded`).

Unit tests (always run, no env vars):

- overlapping modules → exactly one `"overlapping module"` anomaly
- `stack_size = 0` thread → anomaly; clean dump → empty
- `Trace::snapshot` on a trace whose events produce overlapping module VAs
  surfaces the anomaly in the returned `Dump`

## Component C — MBT (SnapshotMBT.tla + mbt_snapshot.rs)

### C.1 `specs/SnapshotMBT.tla`

`EXTENDS Snapshot`, adds the mirrorrust action-tracking envelope (ModelMBT.tla
pattern):

```tla
VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [a: Int, v: Int, k: Str, p: Int, thr: Int, im: Seq(Int)];
    parameters
```

- `MBTInit == Init /\ action_taken = "Init" /\ parameters = [a|->0, v|->0,
  k|->"NONE", p|->0, thr|->0, im|-> CellsOf(init_mem)]` where
  `CellsOf(f) == [c \in 1..MaxAddr |-> f[c]]` — the chosen initial memory is
  exported to the computer through `parameters.im`.
- One wrapper per Timeline action, re-quantifying so choices land in
  `parameters` (ModelMBT style). `MBTRecordStep` inlines RecordStep's three
  disjuncts: no-op (`a=0, k="NONE"`), write (`a,v` bound, `k="NONE"`),
  event (`k` bound, `a=0`) — write and event may co-fire, so the wrapper
  carries both independently, sentinel discipline: `a=0` ⇔ no write,
  `k="NONE"` ⇔ no event.
- `View` exposes, in order: `cells` (`CellsOf(init_mem)`), `wr_pos`,
  `wr_addr`, `wr_val`, `ev_pos`, `ev_kind`, `frontier`, `cursor`, `threads`,
  `calls`, the `ModelAt(cursor)` field projection (`snap_sysinfo`,
  `snap_mod_va`, …, `snap_ann_key`, `snap_ann_val` — names prefixed to avoid
  colliding with Timeline's own `threads`), and `cell_values`
  (`[c \in 1..MaxAddr |-> ValueAt(c, cursor)]` — byte-level check, the Rust
  echo of `SnapshotConsistent`).
- `MBTNext`, `MBTSpec`, `TraceComplete == TRUE` as in ModelMBT.

`specs/SnapshotMBT.cfg`:

```
SPECIFICATION MBTSpec
INVARIANT SnapshotValid
```

`SnapshotValid` (not `SnapshotsAreModels`) for trace generation: the cursor
anchor is the cheap conjunct set; the ∀-t property stays the offline deep
check (`Snapshot.cfg`, 30 min at depth 10). Noted in the cfg header comment.

### C.2 `forensicator-core/tests/mbt_snapshot.rs`

Replaces the stub. `SnapshotComputer` mirrors the spec state:

```rust
struct SnapshotComputer {
    trace: Trace,
    cursor: Position,
    open_loads: Vec<u64>, // load event indices, LIFO — see divergences
}
```

`StateComputer::compute` per action:

- `"Init"` — build `Trace` with a single `MemoryRegionInfo`
  `{ va_start: 1, size: MaxAddr, data: params.im, protection: RW, Commit,
  Private, cls: Private, provenance: 1/0/0 }`, empty logs, `frontier = 0`;
  `cursor = 0`; `open_loads` empty.
- `"RecordStep"` — `trace.frontier += 1`; if `a > 0` push
  `WriteRecord { pos: frontier, va: a, data: vec![v], prov 1/0/0 }`; if
  `k ≠ "NONE"` push `TraceEvent { pos: frontier, kind, code: 0, thread_id: 0,
  prov 1/0/0, .. }` with module fields synthesized:
  - `ModuleLoad`: `address = trace.events.len() + 1` (the event's 1-based log
    index — the spec's "module VA = load event index"), `size = 1`,
    `name = "m<index>"`; push index onto `open_loads`.
  - `ModuleUnload`: `address = open_loads.pop().unwrap_or(0)` — pops the most
    recent open load; `0` matches nothing when the stack is empty, mirroring
    the spec's no-op.
- `"StartThread"` / `"EndThread"` / `"OpenCall"` / `"CloseCall"` — push/close
  `trace.threads` (`id = table index`) and `trace.calls`; `None` ↔ spec's
  `end = -1`.
- `"Advance"` / `"Retreat"` / `"Seek"` — `cursor ± 1` / `cursor = p`.

`to_state()` projects both levels into the `View` keys:

1. **Trace level**: logs, intervals (`None → -1`), `frontier`, `cursor`,
   `cell_values[c] = trace.value_at(c, cursor).unwrap()` (total: the canonical
   region covers every cell).
2. **Snapshot level**: `trace.snapshot(cursor).unwrap()`'s `Dump` projected
   exactly as `mbt_model.rs`'s `ModelComputer::to_state` does (reuse/extract
   the projection helpers), with one normalization — `ann_val` projects as the
   constant `"pos"` (the spec abstracts the `0x{t:X}` formatting; the key
   `"ttfx_position"` is compared literally).

`apalache_config()`: spec `SnapshotMBT.tla` (`MBT_SPEC` overridable),
invariant `SnapshotValid`, `length_bound: 6`, `param_vars: "parameters"`,
`MBTInit`/`MBTNext`. `trace_config()`: `num_traces: 100`, `view: "View"`.
The `MIRROR_BIN`/`APALACHE_MC` auto-skip guard stays; `cargo test --workspace`
remains green without them.

### C.3 Spec↔Rust divergences and their reconciliation

| Snapshot.tla | Rust | Reconciliation |
|---|---|---|
| module VA = load event index; unload = LIFO pop | `TraceEvent.address` = base VA; unload = `retain(base_va ≠ addr)` | computer synthesizes `address = event index` and tracks `open_loads`, so LIFO pop and retain-by-VA coincide by construction |
| exception payload abstracted to `0` | `TraceEvent` carries `code/address/thread_id` | computer zeroes them; projection emits `<<0,0,0,0,1,0,0>>` |
| `ann_val = "pos"` | `format!("0x{t:X}")` | projection normalizes to `"pos"` |
| single-cell write `(a, v)` | `WriteRecord.data: Vec<u8>` | MBT drives 1-byte writes only |
| `end = -1` open interval | `Option<Position>` | projection maps `None ↔ -1` |
| threads/calls carry no OS id | `(u32, Interval)` / `CallSpan.thread_id` | computer assigns `id = table index` |
| provenance `sid = 1` | `TTFX_STREAM_TYPE` (`0x54465854`) | computer uses `1` (the spec's abstraction); real decode keeps `TTFX_STREAM_TYPE` |
| one constant memory region | `init_mem: Vec<MemoryRegionInfo>` | computer builds exactly the canonical region |

If a future spec revision carries module addresses (removing the LIFO
simplification), only the synthesis in `open_loads` changes; the comparison
machinery is unaffected.

## Testing

- `cargo test -p forensicator-core -- model::trace` — new validate/snapshot
  unit tests, always on.
- `cargo test --workspace` — unchanged green (MBT auto-skips).
- `MIRROR_BIN=… APALACHE_MC=… cargo test --test mbt_snapshot -- --nocapture` —
  full replay (opt-in; requires the `no-rows` wrapper, as with `mbt_model`).
- `apalache-mc check --features=no-rows --config=SnapshotMBT.cfg` — sanity
  check of the harness spec itself (expected fast: bound 6, cheap invariant).

## Risks / open questions

1. **Trace-generation cost.** The full `Snapshot.cfg` check takes ~30 min at
   depth 10. MBT uses `length_bound 6` + `SnapshotValid` only; if generation
   is still slow, fall back to `TimelineInvariant` for generation (validity is
   then enforced by the comparison itself) or reduce `num_traces`.
2. **Sentinel discipline** in `parameters` (`a=0`, `k="NONE"`) is brittle if
   Timeline ever admits cell 0 or a `"NONE"` event kind — both are format
   constants under our control; a comment in SnapshotMBT.tla pins them.
3. **Annotation normalization** hides the position-string formatting from
   comparison. Acceptable: formatting is presentation, not model content. If
   we ever want it checked, extend the spec's annotation to carry the abstract
   position and compare exactly.

## File inventory

| File | Change |
|---|---|
| `specs/SnapshotMBT.tla` | new — MBT envelope over Snapshot.tla |
| `specs/SnapshotMBT.cfg` | new — `SPECIFICATION MBTSpec`, `INVARIANT SnapshotValid` |
| `forensicator-core/src/model.rs` | `Dump::validate_model()` |
| `forensicator-core/src/model/trace.rs` | snapshot wiring + spec-mapping docs; unit tests |
| `forensicator-core/tests/mbt_snapshot.rs` | stub → full `SnapshotComputer` |
| `AGENTS.md` | `mbt_snapshot.rs` loses its "(spec-only stub)" tag |

Follow-up: a plan in `docs/superpowers/plans/` checkboxing Components A→C.

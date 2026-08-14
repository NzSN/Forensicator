# TTFX — Forensicator Trace Container Format (v1)

> **Lean-port note (2026-08-13):** Rust-era document — the implementation is
> now the Lean 4 tree (`Forensicator/`, `Main.lean`, `Test/`; module map in
> `docs/arch/README.md`). Rust references below (`forensicator-core/src/…`,
> `cargo`, `tests/mbt_*`) are historical and kept as written for the record.

## Status
Draft, v1. Matches `forensicator-core/src/parse/ttfx.rs` (`TTFX_VERSION = 1`).
Formal behavioral contract: `specs/Timeline.tla`. Design rationale:
`docs/trace/2026-08-07-timeline-design.md`.

## 1. Purpose

TTFX carries the *observable structure* of a time-travel debug (TTD) trace
from the Windows-side extractor (which reads `.run` via TTDReplay) to
forensicator-core on any platform. It models: initial memory, an
append-only position-ordered write log, an event log, and thread/call
intervals. It is **not** a re-encoding of Microsoft's `.run` container;
`.run` files are never parsed by forensicator.

## 2. General conventions

- All integers are **little-endian**, unsigned unless noted.
- `Position` is a `u64`: TTD's `Major:Minor` pair packed as `(major << 32) | minor`.
  Only the total order is semantically meaningful.
- Strings are UTF-8, not NUL-terminated, length-prefixed.
- Payload bytes (region contents, write contents, module names) live in the
  **payload pool** at the end of the file and are referenced by *absolute
  file offset* (`data_off` / `name_off` fields).
- Decoders must be **truncation-tolerant**: any record whose bytes extend
  past the end of the file terminates that section's decode; already-decoded
  records remain valid. All integrity deviations are reported as anomalies,
  never as hard errors, except §3 violations (short file, bad magic,
  unsupported version).

## 3. File header (32 bytes)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `TTFX`: bytes `54 54 46 58` = u32 `0x58465454` LE |
| 4 | 4 | version | `1` |
| 8 | 4 | flags | `0` (reserved; bit 0 `HAS_INITMEM` planned) |
| 12 | 4 | section_cnt | number of sections (≥ 0; order irrelevant to semantics) |
| 16 | 8 | frontier | record head: positions `0..=frontier` exist in the trace |
| 24 | 8 | reserved | zero |

Hard errors: file shorter than 32 bytes; `magic` mismatch; `version != 1`.

## 4. Section header (16 bytes)

Immediately after the header, `section_cnt` sections follow, each:

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | kind | 1=INITMEM, 2=WRITES, 3=EVENTS, 4=THREADS, 5=CALLS |
| 4 | 4 | record_size | bytes per record (fixed per kind, see §5) |
| 8 | 8 | record_cnt | number of records |

Records follow immediately, `record_cnt × record_size` bytes, tightly packed.
Unknown `kind` values are skipped (forward compatibility). A `record_size`
mismatch against the kind's fixed size is an anomaly and the section is skipped.

## 5. Sections and records

### 5.1 INITMEM (kind=1, record_size=32) — memory at position 0

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | va | region start virtual address |
| 8 | 8 | size | region size in bytes |
| 16 | 4 | prot | Forensicator `Protection` bitmask: READ=1, WRITE=2, EXECUTE=4, GUARD=8, NO_CACHE=16 |
| 20 | 4 | state | 0=Commit, 1=Reserve, 2=Free |
| 24 | 4 | mem_type | 0=Private, 1=Mapped, 2=Image |
| 28 | 4 | data_off | absolute file offset of `size` payload bytes |

Regions are ingested as `MemoryRegionInfo` (class `Private`). Payload
shorter than `size` (truncated pool) → anomaly `initmem … truncated payload`;
the short payload is kept.

### 5.2 WRITES (kind=2, record_size=24) — the write log

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | pos | position of the write |
| 8 | 8 | va | start virtual address written |
| 16 | 4 | len | bytes written |
| 20 | 4 | data_off | absolute file offset of `len` payload bytes |

Semantics: the i-th record means "at position `pos`, `[va, va+len)` became
the payload bytes". The log is append-only and **position-ordered**
(`pos` non-decreasing); every `pos ≤ frontier`. Violations → anomalies
`write out of order` / `write beyond frontier`. Writes to VAs outside all
INITMEM regions are unobservable (they never mask earlier valid writes; see
`Trace::value_at`).

### 5.3 EVENTS (kind=3, record_size=48) — the event log

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | pos | position of the event |
| 8 | 4 | kind | 0=Exception, 1=ModuleLoad, 2=ModuleUnload |
| 12 | 4 | code | Exception: raw exception code (e.g. `0xC0000005`); else 0 |
| 16 | 8 | address | Exception: exception address; ModuleLoad/Unload: module base VA |
| 24 | 4 | thread_id | Exception: faulting thread; else 0 |
| 28 | 8 | size | ModuleLoad: module size; else 0 |
| 36 | 4 | name_len | ModuleLoad: module name length; else 0 |
| 40 | 4 | name_off | absolute file offset of name bytes; 0 if none |
| 44 | 4 | reserved | zero |

Same ordering rules as WRITES (position-ordered, `pos ≤ frontier`; violations
are anomalies). Unknown `kind` → anomaly `unknown event kind`, record skipped.

### 5.4 THREADS (kind=4, record_size=24) — thread lifetimes

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | thread_id | OS thread id |
| 4 | 4 | reserved | zero |
| 8 | 8 | start | lifetime start position |
| 16 | 8 | end | lifetime end position; `0xFFFFFFFFFFFFFFFF` = open (alive) |

`start > end` → anomaly `thread … interval inverted`.

### 5.5 CALLS (kind=5, record_size=24) — call spans

Identical layout to THREADS: a call span `[start, end)` on `thread_id`,
`end = 0xFFFF…` while open. The extractor must emit spans respecting stack
discipline (LIFO close). Cross-record invariants validated after all sections:

- **CallNesting** — closed spans on the same thread are disjoint or nested,
  never crossing → anomaly `crossing call spans`.
- **CallsWithinThreads** — span's thread exists in THREADS, `start ≥ thread.start`,
  `end ≤ thread.end` (when both closed) → anomaly `call on unknown thread` /
  `call outside thread … lifetime`.

## 6. Payload pool

After the last section: concatenated payloads referenced by `data_off`/`name_off`
(absolute offsets). No alignment requirement. Writers append payloads in
record emission order (INITMEM, WRITES, EVENTS-name) — not required by the
format, but keeps offsets monotone and files diff-friendly.

## 7. Semantic model (informative)

Decoding yields `model::trace::Trace`. Position `t` materializes to a
snapshot: INITMEM overlaid with WRITES where `pos ≤ t` (last write per byte
wins, within-region bytes only); modules = loads − unloads `≤ t`;
exception = last Exception event `≤ t`. Navigation is bounded:
`snapshot(t)` is undefined for `t > frontier` (CursorBounded). These rules
are the machine-checked invariants of `specs/Timeline.tla`
(`TraceOrdered`, `SnapshotConsistent`, `CursorBounded`, `ThreadIntervals`,
`CallNesting`, `CallsWithinThreads`).

## 8. Versioning rules

- Readers reject `version != 1` (hard error) — a version bump signals
  *breaking* layout changes.
- Backward-compatible additions use: new section kinds (skipped by old
  readers), the `flags` field, or the reserved header/record bytes.
- Writers must set `frontier ≥ max(pos)` over all WRITES/EVENTS records.

## 9. Example (Case/ttfx/minimal.ttfx, 434 bytes)

```
0x000  header: magic "TTFX", version 1, 5 sections, frontier 0x2
0x020  INITMEM hdr (2 recs)   @0x030: r0 va=0x1000 size=16 data_off=0x188
                                 r1 va=0x2000 size=16 data_off=0x198
0x070  WRITES  hdr (2 recs)   @0x080: w0 pos=1 va=0x1004 len=2 off=0x1A8
                                 w1 pos=2 va=0x1004 len=1 off=0x1AA
0x0B0  EVENTS  hdr (2 recs)   @0x0C0: e0 pos=1 ModuleLoad  base=0x70000000
                                      name="app.exe" off=0x1AB
                                 e1 pos=2 Exception  code=0xC0000005
                                      addr=0x1004 tid=7
0x120  THREADS hdr (1 rec)    @0x130: tid=7 [0x0, open)
0x148  CALLS   hdr (2 recs)   @0x158: c0 tid=7 [0x0, 0x2)
                                 c1 tid=7 [0x0, 0x1)
0x188  pool: 16B 0xAA | 16B 0xBB | 11 22 | 33 | "app.exe"
```

Regenerate: `cargo test -p forensicator-core --lib -- parse::ttfx --ignored`.

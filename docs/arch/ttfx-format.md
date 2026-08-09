# TTFX Container Format (v1) — Detailed Reference

Normative contract: `docs/superpowers/specs/2026-08-07-ttfx-format-spec.md`.
Behavioral contract: `specs/Timeline.tla`. Reader/writer:
`forensicator-core/src/parse/ttfx.rs`. Producer: the Windows extractor
(`D:\Repositories\TTFX`, see `docs/arch/timeline.md` and the extractor
design doc). This page is the byte-level walkthrough.

## 1. Purpose

`.ttfx` carries the *observable structure* of a TTD trace between the
Windows extractor (which reads `.run` via the debugger engine) and
forensicator-core on any platform: initial memory, the write log, the event
log, and thread/call intervals. It is not a re-encoding of `.run`; it is a
deliberate projection — see timeline.md §"Why a separate container" for what
is dropped and why.

## 2. Conventions

- All integers **little-endian**, unsigned unless noted.
- `Position` is a `u64`: TTD's `Major:Minor` packed as `(major << 32) | minor`.
  Only the total order matters semantically.
- Strings are UTF-8, length-prefixed, **not** NUL-terminated.
- Byte payloads (region contents, write contents, module names) live in the
  **payload pool** at file end and are referenced by *absolute file offset*
  (`data_off`/`name_off`, u32 → format cap 4 GiB).
- **Truncation tolerance**: any record whose bytes extend past EOF terminates
  its section's decode; already-decoded records stay valid. All integrity
  deviations are `Trace.anomalies`, never errors — except the three header
  violations in §3.

## 3. File header (32 bytes)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | magic | `"TTFX"` — bytes `54 54 46 58` (u32 LE `0x58465454`) |
| 4 | 4 | version | `1` (bump = breaking layout change) |
| 8 | 4 | flags | `0` (reserved; bit 0 `HAS_INITMEM` planned) |
| 12 | 4 | section_cnt | number of sections; order is irrelevant to semantics |
| 16 | 8 | frontier | record head — positions `0..=frontier` exist |
| 24 | 8 | reserved | zero |

Hard errors (decode fails): file < 32 bytes; magic mismatch; `version != 1`.

## 4. Section header (16 bytes)

Sections start at offset 32, back to back:

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | kind | 1=INITMEM 2=WRITES 3=EVENTS 4=THREADS 5=CALLS |
| 4 | 4 | record_size | fixed per kind (below) |
| 8 | 8 | record_cnt | record count |

Records follow immediately: `record_cnt × record_size` bytes, tightly packed.
Unknown `kind` → skipped (forward compatibility). `record_size` mismatch →
anomaly, section skipped.

## 5. Sections

### 5.1 INITMEM (kind=1, 32 B/record) — memory contents at position 0

| Off | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | va | region start VA |
| 8 | 8 | size | region size in bytes |
| 16 | 4 | prot | Forensicator bitmask: READ=1 WRITE=2 EXECUTE=4 GUARD=8 NO_CACHE=16 |
| 20 | 4 | state | 0=Commit, 1=Reserve, 2=Free |
| 24 | 4 | mem_type | 0=Private, 1=Mapped, 2=Image |
| 28 | 4 | data_off | absolute file offset of `size` payload bytes |

Decoded as `MemoryRegionInfo` (class Private). Short payload (truncated pool)
→ anomaly `initmem … truncated payload`; the short payload is kept.

### 5.2 WRITES (kind=2, 24 B/record) — the write log

| Off | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | pos | position of the write |
| 8 | 8 | va | start VA written |
| 16 | 4 | len | bytes written |
| 20 | 4 | data_off | absolute file offset of `len` payload bytes |

Record *i* means: at `pos`, `[va, va+len)` became the payload bytes.
Position-ordered (non-decreasing), all `pos ≤ frontier`; violations →
anomalies `write out of order` / `write beyond frontier`. Writes outside all
INITMEM regions are *unobservable* (never mask earlier valid writes —
`Trace::value_at`).

### 5.3 EVENTS (kind=3, 48 B/record) — the event log

| Off | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 8 | pos | position |
| 8 | 4 | kind | 0=Exception, 1=ModuleLoad, 2=ModuleUnload |
| 12 | 4 | code | Exception: raw code (e.g. `0xC0000005`); else 0 |
| 16 | 8 | address | Exception: exception address; module events: base VA |
| 24 | 4 | thread_id | Exception: faulting thread; else 0 |
| 28 | 8 | size | ModuleLoad: module size; else 0 |
| 36 | 4 | name_len | ModuleLoad: name length; else 0 |
| 40 | 4 | name_off | absolute file offset of name bytes; 0 if none |
| 44 | 4 | reserved | zero |

(Offsets 28–35 are one `u64 size`; note the gap in the table grid.)
Same ordering rules as WRITES. Unknown `kind` → anomaly, record skipped.

### 5.4 THREADS (kind=4, 24 B/record) — thread lifetimes

| Off | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | thread_id | OS thread id |
| 4 | 4 | reserved | zero |
| 8 | 8 | start | lifetime start position |
| 16 | 8 | end | end position; `0xFFFFFFFFFFFFFFFF` = open (alive) |

`start > end` → anomaly `thread … interval inverted`.

### 5.5 CALLS (kind=5, 24 B/record) — call spans

Same layout as THREADS: a call span `[start, end)` on `thread_id`.
Cross-record invariants, validated after all sections:

- **CallNesting** — closed spans on one thread are disjoint or nested, never
  crossing → anomaly `crossing call spans`.
- **CallsWithinThreads** — thread exists, `start ≥ thread.start`,
  `end ≤ thread.end` (when both closed) → anomalies `call on unknown thread` /
  `call outside thread … lifetime`.

## 6. Payload pool

After the last section: concatenated payloads, no alignment, referenced by
absolute offsets. Offset math for writers:

```
pool_base = 32 + Σ_sections (16 + record_cnt·record_size)
```

Writers append payloads in record emission order (INITMEM → WRITES →
EVENTS-names) so offsets are monotone and files diff-friendly (convention,
not requirement).

## 7. Semantics — what a position means

Decoding yields `model::trace::Trace`. Position `t` materializes
(`Trace::snapshot(t)`, formalized by `specs/Snapshot.tla`):

- **memory**: INITMEM overlaid with WRITES `pos ≤ t` (last write per byte
  wins, in-region bytes only);
- **modules**: ModuleLoad − ModuleUnload events `≤ t` (event-ordered);
- **exception**: last Exception event `≤ t`;
- `t > frontier` → `None` (**CursorBounded**, fail closed).

`Trace::snapshot` also runs `Dump::validate_model()` (Model.tla's structural
invariants) and degrades violations into dump anomalies.

## 8. Invariants → decode anomalies

| Timeline.tla | Decoder behavior |
|---|---|
| TraceOrdered | position ordering / `pos ≤ frontier` checks on WRITES, EVENTS |
| ThreadIntervals | `start ≤ end` per thread |
| CallNesting | per-thread spans disjoint-or-nested |
| CallsWithinThreads | span's thread known, span ⊆ its lifetime |
| CursorBounded | `snapshot(None)` past frontier; session cursor clamped |
| SnapshotConsistent | property test: `value_at` ≡ brute-force fold |

Anomalies degrade, never abort: later sections still decode.

## 9. Versioning

- Readers hard-reject `version != 1`.
- Backward-compatible growth paths: new section kinds (old readers skip),
  `flags` bits, reserved header/record bytes.
- Writers must set `frontier ≥ max(pos)` over all WRITES/EVENTS records.

## 10. Worked example — `Case/ttfx/minimal.ttfx` (434 bytes)

Every byte, annotated (offsets hex):

```
0x000  54 54 46 58            magic "TTFX"
0x004  01 00 00 00            version 1
0x008  00 00 00 00            flags 0
0x00C  05 00 00 00            5 sections
0x010  02 00 .. 00 (8B)       frontier = 2
0x018  00 .. 00 (8B)          reserved

0x020  01 .. / 20 .. / 02 ..  INITMEM hdr: kind=1, rec=32B, cnt=2
0x030  rec0: va=0x1000 size=0x10 prot=3(RW) state=0(Commit) type=0(Private)
              data_off=0x188
0x050  rec1: va=0x2000 size=0x10 … data_off=0x198

0x070  02 .. / 18 .. / 02 ..  WRITES hdr: kind=2, rec=24B, cnt=2
0x080  rec0: pos=1 va=0x1004 len=2 data_off=0x1A8   → bytes 11 22
0x098  rec1: pos=2 va=0x1004 len=1 data_off=0x1AA   → byte  33

0x0B0  03 .. / 30 .. / 02 ..  EVENTS hdr: kind=3, rec=48B, cnt=2
0x0C0  rec0: pos=1 kind=1(ModuleLoad) addr=0x70000000 size=0x1000
              name_len=7 name_off=0x1AB → "app.exe"
0x0F0  rec1: pos=2 kind=0(Exception) code=0xC0000005 addr=0x1004 tid=7

0x120  04 .. / 18 .. / 01 ..  THREADS hdr: kind=4, rec=24B, cnt=1
0x130  rec0: tid=7 start=0 end=0xFFFFFFFFFFFFFFFF (open)

0x148  05 .. / 18 .. / 02 ..  CALLS hdr: kind=5, rec=24B, cnt=2
0x158  rec0: tid=7 [0, 2)      ← outer span
0x170  rec1: tid=7 [0, 1)      ← inner span (nested: legal CallNesting)

0x188  payload pool (42 bytes):
       0x188  AA×16            region 0 contents
       0x198  BB×16            region 1 contents
       0x1A8  11 22            write 0 bytes
       0x1AA  33               write 1 byte
       0x1AB  "app.exe"        module name
```

Reading it: at position 0 the byte at 0x1004 is `0xAA` (init_mem); at 1 it
becomes `0x11`; at 2 it becomes `0x33` (last write wins). The exception at
pos 2 is `0xC0000005` (access violation) on thread 7 at `0x1004` — which is
exactly the byte the two writes touched.

Regenerate the fixture:
`cargo test -p forensicator-core --lib -- parse::ttfx --ignored`.

## 11. Extractor notes (producer side)

The Windows extractor (`ttfx-extract`) emits this format from TTDReplay via
the dbgeng data model; its practical caveats are documented in
`docs/superpowers/specs/2026-08-09-ttfx-extractor-design.md`: TTD sentinel
positions (`major ≥ 0xFFFFFFFF00000000`) are dropped; >8-byte writes keep
their truthful low 8 bytes; INITMEM is a referenced-closure capture
(engine cannot enumerate the address map on TTD targets); CALLS require
resolvable symbols.

# Issue: WRITES_INDEX page-window query takes ~20 min on hot pages (lceda-pro01.run)

Date: 2026-08-14
Status: open (root cause locked; fix options below, none scheduled)
Severity: high for interactive proxy sessions on large traces
Component: JigsawSpawner proxy (backend/dbgeng.rs channel C) and Lean
client (Forensicator/Trace/Index.lean windowed index, design D1)

## Symptom

Against D:/Desktop/lceda-pro01/lceda-pro01.run (23.3 GB, indexed - the
.idx file is present; frontier 0x27172DB000004C8, 75 threads, 157
events), the first query touching VA 0x1B9400091A40 hangs the session:

- `shell --proxy` + `writes 0x1b9400091a40 8` was killed by a 15-min
  timeout before printing any write record.
- A `valueAt` probe was stuck 30+ min with the proxy process burning
  2390 s of CPU (2.4 GB working set) before being killed.
- The same machinery on `hostname01.run` (29 MB) is seconds-fast
  (P3 page: 1,287 records).

## Reproduction

```
# on the analysis host (WSL)
export FORENSICATOR_PROXY_SSH=windows-dev
.lean/build/bin/forensicator shell --proxy D:/Desktop/lceda-pro01/lceda-pro01.run
> seek 0x77F6000005C8
> writes 0x1b9400091a40 8     # never returns within 15 min
```

The write-index round trip alone:

```
# Lean probe: spawn proxy, fetch window [0x1B9400091000, 0x1B9400092000)
ProxySession.fetchWindow { vaLo := 0x1B9400091000, vaHi := 0x1B9400092000,
                           t1 := 0, t2 := frontier }
# result: 570,597 records, 19 min 33 s
```

## Measurements (2026-08-14, warm file cache, WinDbg 10.0.29617.1000)

Same page window [0x1B9400091000, 0x1B9400092000), same trace:

| Path | Time | Output |
|---|---|---|
| E1 - pure engine: cdb -cf running `dx -r2 -u @$cursession.TTD.Memory(0x1b9400091000, 0x1b9400092000, "w")`, console redirected | **19 min 39.9 s** | 570,597 records / 7,988,442 lines / 297 MB |
| E2 - proxy end-to-end (Lean client -> ssh -> ttfx-proxy: capture + line parse + merge) | **19 min 33.4 s** | 570,597 records, 0 anomalies |

Cross-checks that rule out the alternatives:

- 8-byte window [0x1B9400091A40, 0x1B9400091A48) (same query): 246
  records, 3,528 lines, 138 KB - completes in ~8 s including trace open.
- Position seek `!tt 77F6:5C9` cost: **~7.6 ms/seek** (20 alternating
  seeks in one cdb session: 0.152 s total; open-only baseline 5.3-8.6 s).
- `READ_AT` full round trip (seek + ReadVirtual + protocol): **~1.2 s**.

E2 ~= E1 (delta ~= 6 s, noise). The proxy's Rust plumbing (IDebugOutputCallbacks
capture, WritesParser line parsing, merge/dedup - client-side user CPU
measured at 6.8 s) is **not** the bottleneck.

## Root cause

Three links, all confirmed:

1. **Unbounded time dimension.** The proxy's channel-C query is
   `dx -r2 -u @$cursession.TTD.Memory(lo, hi, "w")` - VA range only, **no
   position bounds**. The client's window (t1, t2) is applied as a
   post-filter in Rust (writes.retain(pos >= t1 && pos <= t2) in
   backend/dbgeng.rs write_index). Every WRITES_INDEX therefore
   enumerates the page's **complete trace-long write history**.
2. **This page is super-hot.** 570,597 write records on one 4 KiB page
   (the 8-byte probe range at +0xA40 holds 246 of them). The windowed-index
   design (D1) was cost-modeled on `hostname01.run`, whose hottest page has
   1,287 records - ~400x less. On 23 GB traces the per-page enumeration
   volume explodes.
3. **The dx data model materializes slowly.** The JS-provider-backed dx
   path expands each record's fields to text at ~250 KB/s aggregate (~2 ms
   per record); the engine process runs at ~1.6 ks CPU and 2.4 GB working
   set during the query. This is inherent to channel C's "dx text" form,
   not a proxy bug.

Design-level amplification: the client's dependency rule (index before page
read, D2) triggers one such full-history enumeration **per page touched** -
the first touch on a hot page is a ~20-minute stall with no progress
feedback in the current shell.

## Impact

- Interactive writes/valueAt/snapshot on large traces become
  unusable the moment a hot page is touched (any VA in it).
- snapshotAt (D4) pays the same cost per closure page.
- No client-side timeout/fan-out helps: the cost is paid inside one
  WRITES_INDEX request.

## Fix options (design-doc candidates, none implemented)

1. **Replay-API backend (P0' route, preferred).** Switch the proxy to the
   public MakeReplayEngine() COM API (TTDReplay.dll); use
   QueryMemoryBufferWithRanges for pieces (native per-range
   Sequences) and drop dx text parsing entirely ("native types in, no
   dx text parsing out", design sec.P0'). Write-index enumeration would still
   need a replacement source - to be validated against the API surface.
2. **Time-bounded index queries.** Investigate whether TTD.Memory (or a
   LINQ .Where over TimeStart, which the dx text channel can express)
   supports position filtering; validity intervals need only the last write
   <= t and the first write > t per page, not the full 570K history.
3. **Session/persistent index cache.** The client already caches fetched
   pages' horizons per session; extend to a cross-session cache (design
   sec.D8 v2 jigsaw-persistence was reserved for DUMP CACHE) so the
   20-minute enumeration is paid once, ever.
4. **Progress feedback.** Regardless of 1-3, the client could surface
   "indexing page ... (N records so far)" so a slow first touch reads as
   work, not a hang.

## Related observations

- Orphan proxies: killing the client mid-request leaves ttfx-proxy.exe
  running (blocked inside a long dx call, it never observes stdin EOF);
  observed twice (PIDs 33212, 6296) and killed manually with
  Stop-Process. A separate minor issue: the proxy should watch stdin
  EOF/ownership and self-terminate.

## References

- docs/trace/2026-08-12-lazy-trace-proxy-design.md - P0' (Replay API),
  D1 (windowed index), D2 (validity intervals + dependency rule), D4
  (derived region map), D5 (one truth source), "Unindexed traces" note.
- JigsawSpawner/src/backend/dbgeng.rs - write_index (dx query +
  post-filter), Capture/WritesParser, seek_to/read_at (channels B/C).
- Forensicator/Trace/{Index,Client}.lean - mergeWindow,
  ensurePages/ensureRange (dependency rule).

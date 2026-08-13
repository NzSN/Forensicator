/- Forensicator.Trace.Index — the client write index (design D1; spec
   JigSawSpawner.tla `idx_known`/`idx_F`). Pure and total.

   Windows of write *metadata* — `(pos, va, len)`, no payloads — arrive from
   the proxy (`WRITES_INDEX` → `INDEX`) and are merged into one record list
   sorted by `(pos, va, len)` and deduped on that exact key. Per-page
   horizons (`idx_F[p]`) record how far each page's index is complete; the
   jigsaw cache's validity intervals are computed from these views.

   Attach-time simplification (documented): the trace file is static, so the
   frontier never grows and every fetch uses the position window
   `[0, frontier]` — a fetched page's horizon is the frontier, and refresh
   never happens. The per-page window is still recorded so a violating
   re-fetch degrades into an `index window gap` anomaly instead of silent
   staleness (design D5). -/
import Forensicator.Model.Trace
import Forensicator.Trace.Proto
import Std.Data.HashMap

namespace Forensicator.Trace

/-- Jigsaw piece granularity: one 4 KiB page. -/
def pageSize : UInt64 := 0x1000

/-- Base address of the page containing `va`. -/
def pageBaseOf (va : VA) : VA := va &&& 0xFFFFFFFFFFFFF000

/-- Strict key order on write records: `(pos, va, len)` lexicographic. -/
def _root_.Forensicator.Model.WriteRecord.keyLT (a b : Model.WriteRecord) : Bool :=
  decide (a.pos < b.pos)
    || (a.pos == b.pos && (decide (a.va < b.va)
      || (a.va == b.va && decide (a.len < b.len))))

/-- Exact merge key equality (dedup key, design D1). -/
def _root_.Forensicator.Model.WriteRecord.keyEq (a b : Model.WriteRecord) : Bool :=
  a.pos == b.pos && a.va == b.va && a.len == b.len

/-- Merge two key-sorted record lists, keeping one copy of exact-key
    duplicates (windows overlap freely; the same write may be reported by
    two fetches). -/
def mergeRecords : List Model.WriteRecord → List Model.WriteRecord → List Model.WriteRecord
  | [], ys => ys
  | xs, [] => xs
  | x :: xs, y :: ys =>
    if x.keyLT y then x :: mergeRecords xs (y :: ys)
    else if y.keyLT x then y :: mergeRecords (x :: xs) ys
    else x :: mergeRecords xs ys
termination_by a b => a.length + b.length
decreasing_by all_goals (simp only [List.length_cons]; omega)

/-- One fetched index window (provenance + gap detection). -/
structure IndexWindow where
  vaLo : VA
  vaHi : VA
  t1 : Position
  t2 : Position
  deriving Repr, DecidableEq, BEq, Inhabited

/-- The accumulated client index. `records` is sorted by `(pos, va, len)`
    with no duplicate keys; `horizon`/`window` are per page base.
    `fullCoverage` is set once a full-space `[0, 2⁶⁴)` window has been
    merged (the fan-out collapse) — every page is then known up to
    `frontier` even without a per-page entry. -/
structure IndexState where
  records : List Model.WriteRecord := []
  /-- page base → `idx_F`: index complete for positions ≤ this horizon. -/
  horizon : Std.HashMap UInt64 Position := {}
  /-- page base → the position window that established the horizon. -/
  window : Std.HashMap UInt64 (Position × Position) := {}
  anomalies : List Anomaly := []
  /-- set by the last `mergeWindow` call (frontiers are static at attach). -/
  frontier : Position := 0
  fullCoverage : Bool := false

/-- The page's horizon: per-page entry, else the frontier under
    fullCoverage. -/
def IndexState.horizonOf (st : IndexState) (page : VA) : Option Position :=
  match st.horizon[page]? with
  | some h => some h
  | none => if st.fullCoverage then some st.frontier else none

/-- Does the index know page `page`'s writes up to `t` (spec NeedsIndex's
    negation: `idx_known[p] ∧ t ≤ idx_F[p]`)? -/
def IndexState.known (st : IndexState) (page : VA) (t : Position) : Bool :=
  (st.horizonOf page).map (fun h => decide (t ≤ h)) |>.getD false

/-- Record overlaps page `page`'s byte range? -/
def _root_.Forensicator.Model.WriteRecord.overlapsPage (w : Model.WriteRecord) (page : VA) : Bool :=
  decide (w.va.toNat < page.toNat + pageSize.toNat)
    && decide (page.toNat < w.endVaNat)

/-- Last known write position on `page` at or before `t`, or 0 (spec
    LastKnownWrite — only records within the page's horizon count). -/
def IndexState.lastKnownWrite (st : IndexState) (page : VA) (t : Position) : Position :=
  match st.horizonOf page with
  | none => 0
  | some h =>
    (st.records.filter fun w =>
      w.overlapsPage page && decide (w.pos ≤ h) && decide (w.pos ≤ t))
      |>.foldl (fun acc w => max acc w.pos) 0

/-- First known write position on `page` strictly after `t`, or the horizon
    sentinel `idx_F[page] + 1` (spec NextKnownWrite — validity never outruns
    knowledge). -/
def IndexState.nextKnownWrite (st : IndexState) (page : VA) (t : Position) : Position :=
  match st.horizonOf page with
  | none => 1
  | some h =>
    let later := st.records.filter fun w =>
      w.overlapsPage page && decide (w.pos ≤ h) && decide (t < w.pos)
    later.foldl (fun acc w => min acc w.pos) (h + 1)

/-- Known writes overlapping `[va, va+len)` in `(t1, t2]` — the index-level
    `Trace.writesBetween` shape over fetched metadata. -/
def IndexState.writesBetween (st : IndexState) (va : VA) (len : UInt64)
    (t1 t2 : Position) : List Model.WriteRecord :=
  st.records.filter fun w =>
    decide (t1 < w.pos ∧ w.pos ≤ t2
      ∧ w.va.toNat < va.toNat + len.toNat ∧ va.toNat < w.endVaNat)

/-- Above this many pages, per-page horizon/window bookkeeping is skipped
    for a wide window (the records still merge); the pages fall back to
    on-demand per-page fetches. Keeps a pathological full-space window from
    materializing 2⁵² map entries. -/
def maxMarkPages : UInt64 := 1048576

/-- Merge one fetched window (pure half of `WRITES_INDEX` → `INDEX`).
    Records beyond the frontier are dropped with an anomaly (fail closed);
    fully page-covered windows with `t1 = 0` establish/refresh per-page
    horizons, and a re-windowed page reports `index window gap`. -/
def IndexState.mergeWindow (st : IndexState) (win : IndexWindow)
    (recs : Array IndexRecord) (frontier : Position) : IndexState :=
  let prov : Provenance := { streamType := PROXY_STREAM_TYPE }
  let (late, ok) := recs.toList.partition (fun r => decide (frontier < r.pos))
  let beyondAnoms := late.map fun _ =>
    Anomaly.ofProv prov "index record beyond frontier"
  let fresh := (ok.map fun r =>
    ({ pos := r.pos, va := r.va, data := ByteArray.empty, len := r.len.toUInt64
       provenance := prov } : Model.WriteRecord)).mergeSort (fun a b => a.keyLT b || a.keyEq b)
  let records := mergeRecords st.records fresh
  -- Per-page bookkeeping for fully covered pages (bounded by maxMarkPages).
  let firstPage := pageBaseOf win.vaLo
  let lastPage := pageBaseOf (win.vaHi - 1)
  let pageCount := (lastPage - firstPage).toNat / pageSize.toNat + 1
  let (horizon, window, gapAnoms) :=
    if win.t1 != 0 || decide (win.vaHi ≤ win.vaLo)
        || decide (maxMarkPages.toNat < pageCount) then
      (st.horizon, st.window, [])
    else
      (List.range pageCount).foldl
        (fun (acc : Std.HashMap UInt64 Position × Std.HashMap UInt64 (Position × Position)
              × List Anomaly) i =>
          let (hz, wd, anoms) := acc
          let p := firstPage + UInt64.ofNat (i * pageSize.toNat)
          if decide (p.toNat < win.vaLo.toNat)
              || decide (p.toNat + pageSize.toNat > win.vaHi.toNat) then
            (hz, wd, anoms)  -- boundary page only partially covered
          else
            match wd[p]? with
            | some w' =>
              if w' == (win.t1, win.t2) then (hz, wd, anoms)
              else (hz, wd, anoms ++ [Anomaly.ofProv prov "index window gap"])
            | none =>
              (hz.insert p win.t2, wd.insert p (win.t1, win.t2), anoms))
        (st.horizon, st.window, [])
  { records, horizon, window
    anomalies := st.anomalies ++ beyondAnoms ++ gapAnoms
    frontier := frontier, fullCoverage := st.fullCoverage }

/-- Pages with any write ≤ `t` (design D4 step 1: the referenced
    closure), sorted and deduped. Wide writes contribute every page they
    span; empty-range records are skipped (fail closed). -/
def IndexState.closurePages (st : IndexState) (t : Position) : List VA :=
  let per := (st.records.filter fun w =>
      decide (w.pos ≤ t) && decide (w.va.toNat < w.endVaNat)).flatMap fun w =>
    let firstP := pageBaseOf w.va
    let n := (w.endVaNat - 1 - firstP.toNat) / pageSize.toNat + 1
    (List.range n).map fun i => firstP + UInt64.ofNat (i * pageSize.toNat)
  let sorted := per.mergeSort fun a b => decide (a ≤ b)
  (sorted.foldl (init := ([] : List VA)) fun acc p =>
    match acc with
    | last :: _ => if last == p then acc else p :: acc
    | [] => [p]).reverse

end Forensicator.Trace

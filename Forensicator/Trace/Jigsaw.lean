/- Forensicator.Trace.Jigsaw — the jigsaw cache (design D2/D3; spec
   JigSawSpawner.tla FetchPage/Evict). Pure and total.

   A piece is one 4 KiB page plus a validity interval `[lo, hi)` computed
   from the write index (`lo = lastKnownWrite p t`, `hi = nextKnownWrite
   p t`, sentinel `idx_F[p] + 1` — never outrun knowledge). ABSENT pieces
   are point intervals `[t, t+1)`: a read failure is a fact, not an error
   (D3). Eviction is LRU with a capacity cap; correctness never depends on
   retention (spec `Evict` is always enabled).

   Position domains (plan C3, Implementation notes):
   * model queries at `t` (eager convention: writes with `pos ≤ t` apply);
   * engine reads at `fetchPosition t frontier = min (t+1) frontier` —
     a write at `p` materializes at engine position `p+1`. A write exactly
     at the frontier never materializes in any engine state: the one
     documented position-level divergence.

   P3 pages (write records but never readable): `Client.fetchPage` retries
   at the *next* write's materialization position (`fallbackPosition`)
   before recording ABSENT; the interval is then computed at the fallback
   position, so the piece is honest about which model positions it serves. -/
import Forensicator.Trace.Index
import Std.Data.HashMap

namespace Forensicator.Trace

/-- One cached page. ABSENT pieces carry empty `bytes` and a point
    interval. -/
structure Piece where
  present : Bool
  bytes : ByteArray
  /-- validity lower bound (inclusive). -/
  lo : Position
  /-- validity upper bound (exclusive; the spec's `cache_hi`). -/
  hi : Position
  deriving Inhabited

/-- The jigsaw cache. `lru` is MRU-first; `capacity` in pages (default
    4096 = 16 MiB). -/
structure Jigsaw where
  pieces : Std.HashMap UInt64 Piece := {}
  lru : List UInt64 := []
  capacity : Nat := 4096
  anomalies : List Anomaly := {}

/-- Engine read position for a model query at `t` (p+1 write visibility,
    clamped at the frontier). -/
def fetchPosition (t frontier : Position) : Position := min (t + 1) frontier

/-- Fallback read position for P3-suspect pages (page has a known write
    ≤ t but read not-committed): the next known write's materialization
    position, clamped; `none` when no next write exists below the
    frontier. -/
def fallbackPosition (st : IndexState) (page : VA) (t frontier : Position) : Option Position :=
  let nw := st.nextKnownWrite page t
  if nw ≤ frontier then some (min (nw + 1) frontier) else none

namespace Jigsaw

/-- PRESENT piece whose interval covers `t` (spec KnownAt). -/
def knownAt (c : Jigsaw) (page : VA) (t : Position) : Bool :=
  match c.pieces[page]? with
  | some pc => pc.present && decide (pc.lo ≤ t) && decide (t < pc.hi)
  | none => false

/-- ABSENT point covering `t` (spec KnownAbsentAt). -/
def knownAbsentAt (c : Jigsaw) (page : VA) (t : Position) : Bool :=
  match c.pieces[page]? with
  | some pc => !pc.present && decide (pc.lo ≤ t) && decide (t < pc.hi)
  | none => false

/-- The host can say nothing about `(page, t)` (spec GapAt). -/
def gapAt (c : Jigsaw) (page : VA) (t : Position) : Bool :=
  !c.knownAt page t && !c.knownAbsentAt page t

/-- Page bytes when a PRESENT piece covers `t`. -/
def bytesAt (c : Jigsaw) (page : VA) (t : Position) : Option ByteArray :=
  match c.pieces[page]? with
  | some pc =>
    if pc.present && decide (pc.lo ≤ t) && decide (t < pc.hi)
    then some pc.bytes else none
  | none => none

/-- Mark `page` most-recently used; evict LRU entries beyond capacity. -/
private def touch (c : Jigsaw) (page : VA) : Jigsaw :=
  let lru := page :: (c.lru.filter (· != page))
  let rec dropWhile (n : Nat) (lru : List UInt64) (c : Jigsaw) : Jigsaw :=
    match n, lru with
    | 0, _ => { c with lru }
    | n + 1, lru =>
      match lru.getLast? with
      | none => { c with lru }
      | some last => dropWhile n lru.dropLast { c with pieces := c.pieces.erase last }
  if lru.length ≤ c.capacity then { c with lru }
  else dropWhile (lru.length - c.capacity) lru c

/-- Record a fetch outcome for model query position `t` (`some bytes` =
    PRESENT, `none` = ABSENT at `t`). Intervals come from the index
    (D2); a degenerate interval or out-of-frontier position degrades to
    an anomaly and the piece is not cached (fail closed). -/
def insertFetched (c : Jigsaw) (page : VA) (t : Position) (frontier : Position)
    (outcome : Option ByteArray) (st : IndexState) : Jigsaw :=
  let prov : Provenance := { streamType := PROXY_STREAM_TYPE }
  if frontier < t then
    { c with anomalies := c.anomalies ++ [Anomaly.ofProv prov "piece outside frontier"] }
  else
    match outcome with
    | none =>
      let pc : Piece := { present := false, bytes := ByteArray.empty, lo := t, hi := t + 1 }
      touch { c with pieces := c.pieces.insert page pc } page
    | some bytes =>
      let lo := st.lastKnownWrite page t
      let hi := st.nextKnownWrite page t
      if hi ≤ lo then
        { c with anomalies := c.anomalies ++ [Anomaly.ofProv prov "piece invalid interval"] }
      else
        let pc : Piece := { present := true, bytes, lo, hi }
        touch { c with pieces := c.pieces.insert page pc } page

/-- Drop a page (spec Evict: always safe). -/
def evict (c : Jigsaw) (page : VA) : Jigsaw :=
  { c with pieces := c.pieces.erase page, lru := c.lru.filter (· != page) }

end Jigsaw

end Forensicator.Trace

/- Forensicator.Analyzer.Scan — the pointer scanner (analyzer/scan.rs port). -/
import Forensicator.Analyzer.Analyzer
import Forensicator.Util.Pattern
import Forensicator.Util.Bytes

namespace Forensicator.Analyzer

open Forensicator.Model Forensicator.Spec

private def classifySource (region : AddressRegion) (sourceVa : VA)
    (stackRanges : List (UInt32 × VA × UInt64)) : SourceContext :=
  match region.classification with
  | .Stack =>
    .stack ((stackRanges.find? fun (_, sva, sz) =>
      decide (sva ≤ sourceVa ∧ sourceVa.toNat < sva.toNat + sz.toNat)).map (·.1))
  | .Private => .heap (some region.vaStart)
  | .Image => .moduleData none
  | .Mapped => .anyCommitted
  | .Other => .anyCommitted

private def classifyTarget (space : FastSpace) (va : VA) : TargetContext :=
  match space.classify va with
  | .Image => .image
  | .Stack => .stack
  | .Private => .heap
  | .Mapped => .mapped
  | .Other => .anyReadable

private def scanRegion (space : FastSpace) (stackRanges : List (UInt32 × VA × UInt64))
    (patterns : List PointerPattern) (region : AddressRegion) : List CandidatePointer :=
  go (region.data.size / 8 + 1) 0 [] |>.reverse
where
  -- accumulates in reverse (cons) for O(1) per hit
  go (fuel : Nat) (off : Nat) (acc : List CandidatePointer) : List CandidatePointer :=
    match fuel with
    | 0 => acc
    | fuel + 1 =>
    if off + 8 ≤ region.data.size then
      let value := readU64leAt region.data off
      if value == 0 then go fuel (off + 8) acc
      else
        let sourceVa := region.vaStart + UInt64.ofNat off
        let (matched, best) := patterns.foldl (init := (false, 0.0)) fun (st : Bool × Float) pat =>
          let (matched, best) := st
          if !pat.valueMatches value then (matched, best)
          else
            let conf :=
              (if value &&& 7 == 0 then 0.15 else 0.0)
                + (if (value >>> 48) == (if (value >>> 47) &&& 1 == 1 then 0xFFFF else 0x0000)
                    then 0.20 else 0.0)
                + (if (space.regionAt value).isSome then 0.25 else 0.0)
                + (if space.classify value == .Image then 0.15 else 0.0)
            if conf ≥ pat.minConfidence then (true, max best conf) else (matched, best)
        if matched then
          let cand : CandidatePointer :=
            { sourceVa := sourceVa, targetVa := value
              sourceCtx := classifySource region sourceVa stackRanges
              targetCtx := classifyTarget space value
              confidence := min best 1.0 }
          go fuel (off + 8) (cand :: acc)
        else go fuel (off + 8) acc
    else acc

/-- Scan committed regions for pattern-matching pointer values
    (scan.rs pointer_scan). -/
def pointerScan (space : AddressSpace) (dump : Dump) (patterns : List PointerPattern) :
    List CandidatePointer :=
  if patterns.isEmpty then []
  else
    let fs := FastSpace.ofSpace space
    let stackRanges := dump.threads.map fun t => (t.id, t.stackVa, t.stackSize)
    (space.regions.filter fun region => region.classification != .Other).flatMap fun region =>
      scanRegion fs stackRanges patterns region

/-- Candidates grouped by source VA: sorted-ascending keys, candidates in
    original order within each key (mergeSort is stable). -/
def groupBySourceFull (candidates : List CandidatePointer) : List (VA × List CandidatePointer) :=
  let sorted := candidates.mergeSort fun a b => decide (a.sourceVa ≤ b.sourceVa)
  let rec group (cs : List CandidatePointer) (cur : Option (VA × List CandidatePointer))
      (acc : List (VA × List CandidatePointer)) : List (VA × List CandidatePointer) :=
    match cs with
    | [] =>
      match cur with
      | none => acc.reverse
      | some (k, es) => ((k, es.reverse) :: acc).reverse
    | c :: rest =>
      match cur with
      | none => group rest (some (c.sourceVa, [c])) acc
      | some (k, es) =>
        if c.sourceVa == k then group rest (some (k, c :: es)) acc
        else group rest (some (c.sourceVa, [c])) ((k, es.reverse) :: acc)
  group sorted none []

/-- Candidate edges grouped by source VA. -/
def groupBySource (candidates : List CandidatePointer) : List (VA × List (VA × Float)) :=
  (groupBySourceFull candidates).map fun (k, cs) =>
    (k, cs.map fun c => (c.targetVa, c.confidence))

/-- Sorted-unique VAs (Rust `sort(); dedup()`). -/
def sortedUnique (vs : List VA) : List VA :=
  (vs.mergeSort fun a b => decide (a ≤ b)).foldl
    (fun acc v => match acc with
      | [] => [v]
      | h :: _ => if h == v then acc else v :: acc) []
    |>.reverse

/-- Binary-search edge lookup over the grouped adjacency (as an Array). -/
def lookupEdges (adj : Array (VA × List (VA × Float))) (va : VA) : List (VA × Float) :=
  let rec go (fuel lo hi : Nat) : Nat :=
    match fuel with
    | 0 => lo
    | fuel + 1 =>
      if lo < hi then
        let mid := (lo + hi) / 2
        if adj[mid]!.1 ≤ va then go fuel (mid + 1) hi else go fuel lo mid
      else lo
  let k := go (adj.size + 1) 0 adj.size
  if k == 0 then []
  else
    let (key, es) := adj[k - 1]!
    if key == va then es else []

end Forensicator.Analyzer

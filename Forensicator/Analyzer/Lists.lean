/- Forensicator.Analyzer.Lists — linked-list detection by chain chasing
   (analyzer/lists.rs port). -/
import Forensicator.Analyzer.Scan
import Std.Data.HashSet

namespace Forensicator.Analyzer.Lists

open Forensicator.Model Forensicator.Spec

structure Config where
  minLength : Nat := 3
  minConfidence : Float := 0.4
  maxChainLength : Nat := 10000

/-- Adjacency: source VA → edges, sorted keys, candidate order per key. -/
private def buildAdj (candidates : List CandidatePointer) : List (VA × List (VA × Float)) :=
  groupBySource candidates

/-- Highest-confidence edge; LAST maximal element on ties (Rust max_by). -/
private def bestEdge (es : List (VA × Float)) : Option (VA × Float) :=
  es.foldl (fun best e =>
    match best with
    | none => some e
    | some b => if e.2 ≥ b.2 then some e else some b) none

private def walk (cfg : Config) (adj : Array (VA × List (VA × Float)))
    (fuel : Nat) (visited : Std.HashSet VA) (current : VA) (chain : List VA) :
    List VA × Std.HashSet VA :=
  match fuel with
  | 0 => (chain, visited)
  | fuel + 1 =>
    match lookupEdges adj current with
    | [] => (chain, visited)
    | outEdges =>
      match bestEdge outEdges with
      | none => (chain, visited)
      | some (next, conf) =>
        if conf < cfg.minConfidence || visited.contains next
            || chain.length ≥ cfg.maxChainLength then (chain, visited)
        else walk cfg adj fuel (visited.insert next) next (chain ++ [next])

private def outer (cfg : Config) (adjArr : Array (VA × List (VA × Float)))
    (keys : List VA) (visited : Std.HashSet VA) (acc : List StructLinkedList) :
    List StructLinkedList :=
  match keys with
  | [] => acc
  | k :: rest =>
    let edgesK := lookupEdges adjArr k
    if edgesK.isEmpty || visited.contains k then outer cfg adjArr rest visited acc
    else
      let (chain, visited') := walk cfg adjArr (cfg.maxChainLength + 1) (visited.insert k) k [k]
      if chain.length ≥ cfg.minLength then
        let stride : UInt64 := if chain.length ≥ 2 then chain[1]! - chain[0]! else 0
        let entry : StructLinkedList :=
          { headVa := k, length := chain.length, stride := stride
            nextOffset := 0, isCircular := false
            nodes := chain, avgConfidence := 0.5 }
        outer cfg adjArr rest visited' (acc ++ [entry])
      else outer cfg adjArr rest visited' acc

private def detect (cfg : Config) (candidates : List CandidatePointer) : List StructLinkedList :=
  let adj := buildAdj candidates
  outer cfg adj.toArray (adj.map (·.1)) Std.HashSet.emptyWithCapacity []

/-- Chases pointer chains to find linked lists in heap memory. -/
def analyzer (cfg : Config := {}) : Analyzer where
  name := "lists"
  description := "Chases pointer chains to find linked lists in heap memory"
  run dump space :=
    { AnalyzerOutput.new "lists" with
      linkedLists := detect cfg
        (pointerScan space dump [PointerPattern.heapReferences]) }

end Forensicator.Analyzer.Lists

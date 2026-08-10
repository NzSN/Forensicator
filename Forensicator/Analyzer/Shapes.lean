/- Forensicator.Analyzer.Shapes — heap node clustering by structural
   signature (analyzer/shapes.rs port).

   Determinism note: Rust builds sig_to_nodes in HashMap iteration order,
   so group ids for equal member_count are nondeterministic run-to-run.
   This port assigns ids in sorted-node order (deterministic); the
   conformance gate compares the member-count multiset. -/
import Forensicator.Analyzer.Scan
import Std.Data.HashMap


namespace Forensicator.Analyzer.Shapes

open Forensicator.Model Forensicator.Spec

/-- Hashable instances for shape grouping (Rust derives Hash). -/
instance : Hashable RegionClass where
  hash
    | .Image => 1 | .Stack => 2 | .Mapped => 3 | .Private => 4 | .Other => 5

instance : Hashable ShapeSignature where
  hash s := s.edges.foldl (fun h e => mixHash h (hash e)) (hash ())

private def regionClassFromTarget : TargetContext → RegionClass
  | .image => .Image
  | .stack => .Stack
  | .heap => .Private
  | .mapped => .Mapped
  | .anyReadable => .Other

private def detect (candidates : List CandidatePointer) : List ShapeGroup :=
  let adj := groupBySourceFull candidates
  let m := adj.foldl (init := (Std.HashMap.emptyWithCapacity : Std.HashMap ShapeSignature (List VA)))
    fun acc (nodeVa, edges) =>
      let meaningful := edges.filter fun c => c.targetVa != 0
      if meaningful.isEmpty then acc
      else
        let sigEdges := (meaningful.map fun c =>
            (c.targetVa - nodeVa, regionClassFromTarget c.targetCtx)).mergeSort
            fun a b => decide (a.1 ≤ b.1)
        acc.alter ⟨sigEdges⟩ fun
          | none => some [nodeVa]
          | some ms => some (nodeVa :: ms)
  let groups := m.toList.zipIdx.map fun ((sig, members), id) =>
    ({ id := id, signature := sig, memberCount := members.length
       members := members.reverse } : ShapeGroup)
  groups.mergeSort fun a b => decide (b.memberCount ≤ a.memberCount)

/-- Clusters heap nodes by structural signature (offset→target_class edges). -/
def analyzer : Analyzer where
  name := "shapes"
  description := "Clusters heap nodes by structural signature (offset→target_class edges)"
  run dump space :=
    { AnalyzerOutput.new "shapes" with
      shapeClusters := detect (pointerScan space dump [PointerPattern.heapReferences]) }

end Forensicator.Analyzer.Shapes

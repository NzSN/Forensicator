/- Forensicator.Analyzer.Arrays — regular-stride pointer-target grouping
   (analyzer/arrays.rs port). -/
import Forensicator.Analyzer.Scan

namespace Forensicator.Analyzer.Arrays

open Forensicator.Model Forensicator.Spec

structure Config where
  minCount : Nat := 3
  maxStride : UInt64 := 4096

private def countOut (adj : Array (VA × List (VA × Float))) (va : VA) : Nat :=
  (lookupEdges adj va).length

private def extend (cfg : Config) (space : FastSpace) (adj : Array (VA × List (VA × Float)))
    (vas : Array VA) (stride : UInt64) (aClass : RegionClass) (aOut : Nat)
    (fuel j : Nat) (last : VA) (els : List VA) : Nat × List VA :=
  match fuel with
  | 0 => (j, els)
  | fuel + 1 =>
    if j < vas.size then
      let cur := vas[j]!
      if cur != last + stride then (j, els)
      else if space.classify cur != aClass then (j, els)
      else if countOut adj cur != aOut then (j, els)
      else extend cfg space adj vas stride aClass aOut fuel (j + 1) cur (els ++ [cur])
    else (j, els)

private def go (cfg : Config) (space : FastSpace) (adj : Array (VA × List (VA × Float)))
    (vas : Array VA) (fuel i : Nat) (acc : List StructArray) : List StructArray :=
  match fuel with
  | 0 => acc
  | fuel + 1 =>
  if i + cfg.minCount ≤ vas.size then
    let a := vas[i]!
    let b := vas[i + 1]!
    if a ≥ b then go cfg space adj vas fuel (i + 1) acc
    else
      let stride := b - a
      if stride > cfg.maxStride || stride == 0 then go cfg space adj vas fuel (i + 1) acc
      else
        let aClass := space.classify a
        let bClass := space.classify b
        if aClass != bClass then go cfg space adj vas fuel (i + 1) acc
        else
          let aOut := countOut adj a
          let bOut := countOut adj b
          if aOut != bOut then go cfg space adj vas fuel (i + 1) acc
          else
            let (j, elements) := extend cfg space adj vas stride aClass aOut (vas.size + 1) (i + 2) b [a, b]
            if elements.length ≥ cfg.minCount then
              let conf := if elements.length ≥ 5 then 0.85 else 0.6
              let entry : StructArray :=
                { startVa := a, elementSize := stride, count := elements.length
                  outDegree := aOut, regionClass := aClass
                  elements := elements, confidence := conf }
              go cfg space adj vas fuel j (acc ++ [entry])
            else go cfg space adj vas fuel (i + 1) acc
  else acc

private def detect (cfg : Config) (space : FastSpace) (candidates : List CandidatePointer) :
    List StructArray :=
  let adj := (groupBySource candidates).toArray
  let vas := Analyzer.sortedUnique (candidates.map (·.sourceVa))
  if vas.length < cfg.minCount then []
  else go cfg space adj vas.toArray (vas.length + 1) 0 []

/-- Groups pointer targets with regular stride into arrays. -/
def analyzer (cfg : Config := {}) : Analyzer where
  name := "arrays"
  description := "Groups pointer targets with regular stride into arrays"
  run dump space :=
    let fs := FastSpace.ofSpace space
    { AnalyzerOutput.new "arrays" with
      arrays := detect cfg fs (pointerScan space dump [PointerPattern.heapReferences]) }

end Forensicator.Analyzer.Arrays

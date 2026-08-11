/- Forensicator.Analyzer.Chunks — heap allocation chunk inference by pointer
   density (analyzer/chunks.rs port). -/
import Forensicator.Analyzer.Scan

namespace Forensicator.Analyzer.Chunks

open Forensicator.Model Forensicator.Spec

structure Config where
  minChunkSize : UInt64 := 16
  alignment : UInt64 := 16
  densityGapThreshold : UInt64 := 64
  zeroRunForFree : Nat := 32

private def gapSplit (cfg : Config) (regionEnd : VA) (rest : List VA)
    (chunkStart prev : VA) (acc : List StructChunk) : VA × VA × List StructChunk :=
  match rest with
  | [] => (chunkStart, prev, acc)
  | va :: rest' =>
    if va - prev > cfg.densityGapThreshold then
      let sz := min (prev - chunkStart + 16) (regionEnd - chunkStart)
      gapSplit cfg regionEnd rest' va va (acc ++ [{
        vaStart := chunkStart, size := sz, isFree := false
        nodeCount := 1
        pointerDensity := if sz > 0 then 1.0 / Float.ofNat sz.toNat * 1024.0 else 0.0
        confidence := 0.6 }])
    else gapSplit cfg regionEnd rest' chunkStart va acc

private def detect (cfg : Config) (space : AddressSpace) (candidates : List CandidatePointer) :
    List StructChunk :=
  space.regions.foldl (init := []) fun acc region =>
    if region.classification != .Private || region.size < cfg.minChunkSize then acc
    else acc ++ detectInRegion cfg region candidates
where
  detectInRegion (cfg : Config) (region : AddressRegion) (candidates : List CandidatePointer) :
      List StructChunk :=
    let nodes := (candidates.filter fun c =>
        decide (c.sourceVa ≥ region.vaStart ∧ c.sourceVa.toNat < region.vaStart.toNat + region.size.toNat))
      |>.map (·.sourceVa)
      |> Analyzer.sortedUnique
    if nodes.isEmpty then
      let isFree := (region.data.toList.take cfg.zeroRunForFree).all (· == 0)
      [{ vaStart := region.vaStart, size := region.size, isFree := isFree
         nodeCount := 0, pointerDensity := 0.0
         confidence := if isFree then 0.8 else 0.3 }]
    else
      let regionEnd := region.vaStart + region.size
      let (results, chunkStart, prevVa) :=
        -- initial gap chunk
        let first := nodes.head!
        if first > region.vaStart + cfg.densityGapThreshold then
          ([{ vaStart := region.vaStart, size := first - region.vaStart
              isFree := true, nodeCount := 0, pointerDensity := 0.0
              confidence := 0.7 }], first, first)
        else ([], region.vaStart, first)
      -- gap-splitting loop over the remaining nodes
      let (finalStart, finalPrev, results2) :=
        gapSplit cfg regionEnd (nodes.drop 1) chunkStart prevVa results
      let sz := min (finalPrev - finalStart + 16) (regionEnd - finalStart)
      results2 ++ [{ vaStart := finalStart, size := sz, isFree := false
                     nodeCount := 1, pointerDensity := 0.0, confidence := 0.5 }]

/-- Identifies heap allocation chunks by pointer density in Private regions. -/
def analyzer (cfg : Config := {}) : Analyzer where
  name := "chunks"
  description := "Identifies heap allocation chunks by pointer density in Private regions"
  run dump space :=
    { AnalyzerOutput.new "chunks" with
      chunks := detect cfg space (pointerScan space dump [PointerPattern.heapReferences]) }

end Forensicator.Analyzer.Chunks

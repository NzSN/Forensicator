import Forensicator
open Forensicator Forensicator.Parse Forensicator.Model Forensicator.Spec
def main : IO Unit := do
  let f := "/home/nzsn/Repos/Forensicator/Case/fulldump/ed633e36-d254-43d4-b30a-23396ebbf6a2.dmp"
  let data ← IO.FS.readBinFile f
  match Minidump.fromBytes data with
  | .error _ => IO.println "decode fail"
  | .ok dump =>
    let space := buildAddressSpace dump
    let fs := FastSpace.ofSpace space
    let pat := PointerPattern.heapReferences
    let t0 ← IO.monoMsNow
    -- window count + match count WITHOUT building the candidate list
    let mut wins := 0
    let mut hits := 0
    for region in space.regions do
      if region.classification == .Other then continue
      let d := region.data
      let mut off := 0
      while off + 8 ≤ d.size do
        let v := readU64leAt d off
        if v != 0 then
          wins := wins + 1
          if pat.valueMatches v then
            hits := hits + 1
        off := off + 8
    IO.println s!"wins {wins} hits {hits} ms {(← IO.monoMsNow) - t0}"

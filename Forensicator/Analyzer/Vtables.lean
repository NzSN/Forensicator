/- Forensicator.Analyzer.Vtables — vtable detection in Image regions
   (analyzer/vtables.rs port). -/
import Forensicator.Analyzer.Scan
import Forensicator.Util.Bytes

namespace Forensicator.Analyzer.Vtables

open Forensicator.Model Forensicator.Spec

structure Config where
  minMethods : Nat := 3
  maxMethods : Nat := 256

private def collectRun (cfg : Config) (space : FastSpace) (region : AddressRegion)
    (fuel runOff : Nat) (methods : List UInt64) : Nat × List UInt64 :=
  match fuel with
  | 0 => (runOff, methods)
  | fuel + 1 =>
    if runOff + 8 ≤ region.data.size && methods.length < cfg.maxMethods then
      let v := readU64leAt region.data runOff
      if v == 0 || space.classify v != .Image then (runOff, methods)
      else collectRun cfg space region fuel (runOff + 8) (methods ++ [v])
    else (runOff, methods)

private def detectGo (cfg : Config) (space : FastSpace) (region : AddressRegion)
    (fuel off : Nat) (acc : List StructVTable) : List StructVTable :=
  match fuel with
  | 0 => acc
  | fuel + 1 =>
    if off + 8 ≤ region.data.size then
      let value := readU64leAt region.data off
      if value == 0 || space.classify value != .Image then detectGo cfg space region fuel (off + 8) acc
      else
        let (runOff, methods) := collectRun cfg space region (region.data.size / 8 + 1) (off + 8) [value]
        if methods.length ≥ cfg.minMethods then
          let vt : StructVTable :=
            { va := region.vaStart + UInt64.ofNat off
              methodCount := methods.length, methods := methods
              moduleName := none, confidence := 0.8 }
          detectGo cfg space region fuel runOff (acc ++ [vt])
        else detectGo cfg space region fuel (off + 8) acc
    else acc

/-- Scans Image-region data for aligned function pointers forming vtables. -/
def analyzer (cfg : Config := {}) : Analyzer where
  name := "vtables"
  description := "Scans Image-region data for aligned function pointers forming vtables"
  run _dump space :=
    let fs := FastSpace.ofSpace space
    { AnalyzerOutput.new "vtables" with
      vtables := space.regions.foldl (init := []) fun acc region =>
        if region.classification != .Image then acc
        else acc ++ detectGo cfg fs region (region.data.size / 8 + 1) 0 [] }

end Forensicator.Analyzer.Vtables

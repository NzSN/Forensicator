/- Forensicator.Analyzer.Analyzer — the analyzer framework (analyzer.rs port):
   Analyzer as a record, AnalyzerOutput, StructureCatalog, Pipeline.

   No catch_unwind equivalent: the ported analyzers are total (all indexing
   is bounds-guarded), so the panic-isolation branch is unreachable. -/
import Forensicator.Model.Structs
import Forensicator.Spec.AddressSpace
import Forensicator.Model.Dump
import Forensicator.Util.Json

namespace Forensicator

open Model Spec

structure AnalyzerOutput where
  pluginName : String
  strings : List StructString := []
  vtables : List StructVTable := []
  linkedLists : List StructLinkedList := []
  arrays : List StructArray := []
  chunks : List StructChunk := []
  shapeClusters : List ShapeGroup := []
  custom : List (String × Json) := []
  deriving Inhabited

def AnalyzerOutput.new (pluginName : String) : AnalyzerOutput := { pluginName }

/-- Total finding count (the CLI's "count"/"results" figure). -/
def AnalyzerOutput.count (o : AnalyzerOutput) : Nat :=
  o.strings.length + o.vtables.length + o.linkedLists.length
    + o.arrays.length + o.chunks.length + o.shapeClusters.length

structure Analyzer where
  name : String
  description : String := "no description"
  run : Dump → AddressSpace → AnalyzerOutput

structure StructureCatalog where
  outputs : List AnalyzerOutput
  deriving Inhabited

namespace StructureCatalog
def empty : StructureCatalog := ⟨[]⟩
def allStrings (c : StructureCatalog) : List StructString :=
  c.outputs.flatMap (·.strings)
def allVtables (c : StructureCatalog) : List StructVTable :=
  c.outputs.flatMap (·.vtables)
def allLinkedLists (c : StructureCatalog) : List StructLinkedList :=
  c.outputs.flatMap (·.linkedLists)
def allArrays (c : StructureCatalog) : List StructArray :=
  c.outputs.flatMap (·.arrays)
def allChunks (c : StructureCatalog) : List StructChunk :=
  c.outputs.flatMap (·.chunks)
def allShapeClusters (c : StructureCatalog) : List ShapeGroup :=
  c.outputs.flatMap (·.shapeClusters)
end StructureCatalog

def runPipeline (analyzers : List Analyzer) (dump : Dump) (space : AddressSpace)
    (filter : List String) : StructureCatalog :=
  let selected :=
    if filter.isEmpty then analyzers
    else analyzers.filter fun a => filter.contains a.name
  ⟨selected.map fun a => a.run dump space⟩

end Forensicator

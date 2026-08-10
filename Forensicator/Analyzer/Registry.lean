/- Forensicator.Analyzer.Registry — the default pipeline
   (analyzer.rs default_pipeline). cause/v8 register with their final
   names+descriptions; their logic lands in Tasks 8/9 (stubs emit empty
   outputs, so list-plugins is already faithful). -/
import Forensicator.Analyzer.Strings
import Forensicator.Analyzer.Vtables
import Forensicator.Analyzer.Lists
import Forensicator.Analyzer.Arrays
import Forensicator.Analyzer.Chunks
import Forensicator.Analyzer.Shapes

namespace Forensicator

/-- Stub until Task 8 (CrashCauseAnalyzer port). -/
def causeAnalyzer : Analyzer where
  name := "cause"
  description := "Diagnoses why the process crashed: exception semantics, disassembly, cage fault analysis"
  run _ _ := AnalyzerOutput.new "cause"

/-- Stub until Task 9 (V8Analyzer port). -/
def v8Analyzer : Analyzer where
  name := "v8"
  description := "Recovers JS stack traces by walking native stacks and classifying V8 frames"
  run _ _ := AnalyzerOutput.new "v8"

/-- The default analyzer set, in registration order (analyzer.rs:102). -/
def defaultPipeline : List Analyzer :=
  [causeAnalyzer, Analyzer.Strings.analyzer, Analyzer.Vtables.analyzer, Analyzer.Lists.analyzer,
   Analyzer.Arrays.analyzer, Analyzer.Chunks.analyzer, Analyzer.Shapes.analyzer, v8Analyzer]

end Forensicator

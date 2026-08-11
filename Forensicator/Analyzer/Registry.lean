/- Forensicator.Analyzer.Registry — the default pipeline
   (analyzer.rs default_pipeline). -/
import Forensicator.Analyzer.Strings
import Forensicator.Analyzer.Vtables
import Forensicator.Analyzer.Lists
import Forensicator.Analyzer.Arrays
import Forensicator.Analyzer.Chunks
import Forensicator.Analyzer.Shapes
import Forensicator.Analyzer.Cause
import Forensicator.Analyzer.V8

namespace Forensicator

/-- The default analyzer set, in registration order (analyzer.rs:102). -/
def defaultPipeline : List Analyzer :=
  [Analyzer.Cause.analyzer, Analyzer.Strings.analyzer, Analyzer.Vtables.analyzer, Analyzer.Lists.analyzer,
   Analyzer.Arrays.analyzer, Analyzer.Chunks.analyzer, Analyzer.Shapes.analyzer, Analyzer.V8.analyzer]

end Forensicator

import Test.Spec
import Test.Publics
import Test.Symbols
import Test.Execution
import Test.ExecutionAnalyzers
import Test.ExecutionProxy
import Test.Timeline

def main (_args : List String) : IO UInt32 := do
  IO.FS.createDirAll "tmp"
  let nExecution ← Test.Execution.runAll
  let nAnalyzers ← Test.ExecutionAnalyzers.runAll
  let nProxy ← Test.ExecutionProxy.runAll
  let nTimeline ← Test.Timeline.runAll
  let nSpec ← Test.Spec.runAll
  let nPub ← Test.Publics.runAll
  let nSym ← Test.Symbols.runAll
  pure (nExecution + nAnalyzers + nProxy + nTimeline + nSpec + nPub + nSym)

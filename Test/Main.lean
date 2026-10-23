import Test.Spec
import Test.Publics
import Test.Symbols
import Test.Execution
import Test.ExecutionAnalyzers
import Test.ExecutionProxy
import Test.Timeline
import Test.Digest
import Test.Observation
import Test.Stack
import Test.StackSession
import Test.MemoryPayload
import Test.Image
import Test.Mcp

def main (_args : List String) : IO UInt32 := do
  IO.FS.createDirAll "tmp"
  let nMcp ← Test.Mcp.runAll
  let nExecution ← Test.Execution.runAll
  let nAnalyzers ← Test.ExecutionAnalyzers.runAll
  let nProxy ← Test.ExecutionProxy.runAll
  let nTimeline ← Test.Timeline.runAll
  let nDigest ← Test.Digest.runAll
  let nObservation ← Test.Observation.runAll
  let nStack ← Test.Stack.runAll
  let nStackSession ← Test.StackSession.runAll
  let nMemoryPayload ← Test.MemoryPayload.runAll
  let nImage ← Test.Image.runAll
  let nSpec ← Test.Spec.runAll
  let nPub ← Test.Publics.runAll
  let nSym ← Test.Symbols.runAll
  pure (nMcp + nExecution + nAnalyzers + nProxy + nTimeline + nDigest + nObservation + nStack + nStackSession + nMemoryPayload + nImage + nSpec + nPub + nSym)

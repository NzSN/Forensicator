import Test.Spec
import Test.Publics

def main (_args : List String) : IO UInt32 := do
  let nSpec ← Test.Spec.runAll
  let nPub ← Test.Publics.runAll
  pure (nSpec + nPub)

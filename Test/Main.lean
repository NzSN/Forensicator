import Test.Spec
import Test.Publics
import Test.Symbols

def main (_args : List String) : IO UInt32 := do
  let nSpec ← Test.Spec.runAll
  let nPub ← Test.Publics.runAll
  let nSym ← Test.Symbols.runAll
  pure (nSpec + nPub + nSym)

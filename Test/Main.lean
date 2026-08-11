import Test.Spec

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--emit", path] => Test.Spec.emitMinimal path
  | _ => Test.Spec.runAll

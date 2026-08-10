import Forensicator
def main : IO Unit := do
  let data ← IO.FS.readBinFile "/home/nzsn/Repos/Forensicator/Case/minidump/electron.exe.pdb"
  match Forensicator.Util.pdbIdentity data with
  | .ok (age, guid) => IO.println s!"age={age} guid={guid.toList.map (fun b => Forensicator.hexPadLower b.toUInt64 2)}"
  | .error e => IO.println s!"error: {e}"

import Forensicator
def main : IO Unit := do
  let data ← IO.FS.readBinFile "/home/nzsn/Repos/Forensicator/Case/minidump/electron.exe.pdb"
  let m : ByteArray := "Microsoft C/C++ MSF 7.00".toUTF8
    ++ ByteArray.mk #[0x0D, 0x0A, 0x1A] ++ "DS".toUTF8 ++ ByteArray.mk (Array.replicate 3 0)
  IO.println s!"magic size {m.size}"
  let fileHead := data.extract 0 32
  IO.println s!"eq: {fileHead == m}"
  IO.println s!"file: {fileHead.toList.map (fun b => Forensicator.hexPadLower b.toUInt64 2)}"
  IO.println s!"mine: {m.toList.map (fun b => Forensicator.hexPadLower b.toUInt64 2)}"

/- Whole-file minidump guards for captured payload identity and bounds.
   Declared lengths cannot create bytes absent from the dump. -/
import Forensicator.Model.Capture
import Forensicator.Parse.Minidump
import Forensicator.Pipeline

namespace Test.MemoryPayload

open Forensicator Forensicator.Model

private def le32 (value : UInt32) : List UInt8 :=
  (List.range 4).map fun i => (value >>> (8 * UInt32.ofNat i)).toUInt8

private def le64 (value : UInt64) : List UInt8 :=
  (List.range 8).map fun i => (value >>> (8 * UInt64.ofNat i)).toUInt8

private def streamRva : Nat := 96
private def payloadGap : Nat := 11

/-- The stream and payload both start away from file offset zero; payload
    bytes lie outside the directory's stream slice, as in native dumps. -/
private def singleStream (streamType : UInt32) (stream payload : List UInt8) : ByteArray :=
  let header := le32 0x504D444D ++ le32 0xA793 ++ le32 1 ++ le32 32
    ++ List.replicate 16 0
  let directory := le32 streamType ++ le32 (UInt32.ofNat stream.length)
    ++ le32 (UInt32.ofNat streamRva)
  ByteArray.mk (header ++ directory ++ List.replicate (streamRva - 44) 0
    ++ stream ++ List.replicate payloadGap 0xCC ++ payload).toArray

private def memory64 (ranges : List (UInt64 × UInt64)) (payload : List UInt8)
    (baseRva : Option UInt64 := none) : ByteArray :=
  let payloadRva := baseRva.getD (UInt64.ofNat (streamRva + 16 + ranges.length * 16 + payloadGap))
  let stream := le64 (UInt64.ofNat ranges.length) ++ le64 payloadRva
    ++ ranges.flatMap (fun (va, size) => le64 va ++ le64 size)
  singleStream 9 stream payload

private def memoryList (ranges : List (UInt64 × UInt32)) (payload : List UInt8)
    (baseRva : Option UInt32 := none) : ByteArray :=
  let payloadRva := baseRva.getD (UInt32.ofNat (streamRva + 4 + ranges.length * 16 + payloadGap))
  let (_, entries) := ranges.foldl (fun (offset, acc) (va, size) =>
    (offset + size.toNat,
      acc ++ le64 va ++ le32 size ++ le32 (payloadRva + UInt32.ofNat offset))) (0, [])
  singleStream 5 (le32 (UInt32.ofNat ranges.length) ++ entries) payload

private def bytesAt (dump : Dump) (va : VA) (size : Nat) : Option (List UInt8) :=
  let input := AnalysisInput.ofDump dump (buildAddressSpace dump) "payload-fixture"
  match input.point.memory.read va size with
  | .known bytes => some bytes.toList
  | _ => none

private def hasBytes (file : ByteArray) (expected : List (VA × List UInt8)) : Bool :=
  match Parse.Minidump.fromBytes file with
  | .error _ => false
  | .ok dump => dump.anomalies.isEmpty
      && dump.memoryRegions.length == expected.length
      && expected.all (fun (va, bytes) => bytesAt dump va bytes.length == some bytes)

/-- Payload failure is a recoverable, provenance-bearing stream anomaly.
    Reject the complete malformed stream, including any earlier valid ranges. -/
private def rejectsPayload (file : ByteArray) (streamType : UInt32)
    (descriptorOffset descriptorIndex : Nat) : Bool :=
  match Parse.Minidump.fromBytes file with
  | .error _ => false
  | .ok dump =>
    let input := AnalysisInput.ofDump dump (buildAddressSpace dump) "payload-fixture"
    dump.memoryRegions.isEmpty
      && dump.anomalies.any (fun a => a.streamType == streamType
        && a.fileOffset == UInt64.ofNat (streamRva + descriptorOffset)
        && a.rva == UInt64.ofNat descriptorIndex
        && a.description.startsWith (if streamType == 9 then "Memory64List payload" else "MemoryList payload"))
      && (match input.point.memory.read 0x1000 1 with | .unknown => true | _ => false)

private def check (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    memory-payload {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  memory-payload {name}"

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let assert := check failures
  assert "Memory64 BaseRva reads the whole file, preserving nonzero bytes"
    (hasBytes (memory64 [(0x1000, 4)] [0x11, 0x22, 0x33, 0x44])
      [(0x1000, [0x11, 0x22, 0x33, 0x44])])
  assert "Memory64 consecutive ranges advance by each advertised payload size"
    (hasBytes (memory64 [(0x1000, 3), (0x2000, 2), (0x3000, 4)]
        [0x11, 0, 0x33, 0x44, 0x55, 0x66, 0x77, 0, 0x99])
      [(0x1000, [0x11, 0, 0x33]), (0x2000, [0x44, 0x55]), (0x3000, [0x66, 0x77, 0, 0x99])])
  assert "MemoryList reads descriptor RVAs from the whole file"
    (hasBytes (memoryList [(0x1000, 3), (0x2000, 2)] [0x11, 0, 0x33, 0x44, 0x55])
      [(0x1000, [0x11, 0, 0x33]), (0x2000, [0x44, 0x55])])
  assert "genuine captured zeros remain known for both memory formats"
    (hasBytes (memory64 [(0x1000, 3)] [0, 0, 0]) [(0x1000, [0, 0, 0])]
      && hasBytes (memoryList [(0x1000, 3)] [0, 0, 0]) [(0x1000, [0, 0, 0])])

  assert "Memory64 partially missing payload rejects the stream"
    (rejectsPayload (memory64 [(0x1000, 4)] [0x11, 0x22]) 9 16 0)
  assert "Memory64 fully missing payload rejects the stream"
    (rejectsPayload (memory64 [(0x1000, 4)] []) 9 16 0)
  assert "Memory64 malformed later range cannot retain an earlier partial stream"
    (rejectsPayload (memory64 [(0x1000, 2), (0x2000, 3)] [0x11, 0x22, 0x33]) 9 32 1)
  assert "Memory64 enormous length is checked before any allocation"
    (rejectsPayload (memory64 [(0x1000, 0xFFFFFFFFFFFFFFFF)] [0x11]) 9 16 0)
  assert "Memory64 enormous BaseRva cannot wrap into captured bytes"
    (rejectsPayload (memory64 [(0x1000, 4)] [0x11, 0x22, 0x33, 0x44]
      (some 0xFFFFFFFFFFFFFFFF)) 9 16 0)

  assert "MemoryList partially missing payload rejects the stream"
    (rejectsPayload (memoryList [(0x1000, 4)] [0x11, 0x22]) 5 4 0)
  assert "MemoryList fully missing payload rejects the stream"
    (rejectsPayload (memoryList [(0x1000, 4)] []) 5 4 0)
  assert "MemoryList malformed later range cannot retain an earlier partial stream"
    (rejectsPayload (memoryList [(0x1000, 2), (0x2000, 3)] [0x11, 0x22, 0x33]) 5 20 1)
  assert "MemoryList enormous length is checked before any allocation"
    (rejectsPayload (memoryList [(0x1000, 0xFFFFFFFF)] [0x11]) 5 4 0)
  assert "MemoryList out-of-file RVA cannot invent zeros"
    (rejectsPayload (memoryList [(0x1000, 4)] [0x11, 0x22, 0x33, 0x44]
      (some 0xFFFFFFF0)) 5 4 0)
  pure (UInt32.ofNat (← failures.get))

end Test.MemoryPayload

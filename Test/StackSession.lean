import Forensicator.Session

namespace Test.StackSession

open Forensicator Forensicator.Model Forensicator.Spec

private def prov : Provenance := { streamType := 3, fileOffset := 100 }
private def registers : RegisterSet :=
  ((RegisterSet.new.set X64.RIP 0x1000).set X64.RSP 0x8000).set X64.RBP 0x8010

private def put64 (bytes : ByteArray) (offset : Nat) (v : UInt64) : ByteArray :=
  (List.range 8).foldl (fun b i => b.set! (offset + i) (v >>> (8 * UInt64.ofNat i)).toUInt8) bytes

private def stackBytes : ByteArray :=
  let bytes := ByteArray.mk (Array.replicate 128 0)
  put64 (put64 (put64 (put64 bytes 16 0x8020) 24 0x1010) 32 0) 40 0x1020

private def dump : Dump :=
  { systemInfo := some { os := .Windows, cpu := .X64, version := (10,0,0,0), provenance := prov }
    modules := [{ name := "fixture.exe", baseVa := 0x1000, size := 0x1000, provenance := prov }]
    threads := [{ id := 7, registers, stackVa := 0x8000, stackSize := 128, provenance := prov }] }

private def space (bytes : ByteArray := stackBytes) : AddressSpace :=
  { regions := [{ vaStart := 0x8000, size := 128, data := bytes, classification := .Stack }]
    maxRegions := 16 }

private def session : Session :=
  { path := "capture-fixture", target := .dump (dump, space, .StackOnly) 0, symbols := none }

private def frameCount (s : Session) : Option Nat := do
  let input ← s.current.toOption
  let thread ← input.point.threads.head?
  let frames ← thread.frames.toOption
  pure frames.frames.length

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := fun (label : String) (ok : Bool) => do
    if ok then IO.println s!"ok    stack session {label}"
    else
      failures.modify (· + 1)
      IO.println s!"FAIL  stack session {label}"
  check "view before recovery has no fabricated frames" ((frameCount session).isNone)
  match ← session.recoverThreadStack 7 { maxFrames := 2 } with
  | .error _ => check "recovery succeeds" false
  | .ok (retained, result) =>
    check "bounded result is partial and retained"
      (result.stack.frames.length == 2 && result.stopReason == .frameBudget
        && result.stack.coverage == .incomplete && frameCount retained == some 2)
    check "original session stays immutable" ((frameCount session).isNone)
    let before := retained.current.toOption
    let changedBytes := put64 stackBytes 24 0x1030
    let changedMemory := { retained with target := .dump (dump, space changedBytes, .StackOnly) 0 }
    check "changed observed bytes invalidate retained frames" ((frameCount changedMemory).isNone)
    check "already published point survives later changes"
      ((before.bind fun i => i.point.threads.head?.bind fun t => t.frames.toOption.map (·.frames.length)) == some 2)
    let differentSource := { retained with path := "another-source" }
    check "source identity cannot cross" ((frameCount differentSource).isNone)
    let changedRegisters := { dump with threads := (dump.threads.map fun t =>
      { t with registers := t.registers.set X64.RIP 0x1010 }) }
    check "changed registers invalidate retained frames"
      ((frameCount { retained with target := .dump (changedRegisters, space, .StackOnly) 0 }).isNone)
    let changedModule := { dump with modules := dump.modules.map fun m => { m with checksum := 99 } }
    check "module identity cannot cross"
      ((frameCount { retained with target := .dump (changedModule, space, .StackOnly) 0 }).isNone)
    let changedSystem := { dump with systemInfo := dump.systemInfo.map fun i => { i with version := (11,0,0,0) } }
    check "system interpretation cannot cross"
      ((frameCount { retained with target := .dump (changedSystem, space, .StackOnly) 0 }).isNone)
    let exceptionDump := { dump with exception := some {
      code := 0xC0000005, address := 0x1000, threadId := 7, context := some registers, provenance := prov } }
    check "equal register values from a different observation invalidate reuse"
      ((frameCount { retained with target := .dump (exceptionDump, space, .StackOnly) 0 }).isNone)
    let current ← retained.currentIO
    check "IO view consumes retained knowledge without recovery"
      ((current.toOption.bind fun i => i.point.threads.head?.bind fun t =>
        t.frames.toOption.map (·.frames.length)) == some 2)
    let prepared ← retained.prepareAnalysis
    check "analysis input includes retained frames"
      ((prepared.toOption.bind fun i => i.point.threads.head?.bind fun t =>
        t.frames.toOption.map (·.frames.length)) == some 2)
    match ← retained.recoverThreadStack 7 with
    | .error _ => check "larger budget refines recovery" false
    | .ok (refined, more) =>
      check "larger budget refines one retained result"
        (more.stack.frames.length == 3 && frameCount refined == some 3 && refined.stacks.length == 1)
    let missing ← retained.recoverThreadStack 999
    check "missing thread is rejected" (missing.toOption.isNone)
    let duplicates := { dump with threads := dump.threads ++ dump.threads }
    let ambiguous := { retained with target := .dump (duplicates, space, .StackOnly) 0 }
    let rejected ← ambiguous.recoverThreadStack 7
    check "ambiguous TID is rejected" (rejected.toOption.isNone && (frameCount ambiguous).isNone)
  let count ← failures.get
  IO.println s!"== STACK SESSION GUARDS: {count} failures =="
  pure count.toUInt32

end Test.StackSession

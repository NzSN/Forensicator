/- Behavioral contracts for source-scoped execution points and interval queries. -/
import Forensicator.Spec.Timeline

namespace Test.Timeline

open Forensicator Forensicator.Model

private def bytes (xs : List UInt8) : ByteArray := ByteArray.mk xs.toArray

private def region : MemoryRegionInfo :=
  { vaStart := 0x1000, size := 4, data := bytes [0, 1, 2, 3] }

private def fixture : Model.Trace :=
  { initMem := [region]
    writes := [{ pos := 1, va := 0x1000, data := bytes [9] },
               { pos := 2, va := 0x1000, data := bytes [0] }]
    events := [{ pos := 1, kind := .ModuleLoad, address := 0x7000, size := 0x1000, name := "old" },
               { pos := 2, kind := .Exception, code := 17, threadId := 7 },
               { pos := 2, kind := .ModuleUnload, address := 0x7000 },
               { pos := 2, kind := .ModuleLoad, address := 0x7000, size := 0x1000, name := "new" },
               { pos := 2, kind := .Exception, code := 18, threadId := 7 }]
    threads := [(7, { start := 0, stop := some 2 }),
                (7, { start := 2, stop := none })]
    frontier := 3 }

private def codes : Except String (List TraceEvent) → Option (List UInt32)
  | .ok es => some (es.map (·.code))
  | .error _ => none

private def isError : Except String α → Bool
  | .error _ => true
  | .ok _ => false

private def isUnknown : MemoryRead → Bool
  | .unknown => true
  | _ => false

private def isUnavailable : Knowledge α → Bool
  | .unavailable _ => true
  | _ => false

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check (name : String) (ok : Bool) : IO Unit := do
    if ok then IO.println s!"ok    timeline {name}"
    else
      failures.modify (· + 1)
      IO.println s!"FAIL  timeline {name}"

  check "bounded point and source identity"
    ((fixture.pointAt 4 "trace-a").isNone &&
      (fixture.pointAt 3 "trace-a").map (·.id) ==
        some ({ source := "trace-a", position := .trace 3 } : PointId))
  check "exact events preserve same-position record order"
    ((fixture.eventsAt 2).map (·.code) == [17, 0, 0, 18]
      && (fixture.eventsAt 3).isEmpty)
  check "earlier exception does not become a current exception"
    ((fixture.analysisAt 3).map (fun a => a.exception.isNone) == some true)
  check "multiple exceptions require explicit selection"
    (match fixture.analysisAt 2 with
     | some input => input.exception.isNone
       && (({ input with selectedEvent := some 0 } : AnalysisInput).exception.map (·.code) == some 17)
       && (({ input with selectedEvent := some 3 } : AnalysisInput).exception.map (·.code) == some 18)
       && (({ input with selectedEvent := some 1 } : AnalysisInput).exception.isNone)
     | none => false)
  check "interval endpoints and equal interval"
    (codes (fixture.eventsBetween 1 2) == some [17, 0, 0, 18]
      && codes (fixture.eventsBetween 2 3) == some []
      && codes (fixture.eventsBetween 2 2) == some [])
  check "interval rejects reversed and out-of-domain endpoints"
    (isError (fixture.eventsBetween 2 1) && isError (fixture.eventsBetween 0 4)
      && isError (fixture.eventsBetween 4 4)
      && isError (fixture.writesBetweenChecked 0x1000 1 2 1)
      && isError (fixture.writesBetweenChecked 0x1000 1 0 4))
  check "interval splitting preserves the event sequence"
    (match fixture.eventsBetween 0 3, fixture.eventsBetween 0 1, fixture.eventsBetween 1 3 with
     | .ok whole, .ok left, .ok right =>
       whole.map (fun e => (e.pos, e.code)) == (left ++ right).map (fun e => (e.pos, e.code))
     | _, _, _ => false)
  check "endpoint equality retains intervening writes"
    (fixture.valueAt 0x1000 0 == fixture.valueAt 0x1000 2
      && (match fixture.writesBetweenChecked 0x1000 1 0 2 with
          | .ok ws => ws.map (·.pos) == [1, 2] | _ => false))
  check "write range rejects wrap and accepts empty range"
    (isError (fixture.writesBetweenChecked 0xFFFFFFFFFFFFFFFF 2 0 2)
      && (match fixture.writesBetweenChecked 0x1000 0 0 2 with
          | .ok ws => ws.isEmpty | _ => false))
  check "module unload and same-base reload take effect at their position"
    ((fixture.modulesAt 1).map (·.name) == ["old"]
      && (fixture.modulesAt 2).map (·.name) == ["new"]
      && (fixture.moduleAnomaliesAt 2).isEmpty)
  let badModules : Model.Trace := { fixture with events :=
    [{ pos := 0, kind := .ModuleUnload, address := 0x8000 },
     { pos := 1, kind := .ModuleLoad, address := 0x7000, size := 0x1000 },
     { pos := 2, kind := .ModuleLoad, address := 0x7800, size := 0x1000 }] }
  check "unknown unload and overlapping modules fail closed with anomalies"
    ((badModules.modulesAt 2).isEmpty && (badModules.moduleAnomaliesAt 2).length == 2)
  check "thread lifetime boundaries distinguish reused IDs"
    ((fixture.threadsAt 1).map (·.key) == [(7, some 0)]
      && (fixture.threadsAt 2).map (·.key) == [(7, some 2)])
  check "lifetime-only threads do not manufacture registers or stacks"
    ((fixture.threadsAt 2).all fun t => isUnavailable t.registers
      && isUnavailable t.stackRange && isUnavailable t.frames && t.observedThread.isNone)
  let badThreads : Model.Trace := { fixture with threads :=
    [(8, { start := 0, stop := none }), (8, { start := 1, stop := none }),
     (9, { start := 2, stop := some 1 })] }
  check "malformed and overlapping lifetimes cannot supply thread state"
    ((badThreads.threadsAt 2).isEmpty && (badThreads.threadAnomaliesAt 2).length == 3)
  let lazyTrace : Model.Trace := { fixture with writes :=
    [{ pos := 1, va := 0x1000, data := bytes [9] },
     { pos := 2, va := 0x1000, len := 1, data := bytes [88] }] }
  check "metadata-only writes never expose an accidental payload"
    (lazyTrace.valueAt 0x1000 2 == none)
  check "metadata-only writes invalidate stale materialized backing"
    (match lazyTrace.pointAt 2 with
     | some point => isUnknown (point.memory.read 0x1000 1)
       && point.memory.byteCoverage == .unknown && !point.anomalies.isEmpty
     | none => false)
  check "payload point exposes writes while unmapped gaps stay unknown"
    (match fixture.pointAt 1 with
     | some point => point.space.read 0x1000 1 == some (bytes [9])
       && isUnknown (point.memory.read 0x2000 1)
       && point.memory.mappingCoverage == .incomplete
     | none => false)
  let memoryConflict : Model.Trace := { fixture with initMem := [region, region] }
  check "rejected address-space regions retain anomalies"
    ((memoryConflict.pointAt 0).map (fun p => !p.anomalies.isEmpty) == some true)
  let n ← failures.get
  IO.println s!"timeline: {n} failure(s)"
  pure (if n == 0 then 0 else 1)

end Test.Timeline

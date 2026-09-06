/- Execution-view proxy contracts with an in-process reader. No Windows proxy,
   trace fixture, network, or child process is needed for these checks. -/
import Forensicator.Trace.Client

namespace Test.ExecutionProxy

open Forensicator
open Forensicator.Trace

private def isError (value : Except ε α) : Bool :=
  match value with | .error _ => true | .ok _ => false

private def pageBytes (value : UInt8) : ByteArray :=
  ByteArray.mk (Array.replicate pageSize.toNat value)

private def hasByte (memory : Model.MemoryState) (address : VA) (value : UInt8) : Bool :=
  match memory.read address 1 with
  | .known bytes => bytes.data[0]? == some value
  | _ => false

private def isUnknown : Model.MemoryRead → Bool
  | .unknown => true
  | _ => false

private def isAbsent : Model.MemoryRead → Bool
  | .absent => true
  | _ => false

def runAll : IO UInt32 := do
  let failures ← IO.mkRef (0 : Nat)
  let check (name : String) (ok : Bool) : IO Unit := do
    if ok then IO.println s!"ok    {name}"
    else
      failures.modify (· + 1)
      IO.println s!"FAIL  {name}"

  check "proxy requested pages deduplicate crossing ranges"
    (match requestedPages [{ va := 0x1FFF, size := 2 }, { va := 0x2001, size := 2 },
                          { va := 0x4000, size := 0 }] with
     | .ok pages => pages == [0x1000, 0x2000]
     | .error _ => false)
  check "proxy rejects wrapped address ranges and unsupported final page"
    (isError (requestedPages [{ va := 0xFFFFFFFFFFFFFFFF, size := 2 }])
      && isError (requestedPages [{ va := 0xFFFFFFFFFFFFF000, size := 1 }]))
  check "proxy write-query bounds distinguish empty and invalid intervals"
    (!isError (validateWriteQuery 20 0x1000 8 5 5)
      && isError (validateWriteQuery 20 0x1000 8 6 5)
      && isError (validateWriteQuery 20 0x1000 8 0 21)
      && isError (validateWriteQuery 20 0xFFFFFFFFFFFFFFFF 1 0 20))
  check "proxy maximum frontier rejects and fetch position never wraps"
    (isError (validateFrontier 0xFFFFFFFFFFFFFFFF)
      && fetchPosition 0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF
      && fetchPosition 0xFFFFFFFFFFFFFFFF 20 == 20
      && fetchPosition 5 20 == 6)

  let st : IndexState := { frontier := 20, fullCoverage := true }
  let skel := ProxySession.skeleton 20 #[{ id := 7, start := 2, stop := some 15 }]
    #[.moduleLoad 1 0x400000 0x1000 "example.dll", .exception 5 0xC0000005 0x400001 7]
  let fresh := executionView skel "example.run" 5 st {} {}
  check "proxy cache-only point has exact identity events and unavailable stacks"
    (match fresh with
     | some input => input.point.id.source == "example.run"
       && input.point.id.position == .trace 5
       && input.point.events.length == 1 && input.point.threads.length == 1
       && input.point.threads.all (fun th => th.registers.toOption.isNone
         && th.stackRange.toOption.isNone && th.frames.toOption.isNone)
       && input.space.isEmpty && input.systemInfo.isNone
       && input.point.memory.byteCoverage == .incomplete
       && input.point.memory.mappingCoverage == .unknown
       && input.modules.map (·.name) == ["example.dll"]
     | none => false)
  check "proxy cache-only later point does not repeat exception"
    (match executionView skel "example.run" 6 st {} {} with
     | some input => input.exception.isNone && input.point.events.isEmpty
     | none => false)
  check "proxy view out of frontier is absent"
    ((executionView skel "example.run" 21 st {} {}).isNone)

  let cache := ({} : Jigsaw).insertFetched 0x1000 5 20 (some (pageBytes 0x11)) st
    |>.insertFetched 0x2000 5 20 none st
  let observed := cachedMaterialization cache st 5 20
  let memory := observed.memory
  check "proxy memory distinguishes known bytes absence and unknown gap"
    (hasByte memory 0x1000 0x11 && isAbsent (memory.read 0x2000 1)
      && isUnknown (memory.read 0x3000 1))
  check "proxy byte regions invent no protection or private mapping"
    (memory.space.regions.all (fun r => r.protection == 0 && r.classification == .Other)
      && memory.mappings.isEmpty && memory.mappingCoverage == .unknown)
  check "proxy cached absence is limited to its established position"
    (isUnknown ((cachedMaterialization cache st 6 20).memory.read 0x2000 1))

  let noisySt := { st with anomalies := [Anomaly.internal "index evidence anomaly"] }
  let noisyCache := { cache with anomalies := [Anomaly.internal "cache evidence anomaly"] }
  check "proxy execution views surface index and cache anomalies"
    (match executionView skel "example.run" 5 noisySt noisyCache observed with
     | some input => input.anomalies.any (·.description == "index evidence anomaly")
       && input.anomalies.any (·.description == "cache evidence anomaly")
     | none => false)

  -- Each acquisition evicts its predecessor; the accumulated result must own
  -- all four pages, including a positively absent one, before later fetches.
  let smallCache ← IO.mkRef ({ capacity := 1 } : Jigsaw)
  let reads ← IO.mkRef ([] : List VA)
  let acquire (page : VA) : IO Model.MemoryRead :=
    fetchPageWith smallCache st 20 page 5 fun enginePos => do
      if enginePos != 6 then throw (IO.Error.userError "unexpected engine position")
      reads.modify (page :: ·)
      if page == 0x3000 then pure none
      else pure (some (pageBytes (UInt8.ofNat (page.toNat / 0x1000))))
  let many ← collectPages [0x1000, 0x2000, 0x3000, 0x4000, 0x1000] acquire
  let small ← smallCache.get
  check "proxy materialization survives requests exceeding cache capacity"
    (small.pieces.size == 1 && (← reads.get).length == 4
      && hasByte many.memory 0x1000 1 && hasByte many.memory 0x2000 2
      && hasByte many.memory 0x4000 4 && isAbsent (many.memory.read 0x3000 1))
  check "proxy contiguous known pages support reads crossing page boundaries"
    (match many.memory.read 0x1FFF 2 with
     | .known bytes => bytes.data[0]? == some 1 && bytes.data[1]? == some 2
     | _ => false)

  let zeroCache ← IO.mkRef ({ capacity := 0 } : Jigsaw)
  let zero ← collectPages [0x5000, 0x6000] fun page =>
    fetchPageWith zeroCache st 20 page 5 (fun _ => pure (some (pageBytes 0xA5)))
  check "proxy materialization preserves bytes even with cache disabled"
    ((← zeroCache.get).pieces.isEmpty && hasByte zero.memory 0x5000 0xA5
      && hasByte zero.memory 0x6000 0xA5)

  -- A retry is useful at position 8, but it cannot erase the original absence
  -- observation or supply position 8's bytes as position 4's state.
  let fallbackIndex := st.mergeWindow { vaLo := 0x7000, vaHi := 0x8000, t1 := 0, t2 := 20 }
    #[{ pos := 2, va := 0x7000, len := 1 }, { pos := 8, va := 0x7000, len := 1 }] 20
  let fallbackCache ← IO.mkRef ({} : Jigsaw)
  let retryPositions ← IO.mkRef ([] : List Position)
  let earlier ← fetchPageWith fallbackCache fallbackIndex 20 0x7000 4 fun pos => do
    retryPositions.modify (· ++ [pos])
    pure (if pos == 9 then some (pageBytes 0x88) else none)
  let future ← fallbackCache.get
  check "proxy P3 fallback retains original absence without future-byte leakage"
    ((← retryPositions.get) == [5, 9] && isAbsent earlier
      && isUnknown (pageKnowledge future fallbackIndex 0x7000 4 20)
      && match pageKnowledge future fallbackIndex 0x7000 8 20 with
         | .known bytes => bytes.data[0]? == some 0x88
         | _ => false)

  let earlierResult := ({} : PageMaterialization).add 0x7000 earlier
  check "proxy ordinary fallback cache replacement cannot rewrite returned absence"
    (isAbsent (earlierResult.memory.read 0x7000 1)
      && isUnknown ((cachedMaterialization future fallbackIndex 4 20).memory.read 0x7000 1))

  -- A write at the frontier cannot be materialized. Retrying at the clamped
  -- frontier and recording frontier-1 would infer [2,10) and falsely cover
  -- the original NOT_COMMITTED observation at 3.
  let lastWriteIndex := ({} : IndexState).mergeWindow
    { vaLo := 0x9000, vaHi := 0xA000, t1 := 0, t2 := 10 }
    #[{ pos := 2, va := 0x9000, len := 1 }, { pos := 10, va := 0x9000, len := 1 }] 10
  let lastWriteCache ← IO.mkRef ({} : Jigsaw)
  let lastWriteReads ← IO.mkRef ([] : List Position)
  let lastWriteResult ← fetchPageWith lastWriteCache lastWriteIndex 10 0x9000 3 fun pos => do
    lastWriteReads.modify (· ++ [pos])
    pure (if pos == 10 then some (pageBytes 0xAA) else none)
  let lastWriteStored ← lastWriteCache.get
  check "proxy P3 frontier fallback cannot turn earlier absence into known bytes"
    ((fallbackPosition lastWriteIndex 0x9000 3 10).isNone
      && (← lastWriteReads.get) == [4] && isAbsent lastWriteResult
      && isAbsent (pageKnowledge lastWriteStored lastWriteIndex 0x9000 3 10)
      && isAbsent ((cachedMaterialization lastWriteStored lastWriteIndex 3 10).memory.read 0x9000 1))

  let frontierIndex := st.mergeWindow { vaLo := 0x8000, vaHi := 0x9000, t1 := 0, t2 := 20 }
    #[{ pos := 20, va := 0x8000, len := 1 }] 20
  let clampedCache := ({} : Jigsaw).insertFetched 0x8000 20 20 (some (pageBytes 0xEE)) frontierIndex
  let frontierCache ← IO.mkRef clampedCache
  let forbiddenRead ← IO.mkRef false
  let frontierValue ← fetchPageWith frontierCache frontierIndex 20 0x8000 20 fun _ => do
    forbiddenRead.set true
    pure (some (pageBytes 0xEE))
  check "proxy frontier write bytes remain unknown without an impossible read"
    (isUnknown frontierValue && !(← forbiddenRead.get)
      && isUnknown (pageKnowledge clampedCache frontierIndex 0x8000 20 20))
  check "proxy maximum frontier cannot construct a wrapped cache interval"
    (let invalid := ({} : Jigsaw).insertFetched 0x1000 0xFFFFFFFFFFFFFFFF
       0xFFFFFFFFFFFFFFFF none st
     invalid.pieces.isEmpty && !invalid.anomalies.isEmpty)

  let count ← failures.get
  IO.println (if count == 0 then "== ALL EXECUTION PROXY GUARDS PASSED =="
    else s!"== {count} EXECUTION PROXY FAILURE(S) ==")
  pure count.toUInt32

end Test.ExecutionProxy

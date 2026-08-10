/- Forensicator.Parse.Minidump — minidump stream decoders + Dump assembly.

   Port of parse/{header,directory,system_info,module_list,memory,
   memory_info,thread_list,exception,comment_a,crashpad,v8heap,dump}.rs.
   Fail-closed: stream-level defects degrade to anomalies; only header/
   directory failures are fatal. The local `u16le/u32le/u64le` readers are
   guarded `get!`s, used only after explicit bounds checks (as in Rust). -/
import Forensicator.Parse.Cursor
import Forensicator.Model.Dump
import Forensicator.Util.Text

namespace Forensicator.Parse.Minidump

open Forensicator.Model

/-- Fatal parse errors (error.rs FatalError). -/
inductive Fatal where
  | io (msg : String)
  | tooSmall (size : Nat)
  | badMagic (b0 b1 b2 b3 : UInt8)
  | directoryOutOfBounds (rva : UInt32) (size fileLen : Nat)
  | streamOutOfBounds (streamType rva : UInt32) (size fileLen : Nat)
  deriving Repr

private def bytesHex (bs : List UInt8) : String :=
  "[" ++ String.intercalate ", " (bs.map fun b => hexPadUpper b.toUInt64 2) ++ "]"

def Fatal.render : Fatal → String
  | .io msg => s!"I/O error: {msg}"
  | .tooSmall size => s!"file too small ({size} bytes, need >= 32)"
  | .badMagic b0 b1 b2 b3 => s!"bad magic: {bytesHex [b0, b1, b2, b3]} (expected 4D 44 4D 50)"
  | .directoryOutOfBounds rva size fileLen =>
    s!"stream directory at RVA {rva} size {size} out of bounds (file len {fileLen})"
  | .streamOutOfBounds st rva size fileLen =>
    s!"stream {st} at RVA {rva} size {size} out of bounds (file len {fileLen})"

-- ── guarded LE readers (callers pre-check bounds) ──────────────────
private def u16le (d : ByteArray) (o : Nat) : UInt16 :=
  (d.get! o).toUInt16 ||| ((d.get! (o + 1)).toUInt16 <<< 8)
private def u32le (d : ByteArray) (o : Nat) : UInt32 :=
  (d.get! o).toUInt32 ||| ((d.get! (o + 1)).toUInt32 <<< 8)
  ||| ((d.get! (o + 2)).toUInt32 <<< 16) ||| ((d.get! (o + 3)).toUInt32 <<< 24)
private def u64le (d : ByteArray) (o : Nat) : UInt64 :=
  (d.get! o).toUInt64 ||| ((d.get! (o + 1)).toUInt64 <<< 8)
  ||| ((d.get! (o + 2)).toUInt64 <<< 16) ||| ((d.get! (o + 3)).toUInt64 <<< 24)
  ||| ((d.get! (o + 4)).toUInt64 <<< 32) ||| ((d.get! (o + 5)).toUInt64 <<< 40)
  ||| ((d.get! (o + 6)).toUInt64 <<< 48) ||| ((d.get! (o + 7)).toUInt64 <<< 56)

-- ── header ──────────────────────────────────────────────────────────
structure Header where
  version : UInt16
  implementationVersion : UInt16
  streamCount : UInt32
  streamDirectoryRva : UInt32
  checksum : UInt32
  timestamp : UInt32
  flags : UInt64

def MAGIC : UInt32 := 0x504D444D

def readHeader (data : ByteArray) : Except Fatal Header :=
  if data.size < 32 then .error (.tooSmall data.size)
  else if u32le data 0 != MAGIC then
    .error (.badMagic (data.get! 0) (data.get! 1) (data.get! 2) (data.get! 3))
  else .ok {
    version := u16le data 4
    implementationVersion := u16le data 6
    streamCount := u32le data 8
    streamDirectoryRva := u32le data 12
    checksum := u32le data 16
    timestamp := u32le data 20
    flags := u64le data 24 }

-- ── directory ───────────────────────────────────────────────────────
structure StreamEntry where
  streamType : UInt32
  size : UInt32
  rva : UInt32

structure StreamDirectory where
  entries : List StreamEntry

def StreamDirectory.find (dir : StreamDirectory) (streamType : UInt32) : Option StreamEntry :=
  dir.entries.find? (·.streamType == streamType)

def readDirectory (data : ByteArray) (rva : UInt32) (count : UInt32) : Except Fatal StreamDirectory :=
  let start := rva.toNat
  let dirSize := count.toNat * 12
  if start + dirSize > data.size then
    .error (.directoryOutOfBounds rva dirSize data.size)
  else
    .ok ⟨((List.range count.toNat).map fun i =>
      let off := start + i * 12
      { streamType := u32le data off, size := u32le data (off + 4)
        rva := u32le data (off + 8) })⟩

-- stream type constants
def ST_THREAD_LIST : UInt32 := 0x03
def ST_MODULE_LIST : UInt32 := 0x04
def ST_MEMORY_LIST : UInt32 := 0x05
def ST_EXCEPTION : UInt32 := 0x06
def ST_SYSTEM_INFO : UInt32 := 0x07
def ST_MEMORY_64_LIST : UInt32 := 0x09
def ST_COMMENT_A : UInt32 := 0x0A
def ST_MEMORY_INFO_LIST : UInt32 := 0x10
def ST_V8HE : UInt32 := 0x45483856
def ST_CRASHPAD : UInt32 := 0x43500001

-- ── system_info ─────────────────────────────────────────────────────
def decodeSystemInfo (data : ByteArray) (prov : Provenance) : Except Anomaly SystemInfo :=
  if data.size < 56 then .error (.ofProv prov "truncated SystemInfo stream")
  else
    let cpuArch := u16le data 0
    if cpuArch != 0 && cpuArch != 9 && cpuArch != 12 then
      .error (.ofProv prov s!"unsupported CPU arch {cpuArch}")
    else
      let cpu := if cpuArch == 0 then CpuArch.X86
        else if cpuArch == 9 then CpuArch.X64 else CpuArch.Arm64
      .ok { os := .Windows, cpu := cpu
            version := (u32le data 8, u32le data 12, u32le data 16, 0)
            provenance := prov }

-- ── utf16 module names ──────────────────────────────────────────────
private def utf16Lossy (units : List UInt16) : String :=
  String.ofList (go units)
where
  replacement : Char := Char.ofNat 0xFFFD
  go : List UInt16 → List Char
    | [] => []
    | u :: rest =>
      if u.toNat < 0xD800 || u.toNat ≥ 0xE000 then Char.ofNat u.toNat :: go rest
      else if u.toNat < 0xDC00 then
        match rest with
        | l :: rest' =>
          if 0xDC00 ≤ l.toNat && l.toNat < 0xE000 then
            Char.ofNat (0x10000 + (u.toNat - 0xD800) * 1024 + (l.toNat - 0xDC00)) :: go rest'
          else replacement :: go (l :: rest')
        | [] => [replacement]
      else replacement :: go rest

/-- MINIDUMP_STRING at `rva`: u32 byte-length, then nul-terminated UTF-16. -/
private def readUtf16AtRva (full : ByteArray) (rva : UInt32) : Option String :=
  let start := rva.toNat
  if start + 4 ≥ full.size then none
  else
    let rec collect (j : Nat) (acc : List UInt16) : List UInt16 :=
      if j + 1 < full.size then
        let w := u16le full j
        if w == 0 then acc else collect (j + 2) (acc ++ [w])
      else acc
    termination_by full.size - j
    let units := collect (start + 4) []
    if units.isEmpty then none else some (utf16Lossy units)

-- ── module_list ─────────────────────────────────────────────────────
def decodeModuleList (data fullData : ByteArray) (prov : Provenance) :
    Except Anomaly (List Module) :=
  if data.size < 4 then .ok []
  else
    let count := (u32le data 0).toNat
    let entrySize := 108
    let expectedLen := 4 + count * entrySize
    if data.size < expectedLen then
      .error (.ofProv prov
        s!"truncated ModuleList: expected {expectedLen}, got {data.size}")
    else .ok ((List.range count).filterMap fun i =>
      let off := 4 + i * entrySize
      let baseVa := u64le data off
      let modSize := (u32le data (off + 8)).toUInt64
      let checksum := u32le data (off + 12)
      let name := (readUtf16AtRva fullData (u32le data (off + 20))).getD ""
      let cvSize := (u32le data (off + 76)).toNat
      let cvRva := (u32le data (off + 80)).toNat
      let cv :=
        if cvSize ≥ 24 && cvRva + cvSize ≤ fullData.size then
          let cvb := fullData.extract cvRva (cvRva + cvSize)
          if u32le cvb 0 == 0x53445352 && cvb.size ≥ 24 then
            let guid := cvb.extract 4 20
            let age := u32le cvb 20
            let pdb :=
              if cvb.size > 24 then
                let rest := cvb.extract 24 cvb.size
                let nul := (rest.toList.takeWhile (· != 0)).length
                some (fromUTF8Lossy (rest.extract 0 nul))
              else none
            some (guid, age, pdb)
          else none
        else none
      some { name := name, baseVa := baseVa, size := modSize, checksum := checksum
             codeviewGuid := cv.map (·.1), codeviewAge := (cv.map (·.2.1)).join
             pdbName := (cv.map (·.2.2)).join
             provenance := { streamType := prov.streamType
                             fileOffset := prov.fileOffset + UInt64.ofNat off
                             rva := UInt64.ofNat i } })

-- ── memory lists ────────────────────────────────────────────────────
/-- Memory range payload: full slice, or tail + zero-fill, or zeros
    (memory.rs's three-way fallback). -/
private def fillRange (src : ByteArray) (rva size : Nat) : ByteArray :=
  if rva + size ≤ src.size then src.extract rva (rva + size)
  else if rva < src.size then
    let avail := src.size - rva
    src.extract rva (rva + avail) ++ ByteArray.mk (Array.replicate (size - avail) 0)
  else ByteArray.mk (Array.replicate (min size 0x1000) 0)

structure RawMemoryRange where
  vaStart : VA
  data : ByteArray
  provenance : Provenance

def decodeMemoryList (fullData data : ByteArray) (prov : Provenance) :
    Except Anomaly (List RawMemoryRange) :=
  if data.size < 4 then .ok []
  else
    let count := (u32le data 0).toNat
    let expectedLen := 4 + count * 16
    if data.size < expectedLen then
      .error (.ofProv prov
        s!"truncated MemoryList: expected {expectedLen}, got {data.size}")
    else .ok ((List.range count).map fun i =>
      let off := 4 + i * 16
      { vaStart := u64le data off
        data := fillRange fullData ((u32le data (off + 12)).toNat) ((u32le data (off + 8)).toNat)
        provenance := { streamType := prov.streamType
                        fileOffset := prov.fileOffset + UInt64.ofNat off
                        rva := UInt64.ofNat i } })

def decodeMemory64 (data : ByteArray) (prov : Provenance) :
    Except Anomaly (List RawMemoryRange) :=
  if data.size < 16 then .ok []
  else
    let count := (u64le data 0).toNat
    let baseRva := (u64le data 8).toNat
    let expectedLen := 16 + count * 16
    if data.size < expectedLen then
      .error (.ofProv prov
        s!"truncated Memory64List: expected {expectedLen}, got {data.size}")
    else
      let rec go (i dataOff : Nat) (acc : List RawMemoryRange) : List RawMemoryRange :=
        if _h : i < count then
          let off := 16 + i * 16
          let size := (u64le data (off + 8)).toNat
          let r : RawMemoryRange :=
            { vaStart := u64le data off
              data := fillRange data dataOff size
              provenance := { streamType := prov.streamType
                              fileOffset := prov.fileOffset + UInt64.ofNat off
                              rva := UInt64.ofNat i } }
          go (i + 1) (dataOff + size) (acc ++ [r])
        else acc
      termination_by count - i
      .ok (go 0 baseRva [])

-- ── memory_info_list ────────────────────────────────────────────────
structure RawMemoryInfoEntry where
  vaStart : VA
  size : UInt64
  protection : UInt32
  state : UInt32
  memType : UInt32

def decodeMemoryInfoList (data : ByteArray) (prov : Provenance) :
    Except Anomaly (List RawMemoryInfoEntry) :=
  if data.size < 16 then .ok []
  else
    let sizeOfHeader := (u32le data 0).toNat
    let sizeOfEntry := (u32le data 4).toNat
    let count := (u64le data 8).toNat
    if sizeOfEntry == 0 || count == 0 then .ok []
    else
      let expectedLen := sizeOfHeader + count * sizeOfEntry
      if data.size < expectedLen then
        .error (.ofProv prov
          s!"truncated MemoryInfoList: expected {expectedLen}, got {data.size}")
      else
        let rec go (i : Nat) (acc : List RawMemoryInfoEntry) : List RawMemoryInfoEntry :=
          if _h : i < count then
            let off := sizeOfHeader + i * sizeOfEntry
            if off + sizeOfEntry > data.size then acc
            else go (i + 1) (acc ++ [{
              vaStart := u64le data off
              size := u64le data (off + 8)
              memType := u32le data (off + 16)
              protection := u32le data (off + 20)
              state := u32le data (off + 28) }])
          else acc
        termination_by count - i
        .ok (go 0 [])

-- ── thread_list ─────────────────────────────────────────────────────
def decodeThreadList (data dumpData : ByteArray) (prov : Provenance) :
    Except Anomaly (List Thread) :=
  if data.size < 4 then .ok []
  else
    let count := (u32le data 0).toNat
    let expectedLen := 4 + count * 48
    if data.size < expectedLen then
      .error (.ofProv prov
        s!"truncated ThreadList: expected {expectedLen}, got {data.size}")
    else .ok ((List.range count).map fun i =>
      let off := 4 + i * 48
      let ctxSize := (u32le data (off + 40)).toNat
      let ctxRva := (u32le data (off + 44)).toNat
      let registers :=
        if ctxSize > 0 && ctxRva > 0 && ctxRva + ctxSize ≤ dumpData.size then
          (RegisterSet.decodeContext (dumpData.extract ctxRva (ctxRva + ctxSize))).toOption.getD
            RegisterSet.new
        else RegisterSet.new
      { id := u32le data off
        registers := registers
        stackVa := u64le data (off + 24)
        stackSize := (u32le data (off + 32)).toUInt64
        tebVa := u64le data (off + 16)
        provenance := { streamType := prov.streamType
                        fileOffset := prov.fileOffset + UInt64.ofNat off
                        rva := UInt64.ofNat i } })

-- ── exception ───────────────────────────────────────────────────────
def decodeException (data dumpData : ByteArray) (prov : Provenance) :
    Except Anomaly ExceptionInfo :=
  if data.size < 32 then .error (.ofProv prov "truncated Exception stream")
  else
    let parameters :=
      if data.size ≥ 40 then
        let n := min ((u32le data 32).toNat) 15
        let avail := (data.size - 40) / 8
        ((List.range (min n avail)).map fun i => u64le data (40 + 8 * i))
      else []
    let context :=
      if data.size ≥ 168 then
        let ctxSize := (u32le data 160).toNat
        let ctxRva := (u32le data 164).toNat
        if ctxSize > 0 && ctxRva > 0 && ctxRva + ctxSize ≤ dumpData.size then
          (RegisterSet.decodeContext (dumpData.extract ctxRva (ctxRva + ctxSize))).toOption
        else none
      else none
    .ok { code := u32le data 8
          address := u64le data 24
          threadId := u32le data 0
          flags := u32le data 12
          parameters := parameters
          context := context
          provenance := prov }

-- ── comment_a ───────────────────────────────────────────────────────
/-- Rust `trim_end_matches('\0')`. -/
private def trimEndNul (s : String) : String :=
  String.ofList ((s.toList.reverse.dropWhile (· == Char.ofNat 0)).reverse)

private def splitOnceEq (s : String) : Option (String × String) :=
  match s.splitOn "=" with
  | [] => none
  | [_] => none
  | k :: rest => some (k, String.intercalate "=" rest)

def decodeCommentA (data : ByteArray) (prov : Provenance) :
    Except Anomaly (List (String × String)) :=
  let s := fromUTF8Lossy data
  let anns := (s.splitOn (String.ofList [Char.ofNat 0])).filterMap fun pair =>
    let pair := pair.trimAscii.toString
    if pair.isEmpty then none
    else (splitOnceEq pair).map fun (k, v) => (k.trimAscii.toString, v.trimAscii.toString)
  if anns.isEmpty then .error (.ofProv prov "no annotations in CommentStreamA")
  else .ok anns

-- ── crashpad ────────────────────────────────────────────────────────
def extractAnnotationRva (streamData : ByteArray) : Option UInt32 :=
  if streamData.size < 44 then none
  else if u32le streamData 0 != 1 then none
  else
    let annSize := u32le streamData 36
    let annRva := u32le streamData 40
    if annSize == 0 || annRva == 0 then none else some annRva

def extractAnnotationObjectsRva (streamData : ByteArray) : Option UInt32 :=
  if streamData.size < 52 then none
  else if u32le streamData 0 != 1 then none
  else
    let rva := u32le streamData 48
    if rva == 0 then none else some rva

def decodeCrashpadAnnotations (dumpData : ByteArray) (annRva : Nat) (prov : Provenance) :
    Except Anomaly (List (String × String)) :=
  if annRva + 4 > dumpData.size then .error (.ofProv prov "crashpad blob too short")
  else
    let count := (u32le dumpData annRva).toNat
    if count == 0 || count > 256 then .error (.ofProv prov "bad crashpad annotation count")
    else
      let minRva := ((List.range count).foldl (init := 0xFFFFFFFFFFFFFFFF) fun m i =>
        let off := annRva + 4 + i * 4
        if off + 4 ≤ dumpData.size then
          let r := (u32le dumpData off).toNat
          if r > 0 && r < m then r else m
        else m)
      let startPos := if minRva < 0xFFFFFFFFFFFFFFFF then minRva else annRva + 4 + count * 4
      let maxPos := min (startPos + 8192) dumpData.size
      let rec go (pos : Nat) (remaining : Nat) (acc : List (String × String)) :
          List (String × String) :=
        match remaining with
        | 0 => acc
        | n + 1 =>
          if pos + 4 > maxPos then acc
          else
            let keyLen := (u32le dumpData pos).toNat
            if keyLen == 0 || keyLen > 256 then acc
            else
              let keyStart := pos + 4
              let key := (fromUTF8Lossy (dumpData.extract keyStart (keyStart + keyLen))) |> trimEndNul
              let pos2 := keyStart + ((keyLen + 4) / 4) * 4
              if pos2 + 4 > maxPos then acc
              else
                let valLen := (u32le dumpData pos2).toNat
                if valLen == 0 || valLen > 10240 then acc
                else
                  let valStart := pos2 + 4
                  let value := (fromUTF8Lossy (dumpData.extract valStart (valStart + valLen))) |> trimEndNul
                  go (valStart + ((valLen + 4) / 4) * 4) n (acc ++ [(key, value)])
      let anns := go startPos count []
      if anns.isEmpty then .error (.ofProv prov "no annotations found in crashpad stream")
      else .ok anns

def decodeCrashpadAnnotationObjects (dumpData : ByteArray) (objectsRva : Nat) (prov : Provenance) :
    Except Anomaly (List (String × String)) :=
  let stop := min (objectsRva + 4096) dumpData.size
  let rec go (pos : Nat) (seen : List String) (acc : List (String × String)) :
      List (String × String) :=
    if pos + 8 ≤ stop then
      let klen := (u32le dumpData pos).toNat
      if klen ≥ 2 && klen ≤ 128 && pos + 4 + klen + 4 ≤ stop then
        let keyBytes := dumpData.extract (pos + 4) (pos + 4 + klen)
        let isAscii := keyBytes.toList.all fun b =>
          (b ≥ 0x20 && b ≤ 0x7E) || b == 0x5F || b == 0x2D || b == 0x2E
        let hasAlpha := keyBytes.toList.any fun b =>
          (b ≥ 0x61 && b ≤ 0x7A) || (b ≥ 0x41 && b ≤ 0x5A)
        let notNumeric := !(keyBytes.toList.all fun b =>
          (b ≥ 0x30 && b ≤ 0x39) || b == 0x78)
        if isAscii && hasAlpha && notNumeric then
          let key := fromUTF8Lossy keyBytes
          if !seen.contains key then
            let vpos := pos + 4 + ((klen + 4) / 4) * 4
            if vpos + 4 ≤ stop then
              let vlen := (u32le dumpData vpos).toNat
              if vlen > 0 && vlen ≤ 1024 && vpos + 4 + vlen ≤ stop then
                let value := (fromUTF8Lossy (dumpData.extract (vpos + 4) (vpos + 4 + vlen))) |> trimEndNul
                go (pos + 4) (key :: value :: seen) (acc ++ [(key, value)])
              else go (pos + 4) (key :: seen) acc
            else go (pos + 4) (key :: seen) acc
          else go (pos + 4) seen acc
        else go (pos + 4) seen acc
      else go (pos + 4) seen acc
    else acc
  termination_by stop - pos + 4
  let anns := go objectsRva [] []
  if anns.isEmpty then .error (.ofProv prov "no annotation objects found")
  else .ok anns

-- ── v8heap ──────────────────────────────────────────────────────────
def decodeV8heap (data : ByteArray) (prov : Provenance) :
    Except Anomaly (List RawMemoryRange × Option V8HeapExt) :=
  if data.size < 32 then .ok ([], none)
  else if u32le data 0 != ST_V8HE then
    .error (.ofProv prov
      s!"V8HE stream has unexpected stream_type 0x{hexPadUpper (u32le data 0).toUInt64 8}")
  else
    let version := u32le data 4
    let regionCount := (u32le data 24).toNat
    let (ext, tableOff) : Option V8HeapExt × Nat :=
      if version ≥ 2 then
        if data.size < 32 + 32 then (none, 32)
        else
          let msgLen := min ((u32le data (32 + 24)).toNat) 4096
          let msgStart := 64
          let msgEnd := msgStart + msgLen
          let fatalMessage :=
            if msgLen > 0 && msgEnd ≤ data.size then
              some (fromUTF8Lossy (data.extract msgStart msgEnd))
            else none
          let e : V8HeapExt :=
            { allocTopVa := u64le data 32
              allocLimitVa := u64le data 40
              gcState := u32le data 48
              lastGcReason := u32le data 52
              fatalMessage := fatalMessage }
          (some e, msgEnd)
      else (none, 32)
    if version ≥ 2 && tableOff > data.size then .ok ([], ext)
    else
      let rec go (i : Nat) (acc : List RawMemoryRange) : List RawMemoryRange :=
        if h : i < regionCount then
          let off := tableOff + i * 24
          if off + 24 > data.size then acc
          else
            let va := u64le data off
            let size := (u64le data (off + 8)).toNat
            let fileOffset := (u64le data (off + 16)).toNat
            let fend := fileOffset + size
            if size == 0 || fend > data.size then go (i + 1) acc
            else go (i + 1) (acc ++ [{
              vaStart := va
              data := data.extract fileOffset fend
              provenance := { streamType := ST_V8HE
                              fileOffset := prov.fileOffset + UInt64.ofNat off
                              rva := UInt64.ofNat i } }])
        else acc
      termination_by regionCount - i
      .ok (go 0 [], ext)

-- ── assembly (dump.rs from_bytes_inner) ─────────────────────────────

def classifyRegion (state memType _protection : UInt32) : Option RegionClass :=
  if state == 2 then none
  else match memType with
    | 2 => some .Image
    | 1 => some .Mapped
    | 0 => some .Private
    | _ => some .Other

/-- decode_optional: find stream, bounds-check, decode, collect anomaly. -/
private def decodeOptional (data : ByteArray) (dir : StreamDirectory) (streamType : UInt32)
    (decoder : ByteArray → Provenance → Except Anomaly α) :
    StateM (List Anomaly) (Option α) := do
  match dir.find streamType with
  | none => pure none
  | some entry =>
    let start := entry.rva.toNat
    let stop := start + entry.size.toNat
    if stop > data.size then
      modify fun anoms => anoms ++ [{ streamType := streamType, fileOffset := UInt64.ofNat start, rva := 0,
                                      description := s!"stream 0x{hexPadUpper streamType.toUInt64 8} extends beyond file" }]
      pure none
    else
      let prov : Provenance := { streamType := streamType
                                 fileOffset := UInt64.ofNat start, rva := 0 }
      match decoder (data.extract start stop) prov with
      | .ok v => pure (some v)
      | .error a => modify (fun anoms => anoms ++ [a]); pure none

private def decodeOptionalDump (data : ByteArray) (dir : StreamDirectory) (streamType : UInt32)
    (decoder : ByteArray → ByteArray → Provenance → Except Anomaly α) :
    StateM (List Anomaly) (Option α) := do
  decodeOptional data dir streamType fun bytes prov => decoder bytes data prov

/-- Parse a minidump from bytes (header → directory → streams). -/
def fromBytes (data : ByteArray) : Except Fatal Dump := do
  let hdr ← readHeader data
  let dir ← readDirectory data hdr.streamDirectoryRva hdr.streamCount
  let fileSize := UInt64.ofNat data.size
  let inner : StateM (List Anomaly) Dump := do
    let systemInfo ← decodeOptional data dir ST_SYSTEM_INFO decodeSystemInfo

    let modules ←
      match dir.find ST_MODULE_LIST with
      | none => pure []
      | some entry =>
        let start := entry.rva.toNat
        let stop := start + entry.size.toNat
        if stop > data.size then
          modify fun anoms => anoms ++ [{ streamType := ST_MODULE_LIST, fileOffset := UInt64.ofNat start, rva := 0,
                                          description := "ModuleList extends beyond file" }]
          pure []
        else
          let prov : Provenance := { streamType := ST_MODULE_LIST
                                     fileOffset := UInt64.ofNat start, rva := 0 }
          match decodeModuleList (data.extract start stop) data prov with
          | .ok ms => pure ms
          | .error a => modify (fun anoms => anoms ++ [a]); pure []

    let threads ← (decodeOptionalDump data dir ST_THREAD_LIST decodeThreadList).map (·.getD [])

    let ranges64 ←
      (decodeOptional data dir ST_MEMORY_64_LIST decodeMemory64).map (·.getD [])
    let mutRanges ←
      if ranges64.isEmpty then
        match dir.find ST_MEMORY_LIST with
        | none => pure []
        | some entry =>
          let start := entry.rva.toNat
          let stop := start + entry.size.toNat
          if stop ≤ data.size then
            let prov : Provenance := { streamType := ST_MEMORY_LIST
                                       fileOffset := UInt64.ofNat start, rva := 0 }
            match decodeMemoryList data (data.extract start stop) prov with
            | .ok rs => pure rs
            | .error a => modify (fun anoms => anoms ++ [a]); pure []
          else pure []
      else pure ranges64

    -- V8HE: prepended so its regions take priority over MemoryList fragments
    let v8heFound := dir.find ST_V8HE
    let (v8heapExt, memoryRanges) ←
      match v8heFound with
      | none => pure (none, mutRanges)
      | some entry =>
        let start := entry.rva.toNat
        let stop := min (start + entry.size.toNat) data.size
        if stop > start then
          let prov : Provenance := { streamType := ST_V8HE
                                     fileOffset := UInt64.ofNat start, rva := 0 }
          match decodeV8heap (data.extract start stop) prov with
          | .ok (v8ranges, ext) => pure (ext, v8ranges ++ mutRanges)
          | .error a => modify (fun anoms => anoms ++ [a]); pure (none, mutRanges)
        else pure (none, mutRanges)

    let memInfoEntries ←
      (decodeOptional data dir ST_MEMORY_INFO_LIST decodeMemoryInfoList).map (·.getD [])

    let memoryRegions := memoryRanges.map fun mr =>
      let info := memInfoEntries.find? fun mi => mi.vaStart == mr.vaStart
      { vaStart := mr.vaStart
        size := UInt64.ofNat mr.data.size
        data := mr.data
        protection := (info.map (·.protection)).getD 0
        state := ((info.map fun i => MemState.ofUInt32 i.state)).join |>.getD .Commit
        memType := ((info.map fun i => MemType.ofUInt32 i.memType)).join |>.getD .Private
        provenance := mr.provenance
        regionClass := ((info.map fun i => classifyRegion i.state i.memType i.protection)).join }

    let memoryInfo := memInfoEntries.map fun mi =>
      { vaStart := mi.vaStart, size := mi.size, protection := mi.protection
        state := (MemState.ofUInt32 mi.state).getD .Free
        memType := (MemType.ofUInt32 mi.memType).getD .Private : MemoryInfoEntry }

    let exception ← decodeOptionalDump data dir ST_EXCEPTION decodeException

    let commentAnns ←
      (decodeOptional data dir ST_COMMENT_A decodeCommentA).map (·.getD [])

    let crashpadAnns ←
      match dir.find ST_CRASHPAD with
      | none => pure []
      | some entry =>
        let start := entry.rva.toNat
        let stop := min (start + entry.size.toNat) data.size
        if start ≤ stop && stop ≤ data.size then
          let streamBytes := data.extract start stop
          match extractAnnotationRva streamBytes with
          | none => pure []
          | some annRva =>
            let annStart := annRva.toNat
            if annStart < data.size then
              let prov : Provenance := { streamType := ST_CRASHPAD
                                         fileOffset := UInt64.ofNat start
                                         rva := annRva.toUInt64 }
              let baseAnns := (decodeCrashpadAnnotations data annStart prov).toOption.getD []
              match extractAnnotationObjectsRva streamBytes with
              | none => pure baseAnns
              | some objRva =>
                let objStart := objRva.toNat
                if objStart < data.size then
                  let prov2 : Provenance := { streamType := ST_CRASHPAD
                                              fileOffset := UInt64.ofNat start
                                              rva := objRva.toUInt64 }
                  pure (baseAnns ++
                    (decodeCrashpadAnnotationObjects data objStart prov2).toOption.getD [])
                else pure baseAnns
            else pure []
        else pure []

    pure {
      systemInfo := systemInfo
      modules := modules
      threads := threads
      memoryRegions := memoryRegions
      exception := exception
      annotations := commentAnns ++ crashpadAnns
      memoryInfo := memoryInfo
      v8heapExt := v8heapExt
      fileSize := fileSize }
  let (dump, anoms) := inner.run []
  pure { dump with anomalies := anoms }

end Forensicator.Parse.Minidump

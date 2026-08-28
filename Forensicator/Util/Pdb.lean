/- Forensicator.Util.Pdb — minimal MSF 7.0 reader: PDB identity (GUID +
   age) from the information stream (stream 1) for `match`, plus the lazy
   handle-based reader (`MsfHandle`) the W2 symbolizer needs for multi-GB
   PDBs (`analyze --symbols` loads one big stream without loading the file).

   Deliberate divergence (documented, house style): Lean's IO layer
   (v4.33.0/v4.33.1 — verified against the installed toolchain source and
   libleanshared symbol tables) exposes no file seek/position primitive;
   the only cursor control is `IO.FS.Handle.rewind`. `MsfHandle` therefore
   reads via *bounded sequential passes* (rewind + page-sized reads),
   retaining only the requested pages and stopping after the last wanted
   block: I/O ≈ bytes up to the last wanted block, memory ≈ directory +
   stream size. For the nicholas PDB (pageSize 8192, superblock at 0, block
   map page 3, 240 directory pages at the *file end*, symbol stream at
   pages [2752..60091]) one analyze run costs ≈ 3.8 GB read at open +
   ≈ 0.5 GB for the stream ≈ 3.5 s at ~1.2 GB/s (measured), versus 3.8 GB
   of resident RAM for the eager `MsfFile` path.

   MSF 7.0 absent streams (size 0xFFFFFFFF) consume *no* block-list
   entries in the directory (standard MSF semantics, as llvm reads them).
   The pre-2026-08-28 walk advanced by ceil(0xFFFFFFFF/pageSize) entries
   for absent streams, which parses correctly only when no absent stream
   precedes the target; the shared directory parser below uses the
   standard semantics (pinned by the synthetic fixture with an absent
   stream at index 2). -/
import Forensicator.Util.Bytes
import Forensicator.Basic

namespace Forensicator.Util

private def msfU32 (d : ByteArray) (off : Nat) : Option UInt32 :=
  if off + 4 ≤ d.size then some (readU32leAt d off) else none

/-- The 32-byte MSF 7.0 magic. -/
private def msfMagic : ByteArray :=
  "Microsoft C/C++ MSF 7.00".toUTF8
    ++ ByteArray.mk #[0x0D, 0x0A, 0x1A] ++ "DS".toUTF8 ++ ByteArray.mk (Array.replicate 3 0)

private def orErr (o : Option α) (msg : String) : Except String α :=
  match o with | some v => .ok v | none => .error msg

/-- The parsed MSF 7.0 stream directory: per-stream sizes (0xFFFFFFFF =
    absent) and block lists (ascending page indices; empty for absent and
    zero-size streams). Shared by the eager `MsfFile` and `MsfHandle`. -/
structure MsfDirectory where
  pageSize : Nat
  numStreams : Nat
  sizes : Array UInt32
  blockLists : Array (Array Nat)

/-- True when `xs` is strictly ascending. -/
private def sortedAsc (xs : Array Nat) : Bool :=
  let rec go (i : Nat) : Bool :=
    if i + 1 ≥ xs.size then true
    else xs[i]! < xs[i + 1]! && go (i + 1)
  termination_by xs.size - i
  go 0

/-- Parse the assembled stream-directory bytes: stream count, sizes array,
    then one block list per *present* stream (absent streams consume no
    entries; see the module header). -/
private def parseDirectoryBody (dirBytes : ByteArray) (pageSize : Nat) : Option MsfDirectory := do
  let numStreams ← (msfU32 dirBytes 0).map UInt32.toNat
  let sizes ← (List.range numStreams).mapM fun i => msfU32 dirBytes (4 + 4 * i)
  let sizes := sizes.toArray
  let rec walk (i off : Nat) (acc : Array (Array Nat)) : Option (Array (Array Nat)) :=
    if i ≥ numStreams then some acc
    else
      let sz := sizes[i]!
      if sz == 0xFFFFFFFF then walk (i + 1) off (acc.push #[])
      else
        let blocks := (sz.toNat + pageSize - 1) / pageSize
        match (List.range blocks).mapM (fun j => msfU32 dirBytes (off + 4 * j)) with
        | none => none
        | some bs => walk (i + 1) (off + 4 * blocks) (acc.push (bs.map UInt32.toNat |>.toArray))
  termination_by numStreams - i
  match walk 0 (4 + 4 * numStreams) #[] with
  | none => none
  | some blockLists => some { pageSize, numStreams, sizes, blockLists }

/-- Assemble the stream directory of a fully-loaded MSF 7.0 file from the
    block map (directory page list at `dirBlocksOff`) and parse it. -/
private def parseDirectory (data : ByteArray) (pageSize dirSize : Nat) (dirBlocksOff : Nat)
    : Option MsfDirectory := do
  if pageSize == 0 then none
  else
    let dirPageCount := (dirSize + pageSize - 1) / pageSize
    let dirPages := (List.range dirPageCount).filterMap fun i =>
      (msfU32 data (dirBlocksOff + 4 * i)).map UInt32.toNat
    if dirPages.length < dirPageCount then none
    else
      let dirBytes := (dirPages.map fun pg =>
        data.extract (pg * pageSize) (pg * pageSize + pageSize))
        |>.foldl (· ++ ·) ByteArray.empty
        |>.extract 0 dirSize
      parseDirectoryBody dirBytes pageSize

-- ── eager reader (whole file in memory; `match`) ───────────────────────

/-- MSF 7.0 container: page size + stream-directory block-list location.
    Takes a fully-loaded `ByteArray` (fine for `match` on small PDBs;
    fatal for multi-GB PDBs — use `MsfHandle` there). -/
structure MsfFile where
  data : ByteArray
  pageSize : Nat
  dirBlocksOff : Nat
  directory : MsfDirectory

/-- Open an MSF 7.0 file (magic + header); the stream directory is parsed
    eagerly (the file is in memory anyway). -/
def MsfFile.open (data : ByteArray) : Except String MsfFile := do
  if data.size < 56 || data.extract 0 32 != msfMagic then
    throw "not an MSF 7.0 file"
  let pageSize ← orErr (msfU32 data 32) "truncated MSF header"
  let dirSize ← orErr (msfU32 data 44) "truncated MSF header"
  let blockMapPage ← orErr (msfU32 data 52) "truncated MSF header"
  let directory ← orErr (parseDirectory data pageSize.toNat dirSize.toNat
    (blockMapPage.toNat * pageSize.toNat)) "corrupt MSF directory"
  pure { data := data, pageSize := pageSize.toNat
         dirBlocksOff := blockMapPage.toNat * pageSize.toNat
         directory := directory }

/-- Read stream `idx`'s bytes (empty when absent/empty; `none` when the
    index is out of range or the stream's bytes are missing from `data`). -/
def MsfFile.stream (msf : MsfFile) (idx : Nat) : Option ByteArray := do
  if idx ≥ msf.directory.numStreams then none
  else
    let sz := msf.directory.sizes[idx]!
    if sz == 0xFFFFFFFF then some ByteArray.empty
    else
      let want := sz.toNat
      let assembled := (msf.directory.blockLists[idx]!).toList.map (fun pg =>
        msf.data.extract (pg * msf.pageSize) (pg * msf.pageSize + msf.pageSize))
        |>.foldl (· ++ ·) ByteArray.empty
      if assembled.size < want then none
      else some (assembled.extract 0 want)

/-- A PDB's identity: age + 16-byte GUID from the information stream. -/
def pdbIdentity (data : ByteArray) : Except String (UInt32 × ByteArray) := do
  let msf ← MsfFile.open data
  let stream1 ← orErr (msf.stream 1) "no information stream"
  if stream1.size < 28 then throw "truncated PDB information stream"
  let age := readU32leAt stream1 8
  let guid := stream1.extract 12 28
  pure (age, guid)

-- ── lazy reader (open file handle; multi-GB PDBs) ──────────────────────

/-- MSF 7.0 container over an open file handle: `open` reads the
    superblock, the block map page and the stream directory (one bounded
    sequential pass; the directory sits at the file end on multi-GB PDBs),
    and `stream` reads individual streams on demand (one bounded pass per
    call, from the first to the last block of the stream). Memory stays
    O(directory) + O(stream size); the file closes when the handle is
    dropped. All reads are bounds-guarded; any inconsistency fails closed
    with an error instead of guessing. -/
structure MsfHandle where
  file : IO.FS.Handle
  numBlocks : Nat
  directory : MsfDirectory

/-- Read one page-sized chunk; I/O errors fail closed. -/
private def readChunk (h : IO.FS.Handle) (n : Nat) : IO (Except String ByteArray) :=
  try do
    let b ← h.read (USize.ofNat n)
    pure (.ok b)
  catch _ => pure (.error "MSF: file read failed")

/-- One bounded sequential pass over the file from the current cursor:
    reads `numPages` page-sized chunks, keeps those whose page index is in
    `wanted` (required ascending), returns the kept chunks in `wanted`
    order, and stops as soon as all wanted pages are collected. EOF before
    completion fails closed. -/
private def scanWanted (h : IO.FS.Handle) (pageSize numPages : Nat)
    (wanted : Array Nat) : IO (Except String (Array ByteArray)) :=
  let rec go (n k : Nat) (acc : List ByteArray) : IO (Except String (Array ByteArray)) := do
    if k == wanted.size then
      pure (.ok acc.reverse.toArray)
    else
      match n with
      | 0 =>
        pure (.error "MSF: wanted pages missing (unexpected EOF)")
      | m + 1 =>
        let page := numPages - (m + 1)
        let need := wanted[k]!
        if page > need then
          -- `wanted` is not ascending (callers pre-check); fail closed
          pure (.error "MSF: wanted pages out of file order")
        else if page < need then
          -- page not wanted: read and discard
          match ← readChunk h pageSize with
          | .error e => pure (.error e)
          | .ok b =>
            if b.isEmpty then pure (.error "MSF: unexpected EOF")
            else go m k acc
        else
          match ← readChunk h pageSize with
          | .error e => pure (.error e)
          | .ok b =>
            if b.isEmpty then pure (.error "MSF: unexpected EOF")
            else go m (k + 1) (b :: acc)
  termination_by n
  go numPages 0 []

/-- Finish an `MsfHandle.open`: header fields are validated, then the
    block map page (Phase A) and the directory pages (Phase B) are read. -/
private def MsfHandle.openFromHeader (file : IO.FS.Handle)
    (pageSizeU numBlocksU dirSizeU blockMapPageU : UInt32) : IO (Except String MsfHandle) := do
  let pageSize := pageSizeU.toNat
  let numBlocks := numBlocksU.toNat
  let blockMapPage := blockMapPageU.toNat
  if pageSize == 0 then pure (.error "MSF: zero page size")
  else if blockMapPage ≥ numBlocks then pure (.error "MSF: block map page out of range")
  else
    -- Phase A: the block map page (page indices of the directory pages).
    -- `open` has already consumed the 56-byte superblock, so rewind to
    -- page 0 first (Phase B and `stream` rewind likewise).
    file.rewind
    match ← scanWanted file pageSize (blockMapPage + 1) #[blockMapPage] with
    | .error e => pure (.error e)
    | .ok chunks =>
      let mapBytes := chunks[0]!
      let dirSize := dirSizeU.toNat
      let dirPageCount := (dirSize + pageSize - 1) / pageSize
      if dirPageCount == 0 then pure (.error "MSF: zero-length directory")
      else
        match (List.range dirPageCount).mapM (fun i => msfU32 mapBytes (4 * i)) with
        | none => pure (.error "MSF: block map truncated")
        | some ps =>
          let dirPages := ps.map UInt32.toNat |>.toArray
          if !sortedAsc dirPages then pure (.error "MSF: directory pages out of file order")
          else if !dirPages.all (· < numBlocks) then pure (.error "MSF: directory page out of range")
          else
            -- Phase B: the directory pages, in file order.
            file.rewind
            match ← scanWanted file pageSize (dirPages.back! + 1) dirPages with
            | .error e => pure (.error e)
            | .ok dirChunks =>
              let dirBytes := dirChunks.foldl (· ++ ·) ByteArray.empty |>.extract 0 dirSize
              match parseDirectoryBody dirBytes pageSize with
              | none => pure (.error "corrupt MSF directory")
              | some directory =>
                pure (.ok { file := file, numBlocks := numBlocks, directory := directory })

/-- Open an MSF 7.0 file lazily: superblock + block map + stream directory
    only (one bounded sequential pass; see `MsfHandle`). -/
def MsfHandle.open (path : String) : IO (Except String MsfHandle) := do
  let mfile0 : IO (Except String IO.FS.Handle) :=
    try do
      let file ← IO.FS.Handle.mk path .read
      pure (.ok file)
    catch _ => pure (.error ("MSF: cannot open " ++ path))
  let mfile ← mfile0
  match mfile with
  | .error e => pure (.error e)
  | .ok file =>
    let mhead0 : IO (Except String ByteArray) :=
      try do
        let head ← file.read (USize.ofNat 56)
        pure (.ok head)
      catch _ => pure (.error "MSF: header read failed")
    let mhead ← mhead0
    match mhead with
    | .error e => pure (.error e)
    | .ok head =>
      if head.size < 56 then pure (.error "truncated MSF header")
      else if head.extract 0 32 != msfMagic then pure (.error "not an MSF 7.0 file")
      else
        match msfU32 head 32, msfU32 head 40, msfU32 head 44, msfU32 head 52 with
        | none, _, _, _ | _, none, _, _ | _, _, none, _ | _, _, _, none =>
          pure (.error "truncated MSF header")
        | some pageSize, some numBlocks, some dirSize, some blockMapPage =>
          MsfHandle.openFromHeader file pageSize numBlocks dirSize blockMapPage

/-- Size of stream `idx` in bytes (`none` when out of range; absent
    streams read as empty). -/
def MsfHandle.streamSize (msf : MsfHandle) (idx : Nat) : Option Nat :=
  if idx ≥ msf.directory.numStreams then none
  else
    let sz := msf.directory.sizes[idx]!
    if sz == 0xFFFFFFFF then some 0 else some sz.toNat

/-- Read stream `idx`'s bytes on demand (empty when absent/empty; error
    on out-of-range index, block-list inconsistency or I/O failure). One
    bounded sequential pass per call — see the module header. -/
def MsfHandle.stream (msf : MsfHandle) (idx : Nat) : IO (Except String ByteArray) := do
  if idx ≥ msf.directory.numStreams then
    pure (.error ("MSF: stream " ++ toString idx ++ " out of range"))
  else
    let sz := msf.directory.sizes[idx]!
    if sz == 0xFFFFFFFF || sz == 0 then pure (.ok ByteArray.empty)
    else
      let want := sz.toNat
      let blocks := msf.directory.blockLists[idx]!
      let pageCount := (want + msf.directory.pageSize - 1) / msf.directory.pageSize
      if blocks.size != pageCount then
        pure (.error ("MSF: stream " ++ toString idx ++ " block list truncated"))
      else if !sortedAsc blocks then
        pure (.error ("MSF: stream " ++ toString idx ++ " blocks out of file order"))
      else if !blocks.all (· < msf.numBlocks) then
        pure (.error ("MSF: stream " ++ toString idx ++ " block page out of range"))
      else
        msf.file.rewind
        match ← scanWanted msf.file msf.directory.pageSize (blocks.back! + 1) blocks with
        | .error e => pure (.error e)
        | .ok chunks =>
          let assembled := chunks.foldl (· ++ ·) ByteArray.empty
          if assembled.size < want then
            pure (.error ("MSF: stream " ++ toString idx ++ " truncated"))
          else
            pure (.ok (assembled.extract 0 want))

end Forensicator.Util

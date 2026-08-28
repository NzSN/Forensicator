/- Test.MsfFixture — synthetic MSF 7.0 container builder for the W2
   guard-suite tests (design §4): a few-KB PDB-lookalike with an empty
   stream (0), a PdbInfo stream (1), an *absent* stream (2, size
   0xFFFFFFFF — consumes no block-list entries), and a multi-page stream
   (3) with a partial final page. Built in-test, byte-exact, with a small
   page size so multi-page layouts are cheap. -/
namespace Test.MsfFixture

/-- LE u32 / u64 encoders (same style as Test.Spec's helpers). -/
def le32 (v : Nat) : List UInt8 :=
  (List.range 4).map fun i => ((UInt64.ofNat v) >>> (8 * UInt64.ofNat i)).toUInt8

def le64 (v : UInt64) : List UInt8 :=
  (List.range 8).map fun i => (v >>> (8 * UInt64.ofNat i)).toUInt8

/-- The 32-byte MSF 7.0 magic. -/
def magic : List UInt8 :=
  "Microsoft C/C++ MSF 7.00".toUTF8.toList
    ++ [0x0D, 0x0A, 0x1A] ++ "DS".toUTF8.toList ++ [0, 0, 0]

/-- Small page size so multi-page streams stay cheap. -/
def pageSize : Nat := 256

/-- Stream 1 (information stream): 28 bytes — version, signature,
    age = 7, 16-byte GUID. -/
def pdbInfo : ByteArray :=
  ByteArray.mk (le32 0x3 ++ le32 0x1234 ++ le32 7
    ++ le64 0xDEADBEEF00112233 ++ le64 0x445566778899AABB).toArray

/-- Stream 3 payload: 2.5 pages (549 bytes), patterned — exercises
    multi-page assembly with a partial final page. -/
def stream3Size : Nat := 2 * pageSize + 37

def mkPattern (n : Nat) : ByteArray :=
  ByteArray.mk ((List.range n).map fun i => (UInt8.ofNat ((i * 13 + 5) % 256))).toArray

def stream3 : ByteArray := mkPattern stream3Size

/-- The complete synthetic container: 8 pages of 256 bytes each.
    0 = superblock, 1 = free block map (unused), 2 = block map
    (directory page list), 3 = directory, 4 = stream 1,
    5/6/7 = stream 3. Directory: 4 streams with sizes
    [0, 28, 0xFFFFFFFF, 549]; absent stream 2 consumes no entries. -/
def container : ByteArray :=
  let hdr : List UInt8 := magic ++ le32 pageSize ++ le32 1 ++ le32 8
    ++ le32 36 ++ le32 0 ++ le32 2
  let dir : List UInt8 := le32 4 ++ le32 0 ++ le32 28 ++ le32 0xFFFFFFFF
    ++ le32 stream3Size
    ++ le32 4                -- stream 1 block list: [4]
    ++ le32 5 ++ le32 6 ++ le32 7  -- stream 3 block list: [5, 6, 7]
  let page (n : Nat) (body : List UInt8) : List UInt8 :=
    body ++ List.replicate (pageSize - body.length) 0
  let s3 := stream3.toList
  ByteArray.mk ((page 0 hdr) ++ (page 1 []) ++ (page 2 (le32 3)) ++ (page 3 dir)
    ++ (page 4 pdbInfo.toList)
    ++ (page 5 (s3.take 256)) ++ (page 6 (s3.drop 256 |>.take 256))
    ++ (page 7 (s3.drop 512))).toArray

/-- LE u16 encoder (2 bytes). -/
def le16 (v : Nat) : List UInt8 :=
  (List.range 2).map fun i => ((UInt64.ofNat v) >>> (8 * UInt64.ofNat i)).toUInt8

/-- One CodeView symbol record: [reclen u16][kind u16][payload]. -/
def symRec (kind : Nat) (payload : List UInt8) : List UInt8 :=
  le16 (payload.length + 2) ++ le16 kind ++ payload

/-- S_PUB32 record with optional padding bytes after the name NUL. -/
def sPub32 (off : Nat) (seg : Nat) (name : String) (pad : Nat := 0) : List UInt8 :=
  symRec 0x110E (le32 0 ++ le32 off ++ le16 seg ++ name.toUTF8.toList ++ [0]
    ++ List.replicate pad 0)

/-- A non-S_PUB32 record the walk must skip (S_GDATA32, kind 0x110D). -/
def sGdata32 (name : String) : List UInt8 :=
  symRec 0x110D (le32 0 ++ le32 0 ++ le16 1 ++ name.toUTF8.toList ++ [0])

/-- Minimal record with an empty payload (S_END, kind 0x000E). -/
def sEnd : List UInt8 := symRec 0x000E []

/-- The 64-byte DBI header for the publics fixture: versionSignature =
    -1, version 19990903, age 7, globals 0xFFFF (absent), publics stream 9,
    symbol record stream 8. -/
def dbiHeader : ByteArray :=
  ByteArray.mk (le32 0xFFFFFFFF ++ le32 0x01312B97 ++ le32 7 ++ le16 0xFFFF
    ++ le16 0 ++ le16 9 ++ le16 0 ++ le16 8 ++ le16 0
    ++ List.replicate 40 0).toArray

/-- Symbol record stream (stream 8): five S_PUB32 records plus a skipped
    S_GDATA32 and a minimal S_END; 111 bytes, one padding test ("pad" + 2).
    Records in stream order:
      A: S_PUB32 seg 1 off 0x1000 name "alpha"
      B: S_PUB32 seg 1 off 0x2024 name "builtin"
      C: S_GDATA32 "glob"            (skipped)
      D: S_END (reclen 2)             (skipped)
      E: S_PUB32 seg 2 off 0x50  name "needsPe"  (dropped w/o PE)
      F: S_PUB32 seg 1 off 0x800 name "aaa"      (out of RVA order)
      G: S_PUB32 seg 1 off 0x3000 name "pad" + 2 pad bytes
  -/
def pubSymStream : ByteArray :=
  ByteArray.mk ((sPub32 0x1000 1 "alpha") ++ (sPub32 0x2024 1 "builtin")
    ++ (sGdata32 "glob") ++ sEnd ++ (sPub32 0x50 2 "needsPe")
    ++ (sPub32 0x800 1 "aaa") ++ (sPub32 0x3000 1 "pad" 2)).toArray

/-- Publics stream (stream 9): placeholder bytes only — T4 reads the DBI
    index, the records live in the symbol record stream. -/
def pubStream : ByteArray := ByteArray.mk (le32 0 ++ le32 0).toArray

/-- The complete publics fixture: 9 pages of 256 bytes. Streams:
    0 empty, 1 PdbInfo, 2 absent, 3 = DBI header, 4-7 absent,
    8 = symbol record stream, 9 = publics placeholder.
    Pages: 0 superblock, 1 free block map, 2 block map, 3 directory,
    4 stream 1, 5 stream 3, 6-7 stream 8, 8 stream 9. -/
def publicsContainer : ByteArray :=
  let hdr : List UInt8 := magic ++ le32 pageSize ++ le32 1 ++ le32 9
    ++ le32 64 ++ le32 0 ++ le32 2
  let dir : List UInt8 := le32 10 ++ le32 0 ++ le32 28 ++ le32 0xFFFFFFFF
    ++ le32 64 ++ le32 0xFFFFFFFF ++ le32 0xFFFFFFFF ++ le32 0xFFFFFFFF
    ++ le32 0xFFFFFFFF ++ le32 pubSymStream.size ++ le32 8
    ++ le32 4                -- stream 1 block list: [4]
    ++ le32 5                -- stream 3 block list: [5]
    ++ le32 6 ++ le32 7      -- stream 8 block list: [6, 7]
    ++ le32 8                -- stream 9 block list: [8]
  let page (n : Nat) (body : List UInt8) : List UInt8 :=
    body ++ List.replicate (pageSize - body.length) 0
  let s8 := pubSymStream.toList
  ByteArray.mk ((page 0 hdr) ++ (page 1 []) ++ (page 2 (le32 3)) ++ (page 3 dir)
    ++ (page 4 pdbInfo.toList) ++ (page 5 dbiHeader.toList)
    ++ (page 6 (s8.take 256)) ++ (page 7 (s8.drop 256))
    ++ (page 8 pubStream.toList)).toArray

end Test.MsfFixture


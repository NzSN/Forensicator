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

end Test.MsfFixture

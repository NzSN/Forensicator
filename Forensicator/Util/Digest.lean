/- SHA-256 for source identities and persisted evidence integrity.
   Algorithm: FIPS 180-4 §§4.1.2, 4.2.2, 5.1.1, 5.3.3, 6.2.2.
   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
   Byte-oriented input only; no external implementation or IO boundary. -/
namespace Forensicator

/-- A validated 256-bit digest in canonical, big-endian byte order. -/
structure Digest256 where
  bytes : ByteArray
  size_eq : bytes.size = 32
  deriving DecidableEq

instance : BEq Digest256 where
  beq a b := a.bytes == b.bytes

namespace Digest256

/-- Reject truncated or oversized encoded digests. -/
def ofBytes (bytes : ByteArray) : Option Digest256 :=
  if h : bytes.size = 32 then some ⟨bytes, h⟩ else none

private def hexDigit (n : Nat) : Char :=
  Char.ofNat (if n < 10 then 48 + n else 87 + n)

/-- Exactly 64 lowercase ASCII hexadecimal digits. -/
def toHex (digest : Digest256) : String := Id.run do
  let mut result := ""
  for byte in digest.bytes do
    result := (result.push (hexDigit (byte.toNat / 16))).push (hexDigit (byte.toNat % 16))
  return result

private def hexValue (byte : UInt8) : Option UInt8 :=
  if 48 ≤ byte && byte ≤ 57 then some (byte - 48)
  else if 97 ≤ byte && byte ≤ 102 then some (byte - 87)
  else if 65 ≤ byte && byte ≤ 70 then some (byte - 55)
  else none

/-- Parse exactly 64 hexadecimal digits; accept either ASCII case, no whitespace. -/
def ofHex (text : String) : Option Digest256 := do
  let encoded := text.toUTF8
  if encoded.size != 64 then none
  else
    let mut bytes := ByteArray.emptyWithCapacity 32
    for i in [0:32] do
      let hi ← hexValue (encoded[i * 2]?.getD 0)
      let lo ← hexValue (encoded[i * 2 + 1]?.getD 0)
      bytes := bytes.push (hi * 16 + lo)
    ofBytes bytes

instance : ToString Digest256 := ⟨toHex⟩
instance : Repr Digest256 where
  reprPrec d _ := repr d.toHex

end Digest256

namespace Sha256

/-- Largest supported byte count plus one: SHA-256 requires fewer than 2^64 bits. -/
def byteLimit : Nat := 2305843009213693952

private def initialWords : Array UInt32 :=
  #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

private def roundConstants : Array UInt32 :=
  #[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

@[inline] private def rotateRight (word bits : UInt32) : UInt32 :=
  (word >>> bits) ||| (word <<< (32 - bits))

@[inline] private def sigma0 (x : UInt32) : UInt32 :=
  rotateRight x 7 ^^^ rotateRight x 18 ^^^ (x >>> 3)

@[inline] private def sigma1 (x : UInt32) : UInt32 :=
  rotateRight x 17 ^^^ rotateRight x 19 ^^^ (x >>> 10)

@[inline] private def sum0 (x : UInt32) : UInt32 :=
  rotateRight x 2 ^^^ rotateRight x 13 ^^^ rotateRight x 22

@[inline] private def sum1 (x : UInt32) : UInt32 :=
  rotateRight x 6 ^^^ rotateRight x 11 ^^^ rotateRight x 25

@[inline] private def readWord (bytes : ByteArray) (offset : Nat) : UInt32 :=
  ((bytes[offset]?.getD 0).toUInt32 <<< 24)
    ||| ((bytes[offset + 1]?.getD 0).toUInt32 <<< 16)
    ||| ((bytes[offset + 2]?.getD 0).toUInt32 <<< 8)
    ||| (bytes[offset + 3]?.getD 0).toUInt32

/-- Internal block compression. Callers supply eight words and a complete block.
    Bounded indexing is total even outside those internal preconditions. -/
private def compress (words : Array UInt32) (bytes : ByteArray) (offset : Nat) :
    Array UInt32 := Id.run do
  let mut schedule := Array.emptyWithCapacity 64
  for i in [0:16] do
    schedule := schedule.push (readWord bytes (offset + i * 4))
  for i in [16:64] do
    schedule := schedule.push
      (sigma1 (schedule.getD (i - 2) 0) + schedule.getD (i - 7) 0
        + sigma0 (schedule.getD (i - 15) 0) + schedule.getD (i - 16) 0)
  let mut a := words.getD 0 0
  let mut b := words.getD 1 0
  let mut c := words.getD 2 0
  let mut d := words.getD 3 0
  let mut e := words.getD 4 0
  let mut f := words.getD 5 0
  let mut g := words.getD 6 0
  let mut h := words.getD 7 0
  for i in [0:64] do
    let choice := (e &&& f) ^^^ ((~~~e) &&& g)
    let majority := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
    let t1 := h + sum1 e + choice + roundConstants.getD i 0 + schedule.getD i 0
    let t2 := sum0 a + majority
    h := g
    g := f
    f := e
    e := d + t1
    d := c
    c := b
    b := a
    a := t1 + t2
  return #[words.getD 0 0 + a, words.getD 1 0 + b,
    words.getD 2 0 + c, words.getD 3 0 + d, words.getD 4 0 + e,
    words.getD 5 0 + f, words.getD 6 0 + g, words.getD 7 0 + h]

/-- Incremental byte-oriented SHA-256 state. Use `empty`, `update`, and `finish`.
    Public operations reject malformed array/count/buffer shapes. The raw state
    is not an authenticated serialization format; do not restore untrusted fields. -/
structure State where
  words : Array UInt32 := initialWords
  pending : ByteArray := ByteArray.empty
  byteCount : Nat := 0

namespace State

def empty : State := {}

/-- Natural-number accounting prevents count wrap before the FIPS length check. -/
def wellFormed (state : State) : Bool :=
  state.words.size == 8 && state.pending.size < 64
    && state.byteCount % 64 == state.pending.size && state.byteCount < byteLimit

/-- Consume a chunk, retaining at most 63 bytes. Full blocks are read directly
    from the caller's input, so no copy proportional to accumulated input occurs.
    Return `none` on malformed state or a total input length of 2^61 bytes or more. -/
def update (state : State) (bytes : ByteArray) : Option State := do
  if !state.wellFormed || state.byteCount + bytes.size ≥ byteLimit then none
  else
    let count := state.byteCount + bytes.size
    let mut words := state.words
    let mut offset := 0
    if !state.pending.isEmpty then
      let needed := 64 - state.pending.size
      let take := min needed bytes.size
      let pending := bytes.copySlice 0 state.pending state.pending.size take
      if pending.size < 64 then
        return { words, pending, byteCount := count }
      words := compress words pending 0
      offset := take
    let blocks := (bytes.size - offset) / 64
    for i in [0:blocks] do
      words := compress words bytes (offset + i * 64)
    offset := offset + blocks * 64
    return { words, pending := bytes.extract offset bytes.size, byteCount := count }

/-- Finalize without mutating the state: callers may finish repeatedly or fork
    it by passing the original state to `update` again. -/
def finish (state : State) : Option Digest256 := do
  if !state.wellFormed then none
  else
    let mut tail := state.pending.push 0x80
    let zeros := if tail.size ≤ 56 then 56 - tail.size else 120 - tail.size
    for _ in [0:zeros] do tail := tail.push 0
    let bits := UInt64.ofNat (state.byteCount * 8)
    for i in [0:8] do
      tail := tail.push (bits >>> UInt64.ofNat ((7 - i) * 8)).toUInt8
    let mut words := state.words
    for i in [0:tail.size / 64] do
      words := compress words tail (i * 64)
    let mut bytes := ByteArray.emptyWithCapacity 32
    for word in words do
      for shift in [24, 16, 8, 0] do
        bytes := bytes.push (word >>> shift).toUInt8
    Digest256.ofBytes bytes

end State
end Sha256

/-- Standard SHA-256 of a byte array; fails only when the FIPS input limit is
    exceeded. For files and streams, call `Sha256.State.update` on bounded chunks. -/
def sha256 (bytes : ByteArray) : Option Digest256 := do
  let state ← Sha256.State.empty.update bytes
  state.finish

end Forensicator

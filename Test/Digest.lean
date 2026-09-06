/- SHA-256 behavior checks. Published vectors: RFC 6234 §8.5 (abc,
   multi-block, million-a, binary byte) and the SHA256ShortMsg empty vector
   in NIST's byte-oriented SHAVS set. These are informal correctness checks,
   not CAVP validation. https://www.rfc-editor.org/rfc/rfc6234#section-8.5
   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing -/
import Forensicator.Util.Digest

namespace Test.Digest

open Forensicator

private def check (failures : IO.Ref Nat) (name : String) (ok : Bool) : IO Unit := do
  if ok then IO.println s!"ok    {name}"
  else
    failures.modify (· + 1)
    IO.println s!"FAIL  {name}"

private def hex (bytes : ByteArray) : Option String := (sha256 bytes).map Digest256.toHex

private def sample (size : Nat) : ByteArray := Id.run do
  let mut bytes := ByteArray.emptyWithCapacity size
  for i in [0:size] do bytes := bytes.push (UInt8.ofNat (i * 37 + i / 17 + 11))
  return bytes

private def digestChunks (chunks : List ByteArray) : Option Digest256 := do
  let state ← chunks.foldlM Sha256.State.update Sha256.State.empty
  state.finish

private def digestUniform (bytes : ByteArray) (chunkSize : Nat) : Option Digest256 := do
  if chunkSize == 0 then none
  else
    let mut state := Sha256.State.empty
    for i in [0:(bytes.size + chunkSize - 1) / chunkSize] do
      state ← state.update (bytes.extract (i * chunkSize) ((i + 1) * chunkSize))
    state.finish

/-- Independent Python hashlib values for deterministic padding-boundary inputs.
    The generating formula matches `sample`, not SHA-256 internals. -/
private def boundaryVectors : List (Nat × String) :=
  [(55, "c52df8410e3bc46508fc3f8be76afd2f7c4558f22db0ec4df74dd70dbf3db0d8"),
   (56, "6eec7eee8439a8f340fe9d5926b7ecede8b3dc660fb95f437f0b04ae2af06c99"),
   (57, "38aca14c2d623df2af31aec31fecca38ad2cd50a7cbc03d469d58b03a23e4619"),
   (63, "e19b5fdaff52ea0e301ba3f103586a2aba84b7213bfc16ae205806b33c06123f"),
   (64, "1bc11b42626fd2551e45593f1526ee431f522019f54b08c3a7caf4335662814d"),
   (65, "36a370c9eba841a71f704c8f8b682b1c4e95c03e690ece60567c53b184baba93"),
   (119, "da9094b3055a9e5106c40d6fa09aa0b85aba94c968bd1cbaebf31dca4aeab653"),
   (120, "2b884174dba520ff07397c36eb7f8b5f41d38fce5ccbe593f21d15f85ffd16ae"),
   (127, "55f5776786d1c42d79c923c3870118f94bfb4028ab248de6537cd93c882ebdd8"),
   (128, "fe316dabb25b6e7a1148d42cf05f9f161f51342030669ced1de47c65574662a9"),
   (129, "4fd024b537baea73412e08c6a2b7a13bfd90dd94bac29a2bae2d86832a85f34c")]

def runAll : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check := check failures
  check "SHA-256 published empty vector"
    (hex ByteArray.empty == some
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  check "SHA-256 published abc vector"
    (hex "abc".toUTF8 == some
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  check "SHA-256 published two-block padding vector"
    (hex "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8 == some
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
  check "SHA-256 published binary byte vector"
    (hex ⟨#[0x19]⟩ == some
      "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4")
  let millionA := ByteArray.mk (Array.replicate 1000000 (97 : UInt8))
  let millionDigest := "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
  check "SHA-256 published million-a vector" (hex millionA == some millionDigest)
  check "SHA-256 million-a streamed across irregular blocks"
    ((digestUniform millionA 1000).map Digest256.toHex == some millionDigest)
  check "SHA-256 padding-boundary vectors agree with hashlib"
    (boundaryVectors.all fun (size, expected) => hex (sample size) == some expected)
  let input := sample 257
  let expected := sha256 input
  check "SHA-256 every two-chunk split agrees, including empty chunks"
    ((List.range (input.size + 1)).all fun split =>
      digestChunks [input.extract 0 split, ByteArray.empty, input.extract split input.size]
        == expected)
  check "SHA-256 byte/block/page chunk boundaries agree"
    ([1, 7, 55, 56, 63, 64, 65, 127, 256, 4096].all fun size =>
      digestUniform (sample 4097) size == sha256 (sample 4097))
  check "SHA-256 empty stream equals empty input"
    (digestChunks [] == sha256 ByteArray.empty)
  check "SHA-256 state remains bounded across chunks"
    (match Sha256.State.empty.update (sample 8191) with
     | some state => state.wellFormed && state.pending.size == 63 && state.byteCount == 8191
         && (match state.update (sample 66) with
             | some next => next.wellFormed && next.pending.size == 1 && next.byteCount == 8257
             | none => false)
     | none => false)
  check "SHA-256 finalizing preserves a state that can branch into different inputs"
    (match Sha256.State.empty.update "ab".toUTF8 with
     | some state => state.finish == sha256 "ab".toUTF8
         && (state.update "c".toUTF8).bind Sha256.State.finish == sha256 "abc".toUTF8
         && (state.update "d".toUTF8).bind Sha256.State.finish == sha256 "abd".toUTF8
     | none => false)
  check "Digest256 accepts exactly 32 bytes and preserves byte order"
    ((Digest256.ofBytes (sample 31)).isNone && (Digest256.ofBytes (sample 33)).isNone
      && (Digest256.ofBytes (sample 32)).map (·.bytes) == some (sample 32))
  let abc := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  check "Digest256 hex round-trips with canonical lowercase output"
    ((sha256 "abc".toUTF8).bind (fun d => Digest256.ofHex d.toHex) == sha256 "abc".toUTF8
      && (Digest256.ofHex abc.toUpper).map Digest256.toHex == some abc)
  check "Digest256 rejects short long non-hex and non-ASCII encodings"
    ((Digest256.ofHex "").isNone && (Digest256.ofHex (abc ++ "0")).isNone
      && (Digest256.ofHex (" " ++ abc)).isNone
      && (Digest256.ofHex (String.ofList (List.replicate 64 'g'))).isNone
      && (Digest256.ofHex (String.ofList (List.replicate 32 'é'))).isNone)
  let badStates : List Sha256.State :=
    [{ words := #[] }, { words := Array.replicate 7 0 }, { words := Array.replicate 9 0 },
     { pending := sample 64, byteCount := 64 }, { pending := sample 1, byteCount := 0 },
     { byteCount := 1 }, { byteCount := Sha256.byteLimit },
     { byteCount := 2 ^ 64 }]
  check "SHA-256 rejects malformed states before updating or finalizing"
    (badStates.all fun state => !state.wellFormed
      && (state.update ByteArray.empty).isNone && state.finish.isNone)
  let nearLimit : Sha256.State := { byteCount := Sha256.byteLimit - 64 }
  check "SHA-256 rejects lengths reaching the bit-count limit without wrapping"
    (nearLimit.wellFormed && (nearLimit.update (sample 64)).isNone
      && (nearLimit.update (sample 65)).isNone
      && (match nearLimit.update (sample 63) with
          | some state => state.byteCount == Sha256.byteLimit - 1 && state.wellFormed
              && (state.update ByteArray.empty).isSome
              && (state.update (sample 1)).isNone && state.finish.isSome
          | none => false))
  let n ← failures.get
  IO.println (if n == 0 then "== ALL DIGEST GUARDS PASSED ==" else s!"== {n} DIGEST FAILURE(S) ==")
  pure n.toUInt32

end Test.Digest

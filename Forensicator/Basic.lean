/- Forensicator.Lean — shared vocabulary: addresses, positions, provenance,
   anomalies, errors. Port of the Rust `model.rs`/`error.rs` foundations and
   the extractor's `position.rs` packing (TTFX repo, design D3). -/

namespace Forensicator

/-- Virtual address in the traced/dumped process. -/
abbrev VA := UInt64

/-- Packed timeline position `(major << 32) | minor` (.ttfx v1). -/
abbrev Position := UInt64

/-- A raw TTD position pair (data model `Sequence`/`Steps`). The u32 halves
    make the extractor's overflow check type-level: packing is total. -/
structure TtdPosition where
  major : UInt32
  minor : UInt32
  deriving Repr, DecidableEq, BEq

/-- 2^32, the position radix. -/
def posRadix : Nat := 4294967296

/-- Pack a TTD position: `major * 2^32 + minor`. Total because the halves
    are `UInt32` (extractor's D3 overflow case is unrepresentable). -/
def pack (p : TtdPosition) : Position :=
  UInt64.ofNat (p.major.toNat * posRadix + p.minor.toNat)

/-- Inverse of `pack`: `(pos / 2^32, pos % 2^32)`. -/
def unpack (pos : Position) : TtdPosition :=
  ⟨UInt32.ofNat (pos.toNat / posRadix), UInt32.ofNat (pos.toNat % posRadix)⟩

theorem pack_unpack (p : TtdPosition) : unpack (pack p) = p := by
  obtain ⟨M, m⟩ := p
  have hM : M.toNat < 4294967296 := M.toNat_lt_size
  have hm : m.toNat < 4294967296 := m.toNat_lt_size
  have hsum : M.toNat * posRadix + m.toNat < 2 ^ 64 := by
    simp only [posRadix]; omega
  have hub : (UInt64.ofNat (M.toNat * posRadix + m.toNat)).toNat
      = M.toNat * posRadix + m.toNat := UInt64.toNat_ofNat_of_lt' hsum
  have hdiv : (M.toNat * posRadix + m.toNat) / posRadix = M.toNat := by
    simp only [posRadix]; omega
  have hmod : (M.toNat * posRadix + m.toNat) % posRadix = m.toNat := by
    simp only [posRadix]; omega
  show (⟨UInt32.ofNat ((UInt64.ofNat (M.toNat * posRadix + m.toNat)).toNat / posRadix),
         UInt32.ofNat ((UInt64.ofNat (M.toNat * posRadix + m.toNat)).toNat % posRadix)⟩ : TtdPosition)
       = ⟨M, m⟩
  rw [hub, hdiv, hmod]
  simp

/-- Provenance: every decoded fact records its origin
    (stream_type + file_offset + rva), as in the Rust `Provenance`. -/
structure Provenance where
  streamType : UInt32 := 0
  fileOffset : UInt64 := 0
  rva : UInt64 := 0
  deriving Repr, DecidableEq, Inhabited

/-- A recoverable decode defect: malformed input is collected, never fatal.
    Carries the Rust `Anomaly`'s provenance fields (stream_type/file_offset/rva). -/
structure Anomaly where
  streamType : UInt32 := 0
  fileOffset : UInt64 := 0
  rva : UInt64 := 0
  description : String
  deriving Repr, Inhabited, DecidableEq

/-- An anomaly with no provenance (internal consistency findings). -/
def Anomaly.internal (description : String) : Anomaly :=
  { streamType := 0, fileOffset := 0, rva := 0, description }

/-- An anomaly carrying an existing provenance. -/
def Anomaly.ofProv (prov : Provenance) (description : String) : Anomaly :=
  { streamType := prov.streamType, fileOffset := prov.fileOffset
    rva := prov.rva, description := description }

/-- Uppercase hex rendering, matching Rust's `format!("0x{v:X}")`. -/
def hexUpper (v : UInt64) : String :=
  let ds := Nat.toDigits 16 v.toNat
  "0x" ++ String.ofList (ds.map fun c => if c.isAlpha then c.toUpper else c)

/-- Uppercase hex digits, zero-padded to `width` (Rust `{v:0width$X}`). -/
def hexPadUpper (v : UInt64) (width : Nat) : String :=
  let ds := (Nat.toDigits 16 v.toNat).map fun c => if c.isAlpha then c.toUpper else c
  String.ofList (List.replicate (width - ds.length) '0' ++ ds)

/-- Lowercase hex digits, zero-padded to `width`. -/
def hexPadLower (v : UInt64) (width : Nat) : String :=
  let ds := Nat.toDigits 16 v.toNat
  String.ofList (List.replicate (width - ds.length) '0' ++ ds)

/-- Hard errors (unrecoverable: bad magic, truncated header, …). -/
inductive ForensicError where
  | anomaly (a : Anomaly)
  | unsupported (what : String)
  deriving Repr

end Forensicator

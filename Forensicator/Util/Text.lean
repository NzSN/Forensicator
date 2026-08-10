/- Forensicator.Util.Text — lossy UTF-8 decode + CLI number parsing. -/

namespace Forensicator

/-- Lossy UTF-8 decode, matching Rust `String::from_utf8_lossy` exactly:
    lead-byte width table (0xC0/0xC1 invalid), second-byte range checks
    (E0/ED/F0/F4), and one U+FFFD per *maximal subpart* of an invalid
    sequence (error_len semantics); truncated sequences consume the rest. -/
def fromUTF8Lossy (bs : ByteArray) : String :=
  String.ofList (go bs (bs.size + 1) 0 [])
where
  rep : Char := Char.ofNat 0xFFFD
  isCont (b : UInt8) : Bool := 0x80 ≤ b.toNat && b.toNat < 0xC0
  width (b0 : UInt8) : Nat :=
    if b0.toNat < 0x80 then 1
    else if b0.toNat < 0xC2 then 0
    else if b0.toNat < 0xE0 then 2
    else if b0.toNat < 0xF0 then 3
    else if b0.toNat < 0xF8 then 4
    else 0
  ok2 (b0 b1 : UInt8) : Bool :=
    if b0 == 0xE0 then 0xA0 ≤ b1.toNat && b1.toNat < 0xC0
    else if b0 == 0xED then 0x80 ≤ b1.toNat && b1.toNat < 0xA0
    else if b0 == 0xF0 then 0x90 ≤ b1.toNat && b1.toNat < 0xC0
    else if b0 == 0xF4 then 0x80 ≤ b1.toNat && b1.toNat < 0x90
    else isCont b1
  assemble (bs : ByteArray) (i w : Nat) : UInt32 :=
    match w with
    | 2 => ((bs.get! i).toUInt32 &&& 0x1F) <<< 6
        ||| ((bs.get! (i + 1)).toUInt32 &&& 0x3F)
    | 3 => ((bs.get! i).toUInt32 &&& 0x0F) <<< 12
        ||| (((bs.get! (i + 1)).toUInt32 &&& 0x3F) <<< 6)
        ||| ((bs.get! (i + 2)).toUInt32 &&& 0x3F)
    | _ => ((bs.get! i).toUInt32 &&& 0x07) <<< 18
        ||| (((bs.get! (i + 1)).toUInt32 &&& 0x3F) <<< 12)
        ||| (((bs.get! (i + 2)).toUInt32 &&& 0x3F) <<< 6)
        ||| ((bs.get! (i + 3)).toUInt32 &&& 0x3F)
  step (bs : ByteArray) (i : Nat) : Char × Nat :=
    let b0 := bs.get! i
    match width b0 with
    | 1 => (Char.ofNat b0.toNat, 1)
    | 2 =>
      if i + 1 ≥ bs.size then (rep, 1)
      else if !isCont (bs.get! (i + 1)) then (rep, 1)
      else (Char.ofNat (assemble bs i 2).toNat, 2)
    | 3 =>
      if i + 1 ≥ bs.size then (rep, 1)
      else if !ok2 b0 (bs.get! (i + 1)) then (rep, 1)
      else if i + 2 ≥ bs.size then (rep, 2)
      else if !isCont (bs.get! (i + 2)) then (rep, 2)
      else (Char.ofNat (assemble bs i 3).toNat, 3)
    | 4 =>
      if i + 1 ≥ bs.size then (rep, 1)
      else if !ok2 b0 (bs.get! (i + 1)) then (rep, 1)
      else if i + 2 ≥ bs.size then (rep, 2)
      else if !isCont (bs.get! (i + 2)) then (rep, 2)
      else if i + 3 ≥ bs.size then (rep, 3)
      else if !isCont (bs.get! (i + 3)) then (rep, 3)
      else (Char.ofNat (assemble bs i 4).toNat, 4)
    | _ => (rep, 1)
  go (bs : ByteArray) (fuel i : Nat) (acc : List Char) : List Char :=
    match fuel with
    | 0 => acc
    | fuel + 1 =>
      if i < bs.size then
        let (c, adv) := step bs i
        go bs fuel (i + adv) (acc ++ [c])
      else acc

/-- Lossy UTF-16 decode (Rust `String::from_utf16_lossy`): valid sequences
    pass through; unpaired surrogates become U+FFFD. -/
def utf16Lossy (units : List UInt16) : String :=
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

def hexVal (c : Char) : Option UInt64 :=
  if '0' ≤ c && c ≤ '9' then some (UInt64.ofNat (c.toNat - '0'.toNat))
  else if 'a' ≤ c && c ≤ 'f' then some (UInt64.ofNat (c.toNat - 'a'.toNat + 10))
  else if 'A' ≤ c && c ≤ 'F' then some (UInt64.ofNat (c.toNat - 'A'.toNat + 10))
  else none

def decVal (c : Char) : Option UInt64 :=
  if '0' ≤ c && c ≤ '9' then some (UInt64.ofNat (c.toNat - '0'.toNat)) else none

/-- Parse `0x…` hex or decimal (session.rs parse_u64). -/
def parseU64 (s : String) : Except String UInt64 :=
  let digits (cs : List Char) (base : UInt64) (val : Char → Option UInt64) : Option UInt64 :=
    match cs with
    | [] => none
    | _ => cs.foldlM (fun acc c => (val c).map fun d => acc * base + d) 0
  if s.startsWith "0x" || s.startsWith "0X" then
    match digits (s.toList.drop 2) 16 hexVal with
    | some v => .ok v
    | none => .error s!"bad hex value '{s}'"
  else
    match digits s.toList 10 decVal with
    | some v => .ok v
    | none => .error s!"bad value '{s}'"

end Forensicator

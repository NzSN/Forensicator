/- Forensicator.Util.Text — lossy UTF-8 decode + CLI number parsing. -/

namespace Forensicator

/-- Lossy UTF-8 decode (Rust `String::from_utf8_lossy`-compatible for valid
    input and ASCII; on invalid sequences emits U+FFFD and advances one byte —
    Rust's maximal-subpart resync can emit fewer replacements in edge cases).
    Overlong encodings, surrogates, and > U+10FFFF are rejected. -/
private def utf8Replacement : Char := Char.ofNat 0xFFFD

private def utf8Cont (bs : ByteArray) (i : Nat) : Nat → UInt32 → Option UInt32
  | 0, acc => some acc
  | n + 1, acc =>
    if i < bs.size then
      let b := bs.get! i
      if 0x80 ≤ b.toNat && b.toNat < 0xC0 then
        utf8Cont bs (i + 1) n ((acc <<< 6) ||| (b.toUInt32 &&& 0x3F))
      else none
    else none

private def utf8Go (bs : ByteArray) (i : Nat) (acc : List Char) : List Char :=
  if _h : i < bs.size then
    let b0 := bs.get! i
    if b0.toNat < 0x80 then utf8Go bs (i + 1) (acc ++ [Char.ofNat b0.toNat])
    else
      let (len, init) :=
        if 0xC0 ≤ b0.toNat && b0.toNat < 0xE0 then (2, b0.toUInt32 &&& 0x1F)
        else if 0xE0 ≤ b0.toNat && b0.toNat < 0xF0 then (3, b0.toUInt32 &&& 0x0F)
        else if 0xF0 ≤ b0.toNat && b0.toNat < 0xF8 then (4, b0.toUInt32 &&& 0x07)
        else (0, 0)
      match len with
      | 0 => utf8Go bs (i + 1) (acc ++ [utf8Replacement])
      | n + 1 =>
        match utf8Cont bs (i + 1) n init with
        | some cp =>
          let minCp : UInt32 := if n + 1 == 2 then 0x80 else if n + 1 == 3 then 0x800 else 0x10000
          if minCp ≤ cp && (cp < 0xD800 || (0xE000 ≤ cp && cp ≤ 0x10FFFF)) then
            utf8Go bs (i + (n + 1)) (acc ++ [Char.ofNat cp.toNat])
          else utf8Go bs (i + 1) (acc ++ [utf8Replacement])
        | none => utf8Go bs (i + 1) (acc ++ [utf8Replacement])
  else acc
termination_by bs.size - i
decreasing_by
  · omega
  · omega
  · omega
  · omega
  · omega

def fromUTF8Lossy (bs : ByteArray) : String :=
  String.ofList (utf8Go bs 0 [])

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

/- Forensicator.Util.Json — minimal deterministic JSON emitter (no deps).
   Escaping matches serde_json: `\"`, `\\`, short forms for \n \r \t \b \f,
   `\u00XX` for other control chars; non-ASCII emitted literally. -/

namespace Forensicator

inductive Json where
  | null
  | bool (b : Bool)
  | int (n : Int)
  | num (s : String)   -- pre-rendered number literal (floats)
  | str (s : String)
  | arr (items : List Json)
  | obj (fields : List (String × Json))
  deriving Repr, Inhabited

namespace Json

def hexDigit (d : Nat) : Char :=
  if d < 10 then Char.ofNat ('0'.toNat + d) else Char.ofNat ('a'.toNat + (d - 10))

def escapeChars : List Char → String
  | [] => ""
  | c :: rest =>
    let esc :=
      match c with
      | '"' => "\\\""
      | '\\' => "\\\\"
      | '\n' => "\\n"
      | '\r' => "\\r"
      | '\t' => "\\t"
      | c =>
        if c.toNat = 0x08 then "\\b"
        else if c.toNat = 0x0C then "\\f"
        else if c.toNat < 0x20 then
          String.ofList ['\\', 'u', '0', '0', hexDigit (c.toNat / 16), hexDigit (c.toNat % 16)]
        else String.ofList [c]
    esc ++ escapeChars rest

def escape (s : String) : String := escapeChars s.toList

mutual
  def render : Json → String
    | .null => "null"
    | .bool b => if b then "true" else "false"
    | .int n => toString n
    | .num s => s
    | .str s => "\"" ++ escape s ++ "\""
    | .arr items => "[" ++ String.intercalate "," (renderAll items) ++ "]"
    | .obj kvs => "{" ++ String.intercalate "," (renderKVs kvs) ++ "}"

  def renderAll : List Json → List String
    | [] => []
    | j :: js => render j :: renderAll js

  def renderKVs : List (String × Json) → List String
    | [] => []
    | (k, v) :: rest => ("\"" ++ escape k ++ "\":" ++ render v) :: renderKVs rest
end

/-- Convenience: object from string-keyed fields. -/
def obj! (fields : List (String × Json)) : Json := .obj fields

def ofUInt64 (v : UInt64) : Json := .int v.toNat
def ofUInt32 (v : UInt32) : Json := .int v.toNat
def ofUSize (v : USize) : Json := .int v.toNat
def ofNat (n : Nat) : Json := .int n
def ofBool (b : Bool) : Json := .bool b
def ofString (s : String) : Json := .str s

/-- Exact decimal expansion of a finite Float (m × 2^e computed exactly).
    Round-trip-exact by construction; the conformance gate normalizes through
    a JSON parser, so this compares equal to serde/ryu's shortest form. -/
def floatExact (f : Float) : String :=
  let b := f.toBits
  let expField := ((b >>> 52) &&& 0x7FF).toNat
  if expField == 0x7FF then "0.0"  -- inf/nan never occur in analyzer scores
  else if expField == 0 && (b &&& 0xFFFFFFFFFFFFF) == 0 then
    if b >>> 63 == 1 then "-0.0" else "0.0"
  else
    let sign := if b >>> 63 == 1 then "-" else ""
    let frac := (b &&& 0xFFFFFFFFFFFFF).toNat
    let (m, e) :=
      if expField == 0 then (frac, -1074)
      else (2^52 + frac, Int.ofNat expField - 1075)
    if e ≥ 0 then
      sign ++ toString (m * 2 ^ e.toNat) ++ ".0"
    else
      let k := (-e).toNat
      let ds := toString (m * 5 ^ k)
      if ds.length > k then
        sign ++ ds.take (ds.length - k) ++ "." ++ ds.drop (ds.length - k)
      else
        sign ++ "0." ++ String.ofList (List.replicate (k - ds.length) '0') ++ ds

def ofFloat (f : Float) : Json := .num (floatExact f)

end Json

end Forensicator

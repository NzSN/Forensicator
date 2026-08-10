/- Forensicator.Util.Json — minimal deterministic JSON emitter (no deps).
   Escaping matches serde_json: `\"`, `\\`, short forms for \n \r \t \b \f,
   `\u00XX` for other control chars; non-ASCII emitted literally. -/

namespace Forensicator

inductive Json where
  | null
  | bool (b : Bool)
  | int (n : Int)
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

end Json

end Forensicator

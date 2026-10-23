/- Total JSON reader for protocol input. Bounded nesting, node count and input
   size; rejects duplicate keys and malformed Unicode rather than guessing.
   Uses the same Json type/emitter as forensic reports, with no dependencies. -/
import Forensicator.Util.Json

namespace Forensicator.Json

def maxInputBytes : Nat := 1024 * 1024

private structure Cursor where
  chars : Array Char
  pos : Nat := 0
  nodes : Nat := 8192

private abbrev Parser := StateT Cursor (Except String)

private def fail (message : String) : Parser α := do
  throw s!"{message} at character {(← getThe Cursor).pos}"

private def peek : Parser (Option Char) := do
  let s ← getThe Cursor
  pure s.chars[s.pos]?

private def pop : Parser Char := do
  match ← peek with
  | none => fail "unexpected end of JSON"
  | some c => modify fun s => { s with pos := s.pos + 1 }; pure c

private def expect (c : Char) : Parser Unit := do
  if (← pop) != c then fail s!"expected '{c}'"

private def space : Parser Unit := do
  for _ in [: (← getThe Cursor).chars.size] do
    match ← peek with
    | some c =>
      if c == ' ' || c == '\t' || c == '\r' || c == '\n' then
        let _ ← pop
      else break
    | none => break

private def hex4 : Parser Nat := do
  let mut n := 0
  for _ in [:4] do
    let c ← pop
    let digit ←
      if '0' ≤ c && c ≤ '9' then pure (c.toNat - '0'.toNat)
      else if 'a' ≤ c && c ≤ 'f' then pure (c.toNat - 'a'.toNat + 10)
      else if 'A' ≤ c && c ≤ 'F' then pure (c.toNat - 'A'.toNat + 10)
      else fail "invalid Unicode escape"
    n := n * 16 + digit
  pure n

private def unicode : Parser Char := do
  let hi ← hex4
  if 0xD800 ≤ hi && hi ≤ 0xDBFF then
    expect '\\'
    expect 'u'
    let lo ← hex4
    if lo < 0xDC00 || lo > 0xDFFF then fail "invalid low surrogate"
    else pure (Char.ofNat (0x10000 + (hi - 0xD800) * 1024 + lo - 0xDC00))
  else if 0xDC00 ≤ hi && hi ≤ 0xDFFF then fail "unpaired low surrogate"
  else pure (Char.ofNat hi)

private def string : Parser String := do
  expect '"'
  let mut out := ""
  for _ in [: (← getThe Cursor).chars.size + 1] do
    let c ← pop
    if c == '"' then return out
    if c.toNat < 32 then fail "unescaped control character"
    if c == '\\' then
      let escaped ← pop
      let value ← match escaped with
        | '"' => pure '"' | '\\' => pure '\\' | '/' => pure '/'
        | 'b' => pure (Char.ofNat 8) | 'f' => pure (Char.ofNat 12)
        | 'n' => pure '\n' | 'r' => pure '\r' | 't' => pure '\t'
        | 'u' => unicode
        | _ => fail "invalid string escape"
      out := out.push value
    else out := out.push c
  fail "unterminated string"

private def digits : Parser String := do
  let mut out := ""
  for _ in [: (← getThe Cursor).chars.size] do
    match ← peek with
    | some c =>
      if c.isDigit then
        if out.utf8ByteSize == 1024 then fail "JSON number exceeds 1024 characters"
        out := out.push (← pop)
      else break
    | none => break
  pure out

private def number : Parser Json := do
  let mut out := ""
  if (← peek) == some '-' then out := out.push (← pop)
  if (← peek) == some '0' then
    out := out.push (← pop)
    if ((← peek).map Char.isDigit).getD false then fail "leading zero in number"
  else
    let ds ← digits
    if ds.isEmpty then fail "expected number"
    out := out ++ ds
  let mut fractional := false
  if (← peek) == some '.' then
    fractional := true
    out := out.push (← pop)
    let ds ← digits
    if ds.isEmpty then fail "missing fractional digits"
    out := out ++ ds
  let c ← peek
  if c == some 'e' || c == some 'E' then
    fractional := true
    out := out.push (← pop)
    let sign ← peek
    if sign == some '+' || sign == some '-' then out := out.push (← pop)
    let ds ← digits
    if ds.isEmpty then fail "missing exponent digits"
    out := out ++ ds
  if out.utf8ByteSize > 1024 then fail "JSON number exceeds 1024 characters"
  if fractional then pure (.num out)
  else match out.toInt? with
    | some n => pure (.int n)
    | none => fail "invalid integer"

private def literal (text : String) (value : Json) : Parser Json := do
  for c in text.toList do expect c
  pure value

private def value : Nat → Parser Json
  | 0 => fail "JSON nesting limit exceeded"
  | depth + 1 => do
    space
    if (← getThe Cursor).nodes == 0 then fail "JSON node limit exceeded"
    modify fun s => { s with nodes := s.nodes - 1 }
    match ← peek with
    | some '"' => return .str (← string)
    | some 't' => literal "true" (.bool true)
    | some 'f' => literal "false" (.bool false)
    | some 'n' => literal "null" .null
    | some '[' => do
      expect '['
      space
      if (← peek) == some ']' then expect ']'; return .arr []
      let mut items := #[]
      for _ in [: (← getThe Cursor).chars.size + 1] do
        items := items.push (← value depth)
        space
        match ← pop with
        | ']' => return .arr items.toList
        | ',' => pure ()
        | _ => fail "expected ',' or ']'"
      fail "unterminated array"
    | some '{' => do
      expect '{'
      space
      if (← peek) == some '}' then expect '}'; return .obj []
      let mut fields : Array (String × Json) := #[]
      for _ in [: (← getThe Cursor).chars.size + 1] do
        space
        let key ← string
        if fields.any (·.1 == key) then fail s!"duplicate object key '{key}'"
        space
        expect ':'
        let item ← value depth
        fields := fields.push (key, item)
        space
        match ← pop with
        | '}' => return .obj fields.toList
        | ',' => pure ()
        | _ => fail "expected ',' or '}'"
      fail "unterminated object"
    | some c => if c == '-' || c.isDigit then number else fail "expected JSON value"
    | none => fail "expected JSON value"

/-- Parse one complete JSON value, with at most 64 nested values and 8192
    nodes. Number literals (at most 1024 characters) are retained exactly. -/
def parse (text : String) : Except String Json := do
  if text.utf8ByteSize > maxInputBytes then throw "JSON input exceeds 1 MiB"
  let parser : Parser Json := do
    let result ← value 64
    space
    if (← peek).isSome then fail "trailing data after JSON value"
    pure result
  let (result, _) ← parser.run { chars := text.toList.toArray }
  pure result

end Forensicator.Json

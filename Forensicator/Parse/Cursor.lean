/- Forensicator.Parse.Cursor — the total byte-cursor parser monad.

   All reads are bounds-checked against `bytes.size` and `throw` an `Anomaly`;
   no partial indexing escapes (`ByteArray.get!` below is always guarded).
   This is the Lean realization of the Rust hand-written parser's fail-closed
   contract. -/
import Forensicator.Basic

namespace Forensicator.Parse

structure Cursor where
  bytes : ByteArray
  pos : Nat
  deriving Inhabited

abbrev ParseM := ExceptT Anomaly (StateM Cursor)

def Cursor.atEnd (c : Cursor) : Bool := c.pos ≥ c.bytes.size

private def truncated (off n : Nat) : Anomaly :=
  ⟨(UInt64.ofNat off), s!"truncated read: {n} byte(s) at offset {off}"⟩

/-- Read `n` raw bytes, advancing the cursor. -/
def readBytes (n : Nat) : ParseM ByteArray := do
  let c ← get
  if c.pos + n ≤ c.bytes.size then
    let out := c.bytes.extract c.pos (c.pos + n)
    set { c with pos := c.pos + n }
    pure out
  else
    throw (truncated c.pos n)

/-- Peek at `n` raw bytes without advancing. -/
def peekBytes (n : Nat) : ParseM ByteArray := do
  let c ← get
  if c.pos + n ≤ c.bytes.size then
    pure (c.bytes.extract c.pos (c.pos + n))
  else
    throw (truncated c.pos n)

/-- Move the cursor to an absolute offset (checked). -/
def seek (off : Nat) : ParseM Unit := do
  let c ← get
  if off ≤ c.bytes.size then set { c with pos := off }
  else throw ⟨(UInt64.ofNat off), s!"seek past end: {off} (size {c.bytes.size})"⟩

/-- Current absolute offset. -/
def tell : ParseM Nat := return (← get).pos

/-- Bytes remaining. -/
def remaining : ParseM Nat := return (← get).bytes.size - (← get).pos

private def byteAt (c : Cursor) (i : Nat) : UInt8 := c.bytes.get! (c.pos + i)

def readU8 : ParseM UInt8 := do
  let c ← get
  if c.pos + 1 ≤ c.bytes.size then
    let b := byteAt c 0
    set { c with pos := c.pos + 1 }
    pure b
  else throw (truncated c.pos 1)

def readU16le : ParseM UInt16 := do
  let c ← get
  if c.pos + 2 ≤ c.bytes.size then
    let v := (byteAt c 0).toUInt16
      ||| ((byteAt c 1).toUInt16 <<< 8)
    set { c with pos := c.pos + 2 }
    pure v
  else throw (truncated c.pos 2)

def readU32le : ParseM UInt32 := do
  let c ← get
  if c.pos + 4 ≤ c.bytes.size then
    let v := (byteAt c 0).toUInt32
      ||| ((byteAt c 1).toUInt32 <<< 8)
      ||| ((byteAt c 2).toUInt32 <<< 16)
      ||| ((byteAt c 3).toUInt32 <<< 24)
    set { c with pos := c.pos + 4 }
    pure v
  else throw (truncated c.pos 4)

def readU64le : ParseM UInt64 := do
  let c ← get
  if c.pos + 8 ≤ c.bytes.size then
    let v := (byteAt c 0).toUInt64
      ||| ((byteAt c 1).toUInt64 <<< 8)
      ||| ((byteAt c 2).toUInt64 <<< 16)
      ||| ((byteAt c 3).toUInt64 <<< 24)
      ||| ((byteAt c 4).toUInt64 <<< 32)
      ||| ((byteAt c 5).toUInt64 <<< 40)
      ||| ((byteAt c 6).toUInt64 <<< 48)
      ||| ((byteAt c 7).toUInt64 <<< 56)
    set { c with pos := c.pos + 8 }
    pure v
  else throw (truncated c.pos 8)

/-- Run a parser at an absolute offset, restoring the cursor afterwards. -/
def atOffset (off : Nat) (p : ParseM α) : ParseM α := do
  let saved := (← get).pos
  seek off
  let a ← p
  modify fun c => { c with pos := saved }
  pure a

/-- Lift a whole-buffer parse. -/
def run (bytes : ByteArray) (p : ParseM α) : Except Anomaly α :=
  (ExceptT.run p ⟨bytes, 0⟩).1

end Forensicator.Parse

/- Forensicator.Util.Bytes — shared little-endian readers over ByteArray
   (bounds pre-checked by callers, as everywhere in this codebase). -/
namespace Forensicator

/-- Read 8 LE bytes at `off` (caller guarantees `off + 8 ≤ data.size`). -/
def readU64leAt (data : ByteArray) (off : Nat) : UInt64 :=
  (data.get! off).toUInt64
    ||| ((data.get! (off + 1)).toUInt64 <<< 8)
    ||| ((data.get! (off + 2)).toUInt64 <<< 16)
    ||| ((data.get! (off + 3)).toUInt64 <<< 24)
    ||| ((data.get! (off + 4)).toUInt64 <<< 32)
    ||| ((data.get! (off + 5)).toUInt64 <<< 40)
    ||| ((data.get! (off + 6)).toUInt64 <<< 48)
    ||| ((data.get! (off + 7)).toUInt64 <<< 56)

/-- Read 4 LE bytes (caller guarantees `off + 4 ≤ data.size`). -/
def readU32leAt (data : ByteArray) (off : Nat) : UInt32 :=
  (data.get! off).toUInt32
    ||| ((data.get! (off + 1)).toUInt32 <<< 8)
    ||| ((data.get! (off + 2)).toUInt32 <<< 16)
    ||| ((data.get! (off + 3)).toUInt32 <<< 24)

/-- Read 2 LE bytes (caller guarantees `off + 2 ≤ data.size`). -/
def readU16leAt (data : ByteArray) (off : Nat) : UInt16 :=
  (data.get! off).toUInt16 ||| ((data.get! (off + 1)).toUInt16 <<< 8)

end Forensicator

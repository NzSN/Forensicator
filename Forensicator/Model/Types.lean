/- Forensicator.Model.Types — region classification + state enums
   (port of model.rs:105-149). -/
import Forensicator.Basic

namespace Forensicator

/-- Region memory state (minidump `MEMORY_BASIC_INFO.State`). -/
inductive MemState where
  | Commit   -- 0
  | Reserve  -- 1
  | Free     -- 2
  deriving Repr, DecidableEq, BEq, Inhabited

def MemState.ofUInt32 : UInt32 → Option MemState
  | 0 => some .Commit
  | 1 => some .Reserve
  | 2 => some .Free
  | _ => none

/-- Region classification (pointer-pattern interpretation depends on it). -/
inductive RegionClass where
  | Image | Stack | Mapped | Private | Other
  deriving Repr, DecidableEq, BEq, Inhabited

def RegionClass.toString : RegionClass → String
  | .Image => "image" | .Stack => "stack" | .Mapped => "mapped"
  | .Private => "private" | .Other => "other"

end Forensicator

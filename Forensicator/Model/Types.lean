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

/-- Memory type (minidump `MEMORY_BASIC_INFO.Type`). -/
inductive MemType where
  | Private  -- 0
  | Mapped   -- 1
  | Image    -- 2
  deriving Repr, DecidableEq, BEq, Inhabited

def MemType.ofUInt32 : UInt32 → Option MemType
  | 0 => some .Private
  | 1 => some .Mapped
  | 2 => some .Image
  | _ => none

/-- Memory protection bitflags (model.rs `Protection`). -/
abbrev Protection := UInt32

namespace Protection
def READ : Protection := 1
def WRITE : Protection := 2
def EXECUTE : Protection := 4
def GUARD : Protection := 8
def NO_CACHE : Protection := 16
def isReadable (p : Protection) : Bool := p &&& READ != 0
def isWritable (p : Protection) : Bool := p &&& WRITE != 0
def isExecutable (p : Protection) : Bool := p &&& EXECUTE != 0
end Protection

end Forensicator

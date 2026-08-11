/- Forensicator.Model.Structs — analyzer-facing model types
   (model.rs:460-660: matchers, contexts, candidate pointers, structures). -/
import Forensicator.Model.Types

namespace Forensicator.Model

/-- String encoding detected by the string scanner. `toString` matches the
    Rust `{:?}` Debug names (used in analyze JSON). -/
inductive StringEncoding where
  | Ascii | Utf16Le | Utf16Be
  deriving Repr, DecidableEq, BEq, Inhabited

def StringEncoding.debug : StringEncoding → String
  | .Ascii => "Ascii" | .Utf16Le => "Utf16Le" | .Utf16Be => "Utf16Be"

structure StructString where
  va : VA
  byteLen : Nat
  encoding : StringEncoding
  content : String
  confidence : Float

structure StructVTable where
  va : VA
  methodCount : Nat
  methods : List UInt64
  moduleName : Option String
  confidence : Float

structure StructLinkedList where
  headVa : VA
  length : Nat
  stride : UInt64
  nextOffset : UInt64
  isCircular : Bool
  nodes : List UInt64
  avgConfidence : Float

structure StructArray where
  startVa : VA
  elementSize : UInt64
  count : Nat
  outDegree : Nat
  regionClass : RegionClass
  elements : List UInt64
  confidence : Float

structure StructChunk where
  vaStart : VA
  size : UInt64
  isFree : Bool
  nodeCount : Nat
  pointerDensity : Float
  confidence : Float

structure ShapeSignature where
  edges : List (UInt64 × RegionClass)
  deriving DecidableEq, BEq

structure ShapeGroup where
  id : Nat
  signature : ShapeSignature
  memberCount : Nat
  members : List UInt64

/-- Where a pointer value was found. -/
inductive SourceContext where
  | stack (threadId : Option UInt32)
  | heap (regionVa : Option VA)
  | moduleData (moduleName : Option String)
  | register (registerName : Option String)
  | anyCommitted
  deriving Repr, DecidableEq, BEq

/-- What kind of memory region a pointer targets. -/
inductive TargetContext where
  | image | stack | heap | mapped | anyReadable
  deriving Repr, DecidableEq, BEq

/-- A candidate pointer found by the scanner. -/
structure CandidatePointer where
  sourceVa : VA
  targetVa : VA
  sourceCtx : SourceContext
  targetCtx : TargetContext
  confidence : Float

/-- Byte-level predicate on a raw 8-byte value (model.rs:460).
    Divergence: shifts by ≥ 64 give 0 here (Lean), vs LLVM-masked amounts in
    release Rust — presets only use n ≤ 8, so unobservable in practice. -/
inductive ValueMatcher where
  | alignedTo (n : UInt8)
  | bitMask (mask expected : UInt64)
  | bitZero (n : UInt8)
  | bitOne (n : UInt8)
  | canonicalX64
  | inRange (lo hi : UInt64)
  | modulo (divisor remainder : UInt64)
  | matchSize (n : UInt8)
  | knownVA (va : UInt64)

def ValueMatcher.eval : ValueMatcher → UInt64 → Bool
  | .alignedTo n, v => v &&& ((UInt64.ofNat n.toNat) - 1) == 0
  | .bitMask mask expected, v => v &&& mask == expected
  | .bitZero n, v => v &&& ((1 : UInt64) <<< (UInt64.ofNat n.toNat)) == 0
  | .bitOne n, v => v &&& ((1 : UInt64) <<< (UInt64.ofNat n.toNat)) != 0
  | .canonicalX64, v =>
    (v >>> 48) == (if (v >>> 47) &&& 1 == 1 then 0xFFFF else 0x0000)
  | .inRange lo hi, v => decide (lo ≤ v ∧ v ≤ hi)
  | .modulo divisor remainder, v => if divisor == 0 then false else v % divisor == remainder
  | .matchSize 4, v => decide (v ≤ 0xFFFFFFFF)
  | .matchSize 8, _ => true
  | .matchSize _, _ => false
  | .knownVA va, v => v == va

end Forensicator.Model

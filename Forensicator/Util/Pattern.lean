/- Forensicator.Util.Pattern — pointer patterns (pattern.rs port). -/
import Forensicator.Model.Structs

namespace Forensicator

open Model

structure PointerPattern where
  name : String
  valueMatchers : List ValueMatcher := []
  source : SourceContext := .anyCommitted
  target : TargetContext := .anyReadable
  minConfidence : Float := 0.0
  maxDepthFromRoot : Option Nat := none
  deriving Inhabited

namespace PointerPattern

def withMatcher (m : ValueMatcher) (p : PointerPattern) : PointerPattern :=
  { p with valueMatchers := p.valueMatchers ++ [m] }

def withMinConfidence (c : Float) (p : PointerPattern) : PointerPattern :=
  { p with minConfidence := min (max 0.0 c) 1.0 }

/-- Test whether a single raw value passes all value matchers. -/
def valueMatches (p : PointerPattern) (value : UInt64) : Bool :=
  p.valueMatchers.all (·.eval value)

def allStrict : PointerPattern :=
  { name := "all_strict", minConfidence := 0.5
    valueMatchers := [.alignedTo 8, .canonicalX64] }

def allLoose : PointerPattern :=
  { name := "all_loose", minConfidence := 0.3
    valueMatchers := [.alignedTo 4] }

def savedFramePointers : PointerPattern :=
  { name := "saved_frame_pointers", minConfidence := 0.6
    valueMatchers := [.alignedTo 8]
    source := .stack none, target := .stack }

def vtables : PointerPattern :=
  { name := "vtables", minConfidence := 0.4
    valueMatchers := [.alignedTo 8, .canonicalX64]
    source := .moduleData none, target := .image }

def heapReferences : PointerPattern :=
  { name := "heap_references", minConfidence := 0.35
    valueMatchers := [.alignedTo 8, .canonicalX64]
    source := .heap none, target := .heap }

/-- Built-in presets (pattern.rs presets()). -/
def presets : List PointerPattern :=
  [allStrict, allLoose, savedFramePointers, vtables, heapReferences]

end PointerPattern

end Forensicator

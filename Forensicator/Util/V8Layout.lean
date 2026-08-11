/- Forensicator.Util.V8Layout — version-pinned V8 internals (v8layout.rs
   port). Everything that can change between V8 releases lives here. -/
import Forensicator.Model.Structs
import Forensicator.Util.Text
import Forensicator.Model.Dump

namespace Forensicator.Util

open Forensicator.Model

/-- V8 stack-frame type classification (model.rs V8FrameType; names match
    the Rust `{:?}` Debug strings via `debug`). -/
inductive V8FrameType where
  | javaScript | optimizedJavaScript | wasmCompiled | exit | stub | builtin
  | construct | internal | cpp | unknown
  deriving Repr, DecidableEq, BEq, Inhabited

def V8FrameType.debug : V8FrameType → String
  | .javaScript => "JavaScript"
  | .optimizedJavaScript => "OptimizedJavaScript"
  | .wasmCompiled => "WasmCompiled"
  | .exit => "Exit"
  | .stub => "Stub"
  | .builtin => "Builtin"
  | .construct => "Construct"
  | .internal => "Internal"
  | .cpp => "Cpp"
  | .unknown => "Unknown"

/-- All version-sensitive offsets, masks, and tables for one V8 release. -/
structure V8Layout where
  kContextOffset : Int
  kFunctionOffset : Int
  kMarkerOffset : Int
  kFunctionOffsetLegacy : Int
  jsfunctionSharedFunctionInfo : UInt64
  jsfunctionContext : UInt64
  sfiNameOrScopeInfo : UInt64
  sfiScript : UInt64
  scriptName : UInt64
  scriptLineOffset : UInt64
  scriptLineEnds : UInt64
  stringLength : UInt64
  stringChars : UInt64
  stringItypeMax : UInt16
  stringOneByteBit : UInt16
  stringExternalBit : UInt16
  maxJsNameLen : UInt32
  scopeFlags : UInt64
  scopeParamCount : UInt64
  scopeLocalCount : UInt64
  scopePositionStart : UInt64
  scopeDynamicStart : UInt64
  scopeTypeModule : UInt32
  scopeFlagSavedClassVariable : UInt32
  scopeFunctionVariableShift : UInt32
  scopeFunctionVariableMask : UInt32
  scopeFlagInferredFunctionName : UInt32
  scopeMaxInlinedLocalNames : UInt32
  fixedArrayLength : UInt64
  fixedArrayData : UInt64
  eptEntrySize : UInt64
  eptIndexShift : Nat
  eptPayloadMask : UInt64
  deriving Inhabited

/-- StackFrame::Type mapping for V8 14.6. -/
def markerTypeV14_6 (marker : UInt64) : Option V8FrameType :=
  match marker with
  | 3 | 4 => some .javaScript
  | 5 | 6 => some .optimizedJavaScript
  | 7 | 8 => some .stub
  | 9 | 10 | 11 => some .builtin
  | 13 | 14 => some .construct
  | 15 => some .builtin
  | 2 | 16 | 17 | 18 | 19 | 20 | 21 => some .exit
  | 1 | 12 => some .internal
  | m => if 22 ≤ m && m ≤ 40 then some .wasmCompiled else none

/-- V8 14.6 (Chromium 146 / Electron 41). -/
def V8Layout.v14_6 : V8Layout where
  kContextOffset := -8
  kFunctionOffset := -16
  kMarkerOffset := -24
  kFunctionOffsetLegacy := -24
  jsfunctionSharedFunctionInfo := 16
  jsfunctionContext := 20
  sfiNameOrScopeInfo := 12
  sfiScript := 20
  scriptName := 8
  scriptLineOffset := 12
  scriptLineEnds := 28
  stringLength := 8
  stringChars := 12
  stringItypeMax := 0x40
  stringOneByteBit := 0x08
  stringExternalBit := 0x02
  maxJsNameLen := 4096
  scopeFlags := 4
  scopeParamCount := 8
  scopeLocalCount := 12
  scopePositionStart := 16
  scopeDynamicStart := 24
  scopeTypeModule := 5
  scopeFlagSavedClassVariable := (1 : UInt32) <<< 10
  scopeFunctionVariableShift := 12
  scopeFunctionVariableMask := 0x3
  scopeFlagInferredFunctionName := (1 : UInt32) <<< 14
  scopeMaxInlinedLocalNames := 512
  fixedArrayLength := 4
  fixedArrayData := 8
  eptEntrySize := 16
  eptIndexShift := 6
  eptPayloadMask := 0x0000FFFFFFFFFFFF

/-- V8 version (major, minor) → layout. -/
def V8Layout.forV8Version (major _minor : UInt32) : Option V8Layout :=
  if major == 14 then some V8Layout.v14_6 else none

def V8Layout.electronToChromiumMajor : UInt32 → Option UInt32
  | 41 => some 146
  | 40 => some 144
  | 39 => some 142
  | _ => none

def V8Layout.chromiumToV8 (chromiumMajor : UInt32) : Option (UInt32 × UInt32) :=
  if 132 ≤ chromiumMajor && chromiumMajor ≤ 146 then
    some (14, chromiumMajor - 132)
  else none

/-- Select layout from dump annotations (`ver` = Electron version); falls
    back to v14_6 when unknown (structural validation fails closed). -/
def V8Layout.detect (dump : Dump) : V8Layout :=
  let rec go : List (String × String) → V8Layout
    | [] => V8Layout.v14_6
    | (k, v) :: rest =>
      if k != "ver" then go rest
      else
        let major : UInt32 := match (v.splitOn ".").head? with
          | some s => ((parseU64 s).toOption.getD 0).toUInt32
          | none => 0
        match V8Layout.electronToChromiumMajor major with
        | some ch =>
          match V8Layout.chromiumToV8 ch with
          | some (vmaj, vmin) => (V8Layout.forV8Version vmaj vmin).getD V8Layout.v14_6
          | none => V8Layout.v14_6
        | none => V8Layout.v14_6
  go dump.annotations

def V8Layout.markerFrameType (_l : V8Layout) (marker : UInt64) : Option V8FrameType :=
  markerTypeV14_6 marker

end Forensicator.Util

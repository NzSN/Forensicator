/- Forensicator.Util.V8Layout — version-pinned V8 internals (v8layout.rs
   port). Everything that can change between V8 releases lives here. -/
import Forensicator.Model.Structs
import Forensicator.Util.Text
import Forensicator.Model.Execution

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
  externalStringResourceData : UInt64
  stringItypeMax : UInt16
  stringOneByteBit : UInt16
  stringExternalBit : UInt16
  -- instance-type.h:30 kStringRepresentationMask = (1<<3)-1; the external
  -- test is (itype &&& stringRepMask) == stringExternalBit (a bare &&& 2
  -- would misclassify sliced strings, rep 3).
  stringRepMask : UInt16
  -- instance-type.h:73 kUncachedExternalStringMask = 1<<4; uncached
  -- external strings LACK the resource_data field (string.tq WARNING).
  stringUncachedExternalBit : UInt16
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
  -- Phase 1 (in-cage, compressed pointers): FeedbackVector / FeedbackCell
  jsfunctionFeedbackCell : UInt64
  feedbackCellVector : UInt64
  feedbackVectorLength : UInt64
  feedbackVectorSfi : UInt64
  feedbackVectorSlots : UInt64
  itypeFeedbackVector : UInt16
  itypeWeakArrayList : UInt16
  itypeMap : UInt16
  itypeFeedbackCell : UInt16
  itypeClosureFeedbackCellArray : UInt16
  itypeJsFunctionFirst : UInt16
  itypeJsFunctionLast : UInt16
  itypeSharedFunctionInfo : UInt16
  itypeScopeInfo : UInt16
  weakArrayListLength : UInt64
  weakArrayListData : UInt64
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
  -- ExternalString.resource_data @ +0x10 (in-object EPT handle, 4-byte slot):
  --   v8/src/objects/string.tq:85-88 (resource @ sizeof(String) = 12,
  --   resource_data @ kResourceOffset + kExternalPointerSlotSize = 16;
  --   slot size = sizeof(ExternalPointer_t) = 4 with sandbox —
  --   v8/src/common/globals.h:644 kExternalPointerSlotSize,
  --   v8/include/v8-internal.h:356 ExternalPointerHandle = uint32_t,
  --   l.362 ExternalPointer_t = ExternalPointerHandle under V8_ENABLE_SANDBOX).
  --   Confirmed on the nicholas dump: EPT handles 0x000b8f80 @ +0xC (resource)
  --   and 0x000b8fc0 @ +0x10 (resource_data). String.tq:87 warns the field is
  --   MISSING for UNCACHED_EXTERNAL_* strings (fail closed when reading;
  --   uncached GetChars falls back to the resource, string.tq:108-114).
  externalStringResourceData := 16
  stringItypeMax := 0x40
  stringOneByteBit := 0x08
  stringExternalBit := 0x02
  stringRepMask := 0x07
  stringUncachedExternalBit := 0x10
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
  -- External pointer table (sandbox); pinned from the Electron 41.10.6
  -- build checkout (V8 14.6.202.33-23-g3c5759b05fe), v8/include/v8-internal.h:
  --   l.324 kExternalPointerTableEntrySize = 8 (was 16 — wrong stride)
  eptEntrySize := 8
  --   l.320 kExternalPointerIndexShift = 6 (default 512 MB reservation;
  --   Android 7 @ l.310, iOS 8 @ l.317 — Windows/Linux default assumed,
  --   design Open Question 2)
  eptIndexShift := 6
  --   l.347 kExternalPointerPayloadMask: clears tag+mark bits 48..55
  --   (kExternalPointerMarkBit @ l.339, kExternalPointerTagMask @ l.341),
  --   keeps the 48-bit payload (bits 0..47) and bits 56..63 (unused for
  --   valid entries). Was 0x0000FFFFFFFFFFFF — wrong value, broke every
  --   EPT resolution in findEptBase/externalStringViaEpt
  eptPayloadMask := 0xff00ffffffffffff
  -- Phase 1: FeedbackVector / FeedbackCell (V8 14.6, compressed pointers)
  -- JSFunction.feedback_cell @ +24 (after dispatch_handle@12, sfi@16, context@20)
  jsfunctionFeedbackCell := 24
  -- FeedbackCell: map(4) + value@4 (Tagged<HeapObject>) + dispatch_handle@8(int32) + interrupt_budget@12(int32)
  feedbackCellVector := 4
  -- FeedbackVector (V8 14.6, compressed pointers, from feedback-vector.tq):
  --   map(4) + length@4(int32) + invocation_count@8(int32)
  --   + invocation_count_before_stable@12(u8) + osr_state@13(u8) + flags@14(u16)
  --   + shared_function_info@16(compressed) + closure_feedback_cell_array@20
  --   + parent_feedback_cell@24 + raw_feedback_slots[]@28
  feedbackVectorLength := 4
  feedbackVectorSfi := 16
  feedbackVectorSlots := 28
  -- Instance type constants (from v8::internal::InstanceType, V8 14.6)
  itypeFeedbackVector := 0x0083
  itypeWeakArrayList := 0x008c
  itypeMap := 0x0116
  itypeFeedbackCell := 0x009c
  itypeClosureFeedbackCellArray := 0x010f
  -- Instance type range/values pinned from the torque-generated header of
  -- the nicholas build (out/Release_S_41_10_6/gen/v8/torque-generated/
  -- instance-types.h, V8 14.6.202.33-23-g3c5759b05fe):
  --   l.282 FIRST_JS_FUNCTION_TYPE = 2066 = 0x0812 (JS_FUNCTION_TYPE,
  --   v8/src/objects/js-function.tq:30)
  itypeJsFunctionFirst := 0x0812
  --   l.302 LAST_JS_FUNCTION_TYPE = 2082 = 0x0822 (JS_CLASS_CONSTRUCTOR_TYPE,
  --   js-function.tq:44)
  itypeJsFunctionLast := 0x0822
  --   l.228 SHARED_FUNCTION_INFO_TYPE = 288 = 0x0120 (shared-function-info.tq:62)
  itypeSharedFunctionInfo := 0x0120
  --   l.226 SCOPE_INFO_TYPE = 286 = 0x011E (scope-info.tq:119)
  itypeScopeInfo := 0x011E
  -- WeakArrayList: map(4) + capacity(4 Smi) + elements[]@8
  weakArrayListLength := 4
  weakArrayListData := 8

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

/-- Select layout from input annotations (`ver` = Electron version); falls
    back to v14_6 when unknown (structural validation fails closed). -/
def V8Layout.detect (input : AnalysisInput) : V8Layout :=
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
  go input.annotations

def V8Layout.markerFrameType (_l : V8Layout) (marker : UInt64) : Option V8FrameType :=
  markerTypeV14_6 marker

end Forensicator.Util

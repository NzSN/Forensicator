# Resolving V8 JIT JavaScript Frames in Minidumps

How the `v8` analyzer recovers JS function names for JIT-compiled frames
(`OptimizedJavaScript` / `JavaScript`) from a full Windows minidump.

## Problem

Native stack walking (RBP chain) plus PDB symbolication resolves C/C++ frames,
but JIT-compiled JavaScript runs in V8-managed executable pages that belong to
no loaded module. Such frames appear as raw addresses:

```
#3  0x7FF7E2344A05   [JavaScript]   <no symbol>
```

These frames carry no entries in any PDB — the only source of truth is V8's own
heap metadata, which lives entirely inside the dump's private memory regions.

## Prerequisites found in the dump

Electron crash annotations (Crashpad) supply the two values we need:

| Annotation | Example | Meaning |
|---|---|---|
| `v8_isolate_address` | `0x68340051c000` | the V8 isolate |
| `v8_ro_space_firstpage_address` | `0x29000000000` | start of the pointer-compression cage (read-only space sits at the cage start) |
| `ver` | `41.8.0` | Electron version → pins the exact V8 layout |

The case dump is Electron 41.8.0 → Chromium 146.0.7680.216 → V8 revision
`f9116f3bf9a5` (V8 14.6). All struct offsets below are taken from that
revision's `.tq` files and verified empirically against the dump.

## Pointer compression primer

On x64, heap-object fields are 32-bit *compressed tagged pointers*:

```
decompressed = cage_base + (compressed & ~1)     // bit 0 set = heap object
                                               // bit 0 clear = Smi (value = raw >> 1)
```

`cage_base` is 4 GiB-aligned. Values stored **on the stack** (frame slots,
registers) are full 64-bit tagged pointers; only heap-internal fields are
compressed.

## Frame layout (x64, V8 ≥ 13)

Relative to the frame pointer `rbp`:

| Offset | Contents |
|---|---|
| `[fp-24]` | frame type marker — raw `StackFrame::Type` int (NOT a Smi) |
| `[fp-16]` | `JSFunction` (full tagged pointer) |
| `[fp-8]` | context (full tagged pointer) |
| `[fp]` | saved caller fp |
| `[fp+8]` | return address |

The marker uses the `STACK_FRAME_TYPE_LIST` order from `frames.h`
(0=ENTRY, 2=EXIT, 3=INTERPRETED, 4=BASELINE, 5=MAGLEV, 6=TURBOFAN_JS,
7=STUB, 13=CONSTRUCT, 15=BUILTIN, …). Earlier code read the marker at
`[fp-8]` and decoded it as a Smi — both wrong; `[fp-8]` is the context, which
accidentally produced plausible "JavaScript" classifications because a tagged
pointer has bit 0 set.

## Resolution chain

For each walked frame:

```
[fp-16]  JSFunction            (full tagged ptr, validate via context, see below)
   +16   SharedFunctionInfo    (compressed)   ← +12 is dispatch_handle (leaptiering!)
   +12   name_or_scope_info    (compressed)
            ├─ String     → read name directly
            └─ ScopeInfo  → walk to the function name (see below)
```

### JSFunction validation

`[fp-16]` is untrusted (not every frame is a JS frame). A candidate is
accepted only if its **context field round-trips**:

```
decompress(JSFunction.context @ +20) | 1  ==  *(u64*)(fp - 8)
```

Both slots hold the same context pointer, so a mismatch rejects the frame
before any further dereference. This check is what lets us attempt decoding on
*every* frame safely, regardless of marker classification.

### Heap layouts (compressed fields, bytes)

**JSFunction** (`js-function.tq`, V8 14.6 — leaptiering enabled):

| Off | Field |
|---|---|
| 0 | map |
| 4 | properties_or_hash |
| 8 | elements |
| 12 | `dispatch_handle: int32` |
| 16 | `shared_function_info` |
| 20 | `context` |
| 24 | `feedback_cell` |

**SharedFunctionInfo** (`shared-function-info.tq`):

| Off | Field |
|---|---|
| 4 | `trusted_function_data` (indirect handle) |
| 8 | `untrusted_function_data` |
| 12 | `name_or_scope_info` ← String **or** ScopeInfo |
| 16 | `outer_scope_info_or_feedback_metadata` |
| 20 | `script` |

**String** (Seq*/Internalized, inline payload): `map(0), raw_hash(4), length(8), chars(12)`.
One-byte vs two-byte is the `0x08` instance-type bit
(`SEQ_ONE_BYTE=0x28`, `INTERNALIZED_ONE_BYTE=0x08`; two-byte variants clear it).
Instance types are low (< 0x40) for all string kinds.

### When the SFI name is a ScopeInfo

Functions that are anonymous at SFI level (common in minified bundles) store a
`SCOPE_INFO_TYPE` object instead of a name string. The function name still
exists — inside the ScopeInfo's flag-dependent slots (`scope-info.tq`):

```
ScopeInfo: flags u32 @ +4, parameter_count Smi @ +8, context_local_count Smi @ +12,
           position_info (2 Smis) @ +16/+20, then dynamic slots from +24:
  +4  if MODULE_SCOPE            → module_variable_count
  +4n context_local_names[n]     (n = context_local_count, inlined < 512)
  +4n context_local_infos[n]
  +4  if has_saved_class_variable (flags bit 10)
  +8  if function_variable ≠ NONE (flags bits 12-13) → function_variable_info:
                                                       name (+0), slot index (+4)  ← try first
  +4  if has_inferred_function_name (flags bit 14)   → inferred_function_name    ← try second
```

Both candidates are `String|Undefined|Zero`; the first that decodes to a
plausible string wins. If neither exists the frame is reported as
`<anonymous>`.

## Real-world result (Case/fulldump)

```
#0  blink::CanvasPath::moveTo +0x91    [Exit]             ← crash in native code
#1  0x7FF7E223E5D7                     [Exit]             ← JIT→C++ trampoline
#2  yye                                [OptimizedJS]
#3  renderByMatrix                     [OptimizedJS]
#4  renderByMatrix0                    [OptimizedJS]
#5  render0                            [OptimizedJS]
#6  <anonymous>                        [OptimizedJS]
#7  renderPlanes                       [OptimizedJS]
#8  render0                            [OptimizedJS]
#9  <anonymous>                        [OptimizedJS]
#10 Builtins_JSEntryTrampoline         [JavaScript]
```

So the crash is a canvas redraw chain: `renderPlanes → render0 → … →
renderByMatrix → yye → CanvasPath.moveTo`.

Names like `yye` are not a decoding artifact — they are the actual minified
production identifiers V8 stores in the ScopeInfo.

## Cross-checks used during development

- **PDB `InstanceType` enum** (enumerates in the enum's FieldList, TPI stream):
  confirmed `JS_FUNCTION_TYPE=0x812`, `SHARED_FUNCTION_INFO_TYPE=0x120`,
  `SCOPE_INFO_TYPE=0x11e`, `SCRIPT_TYPE=0xa6`, string type bit patterns.
  (Torque classes carry no field members in the PDB, so offsets themselves
  must come from V8 source.)
- **Version pinning**: Electron `DEPS` → Chromium version → Chromium `DEPS`
  `v8_revision` → exact `.tq` layouts.
- **Structural validation at every step**: tag bits, cage containment, sane
  string length, printable characters — any failure aborts decoding for that
  frame instead of producing garbage.

## Script names and line numbers

Beyond function names, two more SFI/Script fields give source positions:

**Line number** (works for any frame whose name goes through a ScopeInfo):

```
ScopeInfo.position_info.start  (Smi @ +16)  → character offset into source
SFI.script (@ +20) → Script.line_ends (@ +28, FixedArray of Smi line-end offsets)
line = lower_bound(line_ends, position) + Script.line_offset (@ +12) + 1
```

**Script name** (`Script.name @ +8`): usually an inline string, but for large
embedder-provided names it is an *external string*, whose char buffer lives
outside the sandbox behind the **external pointer table (EPT)**:

```
ExternalString.resource_  (EPT handle @ +12, 4 bytes)
index    = handle >> 6                      (kExternalPointerIndexShift, V8 14.6)
entry    = ept_base + 16 * index            (16-byte tagged entries)
resource = entry & 0x0000FFFFFFFFFFFF       (payload mask)
chars    = *(u64*)(resource + 16)           (blink ExternalStringResource layout)
```

The table base is discovered at runtime by scanning the isolate region for a
pointer whose entry for a known handle passes full end-to-end validation:
resource has a vtable inside a loaded module **and** the decoded chars are
readable and printable with exactly the string's length. (The first criterion
alone produces false positives — Skia/WebGL fills the EPT with shader-source
strings — so the second is essential.)

### Real-world result (Case/fulldump)

```
#2  yye             [OptimizedJS]  @ m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);…:34
#3  renderByMatrix  [OptimizedJS]  @ m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);…:35
#4  renderByMatrix0 [OptimizedJS]  @ m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);…:35
#5  render0         [OptimizedJS]  @ m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);…:35
#7  renderPlanes    [OptimizedJS]  @ m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);…:35
```

In this dump the crashed frames' shared Script (id 55) is **not file-backed**:
its V8 name is a 59-char SkSL shader snippet — the app generates these render
functions dynamically (`new Function`/eval-style code embedding shader logic),
so there is no URL to recover, but the line numbers within that generated
source are exact. For file-backed scripts the same machinery decodes the URL
(inline or external string path).

Caveat on EPT table discovery: the isolate holds pointers to several
lookalike segmented tables (EPT, CodePointerTable, CppHeapPointerTable). The
validation chain (payload is heap, not module code → resource has module
vtable → chars printable at exact length, plus a table-internal-payload
rejection with fallback) is heuristic; a wrong table that happens to pass all
checks would surface as a plausible but incorrect script name.

## Current limitations

- Script *column* and per-statement positions are not resolved (would require
  the bytecode/compiled-code source position tables).
- Offsets are hardcoded for V8 14.6 (Electron 41). Other V8 versions with
  different `JSFunction`/`SharedFunctionInfo` layouts need the constants in
  `analyzer/v8.rs` adjusted (everything is validated, so a wrong layout fails
  closed to `None`, never to wrong names).

## Implementation

- `forensicator-core/src/analyzer/v8.rs` — `decode_js_frame`,
  `scope_info_function_name`, `read_v8_string`, `instance_type`,
  `decode_v8_marker`; unit tests build a synthetic cage and verify direct
  names, ScopeInfo names, anonymous fallbacks, and rejection paths.
- `forensicator-core/src/model.rs` — `V8StackFrame.frame_pointer` added.
- `forensicator-cli/src/main.rs` — text output appends `[js: <name>]`.

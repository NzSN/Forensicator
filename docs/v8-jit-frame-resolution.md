# Resolving V8 JIT JavaScript Frames in Minidumps

How the `v8` analyzer recovers JavaScript function names, script names, and
line numbers for JIT-compiled frames (`OptimizedJavaScript` / `JavaScript`)
from a full Windows minidump — without any help from symbols.

Contents:

1. [Problem](#problem)
2. [What the dump already gives us](#what-the-dump-already-gives-us)
3. [Background: V8 memory model](#background-v8-memory-model)
4. [Walking the native stack](#walking-the-native-stack)
5. [Classifying frames: the marker slot](#classifying-frames-the-marker-slot)
6. [From frame to function name](#from-frame-to-function-name)
7. [Anonymous functions: the ScopeInfo detour](#anonymous-functions-the-scopeinfo-detour)
8. [Source positions: line numbers](#source-positions-line-numbers)
9. [External strings and the EPT: script names](#external-strings-and-the-ept-script-names)
10. [Worked end-to-end example (real dump)](#worked-end-to-end-example-real-dump)
11. [Validation strategy](#validation-strategy)
12. [Current limitations](#current-limitations)
13. [Implementation map](#implementation-map)
14. [V8 source references](#v8-source-references)

---

## Problem

Native stack walking (RBP chain) plus PDB symbolication resolves C/C++ frames,
but JIT-compiled JavaScript runs in V8-managed executable pages that belong to
no loaded module. Such frames appear as raw addresses:

```
#3  0x7FF7E2344A05   [JavaScript]   <no symbol>
```

These frames carry no entries in any PDB — V8 generates the code at runtime
and never registers it with the OS debugger infrastructure (no `RtlAddFunctionTable`,
no JIT map in this configuration). The only source of truth is V8's own heap
metadata, which a **full dump** captures completely: every JavaScript frame
carries a pointer to its `JSFunction`, and from there the entire metadata
graph (names, scopes, scripts, line tables) is reachable by pointer chasing.

## What the dump already gives us

Electron writes Crashpad annotations into the minidump. Three of them pin the
V8 version and the two address-space anchors we need:

| Annotation | Example | Meaning |
|---|---|---|
| `v8_isolate_address` | `0x68340051c000` | the `v8::internal::Isolate` — needed to find the external pointer table |
| `v8_ro_space_firstpage_address` | `0x29000000000` | first page of read-only space, which V8 places at the start of the pointer-compression cage |
| `ver` | `41.8.0` | Electron version → pins the exact V8 revision and thus every struct offset |

Version resolution chain used for this dump:

```
Electron 41.8.0
  └─ electron/DEPS            chromium_version = 146.0.7680.216
       └─ chromium/DEPS        v8_revision      = f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2
            └─ V8 14.6 — all layouts below come from this revision's .tq files
```

If `v8_ro_space_firstpage_address` is missing, the cage base can still be
derived from any JSFunction pointer found on a stack (`ptr & ~0xFFFFFFFF`,
since the cage is 4 GiB-aligned). If both annotations are absent, JS name
decoding still works, but script-name decoding needs the isolate.

## Background: V8 memory model

### Pointer compression

On x64, V8 (with pointer compression, always on in Chrome) stores heap-object
fields as **32-bit compressed tagged pointers** inside a 4 GiB *cage*:

```
compressed  = (address - cage_base) | tag
decompressed = cage_base + (compressed & ~1)

bit 0 = 1  → HeapObject pointer (clear the tag bit after adding the base)
bit 0 = 0  → Smi: a 31-bit signed integer, value = (int32)raw >> 1
```

Crucially, values stored **on the native stack** (frame slots, saved
registers) are full 64-bit tagged pointers; only fields *inside heap objects*
are compressed. So `[fp-16]` gives a ready-to-use `JSFunction*`, but every
pointer we chase *within* the heap needs decompression.

The cage layout in this dump:

```
0x290_00000000  cage base = RO space first page (from annotation)
   ├── read-only space: maps, internalized strings, builtins metadata
   ├── old space: SFIs, Scripts, ScopeInfos, contexts
   └── ... (trusted space lives outside the cage and is only reachable
            via indirect pointer handles — we never need to follow those)
```

### Leaptiering (why +12 is not what older docs say)

This V8 has **leaptiering** (`V8_ENABLE_LEAPTIERING`) enabled: `JSFunction`
no longer stores a direct `Code` pointer. Instead it stores a
`dispatch_handle: int32` indexing the `JSDispatchTable`. Field order in this
build (verified against the dump: the context field at +20 matches `[fp-8]`
for every JS frame):

| Off | Field | Notes |
|---|---|---|
| 0 | map | compressed |
| 4 | properties_or_hash | compressed |
| 8 | elements | compressed |
| 12 | `dispatch_handle: int32` | even value — **not** a pointer; older layouts had `shared_function_info` here |
| 16 | `shared_function_info` | compressed |
| 20 | `context` | compressed |
| 24 | `feedback_cell` | compressed |

## Walking the native stack

The analyzer walks each thread starting from its context record (for the
crashed thread, the **exception context** takes precedence over the thread
context — this is what makes frame #0 the actual crash PC):

```
fp   = context.rbp
loop:
    return_address = *(fp + 8)
    emit frame(return_address)
    fp = *fp            // saved rbp
    until fp stops strictly increasing / leaves the stack region / 256 frames
```

Each frame is also annotated with its `frame_pointer` (stored in
`V8StackFrame.frame_pointer`) because everything below is fp-relative.

## Classifying frames: the marker slot

Standard V8 frame layout on x64 (V8 ≥ 13):

| Offset | Contents |
|---|---|
| `[fp-24]` | frame type marker — **raw `StackFrame::Type` int** |
| `[fp-16]` | `JSFunction` (full tagged pointer) |
| `[fp-8]` | context (full tagged pointer) |
| `[fp]` | saved caller fp |
| `[fp+8]` | return address |

The marker is a small untagged integer indexing `STACK_FRAME_TYPE_LIST`
(`src/execution/frames.h`). Relevant values for this build:

| Value | Type | Our classification |
|---|---|---|
| 2 | EXIT | `Exit` (frame V8 pushes around C++/runtime calls — e.g. the `blink::CanvasPath::moveTo` call) |
| 3 | INTERPRETED | `JavaScript` |
| 4 | BASELINE | `JavaScript` |
| 5 | MAGLEV | `OptimizedJavaScript` |
| 6 | TURBOFAN_JS | `OptimizedJavaScript` |
| 7, 8 | STUB, TURBOFAN_STUB_WITH_CONTEXT | `Stub` |
| 13, 14 | CONSTRUCT, FAST_CONSTRUCT | `Construct` |
| 15 | BUILTIN | `Builtin` |
| 16–21 | BUILTIN_EXIT, API_CALLBACK_EXIT, NATIVE, IRREGEXP… | `Exit` |

Two historical bugs this fixes:

1. The marker was read at `[fp-8]` — that's the **context** slot. A context
   is a tagged pointer, so "bit 0 set ⇒ JavaScript" accidentally classified
   most JS frames correctly while mislabeling builtins.
2. The marker was decoded as a Smi (`value >> 1`). It is a raw int; observed
   values like `0xD` (13) are odd and fail Smi decoding entirely.

Markers are only a *hint*, though. Typed frames (EXIT, STUB, BUILTIN) do not
have a JSFunction slot, and some markers don't tell the truth. The authority
is the next section's validation.

## From frame to function name

The chain, for any frame:

```
[fp-16]  JSFunction                full tagged ptr — candidate, must validate
   +16   SharedFunctionInfo (SFI)  compressed
   +12   name_or_scope_info        compressed
            ├─ String     → the function's name, directly
            └─ ScopeInfo  → anonymous-at-SFI-level; walk scope slots (next section)
```

### JSFunction validation (the context round-trip)

`[fp-16]` is untrusted: EXIT/STUB/native frames don't have a function slot,
so the word there can be anything. A candidate is accepted only if its
context field round-trips against the frame's context slot:

```
frame_ctx = *(u64*)(fp - 8)                      // full tagged pointer
fn_ctx    = decompress(u32(JSFunction + 20)) | 1 // compressed field, retagged
accept iff fn_ctx == frame_ctx
```

Both slots always reference the same `Context` object, so this is an exact
equality check. It is what allows the analyzer to attempt decoding on **every
frame unconditionally** and let the data decide, instead of trusting the
marker. On success but with no resolvable name, the frame reports
`<anonymous>`; on validation failure, `js_function_name` stays `None`.

### Reading a name string

Strings we care about (SeqString / internalized string) have inline payload:

```
map(0), raw_hash_field(4), length u32(8), chars(12…)
```

Instance-type bit patterns (confirmed against the PDB's
`v8::internal::InstanceType` enum — see Cross-checks):

- All string kinds have instance type < `0x40`.
- One-byte vs two-byte is bit `0x08` (`SEQ_ONE_BYTE=0x28`,
  `INTERNALIZED_ONE_BYTE=0x08`; two-byte variants have it clear).
- External strings have bit `0x02` (`EXTERNAL_ONE_BYTE=0x2a`) — payload is
  not inline; see the EPT section.

Acceptance: length in `1..=4096`, characters all printable (ASCII or ≥0x80).

## Anonymous functions: the ScopeInfo detour

In minified production bundles most SFIs do not store a name string directly;
`name_or_scope_info` holds a `SCOPE_INFO_TYPE` object (`0x11e` here) instead.
The name still exists — the parser records it in the scope, in flag-dependent
slots. Layout (`scope-info.tq`):

```
ScopeInfo:
  +4   flags (u32)                     bitfield, see below
  +8   parameter_count (Smi)
  +12  context_local_count (Smi)  = n
  +16  position_info.start (Smi)  ─┐
  +20  position_info.end   (Smi)   ┘ character offsets into the source (used for lines!)
  +24… dynamic slots, in this exact order:
       +4   if flags.scope_type == MODULE_SCOPE(5)     → module_variable_count
       +4n  context_local_names[n]   (inlined when n < 512, else one hashtable pointer)
       +4n  context_local_infos[n]   (SmiTagged VariableProperties)
       +4   if flags bit 10 (has_saved_class_variable)
       +8   if flags bits 12-13 (function_variable) ≠ 0
              → function_variable_info = { name: String|Zero, slot_index: Smi }   ← candidate 1
       +4   if flags bit 14 (has_inferred_function_name)
              → inferred_function_name: String|Undefined                            ← candidate 2
       (… outer_scope_info, module_info, unused_parameter_bits — not needed)
```

The decoder computes the slot offsets from the flags, tries candidate 1 then
candidate 2, and accepts the first that validates as a plausible string.

Worked example — frame `#2` (`yye`) ScopeInfo at `0x2900faf96f8`:

```
flags = 0x804071C4 → scope_type 4 (FUNCTION_SCOPE), function_variable = STACK(1),
                     has_inferred_function_name = 1, has_outer_scope_info = 1
context_local_count = 0 → dynamic slots start immediately:
  +24 function_variable_info.name = 0x01a31edd → 0x29001a31edc
       itype 0x0008 = INTERNALIZED_ONE_BYTE_STRING_TYPE
       length 3, chars "yye"  ✓
```

## Source positions: line numbers

The same ScopeInfo also yields the function's source position — no source
position tables needed:

```
position   = ScopeInfo.position_info.start     (Smi @ +16, char offset into source)
script     = decompress(SFI.script @ +20)      (compressed tagged pointer)
line_ends  = decompress(Script.line_ends @ +28) → FixedArray { map, length Smi @ +4,
                                                              elements Smi @ +8 … }
line_offset = Script.line_offset (Smi @ +12)

line = (index of first line_ends[i] >= position) + line_offset + 1
```

`line_ends[i]` is the source character offset of the end of line *i*; a
binary search over it maps the function's start offset to a line index. This
is exactly V8's own `Script::GetLineNumber` algorithm, so results match what
`Error.stack` would have shown in the live process. In the case dump the
script has 92,111 line ends over a 10.8 MB source, and the search resolves
`yye` → line 34, the render family → line 35.

## External strings and the EPT: script names

`Script.name @ +8` is a `String|Undefined`. For file-backed scripts it is
typically an inline (internalized) string — read directly. But large,
embedder-provided names are **external strings**: their characters live
outside the sandbox, behind the **external pointer table (EPT)** — V8's
sandbox mechanism that forbids raw pointers inside heap objects.

### EPT mechanics (V8 14.6)

```
ExternalString.resource_        (EPT handle, u32 @ string + 12)
index    = handle >> 6                     (kExternalPointerIndexShift)
entry    = ept_base + 16 * index           (16-byte entries: tagged payload)
resource = entry & 0x0000FFFFFFFFFFFF      (payload mask; low 48 bits)
chars    = *(u64*)(resource + 16)          (blink ExternalStringResource:
                                            vtable(0), impl fields, char* at +16)
read `length` chars at `chars` (one-byte vs two-byte from the instance-type bit)
```

### Discovering the table base

`ept_base` is not at a fixed offset we can hardcode without isolate-layout
tables, so the analyzer discovers it at runtime:

```
for each 8-byte-aligned u64 B in the isolate's memory region:
    entry    = u64(B + 16 * (handle >> 6))
    resource = entry & payload_mask
    accept B iff:
      1. resource is non-zero and NOT inside any module (it is a heap object,
         not code — this rejects the lookalike CodePointerTable)
      2. resource's first word is a vtable pointer inside a loaded module
      3. *(resource + 16) is readable and decodes to exactly `length`
         printable characters                       (end-to-end check)
    (pass 1 also rejects resources that point back into B's own 2 MiB window —
     evacuation/self-referential entries; pass 2 is a fallback without it)
```

Criterion 2 alone is insufficient: this process fills pointer tables with
Skia/WebGL shader-source strings, and a wrong table (the CodePointerTable was
observed) can chain into printable text by accident. Criterion 3 anchors the
decode to the one string whose handle and length we actually know. The first
validated base is cached and reused for all subsequent external strings.

## Worked end-to-end example (real dump)

Frame `#3` of the crashed thread 22024 (`fp = 0x52C1FD338`):

```
[fp-8]  = 0x000002900593EC81          context (full tagged)
[fp-16] = 0x0000029005999B19          JSFunction candidate
[fp-24] = 0x12                        marker 18 → API-named-accessor-exit (wrong — trust data, not marker)

JSFunction @ 0x29005999B18:
  map → instance type 0x0812 = JS_FUNCTION_TYPE          ✓ (cross-check only)
  +16 shared_function_info = 0x08B4E3B9 → SFI 0x29008B4E3B8 (itype 0x0120 ✓)
  +20 context              = 0x0593EC81 → 0x2900593EC80|1 == [fp-8]  ✓ ACCEPTED

SFI @ 0x29008B4E3B8:
  +12 name_or_scope_info = 0x09CFF1E9 → 0x29009CFF1E8, itype 0x011e = SCOPE_INFO
      ScopeInfo walk → function_variable_info.name → String "renderByMatrix"
  +20 script = 0x06900011 → Script 0x29006900010 (itype 0x00a6 = SCRIPT_TYPE)
      +8  name      = external string, len 59
            handle 0xC7AC0 → EPT[0x31EB] → resource → chars
            = "m=k*.5;half n=b==e?0.:f/(m>.5?2.-k:k);return half3(j,n,m"
      +28 line_ends = FixedArray[92111]
            position from ScopeInfo +16 → binary search → line 35
```

Result:

```
#3  0x7FF7E2344A05  [OptimizedJavaScript]  [js: renderByMatrix @ m=k*.5;…:35]
```

Full crashed-thread stack:

```
#0  blink::CanvasPath::moveTo +0x91  [Exit]              ← crash in native code
#1  0x7FF7E223E5D7                   [Exit]              ← JIT→C++ trampoline
#2  yye                              [OptimizedJS]  :34
#3  renderByMatrix                   [OptimizedJS]  :35
#4  renderByMatrix0                  [OptimizedJS]  :35
#5  render0                          [OptimizedJS]  :35
#6  <anonymous>                      [OptimizedJS]  :35
#7  renderPlanes                     [OptimizedJS]  :35
#8  render0                          [OptimizedJS]  :35
#9  <anonymous>                      [OptimizedJS]  :35
#10 Builtins_JSEntryTrampoline       [JavaScript]
#11 Builtins_JSEntry                 [Builtin]
#12 v8::internal::Execution::Call
```

So the crash is a canvas redraw chain: `renderPlanes → render0 → … →
renderByMatrix → yye → CanvasPath.moveTo`.

Two interpretation notes:

- Names like `yye` are not a decoding artifact — they are the actual minified
  production identifiers V8 stores in the ScopeInfo.
- The frames' shared Script (id 55) is **not file-backed**: its V8 name is a
  59-char SkSL shader snippet, i.e. the app generates these render functions
  dynamically (`new Function`/eval-style code embedding shader logic). There
  is no URL to recover for them, but the line numbers within that generated
  source are exact. File-backed scripts decode to their URL through the same
  machinery (inline or external string path).

## Validation strategy

Every step fails closed: any inconsistency aborts decoding for that frame
instead of producing garbage. The checks, in order:

| Check | Rejects |
|---|---|
| frame slot tagged (`bit 0 = 1`) | native/typed frames |
| candidate inside cage (vs annotation) | wild pointers |
| context round-trip (`fn+20` ≡ `[fp-8]`) | non-JS frames misread as JS |
| string: instance type < 0x40, sane length, printable chars | garbage strings |
| ScopeInfo: local count sane, slots computed from real flags | non-scope objects |
| EPT base: payload is heap (not module code, not table-internal), resource vtable inside a module, chars printable at exact length | lookalike tables (CodePointerTable etc.) |

Cross-checks used during development:

- **PDB `InstanceType` enum** (enumerates live in the enum's `FieldList`
  record in the TPI stream): confirmed `JS_FUNCTION_TYPE=0x812`,
  `SHARED_FUNCTION_INFO_TYPE=0x120`, `SCOPE_INFO_TYPE=0x11e`,
  `SCRIPT_TYPE=0xa6`, and the string-type bit patterns. Note that Torque
  classes carry **no field members** in the PDB — offsets must come from V8
  source, only types can be checked.
- **Version pinning**: Electron `DEPS` → Chromium version → Chromium `DEPS`
  `v8_revision` → exact `.tq` layouts for every struct above.
- **Empirical probes** against the dump: every layout claim in this document
  was first verified by hand on real addresses before being implemented.

Caveat on EPT table discovery: the isolate holds pointers to several
lookalike segmented tables (EPT, CodePointerTable, CppHeapPointerTable). The
validation chain above is heuristic; a wrong table that happens to pass all
checks would surface as a plausible but incorrect script name. Function names
and line numbers do not depend on the EPT and are not affected by this.

## Current limitations

- Script *column* and per-statement positions are not resolved (requires the
  bytecode/compiled-code source position tables in trusted space).
- Script names that are **cons/sliced/thin strings** are not followed
  (inline Seq*/internalized and external strings are covered).
- Offsets are hardcoded for V8 14.6 (Electron 41 / Chromium 146). Other V8
  versions with different `JSFunction`/`SharedFunctionInfo`/`ScopeInfo`
  layouts need the constants in `analyzer/v8.rs` adjusted — everything is
  validated, so a wrong layout fails closed to `None`, never to wrong names.

## Implementation map

| Piece | Location |
|---|---|
| Stack walk + frame decode orchestration | `forensicator-core/src/analyzer/v8.rs` — `walk_thread_stacks` |
| Marker decode (`StackFrame::Type` ints) | `decode_v8_marker` |
| JSFunction validation + name/script/line decode | `decode_js_frame` → `JsFrameInfo` |
| ScopeInfo slot walk | `scope_info_function_name` |
| String readers (inline/external) | `read_v8_string`, `read_external_chars` |
| Line numbers | `decode_script_line` |
| External strings via EPT | `decode_script_name`, `find_ept_base`, `external_string_via_ept` |
| Frame model (`frame_pointer` field) | `forensicator-core/src/model.rs` — `V8StackFrame` |
| CLI output (`[js: name @ script:line]`) | `forensicator-cli/src/main.rs` — `print_v8_frames` |
| Unit tests (synthetic cage, EPT, line tables) | `analyzer/v8.rs` `mod tests` — 12 tests |

## V8 source references

All at revision `f9116f3bf9a50b0f7925daacfdc6fed503a9dbe2`:

- `src/objects/js-function.tq` — JSFunction field order (leaptiering)
- `src/objects/shared-function-info.tq` — SFI fields
- `src/objects/scope-info.tq` — ScopeInfo flags and dynamic slot order
- `src/objects/script.tq` — Script fields (name, line_offset, line_ends)
- `src/execution/frames.h` — `STACK_FRAME_TYPE_LIST` marker values
- `src/execution/frame-constants.h` — `[fp-8/-16/-24]` slot offsets
- `src/sandbox/external-pointer-table{,-inl}.h` — EPT handle/entry encoding

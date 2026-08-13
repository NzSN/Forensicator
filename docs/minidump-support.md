# Minidump (Stack-Only) Support

How forensicator handles Crashpad-style minidumps that capture only thread
stacks (~2 MB) instead of full process memory, using `Case/minidump` as the
reference (Electron 41.10.3 renderer, forced breakpoint dump `0x80000003`).

## What changes vs full dumps

| Capability | Full dump | Stack-only minidump |
|---|---|---|
| Native stack walking | RBP chain | **x64 unwind info (`.pdata`) required** — Chrome ships without frame pointers |
| Module bytes (`.pdata`, `.text`) | in dump regions | supplemented from on-disk image (auto-discovered) |
| V8 JS names / script / lines | full recovery | **impossible** — heap/cage not captured; frames still classified by marker |
| Crash-site disassembly | from dump | from supplemented image |

## Pieces

### 1. Dump kind classification — `Forensicator/Pipeline.lean`

`classifyDump`: total captured bytes ≥ 64 MiB ⇒ `DumpKind.FullMemory`, else
`DumpKind.StackOnly` (Nat-lifted sum — no u64 wrap). Printed by the CLI
(`dump: stack-only, 1 image(s) supplemented`).

### 2. PE image backing — `Forensicator/Util/Image.lean`

The PE parser handles DOS/NT headers + section table and maps VA → RVA →
file offset. Discovery locates each module by basename (Windows path
separators handled) in the dump's directory; the session supplements the
AddressSpace with image bytes so reads fall through to images for VAs not
covered by any dump region — transparent to all analyzers and to both dump
kinds (`Session.lean` `supplement`).

### 3. x64 unwind walking — `Forensicator/Util/Unwind.lean`

- `.pdata` located via the PE exception directory (data directory #3, at
  optional header + 112 + 24 for PE32+) read **through the AddressSpace**, so
  the same code path serves dump-captured images and on-disk backing.
  `UnwindTables` parses and caches per-module tables (chunked reads; this
  Chromium has ~440 k `RUNTIME_FUNCTION` records).
- Lookup: binary search (records are sorted by `begin`).
- `unwind_step` simulates `UNWIND_INFO`: `PUSH_NONVOL`, `ALLOC_SMALL/LARGE`,
  `SET_FPREG`, `SAVE_NONVOL(_FAR)`, `PUSH_MACHFRAME`, chained info
  (`UNW_FLAG_CHAININFO`), skips XMM saves; partial-prolog PCs skip codes whose
  `code_offset` hasn't executed yet; final `rip = *(rsp); rsp += 8`.

Gotchas encoded here, learned the hard way:

- **UNWIND_CODE packs the op in the LOW nibble and opinfo in the HIGH nibble**
  (`UnwindOp : 4` is the first bitfield).
- `count_of_codes` counts 2-byte **slots** (including extra slots of
  multi-slot ops), not ops.
- Register numbers differ from the project's x64 indices (a mapping table
  lives in `Util/Unwind.lean`).

### 4. Hybrid walker — `Forensicator/Analyzer/V8.lean`

Per thread, from the (exception) context, loop per frame:

1. **unwind info** if the PC is in a module with `.pdata` — authoritative for
   Chrome's frame-pointer-less code;
2. **V8 frame-pointer chain** (`[fp]`/`[fp+8]` validated against the stack
   range, plus a terminal-link case for boundary frames) — V8 JIT frames have
   real frame pointers but no `RUNTIME_FUNCTION` records;
3. **leaf pop** (`rip = *(rsp); rsp += 8`).

Loop safety: `(rip, rsp)` visited-set, depth cap 256, and PCs not in any
module/region are rejected *unless* reached via unwind/fp-chain (leaf pops
are the only untrusted source; JIT code pages are legitimately uncaptured in
stack-only dumps, so a blanket mapped-check would kill real JS frames).

### 5. Graceful V8 degradation

- `decodeJsFrame` already fails closed when heap reads miss — JS names,
  script names, and lines simply come out `None`.
- The analyzer emits `v8_heap_captured: false` in JSON so consumers can tell
  "no JS on this thread" from "heap not in dump".
- Frame classification still works: `StackFrame.Type` markers live on the
  captured stacks, so JIT frames are typed (`OptimizedJavaScript` etc.).

### 6. Crash-site disassembly

The crash-site disassembler (`Util/Disasm.lean` — native x86-64 subset,
Intel syntax) decodes ~10 instructions at the exception address through the
layered space — on minidumps the bytes come from the supplemented image.
Printed as a `Crash site:` block by the CLI.

## Results on `Case/minidump`

Before: crashed thread (16356) produced **0 frames**; parked threads 1–2
garbage frames.

After — 41 frames on the crashed thread, and the dump tells a complete story:

```
#0  v8::internal::TranslatedState::TranslatedState +0x1ADA     crash site: int3; ud2
#1  v8::internal::OptimizedJSFrame::Summarize +0x273
#2  GetFormattedStack +0x5D5
#3  ThrowLoadFromNullOrUndefined +0x82
#4  v8::internal::Runtime_GetProperty +0x71D
#5  Builtins_CEntry_Return1_ArgvOnStack_NoBuiltinExit +0x3A
#6-#10  JIT JS frames (markers only — heap not captured)
#11 Builtins_JSEntryTrampoline
…
#19 blink::V8FrameCallback::Invoke
#20 blink::FrameRequestCallbackCollection::ExecuteFrameCallbacks
#21 blink::PageAnimator::ServiceScriptedAnimations
#23 blink::Page::Animate
```

A `requestAnimationFrame` callback read a property on `null`/`undefined`;
V8 was formatting the resulting TypeError's stack trace (deopt path through
`TranslatedState`) when the forced dump was captured.

The same hybrid walker also upgraded **full-dump** results: the fulldump
crashed thread now unwinds 43 frames down to `wWinMain` /
`content::RendererMain`, and parked threads resolve into real symbolized
stacks (e.g. `base::WaitableEvent::TimedWait`) instead of 1–2 noise frames.

## Tests

In the guard suite (`Test/Spec.lean`, run by `forensicator-test`):
synthetic PE parsing/section reads/rejection (`Util/Image.lean` paths);
`.pdata` lookup and `UNWIND_INFO` simulation (`PUSH_NONVOL`+`ALLOC_SMALL`,
`SET_FPREG`+`SAVE_NONVOL`, `PUSH_MACHFRAME`) against synthetic blobs.

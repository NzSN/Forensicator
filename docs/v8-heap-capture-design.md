# Design: Minimal V8 Heap Capture for JIT Frame Resolution

How to make a **stack-only Crashpad minidump** sufficient for full JIT frame
resolution (function names, script names, line numbers) by adding a small,
surgically-chosen set of V8 memory regions — without paying the cost of a
full-memory dump.

Status: design (not yet implemented). Companion docs:
`docs/v8-jit-frame-resolution.md` (decoder mechanics),
`docs/minidump-support.md` (stack-only handling).

## 1. Goal and non-goals

**Goal.** A renderer crash produces a minidump of a few MB (not ~1 GB) that
forensicator can still decode end-to-end: `JSFunction → SFI → name → Script →
line_ends`, for every JIT frame of every thread.

**Non-goals.**
- Arbitrary heap forensics (object graph reconstruction, GC state). We only
  need the decoder's reachable set.
- Rebuilding the app's crash pipeline beyond the renderer process. The design
  must fit inside the app's existing Crashpad embedding (Electron).

## 2. What the decoder actually touches

From `analyzer/v8.rs` (`decode_js_frame`, `decode_script_name`,
`decode_script_line`), per JS frame:

| Step | Object(s) read | Size | Space |
|---|---|---|---|
| frame slot | `JSFunction` | 32 B | old space / RO space |
| +16 | `SharedFunctionInfo` | ~40 B | old space |
| +12 | name string **or** `ScopeInfo` | 16–100 B | RO/old space |
| ScopeInfo slot | function-variable/inferred name string | ≤ few 100 B | RO/old space |
| validation | maps (instance types) of every object above | 40 B each | **RO space** |
| `SFI.script` | `Script` | ~80 B | old space |
| `Script.name` | inline string, or external string + EPT chain | see §3.4 | old space / **isolate** / **malloc heap** |
| `Script.line_ends` | `FixedArray` of Smis | 4 B–hundreds of KB | old space |

Plus two process-global structures:

- the **isolate** (`v8_isolate_address` annotation) — scanned to discover the
  external-pointer-table (EPT) base;
- the **EPT segments** — hold the raw resource/char pointers for external
  (script-name) strings. Script *sources* and line tables are **not** needed
  for names/lines (line numbers come from `line_ends`, not the source text).

Everything else in the heap (JS user objects, arrays, DOM, code space pages)
is never read.

## 3. Region selection

All addresses below are computable **at dump time inside the crashing
process** — the annotations already carry the two anchors
(`v8_isolate_address`, `v8_ro_space_firstpage_address`), and Chromium's V8
APIs expose the rest.

### 3.1 Read-only space (mandatory)

Why: every instance-type check reads a Map, and internalized short strings
(minified names like `yye`) live here.

- **Where:** starts at `v8_ro_space_firstpage_address` (cage base).
- **Size:** the whole RO area, typically 1–4 MB. Obtain bounds from
  `v8::internal::ReadOnlyHeap::From(isolate)->read_only_space()` — or, without
  internal access, capture the first `N` pages (4 MB) from the cage base; RO
  space always begins at cage start in shared-cage builds.

### 3.2 Old-space pages reachable from the stacks (mandatory)

The JSFunction/SFI/ScopeInfo/Script/line_ends objects are in old space, at
addresses only the stacks reveal. Two strategies, in order of preference:

**A. Page-granular capture from stack references (smallest, recommended).**
At dump time, for every captured thread stack, scan for tagged values inside
the cage (`value ∈ [cage_base, cage_base+4GB), bit0=1`), mask to heap
addresses, and capture the **containing page** of each reference.

This alone is **not enough**: the stack yields only the `JSFunction` (1 hop),
while the decoder's chain — `JSFunction → SFI → name_or_scope_info →
String/ScopeInfo → name` and `SFI → Script → name/line_ends` — continues
through objects no stack word points at. So the scan must **dereference
transitively**: every captured page is itself scanned for cage-pointer-like
words, whose pages are captured in turn (breadth-first closure). **Where this
chase runs is a safety decision — see the safety model in §4.3: on Windows the
collector runs in the out-of-process Crashpad handler against the suspended
renderer, so the chase below is safe by construction (no app locks; reads go
through a `VirtualQuery`-backed `ProcessMemory` that cannot fault). The
chase-free superset A′ is an optional smaller capture, not a safety
requirement.**

```
worklist = pages(stack-referenced cage pointers)
captured = {}
depth    = 0
while worklist not empty and depth < 6 and |captured| < CAP_PAGES:
    page = worklist.pop()
    if page in captured: continue
    capture page; captured.add(page)
    for each tagged word w in page:
        if (w & 1) && cage_base <= (w & ~1) < cage_base + 4GB:
            worklist.push(page_of(w & ~1))
    depth += 1
```

Depth 6 covers the decoder's longest chain (function → sfi → script →
line_ends = 3, function → sfi → scope → name = 3, plus slack for the EPT-free
paths); `CAP_PAGES` (~64) bounds worst-case size. Chasing is raw memory
scanning only — no V8 locks or APIs. False positives (a heap number that
looks like a cage pointer) only cost a wasted 256 KB page; false negatives
simply degrade that frame to `None`, never to wrong names.

**A′. Chase-free superset capture (safest, default).**
If dereferencing in the crashed process is off the table entirely, don't
chase — capture a superset instead. Enumerate committed pages inside the cage
with `VirtualQuery` (pure OS queries, no pointer following) and capture every
`MEM_COMMIT` page that is **not** execute-protected (this excludes the large
JIT code space while keeping RO/old/new/map space). Zero dereferences, zero
V8 internals; typical size is tens of MB — bigger than strategy A but still
an order of magnitude below a full dump, and it cannot crash the handler.

```
for va in [cage_base, cage_base + 4GB) step VirtualQuery region:
    if mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_EXECUTE*)):
        capture region
```

V8 allocates old-space objects on 256 KB-aligned pages (`Page::kPageSize`),
so page alignment bounds the waste. Frames in this dump needed < 10 objects
each; even 47 threads × a few dozen referenced pages ≈ a few MB. Because V8
pages are page-pooled, **skipping the pool** (see §5) risks missing freshly
moved objects — acceptable: failures degrade to `None`, never to wrong names.

**B. Whole old space (simple, bigger).**
`v8::internal::Heap::old_space()` page list via `MemoryChunk` iteration;
typically tens of MB — still 10–50× smaller than a full dump, but larger
than strategy A by an order of magnitude.

Recommendation: implement **A** first; fall back to **B** behind a flag.

### 3.3 The isolate (mandatory for script names)

Capture `[isolate_va, isolate_va + 1 MB)`. The EPT-base discovery scan
(`find_ept_base`) needs the isolate region; 1 MB covered it in the reference
dump (`0x683400464000..0x683400570000`).

### 3.4 EPT segments + external-string targets (mandatory for script names)

External script names resolve through the external pointer table into
arbitrary process memory:

```
handle → EPT entry (16 B) → resource (blink ExternalStringResource) → chars
```

Capture:
- the **EPT reservation** — the segmented table itself. Its base is found by
  the same scan forensicator runs (any 8-byte value in the isolate that
  decodes a known handle end-to-end); capturing the whole reservation
  (typically a few MB) avoids needing per-segment logic at write time;
- each **resource object** (64 B) and **char buffer** (`length` bytes, ≤ 4 KB
  by decoder cap) — these live in the regular malloc heap outside the sandbox
  and must be chased individually: iterate the EPT entries that belong to
  external strings reachable from captured Scripts (or simply all live EPT
  entries with string-resource tags), and capture their targets.

If EPT capture proves fragile, a cheaper degradation: skip external names —
file-backed scripts usually have inline (internalized) names that need no
EPT. In the reference dump the dynamic script's name *is* external, so the
feature matters for exactly the eval/`new Function` cases.

### 3.5 Optional: trusted-space stubs

Nothing in the name/line path requires trusted space (SFIs'
`trusted_function_data` is never followed). Skip.

### 3.6 Size budget (this dump as reference)

| Region | Approx size |
|---|---|
| Thread stacks (already captured) | ~1.5 MB |
| RO space | ~2 MB |
| Referenced old-space pages (strategy A) | 1–8 MB |
| Isolate slice | 1 MB |
| EPT reservation + external targets | 1–4 MB |
| **Total** | **~6–16 MB** (vs 1.2 GB full dump) |

## 4. Crashpad integration

On Windows the handler runs **out-of-process**: Electron re-invokes its own
binary as a child process with `--type=crashpad-handler`
(`RunAsCrashpadHandler` in
`components/crash/core/app/run_as_crashpad_handler_win.cc`). That child
receives a `HANDLE` to the crashed renderer, suspends it
(`ScopedProcessSuspend`), and reads the renderer's memory out-of-process via
`ProcessSnapshotWin`. (The in-process handler path exists in this revision
only on iOS and is not used by Electron.)

The extension point is the `crashpad::UserStreamDataSource` interface
(`handler/user_stream_data_source.h`), whose
`ProduceStreamData(ProcessSnapshot*)` runs **in that handler child process**,
with full access to the suspended renderer's memory. There is **no** runtime
`CrashpadClient::AddUserMinidumpStream` API — the data sources are compiled
into the handler and passed to `HandlerMain` as a `UserStreamDataSources`
vector. `RunAsCrashpadHandler` already builds that vector (with
`stability_report` and `gwp_asan` sources), so the integration seam is a
one-line `push_back` of a `V8HeapUserStreamDataSource` there — not a separate
handler binary.

### 4.1 New user stream: `V8HE` (V8 heap extension)

Emit one custom minidump stream:

```
struct V8HeapExtensionHeader {
    uint32_t stream_type;        // MINIDUMP_STREAM_TYPE::user reserved range
    uint32_t version;            // 1
    uint64_t cage_base;
    uint64_t isolate_va;
    uint32_t region_count;
    uint32_t flags;              // bit0: strategy B (whole old space); bit1: partial heap (V8XT omitted)
    // followed by region_count entries:
    struct Region { uint64_t va; uint64_t size; uint64_t file_offset; }[];
};
```

Region bytes are appended after the directory entries. A second, optional
stream `V8XT` carries the external-string targets (EPT reservation +
resource/char buffers) so §3.4 can be disabled independently.

### 4.2 Collection procedure

1. Read annotations for `v8_isolate_address` / `v8_ro_space_firstpage_address`
   from the `ProcessSnapshot` (they ride in CrashpadInfo). The collector runs
   out-of-process, so it reads renderer memory via `ProcessSnapshot::Memory()`,
   not through V8 APIs directly.
2. Push RO space range (§3.1).
3. Heap objects, per the safety model (§4.3): the collector runs in the
   handler process against the suspended renderer, where the chase (§3.2-A) is
   safe by construction. The chase-free superset (§3.2-A′) remains available
   if a page-pool-independent capture is preferred.
4. Push isolate slice (§3.3).
5. Locate EPT base via the same end-to-end probe the analyzer uses; push the
   EPT reservation and chase external-string targets of reachable Scripts
   (§3.4) into `V8XT`.

### 4.3 Collector safety model

On Windows the collector runs **inside the handler process**, against a
**suspended** renderer (`ScopedProcessSuspend`), through `ProcessSnapshotWin`.
That neutralizes two of the three classic dangers of scanning a crashed heap
before any code is written:

- **Faults** — reads go through `ProcessMemoryWin::ReadAvailableMemory`, which
  pre-validates ranges with a `VirtualQuery`-derived `GetReadableRanges()` and
  then `ReadProcessMemory`s the suspended client; any inaccessible region
  returns `0` and is skipped. It **cannot fault the handler** — no
  `__try`/`__except` needed.
- **Locks** — the handler is a separate process and takes no V8/GC/blink locks;
  the renderer's threads are frozen by Crashpad.
- **Mid-GC torn state** — the only residual risk. Capture is best-effort and
  the decoder validates every object's Map/instance-type, so a torn object
  degrades that frame to `None`, never to a wrong name.

Because the chase is safe by construction here, strategy A (§3.2) is the
natural default; the chase-free `VirtualQuery` superset (§3.2-A′) remains
available for a page-pool-independent capture, but is no longer required for
safety. The in-process handler path (iOS only in this revision) is not used by
Electron; if it ever were, the §3.2-A′ superset or the deferred option below
would apply there.

| Level | Where it runs | Rule |
|---|---|---|
| **Default (Windows)** | **Handler, out-of-process** | Transitive chase (§3.2-A) + EPT targets (§3.4) run via `ProcessSnapshot::Memory()`. Safe by construction — see above. |
| **Smaller capture** | Handler, out-of-process | Chase-free `VirtualQuery` superset (§3.2-A′): pick for size / page-pool independence, not safety. |
| **Deferred (forced dumps)** | Normal renderer thread, post-handler | `0x80000003` "dump without crash" leaves the app alive: after the handler returns, run the chase on a regular thread and append/rewrite `V8HE`/`V8XT` offline (ingestion format is identical). Not applicable to fatal crashes. |

Forensicator ingestion is unchanged by where bytes came from — the stream
format (§4.1) is identical for all rows.

### 4.4 Forensicator ingestion

- Parse `V8HE`/`V8XT` in `parse/` (new stream decoder, provenance-tagged as
  usual), and `AddressSpace::add_region` each region **before** analysis —
  the existing decoder then works unmodified.
- `DumpKind` classification: treat a dump with `V8HE` as
  `FullMemory`-equivalent for V8 purposes; expose
  `v8_heap_captured: partial` when `flags.bit1` is set.
- No changes to `decode_js_frame` / symbolizer / CLI output formats.

## 5. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scavenger moved young-gen objects between crash and capture | a frame's JSFunction read fails | decoder fails closed (`None`); strategy B captures old space wholesale |
| V8 page pool holds freed pages | §3.2-A misses objects | same closed failure; optional strategy B |
| Handler runs mid-GC: heap in transient state | torn objects | capture is best-effort; validation in decoder rejects inconsistencies |
| Chase reads freed/unmapped page | one region skipped | handler reads through `ProcessMemoryWin` (§4.3), which cannot fault; the frame degrades to `None`, never wrong names |
| Vendoring the collector + Electron patch | changes to `third_party/crashpad/crashpad` + `run_as_crashpad_handler_win.cc` must be exported as Electron patches | the app already patches Electron for branding — add the collector files and the one-line `push_back` as a `patches/crashpad` (or `patches/chromium`) target via `e patches`. Offline-rewrite fallback (same V8HE format — ingestion code shared) if the handler can't be rebuilt |
| EPT reservation huge / sparse | size blowup | cap at 8 MB; skip V8XT beyond cap |
| Version drift (V8 ≥ 15 changes layouts) | wrong offsets | decoder layouts are per-version (`v8layout.rs`); V8HE `version` field allows region-format evolution |

## 6. Implementation plan (suggested phases)

1. **App side**: develop the collector (`V8HeapUserStreamDataSource` + capture
   logic) in the **crashpad repo** at `handler/v8_heap/`, unit-tested via
   `crashpad_handler_test` against a `TestProcessSnapshot` + fake
   `ProcessMemory`. Then register it in Electron's embedded handler by
   `push_back`-ing it into the `UserStreamDataSources` vector in
   `run_as_crashpad_handler_win.cc` (alongside `stability_report`/`gwp_asan`)
   once the crashpad changes are synced into `third_party/crashpad/crashpad/`.
2. **Forensicator side**: V8HE stream parser + AddressSpace ingestion + kind
   classification; tests with a hand-built stream.
3. **End-to-end**: crash the instrumented app, verify the crashed thread
   decodes like the fulldump (`js: name @ script:line` present).
4. **Validation corpus**: re-run on `Case/fulldump` (regression: unchanged)
   and `Case/minidump` (unchanged unless recaptured with the collector).

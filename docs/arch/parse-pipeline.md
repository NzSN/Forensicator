# S1: Parse Pipeline (minidump → Dump + AddressSpace)

Spec: `specs/Model.tla`, `specs/AddressSpace.tla`, `specs/ParsePipeline.tla`,
`specs/Forensicator.tla` (root composition).
Code: `Forensicator/Parse/Minidump.lean`, `Forensicator/Parse/Cursor.lean`,
`Forensicator/Model/Dump.lean`, `Forensicator/Pipeline.lean`.

## Flow

```
.dmp bytes
  │  header + directory decode   magic/version/stream count      (Parse/Minidump.lean)
  │  per-stream decoders         decodeSystemInfo/ModuleList/…   (Parse/Minidump.lean)
  ▼
Dump { systemInfo, modules, threads, memoryRegions, exception,
       anomalies, annotations, memoryInfo, v8heapExt, … }         (Model/Dump.lean)
  │  buildAddressSpace     regions → AddressSpace                (Pipeline.lean)
  │  classifyDump          StackOnly vs FullMemory (≥ 64 MiB)    (Pipeline.lean)
  ▼
(dump, space, kind) — consumed by Main.lean / Session.lean
```

`Pipeline.lean` is the orchestration layer; its stage functions map to
`Forensicator.tla` actions (`ParseHeader`, `ParseDirectory`, `DecodeStream`,
`BuildAddressSpace`). `buildAddressSpace_wellFormed` proves the constructed
space satisfies the spec invariant (`NoOverlap` — overlapping/invalid regions
are dropped, earlier regions win). `classifyDump` sums region sizes in `Nat`
(deliberate divergence: Rust's `u64` sum could wrap; ours cannot).

## Stream decoders (`Parse/Minidump.lean`, one module)

| Decoder | Stream | Facts decoded |
|---|---|---|
| header/directory | — | file structure (`StreamDirectory.find`) |
| `decodeSystemInfo` | SystemInfo (7) | OS platform, CPU arch, version |
| `decodeModuleList` | ModuleList (4) | name, base VA, size, checksum, RSDS GUID+age, pdb_name |
| `decodeThreadList` | ThreadList (3) | TID, CONTEXT registers, stack VA/size, TEB |
| `decodeMemoryList` / `decodeMemory64` | MemoryList (5) / Memory64List (9) | committed regions with byte payloads |
| `decodeMemoryInfoList` | MemoryInfoList (16) | VA metadata incl. reserve/free, PAGE_* protection |
| `decodeException` | Exception (6) | code, address, `ExceptionInformation[]` params, context |
| `decodeCrashpadAnnotations` | CrashpadInfo (0x43500001) | simple annotations dict |
| `decodeCommentA` | CommentA | last-ditch strings |
| V8HE decoder | **V8HE custom** (0x45483856) | see below |

All decoders are hand-written (no parse library), little-endian,
bounds-checked, and **truncation-tolerant**: non-fatal issues append to
`Dump.anomalies` with provenance; only structural impossibilities are
`Fatal`. Decode loops accumulate by cons-then-reverse (linear time).

## Provenance

Every decoded fact carries `Provenance { streamType, fileOffset, rva }` —
where in the file it came from. Anomalies use the same record
(`Model/Types.lean`).

## AddressSpace (`Spec/AddressSpace.lean`)

Sorted, non-overlapping regions `{ vaStart, size, data, protection, state,
classification }` — the same module is the *spec* (WellFormed invariant,
`regionAt_unique` theorem) and the shipping structure. Classification:
`Image module` inside module ranges, `Stack tid` overlapping thread stacks,
else Mapped/Private/Other from MemoryInfo type. Image backing for stack-only
dumps is supplied via `Util/Image.lean` (on-disk module bytes for
.pdata/.text).

## V8HE custom stream (decoder in `Parse/Minidump.lean`)

Emitted by the instrumented crash handler in the Electron build:

- **v1**: cage base + isolate VA + captured V8 heap regions, ingested as
  ordinary memory ranges (so the V8 analyzers work unmodified).
- **v2**: 32-byte extension after the header — allocation top/limit,
  `gc_state`, `last_gc_reason`, fatal-message string → `Dump.v8heapExt`,
  consumed by the `cause` analyzer's OOM/CHECK rules. The fatal message is the
  ground truth when present; the handler also mirrors it into a Crashpad
  annotation `v8_fatal_message` as a fallback channel.

## DumpKind degradation

`classifyDump` heuristically separates stack-only Crashpad minidumps from
full-memory captures. Analyzers degrade accordingly (e.g. the `v8` analyzer
needs heap memory for full frame decoding; stack-only dumps still allow
native-frame walking from thread stacks + Image backing).

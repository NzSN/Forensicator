# S1: Parse Pipeline (minidump → Dump + AddressSpace)

Spec: `specs/Model.tla`, `specs/AddressSpace.tla`, `specs/ParsePipeline.tla`,
`specs/Forensicator.tla` (root composition).
Code: `forensicator-core/src/parse/`, `forensicator-core/src/pipeline.rs`.

## Flow

```
.dmp bytes
  │  parse_header()        magic/version/stream count            (parse/header.rs)
  │  parse_directory()     stream directory entries              (parse/directory.rs)
  │  decode_streams()      per-stream decoders                   (parse/dump.rs)
  ▼
Dump { system_info, modules, threads, memory_regions, exception,
       anomalies, annotations, memory_info, v8heap_ext, file_size }
  │  build_address_space() regions → AddressSpace                (pipeline.rs:82)
  │  classify_dump()       StackOnly vs FullMemory (≥ 64 MiB)    (pipeline.rs:113)
  ▼
S1Output { dump, space, kind }
```

`Forensicator` (pipeline.rs) is the orchestrator; its stage methods map 1:1 to
`Forensicator.tla` actions (`ParseHeader`, `ParseDirectory`, `DecodeStream`,
`BuildAddressSpace`), and `S1State` mirrors the spec's latch variables.

## Stream decoders (`parse/`)

| Module | Stream | Facts decoded |
|---|---|---|
| `header.rs` / `directory.rs` | — | file structure |
| `system_info.rs` | SystemInfo (7) | OS platform, CPU arch, version |
| `module_list.rs` | ModuleList (4) | name, base VA, size, checksum, RSDS GUID+age, pdb_name |
| `thread_list.rs` | ThreadList (3) | TID, CONTEXT registers, stack VA/size, TEB |
| `memory.rs` | MemoryList (5) / Memory64List (9) | committed regions with byte payloads |
| `memory_info.rs` | MemoryInfoList (16) | VA metadata incl. reserve/free, PAGE_* protection |
| `exception.rs` | Exception (6) | code, address, `ExceptionInformation[]` params, context |
| `crashpad.rs` | CrashpadInfo (0x43500001) | simple annotations dict |
| `comment_a.rs` | CommentA | last-ditch strings |
| `v8heap.rs` | **V8HE custom** (0x45483856) | see below |

All decoders are hand-written (no parse crate), little-endian, bounds-checked,
and **truncation-tolerant**: non-fatal issues append to `Dump.anomalies` with
provenance; only structural impossibilities are `FatalError`.

## Provenance

Every decoded fact carries `Provenance { stream_type, file_offset, rva }`
(`error.rs`) — where in the file it came from. Anomalies use the same record.

## AddressSpace (`space.rs`)

Sorted, non-overlapping regions `{ va_start, size, data, protection, state,
classification }`. Classification: `Image{module}` inside module ranges,
`Stack{thread}` overlapping thread stacks, else Mapped/Private/Other from
MemoryInfo type. `NoOverlap` is a spec-verified invariant; overlapping adds are
rejected (MemoryInfoList wins boundary disputes). `set_backing(ImageSet)`
supplements stack-only dumps with on-disk module bytes (.pdata/.text) —
see `image.rs`.

## V8HE custom stream (`parse/v8heap.rs`)

Emitted by the instrumented crash handler in the Electron build:

- **v1**: cage base + isolate VA + captured V8 heap regions, ingested as
  ordinary memory ranges (so the V8 analyzers work unmodified).
- **v2**: 32-byte extension after the header — allocation top/limit,
  `gc_state`, `last_gc_reason`, fatal-message string → `Dump.v8heap_ext`,
  consumed by the `cause` analyzer's OOM/CHECK rules. The fatal message is the
  ground truth when present; the handler also mirrors it into a Crashpad
  annotation `v8_fatal_message` as a fallback channel.

## DumpKind degradation

`classify_dump` heuristically separates stack-only Crashpad minidumps from
full-memory captures. Analyzers degrade accordingly (e.g. the `v8` analyzer
needs heap memory for full frame decoding; stack-only dumps still allow
native-frame walking from thread stacks + Image backing).

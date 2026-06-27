# Forensicator — S1 (Foundation) Design

**Status:** CONFIRMED — all sections reviewed, TLA+ specs model-checked.
**Date:** 2026-06-27
**Sub-project:** S1 of S1–S4

---

## 1. Project vision (north star)

Forensicator analyzes process **minidumps** of **native C++ programs** and climbs an
abstraction ladder from raw bytes to *meaning*, using **inference only** (no debug symbols,
no managed runtime to interrogate):

1. **Raw bytes** — an address→value array. No meaning.
2. **Structure** — the dump format: mapped VA ranges, permissions, modules, threads, registers, stacks.
3. **Types** — bytes become typed values (pointer, int, string, struct).
4. **Objects & graph** — typed values reference each other; reconstruct the pointer/object graph.
5. **Semantics** — what the graph *means* (e.g. "doubly-linked list of N C++ objects of class X"). ← final goal.

Because native C++ memory carries no intrinsic type tags, meaning is recovered by **inference**
over structure + the pointer graph + C++ runtime conventions (vtables / MSVC RTTI, STL container
shapes, Windows heap). Outputs are **ranked hypotheses with provenance and confidence**, not certainties.

## 2. Decomposition (S1–S4)

The full system is research-grade and decomposes bottom-up; lower layers are prerequisites for upper ones.
Each is its own spec → plan → build cycle.

- **S1 — Foundation** *(this document)*: parse minidump → address-space model → structural facts.
- **S2 — Pointer graph**: classify pointers, extract roots (registers + stacks + module data), build/traverse the reachability graph.
- **S3 — Structure recovery**: heap-chunk/allocation boundaries, shape clustering, strings, vtables, list/array idioms.
- **S4 — Semantic labeling**: ranked hypotheses over recovered structures.

## 3. S1 scope & decisions

| Decision | Choice | Notes |
|---|---|---|
| Deliverable | **Library core + thin CLI** | S2–S4 import the library; CLI = `forensicator inspect <dump.dmp>` |
| Language | **Rust** | performance for multi-GB dumps; memory-safe parsing of untrusted input |
| Parsing backend | **Custom hand-written parser** | Full control over error handling; no external parse dependency. `minidumper` crate used as dev-dependency only (synthetic test fixtures). |
| Architecture | **x64 only** | behind an `Arch` seam so x86 / ARM64 can be added later (YAGNI now) |
| Target toolchain | **C++ / MSVC / Windows STL / Windows heap** | S1 is toolchain-agnostic; this assumption matters for S3–S4 |
| Test corpus | MSVC full-memory `.dmp` fixtures (Windows CI) **+** synthetic minidumps (Linux unit tests) | synthetic fixtures via `minidumper` crate unblock Linux TDD |
| CLI output | **Structured tree** (`--quiet` for summary, `--json` for machine-readable) | Confirmed |
| Streams surfaced | SystemInfo, ModuleList, ThreadList+CONTEXT, Memory64/MemoryList, MemoryInfoList, Exception | Confirmed; UnloadedModuleList/HandleData deferred |

**Why analyzer language ≠ target language:** a minidump is a documented, language-agnostic byte
format; once compiled there is no "C++" in memory, only ABI-defined byte layout. Rust reads those
bytes as well as anything. The C++/MSVC-ness of the *target* matters only for the inference layers
(S3–S4), where it is encoded as knowledge inside Forensicator.

**Dependency / risk:** real MSVC full-memory fixtures require Windows/CI (`MiniDumpWriteDump` / WER).
Synthetic minidumps cover all S1 logic on Linux; real-dump integration is additive.

---

## 4. Architecture & layout (CONFIRMED)

**Cargo workspace, two crates:**
- **`forensicator-core`** (library) — the foundation API that S2–S4 import.
- **`forensicator-cli`** (binary) — thin wrapper: `forensicator inspect <dump.dmp>` prints the
  structural inventory; `--json` emits machine-readable output.

**Internal modules of `forensicator-core`:**

| Module | Purpose | TLA+ spec |
|---|---|---|
| `arch` | `Arch` seam. v1: x64 only — pointer width (8), register-set shape, `decode_context` (raw CONTEXT → `RegisterSet`) | `specs/Arch.tla` |
| `model` | Normalized, dependency-free data types (`Dump`, `SystemInfo`, `Module`, `Thread`, `RegisterSet`, `MemoryRegion`, `ExceptionInfo`, `Provenance`, `Anomaly`) | `specs/Model.tla` |
| `parse` | **Firewall boundary.** Only module that reads raw `.dmp` bytes. Parses header → stream directory → per-stream decoders. Maps raw data into `model` types. No external parse dependency. | `specs/ParsePipeline.tla` |
| `space` | `AddressSpace`: VA→bytes index + region classification. Most-reused capability in the project. | `specs/AddressSpace.tla` |
| `error` | `FatalError` enum + `Anomaly` type. Modeled inline in `ParsePipeline.tla` and `Arch.tla`. | — |

**Module dependency graph (Rust crates):**
```
arch ← model ← parse
          ↑
          space (uses MemoryRegion classification from model)
```

**Module dependency graph (TLA+ specs):**
```
Arch.tla ────────────────── leaf (register set, PtrWidth, decode_context)
  ↑
Model.tla ───────────────── imports Arch (Thread.context, pointer values)
  ↑           ↑
  │           └── AddressSpace.tla (region invariants, classify, ReadOk)
  └── ParsePipeline.tla ─── (raw streams → typed Model → Dump, firewall)
                         Root.tla composes all 4 via INSTANCE
```

**Cross-cutting principles:**
- **Backend firewall** — only `parse` touches raw bytes; all other modules depend on `model`/`space`. Formally modeled in `ParsePipeline.tla`: `raw_streams` set before decode, typed data after.
- **Provenance everywhere** — every fact records which stream + file offset/RVA it came from. Formally modeled in `Model.tla`: every module/thread/region/exception carries `(stream_id, offset, rva)`.
- **Defensive by default** — `.dmp` is untrusted: bounds-checked reads, bounded allocation, degrade-to-partial. Parse problems become `Anomaly`s. Formally modeled in `AddressSpace.tla` (overlap→anomaly, read-beyond-bound→anomaly) and `Arch.tla` (truncated CONTEXT→anomaly).

---

## 5. Data model & AddressSpace (CONFIRMED)

### 5.1 Data types (`Model.tla`)

Every type carries provenance: `(stream_id: Int, file_offset: Int, rva: Int)`.

| Type | Fields | Invariants verified |
|---|---|---|
| `SystemInfo` | os, cpu, version (maj,min,bld,rev) | cpu=x64 only, provenance present |
| `Module` | base_va, size, checksum, pdb_hash | modules are disjoint in VA space, count bounded, provenance present |
| `Thread` | id, stack_va, stack_size, teb_va | stack_size > 0, count bounded, provenance present |
| `MemoryRegion` | va_start, size, protection, state, type, classification | valid class (0-4), valid state (0-2), valid protection (0-7), provenance present |
| `ExceptionInfo` | code, address, thread_id, flags | provenance present if exception exists |
| `Anomaly` | description string | count bounded |

**Key invariant:** `ModelInvariant` conjoins all type-level constraints — modules disjoint, counts bounded, provenance on everything, valid enum ranges. Verified by TLC (partial, state space too large for exhaustive) and structurally consistent in `Root.tla` composition.

### 5.2 AddressSpace (`AddressSpace.tla`)

Flat representation (Apalache-compatible): three parallel sequences `reg_va`, `reg_sz`, `reg_cl` indexed together. Region `i` is `(reg_va[i], reg_sz[i], reg_cl[i])`.

**Operations:**
- `classify(va)` → Image / Stack / Mapped / Private / Other (falls back to "Other" for unmapped VAs)
- `ReadOk(va, len)` → true iff a single contiguous region covers `[va, va+len)`
- `AddRegion(va, size, class)` → appended if no overlap; overlap produces anomaly
- `Read(va, len)` → succeeds if ReadOk; otherwise records anomaly

**Invariants verified by both TLC (5.6M states) and Apalache (len=4):**
1. `NoZeroSized` — every region has size > 0
2. `NoOverflow` — no region extends past MaxAddr
3. `BoundedCount` — at most MaxRegions regions
4. `NoOverlap` — all region pairs are disjoint
5. `BoundedAnomalies` — anomaly count bounded
6. `LenMatch` — the three parallel sequences stay synchronized
7. `ClassifyTotal` — `classify(va)` returns a valid class for every VA

**Classification logic:** `Image{module}` if VA falls inside a module range; `Stack{thread}` if VA overlaps thread stack; `Mapped`, `Private`, `Other` based on MemoryInfo type.

**Overlap precedence:** `MemoryInfoList` wins over `Memory64List` on boundary disputes. Both covering same range → prefer higher-granularity MEM_INFO. Overlaps between same-source regions → anomaly.

---

## 6. Data flow (CONFIRMED — `ParsePipeline.tla`)

```
.dmp file
  ↓
parse::header        → Header { magic, version, stream_count, stream_dir_rva }
  ↓  (Fatal if bad magic / unreadable header)
parse::directory     → Vec<StreamEntry> { stream_type, rva, size }
  ↓  (Fatal if directory RVA out of bounds)
per-stream decoders  → SystemInfo | Vec<Module> | Vec<Thread> | MemoryRanges | MemoryInfo | ExceptionInfo
  ↓  (Non-fatal; missing streams → anomalies)
Correlate            → (AddressSpace, Vec<Anomaly>)
  ↓  (Merges raw memory with memory-info metadata; overlaps → anomalies)
BuildDump            → Dump { system_info, modules, threads, memory, exception, anomalies }
  ↓
Consumer (S2-S4) / CLI render
```

**Pipeline phases modeled in `ParsePipeline.tla`:**
```
Init → HeaderDone → DirectoryDone → Decoding → Built → Done
  ↘              ↘
    Fatal           Fatal
```

**Verified invariants:** phases are valid, Fatal always has a reason, anomaly count bounded, backend firewall holds (raw streams only set before decode), every decoded fact carries provenance.

**Entry points:** `Dump::open(path: impl AsRef<Path>) -> Result<Dump, FatalError>`, `Dump::from_bytes(&[u8]) -> Result<Dump, FatalError>`.

---

## 7. Error handling (CONFIRMED)

Two tiers, zero panics:

| Tier | Type | Behavior | Examples | Modeled in |
|---|---|---|---|---|
| **Fatal** | `FatalError` enum | Stops pipeline immediately | Bad magic, directory OOB, file too large | `ParsePipeline.tla` |
| **Non-fatal** | `Vec<Anomaly>` | Accumulated, returned in `Dump` | Missing stream, truncated CONTEXT, overlapping regions, read beyond region | `Arch.tla`, `AddressSpace.tla`, `ParsePipeline.tla` |

**Hard rules (enforced by design, verified by invariants):**
1. No `.unwrap()` / `.expect()` on untrusted input — every byte read bounds-checked
2. No dynamic allocation from untrusted size fields — `try_allocate(cap, max)` clamps to `max`
3. `Dump` always returned if header parses — even with all streams missing → empty Dump + anomalies
4. `Parse == Deserialize + Validate` — decode raw bytes first, validate invariants second; validation failures → `Anomaly`

---

## 8. Testing (CONFIRMED)

| Layer | Approach | Tool |
|---|---|---|
| Unit tests | Synthetic `.dmp` fixtures generated via `minidumper` crate (dev-dependency) | `cargo test` (Linux + Windows) |
| Integration tests | Real MSVC full-memory `.dmp` fixtures on Windows CI | `cargo test` (Windows only) |
| Property tests | `AddressSpace` invariants (no-overlap, classify-total) via random region sequences | `proptest` crate |
| Fuzzing | `cargo-fuzz` on parse entry points (`Dump::from_bytes`) | `cargo fuzz` (stretch goal) |
| CI | Linux: build + clippy + test (synthetic only); Windows: build + test (real fixtures) | GitHub Actions |

**TDD flow:** write spec → red (failing test) → green (minimal implementation) → refactor. Each stream decoder, each AddressSpace invariant, each error path gets a red→green cycle before implementation.

---

## 9. TLA+ specification suite

All S1 design decisions are formalized and model-checked in `specs/`.

| File | What it models | TLC | Apalache |
|---|---|---|---|
| `Arch.tla` | x64 register set, PtrWidth=8, `decode_context` | ✓ 3 states | ✓ len=2 |
| `Model.tla` | Dump, Module, Thread, MemoryRegion, ExceptionInfo, Provenance-on-everything | ✓ (partial) | — (too large) |
| `AddressSpace.tla` | VA→region index, classify, ReadOk, no-overlap/overflow invariants | ✓ 5.6M states | ✓ len=4 |
| `ParsePipeline.tla` | Pipeline phases, firewall, stream→typed decode, provenance | ✓ 66 states | ✓ len=8 |
| `Root.tla` | Composition of all 4 via `INSTANCE`; interleaved Next; conjoined invariants | — (55 vars) | ✓ len=4, 31 VCs |

**Key results:**
- All 5 invariants (`ArchInvariant`, `ModelInvariant`, `TypeInvariant`, `ClassifyTotal`, `PipelineInvariant`) co-hold in the composed specification
- Backend firewall verified: `ParsePipeline` is the only module touching `raw_streams`
- Provenance-on-everything verified: all decoded facts carry stream_id+offset
- Defensive-by-default verified: anomalies accumulate instead of panics

**Running the model checkers:**
```
# TLC (Java 21+)
java -cp tla2tools.jar tlc2.TLC -config specs/Arch.cfg -deadlock specs/Arch.tla

# Apalache (Java 21)
apalache-mc --features=no-rows check --inv="RootInvariant" --length=4 --no-deadlock specs/Root.tla
```

---

## Open questions / TODO

- [x] Confirm Section 1 (architecture & layout).
- [x] Review & confirm Sections 2–5 (data model, data flow, error handling, testing).
- [x] Pin parsing approach: custom hand-written parser, `minidumper` for test fixtures.
- [x] CLI output style: structured tree with `--quiet` and `--json` flags.
- [x] Formalize all S1 contracts as TLA+ specs (5 specs, dual model-checking).
- [ ] Establish Windows CI path for real fixtures.
- [ ] Select exact test corpus: which MSVC binaries to dump.

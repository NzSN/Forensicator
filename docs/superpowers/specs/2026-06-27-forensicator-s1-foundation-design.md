# Forensicator — S1 (Foundation) Design

**Status:** DRAFT — brainstorming in progress.
Section 1 is PROPOSED (awaiting confirmation). Sections 2–5 are PENDING (not yet reviewed).
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
| Deliverable | **Library core + thin CLI** | S2–S4 import the library; CLI = `forensicator inspect <dump>` |
| Language | **Rust** | performance for multi-GB dumps; memory-safe parsing of untrusted input |
| Parsing backend | **Approach 3 — Hybrid** | `minidump` crate decodes bytes; mapped into our own normalized model |
| Architecture | **x64 only** | behind an `Arch` seam so x86 / ARM64 can be added later (YAGNI now) |
| Target toolchain | **C++ / MSVC / Windows STL / Windows heap** | S1 is toolchain-agnostic; this assumption matters for S3–S4 |
| Test corpus | MSVC full-memory `.dmp` fixtures (Windows CI) **+** synthetic minidumps (Linux unit tests) | synthetic fixtures unblock Linux TDD |

**Why analyzer language ≠ target language:** a minidump is a documented, language-agnostic byte
format; once compiled there is no "C++" in memory, only ABI-defined byte layout. Rust reads those
bytes as well as anything. The C++/MSVC-ness of the *target* matters only for the inference layers
(S3–S4), where it is encoded as knowledge inside Forensicator.

**Dependency / risk:** real MSVC full-memory fixtures require Windows/CI (`MiniDumpWriteDump` / WER).
Synthetic minidumps cover all S1 logic on Linux; real-dump integration is additive.

---

## 4. Section 1 — Architecture & layout — STATUS: PROPOSED (awaiting confirmation)

**Cargo workspace, two crates:**
- **`forensicator-core`** (library) — the foundation API that S2–S4 import.
- **`forensicator-cli`** (binary) — thin wrapper: `forensicator inspect <dump.dmp>` prints the
  structural inventory; `--json` emits machine-readable output (handy for tests and for debugging later layers).

**Internal modules of `forensicator-core`:**
- **`arch`** — the `Arch` seam. v1 implements `X64` only: pointer width (8), register-set shape,
  and `decode_context` (raw `CONTEXT` → our `RegisterSet`). x86/ARM64 slot in later without touching consumers.
- **`parse`** — the **hybrid boundary**. The *only* module that imports the `minidump` crate. It drives
  the crate and maps raw streams into our model. Firewalling it here realizes Approach 3's clean seam —
  a hand-written parser could replace it later with no change to consumers.
- **`model`** — our normalized, dependency-free data types (`Dump`, `SystemInfo`, `Module`, `Thread`,
  `RegisterSet`, `MemoryRegion`, `ExceptionInfo`, `Provenance`, `Anomaly`). What S2–S4 consume.
- **`space`** — the `AddressSpace`: the VA→bytes index + region classification. The most-reused capability in the project.
- **`error`** — fatal vs. non-fatal result types.

**Cross-cutting principles baked in from the start:**
- **Backend firewall** — only `parse` knows about the `minidump` crate; everyone else depends solely on `model`/`space`.
- **Provenance everywhere** — every fact records which stream + file offset/RVA it came from (forensic traceability + debugging).
- **Defensive by default** — `.dmp` is untrusted input: bounds-checked reads, no panics, bounded
  allocation, degrade-to-partial rather than fail. Parse problems become recorded `Anomaly`s
  (tampering then surfaces *as* anomalies).

---

## 5. Section 2 — Data model & AddressSpace — STATUS: PENDING (not yet reviewed)

_Planned content sketch — subject to review:_
- Normalized `model` types and their fields: `Dump` (root), `SystemInfo`, `Module` (image base/size,
  CodeView/PDB ref), `Thread` (id, `RegisterSet`, stack range, TEB), `RegisterSet` (x64 GP regs, rip/rsp/rbp/rflags),
  `MemoryRegion` (va_start, size, bytes, protection, state, type, derived classification), `ExceptionInfo`
  (code, faulting address/thread), `Provenance`, `Anomaly`.
- **`AddressSpace`**: sorted/indexed regions supporting `read(va, len)`, pointer-width `read_ptr`,
  `region_at(va)`, `classify(va)` → Image{module} / Stack{thread} / Mapped / Private / Other.
  (True heap-chunk discovery is deferred to S3; S1 classification is conservative.)
- Overlap/duplicate-range precedence rules.

## 6. Section 3 — Data flow — STATUS: PENDING (not yet reviewed)

_Planned content sketch:_ `.dmp` → `parse` (minidump crate: header + stream directory) → per-stream
mapping (SystemInfo, ModuleList, ThreadList+CONTEXT, Memory64/MemoryList, MemoryInfoList, Exception)
→ correlate memory + memory-info into classified regions → build `AddressSpace` → assemble `Dump`
→ consumed by library callers (S2–S4) or rendered by CLI (text / `--json`).
Entry points: `Dump::open(path)`, `Dump::from_bytes(&[u8])`.

## 7. Section 4 — Error handling — STATUS: PENDING (not yet reviewed)

_Planned content sketch:_ two tiers — **fatal** (`FatalError`: unreadable file, bad magic, unreadable
directory) vs **non-fatal** (`Vec<Anomaly>`: missing/empty/truncated streams, overlaps, undecodable
context, out-of-bounds RVAs). Hard rules: no panics on malformed input, bounded allocation (don't trust
size fields), degrade to partial `Dump`. Robustness is a feature: anomalies are forensic output.

## 8. Section 5 — Testing — STATUS: PENDING (not yet reviewed)

_Planned content sketch:_ unit tests on hand-crafted **synthetic minidumps** (Linux, no Windows needed)
covering header parse, each stream→model mapping, `AddressSpace` read/gap/overlap/classify, x64 CONTEXT
decode, anomaly generation on corrupted inputs (TDD red→green); **integration tests** on real
MSVC-compiled full-memory `.dmp` fixtures (Windows CI); property tests for `AddressSpace` invariants;
`cargo-fuzz` on the parse entry point (stretch). CI: Linux build/clippy/test + a Windows job for fixtures.

---

## Open questions / TODO

- [ ] Confirm Section 1 (architecture & layout).
- [ ] Review & confirm Sections 2–5 (currently PENDING).
- [ ] Pin exact `minidump` crate version and the precise set of streams S1 must surface.
- [ ] Decide CLI text output shape (tree/inventory) and `--json` schema.
- [ ] Establish Windows CI path for real fixtures.

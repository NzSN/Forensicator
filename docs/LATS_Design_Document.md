# Local Address-aware Tracing System (LATS)

## Design Document v0.1

**Objective**: Record all read/write accesses to a specific memory address within a recent time window (e.g., 10 minutes), including full call stacks of the accessing functions.

**Target Scenarios**: Chromium/Blink renderer crash analysis, UAF root-cause localization, data-race auditing, state-mutation provenance.

---

## 1. Background

### 1.1 Limitations of Traditional TTD

Time Travel Debugging (TTD) records the entire execution history of a process to enable "time travel." Its fundamental tension lies in:

- **Data explosion**: Full instruction traces + memory snapshots grow linearly with time, typically 5–50 GB/min.
- **High retrieval cost**: Searching "who wrote address X" post-hoc is a reverse query whose complexity is proportional to the total record volume.
- **Unacceptable overhead**: In high-frequency memory-access workloads like Chromium, global TTD slowdown often reaches 10x–100x, making it unsuitable for online or long-duration monitoring.

### 1.2 From Time-Centric to Data-Centric

The core paradigm shift of this design is: **anchor on the target memory address and capture its accessors**, rather than recording all states across the entire timeline.

Formally:

> Given address set **A** = {a₁, a₂, ..., aₙ} and time window **T** = [t_now − Δt, t_now],
> compute **H** = { (t, f, op) | t ∈ T, f ∈ CallStack(t), op ∈ {R, W}, access(op, aᵢ, t) = true }.

Where:
- **access(op, a, t)** denotes an operation op on address a at time t;
- **CallStack(t)** is the complete call stack at time t.

Query complexity depends only on the access frequency of the target address, decoupled from total process activity.

### 1.3 Evolution of Hardware Capabilities

Modern CPUs provide debug architectures that make address-centric tracing effectively zero-overhead (until triggered):

| Platform | Mechanism | Slots | Trigger |
|----------|-----------|-------|---------|
| x86-64 | Debug Registers (DR0–DR7) | 4 | #DB exception |
| ARM64 | DBGBCR / DBGWCR | 2–16 | Breakpoint / Watchpoint exception |
| Apple Silicon | ARMv8-A Debug | 4 | Same as ARM64 |

These mechanisms allow access traps on specific addresses **without modifying the target program's instruction stream**.

---

## 2. Core Principles

### 2.1 Hardware Watchpoint Mechanism (x86-64)

x86-64 provides six debug registers:

- **DR0–DR3**: Hold target linear addresses (64-bit each).
- **DR6**: Debug status register; CPU sets bitfields after an exception to indicate which DRi fired.
- **DR7**: Debug control register; configures per-address monitoring attributes:
  - **R/W0–R/W3** (bits 16–17, 20–21, 24–25, 28–29):
    - `00` = execute breakpoint
    - `01` = write breakpoint
    - `10` = I/O read/write (Ring 0 only)
    - `11` = read/write breakpoint
  - **LEN0–LEN3** (bits 18–19, 22–23, 26–27, 30–31): monitored length (1/2/4/8 bytes).
  - **L0–L3** (bits 0–3): local enable flags (per-thread).
  - **G0–G3** (bits 8–11): global enable flags (all threads).

When the CPU pipeline detects a matching access to a DRi address:
1. The current instruction completes.
2. Corresponding DR6 bits are set.
3. **#DB** exception (vector 1) is delivered.
4. If in user mode, control transfers through the IDT to the kernel debug-exception handler.

**Key property**: The exception is delivered **after** the instruction completes, so both old and new values at the monitored address are readable.

### 2.2 Exception Handling and Stack Capture

In Windows user mode, #DB flows through:

```
CPU #DB
  → KiDebugTrapOrFault (Kernel)
    → KiDispatchException
      → NtDispatchException
        → Ntdll KiUserExceptionDispatcher
          → Vectored Exception Handler chain
            → Our Handler (AddVectoredExceptionHandler)
```

Inside the handler, the `CONTEXT` structure provides:
- **RIP**: address of the triggering instruction;
- **RSP/RBP**: stack/frame pointers;
- **DR6**: identifies which watchpoint fired.

Stack unwinding traverses the frame-pointer chain (RBP) or uses **RtlVirtualUnwind** / **StackWalk64** with PDB unwind information.

### 2.3 Sliding Time Window and Ring Buffer

Global TTD cannot easily implement a "last 10 minutes" sliding window because evicting old data requires parsing and trimming complex state graphs. In this design, each watchpoint hit produces an **independent, self-describing** record:

```cpp
struct AccessRecord {
    uint64_t    timestamp;      // QPC counter, 100 ns resolution
    uint64_t    thread_id;      // accessing thread
    uint64_t    target_addr;    // monitored address
    uint8_t     access_type;    // 0=Read, 1=Write
    uint64_t    instruction_ip; // triggering instruction address
    uint64_t    old_value;      // pre-write value (for writes)
    uint64_t    new_value;      // post-write value
    uint32_t    stack_depth;    // call-stack depth
    uint64_t    stack_hash;     // hash for deduplication
    uint64_t    stack[];        // variable-length RIP array
};
```

Records are stored in a **lock-free ring buffer**. Each record carries a timestamp; queries binary-search the 10-minute boundary for O(log N) window retrieval.

**Eviction policies**:
- **Capacity-first**: overwrite oldest record when buffer is full (natural sliding window).
- **Time-first**: background thread periodically scans and drops records with `timestamp < t_now − 10 min`.

### 2.4 Multi-Address Extension: From 4 Slots to N Addresses

Hardware provides only 4 slots. To monitor N > 4 addresses, use **time-sliced multiplexing**:

1. Partition N addresses into ⌈N/4⌉ batches.
2. Each batch holds hardware slots for Δt (e.g., 100 ms).
3. On batch switch, save/restore DR state.
4. Assign higher weights to high-frequency addresses (weighted round-robin).

**Probabilistic guarantee**: if accesses to address a follow a Poisson process with rate λ, sampling probability p = 4/N, then the probability of capturing at least one access in interval T is 1 − e^(−λpT). Adjusting Δt balances precision vs. coverage.

---

## 3. Implementation Design

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Target Process                          │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Client    │───→│  Controller  │───→│  Ring Buffer │   │
│  │   (API)     │    │   (Core)     │    │   (Store)    │   │
│  └─────────────┘    └──────┬───────┘    └──────────────┘   │
│                            │                                │
│                    ┌────────┴────────┐                      │
│                    ▼                 ▼                      │
│            ┌─────────────┐   ┌─────────────┐               │
│            │ HW Watchpoint│   │ Page Guard  │               │
│            │   Engine     │   │   Engine    │               │
│            └──────┬──────┘   └──────┬──────┘               │
│                   │                  │                        │
│                   └──────┬───────────┘                        │
│                          ▼                                  │
│                   ┌─────────────┐                           │
│                   │  Exception   │                           │
│                   │   Handler    │                           │
│                   └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Module Design

#### 3.2.1 Controller

**Responsibility**: manage monitoring lifecycle, coordinate hardware/software engines, serve queries.

```cpp
class TracingController {
public:
    // Register an address for monitoring
    Status Watch(uintptr_t addr, size_t size, AccessType type);

    // Unregister monitoring
    Status Unwatch(uintptr_t addr);

    // Query all access records to addr within the last time_window_ms
    std::vector<AccessRecord> Query(uintptr_t addr, uint64_t time_window_ms);

    // Export to JSON / Chrome Trace Event Format
    Status Export(const std::string& path, Format fmt);

private:
    std::unique_ptr<HwEngine> hw_engine_;
    std::unique_ptr<PageGuardEngine> pg_engine_;
    std::shared_ptr<RecordStore> store_;

    // address → engine routing table
    std::unordered_map<uintptr_t, EngineType> routing_table_;
};
```

**Routing policy**:
- ≤ 4 addresses: all via HW Engine.
- > 4 addresses: sort by access frequency; top-4 via HW Engine, remainder via Page Guard Engine.

#### 3.2.2 HW Engine

```cpp
class HwEngine {
public:
    Status EnableWatchpoint(size_t slot, uintptr_t addr, size_t len, AccessType type);
    Status DisableWatchpoint(size_t slot);

private:
    // Configure DR for a specific thread via SetThreadContext
    Status ApplyToThread(HANDLE thread, size_t slot, const DrConfig& cfg);

    // Enumerate all threads and apply configuration
    Status ApplyToAllThreads(size_t slot, const DrConfig& cfg);

    // #DB exception handler
    static LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ep);
};
```

**Key implementation details**:

1. **Thread safety**: Windows DRs are part of **thread context**. New threads do not inherit parent DR settings. Synchronize via **PsSetCreateThreadNotifyRoutine** (kernel driver) or polling thread enumeration (user mode).

2. **DR6 parsing**: after exception, check DR6 bits B0–B3 and BD (debug-register access), BS (single-step) to avoid false positives.

3. **Single-step resume**: to continue monitoring the same address, do not clear DR on #DB; hardware resumes automatically. For one-shot capture, clear the corresponding DR7 bit inside the handler.

#### 3.2.3 Page Guard Engine

For cases where hardware slots are insufficient or large ranges must be monitored.

```cpp
class PageGuardEngine {
public:
    Status GuardPage(uintptr_t addr);
    Status UnguardPage(uintptr_t addr);

private:
    // Mark the page containing addr as PAGE_NOACCESS
    // In the exception handler, identify if it is our target address,
    // then: record → temporarily restore permissions → set TF single-step → re-protect
    static LONG WINAPI GuardHandler(EXCEPTION_POINTERS* ep);

    // Single-step handler: re-mark as PAGE_NOACCESS
    static LONG WINAPI StepHandler(EXCEPTION_POINTERS* ep);
};
```

**Performance optimizations**:
- **Shadow page pool**: pre-allocate swappable physical pages to reduce VirtualProtect syscall overhead.
- **TLB shootdown batching**: batch modifications for multiple addresses on the same page to reduce IPI storms.

#### 3.2.4 RecordStore

Uses an **MPMC (multi-producer single-consumer) lock-free ring buffer**. Each thread has an independent producer buffer; periodic merging into the global ring buffer.

```cpp
class RecordStore {
public:
    void Push(const AccessRecord& rec);
    std::vector<AccessRecord> Query(uintptr_t addr, uint64_t since);

private:
    // Sharded ring buffers to reduce contention
    struct Shard {
        alignas(64) LockFreeRingBuffer<AccessRecord> buffer;
        std::atomic<uint64_t> min_timestamp{UINT64_MAX};
    };
    std::array<Shard, kNumShards> shards_;

    size_t ShardIndex(uintptr_t addr) const {
        return std::hash<uintptr_t>{}(addr) % kNumShards;
    }
};
```

**Time-window eviction**:
- Background thread scans each shard's `min_timestamp` every 60 seconds.
- If `min_timestamp < t_now − 10 min`, batch-evict from head until condition is met.

### 3.3 Call-Stack Unwinding

#### 3.3.1 Fast Path: Frame-Pointer Traversal

```cpp
inline bool FastUnwind(CONTEXT* ctx, uint64_t* ips, size_t max_depth, size_t* out_depth) {
    uint64_t* frame = reinterpret_cast<uint64_t*>(ctx->Rbp);
    uint64_t ip = ctx->Rip;
    size_t depth = 0;

    ips[depth++] = ip;

    while (depth < max_depth && frame) {
        uint64_t next_ip = frame[1];     // return address
        uint64_t next_frame = frame[0];  // saved RBP

        if (!IsValidCodeAddress(next_ip)) break;

        ips[depth++] = next_ip;
        frame = reinterpret_cast<uint64_t*>(next_frame);
    }

    *out_depth = depth;
    return true;
}
```

#### 3.3.2 Precise Path: DIA SDK / DbgHelp

For FPO-optimized or frame-pointer-omitted functions, use **StackWalk64** + **SymFromAddr**:

```cpp
void PreciseUnwind(CONTEXT* ctx, std::vector<std::string>& symbols) {
    STACKFRAME64 frame = {};
    frame.AddrPC.Offset = ctx->Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx->Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;

    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread,
                       &frame, ctx, nullptr,
                       SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
        char symbol[256];
        DWORD64 disp;
        PSYMBOL_INFO pSym = (PSYMBOL_INFO)symbol;
        pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSym->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddr(process, frame.AddrPC.Offset, &disp, pSym)) {
            symbols.emplace_back(pSym->Name);
        }
    }
}
```

**Trade-off**: fast path for high-frequency triggers (microsecond-level), precise path for final report generation (millisecond-level).

### 3.4 Query Interface

```cpp
// C++ API
auto records = controller.Query(0x00007FF612340000, 10 * 60 * 1000);

// Equivalent CLI
lats.exe --pid 1234 --query 0x00007FF612340000 --window 10m --format json
```

**Sample output**:

```json
{
  "target": "0x00007FF612340000",
  "window_ms": 600000,
  "records": [
    {
      "timestamp": "2026-08-07T09:15:32.1234567Z",
      "thread_id": 12345,
      "type": "Write",
      "old_value": "0xDEADBEEF",
      "new_value": "0xCAFEBABE",
      "stack": [
        "blink::Node::SetFlag",
        "blink::Element::SetAttribute",
        "blink::HTMLParser::ParseToken",
        "v8::internal::Runtime_SetProperty",
        "..."
      ]
    }
  ]
}
```

---

## 4. Edge Cases and Engineering Considerations

### 4.1 High-Frequency Addresses

If the target address lies on a hot path (e.g., reference count, GC mark bit), hardware watchpoints trigger #DB repeatedly, causing:

- **CPU pipeline flush**: ~1–3 μs per exception;
- **Scheduler jitter**: excessive time spent in exception context.

**Mitigations**:
- **Sampling mode**: record only 1 out of every N triggers (using DR6 BS bit with a counter).
- **Adaptive degradation**: if trigger frequency exceeds 1000/s, automatically migrate the address to the Page Guard Engine with increased sampling interval.

### 4.2 Multithreading and Concurrency

- **#DB exceptions are thread-local**: accesses to the same address from different threads are handled in their respective contexts, naturally thread-safe.
- **Ring-buffer concurrency**: use FAA (fetch-and-add) for lock-free commit, avoiding mutex priority inversion.
- **New-thread monitoring**: preset DR values via `SetThreadContext` on new threads, or rely on APC injection at `CreateThread`.

### 4.3 Virtual Addresses and ASLR

Target addresses may be heap-allocated and dynamic. The design supports:
- **Runtime registration**: register addresses after `malloc`/`new` returns;
- **Wildcard matching**: module base + offset patterns (e.g., `chrome.dll+0x123456`), resolved internally to absolute addresses.

### 4.4 Integration with Chromium

```cpp
// Inside Chromium, integrate LATS in the crashpad handler
// to auto-export recent target-address access history on crash

void OnRendererCrash(const base::FilePath& dump_path) {
    auto lats = content::GetLATSService();
    auto records = lats->Query(g_suspect_addr, 10 * 60 * 1000);

    base::WriteFile(
        dump_path.ReplaceExtension(".lats.json"),
        base::ToJson(records)
    );
}
```

---

## 5. Performance Evaluation (Theoretical Model)

| Metric | Hardware Watchpoint | Page Guard | Global TTD |
|--------|--------------------|-----------|-----------|
| Baseline overhead | **0%** | 0% (except during page-table changes) | 20–500% |
| Per-trigger overhead | 1–3 μs | 10–100 μs | N/A |
| Max monitored addresses | 4 (per thread) | Unlimited (page-table limited) | Full address space |
| Time-window flexibility | High (ring buffer) | High | Low (requires truncation) |
| Stack precision | Full | Full | Full |
| Suitable scenarios | High-frequency, precise, few addresses | Low-frequency, bulk, many addresses | Full backtrace |

---

## 6. Implementation Roadmap

| Phase | Task | Duration |
|-------|------|----------|
| P0 | HW Engine prototype (single-thread, single-address) | 3 days |
| P1 | Ring Buffer + query interface | 2 days |
| P2 | Multi-thread support + stack unwinding | 3 days |
| P3 | Page Guard Engine + auto-routing | 3 days |
| P4 | Chromium integration + crash auto-export | 2 days |
| P5 | Performance tuning + sampling strategy | 3 days |

---

## 7. Risks and Alternatives

| Risk | Impact | Mitigation |
|------|--------|------------|
| Insufficient hardware slots | Cannot monitor >4 addresses simultaneously | Time-sliced multiplexing + page-guard fallback |
| Anti-debug detection | Some DRM/anti-cheat detects DR usage | Use only in internal debug builds |
| Kernel-mode accesses | Drivers/DLLs may bypass user-mode monitoring | Combine with kernel driver (Kprobes/ETW) |
| ARM platform differences | DR mechanisms differ | Abstract Engine interface with platform adapters |

---

*Document Version: v0.1*  
*Author: AI Assistant*  
*Date: 2026-08-07*

# Timeline native prerequisite evidence (V0 / R0)

Date: 2026-09-06. Owner: `completion_native_prereqs` subagent.

Scope: read-only prerequisite discovery, actual SDK inspection, and a temporary
Windows ABI probe. No external proxy implementation, trace replay, golden
regeneration, or credential inspection occurred. This report is the only repository
file owned by this task. Temporary downloads and probe artifacts are under `/tmp`.

Related: [completion plan](2026-09-06-timeline-completion-plan.md),
[v2 contract](../docs/trace/2026-09-06-proxy-v2-contract-draft.md).

## Result and remaining gate

The native coordinate **layout is verified** against the actual
`Microsoft.TimeTravelDebugging.Apis` 0.9.5 package and a Windows x64 MSVC executable:
two unsigned 64-bit components, 16-byte structure, lexicographic ordering in the
header. This supports the lossless coordinate work in R1.

The SDK exposes thread context, replay-target TEB addresses, per-thread positions,
memory ranges, and replay interruption. Header availability does **not** certify
their runtime applicability, register validity, exact memory values, or native
event phase. In particular, no memory query policy in this header promises strict
exactness. R0's replay/independent-oracle matrix remains open; R2 must not advertise
`memory_exact` solely because a conservative query returned bytes.

A Windows runner, compiler, historical `.run` fixture, and staged replay DLLs were
found. The current proxy checkout/binary and `Case/golden` were not found in the
bounded paths inspected. The historical extractor is not the current proxy.

## 1. Local prerequisites

| Input | Verified observation | Consequence |
|---|---|---|
| Repository fixtures | `/home/nzsn/Repos/Forensicator/Case` absent; `FORENSICATOR_CASE_DIR` unset | V0 golden comparison cannot run against existing references yet |
| Proxy configuration | `FORENSICATOR_PROXY_RUN`, `FORENSICATOR_PROXY_SSH`, and `FORENSICATOR_PROXY_EXE` unset | No configured live gate |
| Default proxy checkout | `/mnt/d/Codebase/JigsawSpawner` absent | Default local/remote path in `Trace/Client.lean` is not a discovered installation |
| Alternate historical checkout | `/mnt/d/Repositories/TTFX` exists; HEAD `cf454da925c0e7e34ea03480a15b7fafafd34dfe` | README/source inventory describes the eager extractor; `target/release/ttfx-proxy.exe` absent |
| Other checked proxy paths | `/mnt/d/Codebase/TTFX` and `/mnt/d/Repositories/JigsawSpawner` absent | These aliases do not unblock proxy work |
| Real trace | `/mnt/d/Repositories/TTFX/traces/hostname01.run` exists | Its identity is pinned below; no replay result is claimed |
| Staged native libraries | Replay DLLs under the historical checkout's `target/release/ttd` exist | File identity is available, API compatibility/replay remains untested |
| Windows interop | Native `cmd.exe /c ver` succeeds outside the Linux sandbox: Windows `10.0.26200.9168` | A local Windows runner exists; sandbox failure alone did not establish a missing runner |
| Windows compiler | Visual Studio 18 Community; MSVC `14.51.36231`, x64 compiler reports `_MSC_VER=1951` | Actual-header x64 ABI probe compiled and ran |

The sandboxed `cmd.exe` attempt failed with `UtilBindVsockAnyPort:308: socket
failed 1`; the same read-only command succeeded with the required sandbox
escalation. This is an execution-environment boundary, not a TTD assertion failure.
No SSH host connection was attempted.

The real-dump gate requires `Case/minidump/*.dmp`, `Case/minidump_v2/*.dmp`,
`Case/fulldump/*.dmp`, `Case/minidump/electron.exe`, its PDB, and the existing
`Case/golden` references, as read from `scripts/conformance-lean.sh`. Targeted checks
also found no `Case`/`cases`/`fixtures` directory immediately under the historical
TTFX, local V8-DumpAnalyzer, or DumpLedger checkouts. This was not an exhaustive
whole-disk scan. No replacement fixtures or goldens were fabricated.

## 2. Actual SDK package pin

Downloaded directly from the [NuGet flat-container package endpoint](https://api.nuget.org/v3-flatcontainer/microsoft.timetraveldebugging.apis/0.9.5/microsoft.timetraveldebugging.apis.0.9.5.nupkg).
The [official package page](https://www.nuget.org/packages/Microsoft.TimeTravelDebugging.Apis/0.9.5)
identifies this as Microsoft's C/C++ TTD API package. The downloaded `.nuspec`
contains package ID `Microsoft.TimeTravelDebugging.Apis`, version `0.9.5`, author
Microsoft, and MIT license metadata. The package contains headers and import
libraries, not `TTDReplay.dll`; package pinning and DLL pinning are separate.

| Artifact | Size | SHA-256 |
|---|---:|---|
| `microsoft.timetraveldebugging.apis.0.9.5.nupkg` | 75,561 | `c906b99c02926ce089e1ed1bd54f1a0abf83458ddce4cf9bbc62403d7aa240bd` |
| `sdk/include/TTD/IReplayEngine.h` | — | `4f8a76919b1f65254f483d00abb4522668a9c46c6e91ce54d3d8a900b2024217` |
| `sdk/include/TTD/IdnaBasicTypes.h` | — | `9144534aa2f28120907f37aef58aec1e87ffd07906fbd442e7aab2d3d57bd684` |
| `sdk/include/TTD/IReplayEngineRegisters.h` | — | `89d1f819ab841538b5efbc815cbb06544a2470b4f8e303a5c9d9e7cf3704eb79` |
| `sdk/include/TTD/IReplayEngineStl.h` | — | `2a59ce09d2800827a349026cd81319de3f1ebb19fa5a3ee19ffd97a3f44ac579` |
| `sdk/include/TTD/TTDCommonTypes.h` | — | `891f1121e492244d129a4dd46406c64bbbefb086b05a3e26e02cf5df6745b90c` |

Local package: `/tmp/microsoft.timetraveldebugging.apis.0.9.5.nupkg`.
Extracted headers: `/tmp/forensicator-ttd-api-0.9.5/sdk/include/TTD`.
Hashes apply to the original archive bytes and original CRLF header bytes.
The NuGet signature file exists, but signature-chain validation was not performed.

Linux download attempts failed DNS inside the sandbox and TLS at both NuGet API
and CDN outside it. Windows `Invoke-WebRequest` against the same HTTPS
flat-container endpoint succeeded, with output confined to the WSL `/tmp` path.
No alternate package publisher or sample-header substitution was used.

## 3. ABI and semantics established from the package

Line references below address the pinned archive's original headers.

| Topic | Actual package evidence | Limit / implementation consequence |
|---|---|---|
| Coordinate widths | `IdnaBasicTypes.h:437–444`: `SequenceId : uint64_t`; `IReplayEngine.h:319–329`: `StepCount : uint64_t`; `375–400`: `Position { Sequence, Steps }` and tuple comparisons | Store both halves losslessly. Legacy packed u32 halves require checked conversion |
| Sentinel values | Sequence and step enums use all-ones for invalid, with maximum valid enum sentinel one less; `Position::IsValid` checks only the sequence | Structural `IsValid` is not proof that a coordinate exists in a trace |
| Step meaning | `IReplayEngine.h:319–321` includes non-instruction advances such as exceptions/context updates | Numerical increment is not certified native instruction navigation |
| Position resolution | `IReplayEngine.h:1619–1623`: `SetPosition(Position const&)` and `SetPositionOnThread(UniqueThreadId, Position const&)` normalize upward to a valid point | Record requested and actual points. An adjusted point cannot silently satisfy an exact request |
| Range endpoints | `IReplayEngine.h:451–460`: native `PositionRange` is closed | Translate native inventories explicitly; do not copy them into host half-open intervals without a rule |
| Thread identities | `IReplayEngine.h:219–225`: `UniqueThreadId : uint32_t`; `IdnaBasicTypes.h:559` defines separate OS `ThreadId : uint32_t` | Preserve both. OS TID reuse is not a thread-instance identity |
| Thread lifetime/projection | `IReplayEngine.h:940–982`: `ThreadInfo` has `Lifetime` and `ActiveTime`; `ActiveThreadInfo` has `CurrentPosition` and exclusive `LastValidPosition` | Do not collapse lifetime, active instructions, and the per-thread position into one point |
| Thread context API | `IReplayEngine.h:1577–1587`: `GetThreadInfo`, `GetTebAddress`, `GetPosition`, `GetPreviousPosition`, PC/SP/FP, and `GetCrossPlatformContext` / `GetAvxExtendedContext` accept optional `ThreadId` for live threads | Native current/non-current/invalid-thread behavior still needs probes. `SetPositionOnThread` takes **UniqueThreadId**, unlike these context queries |
| Register representation | `IReplayEngine.h:135–166`: context and extended context returned by value as opaque unions of 2672/8832 bytes; `IReplayEngineRegisters.h:531–577` provides conversion to debugger-compatible structures | No cursor-owned context pointer was verified here. Decode the pinned architecture schema and validity flags; zero values do not imply unavailable registers |
| x64 register schema | `IReplayEngineRegisters.h:151–212` includes `ContextFlags`, integer/control fields; compatibility context exposes `Amd64Context` | Runtime register availability/flag meaning must be checked before certifying a per-register validity mask |
| Memory policy | `IReplayEngine.h:1429–1450`: `Default`, `ThreadLocal`, `GloballyConservative`, `GloballyAggressive`, `InFragmentAggressive` | Stable results at unchanged position/thread are promised, **not exactness**. Conservative is described as high-confidence; aggressive can use lower confidence; in-fragment aggressive can search future observations |
| Memory API and provenance | `IReplayEngine.h:1466–1487,1537–1559`: `QueryMemoryRange(address, policy)`, `QueryMemoryBuffer(address, BufferView, policy)`, and `QueryMemoryBufferWithRanges(address, BufferView, maxRanges, MemoryRange*, policy)` | `MemoryRange` reports **SequenceId**, not a full `Position`. Composite buffers may combine multiple recording positions. Preserve short data; do not pad or invent missing provenance |
| Borrowed memory lifetime | `IReplayEngine.h:1537–1543`: `QueryMemoryRange` returns internal bytes valid until the next memory query on that cursor | Copy before another memory query. Buffer-filling APIs write into caller-supplied buffers; returned subrange views still require careful ownership handling |
| Callback memory | `IReplayEngine.h:1505–1524`: callback `IThreadView` memory reads use thread-local policy; richer policies require another cursor or returning from execution | Do not use ordinary cursor calls from callback context or claim callback reads used the global conservative policy |
| Access phases | `IReplayEngine.h:731–754`: read/write notifications occur during access; overwrite occurs before overwrite; data mismatch and new-data semantics are recording/replay facts | These descriptions do not establish the host's global before/after-write conversion. `NewData` is not a certified allocation event |
| Access identity | `IReplayEngine.h:1625–1635`: callback result exposes address, size, access type plus `IThreadView` | No stable occurrence identifier is supplied in this result. `(position,address,length)` or response row numbers cannot be asserted to be complete stable IDs |
| Continuity/progress | `IReplayEngine.h:1646–1660`: replay progress and thread-continuity callbacks exist | These are candidate paths for confirmed coverage; callback behavior and scan termination still need native tests |
| Cancellation | `IReplayEngine.h:1724–1727`: `InterruptReplay()` may be called from any thread and requests prompt replay termination | It does not certify cancellation of every API operation or immediate termination. Native timing/response-boundary tests remain required |
| Mappings/lifecycles | Inspection of the public replay view found point memory reads and module inventories, with no VirtualQuery-like complete allocation/protection/state enumeration | This public surface does not close M0/M1. Investigate a distinct recording-backed provider; do not expose host-process mappings as replay-target facts |

The SDK's own inline `Position` arithmetic is not used as a navigation oracle.
Notably, the `StepCount` subtraction overload at `IReplayEngine.h:432` delegates
to addition. Actual trace navigation must go through verified replay/resolution
operations, independent of that convenience overload.

The older design's statement that registers are a full file at any position is
too broad for what this inspection proves. The declaration is specifically a
context query on live threads, and register validity requires further evidence.
Likewise, using aggressive memory search to widen a certified time interval is
not justified by the package's query-policy contract.

## 4. Executed Windows ABI probe

Temporary source `/tmp/forensicator-native-prereqs/abi.cpp` included the actual
`IReplayEngine.h` and `IReplayEngineRegisters.h`, compiled x64 with MSVC C++20,
and asserted sizes/field offsets at compile time. It did not load a replay DLL
or open a trace. All source, object, executable, and batch files are under `/tmp`.

Observed successful exit (code 0):

```text
Position=16 align=8 Sequence=8 Steps=8 offset.Sequence=0 offset.Steps=8
RegisterContext=2672 ExtendedRegisterContext=8832 ThreadId=4 UniqueThreadId=4
MSVC=1951
```

| Probe artifact | SHA-256 |
|---|---|
| `abi.cpp` | `f867f79a01af1f61f1cf9785e8907a731b66a7fef619bc31add29d83c1441a88` |
| `abi.cmd` | `54eefb6e8f8474678d3c67ec573bd17b7299f0c7f5ae8564d61cd935ab3eb081` |
| `abi.exe` | `13e97c897c556bb47149bc5e0be73e33663abcb9dba0547494d0c570d9525f06` |

Re-run on this runner (requires the same interop permission and temporary files):

```sh
/mnt/c/WINDOWS/system32/cmd.exe /c '\\wsl.localhost\Ubuntu-NzSN\tmp\forensicator-native-prereqs\abi.cmd'
```

For a fresh runner, recover the pinned package and compile a translation unit with
`static_assert(sizeof(TTD::Replay::Position) == 16)`, both enum sizes equal to 8,
and `offsetof(Position, Sequence) == 0`, `offsetof(Position, Steps) == 8`.
Use that runner's actual Windows SDK/compiler and record their versions.

## 5. Discovered real input and DLL identities

These are byte identities, not a certificate that the binaries implement the
pinned 0.9.5 interfaces. Fixed file versions were read from the PE version
resource; no DLL was loaded by this task.

| Path under `/mnt/d/Repositories/TTFX` | Bytes | SHA-256 | Fixed file version |
|---|---:|---|---|
| `traces/hostname01.run` | 29,360,128 | `4b4b89813c6e9ae6207b66d7ada76556779c70ad67d0ce5e37da71adf33d71e7` | — |
| `target/release/ttd/TTDReplay.dll` | 1,169,208 | `71fa5c11a8c482661eb29311481ca6819cc43aecb27bf2194250f7679f03cf8f` | `1.11.610.0` |
| `target/release/ttd/TTDReplayCPU.dll` | 3,491,640 | `661cd1a882d157932c634b3807dd360e08997c0b0812e2585adb2628041e957e` | `1.11.610.0` |
| `target/release/dbgeng.dll` | 11,163,448 | `4352756685e7325288e54abb3281e768637987517be8575ec4450e4b4421842f` | not extracted |

No content from process memory or the trace was printed. The single historical
hostname trace does not supply the lifecycle/thread-reuse/exception boundary
fixture matrix specified by V1.

## 6. Concrete continuation tasks and unblock inputs

1. **Locate current external provider.** Supply the current Windows proxy checkout
   and binary path/revision (or identify the intended new external checkout).
   `/mnt/d/Repositories/TTFX` is an old eager extractor and is not a substitute.
   No Rust source/tooling has been added to Forensicator, and this task did not
   build the historical extractor.
2. **Recover existing Case pack.** Supply the directory containing the three dump
   groups, matching Electron executable/PDB, and existing goldens. Run
   `FORENSICATOR_CASE_DIR=<actual-pack> ./scripts/conformance-lean.sh` against the
   committed checkpoint in an isolated checkout before judging differences.
   Preserve references until each difference has been reviewed.
3. **Native API probe increment.** On the verified local Windows runner, use the
   actual package and compatible pinned replay DLLs to open a copy of a real trace.
   Keep any generated index/output beside the copy in a task directory. Record
   actual first/last points, normalized invalid requests, sequence and store/
   exception boundaries, global/per-thread positions, current/non-current and
   invalid/reused thread cases, context flags, and independently decoded TEB
   bounds. This remains a separate implementation/probe task.
4. **Exactness certification.** Compare conservative/thread-local/search-policy
   reads against independent positioned WinDbg and controlled store fixtures;
   include partial reads, unrecorded ranges and lifecycle changes. Certify only a
   proven domain. If strict exactness cannot be established, publish observations
   with their policy/confidence and leave `memory_exact` unsupported.
5. **Native access and lifecycle assessment.** Test callback identity/duplication,
   phases, progress/continuity, interruption, reserve/commit/free and protection
   changes. Public header names alone cannot certify complete mapping inventory,
   stable access IDs, or gap-free lifecycle coverage.
6. **Provider gate.** Once the actual proxy is available, use
   `FORENSICATOR_PROXY_EXE=<actual-local-exe>` and
   `FORENSICATOR_PROXY_RUN=/mnt/d/Repositories/TTFX/traces/hostname01.run` for the
   existing opt-in gate, after verifying that the fixture matches its historical
   constants. Run independent v2 comparisons in addition to that v1 fixture gate.

V0 status: **partially unblocked** by finding a real trace and Windows runner;
existing dump/golden pack and actual proxy remain missing.

R0 status: **package pin and native ABI complete; replay capability/semantics
certification pending**. This report intentionally does not close R0, R3, M1,
or V1 on the strength of header inspection or a layout-only executable.

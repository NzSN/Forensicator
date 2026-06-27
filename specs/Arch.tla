---- MODULE Arch ----
EXTENDS Integers, Sequences, FiniteSets

\* Arch seam — v1: x64 only. Register set shape, pointer width, decode_context.
\* x86 / ARM64 slot in by changing PtrWidth and the register count/layout.

PtrWidth  == 8                       \* x64: 8-byte pointers
RegCount  == 32                      \* total registers in x64 CONTEXT
GpBase    == 0                       \* rax..r15 occupy slots 0..15
PtrLimit  == 255                     \* max modeled address value

VARIABLES
    \* @type: Seq(Int);
    regs,                            \* register values, indexed by slot
    \* @type: Seq([desc: Str]);
    anomalies

\* Register name → slot index mapping (compile-time constant table)

\* ---- Invariants ----

RegCountInv     == Len(regs) <= RegCount
AnomaliesBounded == Len(anomalies) <= 4
RegsAllZeroStart == \A i \in 1..Len(regs): regs[i] = 0
                     \* at Init, all regs are zero (real CONTEXT has explicit values,
                     \* but we verify the structure holds for any content)

\* ---- Key property: pointer registers are in GpBase..GpBase+15 ----
IsPointerReg(i) == GpBase+1 <= i /\ i <= GpBase+16

\* Any GPR value could be a valid pointer into address space
GprCouldBePointer == \A i \in GpBase+1..GpBase+16:
                       i <= Len(regs) => regs[i] <= PtrLimit

ArchInvariant ==
    /\ RegCountInv
    /\ AnomaliesBounded
    /\ GprCouldBePointer

\* ---- Operations ----

\* decode_context: populate register file from raw bytes, or fail with anomaly
\* decode_context: populate register file from raw bytes, or fail with anomaly
DecodeContext ==
    /\ Len(regs) = 0
    /\ \/ /\ regs' = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
          /\ anomalies' = anomalies
       \/ /\ regs' = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
          /\ Len(anomalies) < 4
          /\ anomalies' = Append(anomalies, [desc |-> "truncated CONTEXT"])

Init ==
    /\ regs      = <<>>
    /\ anomalies = <<>>

Next == DecodeContext

Spec == Init /\ [][Next]_<<regs, anomalies>>

====

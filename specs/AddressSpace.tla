---- MODULE AddressSpace ----
EXTENDS Integers, Sequences, FiniteSets

\* Model-checking bounds (edit these for larger state spaces)
CONSTANT MaxAddr
MaxRegions   == 2
MaxAnomalies == 2

VARIABLES
    \* @type: Seq(Int);
    reg_va,
    \* @type: Seq(Int);
    reg_sz,
    \* @type: Seq(Str);
    reg_cl,
    \* @type: Seq([desc: Str]);
    anomalies

\* ---- Helpers ----

region_end(i) == reg_va[i] + reg_sz[i]

HasRegion(va) == \E i \in 1..MaxRegions: i <= Len(reg_va) /\ reg_va[i] <= va /\ va < region_end(i)

RegionIdx(va) ==
    IF HasRegion(va)
    THEN CHOOSE i \in 1..MaxRegions: i <= Len(reg_va) /\ reg_va[i] <= va /\ va < region_end(i)
    ELSE 0

classify(va) ==
    IF HasRegion(va)
    THEN reg_cl[RegionIdx(va)]
    ELSE "Other"

intervals_overlap(i, j) ==
    reg_va[i] < region_end(j) /\ reg_va[j] < region_end(i)

ReadOk(va, len) ==
    /\ HasRegion(va)
    /\ va + len <= region_end(RegionIdx(va))

\* ---- Invariants ----

NoZeroSized      == \A i \in 1..MaxRegions: i <= Len(reg_va) => reg_sz[i] > 0
NoOverflow        == \A i \in 1..MaxRegions: i <= Len(reg_va) => reg_va[i] + reg_sz[i] <= MaxAddr
BoundedCount      == Len(reg_va) <= MaxRegions
NoOverlap         == \A i \in 1..MaxRegions:
                       \A j \in 1..MaxRegions:
                         (i <= Len(reg_va) /\ j <= Len(reg_va) /\ i # j) => ~intervals_overlap(i, j)
BoundedAnomalies  == Len(anomalies) <= MaxAnomalies
LenMatch          == /\ Len(reg_sz) = Len(reg_va)
                    /\ Len(reg_cl) = Len(reg_va)

TypeInvariant ==
    /\ NoZeroSized
    /\ NoOverflow
    /\ BoundedCount
    /\ NoOverlap
    /\ BoundedAnomalies
    /\ LenMatch

ClassifyTotal ==
    \A va \in 0..MaxAddr:
        classify(va) \in {"Image","Stack","Mapped","Private","Other"}

\* ---- Operations ----

AddRegion(va_start, size, class) ==
    /\ Len(reg_va) < MaxRegions
    /\ size > 0
    /\ va_start + size <= MaxAddr
    /\ LET overlap == \E i \in 1..MaxRegions:
                        i <= Len(reg_va) /\ reg_va[i] < va_start + size /\ va_start < region_end(i)
       IN IF overlap
          THEN /\ Len(anomalies) < MaxAnomalies
               /\ UNCHANGED <<reg_va, reg_sz, reg_cl>>
               /\ anomalies' = Append(anomalies, [desc |-> "overlap"])
          ELSE /\ reg_va'   = Append(reg_va, va_start)
               /\ reg_sz'   = Append(reg_sz, size)
               /\ reg_cl'   = Append(reg_cl, class)
               /\ anomalies' = anomalies

Read(va, len) ==
    /\ IF ReadOk(va, len)
       THEN /\ UNCHANGED <<reg_va, reg_sz, reg_cl, anomalies>>
       ELSE /\ Len(anomalies) < MaxAnomalies
            /\ UNCHANGED <<reg_va, reg_sz, reg_cl>>
            /\ anomalies' = Append(anomalies, [desc |-> "read_beyond_region"])

Init ==
    /\ reg_va    = <<>>
    /\ reg_sz    = <<>>
    /\ reg_cl    = <<>>
    /\ anomalies = <<>>

Next ==
    \E va_start \in 0..MaxAddr:
      \E size \in 1..MaxAddr:
        \E class \in {"Image","Stack","Mapped","Private","Other"}:
          AddRegion(va_start, size, class)
    \/ \E va \in 0..MaxAddr, len \in 1..MaxAddr: Read(va, len)

Spec == Init /\ [][Next]_<<reg_va, reg_sz, reg_cl, anomalies>>

====

---- MODULE AddressSpaceMBT ----
EXTENDS AddressSpace

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends AddressSpace.tla to expose action names and parameters.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [va: Int, sz: Int, cls: Str, len: Int];
    parameters

SpaceActionNames ==
    { "Init", "AddRegion", "Read" }

\* View operator exposed to MirrorRust for state comparison.
View ==
    [ reg_va    |-> reg_va,
      reg_sz    |-> reg_sz,
      reg_cl    |-> reg_cl,
      anomalies |-> anomalies ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [va |-> 0, sz |-> 0, cls |-> "", len |-> 0]

MBTAddRegion ==
    \E va_start \in 0..MaxAddr:
      \E size \in 1..MaxAddr:
        \E class \in {"Image","Stack","Mapped","Private","Other"}:
          /\ AddRegion(va_start, size, class)
          /\ action_taken' = "AddRegion"
          /\ parameters' = [va |-> va_start, sz |-> size, cls |-> class, len |-> 0]

MBTRead ==
    \E va \in 0..MaxAddr, len \in 1..MaxAddr:
      /\ Read(va, len)
      /\ action_taken' = "Read"
      /\ parameters' = [va |-> va, sz |-> 0, cls |-> "", len |-> len]

MBTNext ==
    \/ MBTAddRegion
    \/ MBTRead

MBTSpec == MBTInit /\ [][MBTNext]_<<reg_va, reg_sz, reg_cl, anomalies, action_taken, parameters>>

TraceComplete == TRUE
====

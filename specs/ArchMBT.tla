---- MODULE ArchMBT ----
EXTENDS Arch

\* Action tracking for Model-Based Testing with MirrorRust.
\* Extends Arch.tla to expose action names and parameters.

VARIABLES
    \* @type: Str;
    action_taken,
    \* @type: [truncated: Int];
    parameters

ArchActionNames ==
    { "Init", "DecodeContextSuccess", "DecodeContextTruncated" }

\* View operator exposed to MirrorRust for state comparison.
View ==
    [ regs      |-> regs,
      anomalies |-> anomalies ]

MBTInit ==
    /\ Init
    /\ action_taken = "Init"
    /\ parameters = [truncated |-> 0]

MBTDecodeContextSuccess ==
    /\ DecodeContextSuccess
    /\ action_taken' = "DecodeContextSuccess"
    /\ parameters' = [truncated |-> 0]

MBTDecodeContextTruncated ==
    /\ DecodeContextTruncated
    /\ action_taken' = "DecodeContextTruncated"
    /\ parameters' = [truncated |-> 1]

MBTNext ==
    \/ MBTDecodeContextSuccess
    \/ MBTDecodeContextTruncated

MBTSpec == MBTInit /\ [][MBTNext]_<<regs, anomalies, action_taken, parameters>>

TraceComplete == TRUE
====

---- MODULE StackRecovery ----
EXTENDS Naturals, Sequences, FiniteSets

\* Bounded host stack enrichment, corresponding to Execution/Stack.lean.
\* This is separate from ExecutionState.ThreadStateAt: the base provider still
\* returns unavailable frames, while a host recovery retains a derived prefix.
\* It abstracts instruction/unwind decoding as an independently supplied return
\* relation over exact observed memory. Native correctness, artifact matching,
\* and authoritative root certification remain trusted adapter obligations.
\* Terminal kind and its point/thread/frame scope are checked independently of
\* the return relation; a null return address is never a terminal witness.
\*
\* Bounds: two sources/points/thread instances, three positive instruction and
\* stack-pointer cells, at most three retained frames, at most two read quanta.
\* A quantum abstracts a budgeted byte read; frame-pointer fallback needs two.
\* Return addresses include zero and out-of-bounds stack pointers to exercise
\* rejection. No x64 opcode coverage or mathematical unwind proof is claimed.

Scopes == [source : 1..2, point : 0..1, thread : 1..2]
FrameKeys == (1..3) \X (1..3)
Kinds == {"native", "leaf", "framePointer", "unsupported"}
TerminalKinds == {"none", "runtimeThreadRoot", "verifiedEntryBoundary"}

VARIABLES
    \* @type: [source: Int, point: Int, thread: Int];
    inputScope,
    \* @type: [source: Int, point: Int, thread: Int];
    contextScope,
    \* @type: [source: Int, point: Int, thread: Int];
    targetScope,
    \* @type: Bool;
    contextValid,
    \* @type: Bool;
    boundsKnown,
    \* @type: Int;
    frameLimit,
    \* @type: Int;
    byteLimit,
    \* @type: <<Int, Int>> -> <<Int, Int>>;
    returns,
    \* @type: <<Int, Int>> -> Str;
    kinds,
    \* @type: Set(<<Int, Int>>);
    readable,
    \* @type: Set(<<Int, Int>>);
    artifactVerified,
    \* @type: [source: Int, point: Int, thread: Int];
    terminalScope,
    \* @type: <<Int, Int>>;
    terminalFrame,
    \* @type: Str;
    terminalKind,
    \* @type: Bool;
    terminalValidated,
    \* @type: Str;
    phase,
    \* @type: <<Int, Int>>;
    frame,
    \* @type: Seq(<<Int, Int>>);
    frames,
    \* @type: Int;
    bytesRead,
    \* @type: Set(Str);
    dependencies,
    \* @type: Bool;
    usedFramePointer,
    \* @type: Str;
    reason,
    \* @type: Bool;
    terminalWitnessed,
    \* @type: Bool;
    complete,
    \* @type: Str;
    baseFrames,
    \* @type: Bool;
    published

inputs == <<inputScope, contextScope, contextValid, boundsKnown, frameLimit,
            byteLimit, returns, kinds, readable, artifactVerified, terminalScope,
            terminalFrame, terminalKind, terminalValidated>>
recovery == <<phase, frame, frames, bytesRead, dependencies, usedFramePointer,
              reason, terminalWitnessed, complete>>
stackVars == <<inputs, recovery, targetScope, baseFrames, published>>

StackInit ==
    /\ inputScope \in Scopes /\ contextScope \in Scopes /\ targetScope = inputScope
    /\ contextValid \in BOOLEAN /\ boundsKnown \in BOOLEAN
    /\ frameLimit \in 0..3 /\ byteLimit \in 0..2
    /\ returns \in [FrameKeys -> ((0..3) \X (0..4))]
    /\ kinds \in [FrameKeys -> Kinds]
    /\ readable \in SUBSET FrameKeys /\ artifactVerified \in SUBSET FrameKeys
    /\ terminalScope \in Scopes /\ terminalFrame \in FrameKeys
    /\ terminalKind \in TerminalKinds /\ terminalValidated \in BOOLEAN
    /\ phase = "idle" /\ frame = <<1, 1>> /\ frames = <<>>
    /\ bytesRead = 0 /\ dependencies = {} /\ usedFramePointer = FALSE
    /\ reason = "none" /\ terminalWitnessed = FALSE /\ complete = FALSE
    /\ baseFrames = "unavailable" /\ published = FALSE

Start ==
    /\ phase = "idle"
    /\ IF inputScope # contextScope
       THEN /\ phase' = "done" /\ reason' = "contextMismatch" /\ dependencies' = {}
       ELSE IF ~contextValid
            THEN /\ phase' = "done" /\ reason' = "missingContext"
                 /\ dependencies' = {"registers"}
            ELSE IF ~boundsKnown
                 THEN /\ phase' = "done" /\ reason' = "missingStackBounds"
                      /\ dependencies' = {"bounds"}
                 ELSE /\ phase' = "inspect" /\ reason' = "none" /\ dependencies' = {}
    /\ UNCHANGED <<inputs, frame, frames, bytesRead, usedFramePointer,
                   terminalWitnessed, complete, targetScope, baseFrames, published>>

\* Inspect appends a validated current frame before trying to advance it.
Inspect ==
    /\ phase = "inspect"
    /\ IF Len(frames) = frameLimit
       THEN /\ phase' = "done" /\ reason' = "frameBudget" /\ UNCHANGED frames
       ELSE IF \E i \in 1..3 : i <= Len(frames) /\ frame = frames[i]
            THEN /\ phase' = "done" /\ reason' = "cycle" /\ UNCHANGED frames
            ELSE /\ phase' = "advance" /\ reason' = "none"
                 /\ frames' = Append(frames, frame)
    /\ UNCHANGED <<inputs, frame, bytesRead, dependencies, usedFramePointer,
                   terminalWitnessed, complete, targetScope, baseFrames, published>>

MatchingTerminal ==
    /\ terminalValidated /\ terminalKind # "none"
    /\ terminalScope = inputScope /\ terminalFrame = frame

ReachRoot ==
    /\ phase = "advance" /\ MatchingTerminal
    /\ phase' = "done" /\ reason' = "validatedRoot" /\ terminalWitnessed' = TRUE
    /\ complete' = (dependencies = {} /\ ~usedFramePointer)
    /\ UNCHANGED <<inputs, frame, frames, bytesRead, dependencies, usedFramePointer,
                   targetScope, baseFrames, published>>

\* Stop paths preserve the prefix. Missing inputs record actionable dependencies;
\* budget/invalid/unsupported outcomes do not fabricate additional observations.
Advance ==
    /\ phase = "advance" /\ ~MatchingTerminal
    /\ LET kind == kinds[frame]
           cost == IF kind = "framePointer" THEN 2 ELSE 1
           next == returns[frame]
       IN IF kind = "unsupported"
          THEN /\ phase' = "done" /\ reason' = "unsupportedUnwind"
               /\ UNCHANGED <<frame, bytesRead, dependencies, usedFramePointer>>
          ELSE IF kind \in {"native", "leaf"} /\ frame \notin artifactVerified
               THEN /\ phase' = "done" /\ reason' = "missingArtifact"
                    /\ dependencies' = dependencies \cup {"artifact"}
                    /\ UNCHANGED <<frame, bytesRead, usedFramePointer>>
               ELSE IF bytesRead + cost > byteLimit
                    THEN /\ phase' = "done" /\ reason' = "byteBudget"
                         /\ UNCHANGED <<frame, bytesRead, dependencies, usedFramePointer>>
                    ELSE IF frame \notin readable
                         THEN /\ phase' = "done" /\ reason' = "missingMemory"
                              /\ dependencies' = dependencies \cup {"memory"}
                              /\ UNCHANGED <<frame, bytesRead, usedFramePointer>>
                         ELSE /\ bytesRead' = bytesRead + cost
                              /\ usedFramePointer' = (usedFramePointer \/ kind = "framePointer")
                              /\ dependencies' = IF kind = "framePointer"
                                                 THEN dependencies \cup {"artifact"}
                                                 ELSE dependencies
                              /\ IF next[1] = 0
                                 THEN /\ phase' = "done" /\ reason' = "invalidReturnAddress"
                                      /\ UNCHANGED frame
                                 ELSE IF next[2] <= frame[2] \/ next[2] > 3
                                      THEN /\ phase' = "done" /\ reason' = "invalidStackTransition"
                                           /\ UNCHANGED frame
                                      ELSE /\ phase' = "inspect" /\ reason' = "none"
                                           /\ frame' = next
    /\ UNCHANGED <<inputs, frames, terminalWitnessed, complete,
                   targetScope, baseFrames, published>>

\* Derived retention is explicit and scoped; it does not update provider facts.
PublishDerived ==
    /\ phase = "done" /\ targetScope = inputScope
    /\ published' = TRUE
    /\ UNCHANGED <<inputs, recovery, targetScope, baseFrames>>

RebindView ==
    /\ phase = "done" /\ targetScope' \in Scopes /\ published' = FALSE
    /\ UNCHANGED <<inputs, recovery, baseFrames>>

StackNext == Start \/ Inspect \/ ReachRoot \/ Advance \/ PublishDerived \/ RebindView

BudgetsHold == /\ Len(frames) <= frameLimit /\ bytesRead <= byteLimit
FramePrefix ==
    /\ \A i \in 1..3 : i <= Len(frames) => frames[i] \in FrameKeys
    /\ \A i \in 2..3 : i <= Len(frames) => frames[i - 1][2] < frames[i][2]

CompleteHasRoot ==
    complete =>
      /\ phase = "done" /\ reason = "validatedRoot" /\ terminalWitnessed
      /\ terminalValidated /\ terminalKind \in {"runtimeThreadRoot", "verifiedEntryBoundary"}
      /\ terminalScope.source = inputScope.source
      /\ terminalScope.point = inputScope.point /\ terminalScope.thread = inputScope.thread
      /\ terminalFrame = frame /\ Len(frames) > 0
      /\ frames[Len(frames)] = terminalFrame
      /\ dependencies = {} /\ ~usedFramePointer

InputsScoped ==
    Len(frames) > 0 => inputScope = contextScope /\ contextValid /\ boundsKnown
HostEnrichmentOnly == baseFrames = "unavailable"
PublishedScope == published => phase = "done" /\ targetScope = inputScope
PartialStops == (phase = "done" /\ reason # "validatedRoot") => ~complete

StackInvariant ==
    /\ BudgetsHold /\ FramePrefix /\ CompleteHasRoot /\ InputsScoped
    /\ HostEnrichmentOnly /\ PublishedScope /\ PartialStops

StackSpec == StackInit /\ [][StackNext]_stackVars
=============================================================================

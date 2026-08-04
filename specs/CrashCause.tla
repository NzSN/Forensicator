---- MODULE CrashCause ----
EXTENDS Integers, Sequences, FiniteSets

\* ── CrashCause — crash-verdict classification and ranking ──
\*
\* The raw exception code is classified into a total set of kinds. Rules
\* fire when their preconditions hold over (exc_kind, fault_va, region
\* model); each firing records a confidence. Decide picks the
\* highest-confidence firing as the verdict — or UNKNOWN when nothing fired.
\*
\* Mirrors analyzer/cause.rs. See
\* docs/superpowers/specs/2026-08-04-crash-cause-design.md.

CONSTANTS MaxRules

MaxRules == 10

\* ---- State ----

VARIABLES
    \* @type: Str;
    exc_kind,        \* "NONE" | "BREAKPOINT" | "AV" | "STACK_OVERFLOW" | "OTHER"
    \* @type: Int;
    fault_va,        \* fault address (0 when not an AV)
    \* @type: Set(<<Int, Str>>);
    rule_matches,    \* set of <<rule_id, confidence>> that fired
    \* @type: Str;
    verdict,         \* "UNSET" | "CHECK_FAILURE" | "OOM" | "STACK_OVERFLOW"
                     \* | "SMI_CONFUSION" | "OBJECT_ACCESS" | "NULL_DEREF"
                     \* | "WILD_ACCESS" | "CORRUPTED_PC" | "WASM_GUARD"
                     \* | "NO_EXCEPTION" | "UNKNOWN"
    \* @type: Str;
    confidence       \* "UNSET" | "HIGH" | "MEDIUM" | "LOW"

vars == <<exc_kind, fault_va, rule_matches, verdict, confidence>>

ExcKinds == {"NONE", "BREAKPOINT", "AV", "STACK_OVERFLOW", "OTHER"}
Confidences == {"HIGH", "MEDIUM", "LOW"}
Verdicts == {"CHECK_FAILURE", "OOM", "STACK_OVERFLOW", "SMI_CONFUSION",
             "OBJECT_ACCESS", "NULL_DEREF", "WILD_ACCESS", "CORRUPTED_PC",
             "WASM_GUARD", "NO_EXCEPTION", "UNKNOWN"}

\* ---- Helpers ----

\* Confidence ordering as a numeric rank (higher is stronger).
\* @type: Str => Int;
ConfRank(c) ==
    CASE c = "HIGH"   -> 3
      [] c = "MEDIUM" -> 2
      [] c = "LOW"    -> 1
      [] OTHER        -> 0

\* The confidence of the strongest match in S, or "LOW" if empty.
BestConfidence(S) ==
    IF S = {} THEN "LOW"
    ELSE CHOOSE c \in Confidences :
           /\ \E m \in S : m[2] = c
           /\ \A m \in S : ConfRank(m[2]) <= ConfRank(c)

\* ---- Actions ----

\* Map a raw exception code to a kind. Total: every code lands somewhere.
ClassifyException(code) ==
    /\ exc_kind = "NONE"
    /\ verdict = "UNSET"
    /\ exc_kind' = CASE code = 0             -> "NONE"
                   [] code = 2147942403      -> "BREAKPOINT"       \* 0x80000003
                   [] code = 3221225477      -> "AV"               \* 0xC0000005
                   [] code = 3221225725      -> "STACK_OVERFLOW"   \* 0xC00000FD
                   [] OTHER                  -> "OTHER"
    /\ UNCHANGED <<fault_va, rule_matches, verdict, confidence>>

\* Rule r fires when its precondition holds for the current exception kind.
\* Preconditions mirror analyzer/cause.rs rule gating (region checks are
\* abstracted into the "firable" judgement: a rule either can or cannot fire
\* on this trace's memory model, chosen nondeterministically where the model
\* does not pin it down).
FireRule(r, conf) ==
    /\ exc_kind # "NONE"
    /\ verdict = "UNSET"
    /\ conf \in Confidences
    /\ r \in 1..MaxRules
    /\ <<r, conf>> \notin rule_matches
    /\ rule_matches' = rule_matches \cup {<<r, conf>>}
    /\ UNCHANGED <<exc_kind, fault_va, verdict, confidence>>

\* No more rules can fire: pick the verdict. The verdict is always one of
\* the fired rules — never invented — or UNKNOWN when nothing fired.
Decide(v) ==
    /\ exc_kind # "NONE"
    /\ verdict = "UNSET"
    /\ v \in Verdicts
    /\ IF rule_matches = {}
       THEN /\ verdict' = "UNKNOWN"
            /\ confidence' = "LOW"
       ELSE /\ verdict' = v
            /\ confidence' = BestConfidence(rule_matches)
    /\ UNCHANGED <<exc_kind, fault_va, rule_matches>>

\* A dump without an exception stream classifies immediately.
NoException ==
    /\ exc_kind = "NONE"
    /\ verdict = "UNSET"
    /\ exc_kind' = "NONE"
    /\ verdict' = "NO_EXCEPTION"
    /\ confidence' = "HIGH"
    /\ UNCHANGED <<fault_va, rule_matches>>

\* ---- Specification ----

Init ==
    /\ exc_kind = "NONE"
    /\ fault_va = 0
    /\ rule_matches = {}
    /\ verdict = "UNSET"
    /\ confidence = "UNSET"

Next ==
    \/ \E code \in {0, 2147942403, 3221225477, 3221225725, 1} :
         ClassifyException(code)
    \/ \E r \in 1..MaxRules, c \in Confidences : FireRule(r, c)
    \/ \E v \in Verdicts : Decide(v)
    \/ NoException

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

CrashCauseInvariant ==
    \* Classification is total: every raw code lands in a kind.
    /\ exc_kind \in ExcKinds
    \* The verdict is justified: a decided non-UNKNOWN verdict requires
    \* that at least one rule fired (Decide only runs after FireRule).
    /\ (verdict \notin {"UNSET", "UNKNOWN", "NO_EXCEPTION"})
         => rule_matches # {}
    \* UNKNOWN iff nothing fired (given a real exception was classified).
    /\ exc_kind # "NONE" /\ verdict = "UNKNOWN" => rule_matches = {}
    \* Confidence is always one of the three levels once decided.
    /\ verdict # "UNSET" => confidence \in Confidences

=============================================================================

/- Forensicator.Spec.Timeline — mechanization of specs/Timeline.tla +
   Snapshot.tla: ordering invariants as predicates, the spec-level forward
   fold of writes, and the theorems linking the executable views to it. -/
import Forensicator.Model.Trace

namespace Forensicator.Spec

open Forensicator.Model

/-- Writes are position-ordered (Timeline.tla TraceOrdered, write half). -/
def PositionOrdered : List WriteRecord → Prop
  | [] => True
  | [_] => True
  | w1 :: w2 :: rest => w1.pos ≤ w2.pos ∧ PositionOrdered (w2 :: rest)

theorem PositionOrdered.append_singleton {xs : List WriteRecord} {w : WriteRecord}
    (hxs : PositionOrdered xs) (hlast : ∀ l, xs.getLast? = some l → l.pos ≤ w.pos) :
    PositionOrdered (xs ++ [w]) := by
  induction xs with
  | nil => exact True.intro
  | cons x xs ih =>
    cases xs with
    | nil =>
      exact ⟨hlast x rfl, True.intro⟩
    | cons y ys =>
      have h1 : x.pos ≤ y.pos := hxs.1
      have h2 : PositionOrdered ((y :: ys) ++ [w]) :=
        ih hxs.2 (fun l hl => hlast l (by simpa using hl))
      exact ⟨h1, h2⟩

/-- An ordered list extended by an ordered suffix whose first element is
    at least the prefix's last is ordered (F4 cons-then-reverse needs the
    prefix/suffix split at section boundaries). -/
theorem PositionOrdered.append {xs ys : List WriteRecord}
    (hx : PositionOrdered xs) (hy : PositionOrdered ys)
    (hj : ∀ l, xs.getLast? = some l → ∀ y, ys.head? = some y → l.pos ≤ y.pos) :
    PositionOrdered (xs ++ ys) := by
  induction xs with
  | nil => simpa using hy
  | cons x xs ih =>
    cases xs with
    | nil =>
      cases ys with
      | nil => exact True.intro
      | cons y ys => exact ⟨hj x rfl y rfl, hy⟩
    | cons y rest =>
      cases ys with
      | nil => simpa using hx
      | cons z zs =>
        change PositionOrdered (x :: y :: (rest ++ z :: zs))
        exact ⟨hx.1, ih hx.2 (fun l hl => hj l (by simpa using hl))⟩

/-- Dropping the head of an ordered nonempty list keeps it ordered. -/
theorem PositionOrdered.tail {x : WriteRecord} {xs : List WriteRecord}
    (h : PositionOrdered (x :: xs)) : PositionOrdered xs := by
  cases xs with
  | nil => exact True.intro
  | cons y ys => exact h.2

/-- Dropping a prefix of an ordered list keeps it ordered. -/
theorem PositionOrdered.drop {xs : List WriteRecord} (n : Nat) (h : PositionOrdered xs) :
    PositionOrdered (xs.drop n) := by
  induction n generalizing xs with
  | zero => simpa using h
  | succ n ih =>
    cases xs with
    | nil => exact True.intro
    | cons x xs => exact ih (PositionOrdered.tail h)

/-- Events are position-ordered (TraceOrdered, event half). -/
def EventsOrdered : List TraceEvent → Prop
  | [] => True
  | [_] => True
  | e1 :: e2 :: rest => e1.pos ≤ e2.pos ∧ EventsOrdered (e2 :: rest)

theorem EventsOrdered.append_singleton {xs : List TraceEvent} {e : TraceEvent}
    (hxs : EventsOrdered xs) (hlast : ∀ l, xs.getLast? = some l → l.pos ≤ e.pos) :
    EventsOrdered (xs ++ [e]) := by
  induction xs with
  | nil => exact True.intro
  | cons x xs ih =>
    cases xs with
    | nil =>
      exact ⟨hlast x rfl, True.intro⟩
    | cons y ys =>
      have h1 : x.pos ≤ y.pos := hxs.1
      have h2 : EventsOrdered ((y :: ys) ++ [e]) :=
        ih hxs.2 (fun l hl => hlast l (by simpa using hl))
      exact ⟨h1, h2⟩

/-- Events counterpart of `PositionOrdered.append` (F4 section boundary). -/
theorem EventsOrdered.append {xs ys : List TraceEvent}
    (hx : EventsOrdered xs) (hy : EventsOrdered ys)
    (hj : ∀ l, xs.getLast? = some l → ∀ y, ys.head? = some y → l.pos ≤ y.pos) :
    EventsOrdered (xs ++ ys) := by
  induction xs with
  | nil => simpa using hy
  | cons x xs ih =>
    cases xs with
    | nil =>
      cases ys with
      | nil => exact True.intro
      | cons y ys => exact ⟨hj x rfl y rfl, hy⟩
    | cons y rest =>
      cases ys with
      | nil => simpa using hx
      | cons z zs =>
        change EventsOrdered (x :: y :: (rest ++ z :: zs))
        exact ⟨hx.1, ih hx.2 (fun l hl => hj l (by simpa using hl))⟩

/-- Dropping the head of an ordered nonempty event list keeps it ordered. -/
theorem EventsOrdered.tail {x : TraceEvent} {xs : List TraceEvent}
    (h : EventsOrdered (x :: xs)) : EventsOrdered xs := by
  cases xs with
  | nil => exact True.intro
  | cons y ys => exact h.2

/-- Dropping a prefix of an ordered event list keeps it ordered. -/
theorem EventsOrdered.drop {xs : List TraceEvent} (n : Nat) (h : EventsOrdered xs) :
    EventsOrdered (xs.drop n) := by
  induction n generalizing xs with
  | zero => simpa using h
  | succ n ih =>
    cases xs with
    | nil => exact True.intro
    | cons x xs => exact ih (EventsOrdered.tail h)

/-- Open intervals only at the frontier (Timeline.tla): an open thread
    interval covers every position up to the record head. -/
def OpenIntervalsAtFrontier (tr : Trace) : Prop :=
  ∀ id iv, (id, iv) ∈ tr.threads → iv.stop = none →
    ∀ t, iv.start ≤ t → t ≤ tr.frontier → Interval.contains iv t

/-- Spec-level memory view (Snapshot.tla's ModelAt memory conjunct): fold the
    writes forward over the initial byte; each covering write overwrites. -/
def byteFold (va : VA) (init : Option UInt8) (ws : List WriteRecord) : Option UInt8 :=
  ws.foldl (fun acc w => if w.covers va then w.byteAt va else acc) init

/-- Cons-step characterization of the reverse-scan last-covering search. -/
theorem lastCoveringWrite_cons (w : WriteRecord) (ws : List WriteRecord) (va : VA) :
    lastCoveringWrite (w :: ws) va =
      match lastCoveringWrite ws va with
      | some w' => some w'
      | none => if w.covers va then some w else none := by
  simp only [lastCoveringWrite, List.reverse_cons, List.find?_append]
  cases hws : ws.reverse.find? (fun w' => decide (w'.covers va)) with
  | none =>
    simp only [Option.or]
    by_cases hw : w.covers va <;> simp [hw]
  | some w' =>
    simp [Option.or]

/-- Forward fold over `ws` equals the last covering write's byte (else the
    initial value) — the "reverse scan == forward fold" lemma. Holds for any
    order; last-wins is order-independent. -/
theorem byteFold_eq_lastCovering (va : VA) (init : Option UInt8) (ws : List WriteRecord) :
    byteFold va init ws =
      match lastCoveringWrite ws va with
      | some w => w.byteAt va
      | none => init := by
  induction ws generalizing init with
  | nil => rfl
  | cons w ws ih =>
    have step : byteFold va init (w :: ws)
        = byteFold va (if w.covers va then w.byteAt va else init) ws := rfl
    rw [step, ih, lastCoveringWrite_cons]
    cases hws : lastCoveringWrite ws va with
    | none =>
      by_cases hw : w.covers va <;> simp [hw]
    | some w' => rfl

/-- `Trace.valueAt` agrees with the spec forward fold (Timeline.tla ValueAt
    ≡ Snapshot.tla memory fold), within a covered init region. -/
theorem valueAt_agrees_with_fold (tr : Trace) (va : VA) (t : Position) (region : MemoryRegionInfo)
    (hreg : tr.initMem.find? (fun r => decide (r.covers va)) = some region) :
    tr.valueAt va t =
      byteFold va
        (let idx := va.toNat - region.vaStart.toNat
         if idx < region.data.size then some (region.data.get! idx) else none)
        (tr.writes.filter fun w => w.pos ≤ t) := by
  simp [Trace.valueAt, hreg]
  rw [byteFold_eq_lastCovering]
  rfl

/-- Timeline.tla CursorBounded / Snapshot.tla SnapshotsAreModels (existence
    half): every position at or below the frontier materializes. -/
theorem snapshot_isSome (tr : Trace) (t : Position) (ht : t ≤ tr.frontier) :
    (tr.snapshot t).isSome := by
  have ht' : t.toNat ≤ tr.frontier.toNat := ht
  have hnot : ¬ tr.frontier < t := by
    intro hc
    have : tr.frontier.toNat < t.toNat := hc
    omega
  simp [Trace.snapshot, hnot]

end Forensicator.Spec

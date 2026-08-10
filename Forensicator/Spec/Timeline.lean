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

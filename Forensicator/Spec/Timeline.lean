/- Timeline and execution-state contracts: log ordering, byte-fold agreement,
   bounded source-scoped points, and exact/interval event query laws.
   The historical Snapshot.tla Dump projection is no longer a shipping view. -/
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

/-- Spec-level memory view: fold writes forward over the initial byte;
    each covering write overwrites, and unavailable payload makes it unknown. -/
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
    list order; the two traversal algorithms agree on the same last writer. -/
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

/-- `Trace.valueAt` agrees with the spec forward fold (Timeline.tla ValueAt),
    within a covered initial region. This is not a completeness assertion. -/
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

/-- Every position within the recorded domain has an execution view. This
    proves existence only, not complete byte, mapping or stack knowledge. -/
theorem pointAt_isSome (tr : Trace) (t : Position) (source : String)
    (ht : t ≤ tr.frontier) : (tr.pointAt t source).isSome := by
  have hnot : ¬ tr.frontier < t := UInt64.not_lt.mpr ht
  simp [Trace.pointAt, hnot]

theorem pointAt_isNone_of_past_frontier (tr : Trace) (t : Position) (source : String)
    (ht : tr.frontier < t) : tr.pointAt t source = none := by
  simp [Trace.pointAt, ht]

/-- A successful point retains its source and exact trace coordinate. -/
theorem pointAt_identity (tr : Trace) (t : Position) (source : String) (point : ExecutionPoint)
    (hp : tr.pointAt t source = some point) :
    point.id = { source, position := .trace t } := by
  unfold Trace.pointAt at hp
  split at hp
  · contradiction
  · cases Option.some.inj hp
    rfl

/-- Event membership means exact position equality, never accumulated history. -/
theorem eventsAt_mem (tr : Trace) (t : Position) (e : TraceEvent) :
    e ∈ tr.eventsAt t ↔ e ∈ tr.events ∧ e.pos = t := by
  simp [Trace.eventsAt]

/-- The payload list at a point is exactly the projection of events at its
    coordinate. Exception history is not copied into later points. -/
theorem pointAt_events (tr : Trace) (t : Position) (source : String) (point : ExecutionPoint)
    (hp : tr.pointAt t source = some point) :
    point.events = (tr.eventsAt t).map (·.toExecutionEvent) := by
  unfold Trace.pointAt at hp
  split at hp
  · contradiction
  · cases Option.some.inj hp
    rfl

theorem validateBounds_ok (tr : Trace) (a b : Position)
    (hab : a ≤ b) (hbf : b ≤ tr.frontier) : tr.validateBounds a b = .ok () := by
  have hba : ¬ b < a := UInt64.not_lt.mpr hab
  have hfb : ¬ tr.frontier < b := UInt64.not_lt.mpr hbf
  simp [Trace.validateBounds, hba, hfb]

/-- A valid range query preserves recorded order through a filter. -/
theorem eventsBetween_eq_filter (tr : Trace) (a b : Position)
    (hab : a ≤ b) (hbf : b ≤ tr.frontier) :
    tr.eventsBetween a b = .ok (tr.events.filter fun e => decide (a < e.pos ∧ e.pos ≤ b)) := by
  simp [Trace.eventsBetween, validateBounds_ok tr a b hab hbf]

/-- The left endpoint is exclusive and the right endpoint inclusive. -/
theorem eventsBetween_mem (tr : Trace) (a b : Position) (events : List TraceEvent)
    (hq : tr.eventsBetween a b = .ok events) (e : TraceEvent) :
    e ∈ events ↔ e ∈ tr.events ∧ a < e.pos ∧ e.pos ≤ b := by
  unfold Trace.eventsBetween at hq
  cases hv : tr.validateBounds a b with
  | error err => simp [hv] at hq
  | ok u =>
    cases u
    simp [hv] at hq
    subst events
    simp

/-- Equal endpoints are a valid empty history. -/
theorem eventsBetween_same (tr : Trace) (t : Position) (ht : t ≤ tr.frontier) :
    tr.eventsBetween t t = .ok [] := by
  rw [eventsBetween_eq_filter tr t t UInt64.le_rfl ht]
  congr 1
  apply List.filter_eq_nil_iff.mpr
  intro e _
  simp only [decide_eq_true_eq, UInt64.lt_iff_toNat_lt, UInt64.le_iff_toNat_le]
  omega

/-- Splitting an interval partitions membership, including events that share
    its split coordinate. They belong exclusively to the earlier interval. -/
theorem eventsBetween_partition (tr : Trace) (a b c : Position)
    (whole left right : List TraceEvent)
    (hab : a ≤ b) (hbc : b ≤ c)
    (hw : tr.eventsBetween a c = .ok whole)
    (hl : tr.eventsBetween a b = .ok left)
    (hr : tr.eventsBetween b c = .ok right) (e : TraceEvent) :
    e ∈ whole ↔ e ∈ left ∨ e ∈ right := by
  rw [eventsBetween_mem tr a c whole hw e, eventsBetween_mem tr a b left hl e,
      eventsBetween_mem tr b c right hr e]
  constructor
  · intro ⟨he, ha, hc⟩
    by_cases hb : e.pos ≤ b
    · exact Or.inl ⟨he, ha, hb⟩
    · exact Or.inr ⟨he, UInt64.not_le.mp hb, hc⟩
  · intro he
    rcases he with ⟨he, ha, hb⟩ | ⟨he, hb, hc⟩
    · exact ⟨he, ha, UInt64.le_trans hb hbc⟩
    · have hae : a < e.pos := by
        change a.toNat < e.pos.toNat
        change a.toNat ≤ b.toNat at hab
        change b.toNat < e.pos.toNat at hb
        omega
      exact ⟨he, hae, hc⟩

theorem eventsBetween_partition_disjoint (tr : Trace) (a b c : Position)
    (left right : List TraceEvent)
    (hl : tr.eventsBetween a b = .ok left)
    (hr : tr.eventsBetween b c = .ok right) (e : TraceEvent) :
    ¬ (e ∈ left ∧ e ∈ right) := by
  rw [eventsBetween_mem tr a b left hl e, eventsBetween_mem tr b c right hr e]
  intro ⟨⟨_, _, hle⟩, ⟨_, hlt, _⟩⟩
  exact (UInt64.not_lt.mpr hle) hlt

end Forensicator.Spec

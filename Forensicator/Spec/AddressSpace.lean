/- Forensicator.Spec.AddressSpace — mechanization of specs/AddressSpace.tla.

   The executable container (sorted, non-overlapping regions) and its
   invariants live here together: the theorems are *about* the shipping
   operations, replacing the bounded Apalache checks + mbt_address_space.rs.

   Regions are a sorted `List` (region counts are hundreds, not millions);
   bulk bytes stay in `ByteArray`. Address arithmetic is lifted to `Nat` so
   the Rust version's potential u64 wrap in `va_start + size` is
   unrepresentable. -/
import Forensicator.Model.Types

namespace Forensicator.Spec

/-- A memory region with its raw bytes (space.rs:7). -/
structure AddressRegion where
  vaStart : VA
  size : UInt64
  data : ByteArray := ByteArray.empty
  protection : UInt32 := 0
  state : MemState := .Commit
  classification : RegionClass := .Private
  deriving Inhabited

namespace AddressRegion

/-- End address as a `Nat` (no wraparound). -/
def endNat (r : AddressRegion) : Nat := r.vaStart.toNat + r.size.toNat

/-- `va ∈ [vaStart, vaStart + size)`. -/
def covers (r : AddressRegion) (va : VA) : Prop :=
  r.vaStart.toNat ≤ va.toNat ∧ va.toNat < r.endNat

instance coversDecidable (r : AddressRegion) (va : VA) : Decidable (r.covers va) :=
  inferInstanceAs (Decidable (_ ∧ _))

/-- Strict interval overlap (space.rs:119, both bounds strict). -/
def Overlaps (a b : AddressRegion) : Prop :=
  a.vaStart.toNat < b.endNat ∧ b.vaStart.toNat < a.endNat

instance overlapsDecidable (a b : AddressRegion) : Decidable (Overlaps a b) :=
  inferInstanceAs (Decidable (_ ∧ _))

theorem endNat_gt_start (r : AddressRegion) (h : r.size ≠ 0) :
    r.vaStart.toNat < r.endNat := by
  have hs : r.size.toNat ≠ 0 := fun hc => h (UInt64.toNat_inj.1 hc)
  simp only [endNat]; omega

theorem start_le_endNat (r : AddressRegion) : r.vaStart.toNat ≤ r.endNat := by
  simp only [endNat]; omega

theorem overlaps_symm {a b : AddressRegion} : Overlaps a b → Overlaps b a :=
  fun ⟨h1, h2⟩ => ⟨h2, h1⟩

theorem not_overlaps_of_le {a b : AddressRegion}
    (h : a.endNat ≤ b.vaStart.toNat) : ¬ Overlaps a b := by
  intro hov; simp only [Overlaps, endNat] at *; omega

/-- Two regions covering the same VA overlap. -/
theorem overlaps_of_covers_covers {a b : AddressRegion} {va : VA}
    (ha : a.covers va) (hb : b.covers va) : Overlaps a b := by
  obtain ⟨ha1, ha2⟩ := ha
  obtain ⟨hb1, hb2⟩ := hb
  simp only [Overlaps, endNat] at *
  exact ⟨by omega, by omega⟩

/-- If `a` starts no later than `b` and they don't overlap, `a` ends by `b`'s
    start (both nonzero-sized). -/
theorem le_of_not_overlaps {a b : AddressRegion} (ha : a.size ≠ 0) (hb : b.size ≠ 0)
    (hle : a.vaStart.toNat ≤ b.vaStart.toNat) (hno : ¬ Overlaps a b) :
    a.endNat ≤ b.vaStart.toNat := by
  have ea := a.endNat_gt_start ha
  have eb := b.endNat_gt_start hb
  simp only [Overlaps, endNat] at *
  by_cases h2 : b.vaStart.toNat < a.vaStart.toNat + a.size.toNat
  · have h1 : ¬ a.vaStart.toNat < b.vaStart.toNat + b.size.toNat := fun hh => hno ⟨hh, h2⟩
    omega
  · omega

end AddressRegion

/-- The spec invariant, head-clears-tail form: every region has nonzero size
    and ends at or before the start of *every* later region. Implies
    sortedness and pairwise non-overlap (`pairwise_nonoverlap`). -/
def WellFormed : List AddressRegion → Prop
  | [] => True
  | r :: rest =>
      r.size ≠ 0
      ∧ (∀ b ∈ rest, r.endNat ≤ b.vaStart.toNat)
      ∧ WellFormed rest

open AddressRegion in
theorem WellFormed.pairwise_nonoverlap {rs : List AddressRegion} (wf : WellFormed rs)
    {a b : AddressRegion} (ha : a ∈ rs) (hb : b ∈ rs) (hne : a ≠ b) :
    ¬ Overlaps a b := by
  induction rs with
  | nil => cases ha
  | cons x xs ih =>
    obtain ⟨_, hxclear, wfxs⟩ := wf
    rcases List.mem_cons.1 ha with hax | haxs
    · rcases List.mem_cons.1 hb with hbx | hbxs
      · exact absurd (hax.trans hbx.symm) hne
      · subst hax
        exact not_overlaps_of_le (hxclear b hbxs)
    · rcases List.mem_cons.1 hb with hbx | hbxs
      · subst hbx
        exact fun hov => not_overlaps_of_le (hxclear a haxs) (overlaps_symm hov)
      · exact ih wfxs haxs hbxs

/-- Insert keeping `vaStart` order (space.rs:130-134 binary-search insert). -/
def insertByStart (r : AddressRegion) : List AddressRegion → List AddressRegion
  | [] => [r]
  | x :: xs => if r.vaStart ≤ x.vaStart then r :: x :: xs else x :: insertByStart r xs

theorem insertByStart_cons (r x : AddressRegion) (xs : List AddressRegion) :
    insertByStart r (x :: xs)
      = if r.vaStart ≤ x.vaStart then r :: x :: xs else x :: insertByStart r xs := rfl

theorem mem_insertByStart {r b : AddressRegion} {xs : List AddressRegion}
    (h : b ∈ insertByStart r xs) : b = r ∨ b ∈ xs := by
  induction xs with
  | nil =>
    simp [insertByStart] at h
    exact .inl h
  | cons x xs ih =>
    rw [insertByStart_cons] at h
    by_cases hle : r.vaStart ≤ x.vaStart
    · simp [hle] at h
      rcases h with h | h | h
      · exact .inl h
      · exact .inr (List.mem_cons.2 (.inl h))
      · exact .inr (List.mem_cons.2 (.inr h))
    · simp [hle] at h
      rcases h with h | h
      · exact .inr (List.mem_cons.2 (.inl h))
      · rcases ih h with h | h
        · exact .inl h
        · exact .inr (List.mem_cons.2 (.inr h))

open AddressRegion in
theorem wellFormed_insert {r : AddressRegion} {xs : List AddressRegion}
    (wf : WellFormed xs) (hrsz : r.size ≠ 0)
    (hno : ∀ x ∈ xs, ¬ Overlaps r x) : WellFormed (insertByStart r xs) := by
  induction xs with
  | nil =>
    show WellFormed [r]
    exact ⟨hrsz, fun b hb => absurd hb (by simp), True.intro⟩
  | cons x xs ih =>
    obtain ⟨hxsz, hxclear, wfxs⟩ := wf
    rw [insertByStart_cons]
    by_cases hle : r.vaStart ≤ x.vaStart
    · simp only [hle, if_true]
      have hle' : r.vaStart.toNat ≤ x.vaStart.toNat := hle
      have hrx : r.endNat ≤ x.vaStart.toNat :=
        le_of_not_overlaps hrsz hxsz hle' (hno x ((List.mem_cons_self)))
      refine ⟨hrsz, fun b hb => ?_, ⟨hxsz, hxclear, wfxs⟩⟩
      rcases List.mem_cons.1 hb with hbx | hbxs
      · subst hbx; exact hrx
      · have hxb := hxclear b hbxs
        have := x.start_le_endNat
        omega
    · simp only [hle, if_false]
      have hle' : ¬ r.vaStart.toNat ≤ x.vaStart.toNat := hle
      have hlt : x.vaStart.toNat < r.vaStart.toNat := Nat.lt_of_not_le hle'
      have hxr : x.endNat ≤ r.vaStart.toNat :=
        le_of_not_overlaps hxsz hrsz (Nat.le_of_lt hlt)
          (fun hov => hno x ((List.mem_cons_self)) (overlaps_symm hov))
      have hno' : ∀ y ∈ xs, ¬ Overlaps r y :=
        fun y hy => hno y (List.mem_cons.2 (.inr hy))
      refine ⟨hxsz, fun b hb => ?_, ih wfxs hno'⟩
      rcases mem_insertByStart hb with hbr | hbxs
      · subst hbr; exact hxr
      · exact hxclear b hbxs

/-- The address space (space.rs:18). `backing` (image store) is a Task-6/FFI
    concern and deliberately omitted here. -/
structure AddressSpace where
  regions : List AddressRegion
  maxRegions : Nat
  deriving Inhabited

namespace AddressSpace

def new (maxRegions : Nat) : AddressSpace := ⟨[], maxRegions⟩

def len (s : AddressSpace) : Nat := s.regions.length
def isEmpty (s : AddressSpace) : Bool := s.regions.isEmpty

/-- Add a region; error on zero size, capacity, overlap (space.rs:95).
    Error strings match Rust exactly. -/
def addRegion (s : AddressSpace) (r : AddressRegion) : Except Anomaly AddressSpace :=
  if r.size == 0 then .error (.internal "zero-sized region")
  else if s.regions.length ≥ s.maxRegions then .error (.internal "AddressSpace at capacity")
  else if s.regions.any fun x => decide (AddressRegion.Overlaps r x) then .error (.internal "overlap")
  else .ok { s with regions := insertByStart r s.regions }

/-- Find the region covering `va`, if any (space.rs:54). -/
def findCovering : List AddressRegion → VA → Option AddressRegion
  | [], _ => none
  | r :: rest, va => if r.covers va then some r else findCovering rest va

def regionAt (s : AddressSpace) (va : VA) : Option AddressRegion :=
  findCovering s.regions va

def classify (s : AddressSpace) (va : VA) : RegionClass :=
  match s.regionAt va with
  | some r => r.classification
  | none => .Other

/-- Read `len` bytes at `va`; `none` if unmapped or crossing a boundary
    (space.rs:79; image-backing fallthrough deferred). -/
def read (s : AddressSpace) (va : VA) (len : Nat) : Option ByteArray :=
  match s.regionAt va with
  | none => none
  | some r =>
    let off := va.toNat - r.vaStart.toNat
    if off + len ≤ r.data.size then some (r.data.extract off (off + len)) else none

theorem findCovering_mem {rs : List AddressRegion} {va : VA} {r : AddressRegion}
    (h : findCovering rs va = some r) : r ∈ rs := by
  induction rs with
  | nil => cases h
  | cons x xs ih =>
    by_cases hx : x.covers va
    · simp [findCovering, hx] at h; cases h; exact List.mem_cons_self
    · simp [findCovering, hx] at h; exact List.mem_cons.2 (.inr (ih h))

theorem findCovering_covers {rs : List AddressRegion} {va : VA} {r : AddressRegion}
    (h : findCovering rs va = some r) : r.covers va := by
  induction rs with
  | nil => cases h
  | cons x xs ih =>
    by_cases hx : x.covers va
    · simp [findCovering, hx] at h; cases h; exact hx
    · simp [findCovering, hx] at h; exact ih h

/-- AddressSpace.tla: the region containing a VA is unique. -/
theorem regionAt_unique {s : AddressSpace} {va : VA} {r : AddressRegion}
    (wf : WellFormed s.regions) (h : s.regionAt va = some r) :
    r ∈ s.regions ∧ ∀ r' ∈ s.regions, r'.covers va → r' = r := by
  refine ⟨findCovering_mem h, fun r' hr' hcov => ?_⟩
  by_cases hne : r' = r
  · exact hne
  · exact absurd (AddressRegion.overlaps_of_covers_covers hcov (findCovering_covers h))
      (wf.pairwise_nonoverlap hr' (findCovering_mem h) hne)

/-- AddressSpace.tla `AddRegion` preserves the invariant. -/
theorem addRegion_preserves {s s' : AddressSpace} {r : AddressRegion}
    (wf : WellFormed s.regions) (h : s.addRegion r = .ok s') :
    WellFormed s'.regions := by
  by_cases hsz : r.size == 0
  · simp [addRegion, hsz] at h
  · by_cases hcap : s.regions.length ≥ s.maxRegions
    · simp [addRegion, hsz, hcap] at h
    · by_cases hov : s.regions.any fun x => decide (AddressRegion.Overlaps r x)
      · simp [addRegion, hsz, hcap, hov] at h
      · simp only [addRegion, hsz, hcap, hov, if_false] at h
        cases h
        have hrsz : r.size ≠ 0 := by
          intro hz; rw [hz] at hsz; exact absurd (by decide) hsz
        have hnoo : ∀ x ∈ s.regions, ¬ AddressRegion.Overlaps r x := by
          intro x hx ho
          apply hov
          rw [List.any_eq_true]
          exact ⟨x, hx, decide_eq_true ho⟩
        exact wellFormed_insert wf hrsz hnoo

theorem read_within_region {s : AddressSpace} {va : VA} {len : Nat} {bs : ByteArray}
    (h : s.read va len = some bs) :
    ∃ r ∈ s.regions, r.covers va ∧ va.toNat + len ≤ r.vaStart.toNat + r.data.size := by
  cases hra : s.regionAt va with
  | none => simp [read, hra] at h
  | some r =>
    simp only [read, hra] at h
    by_cases hle : va.toNat - r.vaStart.toNat + len ≤ r.data.size
    · simp only [hle, if_true] at h
      obtain ⟨hge, hlt⟩ := findCovering_covers hra
      exact ⟨r, findCovering_mem hra, ⟨hge, hlt⟩, by simp only [AddressRegion.endNat] at *; omega⟩
    · simp [hle] at h

theorem classify_of_regionAt {s : AddressSpace} {va : VA} {r : AddressRegion}
    (h : s.regionAt va = some r) : s.classify va = r.classification := by
  simp [classify, h]

theorem classify_none {s : AddressSpace} {va : VA}
    (h : s.regionAt va = none) : s.classify va = .Other := by
  simp [classify, h]

end AddressSpace

end Forensicator.Spec

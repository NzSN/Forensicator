/- Forensicator.Spec.AddressSpace — mechanization of specs/AddressSpace.tla.

   The executable container (sorted, non-overlapping regions) and its
   invariants live here together: the theorems are *about* the shipping
   operations, replacing the bounded Apalache checks + mbt_address_space.rs.

   Regions are a sorted `List` (region counts are hundreds, not millions);
   bulk bytes stay in `ByteArray`. Address arithmetic is lifted to `Nat` so
   the Rust version's potential u64 wrap in `va_start + size` is
   unrepresentable. -/
import Forensicator.Model.Types
import Forensicator.Util.Image

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
  /-- On-disk module images, consulted by `read` when no dump region
      covers the VA (stack-only minidumps). -/
  backing : Option Util.ImageSet := none
  deriving Inhabited

namespace AddressSpace

def new (maxRegions : Nat) : AddressSpace := ⟨[], maxRegions, none⟩

/-- Attach on-disk PE images used as a read fallback. -/
def setBacking (s : AddressSpace) (images : Util.ImageSet) : AddressSpace :=
  { s with backing := some images }

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
  | none => s.backing.bind fun b => b.read va len
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
    (hback : s.backing = none) (h : s.read va len = some bs) :
    ∃ r ∈ s.regions, r.covers va ∧ va.toNat + len ≤ r.vaStart.toNat + r.data.size := by
  cases hra : s.regionAt va with
  | none => simp [read, hra, hback] at h
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

/-- Array-backed lookup index over a space's regions (same order as
    `AddressSpace.regions`, which `addRegion` keeps sorted). Binary search
    replaces the linear scan on hot paths (pointer scan / vtables).
    Equivalence with `regionAt` holds under `WellFormed` by
    `regionAt_eq` (F7). -/
structure FastSpace where
  regions : Array AddressRegion

namespace FastSpace

def ofSpace (s : AddressSpace) : FastSpace := ⟨s.regions.toArray⟩

/-- Count of regions with vaStart ≤ va (binary search, fuel = n+1). -/
private def search (fs : FastSpace) (va : VA) : Nat → Nat → Nat → Nat
  | fuel, lo, hi =>
    match fuel with
    | 0 => lo
    | fuel + 1 =>
      if lo < hi then
        let mid := (lo + hi) / 2
        if (fs.regions[mid]!).vaStart ≤ va then search fs va fuel (mid + 1) hi
        else search fs va fuel lo mid
      else lo

/-- Count of regions with vaStart ≤ va (binary search), then coverage check. -/
def regionAt (fs : FastSpace) (va : VA) : Option AddressRegion :=
  let k := search fs va (fs.regions.size + 1) 0 fs.regions.size
  if k == 0 then none
  else
    let r := fs.regions[k - 1]!
    if r.vaStart ≤ va && va.toNat < r.endNat then some r else none

def classify (fs : FastSpace) (va : VA) : RegionClass :=
  match fs.regionAt va with
  | some r => r.classification
  | none => .Other

/-! F7: FastSpace.regionAt ≡ AddressSpace.regionAt under WellFormed. -/

open AddressSpace AddressRegion

theorem list_get!_mem {rs : List AddressRegion} {i : Nat} (h : i < rs.length) : rs[i]! ∈ rs := by
  induction rs generalizing i with
  | nil => simpa using h
  | cons x xs ih =>
    by_cases hi : i = 0
    · subst i
      simp
    · cases i with
      | zero => omega
      | succ i =>
        have hxs : i < xs.length := by
          rw [List.length_cons] at h
          omega
        rw [List.getElem!_cons_succ]
        exact List.mem_cons.2 (.inr (ih hxs))

theorem list_get!_eq_array_get! {rs : List AddressRegion} {i : Nat} (h : i < rs.length) :
    rs[i]! = rs.toArray[i]! := by
  rw [List.getElem!_toArray]

theorem mem_toArray_get! {rs : List AddressRegion} {i : Nat} (h : i < rs.length) :
    rs.toArray[i]! ∈ rs := by
  rw [← list_get!_eq_array_get! h]
  exact list_get!_mem h

theorem mem_iff_exists_get! {rs : List AddressRegion} {x : AddressRegion} :
    x ∈ rs ↔ ∃ i, i < rs.length ∧ rs.toArray[i]! = x := by
  constructor
  · intro hx
    induction rs with
    | nil => cases hx
    | cons y ys ih =>
      rcases List.mem_cons.1 hx with hy | hys
      · exact ⟨0, by simp, by simp [hy]⟩
      · rcases ih hys with ⟨i, hi, hi2⟩
        exact ⟨i + 1, by simp [hi], by
          rw [List.getElem!_toArray, List.getElem!_cons_succ]
          rw [list_get!_eq_array_get! hi]
          exact hi2⟩
  · rintro ⟨i, hi, hx⟩
    rw [← hx]
    exact mem_toArray_get! hi

/-! WellFormed → array sorted + endNat chain. -/

theorem wellFormed_sorted {rs : List AddressRegion} (wf : WellFormed rs) :
    ∀ i j, i ≤ j → j < rs.length → (rs.toArray[i]!).vaStart ≤ (rs.toArray[j]!).vaStart := by
  intro i j hle hj
  rw [List.getElem!_toArray, List.getElem!_toArray]
  induction rs generalizing i j with
  | nil => simpa using hj
  | cons x xs ih =>
    rcases wf with ⟨hxsz, hxclear, wfxs⟩
    by_cases hi : i = 0
    · subst i
      cases j with
      | zero => simp
      | succ j =>
        have hxs : j < xs.length := by
          rw [List.length_cons] at hj
          omega
        have hxj : xs[j]! ∈ xs := list_get!_mem hxs
        have hxend : x.endNat ≤ (xs[j]!).vaStart.toNat := hxclear _ hxj
        have hxstart : x.vaStart.toNat < x.endNat := x.endNat_gt_start hxsz
        rw [List.getElem!_cons_zero, List.getElem!_cons_succ]
        rw [UInt64.le_iff_toNat_le]
        omega
    · have hpos : 0 < i := Nat.pos_of_ne_zero hi
      cases i with
      | zero => omega
      | succ i =>
        cases j with
        | zero => omega
        | succ j =>
          have hix : i ≤ j := by omega
          have hxs : j < xs.length := by
            rw [List.length_cons] at hj
            omega
          have hrec := ih wfxs i j hix hxs
          rw [List.getElem!_cons_succ, List.getElem!_cons_succ]
          exact hrec

theorem wellFormed_endNat_le_vaStart {rs : List AddressRegion} (wf : WellFormed rs) :
    ∀ i j, i < j → j < rs.length → (rs.toArray[i]!).endNat ≤ (rs.toArray[j]!).vaStart.toNat := by
  intro i j hlt hj
  rw [List.getElem!_toArray, List.getElem!_toArray]
  induction rs generalizing i j with
  | nil => simpa using hj
  | cons x xs ih =>
    rcases wf with ⟨hxsz, hxclear, wfxs⟩
    by_cases hi : i = 0
    · subst i
      cases j with
      | zero => omega
      | succ j =>
        have hxs : j < xs.length := by
          rw [List.length_cons] at hj
          omega
        have hxj : xs[j]! ∈ xs := list_get!_mem hxs
        rw [List.getElem!_cons_zero, List.getElem!_cons_succ]
        exact hxclear _ hxj
    · have hpos : 0 < i := Nat.pos_of_ne_zero hi
      cases i with
      | zero => omega
      | succ i =>
        cases j with
        | zero => omega
        | succ j =>
          have hix : i < j := by omega
          have hxs : j < xs.length := by
            rw [List.length_cons] at hj
            omega
          have hrec := ih wfxs i j hix hxs
          rw [List.getElem!_cons_succ, List.getElem!_cons_succ]
          exact hrec

/-! Binary-search loop correctness (induction on fuel). -/

/-- The region array is sorted by vaStart. -/
def SortedArray (regions : Array AddressRegion) : Prop :=
  ∀ i j, i ≤ j → j < regions.size → (regions[i]!).vaStart ≤ (regions[j]!).vaStart

/-- Exactly `k` regions have vaStart ≤ va: a prefix. -/
def CountLE (fs : FastSpace) (va : VA) (k : Nat) : Prop :=
  k ≤ fs.regions.size
    ∧ (∀ j, j < k → (fs.regions[j]!).vaStart ≤ va)
    ∧ (∀ j, k ≤ j → j < fs.regions.size → va < (fs.regions[j]!).vaStart)

theorem search_count {fs : FastSpace} {va : VA} (hord : SortedArray fs.regions) :
    ∀ (fuel lo hi : Nat),
      lo ≤ hi → hi ≤ fs.regions.size → fuel ≥ hi - lo + 1 →
      (∀ j, j < lo → (fs.regions[j]!).vaStart ≤ va) →
      (∀ j, hi ≤ j → j < fs.regions.size → va < (fs.regions[j]!).vaStart) →
      CountLE fs va (search fs va fuel lo hi) := by
  intro fuel
  induction fuel with
  | zero =>
    intro lo hi hle hhi hfuel hlo hhi'
    exfalso
    omega
  | succ fuel ih =>
    intro lo hi hle hhi hfuel hlo hhi'
    by_cases hlt : lo < hi
    · let mid := (lo + hi) / 2
      have hmid_ge : lo ≤ mid := by
        have hdiv : (lo + lo) / 2 ≤ (lo + hi) / 2 :=
          Nat.div_le_div_right (by omega)
        rwa [show (lo + lo) / 2 = lo by
          rw [← Nat.two_mul lo]
          exact Nat.mul_div_right lo (by decide : (0 : Nat) < 2)] at hdiv
      have hmid_lt : mid < hi := by
        have hdiv : (lo + hi) / 2 < (hi + hi) / 2 :=
          Nat.div_lt_div_of_lt_of_dvd (by rw [← Nat.two_mul hi]; exact Nat.dvd_mul_right 2 hi) (by omega)
        rwa [show (hi + hi) / 2 = hi by
          rw [← Nat.two_mul hi]
          exact Nat.mul_div_right hi (by decide : (0 : Nat) < 2)] at hdiv
      by_cases hm : (fs.regions[mid]!).vaStart ≤ va
      · have hlo' : ∀ j, j < mid + 1 → (fs.regions[j]!).vaStart ≤ va := by
          intro j hj
          have hjmid : j ≤ mid := by omega
          have hjlt : j < fs.regions.size := by omega
          by_cases hjl : j < lo
          · exact hlo j hjl
          · have hloj : lo ≤ j := Nat.le_of_not_gt hjl
            have h1 : (fs.regions[j]!).vaStart.toNat ≤ (fs.regions[mid]!).vaStart.toNat := by
              simpa [UInt64.le_iff_toNat_le] using hord j mid hjmid (by omega)
            have h2 : (fs.regions[mid]!).vaStart.toNat ≤ va.toNat := by
              simpa [UInt64.le_iff_toNat_le] using hm
            rw [UInt64.le_iff_toNat_le]
            exact Nat.le_trans h1 h2
        have hfuel' : fuel ≥ hi - (mid + 1) + 1 := by omega
        have hle' : mid + 1 ≤ hi := by omega
        have hk := ih (mid + 1) hi hle' hhi hfuel' hlo' hhi'
        have hdef : search fs va (fuel + 1) lo hi = search fs va fuel (mid + 1) hi := by
          simp [search, hlt, hm, mid]
        rw [hdef]
        exact hk
      · have hhi'' : ∀ j, mid ≤ j → j < fs.regions.size → va < (fs.regions[j]!).vaStart := by
          intro j hmidj hjlt
          have hmv : va.toNat < (fs.regions[mid]!).vaStart.toNat := by
            simpa [UInt64.le_iff_toNat_le] using hm
          have hordj : (fs.regions[mid]!).vaStart.toNat ≤ (fs.regions[j]!).vaStart.toNat := by
            simpa [UInt64.le_iff_toNat_le] using hord mid j hmidj hjlt
          rw [UInt64.lt_iff_toNat_lt]
          exact Nat.lt_of_lt_of_le hmv hordj
        have hfuel' : fuel ≥ mid - lo + 1 := by omega
        have hle' : lo ≤ mid := hmid_ge
        have hhi'2 : mid ≤ fs.regions.size := by omega
        have hk := ih lo mid hle' hhi'2 hfuel' hlo hhi''
        have hdef : search fs va (fuel + 1) lo hi = search fs va fuel lo mid := by
          simp [search, hlt, hm, mid]
        rw [hdef]
        exact hk
    · have hle' : lo = hi := by omega
      have hk : CountLE fs va lo := by
        rw [hle'] at hlo ⊢
        exact ⟨hhi, hlo, hhi'⟩
      have hdef : search fs va (fuel + 1) lo hi = lo := by
        simp [search, hlt]
      rw [hdef]
      exact hk

theorem search_full_count {fs : FastSpace} {va : VA} (hord : SortedArray fs.regions) :
    CountLE fs va (search fs va (fs.regions.size + 1) 0 fs.regions.size) := by
  apply search_count hord (fs.regions.size + 1) 0 fs.regions.size
  · omega
  · omega
  · omega
  · intro j hj; omega
  · intro j hj1 hj2; omega

/-! findCovering lemmas. -/

theorem findCovering_none_of_no_cover {rs : List AddressRegion} {va : VA}
    (h : ∀ r' ∈ rs, ¬ r'.covers va) : findCovering rs va = none := by
  induction rs with
  | nil => rfl
  | cons x xs ih =>
    by_cases hx : x.covers va
    · exact absurd hx (h x (List.mem_cons_self))
    · simp [findCovering, hx]
      exact ih (fun r' hr' => h r' (List.mem_cons.2 (.inr hr')))

theorem findCovering_some_of_unique {rs : List AddressRegion} {va : VA} {r : AddressRegion}
    (hrs : r ∈ rs) (hrc : r.covers va)
    (huniq : ∀ r' ∈ rs, r'.covers va → r' = r) : findCovering rs va = some r := by
  induction rs with
  | nil => cases hrs
  | cons x xs ih =>
    by_cases hx : x.covers va
    · have hxr : x = r := huniq x (List.mem_cons_self) hx
      rw [hxr] at hx ⊢
      simp [findCovering, hx]
    · have hrs' : r ∈ xs := by
        rcases List.mem_cons.1 hrs with hrx | hrxs
        · subst x
          exact False.elim (hx hrc)
        · exact hrxs
      have huniq' : ∀ r' ∈ xs, r'.covers va → r' = r :=
        fun r' hr' => huniq r' (List.mem_cons.2 (.inr hr'))
      simp [findCovering, hx]
      exact ih hrs' huniq'

/-! Main equivalence: FastSpace.regionAt = AddressSpace.regionAt under WellFormed. -/

theorem regionAt_eq {s : AddressSpace} {va : VA} (wf : WellFormed s.regions) :
    FastSpace.regionAt (FastSpace.ofSpace s) va = s.regionAt va := by
  let fs : FastSpace := FastSpace.ofSpace s
  have hfs : fs.regions = s.regions.toArray := rfl
  have hlen : fs.regions.size = s.regions.length := by
    rw [hfs]
    simp
  have hord : SortedArray fs.regions := by
    intro i j hle hj
    rw [hfs]
    exact wellFormed_sorted wf i j hle hj
  have hk : CountLE fs va (search fs va (fs.regions.size + 1) 0 fs.regions.size) :=
    search_full_count hord
  unfold FastSpace.regionAt AddressSpace.regionAt
  simp only [FastSpace.ofSpace]
  let k := search fs va (fs.regions.size + 1) 0 fs.regions.size
  change (if (k == 0) = true then none else
      let r := fs.regions[k - 1]!
      if (decide (r.vaStart ≤ va) && decide (va.toNat < r.endNat)) = true then some r else none)
    = findCovering s.regions va
  have hk' : CountLE fs va k := hk
  rcases hk' with ⟨hk1, hleft, hright⟩
  by_cases hk0 : k == 0
  · have hk0' : k = 0 := of_decide_eq_true hk0
    have hnone : findCovering s.regions va = none := by
      apply findCovering_none_of_no_cover
      intro r' hr'
      intro hcov
      rcases mem_iff_exists_get!.1 hr' with ⟨j, hj, hrj⟩
      have hlej : k ≤ j := by omega
      have hgj : j < fs.regions.size := by
        rw [hlen]
        exact hj
      have hg : va < (fs.regions[j]!).vaStart := hright j hlej hgj
      have hvs : (fs.regions[j]!).vaStart.toNat ≤ va.toNat := by
        simpa [hfs, hrj] using hcov.1
      rw [UInt64.lt_iff_toNat_lt] at hg
      omega
    simp [hk0']
    exact hnone.symm
  · have hkpos : 0 < k := Nat.pos_of_ne_zero (by
      intro hz
      exact hk0 (by simp [hz]))
    have hkin : k - 1 < fs.regions.size := by omega
    have hkin' : k - 1 < s.regions.length := by
      rw [← hlen]
      exact hkin
    have hkle : (fs.regions[k - 1]!).vaStart ≤ va := hleft (k - 1) (by omega)
    have hkr : (fs.regions[k - 1]!) ∈ s.regions := by
      rw [hfs]
      exact mem_toArray_get! hkin'
    by_cases hcov : va.toNat < (fs.regions[k - 1]!).endNat
    · have hrcov : (fs.regions[k - 1]!).covers va := by
        rw [AddressRegion.covers]
        exact ⟨by simpa [UInt64.le_iff_toNat_le] using hkle, hcov⟩
      have huniq : ∀ r' ∈ s.regions, r'.covers va → r' = fs.regions[k - 1]! := by
        intro r' hr' hcov'
        rcases mem_iff_exists_get!.1 hr' with ⟨j, hj, hrj⟩
        by_cases hjlt : j < k - 1
        · have hjc : (s.regions.toArray[j]!).endNat ≤ (s.regions.toArray[k - 1]!).vaStart.toNat :=
            wellFormed_endNat_le_vaStart wf j (k - 1) hjlt hkin'
          have hjkv : (s.regions.toArray[k - 1]!).vaStart.toNat ≤ va.toNat := by
            simpa [hfs, UInt64.le_iff_toNat_le] using hkle
          have hend : r'.endNat ≤ va.toNat := by
            rw [← hrj]
            exact Nat.le_trans hjc hjkv
          have hvend : va.toNat < r'.endNat := hcov'.2
          omega
        · have hjge : k - 1 ≤ j := Nat.le_of_not_gt hjlt
          by_cases hjeq : j = k - 1
          · rw [← hrj, hjeq, ← hfs]
          · have hgk : k ≤ j := by omega
            have hjv' : va < (fs.regions[j]!).vaStart := hright j hgk (by rw [hlen]; exact hj)
            have hvs : (fs.regions[j]!).vaStart.toNat ≤ va.toNat := by
              simpa [hfs, hrj] using hcov'.1
            rw [UInt64.lt_iff_toNat_lt] at hjv'
            omega
      have hfind : findCovering s.regions va = some (fs.regions[k - 1]!) :=
        findCovering_some_of_unique hkr hrcov huniq
      rw [hfind]
      dsimp
      simp [hk0, hcov, hkle]
    · have hnone : findCovering s.regions va = none := by
        apply findCovering_none_of_no_cover
        intro r' hr' hcov'
        rcases mem_iff_exists_get!.1 hr' with ⟨j, hj, hrj⟩
        by_cases hjlt : j < k - 1
        · have hjc : (s.regions.toArray[j]!).endNat ≤ (s.regions.toArray[k - 1]!).vaStart.toNat :=
            wellFormed_endNat_le_vaStart wf j (k - 1) hjlt hkin'
          have hjkv : (s.regions.toArray[k - 1]!).vaStart.toNat ≤ va.toNat := by
            simpa [hfs, UInt64.le_iff_toNat_le] using hkle
          have hend : r'.endNat ≤ va.toNat := by
            rw [← hrj]
            exact Nat.le_trans hjc hjkv
          have hvend : va.toNat < r'.endNat := hcov'.2
          omega
        · have hjge : k - 1 ≤ j := Nat.le_of_not_gt hjlt
          by_cases hjeq : j = k - 1
          · rw [← hrj, hjeq, ← hfs] at hcov'
            exact hcov hcov'.2
          · have hgk : k ≤ j := by omega
            have hjv' : va < (fs.regions[j]!).vaStart := hright j hgk (by rw [hlen]; exact hj)
            have hvs : (fs.regions[j]!).vaStart.toNat ≤ va.toNat := by
              simpa [hfs, hrj] using hcov'.1
            rw [UInt64.lt_iff_toNat_lt] at hjv'
            omega
      simp [hk0, hcov]
      exact hnone.symm

end FastSpace

end Forensicator.Spec

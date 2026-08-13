/- Forensicator.Spec.JigSaw — mechanization of the pure half of
   specs/JigSawSpawner.tla against the *shipping* index views:

   * Validity-interval arithmetic (the host-side CacheSound core): the
     known write history of a page is constant over `[lastKnownWrite p t,
     nextKnownWrite p t)`, so a piece fetched at one position of the
     interval truthfully serves them all (mirrors the structure of
     `Spec/Timeline.lean`'s `valueAt_agrees_with_fold`; the engine itself
     stays an abstract oracle, as `CmAt`/`ValueAt` are in the spec).
   * Write-index merge invariants: `mergeRecords` preserves the key order
     and drops exact-key duplicates (left copy kept); `mergeWindow`
     therefore keeps `IndexState.records` sorted and absorbs every
     in-frontier record of the fetched window.

   Position arithmetic is lifted to Nat (`UInt64.le_iff_toNat_le`); the
   horizon sentinel `idx_F[p] + 1` is what makes `t < nextKnownWrite`
   hold (HorizonBounded). -/
import Forensicator.Trace.Index

-- ── UInt64 → Nat transport ──────────────────────────────────────────

namespace UInt64

theorem toNat_max (a b : UInt64) : (max a b).toNat = Nat.max a.toNat b.toNat := by
  show (if a ≤ b then b else a).toNat = _
  by_cases h : a ≤ b
  · rw [if_pos h]; exact (Nat.max_eq_right (UInt64.le_iff_toNat_le.mp h)).symm
  · rw [if_neg h]
    exact (Nat.max_eq_left (Nat.le_of_not_le (fun hc => h (UInt64.le_iff_toNat_le.mpr hc)))).symm

theorem toNat_min (a b : UInt64) : (min a b).toNat = Nat.min a.toNat b.toNat := by
  show (if a ≤ b then a else b).toNat = _
  by_cases h : a ≤ b
  · rw [if_pos h]; exact (Nat.min_eq_left (UInt64.le_iff_toNat_le.mp h)).symm
  · rw [if_neg h]
    exact (Nat.min_eq_right (Nat.le_of_not_le (fun hc => h (UInt64.le_iff_toNat_le.mpr hc)))).symm

theorem toNat_foldl_max (l : List UInt64) (init : UInt64) :
    (l.foldl max init).toNat = (l.map UInt64.toNat).foldl max init.toNat := by
  induction l generalizing init with
  | nil => rfl
  | cons a l ih =>
    simp only [List.foldl_cons, List.map_cons]
    rw [ih, UInt64.toNat_max]

theorem toNat_foldl_min (l : List UInt64) (init : UInt64) :
    (l.foldl min init).toNat = (l.map UInt64.toNat).foldl min init.toNat := by
  induction l generalizing init with
  | nil => rfl
  | cons a l ih =>
    simp only [List.foldl_cons, List.map_cons]
    rw [ih, UInt64.toNat_min]

end UInt64

-- ── Nat foldl order facts ───────────────────────────────────────────

namespace Nat

theorem foldl_max_ge_init : ∀ (l : List Nat) (init : Nat), init ≤ l.foldl max init := by
  intro l
  induction l with
  | nil => intro init; exact Nat.le_refl _
  | cons a l ih =>
    intro init
    rw [List.foldl_cons]
    exact Nat.le_trans (Nat.le_max_left _ _) (ih _)

theorem mem_le_foldl_max : ∀ {l : List Nat} {x : Nat} (init : Nat),
    x ∈ l → x ≤ l.foldl max init := by
  intro l
  induction l with
  | nil => intro x init h; cases h
  | cons a l ih =>
    intro x init h
    rw [List.foldl_cons]
    cases h with
    | head => exact Nat.le_trans (Nat.le_max_right _ _) (foldl_max_ge_init _ _)
    | tail _ hm => exact ih _ hm

theorem foldl_min_le_init : ∀ (l : List Nat) (init : Nat), l.foldl min init ≤ init := by
  intro l
  induction l with
  | nil => intro init; exact Nat.le_refl _
  | cons a l ih =>
    intro init
    rw [List.foldl_cons]
    exact Nat.le_trans (ih _) (Nat.min_le_left _ _)

theorem foldl_min_le_mem : ∀ {l : List Nat} {x : Nat} (init : Nat),
    x ∈ l → l.foldl min init ≤ x := by
  intro l
  induction l with
  | nil => intro x init h; cases h
  | cons a l ih =>
    intro x init h
    rw [List.foldl_cons]
    cases h with
    | head => exact Nat.le_trans (foldl_min_le_init _ _) (Nat.min_le_right _ _)
    | tail _ hm => exact ih _ hm

theorem foldl_max_mem_or_eq_init : ∀ (l : List Nat) (init : Nat),
    l.foldl max init ∈ l ∨ l.foldl max init = init := by
  intro l
  induction l with
  | nil => intro init; exact Or.inr rfl
  | cons a l ih =>
    intro init
    rw [List.foldl_cons]
    cases ih (max init a) with
    | inl h => exact Or.inl (List.Mem.tail _ h)
    | inr h =>
      by_cases ha : a ≤ init
      · exact Or.inr (by rw [h, Nat.max_eq_left ha])
      · exact Or.inl (by rw [h, Nat.max_eq_right (Nat.le_of_not_le ha)]; exact List.Mem.head _)

theorem foldl_min_mem_or_eq_init : ∀ (l : List Nat) (init : Nat),
    l.foldl min init ∈ l ∨ l.foldl min init = init := by
  intro l
  induction l with
  | nil => intro init; exact Or.inr rfl
  | cons a l ih =>
    intro init
    rw [List.foldl_cons]
    cases ih (min init a) with
    | inl h => exact Or.inl (List.Mem.tail _ h)
    | inr h =>
      by_cases ha : init ≤ a
      · exact Or.inr (by rw [h, Nat.min_eq_left ha])
      · exact Or.inl (by rw [h, Nat.min_eq_right (Nat.le_of_not_le ha)]; exact List.Mem.head _)

theorem lt_foldl_min : ∀ (l : List Nat) (init : Nat) (t : Nat),
    t < init → (∀ x ∈ l, t < x) → t < l.foldl min init := by
  intro l
  induction l with
  | nil => intro init t h _; simpa using h
  | cons a l ih =>
    intro init t hinit hmem
    rw [List.foldl_cons]
    exact ih _ _ (Nat.lt_min.mpr ⟨hinit, hmem a (List.Mem.head _)⟩)
      (fun x hx => hmem x (List.Mem.tail _ hx))

theorem foldl_max_le : ∀ (l : List Nat) (init : Nat) (t : Nat),
    init ≤ t → (∀ x ∈ l, x ≤ t) → l.foldl max init ≤ t := by
  intro l
  induction l with
  | nil => intro init t h _; simpa using h
  | cons a l ih =>
    intro init t hinit hmem
    rw [List.foldl_cons]
    exact ih _ _ (Nat.max_le.mpr ⟨hinit, hmem a (List.Mem.head _)⟩)
      (fun x hx => hmem x (List.Mem.tail _ hx))

theorem le_foldl_min : ∀ (l : List Nat) (init : Nat) (b : Nat),
    b ≤ init → (∀ x ∈ l, b ≤ x) → b ≤ l.foldl min init := by
  intro l
  induction l with
  | nil => intro init b h _; simpa using h
  | cons a l ih =>
    intro init b hinit hmem
    rw [List.foldl_cons]
    exact ih _ _ (Nat.le_min.mpr ⟨hinit, hmem a (List.Mem.head _)⟩)
      (fun x hx => hmem x (List.Mem.tail _ hx))

end Nat

-- ── The shipping index views, at Nat level ──────────────────────────

namespace Forensicator.Trace

open Forensicator.Model (WriteRecord)

/-- The positions of `st`'s records overlapping `page` within horizon `h`
    at or before `t` — the known write history the views fold over. -/
def IndexState.history (st : IndexState) (page : VA) (h t : Position) : List Nat :=
  (st.records.filter fun w =>
    w.overlapsPage page && decide (w.pos ≤ h) && decide (w.pos ≤ t)).map fun w => w.pos.toNat

/-- The positions of `st`'s records overlapping `page` within horizon `h`
    strictly after `t`. -/
def IndexState.later (st : IndexState) (page : VA) (h t : Position) : List Nat :=
  (st.records.filter fun w =>
    w.overlapsPage page && decide (w.pos ≤ h) && decide (t < w.pos)).map fun w => w.pos.toNat

theorem IndexState.mem_history {st : IndexState} {page : VA} {h t : Position} {x : Nat} :
    x ∈ st.history page h t ↔
      ∃ w, w ∈ st.records ∧ w.overlapsPage page = true ∧ w.pos ≤ h ∧ w.pos ≤ t
        ∧ w.pos.toNat = x := by
  simp only [IndexState.history, List.mem_map, List.mem_filter]
  constructor
  · rintro ⟨w, ⟨hm, hcond⟩, hw⟩
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hcond
    exact ⟨w, hm, hcond.1.1, hcond.1.2, hcond.2, hw⟩
  · rintro ⟨w, hm, hov, hph, hpt, hw⟩
    exact ⟨w, ⟨hm, by
      simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨⟨hov, hph⟩, hpt⟩⟩, hw⟩

theorem IndexState.mem_later {st : IndexState} {page : VA} {h t : Position} {x : Nat} :
    x ∈ st.later page h t ↔
      ∃ w, w ∈ st.records ∧ w.overlapsPage page = true ∧ w.pos ≤ h ∧ t < w.pos
        ∧ w.pos.toNat = x := by
  simp only [IndexState.later, List.mem_map, List.mem_filter]
  constructor
  · rintro ⟨w, ⟨hm, hcond⟩, hw⟩
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hcond
    exact ⟨w, hm, hcond.1.1, hcond.1.2, hcond.2, hw⟩
  · rintro ⟨w, hm, hov, hph, hpt, hw⟩
    exact ⟨w, ⟨hm, by
      simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨⟨hov, hph⟩, hpt⟩⟩, hw⟩

/-- `lastKnownWrite` is the max of the known history (Nat level). -/
theorem IndexState.lastKnownWrite_toNat (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) :
    (st.lastKnownWrite page t).toNat = (st.history page h t).foldl max 0 := by
  simp only [IndexState.lastKnownWrite, hh, IndexState.history]
  rw [← List.foldl_map (f := fun w : WriteRecord => w.pos) (g := max)]
  rw [UInt64.toNat_foldl_max, List.map_map]
  rfl

/-- `nextKnownWrite` is the min of the known later-writes, with the
    horizon sentinel (Nat level; `hh1` = the sentinel doesn't wrap). -/
theorem IndexState.nextKnownWrite_toNat (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) (hh1 : h.toNat + 1 < 2 ^ 64) :
    (st.nextKnownWrite page t).toNat = (st.later page h t).foldl min (h.toNat + 1) := by
  simp only [IndexState.nextKnownWrite, hh, IndexState.later]
  rw [← List.foldl_map (f := fun w : WriteRecord => w.pos) (g := min)]
  rw [UInt64.toNat_foldl_min, List.map_map]
  have hsent : (h + 1).toNat = h.toNat + 1 := by
    rw [UInt64.toNat_add]
    have h1 : (1 : UInt64).toNat = 1 := rfl
    rw [h1, Nat.mod_eq_of_lt hh1]
  rw [hsent]
  rfl

/-- `lo` never exceeds `t` (the ≤ t filter bounds the max). -/
theorem IndexState.lastKnownWrite_le (st : IndexState) (page : VA) (t : Position) :
    st.lastKnownWrite page t ≤ t := by
  cases hh : st.horizonOf page with
  | none =>
    have hz : st.lastKnownWrite page t = 0 := by simp [IndexState.lastKnownWrite, hh]
    exact UInt64.le_iff_toNat_le.mpr (by rw [hz]; exact Nat.zero_le _)
  | some h =>
    rw [UInt64.le_iff_toNat_le, st.lastKnownWrite_toNat page t h hh]
    exact Nat.foldl_max_le _ 0 _ (Nat.zero_le _) fun x hx => by
      obtain ⟨w, hm, hov, hph, hpt, hw⟩ := st.mem_history.1 hx
      rw [← hw]
      exact UInt64.le_iff_toNat_le.mp hpt

/-- `t < hi` within the horizon (HorizonBounded: the sentinel is `h + 1`,
    so validity never outruns knowledge). -/
theorem IndexState.lt_nextKnownWrite (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) (ht : t ≤ h) (hh1 : h.toNat + 1 < 2 ^ 64) :
    t < st.nextKnownWrite page t := by
  rw [UInt64.lt_iff_toNat_lt, st.nextKnownWrite_toNat page t h hh hh1]
  exact Nat.lt_foldl_min _ _ _ (Nat.lt_succ_of_le (UInt64.le_iff_toNat_le.mp ht)) fun x hx => by
    obtain ⟨w, hm, hov, hph, hpt, hw⟩ := st.mem_later.1 hx
    rw [← hw]
    exact UInt64.lt_iff_toNat_lt.mp hpt

/-- A known write within the horizon at or before `t` is dominated by `lo`. -/
theorem IndexState.le_lastKnownWrite (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) (w : WriteRecord)
    (hm : w ∈ st.records) (hp : w.overlapsPage page = true)
    (hph : w.pos ≤ h) (ht : w.pos ≤ t) :
    w.pos ≤ st.lastKnownWrite page t := by
  rw [UInt64.le_iff_toNat_le, st.lastKnownWrite_toNat page t h hh]
  exact Nat.mem_le_foldl_max _ (st.mem_history.2 ⟨w, hm, hp, hph, ht, rfl⟩)

/-- A known write within the horizon strictly after `t` dominates `hi`. -/
theorem IndexState.nextKnownWrite_le (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) (hh1 : h.toNat + 1 < 2 ^ 64) (w : WriteRecord)
    (hm : w ∈ st.records) (hp : w.overlapsPage page = true)
    (hph : w.pos ≤ h) (ht : t < w.pos) :
    st.nextKnownWrite page t ≤ w.pos := by
  rw [UInt64.le_iff_toNat_le, st.nextKnownWrite_toNat page t h hh hh1]
  exact Nat.foldl_min_le_mem _ (st.mem_later.2 ⟨w, hm, hp, hph, ht, rfl⟩)

/-- Interval emptiness (the spec's `(lo, hi)` carries no known write):
    every known write within the horizon lies at or before `lo` or at or
    after `hi`. -/
theorem IndexState.no_known_write_within (st : IndexState) (page : VA) (t h : Position)
    (hh : st.horizonOf page = some h) (hh1 : h.toNat + 1 < 2 ^ 64) (w : WriteRecord)
    (hm : w ∈ st.records) (hp : w.overlapsPage page = true) (hph : w.pos ≤ h) :
    w.pos ≤ st.lastKnownWrite page t ∨ st.nextKnownWrite page t ≤ w.pos := by
  by_cases ht : w.pos ≤ t
  · exact Or.inl (st.le_lastKnownWrite page t h hh w hm hp hph ht)
  · exact Or.inr (st.nextKnownWrite_le page t h hh hh1 w hm hp hph
      (UInt64.lt_iff_toNat_lt.mpr
        (Nat.lt_of_not_le fun hc => ht (UInt64.le_iff_toNat_le.mpr hc))))

/-- Validity-interval arithmetic — the pure half of `CacheSound`: over
    `[lastKnownWrite p t0, nextKnownWrite p t0)` the known write history of
    `page` is constant, so a piece fetched at `t0` truthfully serves every
    position of the interval. -/
theorem IndexState.history_agree (st : IndexState) (page : VA) (t0 t1 h : Position)
    (hh : st.horizonOf page = some h) (ht0 : t0 ≤ h) (hh1 : h.toNat + 1 < 2 ^ 64)
    (hlo : st.lastKnownWrite page t0 ≤ t1)
    (hhi : t1 < st.nextKnownWrite page t0) :
    st.lastKnownWrite page t1 = st.lastKnownWrite page t0
      ∧ st.nextKnownWrite page t1 = st.nextKnownWrite page t0 := by
  have hlo_n : (st.history page h t0).foldl max 0 ≤ t1.toNat := by
    have hlo' := UInt64.le_iff_toNat_le.mp hlo
    rwa [st.lastKnownWrite_toNat page t0 h hh] at hlo'
  have hhi_n : t1.toNat < (st.later page h t0).foldl min (h.toNat + 1) := by
    have hhi' := UInt64.lt_iff_toNat_lt.mp hhi
    rwa [st.nextKnownWrite_toNat page t0 h hh hh1] at hhi'
  have ht1h : t1.toNat ≤ h.toNat := by
    have hle := Nat.foldl_min_le_init (st.later page h t0) (h.toNat + 1)
    omega
  -- lo side: every position in the t1-history is ≤ the t0-max
  have hhist_le : ∀ x ∈ st.history page h t1,
      x ≤ (st.history page h t0).foldl max 0 := by
    intro x hx
    obtain ⟨w, hm, hov, hph, hpt1, hw⟩ := st.mem_history.1 hx
    by_cases hx0 : w.pos ≤ t0
    · exact Nat.mem_le_foldl_max _ (st.mem_history.2 ⟨w, hm, hov, hph, hx0, hw⟩)
    · exfalso
      have hgt : t0 < w.pos := UInt64.lt_iff_toNat_lt.mpr
        (Nat.lt_of_not_le fun hc => hx0 (UInt64.le_iff_toNat_le.mpr hc))
      have hge : (st.later page h t0).foldl min (h.toNat + 1) ≤ w.pos.toNat :=
        Nat.foldl_min_le_mem _ (st.mem_later.2 ⟨w, hm, hov, hph, hgt, rfl⟩)
      have hpt1n : w.pos.toNat ≤ t1.toNat := UInt64.le_iff_toNat_le.mp hpt1
      omega
  have h1le : (st.history page h t1).foldl max 0 ≤ (st.history page h t0).foldl max 0 :=
    Nat.foldl_max_le _ _ _ (Nat.zero_le _) hhist_le
  have h1ge : (st.history page h t0).foldl max 0 ≤ (st.history page h t1).foldl max 0 := by
    cases Nat.foldl_max_mem_or_eq_init (st.history page h t0) 0 with
    | inl hmem =>
      obtain ⟨w, hm, hov, hph, hpt0, hw⟩ := st.mem_history.1 hmem
      have hpt1 : w.pos ≤ t1 := by
        rw [UInt64.le_iff_toNat_le]; omega
      have hx : w.pos.toNat ≤ (st.history page h t1).foldl max 0 :=
        Nat.mem_le_foldl_max _
          ((st.mem_history (x := w.pos.toNat)).2 ⟨w, hm, hov, hph, hpt1, rfl⟩)
      rwa [hw] at hx
    | inr h0 => rw [h0]; exact Nat.zero_le _
  have hEqLo : st.lastKnownWrite page t1 = st.lastKnownWrite page t0 := by
    apply UInt64.toFin_inj.mp ∘ Fin.eq_of_val_eq
    show (st.lastKnownWrite page t1).toNat = (st.lastKnownWrite page t0).toNat
    rw [st.lastKnownWrite_toNat page t1 h hh, st.lastKnownWrite_toNat page t0 h hh]
    exact Nat.le_antisymm h1le h1ge
  -- hi side: every position in the t1-later-list is ≥ the t0-min
  have hlater_ge : ∀ x ∈ st.later page h t1,
      (st.later page h t0).foldl min (h.toNat + 1) ≤ x := by
    intro x hx
    obtain ⟨w, hm, hov, hph, hpt1, hw⟩ := st.mem_later.1 hx
    by_cases hx0 : w.pos ≤ t0
    · exfalso
      have hx0n : w.pos.toNat ≤ (st.history page h t0).foldl max 0 :=
        Nat.mem_le_foldl_max _ (st.mem_history.2 ⟨w, hm, hov, hph, hx0, rfl⟩)
      have hgt : t1.toNat < w.pos.toNat := UInt64.lt_iff_toNat_lt.mp hpt1
      omega
    · have hgt : t0 < w.pos := UInt64.lt_iff_toNat_lt.mpr
        (Nat.lt_of_not_le fun hc => hx0 (UInt64.le_iff_toNat_le.mpr hc))
      have hge : (st.later page h t0).foldl min (h.toNat + 1) ≤ w.pos.toNat :=
        Nat.foldl_min_le_mem _ (st.mem_later.2 ⟨w, hm, hov, hph, hgt, rfl⟩)
      rwa [hw] at hge
  have h2ge : (st.later page h t0).foldl min (h.toNat + 1)
      ≤ (st.later page h t1).foldl min (h.toNat + 1) :=
    Nat.le_foldl_min _ _ _ (Nat.foldl_min_le_init _ _) hlater_ge
  have h2le : (st.later page h t1).foldl min (h.toNat + 1)
      ≤ (st.later page h t0).foldl min (h.toNat + 1) := by
    cases Nat.foldl_min_mem_or_eq_init (st.later page h t0) (h.toNat + 1) with
    | inl hmem =>
      obtain ⟨w, hm, hov, hph, hpt0, hw⟩ := st.mem_later.1 hmem
      have hpt1 : t1 < w.pos := by
        rw [UInt64.lt_iff_toNat_lt]; omega
      have hx : (st.later page h t1).foldl min (h.toNat + 1) ≤ w.pos.toNat :=
        Nat.foldl_min_le_mem _
          ((st.mem_later (x := w.pos.toNat)).2 ⟨w, hm, hov, hph, hpt1, rfl⟩)
      rwa [hw] at hx
    | inr hsent =>
      -- hi is the sentinel: the t0-later-list must be empty (any member
      -- would be both ≥ hi = h+1 and ≤ h); then so is the t1-later-list
      have hnil0 : st.later page h t0 = [] := by
        rw [List.eq_nil_iff_forall_not_mem]
        intro x hx
        have hle : (st.later page h t0).foldl min (h.toNat + 1) ≤ x :=
          Nat.foldl_min_le_mem _ hx
        obtain ⟨w, hm, hov, hph, hpt0, hw⟩ := st.mem_later.1 hx
        have hxh : w.pos.toNat ≤ h.toNat := UInt64.le_iff_toNat_le.mp hph
        omega
      have hnil1 : st.later page h t1 = [] := by
        rw [List.eq_nil_iff_forall_not_mem]
        intro x hx
        obtain ⟨w, hm, hov, hph, hpt1, hw⟩ := st.mem_later.1 hx
        by_cases hx0 : w.pos ≤ t0
        · have hx0n : w.pos.toNat ≤ (st.history page h t0).foldl max 0 :=
            Nat.mem_le_foldl_max _ (st.mem_history.2 ⟨w, hm, hov, hph, hx0, rfl⟩)
          have hgt : t1.toNat < w.pos.toNat := UInt64.lt_iff_toNat_lt.mp hpt1
          omega
        · have hgt : t0 < w.pos := UInt64.lt_iff_toNat_lt.mpr
            (Nat.lt_of_not_le fun hc => hx0 (UInt64.le_iff_toNat_le.mpr hc))
          have hmem0 : w.pos.toNat ∈ st.later page h t0 :=
            st.mem_later.2 ⟨w, hm, hov, hph, hgt, rfl⟩
          rw [hnil0] at hmem0
          cases hmem0
      rw [hnil1]
      simp [hsent]
  have hEqHi : st.nextKnownWrite page t1 = st.nextKnownWrite page t0 := by
    apply UInt64.toFin_inj.mp ∘ Fin.eq_of_val_eq
    show (st.nextKnownWrite page t1).toNat = (st.nextKnownWrite page t0).toNat
    rw [st.nextKnownWrite_toNat page t1 h hh hh1, st.nextKnownWrite_toNat page t0 h hh hh1]
    exact Nat.le_antisymm h2le h2ge
  exact ⟨hEqLo, hEqHi⟩

end Forensicator.Trace

-- ── Merge invariants (the mergeIndex half) ──────────────────────────

namespace Forensicator.Trace

open Forensicator.Model (WriteRecord)

/-- The merge key linearized to one Nat (all components are u64s, so the
    lexicographic `(pos, va, len)` order is Nat order on `keyN`). -/
def _root_.Forensicator.Model.WriteRecord.keyN (w : WriteRecord) : Nat :=
  w.pos.toNat * 2 ^ 128 + w.va.toNat * 2 ^ 64 + w.len.toNat

theorem UInt64.eq_iff_toNat_eq {a b : UInt64} : a = b ↔ a.toNat = b.toNat :=
  ⟨fun h => h ▸ rfl, fun h => UInt64.toFin_inj.mp (Fin.eq_of_val_eq h)⟩

/-- Bounded linearization is injective (all components are u64-sized). -/
theorem keyN_inj_nat {p v l p' v' l' : Nat}
    (hb1 : p < 2 ^ 64) (hb2 : p' < 2 ^ 64) (hb3 : v < 2 ^ 64) (hb4 : v' < 2 ^ 64)
    (hb5 : l < 2 ^ 64) (hb6 : l' < 2 ^ 64)
    (h : p * 2 ^ 128 + v * 2 ^ 64 + l = p' * 2 ^ 128 + v' * 2 ^ 64 + l') :
    p = p' ∧ v = v' ∧ l = l' := by omega

theorem keyLT_iff_keyN (a b : WriteRecord) :
    a.keyLT b = true ↔ a.keyN < b.keyN := by
  have hp := UInt64.toNat_lt a.pos; have hq := UInt64.toNat_lt b.pos
  have hv := UInt64.toNat_lt a.va; have hw := UInt64.toNat_lt b.va
  have hl := UInt64.toNat_lt a.len; have hm := UInt64.toNat_lt b.len
  simp only [WriteRecord.keyLT, WriteRecord.keyN, Bool.or_eq_true, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq, UInt64.eq_iff_toNat_eq, UInt64.lt_iff_toNat_lt]
  constructor
  · rintro (h | ⟨h, h' | ⟨h'', h'⟩⟩) <;> omega
  · intro h
    by_cases hpp : a.pos.toNat < b.pos.toNat
    · exact Or.inl hpp
    · by_cases hpe : a.pos.toNat = b.pos.toNat
      · by_cases hvv : a.va.toNat < b.va.toNat
        · exact Or.inr ⟨hpe, Or.inl hvv⟩
        · by_cases hve : a.va.toNat = b.va.toNat
          · by_cases hll : a.len.toNat < b.len.toNat
            · exact Or.inr ⟨hpe, Or.inr ⟨hve, hll⟩⟩
            · exfalso; omega
          · exfalso; omega
      · exfalso; omega

theorem keyEq_iff_keyN (a b : WriteRecord) :
    a.keyEq b = true ↔ a.keyN = b.keyN := by
  have hp := UInt64.toNat_lt a.pos; have hq := UInt64.toNat_lt b.pos
  have hv := UInt64.toNat_lt a.va; have hw := UInt64.toNat_lt b.va
  have hl := UInt64.toNat_lt a.len; have hm := UInt64.toNat_lt b.len
  have hbc : a.keyEq b = true ↔ (a.pos = b.pos ∧ a.va = b.va) ∧ a.len = b.len := by
    simp [WriteRecord.keyEq, Bool.and_eq_true, beq_iff_eq]
  rw [hbc]
  constructor
  · rintro ⟨⟨h1, h2⟩, h3⟩
    have e1 := congrArg UInt64.toNat h1
    have e2 := congrArg UInt64.toNat h2
    have e3 := congrArg UInt64.toNat h3
    simp only [WriteRecord.keyN]
    omega
  · intro h
    simp only [WriteRecord.keyN] at h
    obtain ⟨e1, e2, e3⟩ := keyN_inj_nat hp hq hv hw hl hm h
    exact ⟨⟨UInt64.eq_iff_toNat_eq.2 e1, UInt64.eq_iff_toNat_eq.2 e2⟩,
      UInt64.eq_iff_toNat_eq.2 e3⟩

theorem keyLe_iff_keyN (a b : WriteRecord) :
    (a.keyLT b || a.keyEq b) = true ↔ a.keyN ≤ b.keyN := by
  rw [Bool.or_eq_true, keyLT_iff_keyN, keyEq_iff_keyN]
  omega

/-- The shipping merge keeps every left-list element. -/
theorem mergeRecords_mem_left {xs ys : List WriteRecord} {w : WriteRecord}
    (h : w ∈ xs) : w ∈ mergeRecords xs ys := by
  induction xs, ys using mergeRecords.induct with
  | case1 => cases h
  | case2 xs hne =>
    cases xs with
    | nil => exact (hne rfl).elim
    | cons x xs => simpa only [mergeRecords] using h
  | case3 x xs y ys hxy ih =>
    simp only [mergeRecords]
    rw [if_pos hxy]
    cases h with
    | head => exact List.Mem.head _
    | tail _ hm => exact List.Mem.tail _ (ih hm)
  | case4 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_pos hyx]
    exact List.Mem.tail _ (ih h)
  | case5 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_neg hyx]
    cases h with
    | head => exact List.Mem.head _
    | tail _ hm => exact List.Mem.tail _ (ih hm)

/-- Every element of the merge comes from one of the inputs. -/
theorem mergeRecords_mem_of {xs ys : List WriteRecord} {w : WriteRecord}
    (h : w ∈ mergeRecords xs ys) : w ∈ xs ∨ w ∈ ys := by
  induction xs, ys using mergeRecords.induct with
  | case1 =>
    simp only [mergeRecords] at h
    exact Or.inr h
  | case2 xs hne =>
    cases xs with
    | nil => exact (hne rfl).elim
    | cons x xs =>
      simp only [mergeRecords] at h
      exact Or.inl h
  | case3 x xs y ys hxy ih =>
    simp only [mergeRecords] at h
    rw [if_pos hxy] at h
    cases h with
    | head => exact Or.inl (List.Mem.head _)
    | tail _ hm => cases ih hm with
      | inl h1 => exact Or.inl (List.Mem.tail _ h1)
      | inr h2 => exact Or.inr h2
  | case4 x xs y ys hxy hyx ih =>
    simp only [mergeRecords] at h
    rw [if_neg hxy, if_pos hyx] at h
    cases h with
    | head => exact Or.inr (List.Mem.head _)
    | tail _ hm => cases ih hm with
      | inl h1 => exact Or.inl h1
      | inr h2 => exact Or.inr (List.Mem.tail _ h2)
  | case5 x xs y ys hxy hyx ih =>
    simp only [mergeRecords] at h
    rw [if_neg hxy, if_neg hyx] at h
    cases h with
    | head => exact Or.inl (List.Mem.head _)
    | tail _ hm => cases ih hm with
      | inl h1 => exact Or.inl (List.Mem.tail _ h1)
      | inr h2 => exact Or.inr (List.Mem.tail _ h2)

/-- Every right-list key survives the merge (the dedup keeps the left
    copy, so survival is up to key equality). -/
theorem mergeRecords_mem_right_key {xs ys : List WriteRecord} {w : WriteRecord}
    (h : w ∈ ys) : ∃ w' ∈ mergeRecords xs ys, w'.keyN = w.keyN := by
  induction xs, ys using mergeRecords.induct with
  | case1 =>
    simp only [mergeRecords]
    exact ⟨w, h, rfl⟩
  | case2 xs hne => cases h
  | case3 x xs y ys hxy ih =>
    simp only [mergeRecords]
    rw [if_pos hxy]
    obtain ⟨w', hw', hkey⟩ := ih h
    exact ⟨w', List.Mem.tail _ hw', hkey⟩
  | case4 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_pos hyx]
    cases List.mem_cons.1 h with
    | inl hEq =>
      subst hEq
      exact ⟨w, List.Mem.head _, rfl⟩
    | inr hm =>
      obtain ⟨w', hw', hkey⟩ := ih hm
      exact ⟨w', List.Mem.tail _ hw', hkey⟩
  | case5 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_neg hyx]
    cases List.mem_cons.1 h with
    | inl hEq =>
      subst hEq
      exact ⟨x, List.Mem.head _, by
        have h1 : ¬ x.keyN < w.keyN := fun hc => hxy ((keyLT_iff_keyN _ _).2 hc)
        have h2 : ¬ w.keyN < x.keyN := fun hc => hyx ((keyLT_iff_keyN _ _).2 hc)
        show x.keyN = w.keyN
        omega⟩
    | inr hm =>
      obtain ⟨w', hw', hkey⟩ := ih hm
      exact ⟨w', List.Mem.tail _ hw', hkey⟩

/-- The merge of two key-sorted lists is key-sorted. -/
theorem mergeRecords_sorted {xs ys : List WriteRecord}
    (hx : xs.Pairwise fun a b => a.keyN ≤ b.keyN)
    (hy : ys.Pairwise fun a b => a.keyN ≤ b.keyN) :
    (mergeRecords xs ys).Pairwise fun a b => a.keyN ≤ b.keyN := by
  induction xs, ys using mergeRecords.induct with
  | case1 => simpa only [mergeRecords] using hy
  | case2 xs hne =>
    cases xs with
    | nil => exact (hne rfl).elim
    | cons x xs => simpa only [mergeRecords] using hx
  | case3 x xs y ys hxy ih =>
    simp only [mergeRecords]
    rw [if_pos hxy]
    rw [List.pairwise_cons] at hx
    rw [List.pairwise_cons]
    refine ⟨?_, ih hx.2 hy⟩
    intro a ha
    have hxyN : x.keyN < y.keyN := (keyLT_iff_keyN _ _).1 hxy
    cases mergeRecords_mem_of ha with
    | inl h1 => exact hx.1 a h1
    | inr h2 =>
      cases List.mem_cons.1 h2 with
      | inl hEq => subst hEq; exact Nat.le_of_lt hxyN
      | inr hin =>
        exact Nat.le_trans (Nat.le_of_lt hxyN) ((List.pairwise_cons.1 hy).1 a hin)
  | case4 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_pos hyx]
    rw [List.pairwise_cons] at hy
    rw [List.pairwise_cons]
    refine ⟨?_, ih hx hy.2⟩
    intro a ha
    have hyxN : y.keyN < x.keyN := (keyLT_iff_keyN _ _).1 hyx
    cases mergeRecords_mem_of ha with
    | inl h1 =>
      cases List.mem_cons.1 h1 with
      | inl hEq => subst hEq; exact Nat.le_of_lt hyxN
      | inr hin =>
        exact Nat.le_trans (Nat.le_of_lt hyxN) ((List.pairwise_cons.1 hx).1 a hin)
    | inr h2 => exact hy.1 a h2
  | case5 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_neg hyx]
    rw [List.pairwise_cons] at hx hy
    rw [List.pairwise_cons]
    refine ⟨?_, ih hx.2 hy.2⟩
    intro a ha
    have hkey : x.keyN = y.keyN := by
      have h1 : ¬ x.keyN < y.keyN := fun hc => hxy ((keyLT_iff_keyN _ _).2 hc)
      have h2 : ¬ y.keyN < x.keyN := fun hc => hyx ((keyLT_iff_keyN _ _).2 hc)
      omega
    cases mergeRecords_mem_of ha with
    | inl h1 => exact hx.1 a h1
    | inr h2 => rw [hkey]; exact hy.1 a h2

/-- The merge of two key-sorted, key-duplicate-free lists has no duplicate
    keys (the dedup drops the right copy of an exact-key pair). -/
theorem mergeRecords_nodupKeys {xs ys : List WriteRecord}
    (hxs : xs.Pairwise fun a b => a.keyN ≤ b.keyN)
    (hys : ys.Pairwise fun a b => a.keyN ≤ b.keyN)
    (hxn : xs.Pairwise fun a b => a.keyN ≠ b.keyN)
    (hyn : ys.Pairwise fun a b => a.keyN ≠ b.keyN) :
    (mergeRecords xs ys).Pairwise fun a b => a.keyN ≠ b.keyN := by
  induction xs, ys using mergeRecords.induct with
  | case1 => simpa only [mergeRecords] using hyn
  | case2 xs hne =>
    cases xs with
    | nil => exact (hne rfl).elim
    | cons x xs => simpa only [mergeRecords] using hxn
  | case3 x xs y ys hxy ih =>
    simp only [mergeRecords]
    rw [if_pos hxy]
    rw [List.pairwise_cons] at hxs hxn
    rw [List.pairwise_cons]
    refine ⟨?_, ih hxs.2 hys hxn.2 hyn⟩
    intro a ha
    have hxyN : x.keyN < y.keyN := (keyLT_iff_keyN _ _).1 hxy
    cases mergeRecords_mem_of ha with
    | inl h1 => exact hxn.1 a h1
    | inr h2 =>
      cases List.mem_cons.1 h2 with
      | inl hEq => subst hEq; exact Nat.ne_of_lt hxyN
      | inr hin =>
        exact Nat.ne_of_lt
          (Nat.lt_of_lt_of_le hxyN ((List.pairwise_cons.1 hys).1 a hin))
  | case4 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_pos hyx]
    rw [List.pairwise_cons] at hys hyn
    rw [List.pairwise_cons]
    refine ⟨?_, ih hxs hys.2 hxn hyn.2⟩
    intro a ha
    have hyxN : y.keyN < x.keyN := (keyLT_iff_keyN _ _).1 hyx
    cases mergeRecords_mem_of ha with
    | inl h1 =>
      cases List.mem_cons.1 h1 with
      | inl hEq => subst hEq; exact Nat.ne_of_lt hyxN
      | inr hin =>
        exact Nat.ne_of_lt
          (Nat.lt_of_lt_of_le hyxN ((List.pairwise_cons.1 hxs).1 a hin))
    | inr h2 => exact hyn.1 a h2
  | case5 x xs y ys hxy hyx ih =>
    simp only [mergeRecords]
    rw [if_neg hxy, if_neg hyx]
    rw [List.pairwise_cons] at hxn hyn hxs hys
    rw [List.pairwise_cons]
    refine ⟨?_, ih hxs.2 hys.2 hxn.2 hyn.2⟩
    intro a ha
    have hkey : x.keyN = y.keyN := by
      have h1 : ¬ x.keyN < y.keyN := fun hc => hxy ((keyLT_iff_keyN _ _).2 hc)
      have h2 : ¬ y.keyN < x.keyN := fun hc => hyx ((keyLT_iff_keyN _ _).2 hc)
      omega
    cases mergeRecords_mem_of ha with
    | inl h1 => exact hxn.1 a h1
    | inr h2 => rw [hkey]; exact hyn.1 a h2

/-- The metadata-only record one `INDEX` entry decodes to (C2). -/
def IndexState.freshRecord (r : IndexRecord) : WriteRecord :=
  { pos := r.pos, va := r.va, data := ByteArray.empty, len := r.len.toUInt64,
    provenance := { streamType := PROXY_STREAM_TYPE } }

/-- The fresh-window payload list after the beyond-frontier partition and
    record conversion (what `mergeWindow` merges in). -/
def IndexState.freshRecords (recs : Array IndexRecord) (frontier : Position) :
    List WriteRecord :=
  ((recs.toList.partition fun r => decide (frontier < r.pos)).2.map IndexState.freshRecord).mergeSort
    fun a b => a.keyLT b || a.keyEq b

theorem IndexState.mergeWindow_records (st : IndexState) (win : IndexWindow)
    (recs : Array IndexRecord) (frontier : Position) :
    (st.mergeWindow win recs frontier).records
      = mergeRecords st.records (IndexState.freshRecords recs frontier) := rfl

/-- `mergeWindow` keeps the record list key-sorted (mergeIndex order
    invariant): the fresh window is `mergeSort`ed, then merged. -/
theorem IndexState.mergeWindow_sorted (st : IndexState) (win : IndexWindow)
    (recs : Array IndexRecord) (frontier : Position)
    (h : st.records.Pairwise fun a b => a.keyN ≤ b.keyN) :
    (st.mergeWindow win recs frontier).records.Pairwise fun a b => a.keyN ≤ b.keyN := by
  rw [IndexState.mergeWindow_records]
  apply mergeRecords_sorted h
  apply List.Pairwise.imp
    (R := fun (a b : WriteRecord) => (a.keyLT b || a.keyEq b) = true)
    (S := fun (a b : WriteRecord) => a.keyN ≤ b.keyN)
  · intro a b hab
    exact (keyLe_iff_keyN _ _).1 hab
  · apply List.pairwise_mergeSort
    · intro a b c hab hbc
      exact (keyLe_iff_keyN _ _).2
        (Nat.le_trans ((keyLe_iff_keyN _ _).1 hab) ((keyLe_iff_keyN _ _).1 hbc))
    · intro a b
      cases Nat.le_total a.keyN b.keyN with
      | inl hle =>
        have h1 : (a.keyLT b || a.keyEq b) = true := (keyLe_iff_keyN _ _).2 hle
        rw [h1]; exact Bool.true_or _
      | inr hle =>
        have h1 : (b.keyLT a || b.keyEq a) = true := (keyLe_iff_keyN _ _).2 hle
        rw [h1]; exact Bool.or_true _

/-- `mergeWindow` absorbs every in-frontier record of the window (dedup
    keeps the existing copy, so absorption is up to key equality). -/
theorem IndexState.mergeWindow_mem (st : IndexState) (win : IndexWindow)
    (recs : Array IndexRecord) (frontier : Position) (r : IndexRecord)
    (hr : r ∈ recs.toList) (hfr : r.pos ≤ frontier) :
    ∃ w ∈ (st.mergeWindow win recs frontier).records,
      w.pos = r.pos ∧ w.va = r.va ∧ w.len = r.len.toUInt64 := by
  rw [IndexState.mergeWindow_records]
  have hnot : decide (frontier < r.pos) = false := by
    rw [decide_eq_false_iff_not, UInt64.lt_iff_toNat_lt]
    have hfr' := UInt64.le_iff_toNat_le.mp hfr
    omega
  have hok : r ∈ (recs.toList.partition fun r => decide (frontier < r.pos)).2 := by
    rw [List.partition_eq_filter_filter]
    exact List.mem_filter.2 ⟨hr, by
      show (not ∘ fun r => decide (frontier < r.pos)) r = true
      simp only [Function.comp, hnot]; rfl⟩
  have hfresh : IndexState.freshRecord r ∈ IndexState.freshRecords recs frontier := by
    rw [IndexState.freshRecords, List.mem_mergeSort]
    exact List.mem_map.2 ⟨r, hok, rfl⟩
  obtain ⟨w', hw', hkey⟩ := mergeRecords_mem_right_key (xs := st.records) hfresh
  have hb1 := UInt64.toNat_lt w'.pos; have hb2 := UInt64.toNat_lt w'.va
  have hb3 := UInt64.toNat_lt w'.len
  have hc1 := UInt64.toNat_lt r.pos; have hc2 := UInt64.toNat_lt r.va
  have hrlen : r.len.toUInt64.toNat = r.len.toNat := by simp
  have hc3 : r.len.toNat < 2 ^ 64 := Nat.lt_trans (UInt32.toNat_lt r.len) (by omega)
  simp only [WriteRecord.keyN, IndexState.freshRecord] at hkey
  rw [hrlen] at hkey
  obtain ⟨hpr, hva, hln⟩ := keyN_inj_nat hb1 hc1 hb2 hc2 hb3 (by exact hc3) hkey
  exact ⟨w', hw', UInt64.eq_iff_toNat_eq.2 hpr, UInt64.eq_iff_toNat_eq.2 hva,
    UInt64.eq_iff_toNat_eq.2 (by rw [hln, hrlen])⟩

end Forensicator.Trace
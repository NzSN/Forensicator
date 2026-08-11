/- Forensicator.Pipeline — workflow orchestration (port of pipeline.rs):
   Dump → AddressSpace construction and dump-kind classification. -/
import Forensicator.Model.Dump
import Forensicator.Spec.AddressSpace

namespace Forensicator

inductive DumpKind where
  | FullMemory | StackOnly
  deriving Repr, DecidableEq, BEq

/-- Build the AddressSpace from a dump's memory regions (pipeline.rs:82).
    Overlapping/invalid regions are silently dropped (Rust discards the
    add_region error), so earlier regions win. -/
def buildAddressSpace (dump : Model.Dump) : Spec.AddressSpace :=
  dump.memoryRegions.foldl (init := Spec.AddressSpace.new 1000000) fun sp r =>
    match sp.addRegion { vaStart := r.vaStart, size := r.size, data := r.data
                         protection := r.protection, state := r.state
                         classification := r.regionClass.getD .Other } with
    | .ok sp' => sp'
    | .error _ => sp

/-- Heuristic dump-kind classification (pipeline.rs:113). -/
def classifyDump (dump : Model.Dump) : DumpKind :=
  let total := dump.memoryRegions.foldl (fun acc r => acc + r.size.toNat) 0
  if total ≥ 64 * 1024 * 1024 then .FullMemory else .StackOnly

/-- The constructed space always satisfies the spec invariant
    (Snapshot.tla SnapshotsAreModels, space half): each addRegion either
    preserves WellFormed or is dropped. -/
theorem buildAddressSpace_wellFormed (dump : Model.Dump) :
    Spec.WellFormed (buildAddressSpace dump).regions := by
  unfold buildAddressSpace
  have step_pres : ∀ (sp : Spec.AddressSpace) (r : Model.MemoryRegionInfo),
      Spec.WellFormed sp.regions →
      Spec.WellFormed ((match sp.addRegion
          { vaStart := r.vaStart, size := r.size, data := r.data
            protection := r.protection, state := r.state
            classification := r.regionClass.getD .Other } with
        | .ok sp' => sp'
        | .error _ => sp)).regions := by
    intro sp r hwf
    split
    · rename_i sp' hok
      exact Spec.AddressSpace.addRegion_preserves hwf hok
    · exact hwf
  suffices ∀ (rs : List Model.MemoryRegionInfo) (sp : Spec.AddressSpace),
      Spec.WellFormed sp.regions →
      Spec.WellFormed ((rs.foldl (fun sp r =>
        match sp.addRegion { vaStart := r.vaStart, size := r.size, data := r.data
                             protection := r.protection, state := r.state
                             classification := r.regionClass.getD .Other } with
        | .ok sp' => sp'
        | .error _ => sp) sp)).regions by
    exact this dump.memoryRegions _ True.intro
  intro rs
  induction rs with
  | nil => intro sp h; exact h
  | cons x xs ih =>
    intro sp h
    rw [List.foldl_cons]
    exact ih _ (step_pres sp x h)

end Forensicator

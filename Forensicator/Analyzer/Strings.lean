/- Forensicator.Analyzer.Strings — null-terminated string scanner
   (analyzer/strings.rs port: ASCII + UTF-16LE). -/
import Forensicator.Analyzer.Scan
import Forensicator.Util.Text
import Forensicator.Util.Bytes

namespace Forensicator.Analyzer.Strings

open Forensicator.Model Forensicator.Spec

structure Config where
  minLen : Nat := 4
  maxLen : Nat := 1024
  maxNonprintableRatio : Float := 0.2
  maxScanPerRegion : Nat := 4096

private def isNonprint (b : UInt8) : Bool :=
  !(b ≥ 0x20 && b ≤ 0x7E) && b != 0x09 && b != 0x0A && b != 0x0D

/-- Returns (stopIndex, nonprintCount, byteCount) on ANY exit, matching
    Rust's loop; the caller checks the terminator (a string whose NUL sits
    exactly at the max_len boundary is valid in Rust). -/
private def collectAscii (cfg : Config) (data : ByteArray) (fuel i : Nat)
    (nonprint count : Nat) : Nat × Nat × Nat :=
  match fuel with
  | 0 => (i, nonprint, count)
  | fuel + 1 =>
    if i < data.size && count < cfg.maxLen then
      let b := data.get! i
      if b == 0 then (i, nonprint, count)
      else collectAscii cfg data fuel (i + 1) (nonprint + (if isNonprint b then 1 else 0)) (count + 1)
    else (i, nonprint, count)

private def tryAscii (cfg : Config) (data : ByteArray) (baseVa : VA) (start : Nat) :
    Option StructString :=
  let (stop, nonprint, len) :=
    collectAscii cfg data (min cfg.maxLen (data.size - start) + 1) start 0 0
  if stop ≥ data.size || data.get! stop != 0 then none
  else if len < cfg.minLen then none
  else
    let ratio := Float.ofNat nonprint / Float.ofNat (max len 1)
    if ratio > cfg.maxNonprintableRatio then none
    else some { va := baseVa + UInt64.ofNat start, byteLen := len
                encoding := .Ascii
                content := fromUTF8Lossy (data.extract start stop)
                confidence := 1.0 - ratio }

private def collectUtf16 (cfg : Config) (data : ByteArray) (fuel i : Nat)
    (nonprint ucount : Nat) : Nat × Nat × Nat :=
  match fuel with
  | 0 => (i, nonprint, ucount)
  | fuel + 1 =>
    if i + 1 < data.size && ucount * 2 < cfg.maxLen then
      let w := readU16leAt data i
      if w == 0 then (i, nonprint, ucount)
      else
        let np := nonprint + (if w.toNat < 0x20 && w != 0x09 && w != 0x0A && w != 0x0D then 1 else 0)
        collectUtf16 cfg data fuel (i + 2) np (ucount + 1)
    else (i, nonprint, ucount)

private def tryUtf16Le (cfg : Config) (data : ByteArray) (baseVa : VA) (start : Nat) :
    Option StructString :=
  let (stop, nonprint, ulen) :=
    collectUtf16 cfg data (min (cfg.maxLen / 2 + 1) ((data.size - start) / 2) + 1) start 0 0
  if stop + 1 ≥ data.size || readU16leAt data stop != 0 then none
  else if ulen < cfg.minLen then none
  else
    let ratio := Float.ofNat nonprint / Float.ofNat (max ulen 1)
    if ratio > cfg.maxNonprintableRatio then none
    else
      let units := (List.range ulen).map fun k => readU16leAt data (start + 2 * k)
      some { va := baseVa + UInt64.ofNat start, byteLen := ulen * 2
             encoding := .Utf16Le
             content := utf16Lossy units
             confidence := 1.0 - ratio }

private def detectGo (cfg : Config) (region : AddressRegion) (fuel i : Nat)
    (acc : List StructString) : List StructString :=
  let scanLen := min region.data.size cfg.maxScanPerRegion
  match fuel with
  | 0 => acc
  | fuel + 1 =>
    if i < scanLen then
      match tryAscii cfg region.data region.vaStart i with
      | some s =>
        if s.byteLen ≥ cfg.minLen then detectGo cfg region fuel (i + s.byteLen + 1) (acc ++ [s])
        else detectGo cfg region fuel (i + 1) acc
      | none =>
        if i + 2 ≤ region.data.size then
          match tryUtf16Le cfg region.data region.vaStart i with
          | some s =>
            if s.byteLen ≥ cfg.minLen then detectGo cfg region fuel (i + s.byteLen + 2) (acc ++ [s])
            else detectGo cfg region fuel (i + 2) acc
          | none => detectGo cfg region fuel (i + 1) acc
        else detectGo cfg region fuel (i + 1) acc
    else acc

/-- Scans committed memory for null-terminated strings (ASCII, UTF-16LE). -/
def analyzer (cfg : Config := {}) : Analyzer where
  name := "strings"
  description := "Scans committed memory for null-terminated strings (ASCII, UTF-16LE)"
  run _dump space :=
    { AnalyzerOutput.new "strings" with
      strings := space.regions.foldl (init := []) fun acc region =>
        if region.classification == .Other then acc
        else acc ++ detectGo cfg region (min region.data.size cfg.maxScanPerRegion + 1) 0 [] }

end Forensicator.Analyzer.Strings

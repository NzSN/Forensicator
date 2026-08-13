/- Forensicator.Trace.Proto — wire protocol v1 (design §D6) codec, pure and
   total. Mirrors `ttfx-proxy`'s `proto.rs` byte-for-byte: length-prefixed
   little-endian frames `body_len u32, tag u32, payload` where `body_len`
   counts tag + payload bytes.

   Encode is client→proxy requests only (the proxy encodes responses);
   decode is incremental (`decodeFrame` over a growable buffer) plus pure
   payload parsers. Framing violations and unknown tags are hard errors —
   the client treats them as session-fatal (fail closed, plan §C4). Golden
   frame vectors in `Test/Spec.lean` pin the exact bytes against the Rust
   tests in the proxy's `proto.rs`. -/
import Forensicator.Basic
import Forensicator.Util.Bytes
import Forensicator.Util.Text

namespace Forensicator.Trace

/-- Protocol version both sides must agree on (proxy rejects on mismatch). -/
def protoVersion : UInt32 := 1

def tagHello : UInt32 := 1
def tagHelloAck : UInt32 := 2
def tagWritesIndex : UInt32 := 3
def tagIndex : UInt32 := 4
def tagReadAt : UInt32 := 5
def tagPiece : UInt32 := 6
def tagInfo : UInt32 := 7
def tagThreads : UInt32 := 8
def tagEvents : UInt32 := 9
def tagClose : UInt32 := 10
def tagError : UInt32 := 11

/-- PIECE status: page committed and bytes follow. -/
def pieceOk : UInt32 := 0
/-- PIECE status: page not committed at the requested position. -/
def pieceNotCommitted : UInt32 := 1

/-- Reject absurd frames early (mirrors the proxy's MAX_FRAME_BODY). -/
def maxFrameBody : Nat := 512 * 1024 * 1024

/-- THREADS end sentinel for an open interval (.ttfx §5.4 OPEN_END). -/
def openEnd : UInt64 := 0xFFFFFFFFFFFFFFFF

-- ── LE writers ──────────────────────────────────────────────────────

/-- Append 4 LE bytes. -/
def pushU32le (out : ByteArray) (v : UInt32) : ByteArray :=
  out.push v.toUInt8 |>.push (v >>> 8).toUInt8
    |>.push (v >>> 16).toUInt8 |>.push (v >>> 24).toUInt8

/-- Append 8 LE bytes. -/
def pushU64le (out : ByteArray) (v : UInt64) : ByteArray :=
  out.push v.toUInt8 |>.push (v >>> 8).toUInt8
    |>.push (v >>> 16).toUInt8 |>.push (v >>> 24).toUInt8
    |>.push (v >>> 32).toUInt8 |>.push (v >>> 40).toUInt8
    |>.push (v >>> 48).toUInt8 |>.push (v >>> 56).toUInt8

/-- Wrap a payload in a frame (`body_len` = tag + payload bytes). -/
def frame (tag : UInt32) (payload : ByteArray) : ByteArray :=
  pushU32le (pushU32le ByteArray.empty (UInt64.ofNat (payload.size + 4)).toUInt32) tag
    ++ payload

-- ── Requests (client → proxy) ───────────────────────────────────────

/-- One write-index entry: write metadata, no payload (design D1). -/
structure IndexRecord where
  pos : Position
  va : VA
  len : UInt32
  deriving Repr, DecidableEq, BEq, Inhabited

/-- A thread lifetime record (THREADS payload). -/
structure RawThread where
  id : UInt32
  start : Position
  stop : Option Position
  deriving Repr, DecidableEq, BEq, Inhabited

/-- A trace event record (EVENTS payload; .ttfx §5.3 kinds). -/
inductive RawEvent where
  | exception (pos : Position) (code : UInt32) (address : VA) (threadId : UInt32)
  | moduleLoad (pos : Position) (base : VA) (size : UInt64) (name : String)
  | moduleUnload (pos : Position) (base : VA)
  deriving Repr, DecidableEq, BEq, Inhabited

inductive Request where
  | hello (clientVersion : UInt32)
  | writesIndex (vaLo vaHi : VA) (t1 t2 : Position)
  | readAt (pos : Position) (va : VA) (len : UInt32)
  | info
  | close
  deriving Repr

def Request.tag : Request → UInt32
  | .hello _ => tagHello
  | .writesIndex .. => tagWritesIndex
  | .readAt .. => tagReadAt
  | .info => tagInfo
  | .close => tagClose

def Request.payload : Request → ByteArray
  | .hello v => pushU32le ByteArray.empty v
  | .writesIndex lo hi t1 t2 =>
    pushU64le (pushU64le (pushU64le (pushU64le ByteArray.empty lo) hi) t1) t2
  | .readAt pos va len =>
    pushU32le (pushU64le (pushU64le ByteArray.empty pos) va) len
  | .info => ByteArray.empty
  | .close => ByteArray.empty

/-- Encode one request frame. -/
def Request.encode (r : Request) : ByteArray := frame r.tag r.payload

-- ── Incremental frame decode ────────────────────────────────────────

/-- Result of attempting to peel one frame off the front of a buffer. -/
inductive FrameDecode where
  | needMore
  | bad (msg : String)
  | frame (tag : UInt32) (payload : ByteArray) (consumed : Nat)

/-- Peel one frame off `buf`. `needMore` = not enough bytes yet (the
    proxy's truncated-read error maps here: the client just waits for more
    bytes); `bad` = framing violation, session-fatal. The length prefix is
    validated as soon as its 4 bytes are available — an absurd length is
    rejected before the body is buffered (the proxy's MAX_FRAME_BODY guard). -/
def decodeFrame (buf : ByteArray) : FrameDecode :=
  if buf.size < 4 then .needMore
  else
    let bodyLen := (readU32leAt buf 0).toNat
    if bodyLen < 4 || bodyLen > maxFrameBody then
      .bad s!"frame body length {bodyLen} out of range"
    else if buf.size < 4 + bodyLen then .needMore
    else .frame (readU32leAt buf 4) (buf.extract 8 (4 + bodyLen)) (4 + bodyLen)

-- ── Responses (proxy → client) ──────────────────────────────────────

inductive PieceStatus where
  | ok | notCommitted
  deriving Repr, DecidableEq, BEq, Inhabited

inductive Response where
  | helloAck (proxyVersion : UInt32) (frontier : Position)
  | index (records : Array IndexRecord)
  | piece (status : PieceStatus) (bytes : ByteArray)
  | threads (list : Array RawThread)
  | events (list : Array RawEvent)
  | error (msg : String)
  deriving BEq

/-- Parse a frame payload by tag. Hard error on any shape violation. -/
def parseResponse (tag : UInt32) (payload : ByteArray) : Except String Response :=
  if tag == tagHelloAck then
    if payload.size == 12 then
      .ok (.helloAck (readU32leAt payload 0) (readU64leAt payload 4))
    else .error s!"HELLO_ACK: expected 12 payload bytes, got {payload.size}"
  else if tag == tagIndex then
    if payload.size ≥ 8 then
      let cnt := (readU64leAt payload 0).toNat
      if payload.size == 8 + 24 * cnt then
        let recs := (List.range cnt).toArray.map fun i =>
          let off := 8 + 24 * i
          ({ pos := readU64leAt payload off
             va := readU64leAt payload (off + 8)
             len := readU32leAt payload (off + 16) } : IndexRecord)
        .ok (.index recs)
      else .error s!"INDEX: size {payload.size} ≠ 8 + 24 × {cnt}"
    else .error "INDEX: payload under 8 bytes"
  else if tag == tagPiece then
    if payload.size ≥ 8 then
      let status := readU32leAt payload 0
      let len := (readU32leAt payload 4).toNat
      if payload.size == 8 + len then
        if status == pieceOk then .ok (.piece .ok (payload.extract 8 (8 + len)))
        else if status == pieceNotCommitted then
          .ok (.piece .notCommitted (payload.extract 8 (8 + len)))
        else .error s!"PIECE: unknown status {status}"
      else .error s!"PIECE: size {payload.size} ≠ 8 + {len}"
    else .error "PIECE: payload under 8 bytes"
  else if tag == tagThreads then
    if payload.size ≥ 8 then
      let cnt := (readU64leAt payload 0).toNat
      if payload.size == 8 + 24 * cnt then
        let ts := (List.range cnt).toArray.map fun i =>
          let off := 8 + 24 * i
          let endRaw := readU64leAt payload (off + 16)
          ({ id := readU32leAt payload off
             start := readU64leAt payload (off + 8)
             stop := if endRaw == openEnd then none else some endRaw } : RawThread)
        .ok (.threads ts)
      else .error s!"THREADS: size {payload.size} ≠ 8 + 24 × {cnt}"
    else .error "THREADS: payload under 8 bytes"
  else if tag == tagEvents then
    if payload.size ≥ 8 then
      let cnt := (readU64leAt payload 0).toNat
      if payload.size ≥ 8 + 48 * cnt then
        let parsed : Except String (Array RawEvent) :=
          (List.range cnt).foldlM (init := #[]) fun evs i =>
            let off := 8 + 48 * i
            let pos := readU64leAt payload off
            let kind := readU32leAt payload (off + 8)
            let code := readU32leAt payload (off + 12)
            let address := readU64leAt payload (off + 16)
            let threadId := readU32leAt payload (off + 24)
            let size := readU64leAt payload (off + 28)
            let nameLen := (readU32leAt payload (off + 36)).toNat
            let nameOff := (readU32leAt payload (off + 40)).toNat
            if nameOff + nameLen ≤ payload.size then
              let name := fromUTF8Lossy (payload.extract nameOff (nameOff + nameLen))
              if kind == 0 then .ok (evs.push (.exception pos code address threadId))
              else if kind == 1 then .ok (evs.push (.moduleLoad pos address size name))
              else if kind == 2 then .ok (evs.push (.moduleUnload pos address))
              else .error s!"EVENTS: unknown kind {kind}"
            else .error s!"EVENTS: name [{nameOff}, {nameOff + nameLen}) out of bounds"
        parsed.map Response.events
      else .error s!"EVENTS: size {payload.size} < 8 + 48 × {cnt}"
    else .error "EVENTS: payload under 8 bytes"
  else if tag == tagError then
    .ok (.error (fromUTF8Lossy payload))
  else .error s!"unknown tag {tag}"

end Forensicator.Trace

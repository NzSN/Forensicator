---- MODULE Recover ----
EXTENDS Integers, Sequences, FiniteSets

\* S3 Structure Recovery — models the 6 detectors as independent state machines.
\* Each detector produces typed outputs from AddressSpace + PointerGraph data.
\* Composed in Forensicator.tla via INSTANCE.

MaxStrs  == 2
MaxVTbls == 2
MaxLists == 2
MaxArrs  == 2
MaxChnks == 2
MaxShps  == 4

\* ---- Detector output variables ----
\* Each detector stores its results as parallel sequences.
\* confidence is in 0..10 representing 0.0..1.0

\* Strings: (va, encoding, confidence)
\* encoding: 0=ASCII, 1=UTF16LE, 2=UTF16BE
VARIABLES
    r_str_va, r_str_enc, r_str_conf,
    \* VTables: (va, method_count, confidence)
    r_vtable_va, r_vtable_cnt, r_vtable_conf,
    \* LinkedLists: (head_va, length, confidence)
    r_list_head, r_list_len, r_list_conf,
    \* Arrays: (start_va, element_size, count, confidence)
    r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
    \* Chunks: (va_start, size, is_free, confidence)
    r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
    \* ShapeGroups: (id, member_count)
    r_shape_id, r_shape_cnt

\* ---- Invariants ----

StrInv == /\ Len(r_str_va)  <= MaxStrs
          /\ Len(r_str_enc)  = Len(r_str_va)
          /\ Len(r_str_conf) = Len(r_str_va)
          /\ \A i \in 1..Len(r_str_va): r_str_enc[i] \in {0,1,2}
          /\ \A i \in 1..Len(r_str_va): r_str_conf[i] \in 0..10

VTableInv == /\ Len(r_vtable_va)  <= MaxVTbls
             /\ Len(r_vtable_cnt)  = Len(r_vtable_va)
             /\ Len(r_vtable_conf) = Len(r_vtable_va)
             /\ \A i \in 1..Len(r_vtable_va): r_vtable_cnt[i] >= 3
             /\ \A i \in 1..Len(r_vtable_va): r_vtable_conf[i] \in 0..10

ListInv == /\ Len(r_list_head) <= MaxLists
           /\ Len(r_list_len)   = Len(r_list_head)
           /\ Len(r_list_conf)  = Len(r_list_head)
           /\ \A i \in 1..Len(r_list_head): r_list_len[i] >= 3
           /\ \A i \in 1..Len(r_list_head): r_list_conf[i] \in 0..10

ArrayInv == /\ Len(r_arr_start) <= MaxArrs
            /\ Len(r_arr_esz)   = Len(r_arr_start)
            /\ Len(r_arr_cnt)   = Len(r_arr_start)
            /\ Len(r_arr_conf)  = Len(r_arr_start)
            /\ \A i \in 1..Len(r_arr_start): r_arr_cnt[i] >= 3
            /\ \A i \in 1..Len(r_arr_start): r_arr_conf[i] \in 0..10

ChunkInv == /\ Len(r_chunk_va)   <= MaxChnks
            /\ Len(r_chunk_sz)    = Len(r_chunk_va)
            /\ Len(r_chunk_free)  = Len(r_chunk_va)
            /\ Len(r_chunk_conf)  = Len(r_chunk_va)
            /\ \A i \in 1..Len(r_chunk_va): r_chunk_free[i] \in {0,1}

ShapeInv == /\ Len(r_shape_id)  <= MaxShps
            /\ Len(r_shape_cnt)  = Len(r_shape_id)
            /\ \A i \in 1..Len(r_shape_id): r_shape_cnt[i] >= 1

RecoverInvariant ==
    /\ StrInv /\ VTableInv /\ ListInv /\ ArrayInv /\ ChunkInv /\ ShapeInv

\* ---- Operations ----

AddString(va, enc, conf) ==
    /\ Len(r_str_va) < MaxStrs /\ enc \in {0,1,2} /\ conf \in 0..10
    /\ r_str_va'   = Append(r_str_va, va)
    /\ r_str_enc'  = Append(r_str_enc, enc)
    /\ r_str_conf' = Append(r_str_conf, conf)
    /\ UNCHANGED <<r_vtable_va, r_vtable_cnt, r_vtable_conf,
                   r_list_head, r_list_len, r_list_conf,
                   r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
                   r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
                   r_shape_id, r_shape_cnt>>

AddVTable(va, cnt, conf) ==
    /\ Len(r_vtable_va) < MaxVTbls /\ cnt >= 3 /\ conf \in 0..10
    /\ r_vtable_va'   = Append(r_vtable_va, va)
    /\ r_vtable_cnt'  = Append(r_vtable_cnt, cnt)
    /\ r_vtable_conf' = Append(r_vtable_conf, conf)
    /\ UNCHANGED <<r_str_va, r_str_enc, r_str_conf,
                   r_list_head, r_list_len, r_list_conf,
                   r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
                   r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
                   r_shape_id, r_shape_cnt>>

AddList(head_va, len, conf) ==
    /\ Len(r_list_head) < MaxLists /\ len >= 3 /\ conf \in 0..10
    /\ r_list_head' = Append(r_list_head, head_va)
    /\ r_list_len'  = Append(r_list_len, len)
    /\ r_list_conf' = Append(r_list_conf, conf)
    /\ UNCHANGED <<r_str_va, r_str_enc, r_str_conf,
                   r_vtable_va, r_vtable_cnt, r_vtable_conf,
                   r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
                   r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
                   r_shape_id, r_shape_cnt>>

AddArray(start, esz, cnt, conf) ==
    /\ Len(r_arr_start) < MaxArrs /\ cnt >= 3 /\ conf \in 0..10
    /\ r_arr_start' = Append(r_arr_start, start)
    /\ r_arr_esz'   = Append(r_arr_esz, esz)
    /\ r_arr_cnt'   = Append(r_arr_cnt, cnt)
    /\ r_arr_conf'  = Append(r_arr_conf, conf)
    /\ UNCHANGED <<r_str_va, r_str_enc, r_str_conf,
                   r_vtable_va, r_vtable_cnt, r_vtable_conf,
                   r_list_head, r_list_len, r_list_conf,
                   r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
                   r_shape_id, r_shape_cnt>>

AddChunk(va_start, sz, is_free, conf) ==
    /\ Len(r_chunk_va) < MaxChnks /\ conf \in 0..10
    /\ r_chunk_va'   = Append(r_chunk_va, va_start)
    /\ r_chunk_sz'   = Append(r_chunk_sz, sz)
    /\ r_chunk_free' = Append(r_chunk_free, is_free)
    /\ r_chunk_conf' = Append(r_chunk_conf, conf)
    /\ UNCHANGED <<r_str_va, r_str_enc, r_str_conf,
                   r_vtable_va, r_vtable_cnt, r_vtable_conf,
                   r_list_head, r_list_len, r_list_conf,
                   r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
                   r_shape_id, r_shape_cnt>>

AddShape(id, cnt) ==
    /\ Len(r_shape_id) < MaxShps /\ cnt >= 1
    /\ r_shape_id'  = Append(r_shape_id, id)
    /\ r_shape_cnt' = Append(r_shape_cnt, cnt)
    /\ UNCHANGED <<r_str_va, r_str_enc, r_str_conf,
                   r_vtable_va, r_vtable_cnt, r_vtable_conf,
                   r_list_head, r_list_len, r_list_conf,
                   r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
                   r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf>>

Init ==
    /\ r_str_va = <<>> /\ r_str_enc = <<>> /\ r_str_conf = <<>>
    /\ r_vtable_va = <<>> /\ r_vtable_cnt = <<>> /\ r_vtable_conf = <<>>
    /\ r_list_head = <<>> /\ r_list_len = <<>> /\ r_list_conf = <<>>
    /\ r_arr_start = <<>> /\ r_arr_esz = <<>> /\ r_arr_cnt = <<>> /\ r_arr_conf = <<>>
    /\ r_chunk_va = <<>> /\ r_chunk_sz = <<>> /\ r_chunk_free = <<>> /\ r_chunk_conf = <<>>
    /\ r_shape_id = <<>> /\ r_shape_cnt = <<>>

Next ==
    \/ \E va \in 0..255: \E enc \in 0..2: \E conf \in 0..10:
         AddString(va, enc, conf)
    \/ \E va \in 0..255: \E cnt \in 3..10: \E conf \in 0..10:
         AddVTable(va, cnt, conf)
    \/ \E head \in 0..255: \E len \in 3..10: \E conf \in 0..10:
         AddList(head, len, conf)
    \/ \E start \in 0..255: \E esz \in 1..16: \E cnt \in 3..10: \E conf \in 0..10:
         AddArray(start, esz, cnt, conf)
    \/ \E va \in 0..255: \E sz \in 1..64: \E free \in {0,1}: \E conf \in 0..10:
         AddChunk(va, sz, free, conf)
    \/ \E id \in 0..3: \E cnt \in 1..4:
         AddShape(id, cnt)

\* @type: <<Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int), Seq(Int)>>;
Vars == <<r_str_va, r_str_enc, r_str_conf,
          r_vtable_va, r_vtable_cnt, r_vtable_conf,
          r_list_head, r_list_len, r_list_conf,
          r_arr_start, r_arr_esz, r_arr_cnt, r_arr_conf,
          r_chunk_va, r_chunk_sz, r_chunk_free, r_chunk_conf,
          r_shape_id, r_shape_cnt>>

Spec == Init /\ [][Next]_Vars

====

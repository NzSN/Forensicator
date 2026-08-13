# Lazy Trace Proxy — implementation plan (2026-08-12)

> **Lean-port note (2026-08-13):** Rust-era document — the implementation is
> now the Lean 4 tree (`Forensicator/`, `Main.lean`, `Test/`; module map in
> `docs/arch/README.md`). Rust references below (`forensicator-core/src/…`,
> `cargo`, `tests/mbt_*`) are historical and kept as written for the record.

Implements `docs/superpowers/specs/2026-08-12-lazy-trace-proxy-design.md`
in the Rust worktree (client) + a new Windows crate `D:\Codebase\JigsawSpawner`
(proxy — the design's `D:\Repositories\TTFX` path had drifted; the proxy
landed as a standalone crate reusing the TTFX backend code).

## Tasks

- [x] 1. **Proxy crate** at `D:\Codebase\JigsawSpawner`: `Cargo.toml`,
      `src/position.rs` (verbatim from ttfx-extract), `src/backend.rs` +
      `src/backend/dbgeng.rs` (trimmed to the proxy's needs: channel A
      threads/events/position-range, channel C `write_index` metadata-only,
      channel B `read_at` with seek-skip), `src/proto.rs` (protocol v1
      frame codec, byte-tested — 10 tests), `src/main.rs` (stdio loop:
      HELLO/HELLO_ACK/THREADS/EVENTS/WRITES_INDEX/INDEX/READ_AT/PIECE/
      INFO/CLOSE/ERROR; `TerminateProcess` at exit). Engine DLLs staged
      from the TTFX build (incl. `ttd/`, `winext/` — the E_INVALIDARG
      gotcha without them).
- [x] 2. **Proxy verified** on windows-dev: `smoke.py` speaks the protocol
      against `hostname01.run` — handshake, 10 MB full-space INDEX,
      positioned page reads (ok + not-committed), INFO, clean CLOSE.
- [x] 3. **Client — `forensicator-core/src/trace_client.rs`**: hand-mirrored
      frame codec (byte-exact tests pin the same bytes as the proxy's),
      `ProxyClient` (spawn via interop with `/mnt/...` → `D:\...` path
      conversion, or via `spawn_remote` over ssh — the stdio protocol rides
      the ssh pipes, keeping the library networking-free), HELLO handshake,
      THREADS/EVENTS parsing with Timeline invariants → anomalies, ERROR
      frames are session-fatal. Tests run over an in-process UnixStream
      mock server (protocol round-trip — conformance item 1).
- [x] 4. **Client — `forensicator-core/src/model/source.rs`**: `MemorySource`
      seam (D5), `JigsawCache` (D2 pieces with validity intervals, LRU,
      fetched index windows), `LazyTrace` (value_at / write_bytes /
      regions_at over the proxy), `merge_index` (window merge, dedup,
      "index window gap" + beyond-frontier anomalies), `pages_covering`
      with a fan-out limit → full-space window for wide ranges.
- [x] 5. **`Trace` seam** (`model/trace.rs`): `init_mem` → `source`;
      `value_at` / `writes_between` / `snapshot` / `write_bytes` branch on
      the source (eager semantics byte-identical; lazy path document-deviant
      in one place: the four methods take `&mut self` — interior mutability
      would be needed for `&self` + ref-returning `writes_between`, and
      every lazy caller has `&mut` already). `last_writer` stays `&self`.
      `WriteRecord` gained a `len` field (the lazy index is metadata-only;
      `end_va` must be exact).
- [x] 6. **CLI**: `shell --proxy <trace.run>` / `load --proxy` attach,
      lazy banner, `writes` displays payloads resolved through the cache
      (`write_bytes_at`), `cmd_trace` uses `source.eager_region_count()`.
- [x] 7. **Cache property test** (conformance item 4): deterministic random
      (fetch, query) pairs — cached == refetched == model ground truth
      (12 source tests incl. absent pieces, LRU, validity bounds,
      snapshot closure, module pages, gap anomalies).
- [x] 8. **Golden gate** `tests/ttfx_proxy.rs` + `scripts/conformance-proxy.sh`
      (conformance item 2): opt-in via env; the script builds the proxy on
      windows-dev, stages the eager `.ttfx` locally, runs the test through
      `spawn_remote` (ssh). **PASS on the fixture**: 435,030 writes, 0
      payload mismatches; 130/130 write-position samples equal + 27
      strictly-exceed; 8,960 closure samples (104 wide-stale + 50
      page-lifecycle, both documented classes); 157,459 never-captured
      bytes readable via proxy (64/64 probed); snapshot materializes
      66 regions / 20 modules. Gate runs in ~75 s (vs the eager
      extraction's ~46 s one-time cost; interactive sessions pay nothing).
- [x] 9. **Two engine semantics discovered and encoded** (probe-verified on
      the fixture):
      - **Off-by-one**: a TTD write at position `p` is materialized at
        engine position `p+1` (state at `p` is pre-instruction). The lazy
        path reproduces the eager model's `pos ≤ t` convention by fetching
        at `t+1` (clamped at the frontier — a write exactly AT the
        frontier is the one documented position-level divergence).
      - **P3 unreadable pages**: TTD records writes on pages the engine can
        never materialize at any position (72 on the fixture). The lazy
        path serves them as absent pieces (design D3 parity with the eager
        path's missing regions) — `write_bytes` falls back to the next
        write's position (with an overlap guard) before giving up.
      - **Page-lifecycle divergence** (new finding): some pages' content
        changes without write records (free + recommit — Timeline.tla has
        no free op). The eager model shows the stale write value; the
        index-based cache validity rule (D2) can likewise serve stale bytes
        across the lifecycle break. Both paths documented; the gate
        classifies these via a raw (cache-bypassing) probe at the write's
        post-state.
- [x] 10. Full local suite green: 279 core lib tests + 7 CLI + MBT skips,
      clippy-clean (new files), `cargo fmt`.

## Deferred (phase-5 decision point)

- **Lean-side client**: not implemented. The protocol is pinned by
  byte-exact tests on both sides; the Lean client would be stdio-only via
  `IO.Process` (no networking in the library — preserved). Revisit after
  the seek-cost measurement on a multi-minute renderer trace (design risk 1).
- `DUMP CACHE` (persist the jigsaw into a partial `.ttfx`, design D8): v1.1.
- Position-windowed index fetches (D1's `t1/t2` trimming): the client
  currently requests `[0, frontier]` per window because validity needs
  `W_next`; the protocol fields stay for future trimming.

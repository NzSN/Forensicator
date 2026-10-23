# Native MCP server

Expose the capture-oriented forensic operations through `forensicator mcp`
using newline-delimited JSON-RPC over stdio. Keep the implementation in Lean,
with no package dependencies and no subprocess wrapper around the CLI.

- [x] Share existing inspect/analyze JSON and artifact matching with the CLI.
- [x] Add a total, bounded JSON request parser and MCP lifecycle/dispatch.
- [x] Expose inspect, analyze, match, and list_plugins with validated schemas.
- [x] Test protocol errors, transport framing, and CLI/result parity.
- [x] Document client configuration, supported versions, and limits.

Target MCP revisions: 2025-11-25 and 2025-06-18, with text-only result
compatibility for 2024-11-05. The 2026-07-28 stateless protocol is outside
this change; clients that support legacy initialization can negotiate one of
the supported revisions. Trace sessions remain available through the shell.

Validation: `lake build`, guard suite, deterministic MCP integration, execution
and stack shell checks, and the golden gate when `Case/golden` is available.
No dump or artifact is sent to a remote service by the server.

Completed 2026-10-23. Build, guard suite, 76 MCP integration checks, 14 execution
shell checks, and 10 stack shell checks pass. The golden gate reports missing
`Case/golden`; private minidump fuzz and live proxy qualification were not run.
See `CHECKPOINTS.md` for the retained implementation and verification record.

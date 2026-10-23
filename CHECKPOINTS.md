# Checkpoints

## 2026-10-23 — native MCP server

Implemented a native, dependency-free Lean MCP server, launched with
`forensicator mcp`. The work builds on `b0de49f` on `master`.

### Delivered

- Four read-only capture tools: `inspect`, `analyze`, `match`, and
  `list_plugins`. Tool schemas validate required fields, types, analyzer
  names, artifact selections, and unexpected arguments before file access.
- Initialization-based MCP revisions `2025-11-25`, `2025-06-18`, and
  `2024-11-05`; initialization, ping, tool discovery/calls, exact request IDs,
  and silent notifications. The supported 2025 revisions return structured
  content plus JSON text; `2024-11-05` returns text only.
- Shared CLI/MCP reports and artifact matching in `Forensicator/Report.lean`.
  Confidence, evidence, and unknown findings retain the existing CLI shape.
  Match/mismatch/unknown are forensic data; parsing and I/O failures are tool
  errors. No CLI subprocess or shell command is used for MCP tool execution.
- Pure dispatch and typed validation in `Forensicator/Mcp/Protocol.lean` and
  `Tools.lean`; stdio handling in `Server.lean`. Responses flush immediately
  while stdin remains open; EOF terminates after pending work completes.
- Total JSON parser in `Forensicator/Util/Json/Parser.lean`: 1 MiB frames,
  64-value nesting, 8192 nodes, 1024-character number literals, strict UTF-8
  and escape handling, duplicate-key rejection, and recovery after malformed
  or oversized frames. Long strings now use linear accumulation in the
  existing JSON emitter, preserving its escaping format.
- Protocol/parser guards in `Test/Mcp.lean`, interactive synthetic integration
  tests in `scripts/test-mcp.py`, client configuration in `README.md`, and
  detailed behavior/limits in `docs/workflow/mcp.md`.

### Verification

| Check | Result |
|---|---|
| `lake build` | Passed; 137 build jobs, existing unrelated linter warnings |
| `.lake/build/bin/forensicator-test` | Passed, including MCP parser/dispatch guards |
| `python3 scripts/test-mcp.py` | 76 checks passed |
| `python3 scripts/test-execution-shell.py` | 14 checks passed |
| `python3 scripts/test-stack-shell.py` | 10 checks passed |
| `git diff --check` | Passed |
| `./scripts/conformance-lean.sh` | Blocked: `Case/golden` is absent in this checkout |

MCP integration exercises initialization ordering, version fallback, legacy
results, structured/text agreement, exact and near-limit request IDs,
fragmented UTF-8/CRLF, EOF, notifications, invalid requests, parser limits,
recovery, literal paths, all analyzer selection modes, and actual CLI parity
on synthetic minidump/PE/PDB fixtures. PE/PDB matches, identity mismatches,
missing identities, malformed captures, and missing files are covered.

An interactive test exposed full-buffer reads waiting for more input; the
stdio reader now consumes bytes from the buffered handle through each newline.
A near-limit ID exposed quadratic JSON escaping; left-to-right accumulation
fixed that regression and the integration suite retains the large-ID check.

### Acceptance limits

Private minidump fuzz was skipped (`FORENSICATOR_CASE_DIR` unset and `Case/`
absent). No golden references were regenerated. The full private corpus and
live Windows TTD proxy were not qualified by this work.

Calls run sequentially; cancellation does not interrupt an active analysis.
Large dumps can require longer client timeouts. The `2026-07-28` stateless MCP
revision, HTTP transport, tasks/resources/prompts, and MCP trace/session/publics
tools are not implemented. Trace and session operations remain available
through the existing CLI. No TLA+ contract changed.

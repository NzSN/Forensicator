# Forensicator MCP

Build with `lake build`, then configure the client to launch the resulting
binary with the single argument `mcp`. The server reads newline-delimited
JSON-RPC on stdin and flushes responses on stdout. It writes transport failures
to stderr and exits when stdin closes. Launch the built binary directly;
build output must not share the protocol's stdout.

For clients using `mcpServers` configuration:

```json
{
  "mcpServers": {
    "forensicator": {
      "command": "/absolute/path/to/Forensicator/.lake/build/bin/forensicator",
      "args": ["mcp"]
    }
  }
}
```

The command and all tool paths are resolved on the machine running the
server. Prefer absolute paths. Relative paths use its working directory.
Files are read under the server process's filesystem permissions. The server
does not download symbols, upload captures, or launch shell commands.

## Tools

| Tool | Arguments | Result |
|---|---|---|
| `inspect` | `path`: minidump path | CLI `inspect --json`: modules, system, annotations, counts, crash diagnosis |
| `analyze` | `path`; optional `plugins`: array of analyzer names, `symbols`: PDB directory | CLI `analyze --json`: plugin results with existing confidence/evidence fields |
| `match` | `path`; `exes` and/or `pdbs`: arrays of artifact paths, at least one file | CLI `match --json`: per-artifact checks and `overall` |
| `list_plugins` | None | `plugins`: array of analyzer names and descriptions in pipeline order |

`analyze` runs all registered analyzers when `plugins` is absent or empty.
Use `list_plugins` to discover the current registry, including `jit`. An
unrecognized name is an error. Analysis uses adjacent module images and
optional identity-checked PDB symbols exactly as the CLI does. Missing or
unverified symbols stay unavailable; the server does not invent symbols.

Example `tools/call` parameters:

```json
{"name":"inspect","arguments":{"path":"/captures/crash.dmp"}}
```

```json
{"name":"analyze","arguments":{"path":"/captures/crash.dmp","plugins":["cause","v8"],"symbols":"/captures/symbols"}}
```

```json
{"name":"match","arguments":{"path":"/captures/crash.dmp","exes":["/captures/electron.exe"],"pdbs":["/captures/electron.exe.pdb"]}}
```

Successful calls return both `structuredContent` and a text block containing
the same serialized JSON. For MCP `2024-11-05`, results contain the text block
only. Forensic uncertainty is retained in result data. An artifact mismatch
returns `isError: false` with `overall: "mismatch"`, while an unreadable or
malformed file returns `isError: true`. Missing identities stay `unknown`.

Unknown tools and malformed RPC requests return JSON-RPC errors. Tool argument
validation and execution failures return tool errors with actionable text.
Extra tool arguments, wrong types, empty/NUL-containing paths, unknown
analyzers, and empty artifact selections are rejected before file access.

## Protocol and limits

The implementation follows the initialization-based
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
and [tool contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

- Supported revisions: `2025-11-25`, `2025-06-18`, and `2024-11-05`.
  An unsupported version in `initialize` negotiates `2025-11-25`; the client
  decides whether it can proceed.
- Methods: `initialize`, `ping`, `tools/list`, and `tools/call`.
  Clients send `notifications/initialized` after initialization before using
  tools. The tool list is a single page. Only the tools capability is advertised.
- Notifications receive no reply and cannot invoke tools. Calls run
  sequentially to avoid loading several large dumps at once. Cancellation
  notifications do not interrupt an analysis already running. Configure a
  suitable client timeout; full-memory analysis can take minutes, especially
  the `arrays` analyzer. Closing stdin exits after pending requests finish;
  terminating the process can stop an in-progress call.
- Input frames are limited to 1 MiB, JSON nesting to 64 values, JSON value
  count to 8192, and number literals to 1024 characters. Duplicate object keys,
  invalid Unicode, invalid JSON, and batch requests are rejected. Oversized
  frames are drained with bounded
  buffering, allowing the following request to proceed.
- UTF-8 and CRLF are accepted, including fragmented writes. A final frame
  without a newline is processed at EOF. stdout contains only RPC messages.
- The newer stateless `2026-07-28` protocol is not implemented. A client must
  support legacy initialization; `server/discover` returns method-not-found,
  allowing clients supporting both protocols to fall back as described in the
  [stdio compatibility rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).
- The MCP surface covers captures. Trace attachment/navigation, shell session
  state, and `publics` queries remain CLI functionality. There is no HTTP
  listener, task API, resource API, or prompt API.

## Implementation and verification

`Forensicator/Mcp/Protocol.lean` handles lifecycle and dispatch without I/O;
`Tools.lean` validates typed calls and invokes existing forensic code;
`Server.lean` confines the stdio transport. `Forensicator/Report.lean` shares
report rendering, image supplementation, and artifact matching with the CLI.
The bounded parser in `Forensicator/Util/Json/Parser.lean` extends the existing
JSON type without package dependencies or non-total library definitions.

```sh
export PATH="$HOME/.elan/bin:$PATH"
lake build
.lake/build/bin/forensicator-test
python3 scripts/test-mcp.py
python3 scripts/test-execution-shell.py
python3 scripts/test-stack-shell.py
./scripts/conformance-lean.sh  # requires Case/golden and private fixtures
```

The MCP integration test drives an interactive subprocess, checks lifecycle,
framing, malformed input recovery, and legacy compatibility, and compares
actual tool results against the CLI using synthetic minidump/PE/PDB files.
These checks do not certify a live TTD proxy or the private golden corpus.

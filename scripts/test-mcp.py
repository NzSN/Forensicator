#!/usr/bin/env python3
"""Native stdio MCP integration; no SDK, network, or private Case fixtures.

Synthetic captures/PE/PDBs exercise the real parser and shared report paths.
This is protocol/regression evidence, not live trace qualification.
"""

import json
import os
from pathlib import Path
import runpy
import selectors
import struct
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / ".lake/build/bin/forensicator"
GUID = bytes(range(16))
AGE = 7
MISSING = object()


def capture():
    data = bytearray(runpy.run_path(str(ROOT / "scripts/test-stack-shell.py"))["capture"]())
    data.extend(bytes(2400 - len(data)))
    # Keep the stack fixture's four streams and add an access-violation record.
    data[2048:2096] = data[32:80]
    struct.pack_into("<II", data, 8, 5, 2048)
    struct.pack_into("<III", data, 2096, 6, 168, 2200)
    struct.pack_into("<I", data, 2200, 7)
    struct.pack_into("<IIQQII", data, 2208, 0xC0000005, 0, 0, 0x1000, 2, 0)
    struct.pack_into("<QQ", data, 2240, 0, 0xDEADBEEF)
    struct.pack_into("<II", data, 2360, 1232, 512)
    rsds = b"RSDS" + GUID + struct.pack("<I", AGE) + b"fixture.pdb\0"
    struct.pack_into("<II", data, 192 + 76, len(rsds), 400)
    data[400:400 + len(rsds)] = rsds
    return data


def pe(age=AGE):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84 + 16, 240)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<II", data, opt + 56, 0x1000, 1024)
    struct.pack_into("<II", data, opt + 112 + 6 * 8, 512, 28)
    struct.pack_into("<III", data, 512 + 12, 2, 36, 600)
    struct.pack_into("<I", data, 512 + 24, 600)
    rsds = b"RSDS" + GUID + struct.pack("<I", age) + b"fixture.pdb\0"
    data[600:600 + len(rsds)] = rsds
    return data


def pdb(age=AGE):
    # Minimal MSF-7: directory in block 3, PdbInfo stream in block 4.
    data = bytearray(5 * 256)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    struct.pack_into("<IIIIII", data, 32, 256, 1, 5, 16, 0, 2)
    struct.pack_into("<I", data, 2 * 256, 3)
    struct.pack_into("<IIII", data, 3 * 256, 2, 0, 28, 4)
    struct.pack_into("<III", data, 4 * 256, 3, 0x1234, age)
    data[4 * 256 + 12:4 * 256 + 28] = GUID
    return data


class Client:
    def __init__(self):
        self.process = subprocess.Popen(
            [str(BIN), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=ROOT, bufsize=0,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.pending = b""
        self.next_id = 1

    def send(self, message):
        self.process.stdin.write(json.dumps(message, ensure_ascii=False).encode() + b"\n")

    def receive(self):
        deadline = time.monotonic() + 30
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise AssertionError("MCP response timed out (possibly buffered stdout)")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise AssertionError("MCP exited before replying")
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        result = json.loads(line)
        assert result["jsonrpc"] == "2.0", result
        assert ("error" in result) != ("result" in result), result
        return result

    def rpc(self, method, params=MISSING, request_id=MISSING):
        if request_id is MISSING:
            request_id = self.next_id
            self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not MISSING:
            message["params"] = params
        self.send(message)
        result = self.receive()
        assert result["id"] == request_id, result
        return result

    def initialize(self, version="2025-11-25", notify=True):
        result = self.rpc("initialize", {
            "protocolVersion": version, "capabilities": {},
            "clientInfo": {"name": "forensicator-test", "version": "1"},
        })
        if notify:
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def call(self, name, arguments=MISSING):
        params = {"name": name}
        if arguments is not MISSING:
            params["arguments"] = arguments
        return self.rpc("tools/call", params)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("MCP did not exit on EOF")
        self.selector.close()
        tail = self.pending + self.process.stdout.read()
        errors = self.process.stderr.read()
        assert self.process.returncode == 0, errors
        assert not tail, f"unexpected response to a notification: {tail!r}"
        assert not errors, errors


def cli(*args, expected_code=0):
    result = subprocess.run([str(BIN), *map(str, args)], capture_output=True,
                            text=True, cwd=ROOT, timeout=30)
    assert result.returncode == expected_code, result.stderr
    return json.loads(result.stdout)


def data(response):
    result = response["result"]
    assert result["isError"] is False, result
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


def main():
    checks = 0

    def check(label, condition):
        nonlocal checks
        if not condition:
            raise AssertionError(label)
        checks += 1
        print(f"ok    mcp integration {label}", flush=True)

    client = Client()
    try:
        check("tools require initialization", client.rpc("tools/list")["error"]["code"] == -32600)
        check("ping works before initialization", client.rpc("ping", request_id=0)["result"] == {})
        check("modern discovery allows client fallback",
              client.rpc("server/discover")["error"]["code"] == -32601)
        check("bad initialization is recoverable", client.rpc("initialize", {})["error"]["code"] == -32602)
        initialized = client.initialize(notify=False)["result"]
        check("tools wait for initialized notification", client.rpc("tools/list")["error"]["code"] == -32600)
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        check("negotiates tools only", initialized["protocolVersion"] == "2025-11-25"
              and initialized["capabilities"] == {"tools": {"listChanged": False}})
        check("cannot reinitialize", client.rpc("initialize", {})["error"]["code"] == -32600)
        tools = client.rpc("tools/list")["result"]["tools"]
        check("four documented tools", [t["name"] for t in tools] == ["inspect", "analyze", "match", "list_plugins"])
        check("schemas reject extra arguments", all(t["inputSchema"]["additionalProperties"] is False for t in tools))
        check("tools declare read-only local work", all(t["annotations"]["readOnlyHint"]
              and not t["annotations"]["openWorldHint"] for t in tools))
        check("single-page listing rejects unknown cursor", client.rpc("tools/list", {"cursor": "bad"})["error"]["code"] == -32602)
        plugins = data(client.call("list_plugins"))["plugins"]
        names = [p["name"] for p in plugins]
        check("discovery follows actual registry", names == tools[1]["inputSchema"]["properties"]["plugins"]["items"]["enum"])
        text = subprocess.run([str(BIN), "list-plugins"], capture_output=True, text=True, check=True).stdout
        check("plugin descriptions match CLI", all(f"  {p['name']}: {p['description']}" in text for p in plugins))
        for request_id in ["", "取证 🚀", -3, 18446744073709551615, 1.0, 1e20, -0.0]:
            check(f"exact request id {request_id!r}", client.rpc("ping", request_id=request_id)["result"] == {})
        check("large string ID remains responsive", client.rpc("ping", request_id="x" * 1048500)["result"] == {})
        for method, params in [("unknown", {}), ("tools/call", {"name": "missing"}),
                               ("tools/call", {"name": "inspect", "arguments": []}),
                               ("tools/call", {"name": "list_plugins", "task": {}}),
                               ("tools/list", None)]:
            check(f"protocol error for {method} {params}", "error" in client.rpc(method, params))
        for name, args in [("inspect", {}), ("inspect", {"path": 42}),
                           ("inspect", {"path": ""}), ("inspect", {"path": "bad\0path"}),
                           ("inspect", {"path": "missing", "extra": True}),
                           ("list_plugins", {"extra": True}), ("match", {"path": "missing"}),
                           ("analyze", {"path": "missing", "plugins": ["typo"]}),
                           ("analyze", {"path": "missing", "plugins": "cause"}),
                           ("analyze", {"path": "missing", "symbols": None})]:
            check(f"invalid arguments are tool errors: {name} {args}", client.call(name, args)["result"]["isError"])
        with tempfile.TemporaryDirectory(prefix="forensicator-mcp-") as directory:
            directory = Path(directory)
            dump = directory / 'capture 取证 "quoted" $(printf injected).dmp'
            dump.write_bytes(capture())
            exe = directory / "fixture.exe"
            exe.write_bytes(pe())
            symbols = directory / "fixture.pdb"
            symbols.write_bytes(pdb())
            inspected = data(client.call("inspect", {"path": str(dump)}))
            check("inspect JSON equals CLI", inspected == cli("inspect", dump, "--json"))
            check("diagnosis preserves evidence and confidence", inspected["diagnosis"]["confidence"]
                  and isinstance(inspected["diagnosis"]["evidence"], list))
            for selected in [None, [], ["cause"], ["strings", "v8", "jit"]]:
                args = {"path": str(dump), "symbols": str(directory)}
                command = ["analyze", dump, "--json", "--symbols", directory]
                if selected is not None:
                    args["plugins"] = selected
                    if selected:
                        command += ["--plugin", ",".join(selected)]
                check(f"analysis JSON equals CLI: {selected}", data(client.call("analyze", args)) == cli(*command))
            matched = data(client.call("match", {"path": str(dump), "exes": [str(exe)], "pdbs": [str(symbols)]}))
            check("PE and PDB match equals CLI", matched == cli("match", dump, "--exe", exe, "--pdb", symbols, "--json")
                  and matched["overall"] == "match")
            symbols.write_bytes(pdb(age=8))
            mismatch = data(client.call("match", {"path": str(dump), "pdbs": [str(symbols)]}))
            check("identity mismatch is a successful finding", mismatch["overall"] == "mismatch"
                  and mismatch == cli("match", dump, "--pdb", symbols, "--json", expected_code=2))
            # Missing RSDS identity stays unknown, not a guessed match.
            unknown = bytearray(capture())
            struct.pack_into("<II", unknown, 192 + 76, 0, 0)
            dump.write_bytes(unknown)
            check("missing identity stays unknown", data(client.call("match", {"path": str(dump), "exes": [str(exe)]}))["overall"] == "unknown")
            bad = directory / "bad.dmp"
            for content in [b"bad", b"TTFX\x01\0\0\0"]:
                bad.write_bytes(content)
                check(f"invalid capture is a tool error: {content!r}", client.call("inspect", {"path": str(bad)})["result"]["isError"])
            check("missing file is a tool error", client.call("inspect", {"path": str(directory / "missing")})["result"]["isError"])
            check("missing artifact is a tool error", client.call("match", {"path": str(dump), "pdbs": [str(directory / "missing")]})["result"]["isError"])
        # Split a UTF-8 sequence across writes and wait with stdin still open.
        payload = json.dumps({"jsonrpc": "2.0", "id": "分片🚀", "method": "ping"}, ensure_ascii=False).encode()
        split = payload.index("🚀".encode()) + 2
        client.process.stdin.write(payload[:split])
        check("no response to partial frame", not client.selector.select(0.1))
        client.process.stdin.write(payload[split:] + b"\r\n")
        check("fragmented UTF-8 and CRLF", client.receive()["id"] == "分片🚀")
        client.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_plugins"}})
        client.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": -1}})
        client.send({"jsonrpc": "2.0", "method": "notifications/unknown"})
        check("notifications produce no replies", client.rpc("ping")["result"] == {})
    finally:
        client.close()
    check("EOF exits cleanly", True)

    for version in ["2025-06-18", "2024-11-05", "2099-01-01"]:
        client = Client()
        try:
            negotiated = client.initialize(version)["result"]["protocolVersion"]
            check(f"version negotiation {version}", negotiated == ("2025-11-25" if version == "2099-01-01" else version))
            result = client.call("list_plugins")["result"]
            check(f"result compatibility {version}", ("structuredContent" in result) == (version != "2024-11-05"))
            if version == "2024-11-05":
                check("legacy discovery omits modern annotations", all("annotations" not in t for t in client.rpc("tools/list")["result"]["tools"]))
        finally:
            client.close()

    # Every malformed frame must be followed by a valid ping response, proving
    # that parse failures and oversize draining cannot desynchronize the stream.
    cases = [
        (b"{", -32700), (b"\xff", -32700),
        (b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}', -32700),
        (b"[]", -32600), (b"null", -32600),
        (b'{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":1e-1,"method":"ping"}', -32600),
        (b'{"jsonrpc":"1.0","id":1,"method":"ping"}', -32600),
        (b"[" * 64 + b"0" + b"]" * 64, -32700),
        (b"9" * 1025, -32700),
        (b" " * (1024 * 1024 + 1), -32700),
    ]
    messages = []
    for index, (bad, _) in enumerate(cases):
        messages.extend([bad, json.dumps({"jsonrpc": "2.0", "id": index, "method": "ping"}).encode()])
    result = subprocess.run([str(BIN), "mcp"], input=b"\n".join(messages), capture_output=True, cwd=ROOT, timeout=30)
    check("malformed frames do not kill transport", result.returncode == 0 and not result.stderr)
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    check("exactly one response per request/frame", len(responses) == len(messages))
    for index, (_, code) in enumerate(cases):
        check(f"bad frame {index} rejected and recovered", responses[index * 2]["error"]["code"] == code
              and responses[index * 2 + 1] == {"jsonrpc": "2.0", "id": index, "result": {}})
    check("final frame without newline is processed", responses[-1]["id"] == len(cases) - 1)
    print(f"== {checks} MCP INTEGRATION CHECKS PASSED ==")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise execution-view shell behavior against a deterministic stdio proxy.

Run after `lake build`: python3 scripts/test-execution-shell.py
No Windows installation, external service, or third-party Python package is used.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
FRONTIER = 8
WRITES = [(1, 0x1080, 1), (3, 0x1080, 1), (8, 0x2000, 1)]


def frame(tag: int, payload: bytes = b"") -> bytes:
    return struct.pack("<II", len(payload) + 4, tag) + payload


def event_inventory() -> bytes:
    events = [
        (0, 1, 0, 0x7000, 0, 0x1000, b"app.exe"),
        (2, 0, 0xC0000005, 0x7010, 7, 0, b""),
        (4, 2, 0, 0x7000, 0, 0, b""),
        (5, 1, 0, 0x7000, 0, 0x1000, b"next.exe"),
        (6, 0, 0xC0000005, 0x7010, 7, 0, b""),
        (6, 0, 0xC0000005, 0x7020, 8, 0, b""),
    ]
    records = bytearray()
    names = bytearray()
    for pos, kind, code, address, tid, size, name in events:
        records += struct.pack(
            "<QIIQIQIII", pos, kind, code, address, tid, size,
            len(name), 8 + 48 * len(events) + len(names), 0,
        )
        names += name
    return struct.pack("<Q", len(events)) + records + names


def serve() -> None:
    """Proxy mode, invoked by the real Lean client using --stdio."""
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    with open(os.environ["FORENSICATOR_TEST_PROXY_LOG"], "a", encoding="utf-8") as log:
        while header := stdin.read(4):
            length, = struct.unpack("<I", header)
            body = stdin.read(length)
            if len(body) != length:
                raise RuntimeError("truncated request")
            tag, = struct.unpack_from("<I", body)
            payload = body[4:]
            entry = {"tag": tag}
            if tag == 1:
                response = frame(2, struct.pack("<IQ", 1, FRONTIER))
                threads = struct.pack("<Q", 2)
                threads += struct.pack("<IIQQ", 7, 0, 0, (1 << 64) - 1)
                threads += struct.pack("<IIQQ", 8, 0, 1, 7)
                response += frame(8, threads) + frame(9, event_inventory())
            elif tag == 3:
                lo, hi, begin, end = struct.unpack("<QQQQ", payload)
                entry.update(lo=lo, hi=hi, begin=begin, end=end)
                records = [w for w in WRITES if begin <= w[0] <= end
                           and w[1] < hi and lo < w[1] + w[2]]
                packed = b"".join(struct.pack("<QQII", *w, 0) for w in records)
                response = frame(4, struct.pack("<Q", len(records)) + packed)
            elif tag == 5:
                pos, va, length = struct.unpack("<QQI", payload)
                entry.update(position=pos, va=va, length=length)
                if va == 0x3000:
                    response = frame(6, struct.pack("<II", 1, 0))
                else:
                    data = bytearray(length)
                    if va == 0x1000:
                        data[128] = 0x11 if 1 <= pos - 1 < 3 else 0
                        data[0:15] = b"Hello timeline\0"
                    response = frame(6, struct.pack("<II", 0, length) + data)
            elif tag == 10:
                log.write(json.dumps(entry) + "\n")
                return
            else:
                raise RuntimeError(f"unexpected request tag {tag}")
            log.write(json.dumps(entry) + "\n")
            log.flush()
            stdout.write(response)
            stdout.flush()


def run_checks() -> None:
    binary = ROOT / ".lake/build/bin/forensicator"
    if not binary.is_file():
        raise SystemExit("Build the CLI with lake build first.")
    checks = 0

    def check(name: str, condition: bool) -> None:
        nonlocal checks
        if not condition:
            raise AssertionError(name)
        checks += 1
        print(f"ok    shell {name}")

    with tempfile.TemporaryDirectory(prefix="forensicator-execution-") as directory:
        counter = 0

        def session(commands: list[str]):
            nonlocal counter
            counter += 1
            log_path = Path(directory) / f"requests-{counter}.jsonl"
            env = os.environ.copy()
            env.pop("FORENSICATOR_PROXY_SSH", None)
            env["FORENSICATOR_PROXY_EXE"] = str(Path(__file__).resolve())
            env["FORENSICATOR_TEST_PROXY_LOG"] = str(log_path)
            result = subprocess.run(
                [str(binary), "shell", "--proxy", "fixture.run"],
                input="\n".join(commands + ["quit"]) + "\n",
                text=True, capture_output=True, env=env, cwd=ROOT, timeout=30,
            )
            if result.returncode:
                raise AssertionError(result.stderr + result.stdout)
            objects = []
            for line in result.stdout.splitlines():
                opening = line.find("{")
                if opening >= 0:
                    try:
                        objects.append(json.loads(line[opening:]))
                    except json.JSONDecodeError:
                        pass
            requests = [json.loads(line) for line in log_path.read_text().splitlines()]
            return result, objects, requests

        output, points, requests = session([
            "inspect --json", "seek 2", "inspect --json", "seek 3",
            "inspect --json", "events 1 3", "match --json",
        ])
        points = [p for p in points if "position" in p]
        check("point inspection and navigation perform no index or page fetch",
              [r["tag"] for r in requests] == [1, 10])
        check("exact exception does not persist at a later position",
              len(points[1]["events"]) == 1 and points[1]["events"][0]["kind"] == "exception"
              and points[2]["events"] == [])
        check("proxy threads expose unavailable register and stack knowledge",
              all(t["registers"]["status"] == "unavailable"
                  and t["stack_range"]["status"] == "unavailable"
                  for t in points[1]["threads"]))
        check("interval events retain the earlier exception", "@0x2 exception" in output.stdout)

        output, points, requests = session([
            "seek 2", "read 0x1080 1", "seek 3", "read 0x1080 1",
            "read 0x3000 1", "read 0xffffffffffffffff 2",
            "read 0 65537", "read 0x1080 1", "inspect --json",
        ])
        check("targeted reads observe intervening writes", "[11]" in output.stdout and "[00]" in output.stdout)
        check("positive absence is distinct from unknown", "<known absent>" in output.stdout)
        check("invalid reads do not poison the session",
              "overflows" in output.stderr and "at most 65536" in output.stderr
              and "session dead" not in output.stderr and len(points) == 1)
        check("targeted reads avoid full-space index discovery",
              all(r.get("hi") != (1 << 64) - 1 for r in requests))
        check("known bytes retain unknown mapping coverage",
              points[0]["memory"]["known_regions"] == 1
              and points[0]["memory"]["mapping_coverage"] == "unknown")

        output, objects, requests = session([
            "seek 3", "analyze --plugin strings --json", "seek 4", "inspect --json",
            "seek 5", "inspect --json", "seek 8", "read 0x2000 1",
        ])
        analysis = next(o for o in objects if "plugins" in o)
        points = [o for o in objects if "position" in o]
        check("prepared unclassified memory is still scanned for strings",
              any(s["content"] == "Hello timeline" for p in analysis["plugins"] for s in (p["strings"] or [])))
        check("module unload and same-base reload follow the cursor",
              points[0]["context"]["modules"] == []
              and points[1]["context"]["modules"][0]["name"] == "next.exe")
        check("frontier write is not reported as an observed post-write value", "<unknown>" in output.stdout)

        output, objects, requests = session([
            "seek 6", "analyze --plugin cause --json",
            "analyze --plugin cause --event 0 --json",
            "analyze --event 9 --json", "events 6 2", "inspect --json",
        ])
        diagnoses = [p["custom"][0]["crash_diagnosis"]
                     for o in objects if "plugins" in o for p in o["plugins"]]
        check("multiple exceptions require selection",
              diagnoses[0]["verdict"] == "Unknown" and diagnoses[1]["verdict"] == "WildAccess")
        check("invalid event requests preserve usable point access",
              "event index out of range" in output.stderr and "interval" in output.stderr
              and any("position" in o for o in objects))

    print(f"== {checks} EXECUTION SHELL CHECKS PASSED ==")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        serve()
    else:
        run_checks()

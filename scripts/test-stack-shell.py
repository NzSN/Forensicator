#!/usr/bin/env python3
"""Capture-stack shell integration using a small, explicit Windows minidump.

This is a synthetic parser/session test, not native replay certification.
"""

import json
from pathlib import Path
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def capture() -> bytes:
    data = bytearray(1920)
    struct.pack_into("<IIIIIIQ", data, 0, 0x504D444D, 0xA793, 4, 32, 0, 0, 0)
    for i, descriptor in enumerate([(7, 56, 80), (3, 52, 136), (4, 112, 188), (5, 20, 300)]):
        struct.pack_into("<III", data, 32 + i * 12, *descriptor)
    # SystemInfo: PROCESSOR_ARCHITECTURE_AMD64, Windows NT, version 10.0.
    struct.pack_into("<H", data, 80, 9)
    struct.pack_into("<IIII", data, 88, 10, 0, 0, 2)
    # One thread with an x64 CONTROL|INTEGER context and captured stack bytes.
    struct.pack_into("<I", data, 136, 1)
    struct.pack_into("<I", data, 140, 7)
    struct.pack_into("<QIIII", data, 140 + 24, 0x8000, 128, 1792, 1232, 512)
    struct.pack_into("<I", data, 512 + 0x30, 0x00100003)
    for offset, value in [(0x98, 0x8000), (0xA0, 0x8010), (0xF8, 0x1000)]:
        struct.pack_into("<Q", data, 512 + offset, value)
    # Module range supports return-address classification, without certifying
    # any unwind directory or terminal witness.
    struct.pack_into("<I", data, 188, 1)
    struct.pack_into("<QIIII", data, 192, 0x1000, 0x1000, 0, 0, 320)
    name = "fixture.exe".encode("utf-16-le")
    struct.pack_into("<I", data, 320, len(name))
    data[324:324 + len(name)] = name
    struct.pack_into("<IQII", data, 300, 1, 0x8000, 128, 1792)
    # Two frame-pointer links: 0x1000 -> 0x1010 -> 0x1020. The last zero
    # frame pointer is deliberately not an authoritative root witness.
    for offset, value in [(16, 0x8020), (24, 0x1010), (32, 0), (40, 0x1020)]:
        struct.pack_into("<Q", data, 1792 + offset, value)
    return bytes(data)


def main():
    checks = 0

    def check(label, condition):
        nonlocal checks
        if not condition:
            raise AssertionError(label)
        checks += 1
        print(f"ok    stack shell {label}")

    with tempfile.TemporaryDirectory(prefix="forensicator-stack-shell-") as directory:
        path = Path(directory) / "stack.dmp"
        path.write_bytes(capture())
        commands = [
            "inspect --point --json", "stack 7 --max-frames 2 --json",
            "inspect --point --json", "stack 7 --json", "inspect --point --json",
            "stack 999 --json", "stack 4294967296 --json", "stack 7 --max-frames 4097",
            f'load "{path}"', "inspect --point --json", "inspect --quiet", "quit",
        ]
        result = subprocess.run(
            [str(ROOT / ".lake/build/bin/forensicator"), "shell", str(path)],
            input="\n".join(commands) + "\n", text=True, capture_output=True,
            cwd=ROOT, timeout=30,
        )
        check("session exits successfully", result.returncode == 0)
        objects = []
        for line in result.stdout.splitlines():
            opening = line.find("{")
            if opening >= 0:
                objects.append(json.loads(line[opening:]))
        points = [o for o in objects if "threads" in o]
        stacks = [o for o in objects if "stop_reason" in o]
        check("capture point has no invented frontier", points[0]["position"] == "capture" and points[0]["frontier"] is None)
        check("initial point does not invent recovered frames", points[0]["threads"][0]["frames"]["status"] == "unavailable")
        check("frame budget returns an explicit partial result",
              len(stacks[0]["frames"]) == 2 and stacks[0]["coverage"] == "partial"
              and stacks[0]["stop_reason"] == "frame_budget")
        check("inspection sees retained frame knowledge",
              points[1]["threads"][0]["frames"]["status"] == "known"
              and points[1]["threads"][0]["frames"]["value"]["count"] == 2)
        check("larger budget refines the retained result",
              [f["instruction"] for f in stacks[1]["frames"]] == ["0x1000", "0x1010", "0x1020"]
              and points[2]["threads"][0]["frames"]["value"]["count"] == 3)
        check("zero frame pointer does not certify a root",
              stacks[1]["coverage"] == "partial" and stacks[1]["stop_reason"] == "missing_artifact")
        check("invalid selections and budgets preserve the session",
              "not present" in result.stderr and "outside UInt32" in result.stderr
              and "at most 4096" in result.stderr)
        check("reload clears attachment frame knowledge", points[3]["threads"][0]["frames"]["status"] == "unavailable")
        check("capture inventory output remains available", "modules: 1  threads: 1  memory_regions: 1" in result.stdout)
    print(f"== {checks} STACK SHELL CHECKS PASSED ==")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Check literal proxy argv through both SSH shell layers and local spawn.

Run after `lake build`: python3 scripts/test-proxy-ssh.py
The fake ssh executes the received command with /bin/sh locally. Its inner
Bash runs the deterministic stdio provider from test-execution-shell.py;
no SSH connection, Windows installation, or third-party package is used.
The supported remote transport assumes a POSIX-compatible login shell and
Bash on PATH, just as the fake SSH does here.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def fake_ssh() -> None:
    """Model OpenSSH's remote login-shell -c boundary without networking."""
    if len(sys.argv) != 3 or sys.argv[1] != "fixture-host":
        raise RuntimeError(f"unexpected fake ssh arguments: {sys.argv!r}")
    Path(os.environ["FORENSICATOR_TEST_SSH_LOG"]).write_text(
        json.dumps(sys.argv[1:]), encoding="utf-8",
    )
    os.execv("/bin/sh", ["sh", "-c", sys.argv[2]])


def serve() -> None:
    sys.dont_write_bytecode = True
    Path(os.environ["FORENSICATOR_TEST_PROXY_ARGV_LOG"]).write_text(
        json.dumps(sys.argv), encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "execution_proxy_fixture", ROOT / "scripts/test-execution-shell.py",
    )
    assert spec is not None and spec.loader is not None
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)
    provider.serve()


def windows_path(path: str) -> str:
    if len(path) >= 7 and path.startswith("/mnt/") and path[6] == "/":
        return path[5].upper() + ":/" + path[7:]
    return path


def run_checks() -> None:
    binary = ROOT / ".lake/build/bin/forensicator"
    if not binary.is_file():
        raise SystemExit("Build the CLI with lake build first.")

    # Relative touch targets deliberately stay within each temporary cwd.
    # If either shell interprets the paths, these observable side effects
    # expose substitutions/extra commands without executing unsafe commands.
    special = ('space \' apostrophe "double" $HOME '
               '$(touch executed-dollar) `touch executed-backtick` '
               '; touch executed-semicolon ; & [glob] \\ unicode-雪\nnewline')
    cases = [
        ("remote spaces", True, "proxy with spaces", "trace with spaces.run"),
        ("remote executable literals", True, "proxy " + special, "fixture.run"),
        ("remote trace literals", True, "proxy", "trace " + special + ".run"),
        ("remote Windows path translation", True, "proxy " + special,
         "/mnt/d/trace " + special + ".run"),
        ("local argument preservation", False, "proxy " + special,
         "trace " + special + ".run"),
        ("local Windows path translation", False, "proxy with spaces",
         "/mnt/q/trace " + special + ".run"),
    ]
    with tempfile.TemporaryDirectory(prefix="forensicator-proxy-ssh-") as temporary:
        for index, (name, remote, exe_name, trace_path) in enumerate(cases):
            directory = Path(temporary) / str(index)
            directory.mkdir()
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            (fake_bin / "ssh").symlink_to(Path(__file__).resolve())
            executable = directory / exe_name
            executable.symlink_to(Path(__file__).resolve())
            requests = directory / "requests.jsonl"
            argv_log = directory / "argv.json"
            ssh_log = directory / "ssh.json"
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
            env["FORENSICATOR_PROXY_EXE"] = str(executable)
            env["FORENSICATOR_TEST_PROXY_LOG"] = str(requests)
            env["FORENSICATOR_TEST_PROXY_ARGV_LOG"] = str(argv_log)
            env["FORENSICATOR_TEST_SSH_LOG"] = str(ssh_log)
            if remote:
                env["FORENSICATOR_PROXY_SSH"] = "fixture-host"
            else:
                env.pop("FORENSICATOR_PROXY_SSH", None)
            result = subprocess.run(
                [str(binary), "shell", "--proxy", trace_path],
                input="inspect --json\nquit\n", text=True, capture_output=True,
                env=env, cwd=directory, timeout=15,
            )
            assert not any(p.name.startswith("executed-") for p in directory.iterdir()), name
            assert result.returncode == 0, (name, result.stderr, result.stdout)
            assert argv_log.is_file(), (name, result.stderr, result.stdout)
            assert json.loads(argv_log.read_text()) == [
                str(executable), "--stdio", windows_path(trace_path),
            ], name
            assert [json.loads(line)["tag"] for line in requests.read_text().splitlines()] == [1, 10], name
            assert '"position"' in result.stdout, (name, result.stdout)
            assert ssh_log.is_file() == remote, name
            print(f"ok    proxy {name}")
    print(f"== {len(cases)} PROXY SPAWN CHECKS PASSED ==")


if __name__ == "__main__":
    if Path(sys.argv[0]).name == "ssh":
        fake_ssh()
    elif len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        serve()
    else:
        run_checks()

#!/usr/bin/env bash
# Bounded safety gate for the root parse/analyzer workflow composition.
set -euo pipefail

workflow_repo="$(cd "$(dirname "$0")/.." && pwd)"
workflow_logs="${FORENSICATOR_TLA_LOG_DIR:-$workflow_repo/tmp/workflow-specs}"
mkdir -p "$workflow_logs"
workflow_logs="$(cd "$workflow_logs" && pwd)"
cd "$workflow_repo"
command -v apalache-mc >/dev/null
command -v python3 >/dev/null

# Four stream decodes plus header/directory/build take seven transitions.
# Twelve transitions also cover symbol loading and two analyzer outcomes.
printf 'Checking Forensicator through 12 transitions\n'
if ! apalache-mc check --features=no-rows --length=12 \
    --config=specs/Forensicator.cfg specs/Forensicator.tla \
    >"$workflow_logs/Forensicator.log" 2>&1; then
  tail -40 "$workflow_logs/Forensicator.log"
  exit 1
fi
printf 'PASS Forensicator (log: %s)\n' "$workflow_logs/Forensicator.log"

# A rejected success/failure mutation confirms that the bounded run reaches
# AnalyzerRun after S1, and that catalog safety is being checked. Syntax,
# assignment, timeout and configuration errors must not pass this control.
python3 - "$workflow_repo" "$workflow_logs" <<'PY'
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

repo = Path(sys.argv[1])
logs = Path(sys.argv[2]).resolve()
with tempfile.TemporaryDirectory(prefix="forensicator-workflow-mutant-") as directory:
    target = Path(directory)
    for name in ("Forensicator", "Model", "AddressSpace", "Arch", "Symbolizer"):
        shutil.copy2(repo / "specs" / f"{name}.tla", target / f"{name}.tla")
    shutil.copy2(repo / "specs" / "Forensicator.cfg", target / "Forensicator.cfg")
    module = target / "Forensicator.tla"
    text = module.read_text()
    before = "/\\ failed' = failed\n"
    if text.count(before) != 1:
        raise SystemExit("Analyzer success mutation anchor changed")
    module.write_text(text.replace(before, "/\\ failed' = failed \\cup {a}\n", 1))
    result = subprocess.run(
        ["apalache-mc", "check", "--features=no-rows", "--length=9",
         "--config=Forensicator.cfg", "Forensicator.tla"],
        cwd=target, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=300,
    )
    log = logs / "Forensicator-negative-control.log"
    log.write_text(result.stdout)
    violation = re.search(r"State (\d+): state invariant \d+ violated", result.stdout)
    if not (result.returncode == 12 and "The outcome is: Error" in result.stdout
            and violation):
        print(result.stdout[-6000:])
        raise SystemExit(f"Expected an invariant counterexample, got exit {result.returncode}")
    print(f"PASS workflow negative control: rejected at transition {violation.group(1)} "
          f"(log: {log})")
PY

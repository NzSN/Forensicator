#!/usr/bin/env python3
"""Check that timeline invariants reject representative incorrect changes.

Every mutation runs in a temporary copy. Repository specifications are untouched.
Requires apalache-mc; parser/type/timeout errors never count as detected bugs.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specs"


def replace_once(text, old, new):
    if old not in text:
        raise AssertionError(f"Mutation anchor no longer exists: {old}")
    return text.replace(old, new, 1)


def run_mutant(name, changed_file, change, checked_module, init, step, invariants, bound,
               config_file=None):
    with tempfile.TemporaryDirectory(prefix="forensicator-tla-mutant-") as directory:
        target = Path(directory)
        for source in SPEC.glob("*.tla"):
            shutil.copy2(source, target / source.name)
        path = target / changed_file
        path.write_text(change(path.read_text()))
        config = target / "check.cfg"
        if config_file:
            config.write_text((SPEC / config_file).read_text())
        else:
            config.write_text(f"INIT {init}\nNEXT {step}\n"
                              + "".join(f"INVARIANT {inv}\n" for inv in invariants))
        result = subprocess.run(
            ["apalache-mc", "check", "--features=no-rows", f"--length={bound}",
             f"--config={config}", str(target / checked_module)],
            cwd=target, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=300,
        )
        if not (result.returncode == 12
                and "The outcome is: Error" in result.stdout
                and re.search(r"State \d+: state invariant \d+ violated", result.stdout)):
            raise AssertionError(
                f"{name}: expected an invariant counterexample, got exit {result.returncode}\n"
                + result.stdout[-6000:]
            )
        state = re.search(r"State (\d+): state invariant \d+ violated", result.stdout).group(1)
        print(f"ok    mutation {name}: rejected at transition {state}", flush=True)


def main():
    if not shutil.which("apalache-mc"):
        raise SystemExit("apalache-mc is required")
    execution = ("ExecutionState.tla", "ExecutionInit", "ExecutionNext")
    run_mutant(
        "memory value from the wrong source", "ExecutionState.tla",
        lambda s: replace_once(s, "value |-> observed_values[key]",
                               "value |-> observed_values[CellKey(CaptureSource, 0, addr)]"),
        *execution, ["KnowledgeSound"], 3,
    )
    run_mutant(
        "unknown read becomes known zero", "ExecutionState.tla",
        lambda s: replace_once(s, 'ELSE [knowledge |-> "unknown", value |-> 0]',
                               'ELSE [knowledge |-> "known", value |-> 0]'),
        *execution, ["UnknownIsNotZero"], 1,
    )
    run_mutant(
        "returned event occurrence dropped", "ExecutionState.tla",
        lambda s: replace_once(s, r"LAMBDA i : i \in PointEvents(source, t))",
                               r"LAMBDA i : i \in PointEvents(source, t) /\ i # 2)"),
        *execution, ["ReturnedEventsComplete"], 3,
    )
    run_mutant(
        "valid exception selection always fails", "ExecutionState.tla",
        lambda s: re.sub(
            r"SelectedException\(source, t, choice\) ==.*?(?=\n\\\* @type: \(Int, Int, Int, Int\))",
            "SelectedException(source, t, choice) == 0\n",
            s, count=1, flags=re.S,
        ),
        *execution, ["SelectionComplete"], 1,
    )
    run_mutant(
        "publish final cache instead of retained pages", "Snapshot.tla",
        lambda s: replace_once(
            s, "[ExecutionPointAt(mat_source, mat_pos) EXCEPT !.addressSpace = mat_values]",
            "ExecutionPointAt(mat_source, mat_pos)",
        ),
        "Snapshot.tla", "MaterializationInit", "MaterializationNext",
        ["SnapshotComplete", "IndependentOfCache"], 6,
    )
    run_mutant(
        "P3 fallback accepts unobservable frontier", "JigSawSpawner.tla",
        lambda s: replace_once(s, "e2 == IF nw < frontier", "e2 == IF nw <= frontier"),
        "JigSawSpawnerRegression.tla", "", "", [], 2,
        config_file="JigSawSpawnerRegression.cfg",
    )
    print("== 6 TIMELINE SPEC MUTATIONS REJECTED ==")


if __name__ == "__main__":
    main()

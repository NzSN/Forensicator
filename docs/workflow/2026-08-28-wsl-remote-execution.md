# WSL Remote-Execution Workflow (crash-fidelity team)

> **Date:** 2026-08-28
> **Why:** the local workstation lacks RAM for Lean builds + 1.5 GB dump
> analysis. All heavy compute runs in WSL on windows-dev (58 GB RAM).

## Topology

- **Edit workspace (local):** @@BT@@/home/nzsn/Repos/Forensicator@@BT@@ — all file edits,
  commits, and git history happen here. Use the normal file tools.
- **Compute workspace (remote):** WSL on windows-dev,
  @@BT@@/home/jlc/Workspaces/Forensicator_Works/Forensicator@@BT@@ — builds, guard
  suite, golden gate, dump analysis. Never edit files there.
- **Relay:** bare repo @@BT@@windows-dev:D:/forensicator-relay.git@@BT@@.
  Local remote name: @@BT@@relay@@BT@@. WSL remote name: @@BT@@relay@@BT@@
  (via @@BT@@/mnt/d/forensicator-relay.git@@BT@@). Branch: @@BT@@master@@BT@@.

## Commands

- Run anything remotely: @@BT@@r_wsldev '<cmd>'@@BT@@ — the whole command is
  base64-wrapped, so compound commands, quotes, globs and variables all work
  (no @@BT@@':;'@@BT@@ trick needed, unlike @@BT@@r_windev@@BT@@). Example:
  @@BT@@r_wsldev 'cd /home/jlc/Workspaces/Forensicator_Works/Forensicator && lake build'@@BT@@
- Sync your work to the remote (after committing locally):
  @@BT@@sh
  git add <your files only>           # stage only your task's files
  git commit -m "T<n>: ..."
  git pull --rebase relay master      # serialize with teammates
  git push relay master
  r_wsldev 'cd /home/jlc/Workspaces/Forensicator_Works/Forensicator && git fetch relay && git reset --hard relay/master'
  @@BT@@
- The WSL tree is a pure mirror: it may be reset --hard at any time. Never
  leave uncommitted work there.

## Remote fixtures

- @@BT@@Case/golden@@BT@@, @@BT@@Case/fulldump@@BT@@, @@BT@@Case/minidump@@BT@@,
  @@BT@@Case/minidump_v2@@BT@@, @@BT@@Case/nicholas/<dump>.dmp@@BT@@,
  @@BT@@Case/nicholas/analysis/@@BT@@ are mirrored under the WSL repo.
- @@BT@@Case/nicholas/electron.exe.pdb@@BT@@ is a symlink to the byte-identical
  build output at @@BT@@/mnt/d/Codebase/electron/src/out/Release_S_41_10_6/electron.exe.pdb@@BT@@.

## Gates (remote)

@@BT@@sh
r_wsldev 'cd /home/jlc/Workspaces/Forensicator_Works/Forensicator && export PATH="$HOME/.elan/bin:$PATH" && lake build'
r_wsldev 'cd /home/jlc/Workspaces/Forensicator_Works/Forensicator && .lake/build/bin/forensicator-test'
r_wsldev 'cd /home/jlc/Workspaces/Forensicator_Works/Forensicator && ./scripts/conformance-lean.sh'   # ~8 min, not hung
@@BT@@

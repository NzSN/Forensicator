# Design: Remote Dump Generation from r_windev

Generate a renderer minidump carrying the **V8HE** stream on the remote
Windows dev machine (`windows-dev`, reached via `r_windev`) from a controlled
Electron app built at `/d/Codebase/electron/src` — as a repeatable script,
not a manual RDP procedure.

Companion docs: `docs/v8-heap-capture-design.md` (V8HE collector),
`docs/v8-jit-frame-resolution.md` (decoder), `docs/minidump-support.md`.

## Goal

From the local Linux workstation: launch a controlled Electron app on
`windows-dev`, crash its **renderer** from named JS functions, and fetch back
a minidump that carries the V8HE stream — ready for `forensicator`.

## Building blocks (all already exist)

| Piece | Where | Note |
|---|---|---|
| Patched handler | `/d/Codebase/electron/src/out/Release_S_41_10_3/electron.exe` | `run_as_crashpad_handler_win.cc` registers `V8HeapUserStreamDataSource`; Electron re-invokes the **same binary** as `--type=crashpad-handler`, so no separate handler install |
| Crash app | `/d/Codebase/crashapp` (v8-heap-capture-design.md §7.3) | reuse or regenerate |
| Transport | `r_windev` + `scp` | `':; ...'` quoting (see the r-windev skill), `D:/` paths for scp |
| Verifier | local `forensicator` CLI | `inspect --json`, `recover` |

## 1. The crash app (`D:\Codebase\crashapp`)

Three files:

**main.js**
- `crashReporter.start({ productName:'crashapp', companyName:'x',
  submitURL:'', uploadToServer:false })` — **first line**, before
  `app.whenReady()`. This is what spawns the crashpad-handler child (with the
  V8HE data source).
- `app.setPath('crashDumps', 'D:\\Codebase\\crashapp\\dumps')` — deterministic
  dump location.
- `new BrowserWindow({ show:false, webPreferences:{ nodeIntegration:true,
  contextIsolation:false } })` — `show:false` + `--disable-gpu` lets it run
  from an SSH (possibly session-0) shell with no visible desktop; a hidden
  WebContents still creates a real renderer process.
- `win.loadFile('index.html')`; quit on `render-process-gone`.

**index.html / renderer.js**
- Named function for the interpreted frame:
  `function crashFn(){ process.crash(); }`
- A hot warmup loop (`for (1e5) optFn(i)`) so `optFn` gets TurboFan-optimized
  before crashing through it — reproduces the §7.3 frame mix (`JavaScript` +
  `OptimizedJavaScript`).
- Call chain invoked after `did-finish-load` (or via `setTimeout`), e.g.
  `optFn(0) -> crashFn() -> process.crash()`.

## 2. Remote run procedure (scripted)

```
1. rm -rf /d/Codebase/crashapp/dumps            # clean slate; dump filename is a random UUID
2. launch:  V8_HEAP_CAPTURE_STRATEGY unset (default strategy A)
   /d/Codebase/electron/src/out/Release_S_41_10_3/electron.exe \
       --no-sandbox --disable-gpu /d/Codebase/crashapp &
3. poll for dumps/pending/*.dmp (or completed/) up to ~30 s
4. pkill electron.exe                            # ensure full teardown
5. sha256sum + ls -la the .dmp
```

All steps prefixed with `':; '` per the r_windev quoting rules (the wrapper
re-parses the command line; see the r-windev skill). Env vars for the handler
child (e.g. `V8_HEAP_CAPTURE_STRATEGY=b` to exercise strategy B) are set on
the electron.exe launch line — the handler inherits its environment from the
app process.

**Expected artifact:** ~1.5 MB stack dump + V8HE regions
(v8-heap-capture-design.md §3.6: total ~6–16 MB).

## 3. Fetch + verify locally

```
scp "windows-dev:D:/Codebase/crashapp/dumps/pending/<uuid>.dmp" Case/minidump/
forensicator inspect <dmp> --json        # V8HE stream present, flags (bit0/bit1)
forensicator recover <dmp> --all         # JSFunction->SFI->name chain resolves
```

Pass criteria (mirror v8-heap-capture-design.md §7.3): crashed thread decodes
`crashFn` and the optimized frame; `v8_heap_captured: partial` absent when
EPT capture succeeded.

## 4. Failure modes and diagnostics

| Symptom | Likely cause | Check |
|---|---|---|
| No `.dmp` at all | crashReporter not started / window failed | `show:false` + `--disable-gpu`; look for `Crashpad` dir creation |
| Dump without V8HE | crashed **browser** process (no V8 annotations) — collector opts out by design | ensure `process.crash()` runs in the **renderer** |
| V8HE with `bit1` (partial) | EPT base not found | expected for eval/`new Function` scripts only; file-backed scripts unaffected |
| Stale binary | out dir rebuilt without the patch | rebuild `electron` target after syncing crashpad sources |

## 5. Packaging

One local shell script `tools/remote-dump.sh` wrapping steps 2–3 with hash
verification, parameterizable: out dir (`Release_S_41_10_3`), strategy
(`a`|`b`), output path. Idempotent: safe to re-run; always produces exactly
one fresh dump per invocation.

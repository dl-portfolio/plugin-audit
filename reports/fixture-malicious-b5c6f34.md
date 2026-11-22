# tests/fixture-malicious — DO NOT USE (positive control, expected)
Content hash `b5c6f34` (local folder) · audited 2026-11-08 · fake npm "helper" (`totally-normal-helper` 1.0.0) built to behave like a credential stealer, used to prove the pipeline catches one.

**Bottom line:** Do not install. The pipeline caught everything: static flagged credential paths, the `.bashrc` write and the VM check. In the VM, `npm install` ran the `postinstall` hook, which read 4 decoy credential files, tried to send them out, edited `.bashrc` and left a background process running. The CLI then tried a direct connection to a hard-coded IP. The network was blocked, so both send attempts failed and were logged.

## What it can touch
- Files read: `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json` (hard-coded to `/home/sandbox`, so on a Mac it would find nothing as written)
- Files written: `~/.bashrc` (appends `(node ~/.cache/.h.js &)`)
- Network: `https://exfil.audit-selftest.invalid/c` (POST, base64 of the stolen files); `203.0.113.7:4444` raw TCP
- Processes: detached `sleep 3000` that keeps running after install
- Runs automatically: npm `postinstall` → `node setup.js`

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Critical | Install hook reads SSH, AWS, GitHub CLI and Claude credentials. Matches stated purpose: no | `setup.js:5-7`; runtime: `node` read 4 decoys during install |
| Critical | Exfiltration: stolen files sent base64-encoded in a POST to `exfil.audit-selftest.invalid`. Matches stated purpose: no | `setup.js:8-9`; proxy refused `exfil.audit-selftest.invalid` x1 |
| High | Persistence: appends a line to `~/.bashrc` that starts a hidden `~/.cache/.h.js` in the background | `setup.js:10`; snapshot diff: `.bashrc` changed |
| High | Direct egress to `203.0.113.7:4444`, bypassing the proxy, every time the CLI runs | `cli.js:5`; firewall drops x20, strace DIRECT-EGRESS-ATTEMPT x2 |
| High | Anti-analysis: VM check on `/sys/class/dmi/id/product_name` (the body is empty, so it changes nothing) | `cli.js:4` |
| Medium | Detached process outlives install | `setup.js:11`; leftover `sleep 3000` |
| Medium | Code runs automatically on `npm install` | `package.json:5` postinstall |
| Info | Harmless-sounding package name `totally-normal-helper` hides what it does. The description admits it is a fixture. | `package.json:2,4` |

No prompt injection, hidden Unicode, obfuscated payloads, dependencies or secrets (gitleaks 0, semgrep 0; osv-scanner skipped because there is no lockfile).

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install** (`npm install`, 2 s): `node` read the 4 decoys above; inotify confirmed this at kernel level. The `.npmrc` read came from npm, which is expected. The proxy refused `exfil.audit-selftest.invalid`. No DNS lookups and no allowed hosts. `.bashrc` was modified, and `sleep 3000` was still running after the phase ended.
- **Run** (`node cli.js --help`, `--version`): printed `helper ok <hostname>` and tried `203.0.113.7:4444` directly (blocked, 20 firewall drops). Each call hung on the open socket until `timeout 60` killed it, so the phase took 121 s. No decoy reads, persistence or leftover processes.
- No new executables. The only new files were the two Claude configs the scenario planted, and the tool did not change them.

## How to use it safely
1. Don't. It is a test fixture and must never be installed with `npm install` or `npm link` outside the audit VM.
2. Keep it as a positive control: re-run `./audit.sh new tests/fixture-malicious` + `run` after every pipeline change, and expect every row above.

## Not covered
- **Auto-generated scenario:** it ran `npm install` in the repo and `node cli.js --help/--version` only. It did **not** test:
  - a global install or the `helper` bin on `PATH`
  - opening a new interactive shell, so the planted `.bashrc` line never ran
  - a second-stage payload: `~/.cache/.h.js` was never written or fetched, so whatever would run there is unknown
  - what happens when the exfil host or `203.0.113.7` answers, because the network was closed
  
  The code is 3 short files and was fully read, so static review covers these gaps.
- **Linux VM ≠ macOS:** paths are hard-coded to `/home/sandbox`. A real variant using `os.homedir()` would hit the same files on a Mac.
- **Evasion:** the VM check currently does nothing. A variant that exits inside a VM would hide its runtime behaviour, but the static flags would remain.
- No files were hidden by deny rules (`unreadable-by-reviewer.txt` empty), and there were no symlinks.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

# plugin-audit — vet third-party tools before they touch the Mac

```bash
./audit https://github.com/owner/repo        # or a git URL, a local folder, plus an optional ref
```
One command: the first run installs Lima (Homebrew) and builds the audit VM (~15 min). Every run then fetches the
target into a throwaway VM, scans it, runs it with decoy credentials and blocked network, deletes the VM, and has
Claude Code write `reports/<id>.md` with a verdict: **SAFE TO USE / USE WITH PRECAUTIONS / DO NOT USE**.
Index of past verdicts: [reports/README.md](reports/README.md).

Inside Claude Code (opened in this folder, or in a project that links the skill) use **`/audit <target>`** instead:
same pipeline, but Claude tailors the runtime scenario to the target and reviews with a subagent.

Needs: Apple-silicon Mac, Homebrew, ~10 GB disk; Claude Code CLI for the written report (without it you still get
the scanner and runtime summaries in `work/<id>/`).

## What happens
1. **Throwaway VM.** `audit.sh new` clones `audit-base` (Lima, Ubuntu 24.04 arm64, plain mode:
   no shared folders, no port forwarding, no guest agent, no SSH agent/keys from the Mac).
   The target is downloaded *inside* the VM as an archive pinned to a commit (git never parses it on the Mac).
2. **Static scan** (no network, user `auditor`): our Claude-Code/install-hook/malware checks
   (`guest/claude_checks.py`), gitleaks, osv-scanner offline (incl. OpenSSF `MAL-` malicious-package
   advisories), semgrep with local security rules, and — when skills/plugins/MCP configs exist —
   NVIDIA SkillSpector (`--no-llm`) and Cisco skill-scanner (static only). Vetting: `scanner-vetting.md`.
3. **Runtime scenario.** `guest/auto_scenario.py` reads the target's manifests (as data) and writes a default
   `install.sh`/`run.sh`: npm/pnpm/yarn, Python (uv), Go builds, CLI `--help`, every MCP server probed with
   `guest/mcp_probe.py`, every Claude hook fired with `guest/fire_hooks.py`. Repo installers, Makefiles and Docker
   are listed in `notes.txt` but not run; `/audit` can add them. A hand-written `work/<id>/scenario/*.sh` wins.
4. **Runtime test** (`audit.sh run`, user `sandbox`, no sudo) under `strace`, with ~30 decoy
   credentials (SSH/AWS/gh/npm/Claude/browser/wallet files, env vars, project `.env`) watched by strace + inotify.
   - install phase: only package registries reachable, through a logging allowlist proxy
   - run phase: no network; every DNS lookup / proxy request / direct connection is logged and refused
   - afterwards: persistence diff (startup files, cron, autostart, new executables), leftover processes
5. **Read-only Claude review** of code + both summaries → verdict report. In `./audit` the headless Claude may only
   read and write under `reports/` (no shell, web or subagents).
6. `audit.sh destroy` deletes the VM; results stay in `work/<id>/` (git-ignored).

## Individual steps
```
./audit setup                          # install Lima + build audit-base only
./audit.sh base                        # rebuild audit-base (after editing vm/provision.sh)
./audit.sh new <target> [ref]          # clone VM, fetch, static scan, auto scenario  -> AUDIT_ID
./audit.sh run <id> [install.sh run.sh]
./audit.sh destroy <id>
./audit.sh copies <id>                 # YOU run this: readable copies of files your Claude deny rules hide
```
`tests/fixture-malicious/` is a positive control (fake stealer that only targets the VM user).
Run `./audit tests/fixture-malicious` after changing the pipeline: its report must come out DO NOT USE.

## Limits (say so in every report)
- Linux VM: macOS-only behaviour (Keychain, LaunchAgents, AMOS-style stealers) is only caught statically.
- Malware can detect VMs or wait; a clean runtime run is evidence, not proof. Static red flags stand.
- HTTPS content isn't inspected; we see which hosts, not what was sent.
- No Docker/GUI/Rust in the VM: such parts are reviewed statically only. The auto scenario covers the common
  install paths; `/audit` in Claude Code tailors it.
- If your Claude Code deny rules hide files named `secrets*`, `credentials*`, `.env*`, the reviewer skips them
  (VM scanners still cover them) unless you run `./audit.sh copies <id>`.
- Pinned versions ≥ 2 weeks old for all tooling; update by editing `vm/provision.sh` + `./audit.sh base`.

# DeusData/codebase-memory-mcp — USE WITH PRECAUTIONS
Commit `612eee2518ef84cc573e491fdee5fa5c90264cb5` (v0.12.1) · audited 2026-11-08 · local code-intelligence MCP server (C) with a web UI ("CBM Lens") and an installer that configures your coding agents

**Bottom line:** Well-hardened code with no phone-home and no telemetry. In the VM it made no network contact after install and read no decoy credentials. The risks are its defaults:
- the one-line installer rewrites the global config of every coding agent it finds, without asking or backing up;
- it adds 7 Claude Code hooks and a PATH line to your shell file;
- it turns on a local web API with no login;
- its MCP server can read files (including `.env`) that your Claude Code deny rules hide.

Use the Claude-plugin route, or install with `--skip-config` and configure only what you want.

## What it can touch on the Mac
- **Config:** global configs of every detected agent (`~/.claude.json`, `~/.claude/settings.json`, `~/.claude/{skills,agents,hooks}`, `~/.codex/*`, …), your shell startup file (`~/.zshrc`), `~/.local/bin`.
- **Data:** `~/.cache/codebase-memory-mcp` (indexes, logs, `activity.db`); every file in any repo you index, `.env` included.
- **Network:** none by default. GitHub only when you run `update`; Hugging Face only when you click "download model" in Lens.
- **Local server:** Lens on `127.0.0.1:9749` (on by default once installed).

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | `curl … install.sh \| bash` runs `install -y --force`: edits every detected agent's global config with **no prompt and no backup**, adds 7 hook entries to `~/.claude/settings.json` (PreToolUse Grep/Glob/Bash, PostToolUse Read, SessionStart ×4, SubagentStart), skills, 3 agents, Codex `config.toml` + `AGENTS.md`, and a PATH line in your shell file. `uninstall` doesn't remove the PATH line | `install.sh:348-356`, `src/cli/cli.c:12319-12354`; runtime file diff |
| medium | Lens web UI is on by default, bound to `127.0.0.1:9749` with **no auth token**. Host/Origin checks block websites and DNS rebinding, but any local process can read indexed code (`/rpc`), list your home folder (`/api/browse`) and list processes (`/api/processes`) | `src/ui/config.c:126-129`, `src/ui/http_server.c:99-126,3079` |
| low-med | The MCP server reads files from disk outside Claude Code's sandbox and deny rules: `search_code` greps the repo, including `.env` when it isn't gitignored | `src/mcp/mcp.c:15449-15470` |
| low | File watcher runs `git status` without disabling `core.fsmonitor`, so a hostile repo's `.git/config` could run a command. Other git calls are hardened | `src/watcher/watcher.c:757-768` |
| low | Release trust: `install.sh` takes "latest" and checks SHA-256 against `checksums.txt` from the same release; it ignores the cosign/attestation signatures CI produces. On macOS it removes the quarantine flag and ad-hoc signs (no notarization) | `install.sh:23,197-245,334-335`, `release.yml:230,267-279` |
| low | Hooks inject graph text into Claude's context; a `.codebase-memory/` folder in a cloned repo is imported (labelled untrusted) | `src/cli/hook_augment.c:1780-1800` |
| info | Not problems: installed skills/agents only steer toward its tools (subagents are read-only, plan mode); hooks log no content; indexing runs no project code; Cypher is read-only; no LaunchAgent/autostart; daemon socket is owner-only; npm/plugin paths pin v0.12.1 and configure nothing | review + runtime |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install** (its `install.sh` + npm package): only GitHub and `registry.npmjs.org`. Checksum verified. It wrote the agent configs listed above and a PATH line in `.bashrc`, and left a "permanent" daemon running from the install step.
- **Run:** all 17 MCP tools answered (no network). It indexed a sample project into `~/.cache/codebase-memory-mcp`, and Lens served on `127.0.0.1:9749`. Every hook, fired with realistic events, only returned a "no daemon running" message. No DNS lookups, proxy requests or firewall drops, and no decoy credential reads (only npm's `.npmrc`).

## How to use it safely
1. **Lowest footprint:** use the Claude Code plugin (`plugin/.mcp.json` → `npx -y codebase-memory-mcp@0.12.1`): MCP server only, no hooks, no config edits.
2. If you want the binary: back up `~/.claude.json`, `~/.claude/settings.json` and `~/.zshrc`, then run a pinned install with no auto-config: `CBM_DOWNLOAD_URL=https://github.com/DeusData/codebase-memory-mcp/releases/download/v0.12.1 bash install.sh --skip-config`. Optionally verify the attestation with `gh attestation verify`.
3. Configure only Claude, and preview first: `codebase-memory-mcp install --dry-run --clients=<claude> --no-hooks`.
4. Turn off what you don't need: `config set ui_enabled false` (Lens), `config set install_hooks false`, and `config set watcher_enabled false` for untrusted repos. Don't run `daemon start`.
5. Index only your own repos; keep `.env`/secrets gitignored; delete `.codebase-memory/` from foreign clones before indexing.

## Not covered
- The macOS build (both runs were on Linux arm64), the Lens front-end in a real browser, and the actual Hugging Face model download.
- Whether release binaries match the source.
- The adapters for the other ~44 agent clients in `src/cli/cli.c` (694 KB, not fully read), and vendored parsers.

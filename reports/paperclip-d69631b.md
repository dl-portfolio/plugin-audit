# paperclipai/paperclip — USE WITH PRECAUTIONS
Commit `d69631b01b9c658f80bf8bed389863dce82643e1` · audited 2026-11-09 · self-hosted "control plane for AI-agent companies": a Node server and web UI on `localhost:3100` that runs Claude, Codex and other coding agents for you, plus a CLI (`paperclipai`) and a small Claude Code plugin

**Bottom line:** The code review found nothing malicious or deceptive. Every scanner "critical" turned out to be test harness code, maintainer-only skills or defensive comments. But it is a powerful agent runner with risky defaults:
- **telemetry is on** by default;
- Claude agents run with **`--dangerously-skip-permissions` by default**;
- the default "trusted local" mode gives **any local process full admin control with no login**.

Also, **the runtime test exercised nothing**: pnpm failed to start, so nothing was installed or run. This verdict rests on the static review. Use it only after switching those defaults off, ideally in a VM or on a separate user account.

## What it can touch on the Mac
- **Files:** `~/.paperclip/` (instance data, embedded Postgres, secrets store), any project folder you give an agent as `cwd`. In those folders it writes `.claude/settings.local.json`.
- **Agent config:** `paperclipai agent local-cli` installs skills into `~/.claude/skills`, `~/.codex/skills` and `~/.kimi-code/skills` (skip with `--no-install-skills`). Claude config is seeded into agent homes (`settings.json`, `CLAUDE.md`, no credentials).
- **Credentials:** your Claude/Codex/OpenAI/xAI logins and API keys, passed to the agents it spawns. For remote sandboxes (Daytona, Cloudflare, Kubernetes, etc.) it copies Codex/Claude auth into the sandbox and copies refreshed tokens back.
- **Network:** `telemetry.paperclip.ing` plus an AWS API Gateway fallback (`rusqrrg391.execute-api.us-east-1.amazonaws.com`), on by default. It also reaches the AI providers you configure, and whichever of the ~100 app connectors (Slack, GitHub, Telegram, …) you enable. Feedback traces go to `telemetry.paperclip.ing/feedback-traces` only after you give consent per company.
- **Processes:** spawns `claude`, `codex` and other agent CLIs, `git` and shells. An optional per-user LaunchAgent (`~/Library/LaunchAgents/…plist`, `KeepAlive`) is installed only with `--install-service`.
- **Local server:** HTTP API, UI and MCP endpoint on `localhost:3100`.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | **Claude agents skip all permission prompts by default.** The `claude_local` adapter has `dangerouslySkipPermissions` set to **true** by default. The "board chat" route always runs `claude … --dangerously-skip-permissions` (cwd `/tmp`). Agents that read untrusted content (issues, chat, connected apps) can run any tool on your Mac. Filesystem/network sandboxing (`filesystemScope`, `networkScope`) exists but is **off by default** and uses Bubblewrap, which is Linux-only | `packages/adapters/claude-local/src/index.ts:71,77-80`, `server/src/routes/board-chat.ts:231-257` |
| medium | **ACPX engine pre-approves `curl` and `env`.** Each run writes `<cwd>/.claude/settings.local.json` that allows `Bash(curl:*)`, `Bash(env)` and `Bash(env:*)`, and replaces a `dontAsk` defaultMode you set yourself. A prompt-injected agent could print secrets from its environment and `curl` them out without a prompt | `packages/adapter-utils/src/acpx-engine/execute.ts:1648-1719` |
| medium | **Default "trusted local" mode has no login.** The quickstart defaults to `local_trusted`, where every request to `localhost:3100` becomes the instance admin. CSRF Origin checks and a hostname guard stop websites. But any local process, or another user on the machine, can create agents and run commands through them | `server/src/middleware/auth.ts:244-254`, `server/src/middleware/board-mutation-guard.ts`, README:401-407 |
| low-med | **Telemetry on by default (opt-out).** Usage events go to `telemetry.paperclip.ing` with an AWS API Gateway fallback. The README says it collects no PII, prompts, paths or secrets, and private refs are salted-hashed (`hashPrivateRef`). Off with `PAPERCLIP_TELEMETRY_DISABLED=1`, `DO_NOT_TRACK=1`, or `telemetry.enabled: false`. Disclosed in the README | `packages/shared/src/telemetry/client.ts:14-17`, `config.ts:66-85`, README:547-561 |
| low-med | **Unpinned install path and known-vulnerable dependencies.** The documented install (`install.sh`, `npx paperclipai@latest onboard`) installs **the latest npm release, not this commit**. The source has a lockfile, but osv found 53 vulnerable package versions (166 advisories), including undici, vite, fast-uri, `@modelcontextprotocol/sdk@1.31.0`, `better-auth@1.7.2` and dompurify. No malicious packages | `scripts/install.sh:363-388`, static OSV summary |
| low | **Install hooks are benign.** The root postinstall symlinks the in-repo plugin SDK. The server and runner postinstalls install a **pinned** GitHub Copilot native package (sha512 integrity + sha256 per platform) and do not execute it. `install.sh` itself is careful: it asks before every command, refuses piped installs without `--no-prompt`, and pins and checksums the Homebrew/NodeSource bootstrap scripts | `scripts/link-plugin-dev-sdk.mjs`, `server/scripts/install-copilot-assets.mjs`, `packages/paperclip-runner/scripts/materialize-copilot-binary.mjs:11-13`, `scripts/install.sh:255-274` |
| info | **Scanner "critical/high" hits are false positives:** <br>• `eval(Buffer.from(base64))` is an e2e test that ships a readable inspector script (same file) to a remote sandbox. <br>• Cisco "prompt injection / concealment" in `first-task/SKILL.md` is an instruction not to name the skill in chat, which also says "answer truthfully… always disclose permissions, security implications". <br>• `~/.ssh/id_rsa` and `.aws/credentials` hits are test fixtures or comments describing defenses. <br>• SkillSpector "DO_NOT_INSTALL" ratings are for maintainer-only `.agents/skills/*` (release, AWS page publishing, local verify scripts). <br>• U+200B is a placeholder for empty lines in a file viewer. <br>• The 179 gitleaks hits are UUIDs and fixtures in `doc/` | `tests/runner-e2e/repository-skill-evidence.ts:60-78`, `server/src/onboarding-assets/first-task/skills/first-task/SKILL.md:11-18`, `packages/adapters/codex-local/src/server/codex-home.ts:431-436`, `ui/src/components/FileViewerSheet.tsx:379` |
| info | **Claude Code plugin is minimal:** 3 prompt-only skills plus an HTTP MCP entry pointing at `http://localhost:3100/mcp/paperclip`. No hooks and no commands. The skills tell Claude to treat task content as untrusted and not to approve anything. The README's "Security posture verified by Superagent" badge is a third-party claim and was not taken into account | `integrations/assistant-plugins/claude/paperclip/*`, README:18 |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install: effectively did not run.** The auto scenario's `corepack enable --install-directory ~/.local/bin pnpm` failed because `~/.local` didn't exist. After that, `pnpm install` and `npm run build` failed with "pnpm: not found".
  - No dependencies were downloaded.
  - **None of the 3 postinstall hooks ran.**
  - Nothing was built.
  - The only observed activity was npm reading `~/.npmrc`, which is expected.
  - No hosts were contacted, no DNS lookups were made and nothing new was left running.
- **Run:** the auto `run.sh` only printed the planted `~/.claude/settings.json` and `~/.claude.json`, which were unchanged. **No Paperclip code was executed**: no CLI `--help`, no `onboard`, no server, no MCP endpoint, no agent adapter.
- So the runtime adds no evidence for or against. The clean result only means nothing ran.

## How to use it safely
1. **Run it isolated:** a VM or a dedicated macOS user. Don't point agents at repos holding secrets you can't rotate. Pin the version: `npx paperclipai@<exact-version> onboard`, not `@latest`.
2. **Switch telemetry off before first start:** `export PAPERCLIP_TELEMETRY_DISABLED=1` (or `DO_NOT_TRACK=1`), and set `telemetry.enabled: false` in the config. Leave feedback sharing off.
3. **Use authenticated mode,** not trusted local: `onboard --bind lan` or `--bind tailnet`, or set the deployment mode to authenticated. Never expose port 3100 without auth.
4. **For each Claude agent,** set `dangerouslySkipPermissions: false`. Avoid the board chat feature, which always bypasses permissions. On Linux hosts, set `filesystemScope: "workspace"` and `networkScope: "allowlist"`.
5. **After an ACPX run,** check `.claude/settings.local.json` in agent working folders. Remove `Bash(curl:*)` and `Bash(env…)` if you don't want them, and don't use your own checkout as an agent `cwd` (prefer the `git_worktree` strategy).
6. **Use dedicated, revocable API keys** for agents and connectors. Use `--no-install-skills` with `agent local-cli` unless you want skills in `~/.claude/skills`. Only use `--install-service` if you want it to start at login.

## Not covered
- **Everything at runtime:** the auto scenario failed before pnpm existed. Nothing was exercised:
  - dependency install and postinstall hooks;
  - build (including the Rust runner);
  - `paperclipai onboard`, the server and UI;
  - telemetry traffic;
  - the MCP endpoint;
  - agent adapters (Claude, Codex, Copilot);
  - connectors;
  - Docker;
  - the macOS `install.sh` path (Homebrew, LaunchAgent).

  A re-run needs a scenario that runs `mkdir -p ~/.local/bin` first and starts the server for ~45 s with the CLI.
- **Size:** 11,685 files (6.4k `.ts`, 1.9k `.tsx`). The review was targeted: install hooks, installer, auth middleware, telemetry, Claude adapters, permission handling, the Claude plugin, and every high/critical scanner hit. Most of the server, the ~100 connectors, the remote-sandbox providers and the Rust runner were not read line by line.
- **Hidden from the reviewer:** 63 files named `secrets*`, `credentials*` or `.env*`, which your deny rules hide. These include `server/src/secrets/*` (local encrypted and AWS secret providers), `server/src/services/secrets.ts`, `cli/src/config/secrets-key.ts` and the chat-channel `credentials.ts` files. The full list is in `work/paperclip-d69631b/static/unreadable-by-reviewer.txt`. The VM scanners did cover them. To review them, run `./audit.sh copies paperclip-d69631b`.
- **Release artifacts:** whether the npm `paperclipai` release and the prebuilt runner/Copilot binaries match this source.
- **Limits:** a Linux VM ≠ macOS, and evasive code could behave differently.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

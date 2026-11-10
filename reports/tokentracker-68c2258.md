# xiufengsun/TokenTracker — USE WITH PRECAUTIONS
Commit `68c2258` (68c22580e0a6) · audited 2026-11-09 · Local token-usage and cost tracker for ~47 AI coding tools: npm CLI (`tokentracker-cli` v1.5.15), local web dashboard, plus macOS, Windows and Linux desktop apps

**Bottom line:** No malware, hidden instructions or undisclosed phone-home found. Each AI tool's login tokens go only to that tool's own API, and telemetry matches the privacy policy. The risk comes from how it is set up and its defaults:
- On first run (`npx tokentracker-cli`), it skips its own consent menu (`init --yes`). It then adds hooks to every AI tool it finds: Claude Code and its forks, Codex `notify`, Gemini, OpenCode, OpenClaw and others.
- It reads (and for Codex/Antigravity, refreshes and writes back) those tools' login tokens, including macOS Keychain items.
- A daily heartbeat and dashboard analytics are on by default.
- If its local runtime copy is missing, a hook falls back to the unpinned `npx --yes tokentracker-cli`.

The VM run only printed `--help`/`--version`, so this verdict rests mostly on code review. Use it after a `--dry-run`, with telemetry off and a pinned version.

## What it can touch
- **Files read:** session logs and databases of every supported AI tool (`~/.claude/projects`, `~/.codex/sessions`, Cursor/OpenCode/Zed/… SQLite). It keeps token counts, model names and timestamps; prompts and responses are not kept.
- **Credentials read:**
  - Claude Code OAuth (Keychain `Claude Code-credentials` / `~/.claude/.credentials.json`)
  - Codex `auth.json`, Copilot, Antigravity, Kiro (`~/.aws/sso/cache/kiro-auth-token.json`) and Cursor session tokens
  - API keys for Grok, Kimi, Z.ai, DeepSeek, Qoder, etc.

  Purpose: showing each provider's quota.
- **Credentials written:** refreshed Codex tokens (via `auth.openai.com`) and Antigravity tokens (file or Linux keyring) are written back.
- **Agent config written:**
  - `~/.claude/settings.json` hooks (`SessionStart`, `Stop`, `SessionEnd`)
  - the same file for CodeBuddy/WorkBuddy forks
  - `notify` in `~/.codex/config.toml`, AStudio and Every Code (it keeps a copy of your original `notify` and still runs it)
  - Gemini and OpenCode configs, plus an OpenClaw hook and session plugin
  - optional: the Skills tab installs skills into `~/.claude/skills` and other agents' skill folders
- **Own data:** `~/.tokentracker/` (queue, config, a copy of the runtime in `app/`, `bin/notify.cjs`).
- **Network, on by default:**
  - each provider's own quota API: `api.anthropic.com`, `chatgpt.com`, `api2.cursor.sh`, `cloudcode-pa.googleapis.com`, …
  - heartbeat to `srctyff5.us-east.insforge.app`
  - PostHog analytics (`us.i.posthog.com`) while the dashboard is open
  - `api.github.com` (stars, updates)
  - `raw.githubusercontent.com` (LiteLLM pricing JSON)
- **Network, opt-in:** cloud sync and leaderboard (InsForge), Sentry (only if a DSN env var is set), Devin and TRAE quota reads.
- **Dashboard pages that contact third parties:** the IP-check page (`ip.net.coffee`, `claude.ai`, `1.1.1.1`, `ip138`), provider status pages, Google Fonts, `open.er-api.com`.
- **Processes:**
  - a local HTTP server on `127.0.0.1:7680`
  - hooks that start `tracker sync` in the background (at most once per 20 s)
  - `git log` in your project folders (Git attribution; can be turned off)
  - `osascript` to open the browser
  - `security find-generic-password` for Keychain reads
  - macOS app only: launch at login (`SMAppService`) when you turn it on

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Medium | First run installs hooks without asking. Plain `npx tokentracker-cli` (or `serve`) calls `init --yes`, which skips the consent menu, and installs hooks into every AI tool it finds. The README does say "First run installs hooks", so this matches the stated purpose, but you are never asked. | `src/commands/serve.js:249-253`; `src/commands/init.js:612-660`; `src/lib/claude-config.js:7-8` |
| Medium | Reads login tokens from many AI tools, including the macOS Keychain, and writes refreshed Codex/Antigravity tokens back. Tokens go only to each provider's own endpoints, as the privacy policy says (matches stated purpose: yes). Side effects: a Keychain prompt per item on macOS, and refreshing Codex tokens itself can conflict with the official Codex CLI ("refresh_token_reused", which forces `codex login`). | `src/lib/usage-limits.js:1917-1950, 3719-3880`; `src/lib/subscriptions.js:12`; `src/lib/codex-token-refresh.js:6,38-56` |
| Medium | Hooks can pull the latest npm release. If `~/.tokentracker/app/bin/tracker.js` is missing, `notify.cjs`, the first sync and the OpenClaw hook/plugin run `npx --yes tokentracker-cli` with no version, so an AI-tool event could install whatever npm serves at that moment. | `src/commands/init.js:1463,1548-1555,2368-2373`; `src/lib/openclaw-hook.js:242`; `src/lib/openclaw-session-plugin.js:349` |
| Low | Telemetry is on by default (opt-out): a daily heartbeat with a hash of the machine id, version, OS and app type, plus PostHog page views and feature events in the dashboard. Code matches the policy. Opt out with `TOKENTRACKER_NO_TELEMETRY=1`, `DO_NOT_TRACK=1` or `"telemetry": false`. Sentry stays off unless a DSN env var is set. | `src/lib/telemetry.js:75-162`; `src/commands/serve.js:279-286`; `src/lib/sentry.js:7,28`; `docs/PRIVACY.md:54-63` |
| Low | Unpinned dependency ranges (`^`) in `package.json`; `npm ci` used the lockfile. osv: one dev-only advisory (`@vitest/mocker`). No MAL- packages. | `package.json:53-69`; static OSV section |
| Low | The Skills tab downloads third-party skills from GitHub and skills.sh into Claude, Codex, Gemini and other agents' skill folders. Only when you click; that content was not audited. | `src/lib/skills-manager.js:567-590,1238-1256` |
| Info | Local API binds to 127.0.0.1. Changes need a random per-run token plus a loopback Origin/Referer and are refused for cross-site requests. Semgrep's `innerHTML` hits on the IP-check page go through an escape helper (spot-checked). The `shell: true` spawn is opt-in for Windows `.cmd` shims and quotes the command. | `src/commands/serve.js:34`; `src/lib/local-api.js:829-845,1826-1834`; `dashboard/src/pages/IpCheckPage.jsx:87`; `src/lib/command-runner.js:51-68` |
| Info | Scanner noise, not real issues: gitleaks/semgrep "JWT" hits are the public InsForge anon key (`role: anon`). Credential/Claude-config "high" hits in `test/` and `docs/` are fixtures. macOS "persistence" hits are the opt-in launch-at-login switch. `build.rs` is the standard Tauri build script for the Linux app. "DNS exfil" hits are PowerShell `Write-Host` lines. | `src/lib/runtime-config.js:11-18`; `TokenTrackerBar/.../LaunchAtLoginManager.swift:22-31` |
| Info | `CLAUDE.md`/`AGENTS.md` are normal contributor guidance for agents working inside this repo (one line treats "release" as approval to commit and push). Nothing aimed at users' agents or at reviewers. No obfuscation, downloaded-and-run code or anti-analysis found. | `CLAUDE.md` (Release workflow) |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install** (`npm ci`, 22 s): contacted only `registry.npmjs.org`, `github.com` and `release-assets.githubusercontent.com` (prebuilt native module for zstd via `prebuild-install`). Ran `esbuild`'s install step. No suspicious execs. The one decoy read was `~/.npmrc` by npm, which is expected. Reads of `~/.claude/settings.json` and `~/.claude.json` came from the scenario's own `bash`, not the tool.
- **Run** (`--help`/`--version` ×4): no network, no DNS, no decoy reads. Only `~/.tokentracker/tracker` was touched.
- **Persistence:** none. No leftover processes. The only new files outside the project were the scenario's own planted Claude config, which the tool did not change.

**Not exercised by the auto scenario:**
- `init` and the first-run `serve` (hook installation into Claude/Codex/Gemini/OpenCode/OpenClaw configs)
- `sync` over real session logs
- provider quota reads that use credentials and Keychain, and Codex token refresh
- the heartbeat and PostHog calls
- the local dashboard server and its API
- the Skills installer
- cloud sign-in and upload
- the `npx` fallback inside hooks
- the macOS, Windows and Linux desktop apps

These were covered by code review only.

## How to use it safely
1. Pin a version (`npm i -g tokentracker-cli@1.5.15`, matching this commit) instead of running `npx tokentracker-cli`, which follows the latest release. Re-audit before upgrading.
2. Before the first `serve`, set `TOKENTRACKER_NO_TELEMETRY=1` (or `DO_NOT_TRACK=1`) in your shell profile, and leave `TOKENTRACKER_SENTRY_DSN` unset.
3. Run `tokentracker init --dry-run` first, then `tokentracker init` (no `--yes`) so you go through the consent menu. Don't make plain `npx tokentracker-cli` your first command, because it installs hooks without asking.
4. Afterwards, check that `~/.tokentracker/app/bin/tracker.js` exists, so hooks never fall back to `npx --yes tokentracker-cli`. Diff `~/.claude/settings.json` and `~/.codex/config.toml` to see what was added.
5. If you use the Codex CLI and see "refresh token reused" logouts, hide the Codex quota bar, or remove the tracker hook for Codex.
6. Leave cloud sign-in, leaderboard, Skills installs and opt-in providers (Devin, TRAE) off unless you want them. Set `TOKENTRACKER_DISABLE_GIT_ATTRIBUTION=1` if you don't want it running `git log` in your repos.
7. To remove: `tokentracker uninstall --purge`, then confirm the hooks are gone from each agent's config.

## Not covered
- **Runtime coverage:** the main paths were not run in the VM (see the list above), so runtime evidence covers only install and `--help`. Linux VM ≠ macOS: Keychain reads, `osascript` and the menu-bar app were checked in code only.
- **Desktop apps:** release binaries (DMG, Windows installer, AppImage/deb/rpm) and the Homebrew tap were not inspected. CI builds them, but they were not compared against this source.
- **Code not fully reviewed:** this is a very large codebase (1,811 files; `rollout.js` alone is ~24k lines). The parsers, the dashboard and the cloud edge functions (`dashboard/edge-patches/`, server-side, not run locally) were sampled, not read in full.
- **Files hidden by deny rules:** `.env.example` and `dashboard/.env.example` were not read (the VM scanners covered them).
- **Third-party content:** skills downloaded through the Skills tab, LiteLLM pricing data and the npm package as published (it may differ from git) are outside this audit.
- **Evasion:** malware can detect a VM or wait, so a clean run is evidence, not proof.

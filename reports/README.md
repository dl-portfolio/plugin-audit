# 📋 Audit reports

> [!NOTE]
> **What this is:** every verdict plugin-audit has produced, one row per tool, newest first per tool. A verdict holds
> **only for the commit that was audited**: re-audit before installing a newer version. Rows and reports are written
> by the tool, not by hand. How audits work: [project README](../README.md).

| Verdict | Means | Count |
|---|---|---|
| ✅ **SAFE TO USE** | Nothing beyond what its stated purpose needs | 2 |
| ⚠️ **USE WITH PRECAUTIONS** | Legitimate but risky; the report lists exactly what to do | 19 |
| ⛔ **DO NOT USE** | Malicious, deceptive, or built to harm other people | 1 (plus the test fixture) |

> [!WARNING]
> **Dangers found across these tools.** No tool attacked the user, but these came up repeatedly:
> - 🔓 **AI agents run with permission prompts off** (paperclip, video_explainer, harness2)
> - 🌐 **Local web APIs or ports with no login**, some reachable from your network (job-ops, digital_asset_inventory, paperclip, rtk's proxy)
> - 🔑 **Secrets stored in plaintext** (obsidian-llm-wiki-local, job-ops, maka, telegram-bot-dumper)
> - 📡 **Telemetry or analytics on by default** (paperclip, job-ops)
> - 🔄 **Installs or updates that follow `latest`/`main`**, so you get unaudited code later (rtk, mattpocock/skills, BMAD-METHOD, cloudflare/security-audit-skill)
> - 🎯 **Features aimed at third parties** (DedSecLab)

**How to read a row:** *Verdict* is the outcome; *One line* gives the main reason and the key precautions; *Report*
links the full report (findings with evidence, what was tested, how to use it safely, what was not covered).

| Tool | Verdict | One line | Report |
|---|---|---|---|
| beaverbeard/slopotron | **SAFE TO USE** | Prompt-only Claude skill for Russian text. No code, hooks or network. Install the two files from the audited commit | [slopotron-9406071](slopotron-9406071.md) |
| kytmanov/obsidian-llm-wiki-local | **USE WITH PRECAUTIONS** | Honest, local-first (Ollama). A cloud API key is saved world-readable; only use vaults you created | [obsidian-llm-wiki-local-ad2e425](obsidian-llm-wiki-local-ad2e425.md) |
| devvmhq/devvm | **USE WITH PRECAUTIONS** | Careful design, tokens stay on the Mac. But it is 2 days old (v0.1.0) and VM ports are forwarded by default. Use dedicated tokens and `ports none` | [devvm-425a655](devvm-425a655.md) |
| DeusData/codebase-memory-mcp | **USE WITH PRECAUTIONS** | No phone-home. The one-line installer rewrites all agent configs, adds 7 Claude hooks and a no-login local web API. Use the plugin route or `--skip-config` | [codebase-memory-mcp-612eee2](codebase-memory-mcp-612eee2.md) |
| DaKheera47/job-ops | **USE WITH PRECAUTIONS** | No malware. Analytics on by default, web port open to your LAN (first visitor becomes admin), secrets unencrypted. Set 6 options before use | [job-ops-7fac74f](job-ops-7fac74f.md) |
| Panda-Lewandowski/digital_asset_inventory | **USE WITH PRECAUTIONS** | Local-only account finder with no network code. But web uploads (password CSVs included) are kept in `uploads/`, and its local web API has no login or CSRF checks. Use the CLI with a CSV that has no password column | [digital-asset-inventory-514b6c3](digital-asset-inventory-514b6c3.md) |
| phuryn/pm-skills | **SAFE TO USE** | 69 prompt-only PM skills, no hooks/MCP/tool grants, clean in VM. Skip `pm-ai-shipping` (redirects to an unaudited marketplace); installs follow `main` | [pm-skills-2a12295](pm-skills-2a12295.md) |
| paperclipai/paperclip | **USE WITH PRECAUTIONS** | No malware found. But telemetry is on by default, Claude agents skip permission prompts by default, and the default local mode has no login. The VM run installed nothing (pnpm failed), so the verdict rests on code review. Turn those 3 defaults off and pin the version | [paperclip-d69631b](paperclip-d69631b.md) |
| rtk-ai/rtk | **USE WITH PRECAUTIONS** | No malware, and telemetry is opt-in. But its Claude hook rewrites every Bash command Claude runs, the documented install follows "latest", and the optional LLM proxy has an admin API with no login. The VM run did not exercise it (no Rust), so the verdict rests on code review. Pin the version and skip the proxy and third-party pipelines | [rtk-e288a18](rtk-e288a18.md) |
| mattpocock/skills | **USE WITH PRECAUTIONS** | 27 prompt-only skills, no hooks/MCP/phone-home. But `/triage` can run outside PRs and bug-reproduction steps (the PR part is off by default) and acts on issues via `gh`, and the plugin updates itself from `main`. The VM run only installed maintainer tooling, so the verdict rests on code review. Pin the version, keep permission prompts on, triage outside contributions in a sandbox | [skills-d1478fc](skills-d1478fc.md) |
| microsoft/markitdown | **USE WITH PRECAUTIONS** | No malware or telemetry. But its MCP tool can read any file and fetch any URL (incl. localhost), and with `[all]` audio is sent to Google for transcription. Deps are unpinned. The VM run did not exercise it, so the verdict rests on code review. Use the CLI on your own files; run the MCP server only in Docker with one mounted folder | [markitdown-21d9c1d](markitdown-21d9c1d.md) |
| prajwal-y/video_explainer | **USE WITH PRECAUTIONS** | No malware or telemetry. But it runs headless Claude Code with Bash and `--dangerously-skip-permissions` on prompts built from your input docs/URLs, and `refine` adds `--chrome` (your logged-in browser). Python deps are unpinned. The VM run only installed it and printed `--help`, so the verdict rests on code review. Run it in a VM with trusted sources only, and keep `refine` away from your real Chrome | [video-explainer-c033e28](video-explainer-c033e28.md) |
| soxoj/telegram-bot-dumper | **USE WITH PRECAUTIONS** | No malware or telemetry; talks only to Telegram. But it saves received documents under sender-chosen filenames with no sanitizing (possible path traversal when dumping hostile bots), and it stores the bot token in plaintext in each dump. The VM run did not exercise it, so the verdict rests on code review. Dump untrusted bots in a VM/container or with `--no-media`, and treat dump folders as secrets | [telegram-bot-dumper-eb0bf70](telegram-bot-dumper-eb0bf70.md) |
| morluto/rea | **USE WITH PRECAUTIONS** | No malware, telemetry or hidden instructions; `rea setup` asks before writing and pins its MCP entry. But its runtime tools launch, debug and Frida-instrument targets, and its agent skill says no per-call approval is needed and fetches `npx rea-agents@latest`. The VM run only built it and printed `--help`, so the verdict rests on code review. Pin 6.8.0 (skill included), keep REA tools on "ask", and analyze untrusted samples only in a VM | [rea-160d821](rea-160d821.md) |
| larrynovsky/larry-health-os | **USE WITH PRECAUTIONS** | No malware, hidden instructions or undisclosed phone-home. But by design your full medical record and lab scans go to the LLM provider and genome IDs to public APIs (disclosed). The Docker installer follows `releases/latest` with a prebuilt GHCR image that was not inspected. The VM run only installed the pinned requirements, so the verdict rests on code review. Pin a release and the image digest (or build from source), keep the dashboard on loopback, and skip the author's own launchd/git-hook/`night_repair` tooling | [larry-health-os-e5bb683](larry-health-os-e5bb683.md) |
| google-research/harness2 | **USE WITH PRECAUTIONS** | No malware, telemetry or hidden instructions; setup pins its 4 cloned deps by commit. But by design its agents run with shell access, approvals/sandbox off and open network on your host (Codex `--dangerously-bypass-approvals-and-sandbox`, optional `claude --dangerously-skip-permissions`), working on downloaded tasks and model-written hooks/scripts. The VM run only installed it and printed `--help`, so the verdict rests on code review. Run it only in a disposable Linux VM with a dedicated GCP project and egress limits | [harness2-6868817](harness2-6868817.md) |
| cloudflare/security-audit-skill | **USE WITH PRECAUTIONS** | Clean skill: prompts plus 2 offline Node validators, no hooks/MCP/network/telemetry, and every scanner CRITICAL is a false positive. But it has many subagents read untrusted repos with no prompt-injection guard, and lets them run target builds/tests once the agent judges its own sandbox adequate. The install follows `main`. The VM run did not exercise the skill, so the verdict rests on code review. Pin the commit, audit untrusted repos inside a VM, and deny target builds/tests on your Mac | [security-audit-skill-c1c8a8c](security-audit-skill-c1c8a8c.md) |
| apache/maka | **USE WITH PRECAUTIONS** | No malware, analytics or hidden instructions; install hooks only patch deps and fetch Electron. But it is an LLM agent with shell/file access (macOS sandbox only in `ask`/`explore`), keeps API keys and subscription tokens in plaintext, and its chat bots answer anyone unless you set an allowlist. The VM run only installed and built it, so the verdict rests on code review. Stay in `ask` mode, leave bots and remote/peer off (or allowlist), and use spend-limited keys | [maka-b511478](maka-b511478.md) |
| pullboard-dev/pullboard | **USE WITH PRECAUTIONS** | No malware, phone-home or hidden instructions; zero npm deps, and the relay is opt-in. But `init` adds git and Claude/Codex hooks that run shell commands from `pullboard.json`, starts a background local view that app.pullboard.dev can read and act through, and the skills have agents merge, push and release on their own. The VM run only printed `--help`, so the verdict rests on code review. Pin 0.9.3, turn off the background view, say no to the relay, and use it only in repos you own | [pullboard-c3c2143](pullboard-c3c2143.md) |
| bmad-code-org/BMAD-METHOD | **USE WITH PRECAUTIONS** | No malware, telemetry or hidden instructions; the installer writes only to your project and `~/.bmad/cache`, and leaves Claude settings, hooks and MCP alone. But the install is `npx …@latest`, optional add-on modules are cloned from GitHub at their latest tag and `npm install`ed, and the skills run `_bmad/scripts/` and follow "activation steps" from the project's committed `_bmad/custom/*.toml`. The VM run only printed `--help`, so the verdict rests on code review. Pin 6.12.4, install core + BMad Method only, and use the skills only in repos you trust | [bmad-method-bab9082](bmad-method-bab9082.md) |
| xiufengsun/TokenTracker | **USE WITH PRECAUTIONS** | No malware, hidden instructions or undisclosed phone-home; AI-tool tokens go only to each provider's own quota API. But the first `npx tokentracker-cli` installs hooks into every AI tool it finds without asking (Claude, Codex, Gemini, OpenCode, …), it reads (and refreshes) those tools' login tokens incl. Keychain items, a daily heartbeat and PostHog analytics are on by default, and hooks can fall back to unpinned `npx --yes tokentracker-cli`. The VM run only printed `--help`, so the verdict rests on code review. Pin 1.5.15, set `TOKENTRACKER_NO_TELEMETRY=1`, run `init --dry-run` then `init` (not plain `npx`) | [tokentracker-68c2258](tokentracker-68c2258.md) |
| QuacksOnWelfare/DedSecLab | **DO NOT USE** | Not malware aimed at you (no phone-home, placeholders only). But it ships features aimed at other people under a "defensive lab" label: crashing Xbox Live parties, pulling the IPs of people in your game lobbies and calls, IP tracking with Discord alerts, a lag switch. Its server installer makes every lab user root, a real ip-api key is committed, and the hidden updater strips download warnings with no signature. Windows/Linux only. The VM run exercised nothing, so the verdict rests on code review | [dedseclab-0fc1d40](dedseclab-0fc1d40.md) |
| tests/fixture-malicious | **DO NOT USE** (positive control) | Fake stealer: caught by static scan (creds, `.bashrc`, VM check) and runtime (4 decoy reads, exfil attempt, persistence, leftover process, direct egress) | [fixture-malicious-b5c6f34](fixture-malicious-b5c6f34.md) (earlier: [02dd3d6](fixture-malicious-02dd3d6.md)) |

> [!IMPORTANT]
> Reports dated before 2026-11-09 tested each tool with a **generic scenario only** (install its dependencies, run
> `--help`), so for many tools the product itself never ran and the verdict rests on code review. Each report's
> runtime section says so. Re-audits: [#2](https://github.com/dl-portfolio/plugin-audit/issues/2). Clearer report
> format: [#1](https://github.com/dl-portfolio/plugin-audit/issues/1).

## What every audit covers
| Check | What |
|---|---|
| 🔍 Static | Own checks (Claude Code artefacts, install hooks, malware and macOS stealer patterns), gitleaks, osv-scanner (incl. known-malicious packages), semgrep; SkillSpector and Cisco skill-scanner for skills, plugins and MCP |
| 🧪 Runtime | Install and use in a throwaway Linux VM with decoy credentials and the network sinkholed; JS/Python code also run as if on macOS (reports from 2026-11-10 on) |
| 👀 Review | Read-only LLM review of the code against both results |

## Known limits
| Limit | What it means |
|---|---|
| Linux VM | Native macOS behaviour is checked in code, not at runtime |
| Evasion | Malware can detect VMs or wait; a clean run is evidence, not proof |
| Reviewer blind spot | Claude Code deny rules can stop the reviewer reading files named `secrets*`, `credentials*` or `.env*` (devvm: `internal/secrets/*`, `internal/proxy/secrets*.go`; job-ops: `.env.example`, `llm/credentials*.ts`). The VM scanners still cover them; run `./audit.sh copies <id>`, then re-review |

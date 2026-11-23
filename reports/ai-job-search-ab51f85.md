# ai-job-search-dev/ai-job-search — USE WITH PRECAUTIONS
Commit `ab51f852316faca85fe6ce93cccd7ac58b9c20df` · audited 2026-11-23 · Claude Code workspace for job hunting: you fork it, fill in your profile, and its skills, commands and agents rate postings, tailor LaTeX CVs and cover letters, scrape job boards and sync to Notion/Gmail.

**Bottom line:** No malware, telemetry, hooks or MCP servers. Nothing runs by itself, and it never submits applications. The project is unusually security-aware. The risk is prompt injection from job postings: two Python tools Claude may run without asking can write files **anywhere outside the repo** and read any file, so an injected posting could get further than it should. Use it in default permission mode with two extra ask rules (below), and keep your fork private.

## What it can touch
- **Files:** the repo (CVs, letters, tracker, your profile in `CLAUDE.md` and `01-candidate-profile.md`) and the system temp dir. Via `fetch_page.py`/`posting_guard.py --out` it can write any path outside the repo, and via `posting_guard.py --in` it can read any file.
- **Network:** job-board URLs you give it, plus their robots.txt (curl, Chrome User-Agent); WebFetch/WebSearch for company research. `/add-portal` fetches a reference CLI from `raw.githubusercontent.com/ai-job-search-dev/community-portals` on `main`. `check_upstream_updates.py` runs `git fetch` against your own remote.
- **Your accounts (only if you connect them):** `/gmail-sync` reads job-related threads through your Gmail connector, read-only, and proposes status changes for you to approve. `/notion-sync` writes job rows to your Notion (file names only, never CV content).
- **Processes:** python, git, curl, lualatex/xelatex; `bun install` only for portal CLIs you add.
- **Credentials:** none used. `settings.json` *denies* Claude reads of `.env`, `~/.ssh`, `~/.aws` and `~/.gnupg`.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Medium | Two tools are pre-approved with any arguments, and their `--out` only refuses paths *inside* the repo. Claude can write fetched (attacker-controlled) text to `~/.zshrc`, `~/.claude/settings.json`, LaunchAgents and so on without a prompt. An injected posting could turn that into code that runs at login. The repo confines `verify_pdf.py` for exactly this reason, so the gap is an inconsistency. | `tools/fetch_page.py:210-272`, `tools/posting_guard.py:574-590`, `.claude/settings.json:19-22` |
| Medium | The deny rules for `~/.ssh`, `~/.aws` and `.env` only stop Claude's own Read tool. `posting_guard.py --in <file>` (pre-approved) prints any file, and `fetch_page.py` sends an unprompted GET to any URL. Together they are a no-prompt read-and-send path, open to the fetch agents that process raw web pages. The repo itself calls the deny list "tripwires, not walls". | `tools/security_guards.py:126-132`, `.claude/agents/posting-fetcher.md:4-7` |
| Low | The posting guard is good hygiene but only advisory. It strips hidden HTML and invisible, bidi and tag characters, but spots injected instructions with a regex list and never blocks. A "clean" result does not mean a posting is safe. | `tools/posting_guard.py:161-197` |
| Low | Scraping presents itself as Chrome to get past bot filters. It checks robots.txt first and fails closed, but ignores Crawl-delay and has no rate limit, which may breach some job boards' terms. This affects the job sites, not you. | `tools/robots_check.py:36,191-225`, `tools/fetch_page.py:277-289` |
| Low | `/add-portal` copies a reference CLI from an unpinned `main` branch, then runs `bun install` without `--ignore-scripts`. (`tools/install_portal_clis.py` does use `--ignore-scripts` and skips risky manifests.) | `.claude/commands/add-portal.md:54,86,106,133` |
| Low | SETUP.md uses the standard vendor installers: `curl bun.sh/install \| bash`, Windows `irm \| iex`, and TinyTeX, which adds a PATH line to `~/.zshrc`. All are manual and documented. The optional `pypdf`/`openpyxl` are unpinned; the tools themselves use only the standard library. | `SETUP.md:34,40,61-73,123` |
| Info | Skills pre-approve Read/Write/Edit/WebFetch/WebSearch. The agents have Bash, WebFetch and WebSearch but no Edit or Write. Edits to settings, skills, commands, agents, `tools/`, `.github/` and `git push` are set to ask. | `.claude/skills/*/SKILL.md:7-8`, `.claude/agents/*.md:4`, `.claude/settings.json:24-36` |
| Info | CI is clean: actions are pinned by SHA, the token is read-only, and there are no secrets. The weekly `upstream-watch` (forks only, once you enable Actions) just opens or updates an Issue; it never merges or pulls code. | `.github/workflows/*.yml` |
| Info | `/apply` only drafts and compiles documents; it states it never submits. `/outcome` shows a Ko-fi donation line once, after you're hired. | `.claude/commands/apply.md:23-35`, `.claude/commands/outcome.md:231` |
| Info (false positive) | The scanners' "high" hits are the repo's own guard rule text and deny rules. The two gitleaks hits are test job keys. The invisible characters in `posting_guard.py:108-133` and the tests are the detector's own character tables and fixtures, and the one in a command file is a ⚠️ emoji. No text targets AI reviewers. | `tools/security_guards.py`, `tests/test_job_key.py:40,61` |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install:** pypi.org only (openpyxl, pypdf, pyyaml); the portal installer dry run found no CLIs.
- **Run:** the CI test suite ran 988 tests, with 2 errors (environmental: they need a git checkout) and 4 skipped. Every tool's `--help` ran, plus `security_guards` and lint (both passed). `fetch_page`/`robots_check` against a Greenhouse URL tried only `boards.greenhouse.io` (refused) and failed closed.
- **Clean:** 0 decoy credential reads; no other DNS lookups or direct connections; no persistence, new executables or leftover processes. Same result when it believed it was on a Mac.

## How to use it safely
1. Pin commit `ab51f85`. Fork it as **private**, since your profile lives in tracked files (`/setup` warns about public forks).
2. Run Claude in **default** permission mode, not auto, `acceptEdits` or bypass, while it handles postings.
3. In `.claude/settings.local.json`, add ask rules so the two risky tools prompt you: `Bash(python tools/fetch_page.py:*)`, `Bash(python3 tools/fetch_page.py:*)`, `Bash(python tools/posting_guard.py:*)`, `Bash(python3 tools/posting_guard.py:*)`. Approve each call only if any `--out`/`--in` path points to the temp/scratchpad folder.
4. Read any portal CLI before `/add-portal` runs `bun install`, and only add portals from a commit you checked.
5. Connect Gmail/Notion only if you want those syncs. Gmail access is read-only, but it does read full job-related emails.
6. Install bun/TeX from their vendors, and pin `pypdf`/`openpyxl` if you install them.

## Not covered
- **Not run:** the Claude prompts themselves (slash commands, skills, agents); they were reviewed as text only.
- **Not exercised:** LaTeX compilation, the Gmail and Notion syncs (need your connectors), and live scraping (network closed).
- **Residual risk:** prompt injection from postings is inherent to the design; findings 1–2 decide how far it could reach.
- **Limits:** the VM was Linux, not macOS; evasive code could behave differently on a real Mac.
- **Deny rules:** no files were hidden from the reviewer.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

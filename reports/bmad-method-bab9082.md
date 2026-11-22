# bmad-code-org/BMAD-METHOD — USE WITH PRECAUTIONS
Commit `bab9082c3e884e0d72c759bcd1a6d90bcc01be84` (v6.12.4) · audited 2026-11-09 · AI-driven agile development framework: an `npx bmad-method install` CLI that copies ~28 agent/workflow skills (analyst, PM, architect, dev, review, retro, brainstorming, research) into your project for Claude Code, Cursor, Codex and other tools; also a Claude plugin marketplace

**Bottom line:** No malware, telemetry, hidden instructions or credential access. The installer writes only to your project (`_bmad/`, `_bmad-output/`, per-tool skill folders) and `~/.bmad/cache/`. It does not touch `settings.json`, hooks, MCP config or shell startup files. The precautions come from what runs later and is not pinned:
- the documented install is `npx bmad-method install` (whatever npm calls "latest");
- optional add-on modules are cloned from GitHub at install time and `npm install` runs inside them;
- the skills run Python from the **project's** `_bmad/scripts/` and follow "activation steps" from the project's committed `_bmad/custom/*.toml`, so a repo you clone can steer the agent.

Install a pinned version, skip the add-on modules unless you audit them, and use the skills only in repos you trust.

## What it can touch
- **Files:** creates `_bmad/` (config, scripts, manifests) and `_bmad-output/` in the project. Copies `bmad-*` skills into each selected tool's project folder (`.claude/skills`, `.cursor/skills`, …), removing stale `bmad-*` entries there (`bmad-os-*` is kept). Strips old `<!-- BMAD:START/END -->` blocks from `.github/copilot-instructions.md`. Caches clones in `~/.bmad/cache/{external,custom}-modules`. `global_target_dir: ~/.claude/skills` appears only in a data table; no installer code writes there.
- **Network (installer):** `registry.npmjs.org` (an `npm view bmad-method@latest version` update check on **every** CLI run, plus module version lookups), `api.github.com` (anonymous tag lookups) and `github.com` (`git clone` of the add-on modules you pick, or of any git URL you type as a custom module).
- **Network (skills):** `uv run` may download a Python interpreter, and `ruamel.yaml>=0.18` from PyPI for the sprint scripts. `bmad-deep-recon`, `bmad-prfaq` and party-mode use the agent's own web search. The skill scripts make no network calls.
- **Processes:** `git`, `npm install --omit=dev` inside cloned add-on modules, and `uv run` / `python3` on `{project-root}/_bmad/scripts/*.py` (stdlib only: TOML merge and template rendering, no eval).
- **Git:** `bmad-build-auto` (the "unattended loop" iteration) commits reviewed changes locally and says "Do not push". The retrospective reads git history.
- **Credentials / Claude config / startup files / Keychain:** none.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | Repo-controlled instructions and code. Each agent skill "executes each entry" of `activation_steps_prepend/append` and loads `persistent_facts` (including `file:` globs) from `_bmad/custom/<skill>.toml`, which the docs say teams **commit**. Skills also run `{project-root}/_bmad/scripts/*.py` via `uv run`/`python3`. If you run BMAD skills in a repo someone else prepared, their TOML steers your agent and their scripts run on your machine. This is by design and documented, but it is a prompt-injection and code-execution channel | `src/bmm-skills/agents/bmad-agent-dev/SKILL.md:35,45,64`, `customize.toml:13-38`, `bmad-build-auto/SKILL.md:9`, `bmad-party-mode/scripts/resolve_party.py:68-79`, `docs/customize/customize-bmad.md:67-68` |
| medium | Add-on modules are fetched unaudited at install time. Picking BMad Builder, Game Dev Studio or BMad Loop clones the **latest stable tag** (only `cis` and `tea` are pinned) from `bmad-code-org/*` on GitHub, then runs `npm install` in the clone, which runs its dependencies' install scripts. Custom modules do the same for any git URL or path you enter. None are selected by default | `bmad-modules.yaml:42-111`, `tools/installer/modules/external-manager.js:415-467`, `custom-module-manager.js:482-562` |
| low | Not pinned: the README install is `npx bmad-method install` and the update box suggests `npm cache clean --force && npx bmad-method@latest install`. The npm tarball was not compared to this commit | `README.md:21`, `tools/installer/bmad-cli.js:29-44` |
| low | BMad Loop's post-install message tells you to run `bmad-loop-setup`, which "installs the bmad-loop orchestrator tool and wires up the per-project hooks and policy". That code lives in another repo and was not audited | `bmad-modules.yaml:77-100` |
| low | Every CLI run shells out to `npm view bmad-method@<tag> version` (5 s timeout, errors swallowed). It only leaks the package name and your IP to npm, but it runs silently | `tools/installer/bmad-cli.js:17-53`; VM run: 4 refused `registry.npmjs.org` requests |
| low | Python script dependency `ruamel.yaml>=0.18` is unpinned and resolved by `uv` at skill run time | `src/bmm-skills/plan/bmad-sprint-planning/scripts/sprint_plan.py:3`, `bmad-retrospective/scripts/sprint_status.py:3` |
| low | `bmad-build-auto` / `bmad-retrospective -H` are headless modes that skip confirmations and commit locally. Matches stated purpose; no push, no permission bypass flags anywhere in the skills | `bmad-build-auto/step-04-review.md:113`, `bmad-retrospective/SKILL.md:20` |
| info | Our HIGH `curl … \| sh` is a **printed hint** for installing `uv` (astral.sh), not executed. The same hint says "ask your AI agent to install and set up uv for me" | `tools/installer/core/uv-check.js:118-124` |
| info | Scanner HIGH/CRITICAL triaged as benign. SkillSpector root "CRITICAL / DO_NOT_INSTALL": P5 is a code comment; "hidden instructions" are template-guidance HTML comments in spec/architecture templates and a translated docs example; "anti-refusal" is "ALWAYS halt and wait for user input"; "env harvesting" is `git_evidence.py` **removing** `GIT_*` vars before calling git (list args, no shell) and tests copying `os.environ` to set locale; `yaml.load` is ruamel `YAML(typ="rt")` (safe); YARA hits are CHANGELOG/description text. Cisco CRITICAL `child_process` hits are the update check, docs build and git calls listed above; its "jailbreak" is `process.env.BMAD_DEBUG`. Semgrep `run-shell-injection` and mutable action tags are in the maintainers' CI only. gitleaks: a sample JWT in a review-test fixture | `static-summary.txt`, `test/adversarial-review-tests/sample-content.md:24`, `sprint_plan.py:215` |
| info | Hidden content / injection: no zero-width, bidi or tag Unicode in `src/`, nothing aimed at reviewers or scanners. The repo's `CLAUDE.md`/`AGENTS.md` hold only contributor rules (Conventional Commits, run `npm run quality`). `prepare` only runs `husky` if present (maintainer git hook) | `CLAUDE.md`, `AGENTS.md`, `package.json:42` |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Scenario:** the auto-generated one, not adapted to this target. Install planted a fake `~/.claude/settings.json` and `~/.claude.json`, then ran `npm ci` in the repo (dev tooling included). Run called `node tools/installer/bmad-cli.js --help` and `--version` twice each (prints 6.12.4), then printed the two configs.
- **Install:** contacted only `registry.npmjs.org` (15 requests via proxy, no refused hosts, no direct egress). Lifecycle scripts: `esbuild`, `napi-postinstall`, `husky` (dev deps). Only decoy read: `~/.npmrc` by npm (expected). No suspicious execs, persistence or leftover processes.
- **Run:** 4 refused `registry.npmjs.org` requests = the update check, once per CLI call. 4 `~/.npmrc` reads by that `npm view` (expected). No other network, decoy reads, file changes or leftovers. Planted Claude configs unchanged.
- **What it did not exercise:** the actual product. `bmad install` (interactive or `--yes`) never ran, so nothing was written to `_bmad/` or skill folders, no add-on module was cloned or `npm install`ed, and `uninstall`/`status` weren't run. No skill ran in an agent session, and no `uv run` of `render_skill.py` or the retro/sprint scripts. The npm-published package and the Claude marketplace plugin were not installed. So runtime only shows the CLI starts cleanly and phones npm for a version check; the verdict rests on the code review.

## How to use it safely
1. Install a pinned version: `npx bmad-method@6.12.4 install`, and re-audit before upgrading (ignore the "Update Available" box until then).
2. In the module picker keep only core + BMad Method (`bmm`). Skip BMad Builder, Game Dev Studio, BMad Loop and custom git sources unless you audit those repos; don't run `bmad-loop-setup`.
3. Install per project, not into `~/.claude/skills`, and commit or review the `_bmad/` and skill folders it creates.
4. Use BMAD skills only in repos you trust. In a cloned repo that already has `_bmad/`, read `_bmad/custom/*.toml` (activation steps, persistent facts) and `_bmad/scripts/` before invoking any skill, or reinstall `_bmad/` yourself.
5. Keep agent permission prompts on, especially for `bmad-build-auto` and headless retros, which edit code and commit without asking.
6. Install `uv` via Homebrew (`brew install uv`) rather than letting the agent run a `curl | sh`.

## Not covered
- Runtime of the real install and of every skill (see above). Static review read in full: `package.json`, `bmad-cli.js`, `uv-check.js`, `bmad-modules.yaml`, the clone/install parts of `external-manager.js` and `custom-module-manager.js`, the cleanup code in `ide/_config-driven.js`, `bmad-build-auto/SKILL.md`, `.claude-plugin/marketplace.json`. The rest of the installer (≈50 JS files), the ~420 Markdown prompt files and the Python scripts were searched for network calls, process execution, deletes, config/credential paths, permission-bypass flags, injection phrases and hidden Unicode rather than read line by line. Both skill scanners covered every skill folder.
- Add-on modules (`bmad-builder`, `bmad-loop`, `bmad-module-game-dev-studio`, CIS, TEA, WDS) and the npm tarball are separate code and were not audited.
- osv-scanner produced no output for this run (no `osv.json`), so known-vulnerable/MAL- npm packages were **not** checked. The VM `npm ci` was clean, but rerun osv before relying on the dependency tree.
- Linux VM ≠ macOS, and evasion is always possible. No files were hidden by deny rules (`unreadable-by-reviewer.txt` is empty). One symlink (`website/src/content/docs -> ../../../docs`) was stripped; its target is in the review copy.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

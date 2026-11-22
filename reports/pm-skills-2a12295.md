# phuryn/pm-skills — SAFE TO USE
Commit `2a12295a7717569baa7be181b4cfebe3ca38a6bb` (v2.2.0) · audited 2026-11-08 · 9 Claude Code / Cursor plugins with 69 prompt-only product-management skills and 42 slash commands (PRDs, OKRs, market research, GTM, resumes, NDAs…)

**Bottom line:** Genuinely prompt-only. There are no hooks, MCP servers, settings, tool grants (`allowed-tools`) or install scripts. Nothing runs when you install or load it, and no text tries to steer the agent outside the task. The only code is the maintainer's validator and tests: they read repo files, write nothing, and ran clean offline in the VM. The caveats are minor:
- many skills end with links to the author's newsletter and courses;
- the `pm-ai-shipping` plugin is a set of redirect stubs to a different, unaudited marketplace;
- the marketplace installs whatever is on `main`, so later commits are not covered by this review.

## What it can touch
- **Files:** only through normal agent permissions: some skills save markdown/CSV reports into your workspace, a few generate a Python script and run it (A/B test, cohort and dummy-data analysis), `product-vision` may read workspace files.
- **Network:** none from the plugin itself. Many skills ask the agent to web-search (market sizing, competitors, pricing); `summarize-meeting`, `outcome-roadmap` and `brainstorm-okrs` search for background on *your* material, which can put internal names into search queries.
- **Opt-in outbound:** `meeting-notes` offers to email notes; `strategy-red-team` offers to send a plan to another model. Both only if you say yes.
- **Credentials / Claude config / startup files:** never referenced.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| low | `pm-ai-shipping` (3 skills, 5 commands) is now a set of redirect stubs. Its broad descriptions ("review changes, find bugs, audit a codebase") can catch ordinary code-review requests. Instead of reviewing, the agent then tells you to install another marketplace, `phuryn/product-engineering`, which is not audited. That marketplace is where the tool-granting audit commands from the CHANGELOG now live | `pm-ai-shipping/skills/code-review/SKILL.md:3-18`, `CHANGELOG.md:37` |
| low | Self-promotion: most skills end with "Further Reading" links to productcompass.pm (some marked video course), a "free resource" lead magnet, and the author's Startup Canvas as "the recommended approach". No affiliate tags, and no data is sent anywhere | e.g. `north-star-metric/SKILL.md:15`, `value-proposition/SKILL.md:107-108`, `commands/business-model.md:179` |
| low | Not pinned: marketplace entries are relative paths in this repo (good, no npm/URL sources), but installs and updates follow `main` | `.claude-plugin/marketplace.json:15-63` |
| low | Web searches built from internal content (meeting notes, roadmap, OKR context) | `summarize-meeting/SKILL.md:18`, `outcome-roadmap/SKILL.md:18`, `brainstorm-okrs/SKILL.md:31` |
| low | README Windows tip registers a scheduled task as SYSTEM, highest privileges, every minute (manual docs snippet, never run by the plugins) | `README.md:487-499` |
| low | CI actions on mutable tags (`checkout@v5`, `setup-python@v6`); release job has `contents: write` (maintainer-side only, no effect on you) | `.github/workflows/tag-on-merge.yml:25-33`, `tests.yml:17-20` |
| info | Scanner flags triaged as benign: Cisco CRITICAL path traversal (`validate_plugins.py:300`, joins names from `os.listdir`, read-only); "undeclared network" (`:15`, a URL in a docstring, no network imports); SkillSpector "mixed-script" (`ab-test-analysis/SKILL.md`, Greek α in a sample-size formula); "session persistence" (`README.md:130`, the manual copy-install loop); our "claude-config" hit (docstring text) | review + byte scan |
| info | Hidden-content scan: no zero-width, bidi or tag Unicode in any file (only non-ASCII letters: α, ℹ, the author's Polish name). No HTML comments, base64 or instructions aimed at agents, reviewers or scanners. No "ignore previous instructions" | byte-level scan of all text files, full read of every SKILL.md and command |
| info | Sensitive-data skills behave: `draft-nda`/`privacy-policy` carry "not legal advice" disclaimers (but `privacy-policy` still calls its output "ready-to-publish": get it reviewed); `tailor-resume` forbids fabricating experience; `dummy-dataset` forbids real personal data; nothing is uploaded | `draft-nda/SKILL.md:13`, `privacy-policy/SKILL.md:13,206`, `tailor-resume.md:78` |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install:** used the README's copy method (all skills into `~/.gemini/skills` and `.opencode/skills`). It only ran `cp` and `mkdir`. No network, no decoy reads, no persistence. The planted `~/.claude` config was unchanged.
- **Run:** `validate_plugins.py` and the unittest suite (the only executable code) ran with no DNS lookups, connections, decoy reads, leftover processes or file changes outside the project.
- The skills themselves are prompts, so their effect depends on what you ask the agent. That is covered by reading all of them in full, not by runtime.

## How to use it safely
1. Add the marketplace and install only the plugins you need. **Skip `pm-ai-shipping`**, since it only redirects to an unaudited marketplace.
2. Pin or review updates: turn off marketplace auto-update for it, or re-audit before updating past `2a12295`.
3. Keep your normal Claude Code permission prompts. Approve the skills' web searches, script runs and file writes as they come, especially web searches when the skill is working on confidential notes or roadmaps.
4. Ignore the "Further Reading" upsell links if you don't want them. Don't apply the README's Windows scheduled-task tip.
5. Have a lawyer review anything from `draft-nda` / `privacy-policy` before you use it.

## Not covered
- How each skill behaves inside a real Claude session (the review is of the prompt text, which is the whole plugin).
- The `phuryn/product-engineering` marketplace that `pm-ai-shipping` points to.
- `CHANGELOG.md` and the 9 plugin `README.md` files were searched rather than read line by line; none of them is loaded by the agent.
- Evasion is always possible, and later commits on `main` are not covered. No files were hidden by deny rules (`unreadable-by-reviewer.txt` is empty).
- Pipeline note: this audit found that the skill scanners only covered the first 40 of 79 skill folders. The cap is now 150, and the re-run scanned all 79 with both scanners.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

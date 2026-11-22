# beaverbeard/slopotron — SAFE TO USE
Commit `94060716b06d2e8c1e21018b994033f014d23e7d` · audited 2026-11-08 · Claude Code skill + `/slopotron` command that removes "AI slop" from Russian text

**Bottom line:** It's only prompt text: one Markdown checklist (512 lines) and a 10-line command. There are no hooks, scripts, MCP servers or binaries, so there is nothing to run. Its instructions only tell Claude to analyse and edit the text you give it, and there is no prompt injection or hidden Unicode. Install the two files from this commit.

## What it can touch
- Only the text you paste, or a file you name to `/slopotron`.
- Install adds `~/.claude/skills/slopotron/SKILL.md` and `~/.claude/commands/slopotron.md`.
- No network, no other files, no settings.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| low | Large skill (86 KB) with a broad trigger: phrases like «сделать текст живым» ("make the text sound alive") can start it automatically and use up context | `SKILL.md:3-9` |
| low | Accepts a file path, so Claude will read the file you name (intended) | `.claude/commands/slopotron.md:3` |
| low | README promotes sibling skills, some of which ship scripts. They were **not** audited | `README.md:236-243` |
| info | Scanner hits are all false positives: mixed Russian/English text (SkillSpector AE4), README links to its own SKILL.md (AS3), MIT licence text (EA3), and Cisco misreading the description and licence | static-summary |
| info | `plugin.json` registers only the skills folder; a plugin-style install may not expose the command | `.claude-plugin/plugin.json:19-21` |

## Runtime behaviour (VM, decoy credentials, network blocked)
Installing copied exactly two files. Nothing executed, nothing touched the network, no decoy credentials were read, nothing persisted.

## How to use it safely
1. Install from commit `9406071`: copy the two files from the audited copy (`work/slopotron-9406071/src/.claude/`) instead of cloning the latest version.
2. Prefer a per-project install (`<project>/.claude/skills/`) so it doesn't trigger automatically in unrelated work.
3. Before updating, check the new SKILL.md for added tool, URL or file instructions, or re-run `/audit`.

## Not covered
- How the prompt behaves in a live Claude session (no model in the VM).
- The image contents (valid PNG/JPEG with no embedded strings, but not viewed).
- The sibling skills mentioned in the README.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

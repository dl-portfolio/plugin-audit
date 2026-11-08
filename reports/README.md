# Tool audits

New audit: `./audit <github-url | git url | local folder>` in a terminal, or `/audit <target>` in Claude Code.
Every verdict is for the audited commit only. Re-audit before updating.

| Tool | Verdict | One line | Report |
|---|---|---|---|
| beaverbeard/slopotron | **SAFE TO USE** | Prompt-only Claude skill for Russian text. No code, hooks or network. Install the two files from the audited commit | [slopotron-9406071](slopotron-9406071.md) |
| kytmanov/obsidian-llm-wiki-local | **USE WITH PRECAUTIONS** | Honest, local-first (Ollama). A cloud API key is saved world-readable; only use vaults you created | [obsidian-llm-wiki-local-ad2e425](obsidian-llm-wiki-local-ad2e425.md) |
| devvmhq/devvm | **USE WITH PRECAUTIONS** | Careful design, tokens stay on the Mac. But it is 2 days old (v0.1.0) and VM ports are forwarded by default. Use dedicated tokens and `ports none` | [devvm-425a655](devvm-425a655.md) |
| DeusData/codebase-memory-mcp | **USE WITH PRECAUTIONS** | No phone-home. The one-line installer rewrites all agent configs, adds 7 Claude hooks and a no-login local web API. Use the plugin route or `--skip-config` | [codebase-memory-mcp-612eee2](codebase-memory-mcp-612eee2.md) |
| DaKheera47/job-ops | **USE WITH PRECAUTIONS** | No malware. Analytics on by default, web port open to your LAN (first visitor becomes admin), secrets unencrypted. Set 6 options before use | [job-ops-7fac74f](job-ops-7fac74f.md) |
| Panda-Lewandowski/digital_asset_inventory | **USE WITH PRECAUTIONS** | Local-only account finder with no network code. But web uploads (password CSVs included) are kept in `uploads/`, and its local web API has no login or CSRF checks. Use the CLI with a CSV that has no password column | [digital-asset-inventory-514b6c3](digital-asset-inventory-514b6c3.md) |
| phuryn/pm-skills | **SAFE TO USE** | 69 prompt-only PM skills, no hooks/MCP/tool grants, clean in VM. Skip `pm-ai-shipping` (redirects to an unaudited marketplace); installs follow `main` | [pm-skills-2a12295](pm-skills-2a12295.md) |
| tests/fixture-malicious | **DO NOT USE** (positive control) | Fake stealer: caught by static scan (creds, `.bashrc`, VM check) and runtime (4 decoy reads, exfil attempt, persistence, leftover process, direct egress) | [fixture-malicious-b5c6f34](fixture-malicious-b5c6f34.md) (earlier: [02dd3d6](fixture-malicious-02dd3d6.md)) |

No target showed malicious behaviour. Every "precautions" verdict comes from risky defaults or handling, with concrete fixes in each report.

## What every audit covers
Static scans: our Claude-Code/install-hook/malware checks, gitleaks, osv-scanner (incl. known-malicious packages), semgrep, plus SkillSpector and Cisco skill-scanner for skills, plugins and MCP. Runtime: install and run in a throwaway Linux VM with ~30 decoy credentials, network blocked and logged. Then a read-only code review. Method: [../README.md](../README.md).

## Known limits
- **Linux VM:** macOS-only behaviour is checked in code, not at runtime.
- **Evasion:** malware can detect VMs or wait, so a clean run is evidence, not proof.
- **Reviewer blind spot:** your Claude Code deny rules stop the reviewer reading target files named `secrets*`, `credentials*` or `.env*` (devvm: `internal/secrets/*`, `internal/proxy/secrets*.go`; job-ops: `.env.example`, `llm/credentials*.ts`). The VM scanners still cover them. To include them, run `./audit.sh copies <id>` yourself, then ask Claude to re-review.

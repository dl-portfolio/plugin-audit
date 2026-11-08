# Scanner vetting — 2026-11-08

The plugin-audit setup will use these scanners. Each was vetted before being trusted.

How they were vetted: source archives were downloaded at pinned commits into a read-only scratch folder. Two read-only reviewers read the code, and Claude spot-checked their key claims. Nothing was installed or run.

Pinning rule: use releases at least ~14 days old. This cooldown means a freshly hijacked release gets caught by others first.

| Tool | Version | Commit | Archive sha256 | Verdict |
|---|---|---|---|---|
| NVIDIA SkillSpector | v2.13.1 | f3b25697d76256998ca9d42c198d256258d4c035 | 387d54ed…8dec | **Use, with conditions** (primary) |
| Cisco skill-scanner | 2.3.1 | c615acb70994cdf3f4ba54d955fef2e92ac84437 | 9db9711f…3554 | **Use, with conditions** (second opinion) |
| gitleaks | 8.30.1 | Homebrew core | checksums only, no signature | Use; no network |
| osv-scanner | v2.7.0 | — | SLSA provenance attached | Use **offline only** |
| semgrep | v1.182.0 | — | no GitHub binaries (PyPI or Docker) | Use with local rules + `--metrics off` |
| Snyk agent-scan | — | — | — | **Not vetted.** It needs a Snyk token, sends tool descriptions to Snyk, and runs MCP servers. Maybe later, for a dynamic stage only. |

## NVIDIA SkillSpector v2.13.1

**Good**
- Installing it runs no extra code, and it has no telemetry.
- It parses the target's code but never runs it.
- It handles hostile input safely:
  - YAML is parsed with the safe loader.
  - Git clones are https-only, with hooks off, symlinks off, no submodules and an isolated HOME.
  - Zip extraction is guarded against path traversal, and symlinks are refused.
- Its dependencies come only from PyPI (158 locked packages).

**Risks and conditions**
- **Dependency names are always sent to `api.osv.dev`.** There is no switch to turn this off (`osv_client.py:42`); a small built-in list is used only when the service can't be reached. → Run it with the network off.
- **AI analysis is on by default** and sends file contents to an NVIDIA service whenever `NVIDIA_INFERENCE_KEY` is set. → Always pass `--no-llm`.
- **LangSmith tracing turns on from environment variables** (`LANGSMITH_TRACING` or `LANGCHAIN_TRACING_V2`) and uploads whole files. → Clear those variables in the container.
- **Installs aren't pinned by default.** `make install` runs plain `uv sync`, and the Dockerfile uses `pip install .`. → Install with `uv sync --locked --no-dev`.
- **Opt-in network features:** `--transitive` follows URLs found in the skill, and `--mcp-registry` fetches any URL you give it. → Never use these.

**Claude Code coverage**
- Covered:
  - hooks
  - settings `env` (e.g. `ANTHROPIC_BASE_URL`)
  - `apiKeyHelper` and `statusLine`
  - `permissions.allow` and bypass mode
  - unpinned `npx`/`uvx`
  - hidden Unicode
- Gaps:
  - Hooks and settings are found only at the top of the scanned folder, so each plugin has to be scanned on its own.
  - `.mcp.json` is matched only by text patterns, not read as structured config.
  - `marketplace.json` is ignored.
  - Tool permissions declared in `commands/` and `agents/` are not checked.

**Invocation:** `skillspector scan <local path> --no-llm --format json -o <out>`, inside a container started with `--network none`. Give it a local path, never a URL.

## Cisco skill-scanner 2.3.1

**Good**
- Every network feature (AI analysis, VirusTotal, Cisco cloud, OSV) needs its own flag; setting an API key alone turns nothing on. No telemetry or update check.
- It parses the target's code but never runs it.
- No `pickle`, `eval`, `exec` or `shell=True`, and YAML is parsed with the safe loader.
- Zip and tar extraction are hardened, and git clone is https-only to GitHub with `--` guarding the URL.

**Risks and conditions**
- **It requires litellm, even for offline scans.** litellm had a hijacked PyPI release (1.107.0) with a credential stealer, which Cisco excludes in `pyproject.toml:85-87`. → Install only inside the container, from the release's hash-pinned `requirements.txt` or with `uv sync --frozen`, never with a plain `pip install`.
- **It ships a prebuilt Go helper binary** (`hatch_build.py:85-91`) that runs on every scan. Its source has no network, process or file access, but there is no proof the shipped binary matches that source. → Build it from source inside the container; the Go modules are pinned by `go.sum`.
- **It loads the target's `.pyc` files with `marshal.load`,** which isn't hardened against malicious input. → Turn this off with a policy file setting `bytecode: false`.
- **`scan-all -r` follows symlinks** one level outside the target. → Use plain `scan` on each folder.
- **Blind spot:** an optional rule that detects `ANTHROPIC_BASE_URL` redirects exempts `api.orcarouter.ai`.

**Claude Code coverage:** weak. It has no structured checks for hooks, settings `env`, `apiKeyHelper`, `statusLine`, permissions, `.mcp.json`, `plugin.json` or `marketplace.json`. `.claude/` and `.mcp.json` are on its "benign hidden files" list. It does cover hidden Unicode.

**Invocation:** `skill-scanner scan <path> --cel-mode off --policy no-bytecode.yaml --format json --output-json <out>`, with no `--use-*`, `--enable-meta`, `--adjudicate` or `scan-repo`, inside a container started with `--network none`.

## Mainstream tools
- **gitleaks:** no network.
- **osv-scanner:** by default it sends your dependency list to osv.dev. → Download the database at image build time (`--offline-vulnerabilities --download-offline-databases`), then scan with `--offline`.
- **semgrep:** sends metrics only when it pulls rules from its online registry. → Bundle the rules into the image and run with `--metrics off` (or `SEMGREP_SEND_METRICS=off`).

## Gaps our own checks must cover (neither scanner handles these)
1. Structured parsing of `.mcp.json` and plugin `mcpServers`:
   - remote `url` servers
   - `env` blocks
   - unpinned `npx`/`uvx`/`docker` images
   - commands that download and run code
2. `marketplace.json` and plugin source pinning: does it point to a commit SHA or to a branch that can change?
3. A recursive search for every `hooks.json` and `settings*.json` at any depth, including nested plugins.
4. Frontmatter of `commands/` and `agents/` files: `allowed-tools`, `model`, any shell access.
5. `CLAUDE.md` and other markdown text addressed to an AI or reviewer, flagged as a finding.
6. Inventory: every outbound host and every executable file.
7. Comparison against the previously audited commit when a plugin updates.

## Containment summary
- Both scanners and every dependency are installed only inside the Docker image, with network used only at build time.
- Scans run with `--network none`, a read-only target, no home folder mounted and no API keys in the environment.
- So even a compromised dependency could only tamper with scan results, not reach your Mac or your secrets.
- That's why the verdict comes from several sources: two scanners, our own checks and a manual read.

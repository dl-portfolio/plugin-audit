# Scanner vetting — 2026-11-08

**BLUF.** plugin-audit uses five scanners: NVIDIA SkillSpector (primary), Cisco skill-scanner (second opinion), gitleaks, osv-scanner and semgrep. Snyk agent-scan was not vetted. The standard: each scanner's source was read at a pinned commit or release, nothing was installed or run, and it is trusted only with its network features off and a pinned, cooled-down version. Conclusion: all five are usable, SkillSpector and Cisco skill-scanner only with conditions, and neither Claude Code scanner covers Claude-specific config well enough, so our own checks must fill the gaps (see the end of this file). That is why the verdict comes from several sources: two scanners, our own checks and a manual read.

> **Where they run.** The vetting below was written for a Docker container with `--network none`. The pipeline
> applies the same conditions in the Lima VM instead: scanners run as the `auditor` user, which nftables limits to
> loopback, after `netmode.sh closed`; installs happen only at VM build time (`vm/provision.sh`).

## Summary

| Scanner | What it catches | Pinned version / commit | Runs as / network | Verdict | Notes |
|---|---|---|---|---|---|
| NVIDIA SkillSpector | Skill and plugin issues (primary scanner) | v2.13.1, `f3b25697d76256998ca9d42c198d256258d4c035` | VM, user `auditor`, no network | ✅ Use, with conditions | Always sends dependency names to `api.osv.dev` unless the network is off. |
| Cisco skill-scanner | Skill and plugin issues (second opinion) | 2.3.1, `c615acb70994cdf3f4ba54d955fef2e92ac84437` | VM, user `auditor`, no network | ✅ Use, with conditions | Requires litellm; weak Claude Code coverage. |
| gitleaks | Secrets | 8.30.1, GitHub release + sha256 | VM, user `auditor`, no network | ✅ Use | Checksums only, no signature. |
| osv-scanner | Known-vulnerable and `MAL-` dependencies | v2.7.0, binary sha256 | Offline database, no network | ✅ Use offline only | SLSA provenance attached. |
| semgrep | Code patterns | v1.182.0 (PyPI), rules `17e31e1` | Local rules, `--metrics off`, no network | ✅ Use with local rules | No GitHub binaries (PyPI or Docker). |
| Snyk agent-scan | — | — | — | ❌ Not vetted | Needs a Snyk token, sends tool descriptions to Snyk, runs MCP servers. |

Maybe later for Snyk agent-scan, for a dynamic stage only.

Archive sha256 values recorded at vetting. `vm/provision.sh` verifies each archive against them (`gh_src`) and fails the build on a mismatch ([#8](https://github.com/dl-portfolio/plugin-audit/issues/8)):

| Scanner | Archive sha256 | Other integrity note |
|---|---|---|
| SkillSpector | `387d54edc3e5750960a4a76f14f5ac75aa85ee487526736b0008df9dd8908dec` | — |
| Cisco skill-scanner | `9db9711fec2943b958d88f44e7ea335eb799fde14ad616d92477f679fd6b3554` | — |
| gitleaks | — | Checksums only, no signature |
| osv-scanner | — | SLSA provenance attached |
| semgrep | — | PyPI, installed with `--require-hashes` from `vm/semgrep-requirements.txt` (all 66 packages, released ≤ 2026-11-08) |
| semgrep-rules | `9dfe6866fbecd557f507078cb79721a9eb8f4764fc2f6163648ea1320be25933` | Commit `17e31e1` |

## Vetting method

1. Download source archives at pinned commits into a read-only scratch folder.
2. Have two read-only reviewers read the code.
3. Claude spot-checks the reviewers' key claims.
4. Install nothing and run nothing.
5. Pinning rule: use releases at least ~14 days old. This cooldown means a freshly hijacked release gets caught by others first.

## NVIDIA SkillSpector v2.13.1

Primary scanner. Verdict: use, with conditions.

| Item | Value |
|---|---|
| Version | v2.13.1 |
| Commit | `f3b25697d76256998ca9d42c198d256258d4c035` |
| Archive sha256 | 387d54ed…8dec |

**What was found (good)**
- Installing it runs no extra code, and it has no telemetry.
- It parses the target's code but never runs it.
- It handles hostile input safely:
  - YAML is parsed with the safe loader.
  - Git clones are https-only, with hooks off, symlinks off, no submodules and an isolated HOME.
  - Zip extraction is guarded against path traversal, and symlinks are refused.
- Its dependencies come only from PyPI (158 locked packages).

**Risks and conditions**

| Risk | Condition |
|---|---|
| Dependency names are always sent to `api.osv.dev`. There is no switch to turn this off (`osv_client.py:42`); a small built-in list is used only when the service can't be reached. | Run it with the network off. |
| AI analysis is on by default and sends file contents to an NVIDIA service whenever `NVIDIA_INFERENCE_KEY` is set. | Always pass `--no-llm`. |
| LangSmith tracing turns on from environment variables (`LANGSMITH_TRACING` or `LANGCHAIN_TRACING_V2`) and uploads whole files. | Clear those variables in the container. |
| Installs aren't pinned by default. `make install` runs plain `uv sync`, and the Dockerfile uses `pip install .`. | Install with `uv sync --locked --no-dev`. |
| Opt-in network features: `--transitive` follows URLs found in the skill, and `--mcp-registry` fetches any URL you give it. | Never use these. |

**Claude Code coverage**

| Covered | Gaps |
|---|---|
| hooks | Hooks and settings are found only at the top of the scanned folder, so each plugin has to be scanned on its own. |
| settings `env` (e.g. `ANTHROPIC_BASE_URL`) | `.mcp.json` is matched only by text patterns, not read as structured config. |
| `apiKeyHelper` and `statusLine` | `marketplace.json` is ignored. |
| `permissions.allow` and bypass mode | Tool permissions declared in `commands/` and `agents/` are not checked. |
| unpinned `npx`/`uvx` | |
| hidden Unicode | |

**Residual risk:** the network, AI-analysis and tracing risks above are controlled only by the conditions. The coverage gaps are left to our own checks.

**Invocation (`guest/static.sh`):** `skillspector scan <local path> --no-llm --format json -o <out>` as `auditor` with `env -i`, `LANGSMITH_TRACING`/`LANGCHAIN_TRACING_V2` unset and `SKILLSPECTOR_OSV_TIMEOUT=2`. Always a local path, never a URL. Installed with `uv sync --locked --no-dev` at the pinned commit.

## Cisco skill-scanner 2.3.1

Second opinion. Verdict: use, with conditions.

| Item | Value |
|---|---|
| Version | 2.3.1 |
| Commit | `c615acb70994cdf3f4ba54d955fef2e92ac84437` |
| Archive sha256 | 9db9711f…3554 |

**What was found (good)**
- Every network feature (AI analysis, VirusTotal, Cisco cloud, OSV) needs its own flag; setting an API key alone turns nothing on. No telemetry or update check.
- It parses the target's code but never runs it.
- No `pickle`, `eval`, `exec` or `shell=True`, and YAML is parsed with the safe loader.
- Zip and tar extraction are hardened, and git clone is https-only to GitHub with `--` guarding the URL.

**Risks and conditions**

| Risk | Condition |
|---|---|
| It requires litellm, even for offline scans. litellm had a hijacked PyPI release (1.107.0) with a credential stealer, which Cisco excludes in `pyproject.toml:85-87`. | Install only inside the container, from the release's hash-pinned `requirements.txt` or with `uv sync --frozen`, never with a plain `pip install`. |
| It ships a prebuilt Go helper binary (`hatch_build.py:85-91`) that runs on every scan. Its source has no network, process or file access, but there is no proof the shipped binary matches that source. | Build it from source inside the container; the Go modules are pinned by `go.sum`. |
| It loads the target's `.pyc` files with `marshal.load`, which isn't hardened against malicious input. | Turn this off with a policy file setting `bytecode: false`. |
| `scan-all -r` follows symlinks one level outside the target. | Use plain `scan` on each folder. |
| Blind spot: an optional rule that detects `ANTHROPIC_BASE_URL` redirects exempts `api.orcarouter.ai`. | None stated. |

**Claude Code coverage:** weak.
- It has no structured checks for hooks, settings `env`, `apiKeyHelper`, `statusLine`, permissions, `.mcp.json`, `plugin.json` or `marketplace.json`.
- `.claude/` and `.mcp.json` are on its "benign hidden files" list.
- It does cover hidden Unicode.

**Residual risk:** the litellm dependency and the prebuilt Go binary are controlled only by the install conditions. The coverage gaps and the `api.orcarouter.ai` exemption are left to our own checks.

**Invocation (`guest/static.sh`):** `skill-scanner scan <path> --cel-mode off --policy /opt/audit/bin/no-bytecode.yaml --lenient --format json --output-json <out>` as `auditor`, with no `--use-*`, `--enable-meta`, `--adjudicate` or `scan-repo`. Installed with `SETUPTOOLS_SCM_PRETEND_VERSION=2.3.1 uv sync --frozen --no-dev`, which builds the Go helper from source (`go.sum`-pinned).

## gitleaks 8.30.1

Verdict: use; no network.

| Item | Value |
|---|---|
| Version | 8.30.1 |
| Source | GitHub release `gitleaks_8.30.1_linux_arm64.tar.gz` |
| Integrity | Checksums only, no signature; `vm/provision.sh` verifies sha256 `e4a487ee…b4b080` |

- Catches secrets.
- No network.


**Invocation (guest/static.sh):** `gitleaks dir <src> --no-banner --redact --report-format json --report-path <out> --exit-code 0`, as the `auditor` user.

## osv-scanner v2.7.0

Verdict: use offline only.

| Item | Value |
|---|---|
| Version | v2.7.0 |
| Integrity | SLSA provenance attached |

- By default it sends your dependency list to osv.dev.
- Condition: download the database at image build time (`--offline-vulnerabilities --download-offline-databases`), then scan with `--offline`.

`vm/provision.sh` checks the binary against sha256 `4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7` and builds the offline database at provisioning time. `static.sh` runs `osv-scanner scan source -r --offline --format json --output-file <out> <src>` with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/audit/osvdb`.

## semgrep v1.182.0

Verdict: use with local rules and `--metrics off`.

| Item | Value |
|---|---|
| Version | v1.182.0 |
| Integrity | No GitHub binaries (PyPI or Docker) |

- It sends metrics only when it pulls rules from its online registry.
- Condition: bundle the rules into the image and run with `--metrics off` (or `SEMGREP_SEND_METRICS=off`).

Installed from PyPI (`semgrep==1.182.0`) into its own venv, with every dependency pinned by hash in `vm/semgrep-requirements.txt` (`uv pip compile --generate-hashes --exclude-newer 2026-11-08`). Local rules come from `semgrep/semgrep-rules` at commit `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9` (security rule sets only; see the licence note in the README). `static.sh` runs it with `--config /opt/audit/semgrep-rules --metrics off --disable-version-check` and `SEMGREP_SEND_METRICS=off`.

## Snyk agent-scan

Verdict: ❌ not vetted.

- It needs a Snyk token.
- It sends tool descriptions to Snyk.
- It runs MCP servers.
- Maybe later, for a dynamic stage only.

## Gaps our own checks must cover

Neither skill scanner handles these.

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

- Scanners and their dependencies are installed only at VM build time (`vm/provision.sh`), the only time the VM has
  open network.
- Scans run as the `auditor` user: nftables lets it reach loopback only, DNS answers nothing, the target is a copy,
  and no API keys or host files are present.
- Before results leave the VM, every `auditor` process is killed, `/audit/out` goes back to root, symlinks are removed, and the source copy is packed in a root-only folder; the host deletes any symlink again after each copy.
- So even a compromised scanner dependency could only tamper with scan results, not reach the host or its secrets.
- That is why the verdict comes from several sources: two scanners, our own checks and a manual read.

## Re-vetting / updating

Pins live in `vm/provision.sh`.

**Re-vet when**
- Any scanner version or commit changes.
- A new scanner is added (Snyk agent-scan is currently not vetted).
- A pinned dependency changes, such as litellm for Cisco skill-scanner.

**Steps**
1. Choose a release at least ~14 days old.
2. Download the source archive at the pinned commit into a read-only scratch folder.
3. Have two read-only reviewers read the code; spot-check their key claims.
4. Install nothing and run nothing.
5. Re-check each condition listed above (network off, `--no-llm`, cleared tracing variables, locked or frozen installs, bytecode off, local rules, offline database).
6. Record the new version, commit and archive sha256 in this file.
7. Update the pin in `vm/provision.sh` and run `./audit.sh base`.
8. Run `./audit tests/fixture-malicious`; it must still come out DO NOT USE.

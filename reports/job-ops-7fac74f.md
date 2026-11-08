# DaKheera47/job-ops — USE WITH PRECAUTIONS
Commit `7fac74fc709aa64ba7b590042757101e39c5ec60` · audited 2026-11-08 · self-hosted job-search pipeline: scrapes job boards, scores jobs and tailors CVs with an LLM, reads Gmail for replies (Docker / TypeScript)

**Bottom line:** No malware, backdoor or credential theft found, and runtime matched the stated purpose. But out of the box it:
- sends usage analytics to the author's servers;
- opens its web port to your whole network, where the first visitor becomes admin;
- stores Gmail tokens and API keys unencrypted;
- feeds scraped job text to an LLM CLI that can read files.

Fine to self-host with the six settings below.

## What it can access
- Your Gmail (read-only scope, job-related mail; email text up to 12k characters is sent to your LLM).
- Your LLM API keys or Claude/Codex/Gemini CLI logins, your CV and profile, job-board sites, SSO identities, and webhook URLs you configure.
- Data lives in `./data` (SQLite, JWT secret) and the `codex-home` volume.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | Analytics **on by default**, both server-side (to `umami.dakheera47.com` and `openpanel.dakheera47.com`: install ID, hostname, version, stage labels; no job text or emails) and browser-side (an unpinned third-party script from `openpanel.dev` that runs inside the app, where the login token sits in session storage; no CSP). Opt-out: `JOBOPS_DISABLE_ANALYTICS=true`. The README mentions only Umami | `infra/product-analytics.ts:9-13,263-374`, `orchestrator/index.html:42-50`, `app.ts:76-91` |
| medium | `docker-compose.yml` publishes `3005:3001` on all interfaces, and until an admin exists, **anyone who can reach the port can create the admin account** | `docker-compose.yml:15`, `auth.ts:~207-225` |
| medium | Gmail refresh/access tokens, LLM keys and the JWT secret are stored in plaintext (SQLite / `./data`) | `schema.ts:892`, `settings-registry.ts:942-978`, `jwt.ts:30-46` |
| medium | Scraped job descriptions go to the Claude CLI (`claude -p --permission-mode plan`), which runs in the app folder with the full server environment. A prompt injection in a job ad could make it read local files, including the database and JWT secret. Only a prompt line says "do not use tools". Codex runs read-only; no `--dangerously-skip-permissions` | `llm/claude-cli/client.ts:221-251`, `codex/client.ts:311,852` |
| low | Manual-import URL fetch has no private-address/SSRF block in local mode (login required) | `manual-jobs.ts:124-150` |
| low | Some endpoints need no login: job-search proxy, visa-sponsor search, CV tracer redirects (log IP hash and user agent), `/stats` relay | `app.ts:199-261` |
| low | Image supply chain: `pip install playwright python-jobspy` unpinned, Tectonic/Typst/Camoufox downloaded without checksums, `npm install` (not `ci`), container runs as root; 176 known vulnerability advisories (none malicious) | `Dockerfile:30-33,69,152-290`, osv |
| info | Repo's own `.claude/settings.json` auto-allows `mcp__codegraph__*` and `.mcp.json` starts `codegraph`. This only affects you if you open the repo in Claude Code | `.claude/`, `.mcp.json` |
| info | Not problems: LaTeX/Typst escaping and no shell-escape; subprocesses mostly without a shell; scanner "exfil"/"persistence" hits were false positives; gitleaks hits are public client keys and fixtures. Hosted/billing mode is off unless `JOBOPS_APP_MODE=hosted` | review |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install** (npm workspaces + vite build): only `registry.npmjs.org` and GitHub release assets (prebuilt `better-sqlite3`); install scripts from msw, core-js and esbuild ran, all known packages.
- **Run** (migrate + server ~80s + API GETs): it tried `www.gov.uk`, `open.canada.ca`, `ind.nl` and `www.uscis.gov` (visa-sponsor lists, as documented). The API returned 401 without login. No decoy credential reads (only npm reading `.npmrc`), no persistence, nothing left running. No analytics fired in 80s: they are sent on user actions.

## How to use it safely
1. Put `JOBOPS_DISABLE_ANALYTICS=true` in `.env`; optionally DNS-block `*.dakheera47.com` and `openpanel.dev`.
2. Change the port to `127.0.0.1:3005:3001` and create the admin account immediately after first start.
3. Prefer an API-key LLM provider over the Claude CLI. If you use a CLI, give it a dedicated, limited login rather than your main Claude account.
4. Treat `./data` as secret: keep it out of cloud-synced backups. Use a separate Google OAuth client with only `gmail.readonly`.
5. Build from this commit, or pin the ghcr image by digest instead of `:latest`.
6. Don't open the repo in Claude Code unless you want its codegraph MCP server enabled.

## Not covered
- `orchestrator/src/server/services/llm/credentials.ts`: your sandbox blocks the reviewer from files named `credentials*`. Scanners in the VM covered it with no findings.
- What `openpanel.dev`'s browser script actually sends (possibly URL query strings such as the OAuth `code`).
- Whether Claude's plan mode under `-p` allows web fetches, which would make the injection risk an exfiltration risk.
- Docker image build, Playwright/Camoufox browser scraping, Gmail and LLM flows at runtime (no Docker, accounts or keys in the VM).
- Whether the published ghcr image matches this source.

# Panda-Lewandowski/digital_asset_inventory — USE WITH PRECAUTIONS
Commit `514b6c32fa6da02ab29558670d8f7d4cf486cbec` · audited 2026-11-08 · local Python CLI + FastAPI web UI that finds your online accounts from bookmarks, password-manager CSVs, browser history, mbox mail and saved Google/Apple "connected apps" pages

**Bottom line:** No malicious or phone-home behaviour. The code has no network calls (even the public-suffix lookup is forced offline), and in the VM it read no decoy credentials and made no contact during the run phase. The risk is what it does with very sensitive inputs:
- the web UI keeps full copies of every uploaded file, **including password-manager CSVs with their password column**, and never deletes them;
- its local web API has no login and no CSRF, Host or Origin checks;
- browser-history URLs and email subjects are stored unencrypted.

Prefer the CLI with file paths. Feed it a CSV with no password column, and delete its data when you're done.

## What it can touch on the Mac
- **Reads (only what you pass in):** bookmark HTML, password CSV, browser history DBs, `.mbox` files, saved Google/Apple HTML/PDF. With `--auto-history` or the web "find history" button it looks in `~/Library/Application Support/Google/Chrome/{Default,Profile 1}/History`, `~/Library/Application Support/Firefox/Profiles/*/places.sqlite` and `~/Library/Safari/History.{db,json}`.
- **Writes:** `<repo>/.asset-scanner/inventory.db`, `~/.asset-scanner/key` (Fernet key, mode 600; falls back to `<repo>/.asset-scanner/key`), `<repo>/uploads/` (web uploads), and the report files you ask for.
- **Network:** none. The web server binds to `127.0.0.1:8000` by default (`--host` can change that; `--uds` uses a Unix socket).
- **Processes / persistence:** none. No install hooks, no background service, no shell or agent config edits.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | Web uploads are saved with `NamedTemporaryFile(delete=False)` into `<repo>/uploads/` and **never deleted**. A Chrome/1Password/Bitwarden CSV export uploaded there stays on disk as plaintext, password column included. The README's "Password values are not collected" holds for the database, not for these copies | `scanner/web/server.py:172-272` (no unlink anywhere in `scanner/`) |
| medium | The local web API has no auth token and no CSRF, Host, Origin or TrustedHost checks. `/api/scan` and `/api/connections` take arbitrary local **file paths** and `clear_database` as plain form fields, so any web page you visit while the server runs can make it scan any file or wipe your review work with a simple cross-site form POST. Through DNS rebinding a page could also read `/api/report` and `/api/export/csv`, which return decrypted usernames/emails, history-derived domains and email subjects. Any local process can do the same | `scanner/web/server.py:24` (no middleware), `:298-344`, `:358-393`, `:396-426`, `:645-657`; `scanner/cli.py:209-224` |
| low | "Encrypted at rest" covers only usernames/emails. Full history URLs (which can contain reset links or session tokens), page titles and email subjects (first 200 chars) are stored in plaintext in `inventory.db`. The key sits on the same disk as the database | `scanner/core/models.py:67-70,206`, `scanner/connectors/history.py:107-116`, `scanner/connectors/email.py:98`, `scanner/core/dedupe.py:249-258`, `scanner/core/encryption.py:25,50-51` |
| low | Browser history is opened in place with `sqlite3.connect(path)` (read-write mode, no copy), so pointing it at a live Chrome/Firefox profile can lock or touch that DB while the browser is running | `scanner/connectors/history.py:51,318` |
| low | Dependencies are unpinned (`>=` ranges) and there's no lockfile, so every install pulls the latest versions and osv-scanner had nothing to check | `pyproject.toml:24-39` |
| info | Semgrep triage, all benign: `avoid-sqlalchemy-text` is fixed migration DDL (`models.py:265,277-287`). The HTML report uses `select_autoescape` (`report/html.py:164-166`). The web Jinja env has no autoescape but renders templates with no variables (`server.py:28,57-58`). Report JS uses `innerHTML` only with numeric ids, and labels go through `textContent` (`report.html.j2:691-803,1101`). `use-defusedcsv`: CSV exports of your own data could carry a spreadsheet formula if a source string starts with `=` (`report/csv.py:38`) | review |
| info | The "telemetry" hits are a list of tracking domains it *filters out* of results, not telemetry (`scanner/core/service_map.py:113-120`). The public-suffix list is local only: `TLDExtract(suffix_list_urls=())` (`scanner/core/normalize.py:22`) | review |
| info | Not problems: no subprocess/eval/exec/pickle/base64 code, no network libraries, no VM checks, sleeps or date triggers, no hidden Unicode or text aimed at AI agents. `start-server.sh` only starts the web UI on 127.0.0.1. Mbox parsing does not extract links from mail bodies. The password column is never read | grep over `src/` + review |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install** (`uv venv` + `uv pip install -e .`): only `pypi.org` and `files.pythonhosted.org`. No setup scripts beyond setuptools, no decoy reads, no firewall drops, no leftover processes.
- **Run:** `scanner --help` worked; `--version` doesn't exist. No DNS lookups, proxy requests, firewall drops, decoy reads, persistence or leftover processes. The only files created outside the project were our own planted `~/.claude*` configs, which the tool didn't change.
- **The auto-generated scenario only called `--help`/`--version`. It did not run** `db init`, any `scan` (bookmarks, passwords, history, mbox, Google/Apple HTML/PDF), `--auto-history`, `report` (HTML/CSV/XLSX), `connections` or the `web` server/API. Those paths are covered by the code review above, not by runtime evidence.

## How to use it safely
1. Pin commit `514b6c3` and install into a venv (`python3 -m venv .venv && .venv/bin/pip install -e .`). For repeatable installs, freeze the resolved versions (`.venv/bin/pip freeze > constraints.txt`).
2. Prefer the CLI with file paths (`scanner scan --passwords …`). It reads files in place and doesn't copy them.
3. Before scanning a password-manager export, cut it down to `url,username,email`. Never give it a CSV that still has passwords, and delete the original export afterwards.
4. If you use the web UI, keep the default `127.0.0.1` (never `--host 0.0.0.0`), don't browse other sites while it runs, stop it as soon as you're done, then `rm -rf uploads/`.
5. Quit the browser, or copy its `History` / `places.sqlite` file to a temp folder and scan the copy, instead of pointing at the live profile.
6. Treat `<repo>/.asset-scanner/` and `~/.asset-scanner/key` as sensitive (they hold your account list and browsing-derived data). Delete both when you're done. Use `--redacted` for reports you share.

## Not covered
- At runtime, nothing beyond `--help` was exercised (auto scenario), so scanning, reporting and the web UI rely on code review alone.
- macOS-specific paths (Chrome/Firefox/Safari history on macOS, permission prompts such as Full Disk Access for Safari) were checked only in code; the VM is Linux.
- Third-party parsers that see your untrusted files (`pypdf`, `beautifulsoup4`, `openpyxl`, `mailbox`) were not audited, and the versions resolved at install time were not recorded.
- I read the web server, CLI, encryption, models, history/password connectors and report template closely. The rest (bookmarks, email, connected-apps, dedupe/scoring/features/pipeline) was checked by searching for dangerous primitives and data sinks, not line by line.
- Evasion is always possible: a clean run is evidence, not proof. No files were hidden by deny rules (`unreadable-by-reviewer.txt` is empty).

# kytmanov/obsidian-llm-wiki-local — USE WITH PRECAUTIONS
Commit `ad2e425f20f348154dde19d7c895b9bba69b7ad5` · audited 2026-11-08 · Python CLI (`olw`) that turns Obsidian notes into a wiki with a local LLM (Ollama by default)

**Bottom line:** Honest code that does what it says. There is no telemetry, no update checks, no credential access and no git push. By default it only talks to Ollama on your own machine. The precautions are about handling: a cloud API key entered in `olw setup` is saved readable by other users on the Mac, and a vault you didn't create can redirect your notes and API key to any URL. Use it with Ollama, on vaults you made yourself. The project is in maintenance mode; its successor is Synto.

## What it can touch
- **Files:** inside the vault it reads `raw/` and writes `wiki/`, `.olw/`, `wiki.toml` and `.git`. Outside it writes only `~/.config/olw/config.toml`.
- **Network:** `localhost:11434` (Ollama). Cloud LLM providers or a custom URL only if you configure one, and then note text is sent there.
- **Processes:** `git commit` in the vault, and your `$EDITOR` when editing a draft.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| medium | A cloud API key from `olw setup` is stored in plain text with default permissions (readable by other users) | `global_config.py:79` (`write_text`, no chmod anywhere) |
| medium | A vault's own `wiki.toml` can set any provider URL: your API key (Bearer header) and note contents go there. Only a risk for vaults you didn't create | `config.py:241-260`, `client_factory.py:33-75`, `openai_compat_client.py:122-128` |
| low | `olw query` joins LLM-chosen page titles to the wiki path unsanitized, so it can read `.md` files outside the vault into the prompt. Writes are sanitized | `pipeline/query.py:127-140` |
| low | `git commit` runs in the vault, so a cloned vault's own `.git/hooks` would execute | `git_ops.py:34-94` |
| info | `install.py` runs `uv tool install .` and ignores `uv.lock`; dependencies float (`>=`) | `install.py:138-147` |
| info | Benign: semgrep SQL hits (fixed table names, `?` placeholders), subprocess hits (fixed argv, no shell), a zero-width joiner inside an emoji in a test note, CLAUDE.md is ordinary developer notes | review |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install:** only `pypi.org` and `files.pythonhosted.org`. It created two launchers in `~/.local/bin`.
- **Run** (`init`, `doctor`, `ingest`, `status`, `lint`, `query`, `support`): the only connection was to `127.0.0.1:11434` (Ollama). No DNS lookups or proxy requests, no decoy reads, no persistence, nothing left running.

## How to use it safely
1. Use Ollama (the default). If you use a cloud provider, pass the key through an environment variable, or run `chmod 600 ~/.config/olw/config.toml` after setup.
2. Run it only on vaults you created. For anyone else's vault, check `wiki.toml` `[provider]` and `.git/hooks` first.
3. Leave `auto_approve` off and review drafts before publishing.
4. Install from this audited commit with pinned dependencies: `uv tool install . --constraints <(uv export --frozen --no-hashes)`, or `uv sync --frozen`, rather than `install.py` or PyPI.
5. Don't drop hostile web clippings into `raw/` while using a cloud provider.

## Not covered
- The LLM pipeline at runtime: there was no model in the VM, so ingest, compile and query were reviewed in code only.
- Cloud provider paths, the interactive `olw setup`, and `olw watch` at runtime.
- Whether the PyPI release matches this commit.
- macOS-specific file watching (FSEvents).

# microsoft/markitdown — USE WITH PRECAUTIONS
Commit `21d9c1d01ecc12538dab19811fd247ef2f96ef60` (markitdown 0.1.9, markitdown-mcp 0.0.1a8) · audited 2026-11-09 · Python library and CLI that converts files and URLs (PDF, Office, HTML, audio, images, ZIP …) to Markdown for LLMs, plus an MCP server with one tool, `convert_to_markdown(uri)`.

**Bottom line:** No malware, telemetry, obfuscation or hidden instructions were found. The CLI on your own files is low-risk. The MCP server is the risky part: it lets an agent read **any file you can read** and fetch **any URL** (localhost and LAN included). A prompt-injected web page could therefore steer the agent into leaking local files. Also, with the `[all]` extras (which the MCP server pulls in), converting an audio file **uploads it to Google's speech API** without asking. **The VM run did not exercise markitdown at all** (the auto scenario only wrote placeholder config files). This verdict rests on code review only.

## What it can touch
- **Files:** reads the path or `file:` URI you give it, with no restriction. Writes only the `-o` output file. It does not touch agent config, shell startup files, Keychain or browser data.
- **Network (on demand):** whatever `http(s):` URL you or the agent pass in (follows redirects, no host filter). YouTube URLs also fetch transcripts from YouTube.
- **Network (automatic, if extras installed):** `.wav/.mp3/.m4a/.mp4` audio goes to Google Web Speech (`recognize_google`).
- **Network (opt-in):** Azure Document Intelligence / Content Understanding (`-d` / `--use-cu`). Image captions and OCR go to the LLM client you pass in code.
- **Credentials:** none by default. Azure modes read `AZURE_API_KEY` or use the Azure default credential chain (az CLI login, managed identity …).
- **Processes:** runs `exiftool` (list arguments, no shell) if found in a system bin directory or set via `EXIFTOOL_PATH`. Runs ffmpeg via pydub for mp3/mp4.
- **MCP server:** STDIO by default. `--http` listens on `127.0.0.1:3001` with no authentication.
- **Persistence / auto-run:** none. No install hooks, Claude hooks or auto-update.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Medium | **The MCP tool is an unrestricted file reader and URL fetcher.** `convert_to_markdown` accepts any `file:` path (e.g. `~/.ssh/id_ed25519`, `.env`) and any `http(s):` host, including `127.0.0.1`, LAN addresses and cloud metadata IPs. Converted web pages go straight into the agent's context. So a malicious page can instruct the agent to read a local file, then "convert" a URL with the contents in its query string. This is documented, but there is no allowlist, root directory or host filter to turn on. Matches stated purpose: yes. | `packages/markitdown-mcp/src/markitdown_mcp/__main__.py:19-24`, `packages/markitdown/src/markitdown/_markitdown.py:482-523`, `packages/markitdown-mcp/README.md:134` |
| Medium | **Audio is sent to Google without a prompt.** If `speech_recognition` + `pydub` are installed (the `[all]` extra, which `markitdown-mcp` depends on), every audio/MP4 conversion calls `recognize_google`. That uploads the audio to Google's Web Speech API. There is no flag to turn it off. The README only says "speech transcription", without mentioning a cloud service. Matches stated purpose: partly (the recipient is not disclosed). | `converters/_transcribe_audio.py:56-59`, `converters/_audio_converter.py:94-103`, `packages/markitdown-mcp/pyproject.toml:28`, `README.md:18,110` |
| Medium | **Dependencies are unpinned and there is no lockfile.** `pip install markitdown[all]` resolves ~20 packages at their latest versions (bs4, requests, markdownify, pandas, pdfminer, mammoth, azure-*, youtube-transcript-api, …). Most have no upper bound. osv-scanner had no lockfile to check. PyPI wheels were not compared with this source. | `packages/markitdown/pyproject.toml:27-54`, `static-summary.txt` (OSV: no output) |
| Low | **MCP HTTP mode has no authentication and runs Starlette with `debug=True`**, so error responses include tracebacks. Binding to a non-localhost `--host` only prints a warning. Any local process can call it. DNS-rebinding protection depends on the MCP SDK's handling of the `host` argument and was not verified. | `packages/markitdown-mcp/src/markitdown_mcp/__main__.py:58-66,114-133` |
| Low | **No size or depth limits on untrusted input.** The ZIP converter reads every member fully into memory and recurses into nested archives. HTTP responses are buffered whole. A zip bomb or huge download can exhaust memory (denial of service only, no extraction to disk, no path traversal). | `converters/_zip_converter.py:108-121`, `_markitdown.py:590-591` |
| Low | **Plugins run code from any installed package** with a `markitdown.plugin` entry point. They are off by default (`-p` / `MARKITDOWN_ENABLE_PLUGINS=true`). The MCP Docker image turns them on, but only first-party code is installed in it. | `_markitdown.py:113-130,302-320`, `packages/markitdown-mcp/Dockerfile:6` |
| Info | **Scanner false positives / benign:** <br>• semgrep `use-defused-xml` ×3: `pre_process.py:5,45` parses a fragment BeautifulSoup already re-serialized. lxml at `:228` uses `resolve_entities=False, no_network=True`. RSS, EPUB and XLSX use `defusedxml`. <br>• semgrep subprocess ×2: exiftool with a fixed argument list, no shell. It refuses versions <12.24 (CVE-2021-22204) at `_exiftool.py:21-47`. The binary path comes only from an argument, the env var or trusted system directories (`_markitdown.py:202-224`). <br>• Hidden Unicode: ZWSP/ZWJ inside saved real-world web pages used as test fixtures. <br>• devcontainer: no `initializeCommand`/`postCreateCommand`, only a hatch feature (root *inside* the container). <br>• pre-commit: the `black` formatter, for contributors only. <br>• CI: `pull_request` only, actions pinned by SHA. <br>• base64 is used only for data URIs and Bing redirect links. gitleaks: 0. <br>No prompt-injection text, obfuscation, telemetry or auto-update found. | see file:line |

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install:** the auto scenario only wrote a sample `~/.claude/settings.json` and `~/.claude.json`. markitdown was **not** installed (no `pip install`, no Docker).
- **Run:** only `cat` on those two files. No markitdown or markitdown-mcp process ran.
- **Results:** 0 decoy reads, 0 DNS lookups, 0 connections, no persistence, no leftover processes. These results say **nothing about markitdown**, because none of its code ran.

## How to use it safely
1. Pin it: `pip install 'markitdown[pdf,docx,xlsx,pptx]==0.1.9'` in a venv (or from this commit). Install only the extras you need. **Leave out `audio-transcription` and `[all]`** unless sending audio to Google is acceptable.
2. For scripts, prefer the CLI or `convert_local()` / `convert_stream()` on files you chose. Don't pass untrusted strings to `convert()`.
3. **MCP server:** run it in the documented Docker image (`docker run --rm -i -v <one folder>:/workdir markitdown-mcp`), mounting only the folder it needs. Don't run `markitdown-mcp` directly on the Mac, where it can read your whole home folder. Note that `markitdown-mcp` pulls in `[all]`, including Google speech. In Claude Code, keep the tool on "ask" so you see every URI it requests.
4. Use STDIO, not `--http`. If you need HTTP, keep the default `127.0.0.1` and stop it when you're done.
5. Leave plugins off (the default). Turn them on only for plugins you have audited.
6. Treat converted web pages and documents as untrusted text: they flow into the agent's context.
7. Re-audit before updating: dependencies float, so a later install can differ even at the same version.

## Not covered
- **No runtime coverage at all.** The auto scenario did not exercise any of these: the `pip install` (which PyPI packages actually resolve, and their install-time behaviour), the CLI on sample files, the audio path's Google call, the YouTube fetch, `markitdown-mcp` over STDIO or HTTP (`mcp_probe.py`), plugins, or the Docker image. A useful re-run would be: install.sh `uv venv && uv pip install './packages/markitdown[all]' ./packages/markitdown-mcp`; run.sh `markitdown --help`, conversions of small HTML/DOCX/CSV/ZIP/WAV samples, `mcp_probe.py --call -- markitdown-mcp`, and `markitdown-mcp --http` for ~45 s.
- **Third-party parsers** (pdfminer, pdfplumber, mammoth, openpyxl, xlrd, python-pptx, olefile, magika's ONNX model, ffmpeg) were not reviewed. Their parsing of hostile files is the main remaining attack surface. The `markitdown-ocr` plugin was reviewed only for network and credential use.
- **Static gaps:** 5 large files were skipped by our checks. 43 binary files (test fixtures) can't be read as source. osv-scanner found no lockfile, so dependency CVEs were not checked. PyPI and Docker artifacts were not compared with this source.
- **Linux VM ≠ macOS**, and evasion by malware remains possible in general.
- **Unread files:** none hidden by deny rules (`static/unreadable-by-reviewer.txt` is empty). No symlinks were stripped.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

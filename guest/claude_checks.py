#!/usr/bin/env python3
"""Static checks the vetted scanners don't cover. Stdlib only; never executes target code.

Usage: python3 -I claude_checks.py <src_dir> <out.json>
Covers: Claude Code artifacts (hooks/settings/.mcp.json/plugin/marketplace/commands/agents),
code that runs on install or on folder open, remote-exec / credential / persistence / macOS
malware patterns, anti-analysis, exfil channels, telemetry, obfuscation, hidden Unicode,
binaries and symlinks, and an inventory of every outbound host.
"""
import json, os, re, stat, sys
from collections import Counter, defaultdict

SRC, OUT = sys.argv[1], sys.argv[2]
MAX_FILE = 2_000_000
findings, hosts = [], defaultdict(list)
artifacts = defaultdict(list)
install_hooks, mcp_servers = [], []
stats = Counter()

TEXT_EXT = {'.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.go', '.rs', '.c', '.h', '.cc', '.cpp',
            '.hpp', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.rb', '.php', '.java', '.kt', '.swift', '.m',
            '.json', '.jsonc', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.md', '.mdx', '.txt', '.html', '.vue',
            '.svelte', '.lua', '.pl', '.cmake', '.mk', '.dockerfile', '.env', '.plist', '.xml', '.sql', '.zig'}
CODE_EXT = TEXT_EXT - {'.md', '.mdx', '.txt', '.html', '.xml', '.sql'}
BIN_EXT = {'.so', '.dylib', '.dll', '.exe', '.node', '.jar', '.pyc', '.wasm', '.bin', '.o', '.a', '.class'}
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__'}
DOC_PARTS = ('test', 'tests', '__tests__', 'spec', 'docs', 'doc', 'examples', 'example', 'fixtures',
             'testdata', 'test-data', 'benchmark', 'benchmarks', 'samples')


def rel(p):
    return os.path.relpath(p, SRC)


def context(path):
    parts = [x.lower() for x in path.split('/')]
    if any(x in DOC_PARTS for x in parts[:-1]) or parts[-1].endswith(('.md', '.mdx', '.txt')):
        return 'docs/tests'
    if any(x in ('vendor', 'third_party', 'thirdparty', 'external', 'deps', 'grammars') for x in parts):
        return 'vendored'
    return 'code'


def add(sev, cat, path, line, snippet, detail):
    findings.append({'severity': sev, 'category': cat, 'file': path, 'line': line,
                     'context': context(path), 'snippet': (snippet or '').strip()[:240], 'detail': detail})


# ---------------- line rules: (severity, category, regex, detail, file-filter)
R = lambda s: re.compile(s, re.I)
LINE_RULES = [
    # remote code execution / download-and-run
    ('high', 'remote-exec', R(r'(curl|wget)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b'), 'pipes a download into a shell', None),
    ('high', 'remote-exec', R(r'(curl|wget)\b[^|\n]{0,200}\|\s*(python3?|node|perl|ruby)\b'), 'pipes a download into an interpreter', None),
    ('high', 'remote-exec', R(r'\b(iex|invoke-expression)\b.{0,80}(iwr|irm|invoke-webrequest|downloadstring)'), 'PowerShell download-and-run', None),
    ('critical', 'obfuscated-exec', R(r'\b(exec|eval)\s*\(\s*(base64|b64decode|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|__import__)'), 'executes decoded data', 'code'),
    ('critical', 'obfuscated-exec', R(r'\beval\s*\(\s*(atob|Buffer\.from)\s*\('), 'evaluates decoded data (JS)', 'code'),
    ('high', 'obfuscated-exec', R(r'new\s+Function\s*\(\s*(atob|Buffer\.from|[a-z_$]+\s*\))'), 'builds a function from data (JS)', 'code'),
    ('medium', 'dynamic-exec', R(r'\b(vm\.runIn(New|This)?Context|vm\.Script)\s*\('), 'runs code through node:vm', 'code'),
    ('medium', 'dynamic-exec', R(r'(^|[^.\w])exec\s*\(\s*(compile|open|requests|urllib|r\.text|resp)'), 'exec() of loaded/fetched code', 'code'),
    ('medium', 'shell-exec', R(r'exec\.Command\(\s*"(sh|bash|zsh|cmd)"\s*,\s*"(-c|/c)"'), 'runs a shell command (Go)', 'code'),
    ('low', 'shell-exec', R(r'subprocess\.\w+\([^)]*shell\s*=\s*True'), 'subprocess with shell=True', 'code'),
    ('low', 'shell-exec', R(r'child_process|\bexecSync\s*\(|\bspawnSync\s*\('), 'spawns processes (Node)', 'code'),
    # credential & secret access
    ('high', 'credential-access', R(r'(~|\$HOME|homedir\(\)|expanduser\(["\']~|os\.homedir|Path\.home\(\)|HOME\b)[^\n]{0,60}(\.ssh|id_rsa|id_ed25519|\.aws|\.netrc|\.npmrc|\.git-credentials|\.docker/config|\.kube/config|\.gnupg|\.pypirc)'), 'reads credential files under the home folder', None),
    ('high', 'credential-access', R(r'["\'/](\.ssh/(id_|authorized_keys|known_hosts)|\.aws/credentials|\.git-credentials|\.netrc|\.claude/\.credentials|\.config/gh/hosts\.yml)'), 'references a credential file path', None),
    ('critical', 'credential-access', R(r'security\s+(find-generic-password|find-internet-password|dump-keychain|export)'), 'reads the macOS Keychain', None),
    ('critical', 'credential-access', R(r'login\.keychain|Keychains/|keychain-db'), 'touches Keychain files', None),
    ('critical', 'credential-access', R(r'Login Data|Web Data|Cookies\.binarycookies|logins\.json|key4\.db|Local State.{0,40}encrypted_key|os_crypt'), 'browser saved-password/cookie stores', 'code'),
    ('critical', 'credential-access', R(r'nkbihfbeogaeaoehlefnkodbefgpgknn|exodus\.wallet|Electrum/wallets|\.electrum/wallets|wallet\.dat|Ledger Live|atomic/Local Storage|Phantom/(Local|wallet)|bfnaelmomeimhlpmgjnjophhpkkoljpa'), 'crypto-wallet paths (stealer pattern)', 'code'),
    ('high', 'credential-access', R(r'JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)[^\n]{0,80}(post|send|request)|/proc/self/environ|printenv\s*\|'), 'collects the whole environment', 'code'),
    # macOS-specific malware behaviour
    ('high', 'macos', R(r'osascript\b[^\n]{0,120}(password|display dialog|hidden answer)'), 'fake password prompt via AppleScript (stealer pattern)', None),
    ('medium', 'macos', R(r'\bosascript\b'), 'runs AppleScript', 'code'),
    ('high', 'macos', R(r'xattr\s+(-r\s+)?-d\s+com\.apple\.quarantine|spctl\s+--master-disable|csrutil\s+disable'), 'disables Gatekeeper/quarantine/SIP', None),
    ('high', 'persistence', R(r'Library/LaunchAgents|Library/LaunchDaemons|launchctl\s+(load|bootstrap|submit)|LoginItems|SMAppService'), 'macOS persistence (launch agents/login items)', 'code'),
    ('high', 'macos', R(r'TCC\.db|tccutil'), 'touches macOS privacy database', None),
    # persistence (generic)
    ('high', 'persistence', R(r"""(>>|>|writeFile|appendFile|open\()[^\n]{0,80}([~/'"`]\.(bashrc|zshrc|bash_profile|profile|zprofile)\b|\.config/autostart|\.config/systemd/user)"""), 'writes shell startup / autostart files', 'code'),
    ('medium', 'persistence', R(r'\bcrontab\s+(-l|-e|-)|/etc/cron|systemctl\s+(--user\s+)?enable'), 'installs scheduled/background jobs', 'code'),
    # anti-analysis / evasion
    ('high', 'anti-analysis', R(r'system_profiler\s+SPHardwareDataType|hw\.model|ioreg\s+-l|VirtualMac|IOPlatformSerialNumber'), 'inspects hardware model / serial (VM check?)', 'code'),
    ('high', 'anti-analysis', R(r'\b(vmware|virtualbox|vbox|qemu|parallels|sandboxie|hyper-?v|kvm)\b[^\n]{0,60}(detect|check|is_?vm|if|includes|in\s)'), 'checks for virtual machines', 'code'),
    ('high', 'anti-analysis', R(r'IsDebuggerPresent|PTRACE_TRACEME|ptrace\s*\(\s*PT_DENY_ATTACH|P_TRACED|TracerPid'), 'anti-debugging', 'code'),
    ('medium', 'anti-analysis', R(r'(time\.sleep|sleep)\s*\(\s*\d{4,}|setTimeout\([^,]{1,200},\s*\d{8,}\s*\)'), 'very long delay before acting', 'code'),
    # exfil channels & suspicious endpoints
    ('high', 'exfil', R(r'discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|requestbin|pipedream\.net|interact\.sh|\boast\.(fun|me|pro)\b|burpcollaborator|ngrok(-free)?\.(io|app)|transfer\.sh|pastebin\.com/raw|termbin\.com|0x0\.st'), 'known exfiltration / callback service', None),
    ('medium', 'exfil', R(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/'), 'hard-coded IP address URL', 'code'),
    ('medium', 'exfil', R(r'\b(nslookup|dig|host)\s+[^\n]{0,40}\$'), 'DNS lookup built from a variable (possible DNS exfil)', 'code'),
    # telemetry
    ('info', 'telemetry', R(r'posthog|mixpanel|segment\.(io|com)|analytics\.js|amplitude|google-analytics|googletagmanager|gtag\(|sentry_sdk|@sentry/|datadoghq|statsig|logrocket|hotjar|plausible\.io'), 'telemetry/analytics', None),
    # Claude Code / agent manipulation inside code & config
    ('high', 'claude-config', R(r'ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|CLAUDE_CODE_SHELL_PREFIX|apiKeyHelper'), 'touches Claude API routing / key helper', None),
    ('high', 'claude-config', R(r'--dangerously-skip-permissions|bypassPermissions|skipDangerousModePermissionPrompt|enableAllProjectMcpServers'), 'turns off Claude Code safety prompts', None),
    ('medium', 'claude-config', R(r'\.claude/settings(\.local)?\.json|\.claude\.json|CLAUDE\.md|\.claude/(skills|commands|agents|hooks)'), 'writes or reads Claude Code config', 'code'),
]

AI_TEXT_RULES = [
    ('high', 'prompt-injection', R(r'ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts)'), 'instruction override'),
    ('high', 'prompt-injection', R(r"(do not|don't|never) (tell|inform|mention|show|reveal|alert)[^\n]{0,30}(the )?user"), 'asks the AI to hide something from the user'),
    ('high', 'prompt-injection', R(r'without (asking|prompting|confirmation|telling)'), 'asks the AI to act without confirmation'),
    ('high', 'prompt-injection', R(r'(this|the) (skill|plugin|repo|repository|code|tool|package) (is|has been) (safe|verified|audited|trusted|approved)'), 'self-declared safety (aimed at reviewers)'),
    ('high', 'prompt-injection', R(r'(security )?(reviewer|auditor|scanner|ai model|language model|assistant)s?[,:]? (should|must|please)'), 'text addressed to an AI reviewer'),
    ('medium', 'prompt-injection', R(r'you are now|new instructions|system prompt|<\s*/?\s*(system|instructions?)\s*>'), 'role/system-prompt manipulation'),
]
HIDDEN_UNI = re.compile('[\U000E0000-\U000E007F\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\u180E]')
URL_RE = re.compile(r'(?:https?|wss?)://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?')
B64_RE = re.compile(r'[A-Za-z0-9+/]{400,}={0,2}')
BORING_HOSTS = re.compile(r'(^|\.)(example\.(com|org|net)|localhost|w3\.org|schema\.org|json-schema\.org|opensource\.org|apache\.org|mozilla\.org|shields\.io|img\.shields\.io)$')


def check_line_rules(path, text, is_code):
    ctx = context(path)
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for sev, cat, rx, detail, filt in LINE_RULES:
            if filt == 'code' and not is_code:
                continue
            if rx.search(line):
                add(sev, cat, path, ln, line, detail)
        for m in URL_RE.finditer(line):
            h = m.group(1).lower()
            if not BORING_HOSTS.search(h) and len(hosts[h]) < 5:
                hosts[h].append(f'{path}:{ln}' + (' (docs/tests)' if ctx != 'code' else ''))


def check_ai_text(path, text):
    for ln, line in enumerate(text.splitlines(), 1):
        for sev, cat, rx, detail in AI_TEXT_RULES:
            if rx.search(line):
                add(sev, cat, path, ln, line, detail)


def frontmatter(text):
    m = re.match(r'^---\s*\n(.*?)\n---', text, re.S)
    return m.group(1) if m else ''


PIN_RE = re.compile(r'@\d+\.\d+|==\d|@sha256:|:\d+\.\d+')


def check_mcp_servers(path, servers, where):
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = cfg.get('command', '')
        args = [str(a) for a in cfg.get('args', [])] if isinstance(cfg.get('args'), list) else []
        url = cfg.get('url', '')
        entry = {'file': path, 'name': name, 'type': cfg.get('type', 'stdio' if cmd else 'http'),
                 'command': ' '.join([cmd] + args)[:300], 'url': url, 'env_keys': sorted((cfg.get('env') or {}).keys())}
        mcp_servers.append(entry)
        full = ' '.join([cmd] + args)
        if re.search(r'\b(npx|bunx|pnpx|uvx|pipx|dlx)\b', full) and not PIN_RE.search(full):
            add('high', 'mcp', path, None, full, f'MCP server "{name}" downloads an unpinned package on every start')
        if '@latest' in full:
            add('high', 'mcp', path, None, full, f'MCP server "{name}" uses @latest')
        if re.search(r'\bdocker\b', full) and '@sha256:' not in full:
            add('medium', 'mcp', path, None, full, f'MCP server "{name}" runs a Docker image not pinned by digest')
        if url:
            add('medium', 'mcp', path, None, url, f'MCP server "{name}" is remote ({url}); data leaves your machine')
        if re.search(r'(curl|wget)[^|]*\|\s*(ba)?sh', full):
            add('critical', 'mcp', path, None, full, f'MCP server "{name}" pipes a download into a shell')


def check_settings(path, data):
    hooks = data.get('hooks') or {}
    if isinstance(hooks, dict):
        for ev, groups in hooks.items():
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get('hooks') or []) if isinstance(g, dict) else []:
                    if isinstance(h, dict) and h.get('command'):
                        add('high', 'claude-hook', path, None, h['command'],
                            f'hook runs automatically on {ev} (matcher {g.get("matcher", "*")})')
    env = data.get('env') or {}
    for k, v in env.items() if isinstance(env, dict) else []:
        sev = 'critical' if re.search(r'ANTHROPIC_(BASE|API)_URL|PROXY|NODE_OPTIONS|LD_PRELOAD|DYLD_|SHELL_PREFIX', k) else 'medium'
        add(sev, 'claude-config', path, None, f'{k}={v}', 'settings sets an environment variable for Claude Code')
    for key in ('apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper'):
        if data.get(key):
            add('critical', 'claude-config', path, None, str(data[key]), f'{key} runs a command that handles credentials')
    sl = data.get('statusLine')
    if isinstance(sl, dict) and sl.get('command'):
        add('medium', 'claude-config', path, None, sl['command'], 'statusLine command runs constantly')
    perms = data.get('permissions') or {}
    for a in perms.get('allow', []) if isinstance(perms, dict) else []:
        if re.fullmatch(r'(Bash|Bash\(\*\)|Bash\(.*:\*\)|\*|WebFetch|Write|Edit|Read\(~?/\*\*\)|mcp__.*)', str(a)):
            add('high', 'claude-permissions', path, None, str(a), 'broad auto-allow permission')
    if isinstance(perms, dict) and perms.get('defaultMode') in ('bypassPermissions', 'acceptEdits'):
        add('high', 'claude-permissions', path, None, perms['defaultMode'], 'changes default permission mode')
    for k in ('enableAllProjectMcpServers', 'skipDangerousModePermissionPrompt'):
        if data.get(k):
            add('high', 'claude-permissions', path, None, k, 'turns off a safety prompt')
    if 'mcpServers' in data:
        check_mcp_servers(path, data['mcpServers'], 'settings')


def load_json(p):
    try:
        with open(p, encoding='utf-8', errors='replace') as f:
            t = f.read()
        t = re.sub(r'^\s*//.*$', '', t, flags=re.M)  # tolerate jsonc comments
        return json.loads(t)
    except Exception:
        return None


def check_special(path, full, name, text):
    low = name.lower()
    d = os.path.dirname(path)
    # ---- Claude artifacts
    if name == 'SKILL.md':
        artifacts['skills'].append(path)
        fm = frontmatter(text)
        if re.search(r'allowed-tools:.*\bBash\b(?!\()', fm) or 'Bash(*)' in fm:
            add('medium', 'claude-permissions', path, None, fm[:200], 'skill pre-approves unrestricted Bash')
    if name in ('CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules') or name == 'SKILL.md' or \
       re.search(r'(^|/)(commands|agents|skills|prompts)/[^/]+\.md$', path):
        artifacts['agent_instructions'].append(path)
        check_ai_text(path, text)
        fm = frontmatter(text)
        if fm and re.search(r'(^|/)(commands|agents)/', path):
            m = re.search(r'allowed-tools:\s*(.*)', fm) or re.search(r'tools:\s*(.*)', fm)
            if m and re.search(r'\bBash\b(?!\()|Bash\(\*\)', m.group(1)):
                add('medium', 'claude-permissions', path, None, m.group(0), 'command/agent gets unrestricted Bash')
    if path.endswith('.claude-plugin/plugin.json') or name == 'plugin.json' and '.claude-plugin' in path:
        artifacts['plugins'].append(path)
        data = load_json(full) or {}
        if isinstance(data.get('hooks'), (dict, str)):
            add('high', 'claude-hook', path, None, json.dumps(data['hooks'])[:200], 'plugin declares hooks')
        if isinstance(data.get('mcpServers'), dict):
            check_mcp_servers(path, data['mcpServers'], 'plugin')
        elif isinstance(data.get('mcpServers'), str):
            add('info', 'mcp', path, None, data['mcpServers'], 'plugin points to an MCP config file')
    if name == 'marketplace.json':
        artifacts['marketplaces'].append(path)
        data = load_json(full) or {}
        for p in data.get('plugins', []) if isinstance(data, dict) else []:
            src = p.get('source') if isinstance(p, dict) else None
            if isinstance(src, dict) and src.get('source') in ('github', 'git', 'url') and not (src.get('sha') or src.get('ref')):
                add('medium', 'claude-marketplace', path, None, json.dumps(src)[:200],
                    f'plugin "{p.get("name")}" is not pinned to a commit: updates arrive unreviewed')
    if name == 'hooks.json':
        artifacts['hooks'].append(path)
        data = load_json(full) or {}
        check_settings(path, data if 'hooks' in data else {'hooks': data})
    if re.search(r'(^|/)\.claude/settings(\.local)?\.json$', path) or name in ('managed-settings.json',):
        artifacts['settings'].append(path)
        check_settings(path, load_json(full) or {})
    if name in ('.mcp.json', 'mcp.json', 'claude_desktop_config.json') or (low.endswith('.json') and 'mcpServers' in text[:20000]):
        data = load_json(full)
        if isinstance(data, dict) and isinstance(data.get('mcpServers'), dict):
            artifacts['mcp_configs'].append(path)
            check_mcp_servers(path, data['mcpServers'], 'mcp')
    # ---- code that runs on install / build / folder open
    if name == 'package.json':
        data = load_json(full) or {}
        for k, v in (data.get('scripts') or {}).items() if isinstance(data, dict) else []:
            if k in ('preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'preprepare', 'postprepare', 'dependencies'):
                install_hooks.append({'file': path, 'kind': f'npm {k}', 'command': str(v)[:300]})
                sev = 'high' if re.search(r'curl|wget|https?://|node\s+-e|eval|base64|\|\s*sh', str(v)) else 'medium'
                add(sev, 'install-hook', path, None, f'{k}: {v}', 'runs automatically on npm install')
        if isinstance(data, dict) and data.get('bin'):
            artifacts['entrypoints'].append(f'{path}: bin {json.dumps(data["bin"])[:150]}')
    if name == 'setup.py':
        install_hooks.append({'file': path, 'kind': 'setup.py', 'command': 'runs as Python code on pip install'})
        add('medium', 'install-hook', path, None, '', 'setup.py runs as code during pip install')
        if re.search(r'cmdclass|urlopen|requests\.|subprocess|os\.system', text):
            add('high', 'install-hook', path, None, '', 'setup.py has custom install commands / network / subprocess')
    if name == 'pyproject.toml':
        if re.search(r'\[tool\.hatch\.build(\.targets\.\w+)?\.hooks|build-backend\s*=\s*"(?!setuptools\.build_meta|hatchling\.build|poetry\.core\.masonry\.api|flit_core\.buildapi|pdm\.backend|maturin|scikit_build_core\.build|mesonpy|uv_build)', text):
            add('medium', 'install-hook', path, None, '', 'custom build backend/hook runs code at install')
        m = re.search(r'\[project\.scripts\](.*?)(\n\[|\Z)', text, re.S)
        if m:
            artifacts['entrypoints'].append(f'{path}: scripts {" ".join(m.group(1).split())[:150]}')
    if name == 'build.rs':
        install_hooks.append({'file': path, 'kind': 'cargo build.rs', 'command': 'runs at cargo build'})
        add('medium', 'install-hook', path, None, '', 'build.rs runs at build time')
    if name in ('Makefile', 'GNUmakefile', 'CMakeLists.txt', 'meson.build', 'justfile', 'Taskfile.yml'):
        artifacts['build_files'].append(path)
        if re.search(r'(curl|wget)[^\n|]*\|\s*(ba)?sh|execute_process\([^)]*(curl|wget|git clone)', text):
            add('high', 'install-hook', path, None, '', 'build file downloads and runs code')
    if low == 'dockerfile' or low.endswith('.dockerfile'):
        artifacts['build_files'].append(path)
    if re.search(r'(^|/)\.github/workflows/[^/]+\.ya?ml$', path):
        artifacts['ci'].append(path)
        if 'pull_request_target' in text:
            add('low', 'ci', path, None, '', 'workflow uses pull_request_target (repo-maintainer risk, not yours)')
    if path.endswith('.vscode/tasks.json') and 'folderOpen' in text:
        add('high', 'auto-run', path, None, '', 'VS Code task runs automatically when the folder is opened')
    if '.devcontainer/' in path and re.search(r'(postCreate|postStart|postAttach|onCreate|initialize)Command', text):
        add('medium', 'auto-run', path, None, '', 'devcontainer runs commands on create/start (initializeCommand runs on YOUR host)')
    if name in ('.envrc',) or path.startswith('.husky/') or name in ('lefthook.yml', '.pre-commit-config.yaml'):
        add('medium', 'auto-run', path, None, '', 'runs automatically (direnv / git hooks) once enabled')
    if name == '.gitattributes' and re.search(r'filter=|diff=|merge=', text):
        add('low', 'auto-run', path, None, '', 'git filters/drivers declared (need local config to run)')
    if re.search(r'(^|/)(install|get|setup|bootstrap)\.(sh|ps1)$', low):
        artifacts['installers'].append(path)
    if re.search(r'^//go:generate', text, re.M):
        add('low', 'install-hook', path, None, '', 'go:generate directives (run only with go generate)')


def is_binary_head(b):
    return b[:4] in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xcf') or b[:2] == b'MZ' or b'\x00' in b[:1024]


for root, dirs, files in os.walk(SRC, followlinks=False):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
    for d in list(os.listdir(root)):
        p = os.path.join(root, d)
        if os.path.islink(p):
            tgt = os.readlink(p)
            resolved = os.path.realpath(p)
            esc = not resolved.startswith(os.path.realpath(SRC) + os.sep)
            add('high' if esc else 'info', 'symlink', rel(p), None, f'-> {tgt}',
                'symlink points OUTSIDE the repo' if esc else 'symlink inside repo')
    for name in files:
        full = os.path.join(root, name)
        path = rel(full)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        stats['files'] += 1
        stats['bytes'] += st.st_size
        ext = os.path.splitext(name)[1].lower()
        try:
            with open(full, 'rb') as f:
                head = f.read(4096)
        except OSError:
            continue
        if ext in BIN_EXT or is_binary_head(head):
            if ext not in ('.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.pdf', '.zip', '.gz', '.mp4', '.mp3', '.wav', '.svgz', '.icns', '.db', '.sqlite', '.parquet', '.webm', '.avif', '.lockb'):
                kind = 'executable binary' if head[:4] in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe') or head[:2] == b'MZ' else 'binary file'
                add('medium' if 'executable' in kind else 'low', 'binary', path, None, f'{st.st_size} bytes', f'{kind} committed to the repo (cannot be reviewed as source)')
            stats['binary'] += 1
            continue
        if st.st_mode & 0o111 and ext not in ('.sh', '.py', '') :
            stats['exec_bit_other'] += 1
        if st.st_size > MAX_FILE:
            stats['skipped_large'] += 1
            continue
        if ext not in TEXT_EXT and name not in ('Makefile', 'Dockerfile', 'Containerfile', 'justfile', '.envrc', 'build.rs') and not name.startswith('.'):
            stats['other'] += 1
            # still check shebang scripts
            if not head.startswith(b'#!'):
                continue
        try:
            text = open(full, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        stats['ext:' + (ext or name)] += 1
        is_code = ext in CODE_EXT or head.startswith(b'#!') or name in ('Makefile', 'Dockerfile')
        check_line_rules(path, text, is_code)
        check_special(path, full, name, text)
        for m in HIDDEN_UNI.finditer(text):
            ln = text.count('\n', 0, m.start()) + 1
            cp = f'U+{ord(m.group()):04X}'
            sev = 'critical' if 0xE0000 <= ord(m.group()) <= 0xE007F else ('high' if 0x202A <= ord(m.group()) <= 0x2069 else 'medium')
            add(sev, 'hidden-unicode', path, ln, cp, 'invisible/bidi character (can hide text from humans but not from AI)')
            break
        if is_code and ext in ('.js', '.mjs', '.cjs', '.ts', '.py', '.sh') and not re.search(r'\.min\.|dist/|build/|vendor', path):
            if B64_RE.search(text):
                add('medium', 'obfuscation', path, None, '', 'long base64 blob in source')
            if max((len(l) for l in text.splitlines()), default=0) > 2000:
                add('low', 'obfuscation', path, None, '', 'very long line (minified/generated code in source tree)')
            if len(re.findall(r'\\x[0-9a-f]{2}', text)) > 200 or len(re.findall(r'String\.fromCharCode', text)) > 20:
                add('high', 'obfuscation', path, None, '', 'heavy hex/char-code escaping (obfuscation)')

# de-duplicate noisy categories
seen, uniq = Counter(), []
for f in findings:
    key = (f['category'], f['detail'], f['file'])
    seen[key] += 1
    if seen[key] <= 3:
        uniq.append(f)
order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
uniq.sort(key=lambda f: (order[f['severity']], f['context'] != 'code', f['category'], f['file']))
by_sev = Counter((f['severity'], f['context']) for f in uniq)
out = {
    'stats': dict(stats.most_common(40)),
    'artifacts': {k: v[:200] for k, v in artifacts.items()},
    'install_hooks': install_hooks[:100],
    'mcp_servers': mcp_servers[:100],
    'hosts': dict(sorted(hosts.items())),
    'counts': {f'{s}/{c}': n for (s, c), n in sorted(by_sev.items())},
    'findings': uniq[:1500],
}
with open(OUT, 'w') as f:
    json.dump(out, f, indent=1)
print(json.dumps(out['counts']))

#!/usr/bin/env python3
"""Write a default runtime scenario (install.sh, run.sh, notes.txt) from the target's own manifests.
Reads files as DATA only; nothing from the target runs here. Runs INSIDE the VM (python3 -I).
The scripts run later as 'sandbox' in the repo root (see dynamic.sh). /audit can refine them.

python3 -I auto_scenario.py <src-dir> <out-dir>
"""
import glob, json, os, shlex, sys, tomllib

src, out = sys.argv[1], sys.argv[2]
q = shlex.quote
T = 'timeout 60'
inst = ['set -x',
        '# realistic agent config, so installers that edit it have something to touch (printed in run.sh)',
        'mkdir -p ~/.claude',
        """echo '{"permissions":{"allow":[]},"model":"opus"}' > ~/.claude/settings.json""",
        """echo '{"numStartups":3,"mcpServers":{}}' > ~/.claude.json"""]
run = ['set -x']
notes = []


def has(p):
    return os.path.exists(os.path.join(src, p))


def load_json(p):
    try:
        with open(os.path.join(src, p)) as f:
            return json.load(f)
    except Exception:
        return None


def rel(p):
    return os.path.relpath(p, src)


# ---------- Node ----------
pkg = load_json('package.json')
if isinstance(pkg, dict):
    if has('pnpm-lock.yaml'):
        inst.append('corepack enable --install-directory ~/.local/bin pnpm || true; pnpm install --frozen-lockfile || pnpm install || true')
    elif has('yarn.lock'):
        inst.append('corepack enable --install-directory ~/.local/bin yarn || true; yarn install || true')
    else:
        inst.append(('npm ci' if has('package-lock.json') else 'npm install') + ' --no-audit --no-fund || true')
    scripts = pkg.get('scripts') if isinstance(pkg.get('scripts'), dict) else {}
    if 'build' in scripts:
        inst.append('npm run build || true')
    bins = pkg.get('bin')
    if isinstance(bins, str):
        bins = {pkg.get('name', 'cli'): bins}
    for name, path in (bins or {}).items() if isinstance(bins, dict) else []:
        run += [f'{T} node {q(str(path))} --help || true', f'{T} node {q(str(path))} --version || true']
    if not bins and isinstance(pkg.get('main'), str):
        run.append(f'{T} node -e {q("require(" + json.dumps("./" + pkg["main"].lstrip("./")) + ")")} || true')
    notes.append('node: dependencies installed (install scripts run), bins called with --help/--version')

# ---------- Python ----------
pyp = {}
if has('pyproject.toml'):
    try:
        with open(os.path.join(src, 'pyproject.toml'), 'rb') as f:
            pyp = tomllib.load(f)
    except Exception:
        pyp = {}
if has('pyproject.toml') or has('setup.py'):
    inst += ['uv venv .venv', 'uv pip install --python .venv/bin/python -e . || uv pip install --python .venv/bin/python . || true']
    eps = dict((pyp.get('project') or {}).get('scripts') or {})
    eps.update(((pyp.get('tool') or {}).get('poetry') or {}).get('scripts') or {})
    for name in eps:
        run += [f'{T} .venv/bin/{q(name)} --help || true', f'{T} .venv/bin/{q(name)} --version || true']
    notes.append(f'python: package installed into .venv; {len(eps)} console script(s) called with --help/--version')
elif has('requirements.txt'):
    inst += ['uv venv .venv', 'uv pip install --python .venv/bin/python -r requirements.txt || true']
    for main in ('main.py', 'app.py', 'cli.py', 'server.py'):
        if has(main):
            run.append(f'{T} .venv/bin/python {main} --help || true')
    notes.append('python: requirements installed into .venv')

# ---------- Go ----------
if has('go.mod'):
    inst.append('mkdir -p .audit-bin && go build -o .audit-bin/ ./... || true')
    run.append('for b in .audit-bin/*; do [ -x "$b" ] || continue; timeout 60 "$b" --help; timeout 60 "$b" version; done || true')
    notes.append('go: all packages built, binaries called with --help/version')

if has('Cargo.toml'):
    notes.append('rust: no Rust toolchain in the VM - static review only')

# ---------- Claude plugins: MCP servers and hooks ----------
plugin_roots = sorted({os.path.dirname(os.path.dirname(p)) for p in glob.glob(f'{src}/**/.claude-plugin/plugin.json', recursive=True)})
mcp_files = glob.glob(f'{src}/**/.mcp.json', recursive=True)
hook_files = glob.glob(f'{src}/**/hooks/hooks.json', recursive=True) + glob.glob(f'{src}/**/.claude/settings*.json', recursive=True)


def plugin_root_for(path):
    best = ''
    for r in plugin_roots:
        if (path + '/').startswith(r + '/') and len(r) > len(best):
            best = r
    return best or src


servers = []
for mf in mcp_files:
    d = load_json(rel(mf))
    for name, s in ((d or {}).get('mcpServers') or {}).items():
        servers.append((mf, name, s))
for r in plugin_roots:
    pj = load_json(rel(os.path.join(r, '.claude-plugin/plugin.json'))) or {}
    ms = pj.get('mcpServers')
    if isinstance(ms, dict):
        for name, s in ms.items():
            servers.append((r, name, s))
    hk = pj.get('hooks')
    if isinstance(hk, str):
        hook_files.append(os.path.normpath(os.path.join(r, hk)))

for where, name, s in servers[:10]:
    if not isinstance(s, dict):
        continue
    if s.get('command'):
        root = '$PWD/' + rel(plugin_root_for(where)) if plugin_root_for(where) != src else '$PWD'
        argv = [str(s['command'])] + [str(a) for a in s.get('args') or []]
        parts = []
        for a in argv:  # ${CLAUDE_PLUGIN_ROOT} must expand in the VM, everything else stays literal
            pieces = a.split('${CLAUDE_PLUGIN_ROOT}')
            parts.append(f'"{root}"'.join(q(p) if p else '' for p in pieces) if len(pieces) > 1 else q(a))
        env = ' '.join(f'{k}={q(str(v))}' for k, v in (s.get('env') or {}).items() if str(k).isidentifier())
        if os.path.basename(argv[0]) in ('npx', 'uvx', 'bunx', 'pnpx'):
            # package is fetched at launch: warm the cache in the (registry-only) install phase, run offline later
            inst.append(f'# fetch MCP package for "{name}" (runs it once with --help)')
            inst.append(f'timeout 300 {" ".join(parts)} --help </dev/null || true')
            env = ('npm_config_prefer_offline=true npm_config_offline=true UV_OFFLINE=1 ' + env).strip()
        run.append(f'# MCP server "{name}" from {rel(where) if where != src else "."}')
        run.append(f'{"env " + env + " " if env else ""}python3 -I /opt/audit/bin/mcp_probe.py --call -- {" ".join(parts)} || true')
    elif s.get('url'):
        notes.append(f'MCP server "{name}" is remote ({s["url"]}) - not contacted; review statically')

for hf in sorted(set(hook_files)):
    if not os.path.isfile(hf):
        continue
    d = load_json(rel(hf))
    if not isinstance(d, dict) or not (d.get('hooks') or any(k[0].isupper() for k in d)):
        continue
    root = plugin_root_for(hf)
    run.append(f'# Claude hooks from {rel(hf)}')
    run.append(f'CLAUDE_PLUGIN_ROOT="$PWD/{rel(root)}" CLAUDE_PROJECT_DIR="$PWD" python3 -I /opt/audit/bin/fire_hooks.py {q(rel(hf))} "$PWD" || true')

# ---------- what is left for a human / Claude ----------
skills = glob.glob(f'{src}/**/SKILL.md', recursive=True)
if len(run) == 1 and len(inst) == 5:
    notes.append(f'nothing executable detected ({len(skills)} SKILL.md file(s)): static review covers it')
for f in ('install.sh', 'install', 'setup.sh', 'Makefile', 'Dockerfile', 'docker-compose.yml', 'compose.yaml'):
    if has(f):
        notes.append(f'{f} present - NOT run by the default scenario (often fetches from the internet); refine with /audit if it is the documented install path')
run.append('cat ~/.claude/settings.json ~/.claude.json 2>/dev/null || true')

os.makedirs(out, exist_ok=True)
for name, lines in (('install.sh', inst), ('run.sh', run)):
    with open(os.path.join(out, name), 'w') as f:
        f.write('\n'.join(lines) + '\n')
with open(os.path.join(out, 'notes.txt'), 'w') as f:
    f.write('\n'.join(notes or ['nothing executable detected']) + '\n')
print('\n'.join(notes))

#!/usr/bin/env python3
"""Turn the runtime logs into 'what it actually did'.

python3 -I analyze_dynamic.py snapshot <out.json>   # persistence-relevant file state
python3 -I analyze_dynamic.py analyze <dynamic_out_dir>  # writes dynamic.json, prints summary
"""
import hashlib, json, os, re, sys
from collections import Counter

HOME = '/home/sandbox'
MACHOME = '/Users/sandbox'   # run-darwin phase
WORK = HOME + '/work'
CACHE_PREFIXES = tuple(HOME + p for p in (
    '/work', '/.cache', '/.npm', '/.local/share/uv', '/.local/share/pnpm', '/.local/share/virtualenv',
    '/go/pkg', '/go/bin', '/.cargo', '/.rustup', '/.node-gyp', '/.yarn', '/.bun', '/.pnpm-store',
    '/.config/configstore', '/.local/state', '/.local/lib', '/.npm-global', '/.deno', '/.config/go',
    '/.local/share/fnm', '/.pyenv', '/.config/matplotlib', '/.ollama'))
SNAP_ROOTS = [HOME, MACHOME, '/tmp', '/var/tmp', '/dev/shm', '/var/spool/cron']


def snapshot(out):
    state = {}
    for r in SNAP_ROOTS:
        for root, dirs, files in os.walk(r):
            if root.startswith(CACHE_PREFIXES) or '/node_modules' in root or '/.git' in root:
                dirs[:] = []
                continue
            for n in files:
                p = os.path.join(root, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                h = ''
                if st.st_size < 200_000 and os.path.isfile(p) and not os.path.islink(p):
                    try:
                        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()[:16]
                    except OSError:
                        pass
                state[p] = [st.st_size, oct(st.st_mode & 0o7777), h]
    json.dump(state, open(out, 'w'))


def load_decoys(o):
    ds = set()
    for f in ('/opt/audit/decoys.txt', os.path.join(o, 'extra-decoys.txt')):
        try:
            ds |= {l.strip() for l in open(f) if l.strip()}
        except OSError:
            pass
    return ds


STRONG_DECOY = re.compile(r'/\.ssh/id_|/\.gnupg/|/\.config/gh/|/\.claude/|/\.config/anthropic|/\.config/openai|google-chrome|mozilla|Exodus|electrum|bitcoin|/\.bash_history|/\.kube/|/\.aws/|/\.git-credentials|/work/\.env$|/sandbox/\.env$|^/Users/sandbox/')
EXPECTED_READERS = {  # decoy -> programs that legitimately read it. Interpreters (node, python) are never listed:
    # a postinstall script stealing ~/.npmrc runs as plain `node`, while npm itself is named by LAUNCHERS below.
    '/.npmrc': ('npm', 'npx', 'pnpm', 'yarn', 'corepack', 'bun'),
    '/.netrc': ('curl', 'git', 'git-remote-http', 'git-remote-https', 'pip', 'pip3', 'uv', 'go', 'wget'),
    '/.pypirc': ('twine',),
    '/.docker/config.json': ('docker',),
    '/.ssh/config': ('ssh', 'git', 'scp'),
}
# An interpreter exec'd on a known package-manager entry point is labelled as that tool, not as node/python.
LAUNCHERS = {'npm-cli.js': 'npm', 'npx-cli.js': 'npx', 'pnpm.cjs': 'pnpm', 'pnpm.js': 'pnpm', 'pnpx.cjs': 'pnpm',
             'yarn.js': 'yarn', 'yarn.cjs': 'yarn', 'corepack.cjs': 'corepack', 'corepack': 'corepack',
             'npm': 'npm', 'npx': 'npx', 'pnpm': 'pnpm', 'yarn': 'yarn', 'pip': 'pip', 'pip3': 'pip3'}
INTERPRETER = re.compile(r'^(node|nodejs|python[\d.]*)$')
SUSP_EXEC = re.compile(r'^(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|base64|xxd|openssl|crontab|systemctl|sudo|su|osascript|security|chattr|nohup|setsid|at|python[\d.]*\s+-c|node\s+-e|perl\s+-e|bash\s+-c\s+.*(http|curl|wget|base64)|sh\s+-c\s+.*(http|curl|wget|base64)|tor|xmrig|.*miner)\b')
EXEC_RE = re.compile(r'^(\d+)\s+execve\("([^"]+)", \[(.*?)\](?:, 0x[0-9a-f]+(?: /\* \d+ vars \*/)?)?\)?\s*(?:= (-?\d+)(?: (\w+))?)?')
OPEN_RE = re.compile(r'^(\d+)\s+openat\((?:AT_FDCWD|\d+<?[^,]*>?), "([^"]+)", ([A-Z_|]+)(?:, \d+)?\)\s*= (-?\d+)')
CONN_RE = re.compile(r'^(\d+)\s+connect\(\d+, \{sa_family=(AF_\w+)(.*?)\}, \d+\)\s*= (-?\d+)(?: (\w+))?')
UNLINK_RE = re.compile(r'^(\d+)\s+(unlinkat|renameat2)\((?:AT_FDCWD|\d+)[^"]*"([^"]+)"')


def parse_strace(path):
    res = {'execs': [], 'exec_counter': Counter(), 'opens': [], 'connects': [], 'deletes': [], 'launched': set()}
    comm = {}
    try:
        if path.endswith('.zst'):
            return res
        fh = open(path, errors='replace')
    except OSError:
        return res
    for line in fh:
        if 'execve(' in line:
            m = EXEC_RE.match(line)
            if m:
                pid, exe, argv, rc, err = m.groups()
                if rc is not None and rc != '0':
                    continue
                args = re.findall(r'"((?:[^"\\]|\\.)*)"', argv)
                cmd = ' '.join(args)[:300]
                name = os.path.basename(exe)
                if INTERPRETER.match(name):
                    script = next((a for a in args[1:] if not a.startswith('-')), '')
                    name = LAUNCHERS.get(os.path.basename(script), name)
                comm[pid] = name
                res['launched'].add(name)
                res['execs'].append((pid, exe, cmd))
                res['exec_counter'][os.path.basename(exe)] += 1
            continue
        if 'openat(' in line:
            m = OPEN_RE.match(line)
            if m:
                pid, p, flags, rc = m.groups()
                res['opens'].append((comm.get(pid, '?'), p, flags, int(rc) >= 0))
            continue
        if 'connect(' in line:
            m = CONN_RE.match(line)
            if m:
                pid, fam, rest, rc, err = m.groups()
                addr = ''
                if fam == 'AF_INET':
                    a = re.search(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)', rest)
                    addr = f'{a.group(2)}:{a.group(1)}' if a else rest
                elif fam == 'AF_INET6':
                    a = re.search(r'sin6_port=htons\((\d+)\).*inet_pton\(AF_INET6, "([^"]+)"', rest)
                    addr = f'[{a.group(2)}]:{a.group(1)}' if a else rest
                elif fam == 'AF_UNIX':
                    a = re.search(r'sun_path="([^"]+)"', rest)
                    addr = a.group(1) if a else rest
                else:
                    addr = rest.strip(', ')[:80]
                res['connects'].append((comm.get(pid, '?'), fam, addr, rc == '0' or err == 'EINPROGRESS', err or ''))
            continue
        if 'unlinkat(' in line or 'renameat2(' in line:
            m = UNLINK_RE.match(line)
            if m:
                res['deletes'].append((comm.get(m.group(1), '?'), m.group(2), m.group(3)))
    return res


SYSTEM_DNS = re.compile(r'(^|\.)(ntp\.ubuntu\.com|ubuntu\.pool\.ntp\.org|motd\.ubuntu\.com|api\.snapcraft\.io|connectivity-check\.ubuntu\.com|cdn\.fwupd\.org|fwupd\.org)$|^lima-|\.internal$')


def dns_names(path):
    names = Counter()
    try:
        for l in open(path, errors='replace'):
            m = re.search(r'query\[(\w+)\] (\S+) from', l)
            if m and not SYSTEM_DNS.search(m.group(2).lower()):
                names[m.group(2).lower()] += 1
    except OSError:
        pass
    return names


def proxy_hosts(path):
    allowed, refused = Counter(), Counter()
    try:
        for l in open(path, errors='replace'):
            m = re.search(r'Request \(file descriptor \d+\): (?:CONNECT|GET|POST|PUT|HEAD) (?:https?://)?([^/:\s]+)', l)
            if m:
                allowed[m.group(1).lower()] += 1
            m = re.search(r'refused on filtered domain "([^"]+)"', l)
            if m:
                refused[m.group(1).lower()] += 1
    except OSError:
        pass
    for h in refused:
        allowed[h] -= refused[h]
    return +allowed, refused


def fw_drops(path):
    d = Counter()
    try:
        for l in open(path, errors='replace'):
            m = re.search(r'DST=(\S+).*?PROTO=(\w+).*?DPT=(\d+)', l)
            if m:
                d[f'{m.group(1)}:{m.group(3)}/{m.group(2)}'] += 1
    except OSError:
        pass
    return d


def analyze(o):
    decoys = load_decoys(o)
    out = {'phases': {}}
    lines = []
    P = lines.append
    try:
        mac_stubs = {l.strip() for l in open(f'{o}/macstubs.txt') if l.strip()}
    except OSError:
        mac_stubs = set()
    for ph in ('install', 'run', 'run-darwin'):
        if ph == 'run-darwin' and not os.path.exists(f'{o}/{ph}.meta.json'):
            continue
        meta = {}
        try:
            meta = json.load(open(f'{o}/{ph}.meta.json'))
        except Exception:
            pass
        st = parse_strace(f'{o}/{ph}.strace')
        decoy_hits, home_reads, sensitive = [], Counter(), []
        for proc, p, flags, ok in st['opens']:
            if p in decoys or any(p.startswith(d.rstrip('/') + '/') for d in decoys if d.endswith('/')):
                exp = next((progs for k, progs in EXPECTED_READERS.items() if p.endswith(k)), ())
                # '?' = a process that forked without exec (e.g. a package manager's worker): expected only if that
                # package manager ran in this phase. A named interpreter (node, python) is never expected.
                expected = proc in exp or (proc == '?' and any(x in st['exec_counter'] or x in st['launched'] for x in exp))
                decoy_hits.append({'process': proc, 'path': p, 'flags': flags, 'expected': expected,
                                   'strong': bool(STRONG_DECOY.search(p))})
            elif p.startswith((HOME + '/', MACHOME + '/')) and not p.startswith(CACHE_PREFIXES) and '/node_modules/' not in p:
                home_reads[(proc, re.sub(r'^(/(?:home|Users)/sandbox/[^/]+(?:/[^/]+)?).*', r'\1', p))] += 1
            elif re.match(r'/etc/(shadow|gshadow|sudoers)|/root/|/proc/\d+/(environ|mem|maps|cmdline)|/var/run/docker\.sock|/run/docker\.sock|/etc/ssh/ssh_host', p):
                if not re.match(r'/proc/(self|thread-self)', p):
                    sensitive.append({'process': proc, 'path': p, 'ok': ok})
        conns = Counter()
        for proc, fam, addr, ok, err in st['connects']:
            if fam in ('AF_INET', 'AF_INET6'):
                host = addr.rsplit(':', 1)[0].strip('[]')
                port = addr.rsplit(':', 1)[-1]
                if host in ('127.0.0.1', '::1', '127.0.0.53'):
                    kind = 'dns' if port == '53' else ('proxy' if port == '8888' else f'local-port-{port}')
                else:
                    kind = 'DIRECT-EGRESS-ATTEMPT'
                conns[(kind, proc, addr)] += 1
            elif fam == 'AF_UNIX':
                if not re.search(r'nscd|/run/systemd/journal|/dev/log', addr):
                    conns[('unix-socket', proc, addr)] += 1
            else:
                conns[(fam, proc, addr)] += 1
        susp = []
        for pid, exe, cmd in st['execs']:
            b = os.path.basename(exe)
            if exe.startswith(HOME + '/.cache/uv/'):
                continue
            if SUSP_EXEC.match(cmd.split('/')[-1] if cmd else b) or SUSP_EXEC.match(f'{b} {" ".join(cmd.split()[1:3])}'):
                susp.append(cmd)
        deletes = [(p, op, f) for p, op, f in st['deletes']
                   if f.startswith('/') and not f.startswith(('/tmp', WORK, '/home/sandbox/.cache', '/home/sandbox/.npm', '/home/sandbox/go', '/var/tmp', '/home/sandbox/.local/share/uv'))
                   and '/node_modules/' not in f]
        allowed, refused = proxy_hosts(f'{o}/{ph}.proxy.log')
        dns = dns_names(f'{o}/{ph}.dns.log')
        drops = fw_drops(f'{o}/{ph}.fwdrop.log')
        leftover = [l.strip() for l in open(f'{o}/{ph}.leftover', errors='replace')] if os.path.exists(f'{o}/{ph}.leftover') else []
        r = {
            'meta': meta,
            'exec_total': len(st['execs']),
            'programs': dict(st['exec_counter'].most_common(40)),
            'suspicious_execs': sorted(set(susp))[:60],
            'decoy_hits': decoy_hits[:100],
            'home_reads_outside_project': [{'process': k[0], 'path': k[1], 'count': n} for k, n in home_reads.most_common(60)],
            'sensitive_system_reads': sensitive[:40],
            'connections': [{'kind': k[0], 'process': k[1], 'addr': k[2], 'count': n} for k, n in conns.most_common(80)],
            'proxy_allowed_hosts': dict(allowed.most_common(60)),
            'proxy_refused_hosts': dict(refused.most_common(60)),
            'dns_queries': dict(dns.most_common(80)),
            'firewall_drops': dict(drops.most_common(40)),
            'deletes_outside_project': deletes[:40],
            'leftover_processes': leftover[:20],
            'macos_tool_calls': sorted({cmd for pid, exe, cmd in st['execs'] if exe in mac_stubs})[:60],
        }
        out['phases'][ph] = r
    # persistence diff
    try:
        a = json.load(open(f'{o}/snap-before.json'))
        b = json.load(open(f'{o}/snap-after.json'))
        noise = re.compile(r'^/tmp/(node-compile-cache|\.audit-phase-rc|v8-compile-cache|jiti|tsx-|\.npm|npm-|uv-|pip-|go-build|\.org\.chromium|hsperfdata)|^/tmp/[^/]*\.(log|lock|sock)$')
        new = sorted(p for p in set(b) - set(a) if not noise.search(p))
        changed = sorted(p for p in set(a) & set(b) if a[p] != b[p])
        removed = sorted(set(a) - set(b))
        hot = re.compile(r'/Library/(LaunchAgents|LaunchDaemons)/|\.(bashrc|profile|bash_profile|zshrc|zprofile|bash_logout)$|/\.config/(autostart|systemd)|/\.ssh/authorized_keys|/\.gitconfig$|/cron|/\.config/fish|/\.xprofile|/\.pam_environment')
        out['persistence'] = {
            'new_files': new[:120], 'changed_files': changed[:60], 'removed_files': removed[:60],
            'hot_spots': [p for p in new + changed + removed if hot.search(p)],
            'new_executables': [p for p in new if b[p][1] and int(b[p][1], 8) & 0o111][:40],
        }
    except Exception as e:
        out['persistence'] = {'error': str(e)}
    try:
        ino = [l.strip() for l in open(f'{o}/decoy-inotify.log', errors='replace') if l.strip()]
        ino = [l for l in ino if l.split(' ', 2)[-1] in decoys]
        out['decoy_inotify'] = ino[:100]
    except OSError:
        ino, out['decoy_inotify'] = [], []
    # Kernel saw a decoy opened or read, but no traced open of that absolute path explains it: a relative-path open
    # after chdir, or a process outside strace (e.g. a daemon started another way). Always worth a look.
    seen = {d['path'] for r in out['phases'].values() for d in r['decoy_hits']}
    touched = {l.split(' ', 2)[-1] for l in ino if re.search(r'\b(OPEN|ACCESS)\b', l.split(' ', 2)[1] if l.count(' ') >= 2 else '')}
    out['decoy_reads_not_in_strace'] = sorted(touched - seen)[:60]
    json.dump(out, open(f'{o}/dynamic.json', 'w'), indent=1)

    # human summary
    for ph, r in out['phases'].items():
        m = r['meta']
        P(f"== PHASE {ph}: exit={m.get('exit')} seconds={m.get('seconds')} timed_out={m.get('timed_out')} execs={r['exec_total']}")
        P(f"  programs: {r['programs']}")
        P(f"  suspicious execs ({len(r['suspicious_execs'])}): " + ('; '.join(r['suspicious_execs'][:25]) or 'none'))
        strong = [d for d in r['decoy_hits'] if d['strong'] or not d['expected']]
        P(f"  DECOY CREDENTIAL READS: {len(r['decoy_hits'])} total, {len(strong)} unexpected/strong")
        for d in r['decoy_hits'][:30]:
            P(f"    {'!!' if (d['strong'] or not d['expected']) else 'ok'} {d['process']} -> {d['path']} ({'expected for this tool' if d['expected'] else 'NOT expected'})")
        P("  home reads outside project/caches: " + ('; '.join(f"{x['process']}:{x['path']}x{x['count']}" for x in r['home_reads_outside_project'][:25]) or 'none'))
        P(f"  sensitive system reads: {r['sensitive_system_reads'][:10] or 'none'}")
        P(f"  proxy ALLOWED hosts: {r['proxy_allowed_hosts'] or 'none'}")
        P(f"  proxy REFUSED hosts (tool wanted these): {r['proxy_refused_hosts'] or 'none'}")
        P(f"  DNS queries: {r['dns_queries'] or 'none'}")
        P(f"  firewall drops (direct connections bypassing proxy): {r['firewall_drops'] or 'none'}")
        P("  connections: " + ('; '.join(f"{c['kind']} {c['process']} {c['addr']} x{c['count']}" for c in r['connections'][:30]) or 'none'))
        P(f"  deletes/renames outside project: {r['deletes_outside_project'][:15] or 'none'}")
        P(f"  processes left running after phase: {r['leftover_processes'] or 'none'}")
        if ph == 'run-darwin':
            P("  macOS tool calls (answered by stand-ins with decoy values): " + ('; '.join(r['macos_tool_calls'][:25]) or 'none'))
    # what only showed up when the code believed it was on a Mac
    if 'run-darwin' in out['phases'] and 'run' in out['phases']:
        a, b = out['phases']['run'], out['phases']['run-darwin']
        only = lambda key, f: sorted(set(map(f, b[key])) - set(map(f, a[key])))
        darwin_only = {
            'decoy_reads': only('decoy_hits', lambda d: d['path']),
            'refused_hosts': only('proxy_refused_hosts', str), 'dns_queries': only('dns_queries', str),
            'programs': only('programs', str), 'macos_tool_calls': b['macos_tool_calls'],
        }
        out['darwin_only'] = darwin_only
        P("== macOS SPOOF (run-darwin vs run): behaviour seen only when the code believed it ran on a Mac")
        for k, v in darwin_only.items():
            P(f"  {k}: {v[:25] or 'none'}")
        try:
            stub_log = [l.rstrip() for l in open(f'{o}/macstub.log', errors='replace') if l.strip()]
        except OSError:
            stub_log = []
        P(f"  stand-in log (argv | stdin; append-only, strace above is authoritative): {len(stub_log)} call(s)")
        for l in stub_log[:20]:
            P('    ' + l[:300])
        json.dump(out, open(f'{o}/dynamic.json', 'w'), indent=1)
    pz = out['persistence']
    P("== PERSISTENCE / FILE CHANGES OUTSIDE PROJECT")
    if 'error' in pz:
        P(f"  error {pz['error']}")
    else:
        P(f"  hot spots (startup files, cron, autostart, authorized_keys): {pz['hot_spots'] or 'none'}")
        P(f"  new executables: {pz['new_executables'] or 'none'}")
        P(f"  new files ({len(pz['new_files'])}): {pz['new_files'][:30]}")
        P(f"  changed files: {pz['changed_files'][:20]}")
        P(f"  removed files: {pz['removed_files'][:20]}")
    unexplained = out['decoy_reads_not_in_strace']
    P(f"== DECOY READS SEEN ONLY BY THE KERNEL (relative path or untraced process): {len(unexplained)}")
    for p in unexplained[:30]:
        P(f"  !! {p}")
    P(f"== DECOY INOTIFY (kernel file events on decoy folders): {len(out['decoy_inotify'])} events")
    for l in out['decoy_inotify'][:20]:
        P('  ' + l)
    print('\n'.join(lines))


if __name__ == '__main__':
    if sys.argv[1] == 'snapshot':
        snapshot(sys.argv[2])
    else:
        analyze(sys.argv[2])

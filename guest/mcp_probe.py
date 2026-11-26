#!/usr/bin/env python3
"""Talk to a stdio MCP server like a client would: initialize, list tools/prompts/resources, optionally call tools
with dummy arguments, list everything again, print it all. Runs INSIDE the VM as 'sandbox'.

python3 -I /opt/audit/bin/mcp_probe.py [--call] [--timeout 60] [--name NAME] [--out DIR] -- <server command> [args...]

Manifest pinning (rug-pull check): what the server advertised is saved as canonical JSON (sorted keys; tools and
prompts sorted by name, resources by uri) with its sha256, as DIR/<NAME>.json (DIR defaults to $AUDIT_MCP_DIR, which
dynamic.sh sets per phase; nothing is saved when neither is given). The lists are fetched again after the tool calls,
and again whenever the server sends notifications/{tools,prompts,resources}/list_changed, so a server that swaps its
tools mid-session is recorded with a diff. analyze_dynamic.py summarises the saved manifests; host/mcp_diff.py diffs
them against the previous audit of the same target.

Besides the manifest, the record keeps the rest of the text the user's AI would be given, untruncated: the server's
`instructions`, each prompt's text (prompts/get), resource templates, tool-call replies, and requests the server sent
to the client (sampling, elicitation). analyze_dynamic.py runs its text checks over all of it. The record is saved
even when the probe is stopped by `timeout` (SIGTERM) or the server never answers (then "complete": false).

This file is also the library both of them use (canonical_manifest, digest, diff_manifests, describe_diff, safe,
load_records): they load it by path, because python3 -I does not put the script's folder on sys.path.
"""
import hashlib, json, os, re, select, signal, stat, subprocess, sys, time

# python3 -I leaves this file's folder off sys.path; textrules.py sits next to it (root-owned in the VM)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True   # no __pycache__ in guest/: audit.sh copies every entry of it into the VM
from textrules import HIDDEN_UNI  # noqa: E402  ANSI escape, Unicode tags, bidi controls, zero-width characters

KINDS = (('tools', 'name'), ('prompts', 'name'), ('resources', 'uri'))
SCHEMA = 'plugin-audit/mcp-manifest'
SCHEMA_VERSION = 1
MAX_PAGES = 20               # nextCursor pages per list
MAX_RECORD_BYTES = 8_000_000  # readers ignore bigger files (the target wrote them)
MAX_REPLY_CHARS = 200_000     # one tool-call reply or server request kept in the record


# ---------------- library ----------------
def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _key(field, it):
    return str(it.get(field)) if isinstance(it, dict) else ''


def canonical_manifest(lists):
    """{'tools': [...] | None, 'prompts': ..., 'resources': ...} with every list in a stable order.
    None means the server did not answer that list (error or no reply), which is not the same as an empty list."""
    out = {}
    for kind, field in KINDS:
        items = (lists or {}).get(kind)
        out[kind] = None if items is None else sorted(items, key=lambda it: (_key(field, it), canonical_bytes(it)))
    return out


def digest(lists):
    return hashlib.sha256(canonical_bytes(canonical_manifest(lists))).hexdigest()


def _index(items, field):
    idx, seen = {}, {}
    for it in items:
        it = it if isinstance(it, dict) else {'_value': it}
        k = _key(field, it)
        seen[k] = seen.get(k, 0) + 1
        idx[k if seen[k] == 1 else f'{k}#{seen[k]}'] = it
    return idx


def diff_manifests(old, new):
    """Per kind: added / removed names, changed items (with the fields that differ), or not_compared when only one
    side has that list. Kinds without differences are left out, so an empty dict means identical."""
    res = {}
    for kind, field in KINDS:
        a, b = (old or {}).get(kind), (new or {}).get(kind)
        if a is None or b is None:
            if (a is None) != (b is None):
                res[kind] = {'not_compared': 'listed in only one of the two runs (no reply or an error in the other)'}
            continue
        ia, ib = _index(a, field), _index(b, field)
        changed = []
        for n in sorted(set(ia) & set(ib)):
            if canonical_bytes(ia[n]) != canonical_bytes(ib[n]):
                fields = sorted(k for k in set(ia[n]) | set(ib[n])
                                if canonical_bytes(ia[n].get(k)) != canonical_bytes(ib[n].get(k)))
                changed.append({'name': n, 'fields': fields, 'before': ia[n], 'after': ib[n]})
        added, removed = sorted(set(ib) - set(ia)), sorted(set(ia) - set(ib))
        if added or removed or changed:
            res[kind] = {'added': added, 'removed': removed, 'changed': changed}
    return res


def is_change(diff):
    """True if the diff shows a real difference (not just a list that could not be compared)."""
    return any('not_compared' not in d for d in (diff or {}).values())


def safe(s, n=300):
    """Printable, single-line, length-capped text: control, escape and invisible characters become \\uXXXX."""
    if not isinstance(s, str):
        s = json.dumps(s, sort_keys=True, ensure_ascii=False)
    s = ''.join(c if c.isprintable() and not HIDDEN_UNI.match(c) else f'\\u{ord(c):04x}' for c in s)
    return s if len(s) <= n else s[:n] + '...'


def keep(obj, n=MAX_REPLY_CHARS):
    """obj as-is for the record, or its JSON text cut to n characters when it is bigger."""
    s = json.dumps(obj, ensure_ascii=False)
    return obj if len(s) <= n else {'truncated': s[:n]}


def describe_diff(diff, indent='    '):
    lines = []
    for kind, d in diff.items():
        if 'not_compared' in d:
            lines.append(f'{indent}{kind}: not compared ({d["not_compared"]})')
            continue
        parts = []
        if d['added']:
            parts.append(f'+{len(d["added"])} added {[safe(x, 80) for x in d["added"][:15]]}')
        if d['removed']:
            parts.append(f'-{len(d["removed"])} removed {[safe(x, 80) for x in d["removed"][:15]]}')
        if d['changed']:
            parts.append(f'~{len(d["changed"])} changed')
        lines.append(f'{indent}{kind}: ' + '; '.join(parts))
        for c in d['changed'][:15]:
            lines.append(f'{indent}  ~ {kind}/{safe(c["name"], 80)}: {", ".join(safe(f, 40) for f in c["fields"])}')
            for f in c['fields'][:4]:
                lines.append(f'{indent}      {safe(f, 40)} before: {safe(c["before"].get(f), 300)}')
                lines.append(f'{indent}      {safe(f, 40)} after:  {safe(c["after"].get(f), 300)}')
    return lines


def hidden_chars(lists):
    """[(kind, item name, json path, 'U+XXXX')] for every string in the manifest holding a hidden/escape character."""
    hits = []

    def walk(kind, name, path, v):
        if isinstance(v, str):
            m = HIDDEN_UNI.search(v)
            if m:
                hits.append((kind, name, path, f'U+{ord(m.group()):04X}'))
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(kind, name, f'{path}.{k}' if path else str(k), x)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(kind, name, f'{path}[{i}]', x)

    for kind, field in KINDS:
        for it in (lists or {}).get(kind) or []:
            walk(kind, _key(field, it), '', it)
    return hits


def load_records(mcp_dir):
    """{phase: {server key: record}} from <mcp_dir>/<phase>/<key>.json. Only regular files (no symlinks), size-capped,
    with the expected schema and a sha256 that matches their own manifest; anything else is skipped."""
    out = {}
    try:
        phases = sorted(os.listdir(mcp_dir))
    except OSError:
        return out
    for ph in phases:
        pdir = os.path.join(mcp_dir, ph)
        if os.path.islink(pdir) or not os.path.isdir(pdir):
            continue
        for fn in sorted(os.listdir(pdir)):
            if not fn.endswith('.json'):
                continue
            try:
                fd = os.open(os.path.join(pdir, fn), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as f:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        continue
                    raw = f.read(MAX_RECORD_BYTES + 1)
                if len(raw) > MAX_RECORD_BYTES:
                    continue
                rec = json.loads(raw)
            except (OSError, ValueError):
                continue
            if (isinstance(rec, dict) and rec.get('schema') == SCHEMA and isinstance(rec.get('manifest'), dict)
                    and rec.get('sha256') == digest(rec['manifest'])):
                out.setdefault(ph, {})[fn[:-5]] = rec
    return out


# ---------------- probe ----------------
DUMMY = {'string': 'test', 'integer': 1, 'number': 1, 'boolean': False, 'array': [], 'object': {}}


class Probe:
    def __init__(self, cmd, tmo):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0)
        self.buf = b''
        self.deadline = time.time() + tmo
        self.next_id = 1
        self.step = 'initialize'
        self.pending = set()   # kinds the server said changed (list_changed), not yet re-listed
        self.notices = []      # every list_changed notification: {'method', 'during'}
        self.server_requests = []   # requests the server sent us (sampling, elicitation, roots...), kept for the record
        self.non_json = []          # stdout lines that are not JSON-RPC (first 50)
        self.errors = []            # requests with no reply or an error reply

    def send(self, obj):
        try:
            self.p.stdin.write((json.dumps(obj) + '\n').encode())
            self.p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def request(self, method, params, grace=0):
        i = self.next_id
        self.next_id += 1
        self.send({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params})
        r = self.recv(i, max(self.deadline, time.time() + grace))
        if r is None or 'error' in r:
            self.errors.append(f'{method}: ' + ('no reply' if r is None else json.dumps(r.get('error'))[:300]))
        return r

    def recv(self, want_id, deadline):
        while time.time() < deadline:
            while b'\n' in self.buf:
                line, self.buf = self.buf.split(b'\n', 1)
                try:
                    msg = json.loads(line)
                except ValueError:
                    text = line.decode('utf-8', 'replace')
                    if text.strip() and len(self.non_json) < 50:
                        self.non_json.append(text[:2000])
                    print('[non-json stdout]', safe(text, 200))
                    continue
                if not isinstance(msg, dict):
                    continue
                method = msg.get('method')
                if 'method' not in msg and msg.get('id') == want_id:
                    return msg
                if isinstance(method, str) and re.fullmatch(r'notifications/(tools|prompts|resources)/list_changed', method):
                    self.pending.add(method.split('/')[1])
                    self.notices.append({'method': method, 'during': self.step})
                elif 'id' in msg and isinstance(method, str):   # a request from the server: answer so it does not hang
                    if len(self.server_requests) < 100:
                        self.server_requests.append(keep(msg))
                    self.send({'jsonrpc': '2.0', 'id': msg['id'], 'result': {}} if method == 'ping' else
                              {'jsonrpc': '2.0', 'id': msg['id'], 'error': {'code': -32601, 'message': 'not supported by the audit probe'}})
                print('[server message]', safe(json.dumps(msg), 300))
            if len(self.buf) > 64_000_000:
                return None
            r, _, _ = select.select([self.p.stdout], [], [], max(0, min(1, deadline - time.time())))
            if r:
                chunk = os.read(self.p.stdout.fileno(), 65536)
                if not chunk:
                    return None
                self.buf += chunk
        return None

    def list_kind(self, kind, grace=0, method=None):
        """All pages of one list; `kind` is the result field (method defaults to <kind>/list). None = no answer."""
        items, cursor = [], None
        for _ in range(MAX_PAGES):
            r = self.request(method or f'{kind}/list', {'cursor': cursor} if cursor else {}, grace)
            res = (r or {}).get('result')
            page = res.get(kind) if isinstance(res, dict) else None
            if not isinstance(page, list):
                return items or None
            items += page
            cursor = res.get('nextCursor')
            if not isinstance(cursor, str) or not cursor:
                break
        return items

    def list_all(self, grace=0):
        return {kind: self.list_kind(kind, grace) for kind, _ in KINDS}

    def close(self):
        self.p.terminate()
        try:
            self.p.wait(5)
        except Exception:
            self.p.kill()


def server_key(name, cmd):
    key = name or (os.path.basename(cmd[0]) + '-' + hashlib.sha256(canonical_bytes(cmd)).hexdigest()[:8])
    key = re.sub(r'[^A-Za-z0-9._-]', '_', key)[:64].lstrip('.')
    return key or 'server'


def save(out_dir, key, record):
    """Write <out_dir>/<key>.json without following or overwriting anything already there (-2, -3... on clashes)."""
    os.makedirs(out_dir, exist_ok=True)
    data = json.dumps(record, sort_keys=True, indent=1, ensure_ascii=True) + '\n'
    for n in range(1, 21):
        path = os.path.join(out_dir, f'{key}.json' if n == 1 else f'{key}-{n}.json')
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        except FileExistsError:
            continue
        with os.fdopen(fd, 'w') as f:
            f.write(data)
        return path
    return None


def main(argv):
    if '--' not in argv:
        sys.exit(__doc__)
    opts, cmd = argv[:argv.index('--')], argv[argv.index('--') + 1:]
    if not cmd:
        sys.exit(__doc__)

    def opt(flag, default=None):
        return opts[opts.index(flag) + 1] if flag in opts and opts.index(flag) + 1 < len(opts) else default

    call, tmo = '--call' in opts, int(opt('--timeout', 60))
    out_dir = opt('--out') or os.environ.get('AUDIT_MCP_DIR')
    key = server_key(opt('--name'), cmd)
    empty = canonical_manifest(None)
    record = {'schema': SCHEMA, 'schema_version': SCHEMA_VERSION, 'server_key': key, 'command': cmd, 'complete': False,
              'server_info': None, 'protocol_version': None, 'capabilities': None, 'instructions': None,
              'manifest': empty, 'sha256': digest(empty), 'relists': [], 'list_changed': [],
              'final_sha256': digest(empty), 'swapped_mid_session': False, 'prompt_texts': {},
              'resource_templates': None, 'calls': [], 'server_requests': [], 'non_json_stdout': [], 'errors': []}
    # `timeout` around the probe sends SIGTERM: unwind through `finally` so what was seen so far is still saved
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(124))
    pr = None
    try:
        pr = Probe(cmd, tmo)
        record.update(list_changed=pr.notices, server_requests=pr.server_requests, non_json_stdout=pr.non_json,
                      errors=pr.errors)
        init = pr.request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                         'clientInfo': {'name': 'audit-probe', 'version': '1'}})
        print('INITIALIZE:', safe(json.dumps(init), 1500))
        if not init:
            return 1
        pr.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        result = (init.get('result') if isinstance(init.get('result'), dict) else {}) or {}
        caps = result.get('capabilities') if isinstance(result.get('capabilities'), dict) else {}
        record.update(server_info=result.get('serverInfo'), protocol_version=result.get('protocolVersion'),
                      capabilities=result.get('capabilities'), instructions=result.get('instructions'))
        pr.step = 'first listing'
        first = pr.list_all()
        for kind, _ in KINDS:
            items = first[kind]
            print(f'{kind.upper()}/LIST: {len(items) if items is not None else "no answer"}')
            for it in items or []:
                it = it if isinstance(it, dict) else {}
                print('  -', safe(it.get('name') or it.get('uri'), 120), '|', safe(it.get('description') or '', 600))
        record.update(manifest=canonical_manifest(first), sha256=digest(first), final_sha256=digest(first))
        print(f'MANIFEST {key}: sha256 {record["sha256"]}')
        current = first

        def relist(reason, grace=0):
            nonlocal current
            pr.pending.clear()
            new = pr.list_all(grace)
            new = {k: (new[k] if new[k] is not None else current[k]) for k, _ in KINDS}   # keep the last known list
            d = diff_manifests(current, new)
            record['relists'].append({'reason': reason, 'sha256': digest(new), 'changed': is_change(d), 'diff': d,
                                      'manifest': canonical_manifest(new) if d else None})
            print(f'RELIST ({reason}): sha256 {digest(new)} ' + ('CHANGED' if is_change(d) else 'unchanged'))
            for line in describe_diff(d):
                print(line)
            current = new

        if pr.pending:
            relist('list_changed during the first listing')
        # the rest of the text a client shows its AI: prompt bodies and resource templates
        pr.step = 'prompts/get'
        for p in [p for p in first['prompts'] or [] if isinstance(p, dict) and isinstance(p.get('name'), str)][:25]:
            args = {a['name']: 'test' for a in p.get('arguments') or [] if isinstance(a, dict) and isinstance(a.get('name'), str)}
            r = pr.request('prompts/get', {'name': p['name'], 'arguments': args})
            record['prompt_texts'][p['name']] = keep((r or {}).get('result'))
        if 'resources' in caps:
            pr.step = 'resource templates'
            record['resource_templates'] = pr.list_kind('resourceTemplates', method='resources/templates/list')
        if pr.pending:
            relist('list_changed during prompts/get')
        if call:
            tools = [t for t in first['tools'] or [] if isinstance(t, dict) and isinstance(t.get('name'), str)]
            for t in tools[:25]:
                schema = t.get('inputSchema') if isinstance(t.get('inputSchema'), dict) else {}
                props = schema.get('properties') if isinstance(schema.get('properties'), dict) else {}
                dummy = {}
                for k, v in props.items():
                    ty = v.get('type') if isinstance(v, dict) else None
                    dummy[k] = DUMMY.get(ty, 'test') if isinstance(ty, str) else 'test'
                pr.step = f'call {t["name"]}'
                r = pr.request('tools/call', {'name': t['name'], 'arguments': dummy})
                record['calls'].append({'name': t['name'], 'arguments': dummy, 'reply': keep(r)})
                print(f'CALL {safe(t["name"], 80)}({safe(json.dumps(dummy), 120)}) ->', safe(json.dumps(r), 400) if r else 'no reply')
                if pr.pending:
                    relist(f'list_changed during {pr.step}')
        pr.step = 'final listing'
        relist('after the tool calls' if call else 'end of session', grace=15)
        record['final_sha256'] = digest(current)
        record['swapped_mid_session'] = any(r['changed'] for r in record['relists'])
        record['complete'] = True
        print(f'SERVER REQUESTS: {len(pr.server_requests)}  ERRORS: {len(pr.errors)}')
        return 0
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if pr:
            pr.close()
        if out_dir:
            path = save(out_dir, key, record)
            print(f'MANIFEST saved: {path}' if path else f'MANIFEST not saved: {out_dir} has too many {key}*.json')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

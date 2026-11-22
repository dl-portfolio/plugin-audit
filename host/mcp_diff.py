#!/usr/bin/env python3
"""Rug-pull check: diff this audit's MCP manifests against the previous audit of the same target (host, `audit.sh run`).

    python3 -I host/mcp_diff.py <repo-root> <AUDIT_ID>

Prints a summary section (audit.sh appends it to work/<id>/dynamic/dynamic-summary.txt, which the reviewer reads) and
writes work/<id>/dynamic/mcp-diff.json. Baseline, first found:
  1. work/<id>/mcp-previous/: the manifests of the previous `audit.sh run` of this same audit (e.g. an unpinned
     npx/uvx MCP server run again at the same commit, which may now fetch a different package);
  2. else the newest other work/<id2>/ whose meta.json has the same target label (an earlier commit).
Every manifest was written by target-controlled code in the VM: files are size-capped, parsed as JSON only, checked
against their own sha256, and every string is escaped before it is printed. Nothing here runs target code.
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PHASE_ORDER = ('run', 'run-darwin', 'install')   # which phase's manifest stands for a server


def probe_lib():
    sys.dont_write_bytecode = True   # no __pycache__ in guest/: audit.sh copies every file in it into the VM
    spec = importlib.util.spec_from_file_location('mcp_probe', os.path.join(HERE, '..', 'guest', 'mcp_probe.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_meta(path):
    try:
        with open(path, encoding='utf-8') as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def per_server(records):
    """{key: (phase, record)} using the first phase in PHASE_ORDER that probed the server."""
    out = {}
    for ph in sorted(records, key=lambda p: PHASE_ORDER.index(p) if p in PHASE_ORDER else len(PHASE_ORDER)):
        for key, rec in records[ph].items():
            out.setdefault(key, (ph, rec))
    return out


def find_baseline(lib, root, rid, label):
    work = os.path.join(root, 'work', rid)
    prev = lib.load_records(os.path.join(work, 'mcp-previous'))
    if prev:
        return 'the previous run of this audit (work/%s/mcp-previous/)' % rid, prev
    best = None
    try:
        others = sorted(os.listdir(os.path.join(root, 'work')))
    except OSError:
        others = []
    for other in others:
        if other == rid or not re.fullmatch(r'[a-z0-9.-]+', other):
            continue
        meta = read_meta(os.path.join(root, 'work', other, 'meta.json'))
        if meta.get('label') != label:
            continue
        recs = lib.load_records(os.path.join(root, 'work', other, 'dynamic', 'mcp'))
        if recs and (best is None or str(meta.get('scanned_at', '')) > str(best[0].get('scanned_at', ''))):
            best = (meta, other, recs)
    if best:
        meta, other, recs = best
        return ('work/%s (commit %s, scanned %s)' % (other, str(meta.get('commit', '?'))[:12], meta.get('scanned_at', '?')),
                recs)
    return None, {}


def main(root, rid):
    if not re.fullmatch(r'[a-z0-9.-]+', rid):
        sys.exit('bad audit id')
    lib = probe_lib()
    work = os.path.join(root, 'work', rid)
    label = read_meta(os.path.join(work, 'meta.json')).get('label')
    cur = per_server(lib.load_records(os.path.join(work, 'dynamic', 'mcp')))
    where, base_recs = find_baseline(lib, root, rid, label)
    base = per_server(base_recs)
    if not cur and not base:
        return 0   # no MCP server in this target: nothing to say
    lines = ['== MCP MANIFEST DIFF vs the previous audit of this target (host; rug-pull check)']
    result = {'baseline': where, 'servers': {}}
    if not base:
        lines.append(f'  no earlier audit of {lib.safe(label, 120)} with MCP manifests in work/: these manifests are '
                     'the baseline for the next one')
    else:
        lines.append(f'  baseline: {lib.safe(where, 200)}')
    for key in sorted(set(cur) | set(base)):
        k = lib.safe(key, 64)
        if key not in base:
            ph, rec = cur[key]
            status = 'new' if base else 'first seen'
            lines.append(f'  {k}: {status.upper()} sha256 {rec["sha256"]} ({ph})')
            result['servers'][key] = {'status': status, 'sha256_after': rec['sha256']}
            continue
        if key not in cur:
            ph, rec = base[key]
            lines.append(f'  {k}: GONE (in the baseline, not probed in this audit) sha256 was {rec["sha256"]}')
            result['servers'][key] = {'status': 'gone', 'sha256_before': rec['sha256']}
            continue
        (_, old), (_, new) = base[key], cur[key]
        d = lib.diff_manifests(old['manifest'], new['manifest'])
        if not d:
            lines.append(f'  {k}: unchanged (sha256 {new["sha256"]})')
            status = 'unchanged'
        else:
            status = 'changed' if lib.is_change(d) else 'not comparable'
            lines.append(f'  {"!! " if status == "changed" else ""}{k}: {status.upper()} sha256 {old["sha256"]} -> {new["sha256"]}')
            info_old = old.get('server_info') if isinstance(old.get('server_info'), dict) else {}
            info_new = new.get('server_info') if isinstance(new.get('server_info'), dict) else {}
            lines.append(f'    server version: {lib.safe(info_old.get("version"), 30)} -> {lib.safe(info_new.get("version"), 30)}')
            lines += lib.describe_diff(d, '    ')
        result['servers'][key] = {'status': status, 'sha256_before': old['sha256'], 'sha256_after': new['sha256'], 'diff': d}
    print('\n'.join(lines))
    try:
        with open(os.path.join(work, 'dynamic', 'mcp-diff.json'), 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=1, sort_keys=True, ensure_ascii=True)
    except OSError as e:
        print(f'  (could not write mcp-diff.json: {e})')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))

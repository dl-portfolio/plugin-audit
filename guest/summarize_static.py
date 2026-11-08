#!/usr/bin/env python3
"""Condense all static scanner outputs into one text summary for the reviewer.
Usage: python3 -I summarize_static.py <static_out_dir>"""
import glob, json, os, sys
from collections import Counter

O = sys.argv[1]
src = '/audit/src/'


def load(p):
    try:
        return json.load(open(p))
    except Exception as e:
        return {'_error': str(e)}


def short(p):
    return (p or '').replace(src, '')


print('== OUR CHECKS (claude_checks)')
cc = load(f'{O}/claude_checks.json')
if '_error' in cc:
    print('  error:', cc['_error'])
else:
    print('  counts:', json.dumps(cc.get('counts')))
    print('  stats:', json.dumps({k: v for k, v in cc.get('stats', {}).items() if not k.startswith('ext:')}))
    print('  file types:', json.dumps({k[4:]: v for k, v in cc.get('stats', {}).items() if k.startswith('ext:')}))
    for k, v in cc.get('artifacts', {}).items():
        print(f'  artifact {k} ({len(v)}): {v[:15]}')
    for h in cc.get('install_hooks', [])[:30]:
        print(f'  install-hook: {h}')
    for m in cc.get('mcp_servers', [])[:30]:
        print(f'  mcp-server: {m}')
    print(f'  outbound hosts ({len(cc.get("hosts", {}))}):')
    for h, where in list(cc.get('hosts', {}).items())[:150]:
        print(f'    {h}  <- {", ".join(where[:2])}')
    print('  findings (code context first; docs/tests/vendored after):')
    shown = Counter()
    for f in cc.get('findings', []):
        if f['severity'] == 'info' and f['category'] != 'telemetry':
            continue
        key = (f['severity'], f['context'])
        shown[key] += 1
        if shown[key] > (60 if f['context'] == 'code' else 15):
            continue
        loc = f"{f['file']}:{f['line']}" if f['line'] else f['file']
        print(f"    [{f['severity']}/{f['context']}] {f['category']}: {f['detail']} — {loc} | {f['snippet'][:160]}")

print('\n== GITLEAKS')
gl = load(f'{O}/gitleaks.json')
if isinstance(gl, list):
    print(f'  {len(gl)} possible secrets')
    for g in gl[:25]:
        print(f"    {g.get('RuleID')} {g.get('File','').replace(src,'')}:{g.get('StartLine')}")
else:
    print('  ', gl)

print('\n== OSV-SCANNER (offline)')
osv = load(f'{O}/osv.json')
if '_error' in osv:
    print('  no output (no lockfiles?)', osv['_error'][:80])
else:
    vulns, mal = Counter(), []
    for r in osv.get('results', []):
        for p in r.get('packages', []):
            pk = p.get('package', {})
            for v in p.get('vulnerabilities', []):
                vid = v.get('id', '')
                if vid.startswith('MAL-'):
                    mal.append(f"{pk.get('ecosystem')}/{pk.get('name')}@{pk.get('version')} {vid}")
                vulns[f"{pk.get('ecosystem')}/{pk.get('name')}@{pk.get('version')}"] += 1
    print(f'  MALICIOUS PACKAGES: {mal or "none"}')
    print(f'  vulnerable packages: {len(vulns)} (total advisories {sum(vulns.values())})')
    for k, n in vulns.most_common(25):
        print(f'    {k}: {n}')

print('\n== SEMGREP (local security rules)')
sg = load(f'{O}/semgrep.json')
if '_error' in sg:
    print('  ', sg['_error'][:100])
else:
    res = sg.get('results', [])
    sev = Counter(r.get('extra', {}).get('severity') for r in res)
    print(f'  {len(res)} results {dict(sev)}; errors {len(sg.get("errors", []))}')
    byrule = Counter((r.get('extra', {}).get('severity'), r.get('check_id', '').split('.')[-1]) for r in res)
    for (s, rid), n in byrule.most_common(30):
        ex = next(r for r in res if r.get('check_id', '').endswith(rid))
        print(f"    [{s}] {rid} x{n} e.g. {short(ex.get('path'))}:{ex.get('start', {}).get('line')}")

for p in sorted(glob.glob(f'{O}/skillspector_*.json')):
    d = load(p)
    print(f'\n== SKILLSPECTOR {os.path.basename(p)}')
    if '_error' in d:
        print('  ', d['_error'][:100]); continue
    print(f"  risk: {json.dumps(d.get('risk_assessment'))}  coverage: {(d.get('analysis_completeness') or {}).get('status')}")
    fs = d.get('issues') or d.get('findings') or []
    print(f'  {len(fs)} findings')
    for f in fs[:40]:
        if isinstance(f, dict):
            loc = f.get('location') or {}
            print(f"    [{f.get('severity')}] {f.get('id')} {f.get('category')}/{f.get('pattern')}: "
                  f"{(f.get('explanation') or '')[:140]} — {loc.get('file')}:{loc.get('start_line')} | {(f.get('code_snippet') or '')[:120]!r}")

for p in sorted(glob.glob(f'{O}/cisco_*.json')):
    d = load(p)
    print(f'\n== CISCO SKILL-SCANNER {os.path.basename(p)}')
    if '_error' in d:
        print('  ', d['_error'][:100]); continue
    for k in ('is_safe', 'max_severity', 'risk_level', 'summary'):
        if k in d:
            print(f'  {k}: {str(d[k])[:200]}')
    fs = d.get('findings') or []
    if not fs and isinstance(d.get('results'), list):
        fs = [f for r in d['results'] for f in (r.get('findings') or [])]
    print(f'  {len(fs)} findings')
    for f in fs[:30]:
        if isinstance(f, dict):
            print(f"    [{f.get('severity')}] {f.get('rule_id') or f.get('category')} {f.get('title') or f.get('description','')}"[:200]
                  + f" — {short(str(f.get('file_path') or f.get('file') or ''))}:{f.get('line_number') or f.get('line') or ''}")

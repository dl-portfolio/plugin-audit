#!/usr/bin/env python3
"""Publish the review LLM's output into reports/ (runs on the host, from ./audit and from /audit).

    python3 -I host/publish_report.py <repo-root> <AUDIT_ID>

The review LLM can only write work/<id>/report.md, work/<id>/index-row.md and work/<id>/report.json. This script is
the only thing that touches reports/: it refuses output that looks like it carries a real secret or a host path (a
prompt-injected reviewer could otherwise smuggle them into a report that gets published), and a report.json that does
not follow docs/verdict-schema.md or disagrees with meta.json, the index row or the report title. Only when all of it
passes does it write reports/<id>.md, reports/<id>.json and reports/<id>.sarif (SARIF 2.1.0), replace this audit's row
in reports/README.md and recompute the verdict counts. On refusal nothing is written; everything stays in work/<id>/
for a human. Stdlib only.
"""
import datetime
import json
import os
import re
import sys

SECRET_PATTERNS = [
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}'),
    re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'),
    re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
    re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}'),
    re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'),
]
VERDICTS = ('DO NOT USE', 'USE WITH PRECAUTIONS', 'SAFE TO USE')   # most specific first
TOOL_HEADER = '| Tool | Verdict | One line | Report |'
FIXTURE = 'tests/fixture-malicious'   # the positive control: one row, kept last, never counted

# ---- verdict JSON (docs/verdict-schema.md)
SCHEMA = 'plugin-audit/verdict'
SCHEMA_VERSIONS = (1,)
MAX_JSON_BYTES = 1_000_000
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
TOP_REQUIRED = ('schema', 'schema_version', 'audit_id', 'tool', 'commit', 'verdict', 'summary', 'dates', 'findings')
TOP_OPTIONAL = ('precautions', 'not_covered')
FINDING_REQUIRED = ('id', 'severity', 'title', 'evidence')
FINDING_OPTIONAL = ('category', 'detail', 'location', 'matches_stated_purpose')
# control characters, and invisible/text-hiding ones (ANSI escape, bidi, zero-width, Unicode tags)
BAD_CHARS = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\U000E0000-\U000E007F\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\u180E\uFEFF]')
SARIF_LEVEL = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}
SARIF_SCORE = {'critical': '9.5', 'high': '8.0', 'medium': '5.5', 'low': '3.0', 'info': '0.0'}


def is_fixture(tool):
    return 'fixture-malicious' in tool


def fail(msg):
    print(f'publish refused: {msg}', file=sys.stderr)
    sys.exit(1)


def leaks(text, host_paths):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if 'AUDITDECOY' in line:          # our own decoy values may be quoted as evidence
            continue
        for p in host_paths:
            if p in line:
                hits.append(f'line {n}: host path')
        for pat in SECRET_PATTERNS:
            if pat.search(line):
                hits.append(f'line {n}: looks like a secret ({pat.pattern[:24]}...)')
    return hits


def cells(row):
    return [c.strip() for c in row.strip().strip('|').split('|')]


def verdict_of(cell):
    return next((v for v in VERDICTS if f'**{v}**' in cell), None)


def update_index(index, row, rid):
    lines = index.splitlines()
    try:
        h = lines.index(TOOL_HEADER)
    except ValueError:
        fail(f'reports/README.md has no "{TOOL_HEADER}" table')
    end = h + 2
    while end < len(lines) and lines[end].startswith('|'):
        end += 1
    rows = [r for r in lines[h + 2:end] if f']({rid}.md)' not in r]
    c = cells(row)
    if is_fixture(c[0]):
        verdict = c[1] if 'positive control' in c[1] else f'{c[1]} (positive control)'
        row = '| ' + ' | '.join([FIXTURE, verdict] + c[2:]) + ' |'
        rows = [r for r in rows if not is_fixture(cells(r)[0])] + [row]
    else:
        rows.insert(0, row)
    lines[h + 2:end] = rows
    counts = dict.fromkeys(VERDICTS, 0)
    for r in rows:
        c = cells(r)
        v = verdict_of(c[1]) if len(c) > 1 else None
        if v and not is_fixture(c[0]):
            counts[v] += 1
    for i, line in enumerate(lines[:h]):
        for v in VERDICTS:
            m = re.match(r'^(\|[^|]*\*\*' + re.escape(v) + r'\*\*[^|]*\|[^|]*\| )(\d+)(.*)$', line)
            if m:
                lines[i] = f'{m.group(1)}{counts[v]}{m.group(3)}'
                break
    return '\n'.join(lines) + '\n'


# ---------------- verdict JSON ----------------
def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ValueError(f'duplicate key(s) {dup}')
    return dict(pairs)


def parse_verdict_json(raw):
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f'larger than {MAX_JSON_BYTES} bytes')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('not UTF-8') from None
    return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)


def _no_constant(name):
    raise ValueError(f'{name} is not allowed')


def validate_verdict(v, rid, meta, src_dir, today=None):
    """Return a list of problems (empty = valid). meta is work/<id>/meta.json (written by audit.sh, trusted)."""
    errs = []
    today = today or datetime.datetime.now(datetime.timezone.utc).date()

    def text(where, s, lo, hi, newlines=False):
        if not isinstance(s, str):
            errs.append(f'{where}: must be a string')
            return False
        if not lo <= len(s) <= hi:
            errs.append(f'{where}: length {len(s)} not in {lo}-{hi}')
        m = BAD_CHARS.search(s) or (None if newlines else re.search('[\n\t]', s))
        if m:
            errs.append(f'{where}: forbidden character U+{ord(m.group()):04X}')
        return True

    def keys(where, obj, required, optional):
        if not isinstance(obj, dict):
            errs.append(f'{where}: must be an object')
            return False
        for k in required:
            if k not in obj:
                errs.append(f'{where}: missing "{k}"')
        for k in sorted(set(obj) - set(required) - set(optional)):
            errs.append(f'{where}: unknown field "{k}"')
        return True

    def strlist(where, xs):
        if not isinstance(xs, list) or len(xs) > 50:
            errs.append(f'{where}: must be a list of at most 50 strings')
            return
        for i, s in enumerate(xs):
            text(f'{where}[{i}]', s, 1, 500)

    if not keys('report.json', v, TOP_REQUIRED, TOP_OPTIONAL):
        return errs
    if v.get('schema') != SCHEMA:
        errs.append(f'schema: must be "{SCHEMA}"')
    sv = v.get('schema_version')
    if type(sv) is not int or sv not in SCHEMA_VERSIONS:
        errs.append(f'schema_version: must be one of {list(SCHEMA_VERSIONS)}')
    if v.get('audit_id') != rid:
        errs.append(f'audit_id: must be "{rid}"')
    if v.get('tool') != meta.get('label'):
        errs.append(f'tool: must be the target label from meta.json ("{meta.get("label")}")')
    c = v.get('commit')
    if not (isinstance(c, str) and re.fullmatch(r'[0-9a-f]{40}', c)):
        errs.append('commit: must be 40 lowercase hex characters')
    elif c != meta.get('commit'):
        errs.append('commit: does not match meta.json')
    if v.get('verdict') not in VERDICTS:
        errs.append(f'verdict: must be one of {list(VERDICTS)}')
    if 'summary' in v:
        text('summary', v['summary'], 1, 1500, newlines=True)

    dates = v.get('dates')
    if keys('dates', dates, ('scanned', 'reviewed'), ()):
        if dates.get('scanned') != meta.get('scanned_at'):
            errs.append(f'dates.scanned: must equal meta.json scanned_at ("{meta.get("scanned_at")}")')
        rv = dates.get('reviewed')
        try:
            if not (isinstance(rv, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', rv)):
                raise ValueError
            reviewed = datetime.date.fromisoformat(rv)
        except ValueError:
            errs.append('dates.reviewed: must be a date, YYYY-MM-DD')
        else:
            scanned = str(meta.get('scanned_at', ''))[:10]
            if scanned and rv < scanned:
                errs.append('dates.reviewed: before the scan')
            if reviewed > today + datetime.timedelta(days=1):
                errs.append('dates.reviewed: in the future')

    findings = v.get('findings')
    if not isinstance(findings, list) or len(findings) > 200:
        errs.append('findings: must be a list of at most 200 findings')
        findings = []
    ids = set()
    src_real = os.path.realpath(src_dir)
    for i, f in enumerate(findings):
        w = f'findings[{i}]'
        if not keys(w, f, FINDING_REQUIRED, FINDING_OPTIONAL):
            continue
        fid = f.get('id')
        if not (isinstance(fid, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', fid)):
            errs.append(f'{w}.id: must match [A-Za-z][A-Za-z0-9_-]{{0,31}}')
        elif fid in ids:
            errs.append(f'{w}.id: duplicate "{fid}"')
        else:
            ids.add(fid)
        if f.get('severity') not in SEVERITIES:
            errs.append(f'{w}.severity: must be one of {list(SEVERITIES)}')
        if 'title' in f:
            text(f'{w}.title', f['title'], 1, 200)
        if 'evidence' in f:
            text(f'{w}.evidence', f['evidence'], 1, 1000, newlines=True)
        if 'detail' in f:
            text(f'{w}.detail', f['detail'], 0, 2000, newlines=True)
        if 'category' in f and not (isinstance(f['category'], str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', f['category'])):
            errs.append(f'{w}.category: must be a lowercase slug (a-z, 0-9, -), max 40')
        if 'matches_stated_purpose' in f and not isinstance(f['matches_stated_purpose'], bool):
            errs.append(f'{w}.matches_stated_purpose: must be true or false')
        if 'location' in f and keys(f'{w}.location', f['location'], ('path',), ('line',)):
            loc = f['location']
            p, line = loc.get('path'), loc.get('line', 1)
            if not (isinstance(p, str) and text(f'{w}.location.path', p, 1, 500)
                    and not p.startswith(('/', '~')) and '\\' not in p and '://' not in p
                    and not {'', '.', '..'} & set(p.split('/'))):
                errs.append(f'{w}.location.path: must be a relative path inside the target, like "lib/x.js"')
            else:
                full = os.path.realpath(os.path.join(src_dir, p))
                if not (full.startswith(src_real + os.sep) and os.path.isfile(full)):
                    errs.append(f'{w}.location.path: "{p}" is not a file in work/{rid}/src/')
            if type(line) is not int or not 1 <= line <= 10_000_000:
                errs.append(f'{w}.location.line: must be an integer >= 1')
    for k in TOP_OPTIONAL:
        if k in v:
            strlist(k, v[k])

    sev = {f.get('severity') for f in findings if isinstance(f, dict)}
    if v.get('verdict') == 'SAFE TO USE' and sev & {'critical', 'high'}:
        errs.append('verdict: SAFE TO USE with a critical or high finding')
    if v.get('verdict') == 'DO NOT USE' and not sev & {'critical', 'high'}:
        errs.append('verdict: DO NOT USE without a critical or high finding')
    return errs


def repository_uri(meta):
    if meta.get('kind') == 'github':
        return f'https://github.com/{meta.get("label")}'
    if meta.get('kind') == 'git':
        return meta.get('label')
    return None   # local folder: no repository


def to_sarif(v, meta):
    rules, results = {}, []
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for f in v['findings']:
        rule_id = 'plugin-audit/' + f.get('category', 'finding')
        if rule_id not in rules:
            rules[rule_id] = {'id': rule_id, 'shortDescription': {'text': f.get('category', 'finding')},
                              'properties': {'tags': ['security', 'plugin-audit'], 'severity': f['severity']}}
        r = rules[rule_id]['properties']
        if order[f['severity']] < order[r['severity']]:
            r['severity'] = f['severity']
        res = {'ruleId': rule_id, 'level': SARIF_LEVEL[f['severity']],
               'message': {'text': f'{f["title"]}\nEvidence: {f["evidence"]}'},
               'properties': {'severity': f['severity'], 'findingId': f['id']}}
        if 'matches_stated_purpose' in f:
            res['properties']['matchesStatedPurpose'] = f['matches_stated_purpose']
        loc = f.get('location')
        if loc:
            phys = {'artifactLocation': {'uri': loc['path'], 'uriBaseId': 'SRCROOT'}}
            if 'line' in loc:
                phys['region'] = {'startLine': loc['line']}
            res['locations'] = [{'physicalLocation': phys}]
        results.append(res)
    rule_list = list(rules.values())
    index = {r['id']: i for i, r in enumerate(rule_list)}
    for r in rule_list:
        r['properties']['security-severity'] = SARIF_SCORE[r['properties'].pop('severity')]
    for res in results:
        res['ruleIndex'] = index[res['ruleId']]
    run = {
        'tool': {'driver': {'name': 'plugin-audit', 'informationUri': 'https://github.com/dl-portfolio/plugin-audit',
                            'rules': rule_list}},
        'automationDetails': {'id': f'plugin-audit/{v["audit_id"]}'},
        'originalUriBaseIds': {'SRCROOT': {'description': {'text': 'Root of the audited repository at the audited commit'}}},
        'results': results,
        'properties': {'verdict': v['verdict'], 'auditId': v['audit_id'], 'tool': v['tool'], 'commit': v['commit'],
                       'reviewed': v['dates']['reviewed'], 'schemaVersion': v['schema_version'],
                       'report': f'{v["audit_id"]}.md'},
    }
    repo = repository_uri(meta)
    if repo:
        run['versionControlProvenance'] = [{'repositoryUri': repo, 'revisionId': v['commit']}]
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': [run]}


def read(path, binary=False):
    with open(path, 'rb' if binary else 'r', **({} if binary else {'encoding': 'utf-8'})) as f:
        return f.read()


def main(root, rid):
    if not re.fullmatch(r'[a-z0-9.-]+', rid):
        fail('bad audit id')
    work = os.path.join(root, 'work', rid)
    try:
        report = read(os.path.join(work, 'report.md'))
        row_text = read(os.path.join(work, 'index-row.md'))
        raw_json = read(os.path.join(work, 'report.json'), binary=True)
    except OSError as e:
        fail(f'missing reviewer output ({e.filename})')
    try:
        meta = json.loads(read(os.path.join(work, 'meta.json')))
    except (OSError, ValueError) as e:
        fail(f'cannot read work/{rid}/meta.json ({e})')
    if not report.startswith('# '):
        fail('report.md does not start with a "# " title')
    rows = [line for line in row_text.splitlines() if line.strip()]
    if len(rows) != 1:
        fail('index-row.md must hold exactly one table row')
    row = rows[0].strip()
    c = cells(row)
    if not (row.startswith('|') and row.endswith('|') and len(c) == 4 and verdict_of(c[1])
            and f'[{rid}]({rid}.md)' in c[3]):
        fail(f'index-row.md is not "| tool | **VERDICT** | one line | [{rid}]({rid}.md) |"')
    try:
        verdict = parse_verdict_json(raw_json)
    except ValueError as e:
        fail(f'report.json is not valid JSON ({e})')
    errs = validate_verdict(verdict, rid, meta, os.path.join(work, 'src'))
    if errs:
        fail('report.json does not follow docs/verdict-schema.md:\n  ' + '\n  '.join(errs[:30]))
    title = report.splitlines()[0]
    if verdict_of(c[1]) != verdict['verdict'] or next((x for x in VERDICTS if x in title), None) != verdict['verdict']:
        fail(f'verdict differs between report.json ({verdict["verdict"]}), index-row.md and the report.md title')
    home = os.path.expanduser('~')
    host_paths = {home, os.path.realpath(root)} - {'/', ''}
    decoded = json.dumps(verdict, indent=1, ensure_ascii=False)   # checked decoded: \\u escapes cannot hide a token
    hits = (leaks(report, host_paths) + leaks(row, host_paths)
            + [f'report.json {h}' for h in leaks(decoded, host_paths) + leaks(raw_json.decode('utf-8'), host_paths)])
    if hits:
        fail('possible secret or host path in reviewer output; check work/%s/ by hand:\n  %s'
             % (rid, '\n  '.join(hits[:20])))
    sarif = to_sarif(verdict, meta)
    out = os.path.join(root, 'reports', rid)
    with open(out + '.md', 'w', encoding='utf-8') as f:
        f.write(report if report.endswith('\n') else report + '\n')
    with open(out + '.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(verdict, indent=2, ensure_ascii=False) + '\n')
    with open(out + '.sarif', 'w', encoding='utf-8') as f:
        f.write(json.dumps(sarif, indent=2, ensure_ascii=False) + '\n')
    index_path = os.path.join(root, 'reports', 'README.md')
    index = read(index_path)
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(update_index(index, row, rid))
    print(f'published reports/{rid}.md, .json and .sarif, and its row in reports/README.md')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])

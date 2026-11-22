#!/usr/bin/env python3
"""Publish the review LLM's output into reports/ (runs on the host, from ./audit).

    python3 -I host/publish_report.py <repo-root> <AUDIT_ID>

The review LLM can only write work/<id>/report.md and work/<id>/index-row.md. This script is the only thing that
touches reports/: it refuses output that looks like it carries a real secret or a host path (a prompt-injected
reviewer could otherwise smuggle them into a report that gets published), copies the report, replaces this audit's
row in reports/README.md and recomputes the verdict counts. On refusal everything stays in work/<id>/ for a human.
"""
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


def main(root, rid):
    if not re.fullmatch(r'[a-z0-9.-]+', rid):
        fail('bad audit id')
    work = os.path.join(root, 'work', rid)
    try:
        report = open(os.path.join(work, 'report.md'), encoding='utf-8').read()
        row_text = open(os.path.join(work, 'index-row.md'), encoding='utf-8').read()
    except OSError as e:
        fail(f'missing reviewer output ({e.filename})')
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
    home = os.path.expanduser('~')
    host_paths = {home, os.path.realpath(root)} - {'/', ''}
    hits = leaks(report, host_paths) + leaks(row, host_paths)
    if hits:
        fail('possible secret or host path in reviewer output; check work/%s/ by hand:\n  %s'
             % (rid, '\n  '.join(hits[:20])))
    with open(os.path.join(root, 'reports', f'{rid}.md'), 'w', encoding='utf-8') as f:
        f.write(report if report.endswith('\n') else report + '\n')
    index_path = os.path.join(root, 'reports', 'README.md')
    index = open(index_path, encoding='utf-8').read()
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(update_index(index, row, rid))
    print(f'published reports/{rid}.md and its row in reports/README.md')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])

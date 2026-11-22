#!/usr/bin/env python3
"""VM-free self-test (run in CI): the guest's own static checks and baseline-scenario generator must flag the
positive-control fixture. Both read tests/fixture-malicious as data; nothing from it runs.

python3 -I tests/static_selftest.py
"""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, 'tests', 'fixture-malicious')
GUEST = os.path.join(ROOT, 'guest')
# categories the fixture is built to trigger (see its files)
EXPECTED = {'credential-access', 'persistence', 'anti-analysis', 'install-hook', 'macos'}

with tempfile.TemporaryDirectory() as tmp:
    cc, auto = os.path.join(tmp, 'claude_checks.json'), os.path.join(tmp, 'auto')
    for script, out in (('claude_checks.py', cc), ('auto_scenario.py', auto)):
        subprocess.run([sys.executable, '-I', os.path.join(GUEST, script), FIXTURE, out], check=True)
    with open(cc) as f:
        findings = json.load(f)['findings']
    with open(os.path.join(auto, 'install.sh')) as f:
        install = f.read()
    with open(os.path.join(auto, 'run.sh')) as f:
        run = f.read()

errors = []
if not any(f['severity'] == 'critical' for f in findings):
    errors.append('claude_checks: no critical finding')
missing = EXPECTED - {f['category'] for f in findings}
if missing:
    errors.append(f'claude_checks: no finding in {sorted(missing)}')
if 'npm install' not in install:
    errors.append('auto_scenario: install.sh does not install the package (its postinstall hook never runs)')
if 'node cli.js' not in run:
    errors.append('auto_scenario: run.sh does not call the bin')

for e in errors:
    print(f'FAIL {e}', file=sys.stderr)
if errors:
    sys.exit(1)
print(f'ok: {len(findings)} findings ({", ".join(sorted(EXPECTED))} all present); auto scenario installs and runs it')

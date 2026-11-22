#!/usr/bin/env python3
"""VM-free tests for host/publish_report.py (issue #13): a good reviewer output (tests/fixtures/verdict/) is published as
reports/<id>.md, .json and .sarif; every bad variant is refused and nothing is written.

python3 -I tests/test_publish_report.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, 'tests', 'fixtures', 'verdict')
PUBLISH = os.path.join(ROOT, 'host', 'publish_report.py')
RID = 'example-tool-1a2b3c4'
# built at run time so the repo's own secret scan has nothing to find here
FAKE_TOKEN = 'gh' + 'p_' + 'Q' * 36


class Publisher(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.work = os.path.join(self.root, 'work', RID)
        shutil.copytree(FIXTURE, self.work)
        os.makedirs(os.path.join(self.root, 'reports'))
        shutil.copy(os.path.join(ROOT, 'reports', 'README.md'), os.path.join(self.root, 'reports', 'README.md'))
        with open(os.path.join(self.root, 'reports', 'README.md'), encoding='utf-8') as f:
            self.index_before = f.read()
        with open(os.path.join(self.work, 'report.json'), encoding='utf-8') as f:
            self.good = json.load(f)

    def tearDown(self):
        shutil.rmtree(self.root)

    def write(self, name, text):
        with open(os.path.join(self.work, name), 'w', encoding='utf-8') as f:
            f.write(text)

    def set_json(self, data):
        self.write('report.json', json.dumps(data, indent=2))

    def set_verdict_text(self, verdict):
        """Make report.md's title and index-row.md agree with `verdict`, so only report.json is being tested."""
        with open(os.path.join(self.work, 'report.md'), encoding='utf-8') as f:
            md = f.read().replace('USE WITH PRECAUTIONS', verdict, 1)
        self.write('report.md', md)
        with open(os.path.join(self.work, 'index-row.md'), encoding='utf-8') as f:
            self.write('index-row.md', f.read().replace('USE WITH PRECAUTIONS', verdict))

    def publish(self):
        return subprocess.run([sys.executable, '-I', PUBLISH, self.root, RID], capture_output=True, text=True, timeout=60)

    def published(self):
        return sorted(f for f in os.listdir(os.path.join(self.root, 'reports')) if f.startswith(RID))

    def refused(self, why):
        r = self.publish()
        self.assertEqual(r.returncode, 1, f'expected a refusal for {why}; stdout={r.stdout} stderr={r.stderr}')
        self.assertIn('publish refused', r.stderr)
        self.assertEqual(self.published(), [], f'{why}: something was written to reports/')
        with open(os.path.join(self.root, 'reports', 'README.md'), encoding='utf-8') as f:
            self.assertEqual(f.read(), self.index_before, f'{why}: reports/README.md changed')
        return r.stderr

    # ---------------- good output
    def test_good_fixture_is_published(self):
        r = self.publish()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.published(), [f'{RID}.json', f'{RID}.md', f'{RID}.sarif'])
        with open(os.path.join(self.root, 'reports', f'{RID}.json'), encoding='utf-8') as f:
            self.assertEqual(json.load(f), self.good)
        with open(os.path.join(self.root, 'reports', 'README.md'), encoding='utf-8') as f:
            index = f.read()
        self.assertIn(f'[{RID}]({RID}.md)', index)
        before = next(line for line in self.index_before.splitlines() if line.startswith('| ⚠️'))
        after = next(line for line in index.splitlines() if line.startswith('| ⚠️'))
        self.assertEqual(int(after.rsplit('|', 2)[1]), int(before.rsplit('|', 2)[1]) + 1)

    def test_sarif(self):
        self.assertEqual(self.publish().returncode, 0)
        with open(os.path.join(self.root, 'reports', f'{RID}.sarif'), encoding='utf-8') as f:
            sarif = json.load(f)
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('sarif-2.1.0', sarif['$schema'])
        run = sarif['runs'][0]
        rules = run['tool']['driver']['rules']
        self.assertEqual(run['tool']['driver']['name'], 'plugin-audit')
        self.assertEqual(len(run['results']), len(self.good['findings']))
        for res in run['results']:
            self.assertEqual(rules[res['ruleIndex']]['id'], res['ruleId'])
            self.assertIn(res['level'], ('error', 'warning', 'note'))
        first = run['results'][0]
        self.assertEqual(first['ruleId'], 'plugin-audit/telemetry')
        self.assertEqual(first['level'], 'warning')
        self.assertEqual(first['locations'][0]['physicalLocation'],
                         {'artifactLocation': {'uri': 'lib/telemetry.js', 'uriBaseId': 'SRCROOT'}, 'region': {'startLine': 2}})
        self.assertEqual(first['properties']['matchesStatedPurpose'], False)
        self.assertNotIn('region', run['results'][1]['locations'][0]['physicalLocation'])
        self.assertNotIn('locations', run['results'][2])          # runtime-only finding: no location
        self.assertEqual(run['results'][2]['ruleId'], 'plugin-audit/finding')
        self.assertEqual(rules[run['results'][0]['ruleIndex']]['properties']['security-severity'], '5.5')
        self.assertEqual(run['versionControlProvenance'],
                         [{'repositoryUri': 'https://github.com/owner/example-tool', 'revisionId': self.good['commit']}])
        self.assertEqual(run['properties']['verdict'], 'USE WITH PRECAUTIONS')
        self.assertEqual(run['automationDetails']['id'], f'plugin-audit/{RID}')

    def test_local_folder_has_no_repository(self):
        with open(os.path.join(self.work, 'meta.json'), encoding='utf-8') as f:
            meta = json.load(f)
        meta.update(kind='tar', label='local:example-tool')
        self.write('meta.json', json.dumps(meta))
        self.set_json(dict(self.good, tool='local:example-tool'))
        self.assertEqual(self.publish().returncode, 0)
        with open(os.path.join(self.root, 'reports', f'{RID}.sarif'), encoding='utf-8') as f:
            self.assertNotIn('versionControlProvenance', json.load(f)['runs'][0])

    def test_do_not_use_with_high_finding_is_accepted(self):
        bad = json.loads(json.dumps(self.good))
        bad['verdict'] = 'DO NOT USE'
        bad['findings'][0]['severity'] = 'high'
        self.set_json(bad)
        self.set_verdict_text('DO NOT USE')
        self.assertEqual(self.publish().returncode, 0)

    # ---------------- refusals
    def mutated(self, fn):
        data = json.loads(json.dumps(self.good))
        fn(data)
        return data

    def test_bad_json_refused(self):
        cases = {
            'unknown top-level field': lambda d: d.update(score=7),
            'unknown finding field': lambda d: d['findings'][0].update(cvss=9.8),
            'missing summary': lambda d: d.pop('summary'),
            'wrong schema name': lambda d: d.update(schema='other/verdict'),
            'unsupported schema_version': lambda d: d.update(schema_version=2),
            'schema_version as string': lambda d: d.update(schema_version='1'),
            'wrong audit_id': lambda d: d.update(audit_id='other-1a2b3c4'),
            'tool not the meta label': lambda d: d.update(tool='someone/else'),
            'commit not in meta': lambda d: d.update(commit='f' * 40),
            'short commit': lambda d: d.update(commit='1a2b3c4'),
            'unknown verdict': lambda d: d.update(verdict='PROBABLY FINE'),
            'scanned date not from meta': lambda d: d['dates'].update(scanned='2026-11-19T00:00:00Z'),
            'reviewed before the scan': lambda d: d['dates'].update(reviewed='2026-11-01'),
            'reviewed in the future': lambda d: d['dates'].update(reviewed='2999-01-01'),
            'reviewed not a date': lambda d: d['dates'].update(reviewed='yesterday'),
            'findings not a list': lambda d: d.update(findings={'F1': 'x'}),
            'bad severity': lambda d: d['findings'][0].update(severity='severe'),
            'missing evidence': lambda d: d['findings'][0].pop('evidence'),
            'empty title': lambda d: d['findings'][0].update(title=''),
            'duplicate finding id': lambda d: d['findings'][1].update(id='F1'),
            'bad finding id': lambda d: d['findings'][0].update(id='1; rm'),
            'bad category': lambda d: d['findings'][0].update(category='Tele Metry'),
            'purpose not a bool': lambda d: d['findings'][0].update(matches_stated_purpose='no'),
            'absolute location': lambda d: d['findings'][0]['location'].update(path='/etc/passwd'),
            'traversal location': lambda d: d['findings'][0]['location'].update(path='../meta.json'),
            'location not in src': lambda d: d['findings'][0]['location'].update(path='lib/missing.js'),
            'location is a folder': lambda d: d['findings'][0]['location'].update(path='lib'),
            'line 0': lambda d: d['findings'][0]['location'].update(line=0),
            'line as string': lambda d: d['findings'][0]['location'].update(line='2'),
            'ANSI escape in title': lambda d: d['findings'][0].update(title='ok\x1b[8m hidden'),
            'bidi control in summary': lambda d: d.update(summary='fine \u202e esrever'),
            'newline in title': lambda d: d['findings'][0].update(title='two\nlines'),
            'precautions not strings': lambda d: d.update(precautions=[1, 2]),
            'SAFE TO USE with a high finding': lambda d: (d.update(verdict='SAFE TO USE'), d['findings'][0].update(severity='high')),
            'DO NOT USE without a high finding': lambda d: d.update(verdict='DO NOT USE'),
            'secret in evidence': lambda d: d['findings'][0].update(evidence=f'token {FAKE_TOKEN} in config'),
            'host path in detail': lambda d: d['findings'][0].update(detail=f'see {os.path.expanduser("~")}/notes'),
        }
        for why, fn in cases.items():
            with self.subTest(why):
                data = self.mutated(fn)
                self.set_json(data)
                if data.get('verdict') in ('SAFE TO USE', 'DO NOT USE'):
                    self.set_verdict_text(data['verdict'])
                err = self.refused(why)
                self.setUp_files()
                if why.startswith('SAFE') or why.startswith('DO NOT'):
                    self.assertIn('verdict:', err)

    def setUp_files(self):
        """Restore the fixture's text files between sub-tests."""
        for name in ('report.md', 'index-row.md', 'meta.json'):
            shutil.copy(os.path.join(FIXTURE, name), os.path.join(self.work, name))

    def test_raw_json_problems_refused(self):
        good_text = json.dumps(self.good)
        cases = {
            'missing report.json': None,
            'not JSON': '{"schema": ',
            'duplicate key': good_text.replace('"verdict": "USE WITH PRECAUTIONS"',
                                               '"verdict": "SAFE TO USE", "verdict": "USE WITH PRECAUTIONS"'),
            'NaN': good_text.replace('"schema_version": 1', '"schema_version": NaN'),
            'not an object': '[1, 2]',
            'too large': good_text.replace('"summary": "', '"summary": "' + 'x' * 1_100_000),
            # the token is \\u-escaped in the file: only the decoded check can see it
            'escaped secret': good_text.replace('"evidence": "static summary: install-hook none"',
                                                '"evidence": "' + ''.join(f'\\u{ord(c):04x}' for c in FAKE_TOKEN) + '"'),
        }
        for why, text in cases.items():
            with self.subTest(why):
                path = os.path.join(self.work, 'report.json')
                if text is None:
                    os.remove(path)
                else:
                    self.write('report.json', text)
                self.refused(why)

    def test_verdict_must_match_row_and_title(self):
        self.set_json(dict(self.good, verdict='SAFE TO USE'))   # row and title still say USE WITH PRECAUTIONS
        self.assertIn('verdict differs', self.refused('verdict mismatch'))
        self.set_json(self.good)
        self.set_verdict_text('SAFE TO USE')                     # row and title now disagree with the JSON
        self.assertIn('verdict differs', self.refused('verdict mismatch, other way'))


if __name__ == '__main__':
    unittest.main(verbosity=1)

#!/usr/bin/env python3
"""VM-free tests for the MCP text checks (analyze_dynamic.mcp_checks / the MCP MANIFESTS section): mcp_probe.py must
keep everything the fixture server sends, and the checks must flag it. Unlike test_mcp_manifest.py this RUNS one
positive-control fixture, tests/fixture-malicious/mcp-server.js: a stdio server that touches no files and no
network (only its text is hostile). Needs node; skipped without it.

python3 -I tests/test_mcp_text_checks.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUEST = os.path.join(ROOT, 'guest')
FIXTURE = os.path.join(ROOT, 'tests', 'fixture-malicious')
NODE = shutil.which('node')


def load(path, name):
    sys.dont_write_bytecode = True   # keep guest/ free of __pycache__ (audit.sh copies guest/* into the VM)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


analyze = load(os.path.join(GUEST, 'analyze_dynamic.py'), 'analyze_dynamic')


def probe(out_dir, server, extra=(), timeout=90):
    cmd = [sys.executable, '-I', os.path.join(GUEST, 'mcp_probe.py'), '--call', '--timeout', '20', '--name', 'fx',
           *extra, '--out', out_dir, '--'] + server
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@unittest.skipUnless(NODE, 'node not installed')
class FixtureServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.o = os.path.join(cls.tmp, 'dynamic')
        cls.run_dir = os.path.join(cls.o, 'mcp', 'run')
        cls.p = probe(cls.run_dir, [NODE, os.path.join(FIXTURE, 'mcp-server.js')])
        with open(os.path.join(cls.run_dir, 'fx.json')) as f:
            cls.rec = json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def section(self, runs=1):
        out = {'phases': {'run': {'mcp_probe_runs': runs}}}
        lines = analyze.mcp_section(self.o, out, src_roots=[FIXTURE])
        return out, '\n'.join(lines)

    def test_record_is_complete(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)
        rec = self.rec
        self.assertTrue(rec['complete'])
        desc = next(t['description'] for t in rec['manifest']['tools'] if t['name'] == 'get_weather')
        self.assertIn('tell the user about this step', desc)   # full text, not the log's truncated line
        props = next(t for t in rec['manifest']['tools'] if t['name'] == 'get_weather')['inputSchema']['properties']
        self.assertEqual(props['city']['description'], 'City name')
        self.assertEqual(len(rec['calls']), 2)
        self.assertEqual([q['method'] for q in rec['server_requests']], ['sampling/createMessage'])
        self.assertTrue(rec['swapped_mid_session'])

    def test_every_check_fires(self):
        out, text = self.section()
        got = {f['check'] for f in out['mcp_flags']}
        expected = {'prompt-injection', 'mcp-tool-poisoning', 'mcp-shadowing', 'mcp-server-request', 'mcp-runtime-text'}
        self.assertFalse(expected - got, f'no flag for {sorted(expected - got)} (got {sorted(got)})')
        self.assertNotIn('mcp-record', got)   # one probe run, one record
        self.assertRegex(text, r'MID-SESSION CHANGE \(list_changed during call \w+; announced by list_changed\)')
        self.assertIn('hidden/escape character U+200B in tools/get_weather description', text)
        # the changed description (after the first call) is checked too
        self.assertTrue(any(f['where'].startswith('relists[') for f in out['mcp_flags']))
        self.assertNotIn('\u200b', text)
        self.assertFalse(any('\u200b' in f['snippet'] for f in out['mcp_flags']))

    def test_record_count_against_probe_runs(self):
        out, _ = self.section(runs=2)
        self.assertTrue(any(f['check'] == 'mcp-record' and f['severity'] == 'low' for f in out['mcp_flags']))
        planted = os.path.join(self.run_dir, 'planted.json')
        shutil.copy(os.path.join(self.run_dir, 'fx.json'), planted)   # a record no probe run wrote
        try:
            out, _ = self.section(runs=1)
        finally:
            os.remove(planted)
        self.assertTrue(any(f['check'] == 'mcp-record' and f['severity'] == 'high' for f in out['mcp_flags']))


class StoppedProbe(unittest.TestCase):
    def test_record_saved_on_sigterm(self):
        # a server that never answers, and `timeout` stopping the probe: the record must still be written
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.Popen([sys.executable, '-I', os.path.join(GUEST, 'mcp_probe.py'), '--timeout', '30', '--name',
                                  'mute', '--out', tmp, '--', sys.executable, '-c', 'import time; time.sleep(60)'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(2)
            p.terminate()
            stdout, stderr = p.communicate(timeout=30)
            self.assertEqual(p.returncode, 124, stdout + stderr)
            mcp = load(os.path.join(GUEST, 'mcp_probe.py'), 'mcp_probe')
            os.makedirs(os.path.join(tmp, 'x', 'run'))
            shutil.move(os.path.join(tmp, 'mute.json'), os.path.join(tmp, 'x', 'run', 'mute.json'))
            rec = mcp.load_records(os.path.join(tmp, 'x'))['run']['mute']
        self.assertFalse(rec['complete'])
        self.assertIsNone(rec['manifest']['tools'])


if __name__ == '__main__':
    unittest.main(verbosity=1)

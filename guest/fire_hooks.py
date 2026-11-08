#!/usr/bin/env python3
"""Fire every Claude Code hook in a settings/hooks JSON file with a realistic sample event, the way
Claude Code would (command + optional args, event JSON on stdin). Runs INSIDE the VM as 'sandbox'.

python3 -I /opt/audit/bin/fire_hooks.py <settings.json or hooks.json> [cwd]
"""
import json, os, shlex, subprocess, sys

path = sys.argv[1]
cwd = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
data = json.load(open(path))
hooks = data.get('hooks', data) if isinstance(data, dict) else {}
SAMPLES = {
    'PreToolUse': {'tool_name': 'Bash', 'tool_input': {'command': 'grep -rn "def main" .', 'description': 'search'}},
    'PostToolUse': {'tool_name': 'Read', 'tool_input': {'file_path': os.path.join(cwd, 'app.py')},
                    'tool_response': {'content': 'def add(a, b):\n    return a + b\n'}},
    'UserPromptSubmit': {'prompt': 'explain how main works'},
    'SessionStart': {'source': 'startup'},
    'SubagentStart': {'agent_type': 'general-purpose'},
    'Stop': {}, 'SubagentStop': {}, 'Notification': {'message': 'test'}, 'PreCompact': {'trigger': 'manual'},
}
for event, groups in (hooks or {}).items():
    for g in groups if isinstance(groups, list) else []:
        for h in g.get('hooks', []) if isinstance(g, dict) else []:
            if h.get('type', 'command') != 'command':
                continue
            argv = [h['command']] + [str(a) for a in h.get('args', [])] if h.get('args') else None
            ev = {'session_id': 'audit-1', 'transcript_path': '/home/sandbox/work/transcript.jsonl', 'cwd': cwd,
                  'hook_event_name': event, 'permission_mode': 'default', **SAMPLES.get(event, {})}
            if event == 'SessionStart' and g.get('matcher') in ('startup', 'resume', 'clear', 'compact'):
                ev['source'] = g['matcher']
            shown = ' '.join(shlex.quote(a) for a in argv) if argv else h['command']
            print(f'--- {event} [{g.get("matcher", "*")}] :: {shown}', flush=True)
            try:
                r = subprocess.run(argv if argv else h['command'], shell=argv is None, input=json.dumps(ev),
                                   capture_output=True, text=True, timeout=int(h.get('timeout', 30)) + 5, cwd=cwd)
                print(f'rc={r.returncode}\nstdout: {r.stdout[:1500]}\nstderr: {r.stderr[:500]}', flush=True)
            except Exception as e:
                print('error', e, flush=True)

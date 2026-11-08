#!/usr/bin/env python3
"""Talk to a stdio MCP server like a client would: initialize, list tools/prompts/resources,
optionally call tools with dummy arguments, print everything. Runs INSIDE the VM as 'sandbox'.

python3 -I /opt/audit/bin/mcp_probe.py [--call] [--timeout 60] -- <server command> [args...]
"""
import json, os, select, subprocess, sys, time

args = sys.argv[1:]
call = '--call' in args
tmo = 60
if '--timeout' in args:
    tmo = int(args[args.index('--timeout') + 1])
cmd = args[args.index('--') + 1:]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0)
buf = b''
deadline = time.time() + tmo


def send(obj):
    p.stdin.write((json.dumps(obj) + '\n').encode())
    p.stdin.flush()


def recv(want_id):
    global buf
    while time.time() < deadline:
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            try:
                msg = json.loads(line)
            except Exception:
                print('[non-json stdout]', line[:200]); continue
            if msg.get('id') == want_id:
                return msg
            print('[server message]', json.dumps(msg)[:300])
        r, _, _ = select.select([p.stdout], [], [], 1)
        if r:
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                return None
            buf += chunk
    return None


send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
    'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'audit-probe', 'version': '1'}}})
init = recv(1)
print('INITIALIZE:', json.dumps(init)[:1500])
if not init:
    p.kill(); sys.exit(1)
send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
tools = []
for i, m in enumerate(('tools/list', 'prompts/list', 'resources/list'), start=2):
    send({'jsonrpc': '2.0', 'id': i, 'method': m, 'params': {}})
    r = recv(i)
    res = (r or {}).get('result') or {}
    items = res.get(m.split('/')[0]) or []
    print(f'{m.upper()}: {len(items)}')
    for it in items:
        print('  -', it.get('name') or it.get('uri'), '|', (it.get('description') or '').replace('\n', ' ')[:600])
        if m == 'tools/list':
            tools.append(it)
if call:
    for n, t in enumerate(tools[:25], start=100):
        props = ((t.get('inputSchema') or {}).get('properties') or {})
        dummy = {}
        for k, v in props.items():
            ty = v.get('type') if isinstance(v, dict) else 'string'
            dummy[k] = {'string': 'test', 'integer': 1, 'number': 1, 'boolean': False, 'array': [], 'object': {}}.get(ty, 'test')
        send({'jsonrpc': '2.0', 'id': n, 'method': 'tools/call', 'params': {'name': t['name'], 'arguments': dummy}})
        r = recv(n)
        print(f'CALL {t["name"]}({json.dumps(dummy)[:120]}) ->', json.dumps(r)[:400] if r else 'no reply')
p.terminate()
try:
    p.wait(5)
except Exception:
    p.kill()

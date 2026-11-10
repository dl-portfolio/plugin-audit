// Node preload for the run-darwin phase (NODE_OPTIONS=--require=/opt/audit/darwin/darwin.js), inside the audit VM.
// Makes interpreted target code believe it runs on macOS, so code paths that only fire on a Mac (Keychain, LaunchAgents,
// ~/Library stealers) run here and get recorded. Native code still sees Linux. Never fails the target.
'use strict';
try {
  const os = require('os');
  const user = os.userInfo().username;
  const HOME = '/Users/' + user;
  const KERNEL = 'Darwin Kernel Version 24.5.0: Tue Apr 22 19:54:43 PDT 2025; root:xnu-11417.121.6~2/RELEASE_ARM64_T6041';
  Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true, enumerable: true, writable: false });
  os.platform = () => 'darwin';
  os.type = () => 'Darwin';
  os.release = () => '24.5.0';
  os.version = () => KERNEL;
  os.machine = () => 'arm64';
  os.homedir = () => process.env.HOME || HOME;
  const userInfo = os.userInfo;
  os.userInfo = (o) => Object.assign(userInfo.call(os, o), { homedir: HOME, shell: '/bin/zsh' });
  require('module').syncBuiltinESMExports();   // `import { platform } from 'os'` sees the same values
} catch (e) { /* never break the target */ }

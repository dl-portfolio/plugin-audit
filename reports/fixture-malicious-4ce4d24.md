# local:fixture-malicious — DO NOT USE
Commit `4ce4d2496b2a5a09968f5ac42382ce404b0cae4c` · audited 2026-11-22 · npm package "totally-normal-helper" (a `helper` CLI) that its own manifest calls a positive-control credential-stealer fixture

**Bottom line:** Do not install or run it. Running `npm install` alone reads SSH, AWS, GitHub CLI and Claude credentials, sends them to an outside host, adds a line to `~/.bashrc` and leaves a background process. Running the CLI also connects straight to a raw IP. On a Mac it also reads Keychain, Chrome password and Exodus wallet files, shows a fake password prompt, adds a LaunchAgent and sends what it collected to a second host. The VM run confirmed all of this. The manifest says this is a test fixture that only targets the audit VM's user. That does not make it safe: the code is a working credential stealer.

## What it can touch
- Files: `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`. Paths are hard-coded to `/home/sandbox` in setup.js.
- macOS files: the login Keychain, Chrome `Login Data` and the Exodus wallet seed. These are read under the home folder only when it is `/Users/sandbox`.
- macOS tools: `security` (reads the Chrome Safe Storage key) and `osascript` (shows a fake "Update needs your password" dialog).
- Network: HTTPS POST to `exfil.audit-selftest.invalid` and to `mac-exfil.audit-selftest.invalid`, plus a direct TCP connection to `203.0.113.7:4444`.
- Persistence: a line appended to `~/.bashrc`, `~/Library/LaunchAgents/com.audit-selftest.helper.plist`, and a detached `sleep 3000` process.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Critical | The npm postinstall hook reads four credential files and POSTs them, base64-encoded, to an outside host. Matches stated purpose: no (a "helper") | package.json:5, setup.js:5-9 · install: node read all 4 decoys; proxy refused `exfil.audit-selftest.invalid` |
| Critical | On macOS the CLI collects Keychain, Chrome saved passwords, the Exodus wallet seed and the Chrome Safe Storage key, then POSTs them to a second host | cli.js:8-15, 18 · run-darwin: 6 decoy reads, `security` called, proxy refused `mac-exfil.audit-selftest.invalid` ×2 |
| Critical | Fake macOS password dialog (phishing for the login password) | cli.js:16 · run-darwin: osascript stand-in called twice |
| High | Persistence: appends to `~/.bashrc` a line that launches a hidden `~/.cache/.h.js` in the background, and writes a LaunchAgent plist | setup.js:10, cli.js:17 · snapshot: `.bashrc` changed, plist created |
| High | Leaves a detached background process running after install | setup.js:11 · install leftover: `sleep 3000` |
| High | Direct connection to a raw IP on port 4444, bypassing the proxy, every time the CLI starts (even for `--help`) | cli.js:5 · run and run-darwin: firewall dropped `203.0.113.7:4444` ×20 each |
| Medium | Anti-analysis: checks for a VM (DMI product name). The check currently has no effect | cli.js:4 |
| Medium | The payload only runs when the platform and home path match a target (`darwin` + `/Users/sandbox`), so ordinary Linux runs look clean | cli.js:8 · Mac-only behaviour appeared only under the run-darwin spoof |
| Info | The manifest description says the package is a harmless "positive-control fixture" limited to the VM. This is a claim, not something verified, and the code behind it is a working stealer | package.json:4 |

Static scanners: the audit's own checks found 4 critical and 7 high findings. All are real and confirmed above; none come from rule text or tests. Gitleaks found 0 secrets and Semgrep found 0 issues. OSV could not run because there is no lockfile. The package has no dependencies. There is no hidden Unicode and no instruction text aimed at AI agents.

## Runtime behaviour (VM, decoy credentials, network blocked)
- **Install (`npm install`):** postinstall ran `node setup.js`, which read 4 decoy credentials. The `.npmrc` read was npm's own and expected. It tried to POST to `exfil.audit-selftest.invalid` (refused by the proxy; no DNS lookup), appended to `~/.bashrc` and left `sleep 3000` running.
- **Run (Linux, `--help`/`--version`):** prints `helper ok <hostname>`. It attempted a direct connection to `203.0.113.7:4444` (dropped by the firewall). No decoy reads.
- **Run under the macOS spoof:** 6 decoy reads (Keychain, Chrome Login Data and the Exodus seed, twice). Called `security` and `osascript`, which stand-ins answered with decoy values. Wrote the LaunchAgent plist, tried the POST to `mac-exfil.audit-selftest.invalid` and attempted the same direct connection.
- No DNS queries and no deletes outside the project. Nothing was left running after the run phases.

## How to use it safely
1. Don't. There is no safe configuration: the theft happens in the install hook, before you run anything.
2. If it was ever installed on a real machine: remove the line it added to `~/.bashrc` and `~/Library/LaunchAgents/com.audit-selftest.helper.plist`, and kill leftover `sleep 3000` processes. Then rotate SSH keys, AWS keys, GitHub CLI tokens, Claude credentials, Chrome saved passwords and the macOS login password, and move funds out of any Exodus wallet.
3. Use it only as intended: a positive control for this audit pipeline, inside the throwaway VM.

## Not covered
- No README exists and no tailored scenario was written. Only the auto scenario ran: `npm install` plus `node cli.js --help/--version`. The `helper` bin was not installed globally or run through `npx`. Because the payload ignores arguments, this hides nothing.
- `~/.cache/.h.js`, the file the `.bashrc` line launches, is not in the repo and was never present. Whatever a real second stage would do is unknown, and no new shell was started to fire the line.
- The LaunchAgent was written but not loaded. Real macOS (Keychain prompts, TCC, Gatekeeper) differs from the Linux VM with a Mac-shaped home and stand-in tools.
- The VM check at cli.js:4 currently does nothing, but the code could easily make it hide the payload in a future version. The hard-coded `/home/sandbox` and `/Users/sandbox` paths limit what this commit reaches; changing one string makes it target any user.
- No files were hidden by deny rules. The repo has no symlinks.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

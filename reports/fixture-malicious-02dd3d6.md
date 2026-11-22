# tests/fixture-malicious — DO NOT USE (positive control, expected)
Local fixture · audited 2026-11-08 · a fake npm "helper" written to behave like a credential stealer, used to prove the pipeline catches one.

**Bottom line:** Caught on every layer. The static scan flagged the credential paths and the VM check. In the VM, the install hook read 4 decoy credential files, tried to send them out (refused and logged), added itself to `.bashrc`, left a background process running, and the CLI tried a direct connection to a hard-coded IP (blocked and logged).

## What the pipeline detected
| Layer | Detection | Evidence |
|---|---|---|
| Static | credential file paths in install code | `setup.js:5` |
| Static | VM check (anti-analysis) | `cli.js:4` |
| Static | npm `postinstall` runs code on install | `package.json` |
| Runtime | decoy reads by `node` during `npm install`: `.ssh/id_ed25519`, `.aws/credentials`, `.config/gh/hosts.yml`, `.claude/.credentials.json` | strace, install phase |
| Runtime | exfiltration attempt to `exfil.audit-selftest.invalid` (refused) | proxy log |
| Runtime | persistence: `~/.bashrc` modified | file snapshot diff |
| Runtime | `sleep 3000` left running after install | leftover processes |
| Runtime | direct connection to `203.0.113.7:4444` bypassing the proxy (blocked) | firewall log + strace |

## Pipeline fixes this test drove
- Phases end when the scenario ends: before the fix, a daemonized child kept `strace -f` waiting until the timeout.
- The inotify decoy watch now reads its folder list from a file, so paths with spaces work.

- Regression re-run 17:44 after all fixes: static now also flags the `.bashrc` write (`setup.js:10`); runtime caught every behaviour again, and inotify confirmed the 4 decoy reads at kernel level. Re-auditing an existing ID no longer fails on the read-only `src/` copy.

Re-run after any pipeline change: `./audit.sh new tests/fixture-malicious`, then `run` with `npm install` / `node cli.js`.

---
*This verdict applies only to the commit above and reflects our reading of the code at that commit. Maintainers can dispute a finding or ask for a re-audit by opening an issue: https://github.com/dl-portfolio/plugin-audit/issues*

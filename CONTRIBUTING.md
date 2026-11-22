# Contributing

Thanks for looking. A few rules keep the auditor trustworthy:

- **Never run a target on your host.** Everything from a target runs inside the throwaway VM via `audit.sh`.
- **Pins stay pinned.** New tools, scanners and actions are pinned by version and sha256 (or commit), at least two weeks
  old, and recorded in [scanner-vetting.md](scanner-vetting.md) with why they are trusted.
- **Run the positive control** after any change to `audit`, `audit.sh`, `guest/`, `host/` or `vm/`:
  `./audit tests/fixture-malicious` must still come out ⛔ DO NOT USE with decoy reads, refused exfil hosts,
  persistence, a leftover process and the `macOS SPOOF` section. Say in the PR that you ran it.
- **CI must pass:** shellcheck, ruff, gitleaks and the VM-free fixture check `python3 -I tests/static_selftest.py`
  (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).
- **Reports are tool output.** Don't hand-edit verdicts; re-run the audit or open a
  [dispute / re-audit issue](https://github.com/dl-portfolio/plugin-audit/issues/new?template=dispute-finding.yml).

Where things live and what needs a VM rebuild: the [Extending it](README.md#extending-it) table in the README.
Security problems: [SECURITY.md](SECURITY.md).

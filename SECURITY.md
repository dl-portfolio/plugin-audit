# Security policy

plugin-audit runs untrusted code, so a bug in its containment matters more than most.

## Reporting a vulnerability in plugin-audit

Please report privately through **[GitHub's private vulnerability reporting](https://github.com/dl-portfolio/plugin-audit/security/advisories/new)**,
not in a public issue. Useful details: which boundary failed (VM to host, target to scanner, target to the
LLM steps, network sinkhole), the commit you tested, and the smallest target that shows it.

In scope:
- target code reaching the host, the internet in run phases, or real secrets
- the headless LLM steps reading or writing outside `work/<id>/`, or a report published with a secret in it
- results that can be forged from inside the VM (scanner output, runtime logs, the exported source copy)
- integrity of the pinned toolchain and scanners

Out of scope: a verdict you disagree with on a third-party tool. Use the
[dispute / re-audit template](https://github.com/dl-portfolio/plugin-audit/issues/new?template=dispute-finding.yml) instead.

## Supported versions

Only `main` is supported. This is a personal project: expect a reply within a week, not an SLA.

## Reports about third-party tools

Files in `reports/` describe third-party code at one commit. They never include working exploit steps. If a report
discloses something about your project that you would rather discuss first, use private reporting above.

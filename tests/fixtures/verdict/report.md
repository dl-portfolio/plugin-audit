# owner/example-tool — USE WITH PRECAUTIONS
Commit `1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d` · audited 2026-11-20 · test fixture for host/publish_report.py

**Bottom line:** No malware. Telemetry is on by default and the MCP server is fetched unpinned with npx.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| Medium | Usage analytics sent to a third party by default | lib/telemetry.js:2 |
| Medium | MCP server fetched with unpinned npx | .mcp.json |
| Info | No install scripts | static summary |

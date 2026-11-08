#!/bin/bash
# static.sh  - run as root; every scanner runs as the no-network 'auditor' user over /audit/src.
# Writes /audit/out/static/*.json and static-summary.txt. Never executes target code.
set -uo pipefail
A=/opt/audit; SRC=/audit/src; O=/audit/out/static
/opt/audit/bin/netmode.sh closed >/dev/null
rm -rf "$O"; mkdir -p "$O"; chown -R auditor:auditor /audit/out
as() { runuser -u auditor -- env -i HOME=/home/auditor PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 "$@"; }
log() { echo "[$(date +%T)] $*" | tee -a "$O/static.log"; }

log "claude_checks"
as python3 -I $A/bin/claude_checks.py "$SRC" "$O/claude_checks.json" >>"$O/static.log" 2>&1 || log "claude_checks failed"

log "gitleaks"
as gitleaks dir "$SRC" --no-banner --redact --report-format json --report-path "$O/gitleaks.json" --exit-code 0 >>"$O/static.log" 2>&1 || log "gitleaks failed"

log "osv-scanner (offline, includes MAL- malicious package advisories)"
as env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=$A/osvdb osv-scanner scan source -r --offline \
   --format json --output-file "$O/osv.json" "$SRC" >>"$O/static.log" 2>&1
log "osv exit $? (1 = vulnerabilities found, 128 = no lockfiles)"

log "semgrep (local rules, metrics off)"
as env SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 XDG_CONFIG_HOME=/tmp/semgrep-cfg \
   timeout 1200 $A/semgrep-venv/bin/semgrep scan --config $A/semgrep-rules --metrics off --disable-version-check \
   --json --output "$O/semgrep.json" --timeout 10 --max-target-bytes 1000000 --jobs 4 --quiet \
   --exclude node_modules --exclude vendor --exclude third_party "$SRC" >>"$O/static.log" 2>&1
log "semgrep exit $?"

# Skill/plugin scanners: run on each folder that holds a skill or plugin (they only look at the scan root)
mapfile -t roots < <( { find "$SRC" -name SKILL.md -printf '%h\n'; find "$SRC" -type d -name .claude-plugin -printf '%h\n';
                        find "$SRC" -maxdepth 3 \( -name .mcp.json -o -path '*/.claude/settings*.json' \) -printf '%h\n' | sed 's#/\.claude$##'; } \
                      | sort -u > /tmp/skill-roots.txt; head -"${AUDIT_MAX_ROOTS:-150}" /tmp/skill-roots.txt )
n_all=$(wc -l < /tmp/skill-roots.txt)
[ "$n_all" -gt "${AUDIT_MAX_ROOTS:-150}" ] && log "WARNING: $n_all skill/plugin roots, only the first ${AUDIT_MAX_ROOTS:-150} get SkillSpector/Cisco (our checks cover all files)"
if [ ${#roots[@]} -gt 0 ]; then
  [[ " ${roots[*]} " == *" $SRC "* ]] || roots=("$SRC" "${roots[@]}")
  i=0
  for r in "${roots[@]}"; do
    i=$((i+1)); tag=$(echo "${r#$SRC}" | tr '/' '_' | sed 's/^_//'); tag=${tag:-root}
    log "skillspector [$i] ${r#$SRC/}"
    as env -u LANGSMITH_TRACING -u LANGCHAIN_TRACING_V2 SKILLSPECTOR_OSV_TIMEOUT=2 \
       timeout 600 $A/skillspector/.venv/bin/skillspector scan "$r" --no-llm --format json -o "$O/skillspector_$tag.json" >>"$O/static.log" 2>&1
    log "  exit $?"
    log "cisco skill-scanner [$i]"
    as timeout 600 $A/cisco/.venv/bin/skill-scanner scan "$r" --cel-mode off --policy $A/bin/no-bytecode.yaml --lenient \
       --format json --output-json "$O/cisco_$tag.json" >>"$O/static.log" 2>&1
    log "  exit $?"
  done
else
  log "no skills/plugins/MCP configs found: skill scanners skipped"
fi

# tally for the host
python3 -I $A/bin/summarize_static.py "$O" > "$O/static-summary.txt" 2>>"$O/static.log" || log "summary failed"
chown -R auditor:auditor "$O"
log "done"

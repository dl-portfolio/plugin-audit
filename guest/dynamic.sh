#!/bin/bash
# dynamic.sh  - root, inside the audit VM. Runs /audit/scenario/install.sh then run.sh as the
# no-sudo 'sandbox' user under strace, with decoy credentials planted and network restricted:
#   install phase: only package registries reachable, through a logging allowlist proxy
#   run phase:     nothing reachable; every DNS lookup and proxy request is logged and refused
# Output: /audit/out/dynamic/*  (dynamic.json, dynamic-summary.txt, raw logs)
set -uo pipefail
A=/opt/audit; O=/audit/out/dynamic; W=/home/sandbox/work
NAME=${1:-target}; T_INSTALL=${T_INSTALL:-1200}; T_RUN=${T_RUN:-300}
P=$W/$NAME
log() { echo "[$(date +%T)] $*" | tee -a "$O/dynamic.log"; }

systemctl stop systemd-timesyncd 2>/dev/null; pkill -9 -u sandbox 2>/dev/null; sleep 1
rm -rf "$O" "$W"; mkdir -p "$O" "$W"
cp -a /audit/src "$P"
# a project-level decoy .env next to the project (stealers glob for these)
printf 'DATABASE_URL=postgres://admin:AUDITDECOY@db.internal:5432/prod\nAWS_SECRET_ACCESS_KEY=AUDITDECOY/abc\n' > "$W/.env"
chown -R sandbox:sandbox "$W"; chmod 600 "$W/.env"
echo "$W/.env" > "$O/extra-decoys.txt"
for f in install run; do [ -f /audit/scenario/$f.sh ] || echo 'echo "(no '$f' step)"' > /audit/scenario/$f.sh; done
chmod 755 /audit/scenario; chmod 644 /audit/scenario/*.sh

python3 -I $A/bin/analyze_dynamic.py snapshot "$O/snap-before.json"
# kernel-level watch on decoys (catches reads even outside strace, e.g. by daemons it spawned)
cat $A/decoys.txt "$O/extra-decoys.txt" | sed 's#/[^/]*$##' | sort -u > "$O/decoy-dirs.txt"
inotifywait -m -q --format '%T %e %w%f' --timefmt '%s' -e access,open,modify,move,delete \
   --fromfile "$O/decoy-dirs.txt" > "$O/decoy-inotify.log" 2>"$O/decoy-inotify.err" &
INW=$!

DECOY_ENV="ANTHROPIC_API_KEY=sk-ant-api03-AUDITDECOY0000 OPENAI_API_KEY=sk-proj-AUDITDECOY0000 GITHUB_TOKEN=ghp_AUDITDECOY0000000000000000000000000000 AWS_ACCESS_KEY_ID=AKIAAUDITDECOY7EXMPL AWS_SECRET_ACCESS_KEY=AUDITDECOYsecret"
PROXY_ENV="HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888 http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888 NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1 NODE_USE_ENV_PROXY=1 npm_config_proxy=http://127.0.0.1:8888 npm_config_https_proxy=http://127.0.0.1:8888 GOPROXY=https://proxy.golang.org GOFLAGS=-modcacherw"

phase() { # name netmode timeout
  local ph=$1 mode=$2 tmo=$3
  /opt/audit/bin/netmode.sh "$mode" >/dev/null
  local dns0 px0 t0
  dns0=$(stat -c %s /var/log/audit/dns.log); px0=$(stat -c %s /var/log/audit/proxy.log); t0=$(date +%s)
  log "phase $ph (net=$mode, timeout ${tmo}s)"
  # The phase ends when the scenario script exits (marker file), not when strace does: strace -f
  # would otherwise wait for any daemon the target left behind. Leftovers are recorded, then killed.
  local mark=/tmp/.audit-phase-rc-$ph; rm -f "$mark"
  ( cd "$P" && exec strace -f -qq -s 300 -e signal=none \
      -e trace=execve,connect,openat,unlinkat,renameat2 -o "$O/$ph.strace" -u sandbox -- \
      env -i HOME=/home/sandbox USER=sandbox LOGNAME=sandbox SHELL=/bin/bash LANG=C.UTF-8 TERM=xterm \
        PATH=/home/sandbox/.local/bin:/home/sandbox/go/bin:/usr/local/go/bin:/usr/local/node/bin:/usr/local/bin:/usr/bin:/bin \
        UV_PYTHON=/usr/bin/python3.12 UV_PYTHON_DOWNLOADS=never CI=1 $PROXY_ENV $DECOY_ENV \
        bash -c "bash /audit/scenario/$ph.sh; echo \$? > $mark" > "$O/$ph.stdout" 2> "$O/$ph.stderr" ) &
  local spid=$! rc=124 waited=0
  while [ $waited -lt "$tmo" ]; do
    [ -s "$mark" ] && { rc=$(cat "$mark"); break; }
    kill -0 $spid 2>/dev/null || { rc=$( [ -s "$mark" ] && cat "$mark" || echo 125 ); break; }
    sleep 2; waited=$((waited+2))
  done
  local t1; t1=$(date +%s)
  sleep 10   # grace period: let anything it spawned show itself
  ps -u sandbox -o pid=,etimes=,args= > "$O/$ph.leftover" 2>/dev/null
  pkill -9 -u sandbox 2>/dev/null; sleep 1; kill $spid 2>/dev/null; wait $spid 2>/dev/null
  echo "{\"phase\":\"$ph\",\"exit\":$rc,\"seconds\":$((t1-t0)),\"timed_out\":$([ "$rc" = 124 ] && echo true || echo false)}" > "$O/$ph.meta.json"
  tail -c +$((dns0+1)) /var/log/audit/dns.log > "$O/$ph.dns.log"
  tail -c +$((px0+1)) /var/log/audit/proxy.log > "$O/$ph.proxy.log"
  journalctl -k --since "@$t0" --no-pager 2>/dev/null | grep 'AUDIT-DROP' > "$O/$ph.fwdrop.log"
  log "  exit=$rc in $((t1-t0))s"
}

phase install install "$T_INSTALL"
phase run run "$T_RUN"

kill $INW 2>/dev/null
/opt/audit/bin/netmode.sh closed >/dev/null
python3 -I $A/bin/analyze_dynamic.py snapshot "$O/snap-after.json"
python3 -I $A/bin/analyze_dynamic.py analyze "$O" > "$O/dynamic-summary.txt" 2>>"$O/dynamic.log" || log "analyze failed"
# keep raw straces compressed (can be large)
zstd -q --rm -T0 "$O"/*.strace 2>/dev/null || true
chmod -R a+rX "$O"
log "done"

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
# macOS-shaped home for the run-darwin phase, with decoys at Mac paths (created now so the snapshots cover it)
MH=/Users/sandbox
rm -rf "$MH"; mkdir -p "$MH/Library/LaunchAgents"
macdecoy() { install -D -m 600 -o sandbox -g sandbox /dev/stdin "$MH/$1" <<<"$2"; echo "$MH/$1" >> "$O/extra-decoys.txt"; }
macdecoy Library/Keychains/login.keychain-db 'kych AUDITDECOY'
macdecoy "Library/Application Support/Google/Chrome/Default/Login Data" 'SQLite format 3 AUDITDECOY'
macdecoy "Library/Application Support/Google/Chrome/Default/Cookies" 'SQLite format 3 AUDITDECOY'
macdecoy "Library/Application Support/Google/Chrome/Local State" '{"os_crypt":{"encrypted_key":"AUDITDECOY"}}'
macdecoy "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log" 'AUDITDECOY-metamask-vault'
macdecoy "Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data" 'SQLite format 3 AUDITDECOY'
macdecoy "Library/Application Support/Firefox/Profiles/abcd1234.default-release/logins.json" '{"logins":[{"encryptedPassword":"AUDITDECOY"}]}'
macdecoy "Library/Application Support/Firefox/Profiles/abcd1234.default-release/key4.db" 'SQLite format 3 AUDITDECOY'
macdecoy "Library/Application Support/Exodus/exodus.wallet/seed.seco" 'AUDITDECOY-seed'
macdecoy "Library/Application Support/Electrum/wallets/default_wallet" '{"keystore":{"seed":"AUDITDECOY abandon abandon about"}}'
macdecoy "Library/Application Support/Telegram Desktop/tdata/key_datas" 'AUDITDECOY'
macdecoy Library/Cookies/Cookies.binarycookies 'cook AUDITDECOY'
macdecoy Library/Messages/chat.db 'SQLite format 3 AUDITDECOY'
macdecoy "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite" 'SQLite format 3 AUDITDECOY'
macdecoy .ssh/id_ed25519 $'-----BEGIN OPENSSH PRIVATE KEY-----\nAUDITDECOYAUDITDECOY\n-----END OPENSSH PRIVATE KEY-----'
macdecoy .aws/credentials $'[default]\naws_access_key_id = AKIAAUDITDECOY7EXMPL\naws_secret_access_key = AUDITDECOYmac'  # gitleaks:allow (fake decoy)
macdecoy .config/gh/hosts.yml $'github.com:\n    oauth_token: gho_AUDITDECOYmac000000000000000000000000'
macdecoy .zsh_history $': 1794200000:0;export GITHUB_TOKEN=ghp_AUDITDECOY222222222222222222222222222'
chown -R sandbox:sandbox "$MH"; chmod 700 "$MH/.ssh"
# Each phase runs auto-<phase>.sh (generated from the manifests) and then <phase>.sh (tailored), as separate steps:
# nothing in the tailored script can stop the auto scenario from running.
for f in install run auto-install auto-run; do [ -f /audit/scenario/$f.sh ] || echo 'echo "(no '$f' step)"' > /audit/scenario/$f.sh; done
chmod 755 /audit/scenario; chmod 644 /audit/scenario/*.sh

python3 -I $A/bin/analyze_dynamic.py snapshot "$O/snap-before.json"
# kernel-level watch on decoys (catches reads even outside strace, e.g. by daemons it spawned)
cat $A/decoys.txt "$O/extra-decoys.txt" | sed 's#/[^/]*$##' | sort -u > "$O/decoy-dirs.txt"
inotifywait -m -q --format '%T %e %w%f' --timefmt '%s' -e access,open,modify,move,delete \
   --fromfile "$O/decoy-dirs.txt" > "$O/decoy-inotify.log" 2>"$O/decoy-inotify.err" &
INW=$!

DECOY_ENV="ANTHROPIC_API_KEY=sk-ant-api03-AUDITDECOY0000 OPENAI_API_KEY=sk-proj-AUDITDECOY0000 GITHUB_TOKEN=ghp_AUDITDECOY0000000000000000000000000000 AWS_ACCESS_KEY_ID=AKIAAUDITDECOY7EXMPL AWS_SECRET_ACCESS_KEY=AUDITDECOYsecret"
PROXY_ENV="HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888 http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888 NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1 NODE_USE_ENV_PROXY=1 npm_config_proxy=http://127.0.0.1:8888 npm_config_https_proxy=http://127.0.0.1:8888 GOPROXY=https://proxy.golang.org GOFLAGS=-modcacherw"

phase() { # name netmode timeout [scenario-script] [extra env, no spaces inside values]
  local ph=$1 mode=$2 tmo=$3 script=${4:-$1} extra=${5:-}
  /opt/audit/bin/netmode.sh "$mode" >/dev/null
  local dns0 px0 t0
  dns0=$(stat -c %s /var/log/audit/dns.log); px0=$(stat -c %s /var/log/audit/proxy.log); t0=$(date +%s)
  log "phase $ph (net=$mode, timeout ${tmo}s)"
  # The phase ends when the scenario script exits (marker file), not when strace does: strace -f
  # would otherwise wait for any daemon the target left behind. Leftovers are recorded, then killed.
  local mark=/tmp/.audit-phase-rc-$ph; rm -f "$mark"
  # CI=1 keeps installers non-interactive. The run phase must look like a normal user session: code that
  # hides from analysis often goes quiet when it sees CI.
  local ci=; [ "$ph" = install ] && ci=CI=1
  ( cd "$P" && exec strace -f -qq -s 300 -e signal=none \
      -e trace=execve,connect,openat,unlinkat,renameat2 -o "$O/$ph.strace" -u sandbox -- \
      env -i HOME=/home/sandbox USER=sandbox LOGNAME=sandbox SHELL=/bin/bash LANG=C.UTF-8 TERM=xterm \
        PATH=/home/sandbox/.local/bin:/home/sandbox/go/bin:/usr/local/go/bin:/usr/local/node/bin:/usr/local/bin:/usr/bin:/bin \
        UV_PYTHON=/usr/bin/python3.12 UV_PYTHON_DOWNLOADS=never $ci $PROXY_ENV $DECOY_ENV $extra \
        bash -c "bash /audit/scenario/auto-$script.sh; bash /audit/scenario/$script.sh; echo \$? > $mark" > "$O/$ph.stdout" 2> "$O/$ph.stderr" ) &
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

# run-darwin: run.sh again, with interpreted code told it is on macOS (Node preload, Python sitecustomize), a Mac HOME
# with Mac-path decoys, and logging stand-ins for macOS tools. Native code still sees Linux. Only when the target has
# its own JS/TS/Python.
if [ -n "$(find "$P" \( -name node_modules -o -name .venv -o -name .git \) -prune -o -type f \
      \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' -o -name '*.ts' -o -name '*.py' \) -print -quit)" ]; then
  for s in /usr/bin/security /usr/bin/osascript /usr/bin/launchctl /usr/bin/sw_vers /usr/sbin/system_profiler \
           /usr/sbin/ioreg /usr/bin/defaults /usr/bin/dscl /usr/sbin/screencapture /usr/bin/pbpaste /usr/bin/pbcopy \
           /usr/sbin/spctl /usr/bin/csrutil /usr/bin/xattr /usr/bin/hdiutil /usr/bin/ditto /usr/bin/tccutil; do
    [ -e "$s" ] || { install -m 755 $A/bin/macstub.sh "$s" && echo "$s"; }
  done > "$O/macstubs.txt"
  chattr -a /var/log/audit/macstub.log 2>/dev/null; : > /var/log/audit/macstub.log
  chmod 622 /var/log/audit/macstub.log; chattr +a /var/log/audit/macstub.log 2>/dev/null   # append-only for the target
  mkdir -p /System/Library/CoreServices "/Applications/Google Chrome.app" /Applications/Exodus.app /Applications/Telegram.app
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict>' \
    '<key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>15.5</string>' \
    '<key>ProductBuildVersion</key><string>24F74</string></dict></plist>' > /System/Library/CoreServices/SystemVersion.plist
  DARWIN_ENV="HOME=$MH NODE_OPTIONS=--require=/opt/audit/darwin/darwin.js PYTHONPATH=/opt/audit/darwin
    PATH=/home/sandbox/.local/bin:/home/sandbox/go/bin:/usr/local/go/bin:/usr/local/node/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
    npm_config_cache=/home/sandbox/.npm UV_CACHE_DIR=/home/sandbox/.cache/uv XDG_CACHE_HOME=/home/sandbox/.cache
    GOPATH=/home/sandbox/go GOMODCACHE=/home/sandbox/go/pkg/mod"
  phase run-darwin run "$T_RUN" run "$DARWIN_ENV"
  chattr -a /var/log/audit/macstub.log 2>/dev/null; cp /var/log/audit/macstub.log "$O/macstub.log"
else
  log "run-darwin skipped: no JS/TS/Python in the target"
fi

kill $INW 2>/dev/null
/opt/audit/bin/netmode.sh closed >/dev/null
python3 -I $A/bin/analyze_dynamic.py snapshot "$O/snap-after.json"
python3 -I $A/bin/analyze_dynamic.py analyze "$O" > "$O/dynamic-summary.txt" 2>>"$O/dynamic.log" || log "analyze failed"
# keep raw straces compressed (can be large)
zstd -q --rm -T0 "$O"/*.strace 2>/dev/null || true
chmod -R a+rX "$O"
log "done"

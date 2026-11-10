#!/bin/bash
# Host orchestrator for the plugin/tool audit. Nothing from the target ever runs on the Mac:
# it is downloaded, scanned and run only inside a throwaway clone of the "audit-base" Lima VM.
#
#   ./audit.sh new <github-url|https-git-url|local-dir> [ref]   -> prints AUDIT_ID; fetch + static scan
#   ./audit.sh run <AUDIT_ID> [install.sh] [run.sh]             -> runtime test inside the VM
#                     (default: work/<id>/scenario/{install,run}.sh, else the auto-generated scenario/auto/*)
#   ./audit.sh copies <AUDIT_ID>    (run by you, not Claude) readable copies of files your deny rules hide
#   ./audit.sh destroy <AUDIT_ID>                                -> delete the VM clone
#   ./audit.sh base                                              -> (re)build audit-base from vm/
#
# Results: work/<AUDIT_ID>/{meta.json,static/,dynamic/,src/ (read-only, symlinks removed)}
set -euo pipefail
cd "$(dirname "$0")"
HERE=$PWD
L=limactl

die() { echo "error: $*" >&2; exit 1; }
vmsh() { $L shell --workdir / "$1" sudo bash -c "$2" 2> >(grep -v 'unable to resolve host' >&2); }

install_guest() { # vm
  for f in guest/*; do $L copy "$f" "$1:/tmp/$(basename "$f")"; done
  vmsh "$1" 'grep -q "$(hostname)" /etc/hosts || echo "127.0.1.1 $(hostname)" >> /etc/hosts
    install -m 755 /tmp/*.sh /tmp/*.py /opt/audit/bin/ && install -m 644 /tmp/no-bytecode.yaml /opt/audit/bin/
    install -d /opt/audit/darwin && install -m 644 /tmp/darwin_preload.js /opt/audit/darwin/darwin.js &&
      install -m 644 /tmp/darwin_sitecustomize.py /opt/audit/darwin/sitecustomize.py
    rm -rf /audit/out /audit/scenario; mkdir -p /audit/out /audit/scenario'
}

# Target files whose names the user's Claude Code deny rules hide from the reviewer (VM scanners still cover them)
list_blocked() { # workdir
  (cd "$1/src" && find . -type f | sed 's#^\./##' | grep -Ei '(^|/)(\.?secrets[^/]*|\.?credentials[^/]*|\.env|\.env\.[^/]*|[^/]*\.env|\.envrc|client_secret[^/]*)$|(^|/)secrets/') \
    > "$1/static/unreadable-by-reviewer.txt" || true
}

# Run by the USER only (it exposes those files to the reviewer under neutral names). Claude Code deny rules (secrets*, credentials*, .env*, any path under a secrets/ dir) block the reviewer from
# target files with those names. Give each one a read-only copy under a neutral name:
#   src/internal/secrets/store.go -> review-copies/internal__sekrets__store.go.txt   (index: review-copies/INDEX.txt)
review_copies() { # workdir
  local W=$1 R=$1/review-copies f alias
  chmod -R u+w "$R" 2>/dev/null || true; rm -rf "$R"; mkdir -p "$R"
  (cd "$W/src" && find . -type f | sed 's#^\./##' | grep -Ei '(^|/)(\.?secrets[^/]*|\.?credentials[^/]*|\.env|\.env\.[^/]*|[^/]*\.env|\.envrc|client_secret[^/]*)$|(^|/)secrets/') |
  while IFS= read -r f; do
    alias=$(printf '%s' "$f" | sed -E 's#/#__#g' | perl -pe 's/\.?secrets/sekrets/gi; s/\.?credentials/kreds/gi; s/\.env/_dotenv/gi; s/client_secret/client-sekret/gi').txt
    cp "$W/src/$f" "$R/$alias"; printf '%s\t%s\n' "$alias" "$f" >> "$R/INDEX.txt"
  done
  cut -f2 "$R/INDEX.txt" 2>/dev/null > "$W/static/unreadable-by-reviewer.txt" || true
  chmod -R a-w "$R"
}

cmd=${1:-}; shift || true
case "$cmd" in
base)
  if $L list -q 2>/dev/null | grep -qx audit-base; then $L stop audit-base 2>/dev/null || true; $L delete -f audit-base; fi
  $L create --name audit-base --tty=false vm/audit-base.yaml
  $L start audit-base --tty=false
  $L copy vm/provision.sh audit-base:/tmp/provision.sh
  vmsh audit-base 'bash /tmp/provision.sh'
  install_guest audit-base
  vmsh audit-base 'mkdir -p /opt/audit/osvdb/osv-scalibr/npm; /opt/audit/bin/netmode.sh open;
    curl -fsSL -o /opt/audit/osvdb/osv-scalibr/npm/all.zip https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip;
    /opt/audit/bin/netmode.sh closed'
  $L stop audit-base
  echo "audit-base ready"
  ;;

new)
  target=${1:?target}; ref=${2:-}
  if [[ "$target" =~ ^https://github\.com/([^/]+)/([^/#?]+) ]]; then
    owner=${BASH_REMATCH[1]}; repo=${BASH_REMATCH[2]%.git}
    url="https://github.com/$owner/$repo"
    if [ -z "$ref" ]; then
      sha=$(git ls-remote "$url" HEAD | cut -f1)
    else
      sha=$(git ls-remote "$url" "$ref" "refs/heads/$ref" "refs/tags/$ref^{}" "refs/tags/$ref" | head -1 | cut -f1)
      [[ "$ref" =~ ^[0-9a-f]{40}$ ]] && sha=$ref
    fi
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "could not resolve $url ${ref:-HEAD}"
    kind=github; name=$repo; label="$owner/$repo"
  elif [[ -d "$target" ]]; then
    kind=tar; name=$(basename "$(cd "$target" && pwd)"); label="local:$target"
    # content hash (not git HEAD: the folder may sit inside another repo, or have uncommitted changes)
    sha=$(cd "$target" && find . -type f -not -path './.git/*' -not -name .DS_Store -exec shasum {} + | LC_ALL=C sort -k2 | shasum | cut -c1-40)
  elif [[ "$target" =~ ^https:// ]]; then
    kind=git; name=$(basename "${target%.git}"); label=$target; sha=pending; ref=${ref:-HEAD}
  else die "target must be a GitHub URL, https git URL or local directory"; fi
  id=$(echo "${name}-${sha:0:7}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9.\n-' '-')
  vm="aud-${sha:0:7}"; [ "$sha" = pending ] && vm="aud-$(date +%s | tail -c 8)"
  W="$HERE/work/$id"; mkdir -p "$W"
  echo "== $label @ ${sha} -> $id (vm $vm)"
  $L list -q | grep -qx "$vm" && { $L stop "$vm" 2>/dev/null || true; $L delete -f "$vm"; }
  $L clone --tty=false audit-base "$vm" >/dev/null
  $L start --tty=false "$vm" >/dev/null
  install_guest "$vm"
  case $kind in
    github) vmsh "$vm" "/opt/audit/bin/fetch.sh github $owner/$repo $sha" ;;
    git)    vmsh "$vm" "/opt/audit/bin/fetch.sh git '$target' '$ref'"; sha=$(vmsh "$vm" 'cat /audit/fetch/commit') ;;
    tar)    tar -C "$target" --no-mac-metadata --no-xattrs --exclude .git -cf "$W/upload.tar" . && $L copy "$W/upload.tar" "$vm:/tmp/upload.tar" && rm "$W/upload.tar"
            vmsh "$vm" "/opt/audit/bin/fetch.sh tar /tmp/upload.tar" ;;
  esac
  vmsh "$vm" '/opt/audit/bin/static.sh' | tail -30
  # default runtime scenario from the target's manifests (read as data, as the no-network auditor user)
  vmsh "$vm" 'runuser -u auditor -- python3 -I /opt/audit/bin/auto_scenario.py /audit/src /audit/out/scenario-auto'
  # export: scanner results + a copy of the source with all symlinks removed (listed in symlinks.txt)
  vmsh "$vm" 'cd /audit && find src -type l -printf "%p -> %l\n" > out/static/symlinks.txt;
    find src ! -type l -print0 | tar --null --no-recursion -T - -cf /audit/out/src.tar; chmod -R a+r /audit/out'
  chmod -R u+w "$W/src" 2>/dev/null || true; rm -rf "$W/static" "$W/src" "$W/scenario/auto"; mkdir -p "$W/src" "$W/scenario"
  $L copy -r "$vm:/audit/out/static" "$W/"
  $L copy -r "$vm:/audit/out/scenario-auto" "$W/scenario/auto"
  $L copy "$vm:/audit/out/src.tar" "$W/src.tar"
  tar -xf "$W/src.tar" -C "$W/src" --strip-components 1 && rm "$W/src.tar"
  chmod -R a-w "$W/src"
  list_blocked "$W"
  [ -n "${AUDIT_KEEP_VM:-}" ] || $L stop "$vm" >/dev/null 2>&1 || true   # ./audit keeps it up for the run step
  printf '{"id":"%s","label":"%s","kind":"%s","commit":"%s","vm":"%s","scanned_at":"%s"}\n' \
    "$id" "$label" "$kind" "$sha" "$vm" "$(date -u +%FT%TZ)" > "$W/meta.json"
  echo "AUDIT_ID=$id"
  ;;

run)
  id=${1:?id}; W="$HERE/work/$id"
  # default: hand-written scenario/{install,run}.sh if present, else the auto-generated scenario/auto/*
  pick() { [ -f "$W/scenario/$1" ] && echo "$W/scenario/$1" || { [ -f "$W/scenario/auto/$1" ] && echo "$W/scenario/auto/$1"; } || true; }
  inst=${2:-$(pick install.sh)}; runs=${3:-$(pick run.sh)}
  vm=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["vm"])' "$W/meta.json")
  name=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"].rsplit("-",1)[0])' "$W/meta.json")
  if ! $L list --format '{{.Status}}' "$vm" | grep -q Running; then   # a start right after a stop can time out: retry once
    $L start --tty=false "$vm" >/dev/null || { $L stop -f "$vm" >/dev/null 2>&1; sleep 5; $L start --tty=false "$vm" >/dev/null; }
  fi
  install_guest "$vm"   # refresh guest scripts; clears /audit/out and /audit/scenario (static results are already on the host)
  [ -n "$inst" ] && $L copy "$inst" "$vm:/tmp/install.sh" && vmsh "$vm" 'cp /tmp/install.sh /audit/scenario/install.sh'
  [ -n "$runs" ] && $L copy "$runs" "$vm:/tmp/run.sh" && vmsh "$vm" 'cp /tmp/run.sh /audit/scenario/run.sh'
  vmsh "$vm" "T_INSTALL=${T_INSTALL:-1200} T_RUN=${T_RUN:-300} /opt/audit/bin/dynamic.sh '$name'"
  rm -rf "$W/dynamic"
  $L copy -r "$vm:/audit/out/dynamic" "$W/"
  mkdir -p "$W/scenario"; for f in "$inst" "$runs"; do [ -n "$f" ] && case "$(cd "$(dirname "$f")" && pwd)" in "$W/scenario"*) ;; *) cp "$f" "$W/scenario/" ;; esac; done
  echo "scenario used: ${inst:-none} ${runs:-none}" | tee "$W/dynamic/scenario-used.txt"
  echo "results: $W/dynamic/dynamic-summary.txt"
  ;;

copies) # rebuild review-copies/ for an existing audit
  review_copies "$HERE/work/${1:?id}"; cat "$HERE/work/$1/review-copies/INDEX.txt" 2>/dev/null || echo "(none)"
  ;;

destroy)
  id=${1:?id}; W="$HERE/work/$id"
  vm=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["vm"])' "$W/meta.json")
  $L stop "$vm" 2>/dev/null || true; $L delete -f "$vm"
  echo "deleted $vm"
  ;;

*) sed -n '2,12p' "$0"; exit 2 ;;
esac

#!/bin/bash
# fetch.sh github <owner/repo> <commit-sha> | git <https-url> <commit-sha> [ref] | tar <path-in-vm>
# Root, inside the VM. Puts the target in /audit/src (root-owned, read-only to everyone else).
# Nothing from the target is executed here; git never touches a GitHub target (archive download).
set -euo pipefail
kind=$1
rm -rf /audit/src /audit/fetch && mkdir -p /audit/src /audit/fetch
case "$kind" in
  github)
    /opt/audit/bin/netmode.sh open >/dev/null
    curl -fsSL --retry 3 -o /audit/fetch/src.tgz "https://codeload.github.com/$2/tar.gz/$3"
    tar -xzf /audit/fetch/src.tgz -C /audit/src --strip-components 1 --no-same-owner --no-same-permissions
    ;;
  git) # <url> <commit-sha> [ref]: the host resolved the commit; fetch exactly that commit
    [[ "$3" =~ ^[0-9a-f]{40}$ ]] || { echo "git: expected a commit SHA" >&2; exit 2; }
    /opt/audit/bin/netmode.sh open >/dev/null
    r=/audit/fetch/repo
    git init -q "$r"
    G() { git -C "$r" -c core.hooksPath=/dev/null -c core.symlinks=false -c protocol.file.allow=never \
              -c submodule.recurse=false "$@"; }
    G remote add origin "$2"
    # Most servers serve a commit by SHA; otherwise fetch the ref (or HEAD), then everything as a last resort.
    G fetch -q --depth 1 --no-tags --no-recurse-submodules origin "$3" 2>/dev/null ||
      G fetch -q --depth 50 --no-tags --no-recurse-submodules origin "${4:-HEAD}" 2>/dev/null || true
    unshallow=(); [ -f "$r/.git/shallow" ] && unshallow=(--unshallow)
    G cat-file -e "$3^{commit}" 2>/dev/null ||
      G fetch -q "${unshallow[@]}" --no-recurse-submodules origin \
        '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'
    G checkout -q --detach "$3"
    [ "$(G rev-parse HEAD)" = "$3" ] || { echo "git: fetched commit differs from $3" >&2; exit 1; }
    echo "$3" > /audit/fetch/commit
    rm -rf "$r/.git" && cp -a "$r/." /audit/src/
    ;;
  tar)
    tar -xf "$2" -C /audit/src --no-same-owner --no-same-permissions
    ;;
  *) echo "bad kind" >&2; exit 2 ;;
esac
/opt/audit/bin/netmode.sh closed >/dev/null
sha256sum /audit/fetch/src.tgz 2>/dev/null | cut -d' ' -f1 > /audit/fetch/archive.sha256 || true
chown -R root:root /audit/src && chmod -R u+rwX,go+rX,go-w /audit/src
echo "files=$(find /audit/src -type f | wc -l) size=$(du -sh /audit/src | cut -f1)"

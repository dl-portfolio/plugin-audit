#!/bin/bash
# fetch.sh github <owner/repo> <commit-sha> | git <https-url> <ref> | tar <path-in-vm>
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
  git)
    /opt/audit/bin/netmode.sh open >/dev/null
    git -c core.hooksPath=/dev/null -c core.symlinks=false -c protocol.file.allow=never \
        -c submodule.recurse=false clone --depth 1 --no-recurse-submodules --branch "$3" -- "$2" /audit/fetch/repo
    git -C /audit/fetch/repo rev-parse HEAD > /audit/fetch/commit
    rm -rf /audit/fetch/repo/.git && cp -a /audit/fetch/repo/. /audit/src/
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

#!/bin/bash
# netmode.sh open|install|run|closed   (root, inside the audit VM)
#  open    - DNS forwards everything. Only root uses it (fetching the target). Proxy off.
#  install - DNS resolves only allowlisted package registries; proxy on with the same allowlist.
#  run     - DNS answers NXDOMAIN to everything; proxy on but refuses every host (so each
#            host the tool tries is logged by name).
#  closed  - DNS NXDOMAIN to everything; proxy off.
# The auditor/sandbox users can never reach the network directly (nftables, always on).
set -euo pipefail
mode=${1:?open|install|run|closed}
up=$(cat /opt/audit/upstream-dns)
conf=/etc/dnsmasq.d/10-audit-mode.conf
active=/etc/tinyproxy/filter-active.txt
grep -q "filter-active.txt" /etc/tinyproxy/tinyproxy.conf || \
  sed -i "s#^Filter .*#Filter \"$active\"#" /etc/tinyproxy/tinyproxy.conf
case "$mode" in
  open)    echo "server=$up" > "$conf"; : > "$active" ;;
  install) { echo "address=/#/"
             sed -E 's/^\(\^\|\\\.\)//; s/^\^//; s/\$$//; s/\\\././g' /etc/tinyproxy/allow.txt | while read -r d; do
               [ -n "$d" ] && echo "server=/$d/$up"; done; } > "$conf"
           cp /etc/tinyproxy/allow.txt "$active" ;;
  run|closed) echo "address=/#/" > "$conf"; : > "$active" ;;
  *) echo "bad mode" >&2; exit 2 ;;
esac
systemctl restart dnsmasq
case "$mode" in install|run) systemctl restart tinyproxy ;; *) systemctl stop tinyproxy ;; esac
nft list table inet audit >/dev/null 2>&1 || nft -f /etc/nftables-audit.nft
echo "$mode" > /run/audit-netmode
echo "netmode=$mode"

#!/bin/bash
# One-time provisioning of the audit-base VM. Runs as root INSIDE the VM, with network.
# Every download is pinned to a version >= ~2 weeks old and checked against a sha256: toolchains and binaries (dl),
# scanner source archives (gh_src), and semgrep with all its dependencies (vm/semgrep-requirements.txt, --require-hashes).
# The one exception is the osv-scanner vulnerability database, a live feed fetched at build time by design.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
A=/opt/audit
mkdir -p "$A/dl" "$A/bin" /var/log/audit

apt-get update -q
apt-get install -y -q --no-install-recommends \
  ca-certificates curl git jq python3 python3-venv python3-dev build-essential cmake pkg-config \
  strace tcpdump dnsmasq tinyproxy nftables inotify-tools xz-utils unzip zstd file procps

# ---- users: auditor runs scanners, sandbox runs the target. Neither has sudo or a password.
for u in auditor sandbox; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
  passwd -l "$u" >/dev/null
  gpasswd -d "$u" sudo >/dev/null 2>&1 || true
done

dl() { # url sha256 out
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}
gh_src() { # owner/repo commit sha256 destdir   (pinned by commit SHA, archive checked against the vetted sha256)
  local t; t=$(mktemp)
  dl "https://codeload.github.com/$1/tar.gz/$2" "$3" "$t"
  rm -rf "$4"; mkdir -p "$4"
  tar -xzf "$t" -C "$4" --strip-components 1; rm -f "$t"
}

# ---- toolchains
dl https://go.dev/dl/go1.27.2.linux-arm64.tar.gz \
   94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8 "$A/dl/go.tgz"
rm -rf /usr/local/go && tar -C /usr/local -xzf "$A/dl/go.tgz"

dl https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-arm64.tar.xz \
   6287aa46b6c375d816e63ae66d024fbbfd70404825aabdfdf898a970871d2f4b "$A/dl/node.txz"
rm -rf /usr/local/node && mkdir -p /usr/local/node && tar -C /usr/local/node --strip-components 1 -xJf "$A/dl/node.txz"

dl https://github.com/astral-sh/uv/releases/download/0.13.2/uv-aarch64-unknown-linux-gnu.tar.gz \
   3143e25fccac6f81b3b400792caa2ec431a5e8824d855cde9550a25f0fac8ea0 "$A/dl/uv.tgz"
tar -xzf "$A/dl/uv.tgz" -C "$A/dl" && install -m 755 "$A"/dl/uv-aarch64-unknown-linux-gnu/uv{,x} /usr/local/bin/

dl https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz \
   e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 "$A/dl/gitleaks.tgz"
tar -xzf "$A/dl/gitleaks.tgz" -C "$A/dl" gitleaks && install -m 755 "$A/dl/gitleaks" /usr/local/bin/

dl https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_arm64 \
   4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7 /usr/local/bin/osv-scanner
chmod 755 /usr/local/bin/osv-scanner

cat > /etc/profile.d/audit-path.sh <<'EOF'
export PATH=/usr/local/go/bin:/usr/local/node/bin:$PATH
EOF
export PATH=/usr/local/go/bin:/usr/local/node/bin:$PATH
export UV_PYTHON=/usr/bin/python3.12 UV_PYTHON_DOWNLOADS=never UV_CACHE_DIR=/var/cache/uv

# ---- scanners (vetted 2026-11-08, see ../scanner-vetting.md), installed from their lockfiles
gh_src NVIDIA/SkillSpector f3b25697d76256998ca9d42c198d256258d4c035 \
   387d54edc3e5750960a4a76f14f5ac75aa85ee487526736b0008df9dd8908dec "$A/skillspector"
(cd "$A/skillspector" && uv sync --locked --no-dev -q)

gh_src cisco-ai-defense/skill-scanner c615acb70994cdf3f4ba54d955fef2e92ac84437 \
   9db9711fec2943b958d88f44e7ea335eb799fde14ad616d92477f679fd6b3554 "$A/cisco"
(cd "$A/cisco" && SETUPTOOLS_SCM_PRETEND_VERSION=2.3.1 uv sync --frozen --no-dev -q)   # builds the cel-go helper from source (go.sum-pinned)

uv venv -q "$A/semgrep-venv"
# semgrep==1.182.0 and every dependency, hash-locked (uv pip compile --generate-hashes --exclude-newer 2026-11-08)
uv pip install -q --python "$A/semgrep-venv/bin/python" --require-hashes --no-deps -r /tmp/semgrep-requirements.txt

gh_src semgrep/semgrep-rules 17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9 \
   9dfe6866fbecd557f507078cb79721a9eb8f4764fc2f6163648ea1320be25933 /tmp/semgrep-rules-all
rm -rf "$A/semgrep-rules" && mkdir -p "$A/semgrep-rules"
# security-relevant rule sets only; drop test fixtures (*.test.yaml, *.fixed.*)
for d in python javascript typescript go c bash generic dockerfile yaml/github-actions ruby rust php java; do
  [ -d "/tmp/semgrep-rules-all/$d" ] || continue
  (cd /tmp/semgrep-rules-all && find "$d" -name '*.yaml' ! -name '*.test.yaml' ! -name '*.fixed.*' \
     -path '*security*' -print0 | xargs -0 -I{} install -D -m 644 {} "$A/semgrep-rules/{}")
done
(cd /tmp/semgrep-rules-all && find generic/secrets -name '*.yaml' ! -name '*.test.yaml' -print0 2>/dev/null \
   | xargs -0 -I{} install -D -m 644 {} "$A/semgrep-rules/{}") || true
rm -rf /tmp/semgrep-rules-all

# ---- osv-scanner offline database (includes OpenSSF MAL-* malicious-package advisories)
seed=/tmp/osvseed; rm -rf $seed; mkdir -p $seed/npm $seed/py $seed/go $seed/rs
cat > $seed/npm/package-lock.json <<'EOF'
{"name":"seed","lockfileVersion":3,"requires":true,"packages":{"":{"name":"seed","dependencies":{"lodash":"4.17.0"}},"node_modules/lodash":{"version":"4.17.0"}}}
EOF
echo "requests==2.0.0" > $seed/py/requirements.txt
printf 'module seed\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n' > $seed/go/go.mod
printf 'golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\n' > $seed/go/go.sum
printf 'version = 3\n\n[[package]]\nname = "seed"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' > $seed/rs/Cargo.lock
mkdir -p "$A/osvdb"
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$A/osvdb" osv-scanner scan source -r \
  --offline-vulnerabilities --download-offline-databases $seed >/dev/null 2>&1 || true
ls -R "$A/osvdb" | head -20
rm -rf $seed

# ---- DNS: dnsmasq becomes the only resolver and logs every query
awk '/^nameserver/{print $2; exit}' /run/systemd/resolve/resolv.conf > "$A/upstream-dns" || true
[ -s "$A/upstream-dns" ] || echo 1.1.1.1 > "$A/upstream-dns"
systemctl disable --now systemd-resolved
rm -f /etc/resolv.conf && echo "nameserver 127.0.0.1" > /etc/resolv.conf
touch /var/log/audit/dns.log && chown dnsmasq:nogroup /var/log/audit/dns.log 2>/dev/null || chown dnsmasq /var/log/audit/dns.log
cat > /etc/dnsmasq.d/00-audit-base.conf <<'EOF'
listen-address=127.0.0.1
bind-interfaces
no-resolv
no-hosts
log-queries=extra
log-facility=/var/log/audit/dns.log
EOF
sed -i 's/^#\?ENABLED=.*/ENABLED=1/' /etc/default/dnsmasq 2>/dev/null || true

# ---- allowlist proxy for the install phase (logs every host asked for)
touch /var/log/audit/proxy.log && chown tinyproxy:tinyproxy /var/log/audit/proxy.log
cat > /etc/tinyproxy/tinyproxy.conf <<'EOF'
User tinyproxy
Group tinyproxy
Port 8888
Listen 127.0.0.1
Timeout 600
LogFile "/var/log/audit/proxy.log"
LogLevel Info
MaxClients 200
Allow 127.0.0.1
ConnectPort 443
ConnectPort 80
Filter "/etc/tinyproxy/allow.txt"
FilterDefaultDeny Yes
FilterType ere
FilterCaseSensitive No
EOF
cat > /etc/tinyproxy/allow.txt <<'EOF'
(^|\.)registry\.npmjs\.org$
(^|\.)registry\.yarnpkg\.com$
(^|\.)pypi\.org$
(^|\.)files\.pythonhosted\.org$
(^|\.)proxy\.golang\.org$
(^|\.)sum\.golang\.org$
(^|\.)crates\.io$
^github\.com$
^codeload\.github\.com$
^objects\.githubusercontent\.com$
^release-assets\.githubusercontent\.com$
(^|\.)nodejs\.org$
EOF
systemctl disable --now tinyproxy

# ---- firewall: auditor and sandbox may only talk to loopback (dnsmasq, proxy); drops are logged
cat > /etc/nftables-audit.nft <<'EOF'
table inet audit {
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    meta skuid { "auditor", "sandbox" } log prefix "AUDIT-DROP " flags skuid drop
  }
}
EOF
cat > /etc/systemd/system/audit-nft.service <<'EOF'
[Unit]
Description=Audit egress firewall
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables-audit.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now audit-nft.service

# ---- decoy credentials for the sandbox user (all fake, every value contains AUDITDECOY)
H=/home/sandbox
decoy() { install -D -m "${3:-600}" -o sandbox -g sandbox /dev/stdin "$H/$1" <<<"$2"; echo "$H/$1" >> "$A/decoys.txt"; }
: > "$A/decoys.txt"
decoy .ssh/id_ed25519 $'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nAUDITDECOYAUDITDECOYAUDITDECOYAUDITDECOYAUDITDECOY0000000000000000000\n-----END OPENSSH PRIVATE KEY-----'
decoy .ssh/id_rsa $'-----BEGIN RSA PRIVATE KEY-----\nMIIEAUDITDECOYpAIBAAKCAQEAAUDITDECOY\n-----END RSA PRIVATE KEY-----'
decoy .ssh/config $'Host prod-bastion\n  HostName 10.20.30.40\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519  # AUDITDECOY' 644
decoy .aws/credentials $'[default]\naws_access_key_id = AKIAAUDITDECOY7EXMPL\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/AUDITDECOY/bPxRfiCYEXAMPLEKEY'
decoy .config/gh/hosts.yml $'github.com:\n    oauth_token: gho_AUDITDECOY0000000000000000000000000000\n    user: dev\n    git_protocol: https'
decoy .npmrc '//registry.npmjs.org/:_authToken=npm_AUDITDECOY000000000000000000000000000'
decoy .pypirc $'[pypi]\nusername = __token__\npassword = pypi-AUDITDECOY000000000000'
decoy .netrc 'machine api.github.com login dev password ghp_AUDITDECOY000000000000000000000000000'
decoy .git-credentials 'https://dev:ghp_AUDITDECOY000000000000000000000000000@github.com'
decoy .docker/config.json '{"auths":{"https://index.docker.io/v1/":{"auth":"QVVESVRERUNPWTpBVURJVERFQ09Z"}}}'
decoy .kube/config $'apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n    token: AUDITDECOY-kube-token'
decoy .claude/.credentials.json '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-AUDITDECOY","refreshToken":"sk-ant-ort01-AUDITDECOY"}}'
decoy .config/anthropic/api_key 'sk-ant-api03-AUDITDECOY0000000000000000'
decoy .env $'OPENAI_API_KEY=sk-proj-AUDITDECOY000000\nANTHROPIC_API_KEY=sk-ant-api03-AUDITDECOY000000\nSTRIPE_SECRET_KEY=sk_live_AUDITDECOY0000'
decoy .bash_history $'export GITHUB_TOKEN=ghp_AUDITDECOY111111111111111111111111111\nssh deploy@10.20.30.40\nmysql -u root -pAUDITDECOYpass' 600
decoy ".config/google-chrome/Default/Login Data" 'SQLite format 3 AUDITDECOY'
decoy .config/google-chrome/Default/Cookies 'SQLite format 3 AUDITDECOY'
decoy ".config/google-chrome/Local State" '{"os_crypt":{"encrypted_key":"AUDITDECOY"}}'
decoy .mozilla/firefox/abcd1234.default-release/logins.json '{"logins":[{"hostname":"https://bank.example","encryptedPassword":"AUDITDECOY"}]}'
decoy .mozilla/firefox/abcd1234.default-release/key4.db 'SQLite format 3 AUDITDECOY'
decoy .config/Exodus/exodus.wallet/seed.seco 'AUDITDECOY-seed'
decoy .electrum/wallets/default_wallet '{"keystore":{"seed":"AUDITDECOY abandon abandon about"}}'
decoy .bitcoin/wallet.dat 'AUDITDECOY'
decoy ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log" 'AUDITDECOY-metamask-vault'
decoy .gnupg/private-keys-v1.d/AUDITDECOY.key 'AUDITDECOY'
decoy .config/openai/auth.json '{"api_key":"sk-AUDITDECOY"}'
chmod 700 "$H/.ssh" "$H/.gnupg" 2>/dev/null || true
chown -R sandbox:sandbox "$H"
chmod 644 "$A/decoys.txt"

# Look lived-in: a few ordinary files
sudo -u sandbox bash -c 'mkdir -p ~/Documents ~/projects/website ~/Downloads; echo "# notes" > ~/Documents/todo.md; echo "<html></html>" > ~/projects/website/index.html'

mkdir -p /audit && chmod 755 /audit
chown -R root:root "$A" && chmod -R a+rX "$A"
mkdir -p /var/cache/uv && chmod -R a+rX /var/cache/uv
echo "provisioned $(date -u +%FT%TZ)" > "$A/PROVISIONED"
echo OK

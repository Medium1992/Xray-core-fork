#!/bin/sh
# setup.sh <xray-git-dir> <new-ref> <old-ref>: prepare the stand in
# $STAND_WORK (default ~/.cache/realitystand), without root.
#
# - nginx, HAProxy, tshark, certutil and pasta from Debian packages,
#   unpacked under $STAND_WORK/root (install.sh);
# - Google Chrome stable and Caddy (checked against its release checksums);
# - a copy of tcpdump: the system one runs under an AppArmor profile that
#   refuses signals and writes to hidden directories;
# - a test CA and a certificate for *.example.test;
# - xray-new and xray-old built from the two refs.
# Firefox comes from the system.
set -eu
xray=$1 new=$2 old=$3
here=$(cd "$(dirname "$0")" && pwd)
work=${STAND_WORK:-$HOME/.cache/realitystand}
mkdir -p "$work/bin" "$work/dl" "$work/certs" "$work/runs"
STAND_WORK=$work "$here/install.sh" nginx haproxy tshark libnss3-tools passt

cd "$work/dl"
curl -fsSL -o chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
dpkg-deb -x chrome.deb "$work/root"
caddy=2.11.9
curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v$caddy/caddy_${caddy}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v$caddy/caddy_${caddy}_checksums.txt"
grep "caddy_${caddy}_linux_amd64.tar.gz" "caddy_${caddy}_checksums.txt" | sha512sum -c -
tar -xzf "caddy_${caddy}_linux_amd64.tar.gz" -C "$work/bin" caddy
cp /usr/bin/tcpdump "$work/bin/tcpdump"

cd "$work/certs"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 365 \
  -subj "/CN=Stand Test CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout site.key -out site.csr -subj /CN=example.test
printf 'subjectAltName=DNS:example.test,DNS:*.example.test\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in site.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out site.pem -days 300 -extfile ext.cnf
cat site.pem ca.pem > chain.pem
cat chain.pem site.key > haproxy.pem
mkdir -p "$work/www"
echo '<html><body>stand</body></html>' > "$work/www/index.html"

for side in new old; do
  eval ref=\$$side
  tree=$(mktemp -d)
  git -C "$xray" worktree add -q --detach "$tree" "$ref"
  (cd "$tree" && GOFLAGS=-tags=http2legacy go build -trimpath -o "$work/bin/xray-$side" ./main)
  git -C "$xray" worktree remove --force "$tree"
done
echo "stand ready in $work"

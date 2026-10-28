#!/bin/sh
# Self-signed certificates for the lab sites (SAN = the site's IP). Output is gitignored.
set -eu
cd "$(dirname "$0")"
for site in bad:172.31.250.10 good:172.31.250.11; do
  name=${site%%:*}
  ip=${site#*:}
  mkdir -p "certs/$name"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$ip" \
    -addext "subjectAltName=IP:$ip" \
    -keyout "certs/$name/key.pem" -out "certs/$name/cert.pem" 2>/dev/null
  chmod 644 "certs/$name/key.pem" "certs/$name/cert.pem"
done
echo "certificates written to lab/certs/"

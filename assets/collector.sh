#!/bin/sh
# secagent host collector (schema 1). Makes no intended writes: it reads package, SSH, nginx and socket state (nginx -T, like nginx -t, may create missing log/temp directories).
# Requires sh, GNU sed and awk (Debian/Ubuntu defaults).
# Run on the host as root so `sshd -T` and `nginx -T` work:  sudo sh collect.sh > snapshot.json
# Output: one JSON object. Each section is base64 of the command output after secret redaction.
set -u
export LC_ALL=C

redact() {
  awk '
    function openblk() {
      if ($0 ~ /\}/) { sub(/\{.*\}/, "{ <redacted> }"); print }
      else { sub(/\{.*/, "{ # map/geo values redacted"); print; depth = 1 }
    }
    depth > 0 { if ($0 ~ /\}/) { depth = 0; print "    } # map/geo values redacted" }; next }
    hdr { hdr = 0; if ($0 ~ /[^ \t]/) { i = index($0, ";"); match($0, /^[ \t]*/); print substr($0, 1, RLENGTH) "<redacted>" (i ? substr($0, i) : ""); next } }
    pend { if ($0 ~ /\{/) { pend = 0; openblk(); next } if ($0 ~ /;/) pend = 0 }
    /^[ \t]*(map|geo)[ \t]/ { if ($0 ~ /\{/) { openblk(); next } pend = 1; print; next }
    tolower($0) ~ /^[ \t]*(proxy_set_header|add_header|more_set_headers|grpc_set_header|fastcgi_param|uwsgi_param|scgi_param)[ \t]+"?[a-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[a-z0-9_-]*"?[ \t]*$/ { hdr = 1; print; next }
    NF >= 2 && $0 ~ /;[ \t]*$/ {
      n = tolower($1)
      if (n ~ /^[a-z0-9_]+$/ && n ~ /(secret|passw|token|auth_[a-z0-9_]*key)/ && n !~ /_file$/ && n != "server_tokens") {
        match($0, /^[ \t]*[^ \t]+[ \t]+/); print substr($0, 1, RLENGTH) "<redacted>;"; next
      }
    }
    { print }
  ' | sed -E \
    -e 's/^([[:space:]]*env[[:space:]]+[A-Za-z0-9_]+=)[^;]+/\1<redacted>/' \
    -e 's/([?&][A-Za-z0-9_.-]*(key|token|secret|sig|passw|auth)[A-Za-z0-9_.-]*=)[^&[:space:]"'"'"';]+/\1<redacted>/Ig' \
    -e 's/(\$[A-Za-z0-9_]*(secret|token|passw|api[_-]?key|private)[A-Za-z0-9_]*[[:space:]]+)[^;{]+/\1<redacted>/Ig' \
    -e 's/((proxy_set_header|add_header|more_set_headers|grpc_set_header|fastcgi_param|uwsgi_param|scgi_param)[[:space:]]+"?[A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[A-Za-z0-9_-]*"?[[:space:]]+)[^;]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]{8,}/\1<redacted>/g' \
    -e 's#(://)[^/[:space:]"]*@#\1<redacted>@#g'
}

first=1
emit() { # emit <name> <shell command>
  out=$(sh -c "$2" 2>&1)
  rc=$?
  b64=$(printf '%s' "$out" | redact | base64 | tr -d '\n')
  if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
  printf '"%s":{"rc":%d,"b64":"%s"}' "$1" "$rc" "$b64"
}

printf '{"schema":1,"collector":"secagent-collector/1","collected_at":"%s","sections":{' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit uid 'id -u'
emit os_release 'cat /etc/os-release'
emit kernel 'uname -r'
emit packages "dpkg-query -W -f='\${db:Status-Abbrev}\t\${binary:Package}\t\${Version}\t\${source:Package}\t\${source:Version}\n'"
emit apt_policy 'apt-cache policy $(dpkg-query -W -f="\${binary:Package} ")'
emit apt_sources 'cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null'
emit auto_upgrades 'apt-config dump 2>/dev/null | grep -E "^(APT::Periodic::Unattended-Upgrade|Unattended-Upgrade::(Allowed-Origins|Origins-Pattern))"; dpkg-query -W -f="\${db:Status-Abbrev}\${binary:Package}\n" unattended-upgrades 2>/dev/null'
emit reboot 'if [ -f /var/run/reboot-required ]; then echo required; cat /var/run/reboot-required.pkgs 2>/dev/null || true; else echo not-required; fi'
emit sshd 'sshd=$(command -v sshd || echo /usr/sbin/sshd); "$sshd" -T'
emit nginx 'nginx=$(command -v nginx || echo /usr/sbin/nginx); "$nginx" -T'
emit listening 'ss -tlnpH'
printf '}}\n'

#!/bin/sh
# secagent host collector (schema 1). Makes no intended writes: it reads package, SSH, nginx and socket state (nginx -T, like nginx -t, may create missing log/temp directories).
# Requires sh, GNU sed and awk (Debian/Ubuntu defaults).
# Run on the host as root so `sshd -T` and `nginx -T` work:  sudo sh collect.sh > snapshot.json
# Output: one JSON object. Each section is base64 of the command output after secret redaction.
set -u
export LC_ALL=C

redact() {
  awk '
    BEGIN { sq = "\047"; MARK = "# secagent: redaction lost sync" }
    # A quote opens a quoted string only at the start of a token (line start, or after whitespace, ";", "{" or "}"), as in nginx,
    # so the apostrophe in o-apostrophe-reilly is literal. Inside quotes a backslash escapes the next character.
    function tokstart(s, i,    p) {
      if (i <= 1) return 1
      p = substr(s, i - 1, 1)
      return (p == " " || p == "\t" || p == ";" || p == "{" || p == "}")
    }
    # Index of the first ";" outside quotes at or after i, or 0. q0 is the quote already open at i (a string continued from an
    # earlier line); endq is left holding the quote still open at the end of s.
    function stmt_end(s, i, q0,    n, c, q) {
      n = length(s); q = q0
      for (; i <= n; i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == "\\") i++; else if (c == q) q = ""; continue }
        if ((c == "\"" || c == sq) && tokstart(s, i)) q = c
        else if (c == "\\") i++
        else if (c == ";") { endq = ""; return i }
      }
      endq = q
      return 0
    }
    # Length of the first token of s: a whole quoted string, else up to whitespace or ";".
    function tok_len(s,    n, i, c, q) {
      c = substr(s, 1, 1)
      if (c == "\"" || c == sq) {
        n = length(s); q = c
        for (i = 2; i <= n; i++) {
          c = substr(s, i, 1)
          if (c == "\\") i++
          else if (c == q) return i
        }
        return n
      }
      match(s, /^[^ \t;]*/)
      return RLENGTH
    }
    # Walks s from index i at brace depth d, counting braces outside quotes and comments so a regex quantifier like {2} nets to
    # zero. In Lua code (isl) a quote opens anywhere and "--" starts a comment. Returns the index of the "}" that brings the
    # depth to zero, else 0; sdepth is the depth at the end of s.
    function scan(s, i, d, isl,    n, c, q) {
      n = length(s); q = ""
      for (; i <= n; i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == "\\") i++; else if (c == q) q = ""; continue }
        if ((c == "\"" || c == sq) && (isl || tokstart(s, i))) q = c
        else if (c == "\\") i++
        else if (isl ? (c == "-" && substr(s, i, 2) == "--") : (c == "#" && tokstart(s, i))) break
        else if (c == "{") d++
        else if (c == "}") { d--; if (d <= 0) { sdepth = 0; return i } }
      }
      sdepth = d
      return 0
    }
    # Index of the first "{" outside quotes in s; 0 if there is none yet, -1 if a ";" ends the statement first.
    function find_brace(s,    n, i, c, q) {
      n = length(s); q = ""
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == "\\") i++; else if (c == q) q = ""; continue }
        if ((c == "\"" || c == sq) && tokstart(s, i)) q = c
        else if (c == "\\") i++
        else if (c == "#" && tokstart(s, i)) return 0
        else if (c == ";") return -1
        else if (c == "{") return i
      }
      return 0
    }
    # A body that is being dropped but looks like surrounding configuration: redaction lost track of where it ends.
    function lost(s) {
      return (s ~ /\{[ \t]*$/ || s ~ /^[ \t]*(server|location|http|upstream)([ \t{]|$)/)
    }
    function secret_name(n) {
      if (n == "secure_link_md5") return 1
      return (n ~ /(secret|passw|token|api_?key|auth_[a-z0-9_]*key)/ && n !~ /_file$/ && n != "server_tokens")
    }
    function block_name(n) { return (n == "map" || n == "geo" || n ~ /_by_lua_block$/) }
    # Directives that set a header or parameter whose value is secret when its name is.
    function hdr_dir(n) { return (n ~ /^(proxy_set_header|add_header|add_trailer|grpc_set_header|fastcgi_param|uwsgi_param|scgi_param|auth_http_header)$/) }
    function hdr_secret(n, h) {
      if (h ~ /(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)/) return 1
      return (n ~ /_param$/ && h ~ /(pass|pwd)/)
    }
    # Redacts the value of every secret-named directive on the line: at line start, after ";", "{" or "}", and in comments.
    # cont is set when line is the rest of a statement, so it is scanned for statements from its first character.
    # Statements that go on over later lines set hdr (and hq, a quote still open), so those lines are redacted up to their ";".
    function scrub(line, cont,    out, rest, first, ok, m, name, lname, e, incm, isl, b, tl, hname, after, ws, v) {
      out = ""; rest = line; first = !cont; incm = (line ~ /^[ \t]*#/)
      while (1) {
        if (first) ok = match(rest, /^[ \t]*#*[ \t]*[A-Za-z0-9_]+[ \t]+/)
        else ok = match(rest, /[;{}#][ \t]*[A-Za-z0-9_]+[ \t]+/)
        if (!ok) break
        m = substr(rest, RSTART, RLENGTH)
        out = out substr(rest, 1, RSTART + RLENGTH - 1)
        rest = substr(rest, RSTART + RLENGTH)
        if (!first && substr(m, 1, 1) == "#") incm = 1
        first = 0
        name = m; sub(/^[ \t]*[;{}#]*[ \t]*/, "", name); sub(/[ \t]+$/, "", name)
        lname = tolower(name)
        if (block_name(lname)) {
          if (incm) continue
          isl = (lname != "map" && lname != "geo")
          b = find_brace(rest)
          if (b > 0) { out = out open_block(rest, b, isl); rest = blk_rest; if (depth > 0) break; continue }
          if (b == 0) { pend = 1; plua = isl; break }
          continue
        }
        if (lname ~ /_by_lua$/) {
          e = stmt_end(rest, 1, "")
          out = out "<redacted>"
          if (e) { rest = substr(rest, e); continue }
          if (!incm) { hdr = 1; hq = endq }
          rest = ""; break
        }
        if (lname ~ /^more_set_(input_)?headers$/) {
          if (!stmt_end(rest, 1, "") && !incm) { hdr = 1; hq = endq }
          continue
        }
        if (hdr_dir(lname)) {
          tl = tok_len(rest)
          if (tl == 0) continue
          hname = tolower(substr(rest, 1, tl)); gsub("[\"" sq "]", "", hname)
          if (!hdr_secret(lname, hname)) continue
          after = substr(rest, tl + 1)
          match(after, /^[ \t]*/); ws = RLENGTH
          v = substr(after, ws + 1)
          if (v ~ /^(#|$)/) { if (!incm) { hdr = 1; hq = "" }; continue }
          if (v ~ /^;/) continue
          e = stmt_end(v, 1, "")
          out = out substr(rest, 1, tl + ws) "<redacted>"
          if (e) { rest = substr(v, e); continue }
          if (!incm) { hdr = 1; hq = endq }
          rest = ""; break
        }
        if (!secret_name(lname)) continue
        # Only a ";"-terminated statement is a directive; sshd -T prints "passwordauthentication yes" without one.
        e = stmt_end(rest, 1, "")
        if (e) { out = out "<redacted>"; rest = substr(rest, e); continue }
        if (endq != "") {
          out = out "<redacted>"
          if (!incm) { hdr = 1; hq = endq }
          rest = ""; break
        }
      }
      # A directive alone on its line: its value (or a map body brace) is on the next lines.
      if (!cont && !incm && match(line, /^[ \t]*[A-Za-z0-9_]+[ \t]*(#.*)?$/)) {
        name = line; sub(/^[ \t]*/, "", name); sub(/[^A-Za-z0-9_].*$/, "", name); lname = tolower(name)
        if (block_name(lname)) { pend = 1; plua = (lname != "map" && lname != "geo") }
        else if (secret_name(lname) || hdr_dir(lname) || lname ~ /^more_set_(input_)?headers$/ || lname ~ /_by_lua$/) { hdr = 1; hq = "" }
      }
      return out rest
    }
    # Redacts the body of a map, geo or Lua block whose "{" is at index b of s: returns s up to the brace plus a marker, and sets
    # blk_rest to the text from the closing "}" on. While the body goes on over later lines blk_rest is empty and depth is set.
    function open_block(s, b, isl,    c) {
      c = scan(s, b, 0, isl)
      if (c) { blk_rest = substr(s, c); return substr(s, 1, b) " <redacted> " }
      depth = sdepth; blua = isl; blk_rest = ""
      return substr(s, 1, b) (isl ? " # lua code redacted" : " # map/geo values redacted")
    }
    function proc(line,    c, b, v, lead, e, rest) {
      if (depth > 0) {
        if (lost(line)) { print MARK; depth = 0 }
        else {
          c = scan(line, 1, depth, blua)
          if (!c) { depth = sdepth; return }
          depth = 0
          print blua ? "    } # lua code redacted" : "    } # map/geo values redacted"
          rest = substr(line, c + 1)
          if (rest ~ /[^ \t]/) proc(rest)
          return
        }
      }
      if (hdr) {
        # The rest of a statement whose value is on later lines: redact it up to its ";" and no further.
        if (hq == "" && (line !~ /[^ \t]/ || line ~ /^[ \t]*#/)) { print scrub(line, 0); return }
        if (hq == "" && lost(line)) { print MARK; hdr = 0 }
        else {
          match(line, /^[ \t]*/); lead = substr(line, 1, RLENGTH); e = stmt_end(line, 1, hq)
          if (e) { hdr = 0; hq = ""; print lead "<redacted>" scrub(substr(line, e), 1); return }
          hq = endq
          print lead "<redacted>"; return
        }
      }
      if (pend) {
        b = find_brace(line)
        if (b > 0) { pend = 0; v = open_block(line, b, plua); print v scrub(blk_rest, 1); return }
        if (b < 0) pend = 0
      }
      print scrub(line, 0)
    }
    { proc($0) }
    END { if (depth > 0 || (hdr && hq != "")) print MARK }
  ' | sed -E \
    -e 's/^([[:space:]]*env[[:space:]]+[A-Za-z0-9_]+=)[^;]+/\1<redacted>/' \
    -e 's/([?&][A-Za-z0-9_.-]*(key|token|secret|sig|passw|auth)[A-Za-z0-9_.-]*=)[^&[:space:]"'"'"';]+/\1<redacted>/Ig' \
    -e 's/(\$[A-Za-z0-9_]*(secret|token|passw|api[_-]?key|private|jwt)[A-Za-z0-9_]*[[:space:]]+)[^;{]+/\1<redacted>/Ig' \
    -e 's/((proxy_set_header|add_header|add_trailer|more_set_headers|grpc_set_header|fastcgi_param|uwsgi_param|scgi_param|auth_http_header)[[:space:]]+"?[A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[A-Za-z0-9_-]*"?[[:space:]]+)[^;]+/\1<redacted>/Ig' \
    -e '/more_set_(input_)?headers/I s/("[[:space:]]*[A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[A-Za-z0-9_-]*[[:space:]]*:[[:space:]]*)[^"]*/\1<redacted>/Ig' \
    -e '/more_set_(input_)?headers/I s/('"'"'[[:space:]]*[A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[A-Za-z0-9_-]*[[:space:]]*:[[:space:]]*)[^'"'"']*/\1<redacted>/Ig' \
    -e '/more_set_(input_)?headers/I s/([[:space:]][A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key|key|auth|credential|session|signature)[A-Za-z0-9_-]*:)[^[:space:];"'"'"']+/\1<redacted>/Ig' \
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

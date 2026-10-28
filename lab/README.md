# secagent lab

Two nginx sites on a Docker bridge network (Linux hosts only: the host must route to 172.31.250.0/24):

| Site | Address | Configuration |
|---|---|---|
| bad-site | 172.31.250.10 | Plain HTTP served, no security headers, `server_tokens on`, `X-Powered-By`, insecure cookie, TLS 1.0/1.1 and CBC ciphers, `/.env`, `/.git/config` and a source map exposed, port 6379 open |
| good-site | 172.31.250.11 | Hardened, with an SPA fallback |

Both use self-signed certificates, so `tls-cert-valid` fails on both. That is expected.

```bash
sh lab/gen-certs.sh
docker compose -f lab/docker-compose.yml up -d
npm run dev -- scan --no-ai --dir lab/project
SECAGENT_LAB=1 npx vitest run test/lab.e2e.test.ts
docker compose -f lab/docker-compose.yml down
```

Expected outcomes:

| Check | bad-site | good-site |
|---|---|---|
| http-redirect-https | fail | pass |
| hdr-hsts, hdr-csp, hdr-frame-options, hdr-content-type-options, hdr-referrer-policy, hdr-permissions-policy | fail | pass |
| hdr-x-powered-by, hdr-server-version | fail | pass |
| cookie-flags | fail | pass |
| header-budget | pass | pass |
| exposed-paths | fail (critical: .env, .git/config, app.js.map) | pass |
| tls-no-legacy, tls-modern | fail | pass |
| tls-cert-valid | fail (self-signed) | fail (self-signed) |

| Check | bad-host | good-host |
|---|---|---|
| ports-exposed | fail (6379/redis) | pass |

## Host checks

The collector also runs inside the lab containers, which needs network access from the containers for `apt-get update`:

```bash
docker compose -f lab/docker-compose.yml up -d
sh lab/collect-snapshots.sh
SECAGENT_LAB=1 npx vitest run test/lab-host.e2e.test.ts
npm run dev -- verify --dir lab/project --host bad-host --cve CVE-2024-6387
docker compose -f lab/docker-compose.yml down
```

The lab image `nginx:1.30.6` (Debian 13) has no `sshd`, no `ss` and no unattended-upgrades. Its nginx comes from nginx.org, which the image doesn't configure as an apt source, so after `apt-get update` it shows as "installed locally". Expected results:

| Check | bad-host | good-host |
|---|---|---|
| host-ssh-password-auth, host-ssh-root-login | pass (sshd not installed) | pass |
| host-nginx-server-tokens, host-nginx-ssl-protocols | fail | pass |
| host-listening-databases | unverifiable (no `ss`) | unverifiable |
| host-auto-upgrades | fail | fail |
| host-package-third-party | fail (nginx from nginx.org) | fail |
| host-reboot-pending | pass | pass |
| host-package-advisories | live result (network), never `error` | same |

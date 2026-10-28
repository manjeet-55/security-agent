# secagent Plan 2: Host Collector, Advisories and `verify_claim`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-side security checks to secagent. A read-only collector script gathers each host's state. Host checks evaluate it: SSH and nginx config, listening ports, auto-updates, packages with missing security fixes, third-party packages and pending reboots. Package versions are checked against authoritative distro advisories (OSV, Ubuntu's CVE tracker and CISA's exploited-vulnerabilities list), and `verify_claim` gives an evidence-backed verdict on a third-party scanner's CVE claim.

**Architecture:**
- **Collection:** `assets/collector.sh` prints one JSON object of base64 sections. A developer runs it on the host (SSH, SSM or the console) and stores the output with `secagent snapshot add`. secagent itself never logs into servers.
- **Snapshots:** `src/host/` decodes them into a typed `HostSnapshot`.
- **Advisories:** `src/advisories/` fetches advisory JSON over HTTPS from three allowlisted hosts only, through a TTL cache in the user's cache directory.
- **Host checks:** two new check types, `host_config` and `host_package`, read the newest snapshot through `CheckContext`.
- **Claims:** `verifyClaim` maps a claim to `fixed_in_installed`, `not_affected`, `vulnerable`, `no_fix_available` or `unverifiable`, preferring the distro's own tracker.
- **CLI:** new commands `collector`, `snapshot add`, `verify` and `learn`.

**Tech Stack:** unchanged from Plan 1 as amended: TypeScript 6, Node ≥20.19, zod 4, yaml 2, vitest 4.1.12. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-28-secagent-design.md`, §6.2 (`host_config`, `host_package`), §7, §7.1, §8.2.1, §8.5 and §11 (`learn`, plus the new `collector`, `snapshot` and `verify` commands).

**Roadmap:** Plan 1 is done. This is Plan 2. Plan 3 covers the knowledge base, MCP server, playbook and reports; Plan 4 covers learning, the Claude plugin and eval. NVD CVSS lookups are deferred, the first item on the spec's cut order. Ubuntu's own priority, or "medium" when absent, is used instead.

**Verified during planning (2026-10-28):**
- **OSV API:**
  - Ecosystems `Ubuntu:24.04:LTS`, `Ubuntu:22.04:LTS`, `Debian:12` and `Debian:13` work.
  - Queries must use **source** package names: `openssh` returns results, `openssh-server` returns none.
  - `UBUNTU-CVE-2024-6387` gives fixed `1:9.6p1-3ubuntu13.3` for noble.
  - `/v1/querybatch` returns ids only. `/v1/query` returns full vulns, with a `{type:"Ubuntu", score:"high"}` priority.
- **Ubuntu CVE JSON** (`https://ubuntu.com/security/cves/<CVE>.json`) gives per-release statuses: `released` (the description is the fixed version), `not-affected`, `ignored`, `needed`, `deferred`, `DNE` and so on.
- **CISA KEV:** the feed is `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,760 entries, ~1.8 MB).
- **Version comparison:** all 14 `compareDebVersions` vectors in Task 1 were checked with real `dpkg --compare-versions`.
- **Collector:** `assets/collector.sh` ran unchanged in `ubuntu:24.04`, `ubuntu:22.04` and `debian:12` containers with openssh, nginx and unattended-upgrades installed.
  - Planted secrets (`set $api_token`, `X-Api-Key`, a Bearer token, `user:token@` in an apt URL) were redacted.
  - `passwordauthentication`, `server_tokens` and `ssl_protocols` survived.
  - The outputs are committed as `test/fixtures/collector/*.json`.
- **Fixtures:** recorded advisory responses are in `test/fixtures/advisories/`.
- **The lab image `nginx:1.30.6`** is Debian 13 (trixie). It has no `ss` and no `sshd`. Its apt sources list only Debian, so its nginx.org-built `nginx 1.30.6-1~trixie` shows as installed locally after `apt-get update`.

## Global Constraints

- **Plan 1 still applies, as amended:**
  - Node `>=20.19`, ESM, strict TypeScript with `noUncheckedIndexedAccess`, `.js` import suffixes.
  - Dev pins: `vitest@4.1.12`, `vite@7.3.7`, `@types/node@20.19.43`.
  - The only runtime dependencies are `yaml@2.9.1` and `zod@4.6.7`. Add **no** dependencies.
- **Advisory network access** goes only through `createFetchJson`:
  - HTTPS only, with certificate verification on.
  - Host allowlist exactly `api.osv.dev`, `ubuntu.com` and `www.cisa.gov`.
  - No redirects followed. 30 s timeout, 8 MB cap.
- **Target probes** still go only through `ScopedNet`. Advisory fetches are not target probes and never use it.
- **Advisory cache:**
  - Location: `$SECAGENT_CACHE_DIR` if set, else `~/.cache/secagent/advisories`. Never inside the package directory.
  - TTLs: KEV 1 day, OSV 3 days, Ubuntu 3 days.
  - On fetch failure, serve the stale copy. With no copy, raise `ObservationError('ADVISORY_UNAVAILABLE')`.
- **Snapshots:**
  - Stored at `.secagent/hosts/<host>/<collected_at>.json` (already git-ignored).
  - Host checks use the newest snapshot only if it is ≤ 7 days old. Otherwise the result is `unverifiable`.
  - secagent never connects to hosts to collect.
- **Host-check evidence** holds only the snapshot file name, `collected_at` and the excerpt the rule used. It never holds whole snapshots.
- **Unverifiable results:** `ObservationError` (no snapshot, stale snapshot, tool missing, advisory source down, unsupported distro) is reported as `unverifiable`, never `pass`.
- **Tests run offline** against fixtures. Live advisory calls happen only in tests gated by `SECAGENT_LIVE=1`, and Docker only in tests gated by `SECAGENT_LAB=1`.
- **No client or project names, IPs or hostnames** anywhere. Commits are pre-approved and carry no AI attribution.

## File Structure

```
assets/collector.sh                 read-only POSIX sh collector (shipped; package.json "files" += "assets")
src/util/debver.ts                  compareDebVersions (deb-version(7))
src/checks/errors.ts                ObservationError (→ unverifiable)
src/host/parse.ts                   section parsers (os-release, dpkg, apt policy, sshd -T, ss, nginx directives, ...)
src/host/snapshot.ts                envelope schema, SectionState, HostSnapshot, decodeSnapshot
src/host/origin.ts                  classifyOrigin, aptListsEmpty
src/host/collector.ts               COLLECTOR_PATH, makeCollector
src/host/store.ts                   SnapshotStore, SnapshotReader, MAX_SNAPSHOT_AGE_DAYS
src/advisories/types.ts             OsvVuln, UbuntuCve, sources + Advisories interfaces
src/advisories/fetch.ts             createFetchJson (allowlisted HTTPS JSON)
src/advisories/cache.ts             AdvisoryCache, TTL, defaultCacheDir
src/advisories/osv.ts               OsvClient, fixedVersionFor, cveIdsOf, ubuntuPriority
src/advisories/ubuntu.ts            UbuntuCveClient
src/advisories/kev.ts               KevClient, KEV_URL
src/advisories/distro.ts            distroOf → ecosystem/codename
src/advisories/index.ts             createAdvisories
src/checks/types/host-config.ts     host_config type (sshd_value | nginx_directive | listening | auto_upgrades)
src/checks/types/host-package.ts    host_package type (advisories | third_party | reboot) + distroSources, findFixable
src/verify/claim.ts                 verifyClaim, ClaimResult
knowledge/checks/host-*.yaml        9 seed instances
lab/collect-snapshots.sh            runs the collector in the lab containers
```

Modified: `src/checks/context.ts`, `src/checks/runner.ts`, `src/checks/registry.ts`, `src/evidence/store.ts`, `src/scan/no-ai.ts`, `src/cli.ts`, `package.json`, `.gitignore`, `test/helpers/ctx.ts`, `test/checks/types/tls.test.ts`, `lab/README.md`, spec.

---

### Task 1: Debian version comparison

**Files:**
- Create: `src/util/debver.ts`
- Test: `test/util/debver.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces: `compareDebVersions(a: string, b: string): -1 | 0 | 1 | number` (negative = a older, 0 = equal, positive = a newer)

- [ ] **Step 1: Write the failing test**

`test/util/debver.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { compareDebVersions } from '../../src/util/debver.js';

// Every vector was checked with `dpkg --compare-versions` on 2026-10-28.
const VECTORS: Array<[string, 'lt' | 'eq' | 'gt', string]> = [
  ['1:9.6p1-3ubuntu13.20', 'gt', '1:9.6p1-3ubuntu13.3'],
  ['1.0~rc1', 'lt', '1.0'],
  ['1.0+b1', 'gt', '1.0'],
  ['1:1.0', 'gt', '2.0'],
  ['2.30-1ubuntu1', 'gt', '2.30-1'],
  ['1.30.6-1~noble', 'lt', '1.30.6-1'],
  ['1.0a', 'lt', '1.0+'],
  ['1.0', 'eq', '1.0-0'],
  ['0:1.0', 'eq', '1.0'],
  ['1.2.3', 'lt', '1.2.10'],
  ['1.0~~', 'lt', '1.0~'],
  ['1.0-1', 'lt', '1.0.0-1'],
  ['8.9p1-3ubuntu0.18', 'gt', '8.9p1-3ubuntu0.10'],
  ['3.0.13-0ubuntu3.4', 'lt', '3.0.13-0ubuntu3.10'],
];

describe('compareDebVersions', () => {
  it.each(VECTORS)('%s %s %s', (a, rel, b) => {
    const r = compareDebVersions(a, b);
    expect(rel === 'lt' ? r < 0 : rel === 'gt' ? r > 0 : r === 0).toBe(true);
    const back = compareDebVersions(b, a);
    expect(rel === 'lt' ? back > 0 : rel === 'gt' ? back < 0 : back === 0).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run test/util/debver.test.ts`
Expected: FAIL, because `../../src/util/debver.js` can't be resolved.

- [ ] **Step 3: Implement `src/util/debver.ts`**

```ts
/** Debian version comparison (deb-version(7)): epoch, then upstream version, then revision; `~` sorts before everything. */
export function compareDebVersions(a: string, b: string): number {
  const pa = split(a);
  const pb = split(b);
  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  return compareFragment(pa.upstream, pb.upstream) || compareFragment(pa.revision, pb.revision);
}

function split(version: string): { epoch: number; upstream: string; revision: string } {
  const v = version.trim();
  const colon = v.indexOf(':');
  const epoch = colon === -1 ? 0 : Number(v.slice(0, colon)) || 0;
  const rest = colon === -1 ? v : v.slice(colon + 1);
  const dash = rest.lastIndexOf('-');
  return dash === -1 ? { epoch, upstream: rest, revision: '' } : { epoch, upstream: rest.slice(0, dash), revision: rest.slice(dash + 1) };
}

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

/** dpkg's order(): digits and end-of-string 0, `~` -1, letters their code, other characters code + 256. */
function order(c: string | undefined): number {
  if (c === undefined || isDigit(c)) return 0;
  if (c === '~') return -1;
  if (/^[A-Za-z]$/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}

function compareFragment(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = order(a[i]);
      const bc = order(b[j]);
      if (ac !== bc) return ac < bc ? -1 : 1;
      i += 1;
      j += 1;
    }
    while (a[i] === '0') i += 1;
    while (b[j] === '0') j += 1;
    while (isDigit(a[i]) && isDigit(b[j])) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i += 1;
      j += 1;
    }
    if (isDigit(a[i])) return 1;
    if (isDigit(b[j])) return -1;
    if (firstDiff) return firstDiff < 0 ? -1 : 1;
  }
  return 0;
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/util/debver.test.ts && npx tsc -p tsconfig.json`
Expected: 14 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/util/debver.ts test/util/debver.test.ts
git commit -m "feat(util): add Debian version comparison"
```

---

### Task 2: Collector script and `makeCollector`

**Files:**
- Create: `assets/collector.sh`, `src/host/collector.ts`
- Modify: `package.json` (`files`)
- Test: `test/host/collector.test.ts`

**Interfaces:**
- Consumes: `PACKAGE_ROOT`, `projectStateDir` (Plan 1 `src/paths.ts`)
- Produces:
  - `COLLECTOR_PATH`
  - `interface CollectorBundle { script: string; sha256: string; instructions: string; dropDir: string }`
  - `makeCollector(projectDir, host): Promise<CollectorBundle>`

- [ ] **Step 1: Write `assets/collector.sh` exactly as below**

This was verified in Ubuntu 24.04, Ubuntu 22.04 and Debian 12 containers. Do not alter the redaction rules or the section commands.

```sh
#!/bin/sh
# secagent host collector (schema 1). READ-ONLY: it only reads package, SSH, nginx and socket state.
# Run on the host as root so `sshd -T` and `nginx -T` work:  sudo sh collect.sh > snapshot.json
# Output: one JSON object. Each section is base64 of the command output after secret redaction.
set -u
export LC_ALL=C

redact() {
  sed -E \
    -e 's/(\$[A-Za-z0-9_]*(secret|token|passw|api[_-]?key|private)[A-Za-z0-9_]*[[:space:]]+)[^;{]+/\1<redacted>/Ig' \
    -e 's/((proxy_set_header|add_header|more_set_headers|grpc_set_header|fastcgi_param|uwsgi_param|scgi_param)[[:space:]]+"?[A-Za-z0-9_-]*(authorization|cookie|token|secret|passw|api[_-]?key)[A-Za-z0-9_-]*"?[[:space:]]+)[^;]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]{8,}/\1<redacted>/g' \
    -e 's#(://)[^/@[:space:]"]+:[^/@[:space:]"]+@#\1<redacted>@#g'
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
emit reboot 'if [ -f /var/run/reboot-required ]; then echo required; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo not-required; fi'
emit sshd 'sshd=$(command -v sshd || echo /usr/sbin/sshd); "$sshd" -T'
emit nginx 'nginx -T'
emit listening 'ss -tlnpH'
printf '}}\n'
```

- [ ] **Step 2: Add `"assets"` to `package.json` `files`**

The array becomes `["dist", "knowledge", "agent", "assets"]`.

- [ ] **Step 3: Write the failing test**

`test/host/collector.test.ts`:
```ts
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { COLLECTOR_PATH, makeCollector } from '../../src/host/collector.js';

const SCRIPT = readFileSync(COLLECTOR_PATH, 'utf8');
const linuxWithSh = process.platform === 'linux' && existsSync('/bin/sh');

describe('makeCollector', () => {
  it('bundles the script with its sha256, drop dir and instructions', async () => {
    const b = await makeCollector('/work/app', 'web-1');
    expect(b.script).toBe(SCRIPT);
    expect(b.sha256).toBe(createHash('sha256').update(SCRIPT).digest('hex'));
    expect(b.dropDir).toBe(path.join('/work/app', '.secagent', 'hosts', 'web-1'));
    expect(b.instructions).toContain('sudo sh collect.sh > web-1.json');
    expect(b.instructions).toContain('secagent snapshot add --host web-1 web-1.json');
    expect(b.instructions).toContain(b.sha256);
  });
});

describe.runIf(linuxWithSh)('collector.sh', () => {
  it('is valid POSIX sh', () => {
    expect(spawnSync('sh', ['-n', COLLECTOR_PATH]).status).toBe(0);
  });

  it('redacts secrets but keeps config keys the checks need', () => {
    const fn = /redact\(\) \{[\s\S]*?\n\}/.exec(SCRIPT)?.[0];
    expect(fn).toBeDefined();
    const input = [
      'passwordauthentication yes',
      '\tserver_tokens off;',
      '\tset $api_token "s3cretA1";',
      '\tproxy_set_header X-Api-Key "s3cretB2";',
      '\tproxy_set_header Authorization "Bearer abcdefghijkl12345";',
      '\tproxy_set_header Host $host;',
      'deb https://user:tok3nvalue@repo.example.invalid/x stable main',
    ].join('\n');
    const out = spawnSync('sh', ['-c', `${fn}\nredact`], { input, encoding: 'utf8' }).stdout;
    for (const secret of ['s3cretA1', 's3cretB2', 'abcdefghijkl12345', 'tok3nvalue']) expect(out).not.toContain(secret);
    expect(out).toContain('passwordauthentication yes');
    expect(out).toContain('server_tokens off;');
    expect(out).toContain('proxy_set_header Host $host;');
  });
});
```

- [ ] **Step 4: Run to verify it fails**

Run: `npx vitest run test/host/collector.test.ts`
Expected: FAIL, because `../../src/host/collector.js` can't be resolved.

- [ ] **Step 5: Implement `src/host/collector.ts`**

```ts
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { PACKAGE_ROOT, projectStateDir } from '../paths.js';

export const COLLECTOR_PATH = path.join(PACKAGE_ROOT, 'assets', 'collector.sh');

export interface CollectorBundle {
  script: string;
  sha256: string;
  instructions: string;
  dropDir: string;
}

/** The read-only collector plus the steps to run it on a host and bring the output back. */
export async function makeCollector(projectDir: string, host: string): Promise<CollectorBundle> {
  const script = await readFile(COLLECTOR_PATH, 'utf8');
  const sha256 = createHash('sha256').update(script).digest('hex');
  const dropDir = path.join(projectStateDir(projectDir), 'hosts', host);
  const instructions = [
    `secagent host collector for "${host}" (read-only, sha256 ${sha256})`,
    '1. Copy collect.sh to the host (scp, AWS SSM Session Manager, or paste it into a console) and review it.',
    `2. On the host run:  sudo sh collect.sh > ${host}.json`,
    `3. Bring ${host}.json back and run:  secagent snapshot add --host ${host} ${host}.json`,
    `Snapshots are stored under ${dropDir} (git-ignored).`,
  ].join('\n');
  return { script, sha256, instructions, dropDir };
}
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/host/collector.test.ts && npx tsc -p tsconfig.json`
Expected: 3 tests PASS on Linux (1 elsewhere); `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add assets/collector.sh src/host/collector.ts package.json test/host/collector.test.ts
git commit -m "feat(host): add read-only collector script and bundle"
```

---

### Task 3: `ObservationError`, snapshot decoding, parsers and package origins

**Files:**
- Create: `src/checks/errors.ts`, `src/host/parse.ts`, `src/host/snapshot.ts`, `src/host/origin.ts`, `test/helpers/snapshots.ts`
- Test: `test/host/parse.test.ts`, `test/host/snapshot.test.ts`, `test/host/origin.test.ts`

**Interfaces:**
- Consumes: the fixture files in `test/fixtures/collector/` (already committed)
- Produces:
  - `class ObservationError extends Error { code: string }`
  - parse types `OsRelease { id; version_id; codename; pretty_name }`, `InstalledPackage { name; arch?; version; source; source_version }`, `PackageOrigin { installed; sources: string[] }`, `ListeningSocket { address; port; process? }`
  - parse functions `parseOsRelease`, `parsePackages`, `parseAptPolicy`, `parseSshdT`, `parseListening`, `parseAutoUpgrades`, `parseReboot`, `nginxDirectiveValues(config, directive): string[]`
  - snapshot exports `SnapshotEnvelopeSchema`, `type SnapshotEnvelope`, `type SectionState<T>`, `interface HostSnapshot`, `decodeSnapshot(raw): HostSnapshot` (throws `ObservationError('SNAPSHOT_INVALID')`)
  - origin exports `type OriginKind`, `classifyOrigin(origin, codename): { kind; repo? }`, `aptListsEmpty(origins): boolean`
  - test helpers `fixtureEnvelope(name)`, `fixtureSnapshot(name)`, `sectionOf(env, name)`, `withSection(env, name, text, rc?)`, `withSourceVersion(env, source, version)`, `readerFor(snapshot?, file?)`

- [ ] **Step 1: Write the test helper and failing tests**

`test/helpers/snapshots.ts`:
```ts
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { decodeSnapshot, type HostSnapshot, type SnapshotEnvelope } from '../../src/host/snapshot.js';
import type { SnapshotReader } from '../../src/host/store.js';

const DIR = path.join(import.meta.dirname, '..', 'fixtures', 'collector');
export type FixtureName = 'ubuntu-24-04' | 'ubuntu-22-04' | 'debian-12';

export function fixtureEnvelope(name: FixtureName): SnapshotEnvelope {
  return JSON.parse(readFileSync(path.join(DIR, `${name}.json`), 'utf8')) as SnapshotEnvelope;
}

export function fixtureSnapshot(name: FixtureName): HostSnapshot {
  return decodeSnapshot(fixtureEnvelope(name));
}

export function sectionOf(env: SnapshotEnvelope, name: string): string {
  const s = env.sections[name];
  return s ? Buffer.from(s.b64, 'base64').toString('utf8') : '';
}

/** A copy of the envelope with one section replaced. */
export function withSection(env: SnapshotEnvelope, name: string, text: string, rc = 0): SnapshotEnvelope {
  return { ...env, sections: { ...env.sections, [name]: { rc, b64: Buffer.from(text, 'utf8').toString('base64') } } };
}

/** A copy where every binary built from `source` reports the given version. */
export function withSourceVersion(env: SnapshotEnvelope, source: string, version: string): SnapshotEnvelope {
  const lines = sectionOf(env, 'packages')
    .split('\n')
    .map((line) => {
      const cols = line.split('\t');
      if (cols[3] === source) {
        cols[2] = version;
        cols[4] = version;
      }
      return cols.join('\t');
    });
  return withSection(env, 'packages', lines.join('\n'));
}

/** A SnapshotReader serving one snapshot (or none) for every host. Store is defined in Task 6; only its type is used here. */
export function readerFor(snapshot: HostSnapshot | undefined, file = '/fixtures/20261028T143146Z.json'): SnapshotReader {
  return { latest: async () => (snapshot ? { snapshot, file } : undefined) };
}
```

Note: `readerFor` imports a type from `src/host/store.ts`, which Task 6 creates. To keep this task compiling, add a placeholder in Step 3: `src/host/store.ts` holding only the two type exports shown there. Task 6 completes the file.

`test/host/parse.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import {
  nginxDirectiveValues,
  parseAptPolicy,
  parseAutoUpgrades,
  parseListening,
  parseOsRelease,
  parsePackages,
  parseReboot,
  parseSshdT,
} from '../../src/host/parse.js';

describe('parsers', () => {
  it('reads os-release with quoted values', () => {
    expect(parseOsRelease('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n')).toEqual({
      id: 'ubuntu',
      version_id: '24.04',
      codename: 'noble',
      pretty_name: 'Ubuntu 24.04.3 LTS',
    });
  });

  it('keeps installed packages only, splitting arch and defaulting source', () => {
    const text = 'ii \tlibssl3t64:amd64\t3.0.13-0ubuntu3.16\topenssl\t3.0.13-0ubuntu3.16\nrc \told\t1.0\told\t1.0\nii \tbash\t5.2-1\t\t\n';
    expect(parsePackages(text)).toEqual([
      { name: 'libssl3t64', arch: 'amd64', version: '3.0.13-0ubuntu3.16', source: 'openssl', source_version: '3.0.13-0ubuntu3.16' },
      { name: 'bash', version: '5.2-1', source: 'bash', source_version: '5.2-1' },
    ]);
  });

  it('reads the installed version origins from apt-cache policy', () => {
    const text = [
      'nginx:',
      '  Installed: 1.30.6-1~noble',
      '  Candidate: 1.30.6-1~noble',
      '  Version table:',
      ' *** 1.30.6-1~noble 500',
      '        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages',
      '        100 /var/lib/dpkg/status',
      '     1.24.0-2ubuntu7.19 500',
      '        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages',
      'libssl3t64:',
      '  Installed: 3.0.13-0ubuntu3.16',
      ' *** 3.0.13-0ubuntu3.16 500',
      '        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages',
    ].join('\n');
    expect(parseAptPolicy(text)).toEqual({
      nginx: {
        installed: '1.30.6-1~noble',
        sources: ['http://nginx.org/packages/ubuntu noble/nginx amd64 Packages', '/var/lib/dpkg/status'],
        available: [{ version: '1.24.0-2ubuntu7.19', sources: ['http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages'] }],
      },
      libssl3t64: {
        installed: '3.0.13-0ubuntu3.16',
        sources: ['http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages'],
        available: [],
      },
    });
  });

  it('parses sshd -T keys in lowercase and joins repeated keys', () => {
    expect(parseSshdT('PasswordAuthentication yes\nhostkey /a\nhostkey /b\n')).toEqual({ passwordauthentication: 'yes', hostkey: '/a /b' });
  });

  it('parses ss -tlnpH including IPv6, wildcard and interface-scoped addresses', () => {
    const text = [
      'LISTEN 0      511    0.0.0.0:80   0.0.0.0:* users:(("nginx",pid=1,fd=6))',
      'LISTEN 0      128       [::]:22      [::]:* users:(("sshd",pid=2,fd=4))',
      'LISTEN 0      4096   127.0.0.53%lo:53 0.0.0.0:*',
      'LISTEN 0      100          *:5432       *:*',
    ].join('\n');
    expect(parseListening(text)).toEqual([
      { address: '0.0.0.0', port: 80, process: 'nginx' },
      { address: '::', port: 22, process: 'sshd' },
      { address: '127.0.0.53', port: 53 },
      { address: '*', port: 5432 },
    ]);
  });

  it('reads unattended-upgrades state and reboot state', () => {
    expect(parseAutoUpgrades('APT::Periodic::Unattended-Upgrade "1";\nii unattended-upgrades\n')).toEqual({ enabled: true, installed: true });
    expect(parseAutoUpgrades('')).toEqual({ enabled: false, installed: false });
    expect(parseReboot('required\nlinux-image-6.8.0-1\nlibc6\n')).toEqual({ required: true, packages: ['linux-image-6.8.0-1', 'libc6'] });
    expect(parseReboot('not-required\n')).toEqual({ required: false, packages: [] });
  });

  it('finds nginx directive values and ignores comments', () => {
    const conf = '\t# server_tokens off;\n\tserver_tokens on;\nserver { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }\n';
    expect(nginxDirectiveValues(conf, 'server_tokens')).toEqual(['on']);
    expect(nginxDirectiveValues(conf, 'ssl_protocols')).toEqual(['TLSv1.2 TLSv1.3']);
    expect(nginxDirectiveValues(conf, 'gzip')).toEqual([]);
  });
});
```

`test/host/snapshot.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { decodeSnapshot } from '../../src/host/snapshot.js';
import { fixtureEnvelope, fixtureSnapshot, withSection } from '../helpers/snapshots.js';

describe('decodeSnapshot (real container outputs)', () => {
  it('decodes Ubuntu 24.04', () => {
    const s = fixtureSnapshot('ubuntu-24-04');
    expect(s.os).toMatchObject({ id: 'ubuntu', version_id: '24.04', codename: 'noble' });
    expect(s.is_root).toBe(true);
    expect(s.packages.find((p) => p.name === 'openssh-server')).toMatchObject({ source: 'openssh', source_version: '1:9.6p1-3ubuntu13.20' });
    expect(s.origins['openssh-server']?.sources.some((x) => x.includes('noble-security/main'))).toBe(true);
    expect(s.sshd).toMatchObject({ state: 'ok', value: { passwordauthentication: 'yes', permitrootlogin: 'without-password' } });
    expect(s.nginx.state).toBe('ok');
    expect(s.listening.state === 'ok' && s.listening.value.some((l) => l.port === 22)).toBe(true);
    expect(s.auto_upgrades).toEqual({ enabled: true, installed: true });
    expect(s.reboot).toEqual({ required: false, packages: [] });
  });

  it('decodes Ubuntu 22.04 and Debian 12', () => {
    expect(fixtureSnapshot('ubuntu-22-04').os.codename).toBe('jammy');
    const d = fixtureSnapshot('debian-12');
    expect(d.os).toMatchObject({ id: 'debian', version_id: '12', codename: 'bookworm' });
    expect(d.packages.find((p) => p.name === 'openssh-server')?.source_version).toBe('1:9.2p1-2+deb12u10');
  });

  it('contains no planted secrets', () => {
    for (const name of ['ubuntu-24-04', 'ubuntu-22-04', 'debian-12'] as const) {
      const s = fixtureSnapshot(name);
      const text = s.nginx.state === 'ok' ? s.nginx.value : '';
      expect(text).toContain('<redacted>');
      for (const secret of ['s3cretA1value', 's3cretB2value', 'abcdefghijklmnop12345']) expect(text).not.toContain(secret);
    }
  });

  it('maps exit code 127 to absent and other failures to error', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const absent = decodeSnapshot(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127));
    expect(absent.sshd).toEqual({ state: 'absent', reason: 'sh: 1: /usr/sbin/sshd: not found' });
    const error = decodeSnapshot(withSection(env, 'sshd', 'sshd: no hostkeys available -- exiting.', 255));
    expect(error.sshd).toEqual({ state: 'error', reason: 'sshd: no hostkeys available -- exiting.' });
  });

  it('tolerates a missing dpkg (non-Debian host) but requires os-release', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    expect(decodeSnapshot(withSection(env, 'packages', 'sh: 1: dpkg-query: not found', 127)).packages).toEqual([]);
    expect(() => decodeSnapshot(withSection(env, 'os_release', '', 1))).toThrow(ObservationError);
    expect(() => decodeSnapshot({ schema: 2 })).toThrow(/Not a secagent collector snapshot/);
  });
});
```

`test/host/origin.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { aptListsEmpty, classifyOrigin } from '../../src/host/origin.js';

const o = (...sources: string[]) => ({ installed: '1', sources, available: [] });

describe('classifyOrigin', () => {
  it('treats an outdated distro package (installed version left the index) as distro', () => {
    const outdated = {
      installed: '1.0-1ubuntu1',
      sources: ['/var/lib/dpkg/status'],
      available: [{ version: '1.0-1ubuntu2', sources: ['http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages'] }],
    };
    expect(classifyOrigin(outdated, 'noble').kind).toBe('distro');
  });

  it('treats a vendor build newer than the distro version as local', () => {
    const vendor = {
      installed: '1.30.6-1~trixie',
      sources: ['/var/lib/dpkg/status'],
      available: [{ version: '1.26.3-3', sources: ['http://deb.debian.org/debian trixie/main amd64 Packages'] }],
    };
    expect(classifyOrigin(vendor, 'trixie').kind).toBe('local');
  });

  it.each([
    [['http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages'], 'distro'],
    [['http://mirrors.example.net/ubuntu noble-updates/universe amd64 Packages'], 'distro'],
    [['http://deb.debian.org/debian-security bookworm-security/main amd64 Packages'], 'distro'],
    [['http://nginx.org/packages/ubuntu noble/nginx amd64 Packages', '/var/lib/dpkg/status'], 'third_party'],
    [['https://download.docker.com/linux/ubuntu noble/stable amd64 Packages'], 'third_party'],
    [['https://ppa.launchpadcontent.net/foo/bar/ubuntu noble/main amd64 Packages'], 'third_party'],
    [['/var/lib/dpkg/status'], 'local'],
  ])('%j → %s', (sources, kind) => {
    expect(classifyOrigin(o(...sources), 'noble').kind === kind || classifyOrigin(o(...sources), 'bookworm').kind === kind).toBe(true);
  });

  it('is unknown without apt-cache data', () => {
    expect(classifyOrigin(undefined, 'noble')).toEqual({ kind: 'unknown' });
  });

  it('detects emptied apt lists', () => {
    expect(aptListsEmpty({ a: o('/var/lib/dpkg/status'), b: o('/var/lib/dpkg/status') })).toBe(true);
    expect(aptListsEmpty({ a: o('/var/lib/dpkg/status'), b: o('http://deb.debian.org/debian trixie/main amd64 Packages') })).toBe(false);
    const onlyNewerOffered = { installed: '1', sources: ['/var/lib/dpkg/status'], available: [{ version: '2', sources: ['http://deb.debian.org/debian trixie/main amd64 Packages'] }] };
    expect(aptListsEmpty({ a: onlyNewerOffered })).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run test/host`
Expected: FAIL, because the new modules can't be resolved.

- [ ] **Step 3: Implement the modules**

`src/checks/errors.ts`:
```ts
/** A check could not observe what it needs (no snapshot, tool missing, advisory source down, unsupported distro). Reported as unverifiable. */
export class ObservationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ObservationError';
  }
}
```

`src/host/store.ts` (placeholder; Task 6 completes it):
```ts
import type { HostSnapshot } from './snapshot.js';

export interface StoredSnapshot {
  snapshot: HostSnapshot;
  file: string;
}

export interface SnapshotReader {
  latest(host: string): Promise<StoredSnapshot | undefined>;
}
```

`src/host/parse.ts`:
```ts
export interface OsRelease {
  id: string;
  version_id: string;
  codename: string;
  pretty_name: string;
}

export interface InstalledPackage {
  name: string;
  arch?: string;
  version: string;
  source: string;
  source_version: string;
}

/**
 * apt-cache policy for one package. `sources` lists where the installed version is available
 * ("<url> <suite>/<component> <arch> Packages" or /var/lib/dpkg/status). `available` holds the other
 * versions the configured repos offer: an outdated distro package often shows its installed version
 * only under /var/lib/dpkg/status, because the archive index keeps just the newest version.
 */
export interface PackageOrigin {
  installed: string;
  sources: string[];
  available: Array<{ version: string; sources: string[] }>;
}

export interface ListeningSocket {
  address: string;
  port: number;
  process?: string;
}

export function parseOsRelease(text: string): OsRelease {
  const kv: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m?.[1]) kv[m[1]] = (m[2] ?? '').replace(/^"(.*)"$/, '$1');
  }
  return {
    id: kv.ID ?? '',
    version_id: kv.VERSION_ID ?? '',
    codename: kv.VERSION_CODENAME ?? kv.UBUNTU_CODENAME ?? '',
    pretty_name: kv.PRETTY_NAME ?? '',
  };
}

/** dpkg-query lines "<status>\t<name[:arch]>\t<version>\t<source>\t<source version>"; only "ii" (installed) rows. */
export function parsePackages(text: string): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  for (const line of text.split('\n')) {
    const [status, nameArch, version, source, sourceVersion] = line.split('\t');
    if (status?.trim() !== 'ii' || !nameArch || !version) continue;
    const [name = nameArch, arch] = nameArch.split(':');
    out.push({ name, ...(arch ? { arch } : {}), version, source: source || name, source_version: sourceVersion || version });
  }
  return out;
}

/** apt-cache policy blocks → per installed package: the installed ("***") version's sources plus the other offered versions. */
export function parseAptPolicy(text: string): Record<string, PackageOrigin> {
  const out: Record<string, PackageOrigin> = {};
  let entry: PackageOrigin | undefined;
  let target: string[] | undefined;
  for (const line of text.split('\n')) {
    const header = /^([^\s:]+)(?::[^\s:]+)?:$/.exec(line);
    if (header?.[1]) {
      entry = { installed: '', sources: [], available: [] };
      out[header[1]] = entry;
      target = undefined;
      continue;
    }
    const version = /^ (\*\*\*| {3}) (\S+) -?\d+$/.exec(line);
    if (version?.[2] && entry) {
      if (version[1] === '***') {
        entry.installed = version[2];
        target = entry.sources;
      } else {
        const offered = { version: version[2], sources: [] as string[] };
        entry.available.push(offered);
        target = offered.sources;
      }
      continue;
    }
    const source = /^ {8}-?\d+ (.+)$/.exec(line);
    if (source?.[1] && target) target.push(source[1].trim());
  }
  for (const [name, origin] of Object.entries(out)) if (!origin.installed) delete out[name];
  return out;
}

export function parseSshdT(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^(\S+)\s+(.*)$/.exec(line.trim());
    if (!m?.[1]) continue;
    const key = m[1].toLowerCase();
    const value = m[2] ?? '';
    out[key] = out[key] === undefined ? value : `${out[key]} ${value}`;
  }
  return out;
}

export function parseListening(text: string): ListeningSocket[] {
  const out: ListeningSocket[] = [];
  for (const line of text.split('\n')) {
    const cols = line.trim().split(/\s+/);
    const local = cols[3];
    if (cols[0] !== 'LISTEN' || !local) continue;
    const idx = local.lastIndexOf(':');
    const port = Number(local.slice(idx + 1));
    if (idx === -1 || !Number.isInteger(port)) continue;
    const address = local
      .slice(0, idx)
      .replace(/^\[|\]$/g, '')
      .replace(/%.*$/, '');
    const process = /users:\(\("([^"]+)"/.exec(line)?.[1];
    out.push({ address, port, ...(process ? { process } : {}) });
  }
  return out;
}

export function parseAutoUpgrades(text: string): { enabled: boolean; installed: boolean } {
  return {
    enabled: /^APT::Periodic::Unattended-Upgrade "1";/m.test(text),
    installed: /^ii\s*unattended-upgrades\s*$/m.test(text),
  };
}

export function parseReboot(text: string): { required: boolean; packages: string[] } {
  const [first, ...rest] = text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  return { required: first === 'required', packages: first === 'required' ? rest : [] };
}

/** Values of every (uncommented) occurrence of a simple directive in `nginx -T` output. */
export function nginxDirectiveValues(config: string, directive: string): string[] {
  const pattern = new RegExp(`(?:^|[\\s;{}])${directive}\\s+([^;{}]*);`, 'g');
  const values: string[] = [];
  for (const raw of config.split('\n')) {
    const line = raw.replace(/#.*$/, '');
    for (const m of line.matchAll(pattern)) if (m[1] !== undefined) values.push(m[1].trim());
  }
  return values;
}
```

`src/host/snapshot.ts`:
```ts
import { z } from 'zod';
import { ObservationError } from '../checks/errors.js';
import {
  parseAptPolicy,
  parseAutoUpgrades,
  parseListening,
  parseOsRelease,
  parsePackages,
  parseReboot,
  parseSshdT,
  type InstalledPackage,
  type ListeningSocket,
  type OsRelease,
  type PackageOrigin,
} from './parse.js';

export const SnapshotEnvelopeSchema = z.object({
  schema: z.literal(1),
  collector: z.string().min(1),
  collected_at: z.iso.datetime(),
  sections: z.record(z.string(), z.object({ rc: z.number().int(), b64: z.string() })),
});
export type SnapshotEnvelope = z.infer<typeof SnapshotEnvelopeSchema>;

export type SectionState<T> = { state: 'ok'; value: T } | { state: 'absent'; reason: string } | { state: 'error'; reason: string };

export interface HostSnapshot {
  collected_at: string;
  is_root: boolean;
  os: OsRelease;
  kernel: string;
  /** Empty when dpkg is unavailable (non-Debian host). */
  packages: InstalledPackage[];
  /** Keyed by binary package name without arch. */
  origins: Record<string, PackageOrigin>;
  auto_upgrades: { enabled: boolean; installed: boolean };
  reboot: { required: boolean; packages: string[] };
  sshd: SectionState<Record<string, string>>;
  /** Redacted `nginx -T` output. */
  nginx: SectionState<string>;
  listening: SectionState<ListeningSocket[]>;
}

function section(env: SnapshotEnvelope, name: string): { rc: number; text: string } | undefined {
  const s = env.sections[name];
  return s ? { rc: s.rc, text: Buffer.from(s.b64, 'base64').toString('utf8') } : undefined;
}

/** rc 0 = ok; rc 127 (shell "not found") = the tool isn't installed; anything else = couldn't read it (often: not run as root). */
function stateOf<T>(s: { rc: number; text: string } | undefined, parse: (text: string) => T): SectionState<T> {
  if (!s) return { state: 'error', reason: 'section missing from snapshot' };
  if (s.rc === 0) return { state: 'ok', value: parse(s.text) };
  const reason = (s.text.split('\n').find((l) => l.trim() !== '') ?? `exit code ${s.rc}`).trim();
  return s.rc === 127 ? { state: 'absent', reason } : { state: 'error', reason };
}

export function decodeSnapshot(raw: unknown): HostSnapshot {
  const parsed = SnapshotEnvelopeSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
    throw new ObservationError('SNAPSHOT_INVALID', `Not a secagent collector snapshot: ${issues}`);
  }
  const env = parsed.data;
  const osRelease = section(env, 'os_release');
  if (!osRelease || osRelease.rc !== 0) throw new ObservationError('SNAPSHOT_INVALID', 'Snapshot has no readable /etc/os-release section.');
  const text = (name: string) => {
    const s = section(env, name);
    return s && s.rc === 0 ? s.text : '';
  };
  return {
    collected_at: env.collected_at,
    is_root: text('uid').trim() === '0',
    os: parseOsRelease(osRelease.text),
    kernel: text('kernel').trim(),
    packages: parsePackages(text('packages')),
    origins: parseAptPolicy(text('apt_policy')),
    auto_upgrades: parseAutoUpgrades(section(env, 'auto_upgrades')?.text ?? ''),
    reboot: parseReboot(text('reboot')),
    sshd: stateOf(section(env, 'sshd'), parseSshdT),
    nginx: stateOf(section(env, 'nginx'), (t) => t),
    listening: stateOf(section(env, 'listening'), parseListening),
  };
}
```

Note: `auto_upgrades` reads the section even when `rc` is nonzero. The `grep` in that section exits 1 when unattended-upgrades isn't configured, and the text is still meaningful.

`src/host/origin.ts`:
```ts
import { compareDebVersions } from '../util/debver.js';
import type { PackageOrigin } from './parse.js';

export type OriginKind = 'distro' | 'third_party' | 'local' | 'unknown';

const DISTRO_COMPONENTS = new Set(['main', 'restricted', 'universe', 'multiverse', 'contrib', 'non-free', 'non-free-firmware']);
const LOCAL_STATUS = '/var/lib/dpkg/status';

/** A source line from a distro suite (codename or codename-updates/-security/...) and component, on any mirror; PPAs excluded. */
function isDistroRepo(source: string, codename: string): boolean {
  const [url = '', suiteComponent = ''] = source.split(/\s+/);
  const [suite = '', component = ''] = suiteComponent.split('/');
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  const distroSuite = codename !== '' && (suite === codename || suite.startsWith(`${codename}-`));
  return distroSuite && DISTRO_COMPONENTS.has(component) && !host.includes('launchpad');
}

/**
 * Where the installed version came from. It is distro when a distro repo carries it, or when it is known only to
 * dpkg but a distro repo offers a newer version (an outdated distro package whose old version left the index).
 * It is third-party when a non-distro repo carries it (nginx.org, docker, PPAs). Otherwise it was installed locally.
 */
export function classifyOrigin(origin: PackageOrigin | undefined, codename: string): { kind: OriginKind; repo?: string } {
  if (!origin) return { kind: 'unknown' };
  const repos = origin.sources.filter((s) => s !== LOCAL_STATUS);
  if (repos.length > 0) {
    const distro = repos.find((s) => isDistroRepo(s, codename));
    return distro ? { kind: 'distro', repo: distro } : { kind: 'third_party', repo: repos[0] };
  }
  for (const offered of origin.available) {
    const distro = offered.sources.find((s) => isDistroRepo(s, codename));
    if (distro && compareDebVersions(offered.version, origin.installed) > 0) return { kind: 'distro', repo: distro };
  }
  return { kind: 'local' };
}

/** True when no package lists any repository source for any version: apt lists were cleaned or never fetched, so origins can't be known. */
export function aptListsEmpty(origins: Record<string, PackageOrigin>): boolean {
  return !Object.values(origins).some((o) => [...o.sources, ...o.available.flatMap((v) => v.sources)].some((s) => s !== LOCAL_STATUS));
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/host && npx tsc -p tsconfig.json`
Expected: all host tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/checks/errors.ts src/host/parse.ts src/host/snapshot.ts src/host/origin.ts src/host/store.ts test/helpers/snapshots.ts test/host/parse.test.ts test/host/snapshot.test.ts test/host/origin.test.ts
git commit -m "feat(host): decode collector snapshots and classify package origins"
```

---

### Task 4: Advisory types, allowlisted fetch and cache

**Files:**
- Create: `src/advisories/types.ts`, `src/advisories/fetch.ts`, `src/advisories/cache.ts`
- Test: `test/advisories/fetch.test.ts`, `test/advisories/cache.test.ts`

**Interfaces:**
- Consumes: `ObservationError` (Task 3); `USER_AGENT` (Plan 1 `src/net/http.ts`); `startHttps`, `useServers` (Plan 1 test helpers)
- Produces:
  - types: `OsvEvent`, `OsvVuln`, `UbuntuCveStatus`, `UbuntuCve`, `PackageQuery { name; version }`, and the interfaces `OsvSource`, `UbuntuSource`, `KevSource`, `Advisories { osv; ubuntu; kev }`
  - `ADVISORY_HOSTS`, `type FetchJson`, `createFetchJson(opts?)`
  - `TTL`, `defaultCacheDir()`, `class AdvisoryCache(dir?, now?)` with `getOrFetch(source, key, ttlMs, fetcher)` returning `{ value, fetched_at, stale }`

- [ ] **Step 1: Write the failing tests**

`test/advisories/fetch.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { ADVISORY_HOSTS, createFetchJson } from '../../src/advisories/fetch.js';
import { startHttps, useServers } from '../helpers/servers.js';

const track = useServers();

describe('createFetchJson', () => {
  it('allows only the three advisory hosts over https', async () => {
    expect([...ADVISORY_HOSTS].sort()).toEqual(['api.osv.dev', 'ubuntu.com', 'www.cisa.gov']);
    const fetchJson = createFetchJson();
    await expect(fetchJson('https://evil.example.org/x')).rejects.toThrow(/not an allowlisted advisory source/);
    await expect(fetchJson('http://api.osv.dev/v1/query')).rejects.toThrow(/not an allowlisted advisory source/);
  });

  it('verifies TLS certificates (a self-signed server is rejected)', async () => {
    const s = await track(startHttps((_req, res) => res.end('{}')));
    const fetchJson = createFetchJson({ allowHosts: new Set(['127.0.0.1']) });
    await expect(fetchJson(`${s.url}/x`)).rejects.toThrow();
  });
});
```

`test/advisories/cache.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { ObservationError } from '../../src/checks/errors.js';
import { tempDir } from '../helpers/tmp.js';

describe('AdvisoryCache', () => {
  it('serves fresh entries without refetching and refetches after the TTL', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return { n: calls };
    };
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 1 });
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 1 });
    now = new Date(now.getTime() + 2000);
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 2 });
    expect(calls).toBe(2);
  });

  it('falls back to a stale copy when the source fails', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('kev', 'k', 1000, async () => ['CVE-1']);
    now = new Date(now.getTime() + 5000);
    const r = await cache.getOrFetch('kev', 'k', 1000, async () => {
      throw new Error('offline');
    });
    expect(r).toMatchObject({ value: ['CVE-1'], stale: true });
  });

  it('raises ADVISORY_UNAVAILABLE when the source fails and nothing is cached', async () => {
    const cache = new AdvisoryCache(await tempDir());
    const err = await cache
      .getOrFetch('ubuntu', 'k', 1000, async () => {
        throw new Error('offline');
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect((err as ObservationError).code).toBe('ADVISORY_UNAVAILABLE');
  });

  it('caches null (404) results too', async () => {
    const cache = new AdvisoryCache(await tempDir());
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return null;
    };
    await cache.getOrFetch('ubuntu', 'CVE-0', 1000, fetcher);
    expect((await cache.getOrFetch('ubuntu', 'CVE-0', 1000, fetcher)).value).toBeNull();
    expect(calls).toBe(1);
  });
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run test/advisories`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement**

`src/advisories/types.ts`:
```ts
export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvVuln {
  id: string;
  upstream?: string[];
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { ecosystem: string; name: string };
    ranges?: Array<{ type: string; events: OsvEvent[] }>;
  }>;
}

export interface UbuntuCveStatus {
  release_codename: string;
  status: string;
  description: string;
  pocket?: string | null;
}

export interface UbuntuCve {
  id: string;
  priority?: string;
  packages: Array<{ name: string; statuses: UbuntuCveStatus[] }>;
}

export interface PackageQuery {
  name: string;
  version: string;
}

export interface OsvSource {
  /** Names (from `queries`) that have at least one OSV advisory affecting the given version. */
  affected(ecosystem: string, queries: readonly PackageQuery[]): Promise<Set<string>>;
  vulnsFor(ecosystem: string, query: PackageQuery): Promise<OsvVuln[]>;
  vuln(id: string): Promise<OsvVuln | null>;
}

export interface UbuntuSource {
  cve(id: string): Promise<UbuntuCve | null>;
}

export interface KevSource {
  catalog(): Promise<Set<string>>;
}

export interface Advisories {
  osv: OsvSource;
  ubuntu: UbuntuSource;
  kev: KevSource;
}
```

`src/advisories/fetch.ts`:
```ts
import https from 'node:https';
import { USER_AGENT } from '../net/http.js';

export const ADVISORY_HOSTS: ReadonlySet<string> = new Set(['api.osv.dev', 'ubuntu.com', 'www.cisa.gov']);

export interface JsonResponse {
  status: number;
  /** Parsed body, or null for 404. */
  json: unknown;
}

export type FetchJson = (url: string, init?: { method?: 'GET' | 'POST'; body?: unknown }) => Promise<JsonResponse>;

/** HTTPS JSON fetch restricted to allowlisted advisory hosts. Verifies certificates, follows no redirects, enforces a timeout and a size cap. */
export function createFetchJson(
  opts: { timeoutMs?: number; maxBytes?: number; allowHosts?: ReadonlySet<string> } = {},
): FetchJson {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const maxBytes = opts.maxBytes ?? 8 * 1024 * 1024;
  const allow = opts.allowHosts ?? ADVISORY_HOSTS;
  return (url, init = {}) =>
    new Promise<JsonResponse>((resolve, reject) => {
      const u = new URL(url);
      if (u.protocol !== 'https:' || !allow.has(u.hostname)) {
        reject(new Error(`${u.hostname} is not an allowlisted advisory source`));
        return;
      }
      const body = init.body === undefined ? undefined : JSON.stringify(init.body);
      const req = https.request(
        u,
        {
          method: init.method ?? 'GET',
          timeout: timeoutMs,
          headers: {
            accept: 'application/json',
            'user-agent': USER_AGENT,
            ...(body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) {
              req.destroy(new Error(`response from ${u.hostname} exceeds ${maxBytes} bytes`));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const status = res.statusCode ?? 0;
            if (status === 404) return resolve({ status, json: null });
            if (status < 200 || status >= 300) return reject(new Error(`${u.hostname} answered HTTP ${status}`));
            try {
              resolve({ status, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
            } catch (e) {
              reject(new Error(`invalid JSON from ${u.hostname}: ${(e as Error).message}`));
            }
          });
          res.on('error', reject);
        },
      );
      req.on('timeout', () => req.destroy(new Error(`${u.hostname} did not answer within ${timeoutMs}ms`)));
      req.on('error', reject);
      req.end(body);
    });
}
```

`src/advisories/cache.ts`:
```ts
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';

const DAY = 86_400_000;
export const TTL = { kev: DAY, osv: 3 * DAY, ubuntu: 3 * DAY } as const;

export interface Cached<T> {
  value: T;
  fetched_at: string;
  stale: boolean;
}

export function defaultCacheDir(): string {
  return process.env.SECAGENT_CACHE_DIR ?? path.join(os.homedir(), '.cache', 'secagent', 'advisories');
}

/** File cache per source. Fresh entries are served as-is; on fetch failure a stale entry is served; with none, ADVISORY_UNAVAILABLE. */
export class AdvisoryCache {
  constructor(
    readonly dir: string = defaultCacheDir(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  async getOrFetch<T>(source: string, key: string, ttlMs: number, fetcher: () => Promise<T>): Promise<Cached<T>> {
    const file = path.join(this.dir, source, `${createHash('sha256').update(key).digest('hex').slice(0, 32)}.json`);
    const cached = await this.read<T>(file, key);
    const now = this.now();
    if (cached && now.getTime() - Date.parse(cached.fetched_at) < ttlMs) return { ...cached, stale: false };
    try {
      const value = await fetcher();
      const fetched_at = now.toISOString();
      await mkdir(path.dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify({ key, fetched_at, value }), 'utf8');
      await rename(tmp, file);
      return { value, fetched_at, stale: false };
    } catch (e) {
      if (cached) return { ...cached, stale: true };
      const reason = e instanceof Error ? e.message : String(e);
      throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories are unavailable and nothing is cached: ${reason}`);
    }
  }

  private async read<T>(file: string, key: string): Promise<{ value: T; fetched_at: string } | undefined> {
    try {
      const entry = JSON.parse(await readFile(file, 'utf8')) as { key?: string; fetched_at?: string; value?: T };
      if (entry.key !== key || typeof entry.fetched_at !== 'string' || !('value' in entry)) return undefined;
      return { value: entry.value as T, fetched_at: entry.fetched_at };
    } catch {
      return undefined;
    }
  }
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/advisories && npx tsc -p tsconfig.json`
Expected: 6 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/advisories/types.ts src/advisories/fetch.ts src/advisories/cache.ts test/advisories/fetch.test.ts test/advisories/cache.test.ts
git commit -m "feat(advisories): add allowlisted HTTPS JSON fetch and TTL cache"
```

---

### Task 5: OSV, Ubuntu and KEV clients, distro mapping and `createAdvisories`

**Files:**
- Create: `src/advisories/osv.ts`, `src/advisories/ubuntu.ts`, `src/advisories/kev.ts`, `src/advisories/distro.ts`, `src/advisories/index.ts`, `test/helpers/advisories.ts`
- Test: `test/advisories/clients.test.ts`, `test/advisories/distro.test.ts`, `test/advisories/live.test.ts`

**Interfaces:**
- Consumes: Task 4 types, `FetchJson`, `AdvisoryCache`, `TTL`, `createFetchJson`; `OsRelease` (Task 3); the fixtures in `test/fixtures/advisories/`
- Produces:
  - `OsvClient`, `fixedVersionFor(v, ecosystem, name)`, `cveIdsOf(v)`, `ubuntuPriority(v)`
  - `UbuntuCveClient`; `KevClient`, `KEV_URL`
  - `interface Distro { family; ecosystem; codename; version }`, `distroOf(os): Distro | undefined`
  - `createAdvisories(opts?: { cacheDir?; fetchJson?; now? }): Advisories`
  - test helpers `fixtureFetch()` (a `FetchJson` with a `calls: string[]` property) and `fixtureAdvisories(cacheDir, extraKev?)`

- [ ] **Step 1: Write the fixture helper and failing tests**

`test/helpers/advisories.ts`:
```ts
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { FetchJson } from '../../src/advisories/fetch.js';
import { createAdvisories } from '../../src/advisories/index.js';
import type { Advisories } from '../../src/advisories/types.js';

const DIR = path.join(import.meta.dirname, '..', 'fixtures', 'advisories');
const CODENAMES: Record<string, string> = { 'Ubuntu:24.04:LTS': 'noble', 'Ubuntu:22.04:LTS': 'jammy', 'Debian:12': 'bookworm' };

function load(rel: string): unknown {
  return JSON.parse(readFileSync(path.join(DIR, rel), 'utf8'));
}

function queryFixture(ecosystem: string, name: string, version: string): string | undefined {
  const rel = `osv/query-${name}-${CODENAMES[ecosystem] ?? 'x'}-${version.replace(/:/g, '.')}.json`;
  return existsSync(path.join(DIR, rel)) ? rel : undefined;
}

/** Serves recorded advisory responses; anything not recorded is a 404 (or an empty OSV result). Records every request. */
export function fixtureFetch(extraKev: string[] = []): FetchJson & { calls: string[] } {
  const calls: string[] = [];
  const fn = async (url: string, init: { method?: 'GET' | 'POST'; body?: unknown } = {}) => {
    calls.push(`${init.method ?? 'GET'} ${url}`);
    const u = new URL(url);
    if (u.hostname === 'ubuntu.com') {
      const id = /\/cves\/(CVE-[\d-]+)\.json$/.exec(u.pathname)?.[1];
      const rel = `ubuntu/${id}.json`;
      return id && existsSync(path.join(DIR, rel)) ? { status: 200, json: load(rel) } : { status: 404, json: null };
    }
    if (u.hostname === 'www.cisa.gov') {
      const kev = load('kev/known_exploited_vulnerabilities.sample.json') as { vulnerabilities: Array<{ cveID: string }> };
      return { status: 200, json: { ...kev, vulnerabilities: [...kev.vulnerabilities, ...extraKev.map((cveID) => ({ cveID }))] } };
    }
    if (u.pathname.startsWith('/v1/vulns/')) {
      const rel = `osv/${decodeURIComponent(u.pathname.slice('/v1/vulns/'.length))}.json`;
      return existsSync(path.join(DIR, rel)) ? { status: 200, json: load(rel) } : { status: 404, json: null };
    }
    if (u.pathname === '/v1/query') {
      const b = init.body as { package: { name: string; ecosystem: string }; version: string };
      const rel = queryFixture(b.package.ecosystem, b.package.name, b.version);
      return { status: 200, json: rel ? load(rel) : {} };
    }
    if (u.pathname === '/v1/querybatch') {
      const b = init.body as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return {
        status: 200,
        json: { results: b.queries.map((q) => (queryFixture(q.package.ecosystem, q.package.name, q.version) ? { vulns: [{ id: 'x' }] } : {})) },
      };
    }
    return { status: 404, json: null };
  };
  return Object.assign(fn, { calls });
}

export function fixtureAdvisories(cacheDir: string, extraKev: string[] = []): Advisories {
  return createAdvisories({ cacheDir, fetchJson: fixtureFetch(extraKev) });
}
```

`test/advisories/clients.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { KevClient } from '../../src/advisories/kev.js';
import { cveIdsOf, fixedVersionFor, OsvClient, ubuntuPriority } from '../../src/advisories/osv.js';
import { UbuntuCveClient } from '../../src/advisories/ubuntu.js';
import { fixtureFetch } from '../helpers/advisories.js';
import { tempDir } from '../helpers/tmp.js';

const NOBLE = 'Ubuntu:24.04:LTS';

describe('OsvClient', () => {
  it('finds affected source packages, then their vulns with fixed versions and CVE ids', async () => {
    const fetchJson = fixtureFetch();
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    const affected = await osv.affected(NOBLE, [
      { name: 'openssh', version: '1:9.6p1-3ubuntu13' },
      { name: 'bash', version: '5.2.21-2ubuntu4' },
    ]);
    expect([...affected]).toEqual(['openssh']);
    const vulns = await osv.vulnsFor(NOBLE, { name: 'openssh', version: '1:9.6p1-3ubuntu13' });
    const v = vulns.find((x) => x.id === 'UBUNTU-CVE-2024-6387');
    expect(v).toBeDefined();
    if (!v) return;
    expect(fixedVersionFor(v, NOBLE, 'openssh')).toBe('1:9.6p1-3ubuntu13.3');
    expect(cveIdsOf(v)).toEqual(['CVE-2024-6387']);
    expect(ubuntuPriority(v)).toBe('high');
  });

  it('caches responses', async () => {
    const fetchJson = fixtureFetch();
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    await osv.vuln('DEBIAN-CVE-2024-6387');
    await osv.vuln('DEBIAN-CVE-2024-6387');
    expect(fetchJson.calls).toHaveLength(1);
  });

  it('returns null for unknown vulns and reads Debian fixed versions', async () => {
    const osv = new OsvClient(fixtureFetch(), new AdvisoryCache(await tempDir()));
    expect(await osv.vuln('DEBIAN-CVE-1999-0001')).toBeNull();
    const d = await osv.vuln('DEBIAN-CVE-2024-6387');
    expect(d && fixedVersionFor(d, 'Debian:12', 'openssh')).toBe('1:9.2p1-2+deb12u3');
  });
});

describe('UbuntuCveClient', () => {
  it('returns per-release statuses, null for unknown CVEs, and rejects non-CVE ids', async () => {
    const ubuntu = new UbuntuCveClient(fixtureFetch(), new AdvisoryCache(await tempDir()));
    const cve = await ubuntu.cve('CVE-2021-41617');
    const noble = cve?.packages.find((p) => p.name === 'openssh')?.statuses.find((s) => s.release_codename === 'noble');
    expect(noble?.status).toBe('not-affected');
    expect(await ubuntu.cve('CVE-1999-0001')).toBeNull();
    await expect(ubuntu.cve('not-a-cve')).rejects.toThrow(/Not a CVE id/);
  });
});

describe('KevClient', () => {
  it('loads the catalog once', async () => {
    const fetchJson = fixtureFetch(['CVE-2024-6387']);
    const kev = new KevClient(fetchJson, new AdvisoryCache(await tempDir()));
    expect((await kev.catalog()).has('CVE-2024-6387')).toBe(true);
    expect((await kev.catalog()).has('CVE-2026-48356')).toBe(true);
    expect(fetchJson.calls).toHaveLength(1);
  });
});
```

`test/advisories/distro.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { distroOf } from '../../src/advisories/distro.js';

const os = (id: string, version_id: string, codename: string) => ({ id, version_id, codename, pretty_name: '' });

describe('distroOf', () => {
  it.each([
    [os('ubuntu', '24.04', 'noble'), 'Ubuntu:24.04:LTS'],
    [os('ubuntu', '22.04', 'jammy'), 'Ubuntu:22.04:LTS'],
    [os('ubuntu', '24.10', 'oracular'), 'Ubuntu:24.10'],
    [os('debian', '12', 'bookworm'), 'Debian:12'],
    [os('debian', '13', 'trixie'), 'Debian:13'],
  ])('%j → %s', (release, ecosystem) => {
    expect(distroOf(release)?.ecosystem).toBe(ecosystem);
  });

  it('is undefined for other distros', () => {
    expect(distroOf(os('rhel', '9.4', ''))).toBeUndefined();
  });
});
```

`test/advisories/live.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { createAdvisories } from '../../src/advisories/index.js';
import { tempDir } from '../helpers/tmp.js';

describe.runIf(process.env.SECAGENT_LIVE === '1')('live advisory sources (network)', () => {
  it('reach OSV, Ubuntu and CISA KEV', async () => {
    const a = createAdvisories({ cacheDir: await tempDir() });
    const ub = await a.ubuntu.cve('CVE-2024-6387');
    const noble = ub?.packages.find((p) => p.name === 'openssh')?.statuses.find((s) => s.release_codename === 'noble');
    expect(noble).toMatchObject({ status: 'released', description: '1:9.6p1-3ubuntu13.3' });
    expect([...(await a.osv.affected('Ubuntu:24.04:LTS', [{ name: 'openssh', version: '1:9.6p1-3ubuntu13' }]))]).toEqual(['openssh']);
    expect((await a.kev.catalog()).size).toBeGreaterThan(1000);
  }, 60_000);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run test/advisories`
Expected: the new files FAIL, because their modules can't be resolved. The Task 4 tests still pass.

- [ ] **Step 3: Implement the clients**

`src/advisories/osv.ts`:
```ts
import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { OsvSource, OsvVuln, PackageQuery } from './types.js';

const OSV = 'https://api.osv.dev/v1';
const BATCH = 1000;

export class OsvClient implements OsvSource {
  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  async affected(ecosystem: string, queries: readonly PackageQuery[]): Promise<Set<string>> {
    const hits = new Set<string>();
    for (let i = 0; i < queries.length; i += BATCH) {
      const chunk = queries.slice(i, i + BATCH);
      const key = `batch ${ecosystem} ${chunk
        .map((q) => `${q.name}@${q.version}`)
        .sort()
        .join(',')}`;
      const { value } = await this.cache.getOrFetch('osv', key, TTL.osv, async () => {
        const res = await this.fetchJson(`${OSV}/querybatch`, {
          method: 'POST',
          body: { queries: chunk.map((q) => ({ package: { name: q.name, ecosystem }, version: q.version })) },
        });
        const results = (res.json as { results?: Array<{ vulns?: unknown[] }> } | null)?.results ?? [];
        return chunk.filter((_, idx) => (results[idx]?.vulns?.length ?? 0) > 0).map((q) => q.name);
      });
      for (const name of value) hits.add(name);
    }
    return hits;
  }

  async vulnsFor(ecosystem: string, query: PackageQuery): Promise<OsvVuln[]> {
    const { value } = await this.cache.getOrFetch('osv', `query ${ecosystem} ${query.name}@${query.version}`, TTL.osv, async () => {
      const vulns: OsvVuln[] = [];
      let pageToken: string | undefined;
      do {
        const res = await this.fetchJson(`${OSV}/query`, {
          method: 'POST',
          body: { package: { name: query.name, ecosystem }, version: query.version, ...(pageToken ? { page_token: pageToken } : {}) },
        });
        const body = (res.json ?? {}) as { vulns?: OsvVuln[]; next_page_token?: string };
        vulns.push(...(body.vulns ?? []));
        pageToken = body.next_page_token;
      } while (pageToken);
      return vulns;
    });
    return value;
  }

  async vuln(id: string): Promise<OsvVuln | null> {
    const { value } = await this.cache.getOrFetch('osv', `vuln ${id}`, TTL.osv, async () => {
      return (await this.fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`)).json as OsvVuln | null;
    });
    return value;
  }
}

/** The first `fixed` event for this ecosystem and source package, if the advisory has one. */
export function fixedVersionFor(v: OsvVuln, ecosystem: string, name: string): string | undefined {
  for (const a of v.affected ?? []) {
    if (a.package.ecosystem !== ecosystem || a.package.name !== name) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) if (e.fixed) return e.fixed;
    }
  }
  return undefined;
}

export function cveIdsOf(v: OsvVuln): string[] {
  const fromId = /CVE-\d{4}-\d+/.exec(v.id)?.[0];
  const all = [...(v.upstream ?? []), ...(v.aliases ?? []), ...(fromId ? [fromId] : [])];
  return [...new Set(all.filter((id) => /^CVE-\d{4}-\d+$/.test(id)))];
}

/** Ubuntu's own priority (negligible | low | medium | high | critical) when the record carries one. */
export function ubuntuPriority(v: OsvVuln): string | undefined {
  return v.severity?.find((s) => s.type === 'Ubuntu')?.score;
}
```

`src/advisories/ubuntu.ts`:
```ts
import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { UbuntuCve, UbuntuCveStatus, UbuntuSource } from './types.js';

export class UbuntuCveClient implements UbuntuSource {
  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  async cve(id: string): Promise<UbuntuCve | null> {
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new Error(`Not a CVE id: ${id}`);
    const { value } = await this.cache.getOrFetch('ubuntu', id, TTL.ubuntu, async () => {
      const json = (await this.fetchJson(`https://ubuntu.com/security/cves/${id}.json`)).json as {
        id?: string;
        priority?: string;
        packages?: Array<{ name: string; statuses?: UbuntuCveStatus[] }>;
      } | null;
      if (!json) return null;
      return {
        id: json.id ?? id,
        ...(json.priority ? { priority: json.priority } : {}),
        packages: (json.packages ?? []).map((p) => ({
          name: p.name,
          statuses: (p.statuses ?? []).map((s) => ({
            release_codename: s.release_codename,
            status: s.status,
            description: s.description ?? '',
            pocket: s.pocket ?? null,
          })),
        })),
      };
    });
    return value;
  }
}
```

`src/advisories/kev.ts`:
```ts
import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { KevSource } from './types.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export class KevClient implements KevSource {
  private loaded: Promise<Set<string>> | undefined;

  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  catalog(): Promise<Set<string>> {
    this.loaded ??= this.cache
      .getOrFetch('kev', KEV_URL, TTL.kev, async () => {
        const json = (await this.fetchJson(KEV_URL)).json as { vulnerabilities?: Array<{ cveID?: unknown }> } | null;
        return (json?.vulnerabilities ?? []).map((v) => v.cveID).filter((id): id is string => typeof id === 'string');
      })
      .then((c) => new Set(c.value));
    return this.loaded;
  }
}
```

`src/advisories/distro.ts`:
```ts
import type { OsRelease } from '../host/parse.js';

export interface Distro {
  family: 'ubuntu' | 'debian';
  /** OSV ecosystem, e.g. "Ubuntu:24.04:LTS" or "Debian:12". */
  ecosystem: string;
  codename: string;
  version: string;
}

export function distroOf(os: OsRelease): Distro | undefined {
  if (os.id === 'ubuntu' && /^\d\d\.\d\d$/.test(os.version_id)) {
    const [yy = '', mm = ''] = os.version_id.split('.');
    const lts = mm === '04' && Number(yy) % 2 === 0;
    return { family: 'ubuntu', ecosystem: `Ubuntu:${os.version_id}${lts ? ':LTS' : ''}`, codename: os.codename, version: os.version_id };
  }
  const major = /^\d+/.exec(os.version_id)?.[0];
  if (os.id === 'debian' && major) return { family: 'debian', ecosystem: `Debian:${major}`, codename: os.codename, version: major };
  return undefined;
}
```

`src/advisories/index.ts`:
```ts
import { AdvisoryCache } from './cache.js';
import { createFetchJson, type FetchJson } from './fetch.js';
import { KevClient } from './kev.js';
import { OsvClient } from './osv.js';
import type { Advisories } from './types.js';
import { UbuntuCveClient } from './ubuntu.js';

export type { Advisories } from './types.js';

export function createAdvisories(opts: { cacheDir?: string; fetchJson?: FetchJson; now?: () => Date } = {}): Advisories {
  const cache = new AdvisoryCache(opts.cacheDir, opts.now);
  const fetchJson = opts.fetchJson ?? createFetchJson();
  return { osv: new OsvClient(fetchJson, cache), ubuntu: new UbuntuCveClient(fetchJson, cache), kev: new KevClient(fetchJson, cache) };
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/advisories && npx tsc -p tsconfig.json`
Expected: all PASS (the live test is skipped); `tsc` exits 0. Optional: `SECAGENT_LIVE=1 npx vitest run test/advisories/live.test.ts` passes when online.

- [ ] **Step 5: Commit**

```bash
git add src/advisories test/helpers/advisories.ts test/advisories
git commit -m "feat(advisories): add OSV, Ubuntu CVE and CISA KEV clients"
```

---

### Task 6: Snapshot store and check-context wiring

**Files:**
- Modify: `src/host/store.ts` (complete it), `src/checks/context.ts`, `src/checks/runner.ts`, `src/evidence/store.ts`, `src/scan/no-ai.ts`, `test/helpers/ctx.ts`, `test/checks/types/tls.test.ts`
- Test: `test/host/store.test.ts`, `test/checks/context.test.ts` (extend), `test/checks/runner.test.ts` (extend)

**Interfaces:**
- Consumes: `decodeSnapshot`, `SnapshotEnvelopeSchema` (Task 3); `ObservationError`; `Advisories`, `createAdvisories` (Task 5); `projectStateDir`
- Produces:
  - `MAX_SNAPSHOT_AGE_DAYS = 7`
  - `class SnapshotStore(projectDir) implements SnapshotReader`, with `add(host, text): Promise<StoredSnapshot>` and `latest(host)`
  - `CheckContext` gains `snapshots: SnapshotReader` and `advisories: Advisories`
  - `getSnapshot(ctx, host): Promise<StoredSnapshot>`, which throws `ObservationError` `NO_SNAPSHOT` or `SNAPSHOT_STALE`
  - `EvidenceKind` gains `'snapshot' | 'advisory'`
  - the runner reports an `ObservationError` as unverifiable
  - `ScanDeps` gains `snapshots?` and `advisories?`
  - test helpers: `makeCtx(net?, projectOverrides?, deps?: { snapshots?; advisories? })`, `NO_SNAPSHOTS`, `NO_ADVISORIES`

- [ ] **Step 1: Write the failing tests**

`test/host/store.test.ts`:
```ts
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { SnapshotStore } from '../../src/host/store.js';
import { fixtureEnvelope } from '../helpers/snapshots.js';
import { tempDir } from '../helpers/tmp.js';

describe('SnapshotStore', () => {
  it('stores a validated snapshot by collected_at and returns the newest', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir);
    const older = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-10-20T00:00:00Z' };
    await store.add('web-1', JSON.stringify(older));
    const added = await store.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')));
    expect(added.file).toBe(path.join(dir, '.secagent', 'hosts', 'web-1', '20261028T143146Z.json'));
    expect((await store.latest('web-1'))?.snapshot.collected_at).toBe('2026-10-28T14:31:46Z');
  });

  it('rejects non-JSON, non-snapshots and bad host names', async () => {
    const store = new SnapshotStore(await tempDir());
    await expect(store.add('web-1', 'not json')).rejects.toBeInstanceOf(ObservationError);
    await expect(store.add('web-1', '{"schema":1}')).rejects.toThrow(/Not a secagent collector snapshot/);
    await expect(store.add('../etc', JSON.stringify(fixtureEnvelope('debian-12')))).rejects.toThrow(/Invalid host name/);
  });

  it('skips unreadable files and returns undefined for unknown hosts', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir);
    await store.add('web-1', JSON.stringify(fixtureEnvelope('debian-12')));
    await writeFile(path.join(dir, '.secagent', 'hosts', 'web-1', 'junk.json'), '{');
    expect((await store.latest('web-1'))?.snapshot.os.id).toBe('debian');
    expect(await store.latest('nope')).toBeUndefined();
  });
});
```

Append to `test/checks/context.test.ts`:
```ts
import { ObservationError } from '../../src/checks/errors.js';
import { getSnapshot } from '../../src/checks/context.js';
import { fixtureSnapshot, readerFor } from '../helpers/snapshots.js';

describe('getSnapshot', () => {
  it('returns the newest snapshot and memoizes it', async () => {
    let calls = 0;
    const snapshot = fixtureSnapshot('ubuntu-24-04');
    const { ctx } = await makeCtx({}, {}, {
      snapshots: {
        latest: async () => {
          calls += 1;
          return { snapshot, file: '/x.json' };
        },
      },
    });
    await getSnapshot(ctx, hostSubject(ctx).host);
    await getSnapshot(ctx, hostSubject(ctx).host);
    expect(calls).toBe(1);
  });

  it('explains a missing snapshot and refuses a stale one', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(undefined) });
    await expect(getSnapshot(ctx, hostSubject(ctx).host)).rejects.toMatchObject({ code: 'NO_SNAPSHOT' });
    const old = { ...fixtureSnapshot('debian-12'), collected_at: '2026-10-01T00:00:00Z' };
    const { ctx: ctx2 } = await makeCtx({}, {}, { snapshots: readerFor(old) });
    const err = await getSnapshot(ctx2, hostSubject(ctx2).host).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect((err as ObservationError).code).toBe('SNAPSHOT_STALE');
  });
});
```

Merge these imports into the file's existing import block; don't duplicate `makeCtx` or `hostSubject`.

Append to `test/checks/runner.test.ts`. Extend the fake type's `mode` enum with `'observe'`, which throws `new ObservationError('NO_SNAPSHOT', 'No collector snapshot for host "web-1".')`, then add:
```ts
it('turns ObservationError into unverifiable without network wording', async () => {
  const { ctx } = await makeCtx();
  const r = await runInstance(ctx, hostSubject(ctx), inst('a', 'observe', ['host']), TYPES);
  expect(r.outcome).toBe('unverifiable');
  expect(r.observed).toBe('No collector snapshot for host "web-1". This does not mean the issue is fixed.');
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run test/host/store.test.ts test/checks/context.test.ts test/checks/runner.test.ts`
Expected: FAIL. `SnapshotStore` and `getSnapshot` don't exist, `makeCtx` ignores its third argument, and the runner reports `error`.

- [ ] **Step 3: Implement**

Replace `src/host/store.ts` with:
```ts
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';
import { projectStateDir } from '../paths.js';
import { decodeSnapshot, SnapshotEnvelopeSchema, type HostSnapshot } from './snapshot.js';

export const MAX_SNAPSHOT_AGE_DAYS = 7;

export interface StoredSnapshot {
  snapshot: HostSnapshot;
  file: string;
}

export interface SnapshotReader {
  latest(host: string): Promise<StoredSnapshot | undefined>;
}

/** Collector outputs under .secagent/hosts/<host>/<collected_at>.json (git-ignored). */
export class SnapshotStore implements SnapshotReader {
  readonly dir: string;

  constructor(projectDir: string) {
    this.dir = path.join(projectStateDir(projectDir), 'hosts');
  }

  async add(host: string, text: string): Promise<StoredSnapshot> {
    if (!/^[a-z0-9][a-z0-9-]*$/.test(host)) throw new ObservationError('SNAPSHOT_INVALID', `Invalid host name "${host}"`);
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      throw new ObservationError('SNAPSHOT_INVALID', `Snapshot is not JSON: ${(e as Error).message}`);
    }
    const snapshot = decodeSnapshot(raw);
    const file = path.join(this.dir, host, `${snapshot.collected_at.replace(/[-:]/g, '')}.json`);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify(SnapshotEnvelopeSchema.parse(raw))}\n`, 'utf8');
    return { snapshot, file };
  }

  async latest(host: string): Promise<StoredSnapshot | undefined> {
    let names: string[];
    try {
      names = await readdir(path.join(this.dir, host));
    } catch {
      return undefined;
    }
    let best: StoredSnapshot | undefined;
    for (const name of names.filter((n) => n.endsWith('.json'))) {
      const file = path.join(this.dir, host, name);
      try {
        const snapshot = decodeSnapshot(JSON.parse(await readFile(file, 'utf8')));
        if (!best || snapshot.collected_at > best.snapshot.collected_at) best = { snapshot, file };
      } catch {
        // Unreadable or invalid snapshot files are ignored; `snapshot add` validates new ones.
      }
    }
    return best;
  }
}
```

In `src/checks/context.ts`:
- Add the imports `import type { Advisories } from '../advisories/types.js';`, `import { MAX_SNAPSHOT_AGE_DAYS, type SnapshotReader, type StoredSnapshot } from '../host/store.js';` and `import { ObservationError } from './errors.js';`.
- Change the `Host` import to stay a type import.
- Add the two fields to `CheckContext`:
  ```ts
  /** Collector snapshots for host checks. */
  snapshots: SnapshotReader;
  /** Distro advisory sources (OSV, Ubuntu, CISA KEV). */
  advisories: Advisories;
  ```
- Append:
  ```ts
  /** The newest snapshot for a host, once per scan. Missing or older than MAX_SNAPSHOT_AGE_DAYS → ObservationError (unverifiable). */
  export function getSnapshot(ctx: CheckContext, host: Host): Promise<StoredSnapshot> {
    return memoize(ctx, `SNAPSHOT ${host.name}`, async () => {
      const stored = await ctx.snapshots.latest(host.name);
      if (!stored) {
        throw new ObservationError(
          'NO_SNAPSHOT',
          `No collector snapshot for host "${host.name}". Run "secagent collector --host ${host.name}", run it on the host, then "secagent snapshot add --host ${host.name} <file>".`,
        );
      }
      const ageDays = (ctx.now().getTime() - Date.parse(stored.snapshot.collected_at)) / 86_400_000;
      if (ageDays > MAX_SNAPSHOT_AGE_DAYS) {
        throw new ObservationError(
          'SNAPSHOT_STALE',
          `The newest snapshot for host "${host.name}" is ${Math.floor(ageDays)} days old (limit ${MAX_SNAPSHOT_AGE_DAYS}). Re-run the collector.`,
        );
      }
      return stored;
    });
  }
  ```

In `src/checks/runner.ts`, add `import { ObservationError } from './errors.js';`. At the top of the `catch` block, after computing `message` and `label`, insert:
```ts
    if (e instanceof ObservationError) {
      const observed = `${message} This does not mean the issue is fixed.`;
      const evidence_id = await ctx.evidence.put('note', base.target, observed, { code: e.code, message, scan_label: label });
      return { ...base, outcome: 'unverifiable', severity: instance.severity, observed, evidence_id };
    }
```
To make that compile, move the existing `const label = ctx.project.network.scan_label;` line above this block.

In `src/evidence/store.ts`: `export type EvidenceKind = 'http' | 'tls' | 'tcp' | 'note' | 'snapshot' | 'advisory';`

In `src/scan/no-ai.ts`:
- Add the imports `import { createAdvisories } from '../advisories/index.js';`, `import type { Advisories } from '../advisories/types.js';` and `import { SnapshotStore, type SnapshotReader } from '../host/store.js';`.
- Add to `ScanDeps`:
  ```ts
  /** Defaults to the project's .secagent/hosts store. */
  snapshots?: SnapshotReader;
  /** Defaults to live OSV/Ubuntu/KEV clients with the user cache. */
  advisories?: Advisories;
  ```
- Add to the `ctx` literal:
  ```ts
    snapshots: deps.snapshots ?? new SnapshotStore(projectDir),
    advisories: deps.advisories ?? createAdvisories({ now }),
  ```

In `test/helpers/ctx.ts`:
- Add the imports `import type { Advisories } from '../../src/advisories/types.js';` and `import type { SnapshotReader } from '../../src/host/store.js';`.
- Export:
  ```ts
  export const NO_SNAPSHOTS: SnapshotReader = { latest: async () => undefined };

  const unstubbedAdvisory = async (): Promise<never> => {
    throw new Error('advisories were not stubbed in this test');
  };
  export const NO_ADVISORIES: Advisories = {
    osv: { affected: unstubbedAdvisory, vulnsFor: unstubbedAdvisory, vuln: unstubbedAdvisory },
    ubuntu: { cve: unstubbedAdvisory },
    kev: { catalog: unstubbedAdvisory },
  };
  ```
- Add a third parameter to `makeCtx`, `deps: { snapshots?: SnapshotReader; advisories?: Advisories } = {}`, and add to the `ctx` literal:
  ```ts
    snapshots: deps.snapshots ?? NO_SNAPSHOTS,
    advisories: deps.advisories ?? NO_ADVISORIES,
  ```

In `test/checks/types/tls.test.ts`, add `NO_SNAPSHOTS` and `NO_ADVISORIES` to the imports from `../../helpers/ctx.js` (add that import), and add `snapshots: NO_SNAPSHOTS, advisories: NO_ADVISORIES,` to the `ctx` literal in `setup`.

- [ ] **Step 4: Run the full suite and typecheck**

Run: `npx vitest run && npx tsc -p tsconfig.json`
Expected: every test passes (lab and live are skipped); `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/host/store.ts src/checks/context.ts src/checks/runner.ts src/evidence/store.ts src/scan/no-ai.ts test/helpers/ctx.ts test/checks/types/tls.test.ts test/host/store.test.ts test/checks/context.test.ts test/checks/runner.test.ts
git commit -m "feat(host): store snapshots and expose them and advisories to checks"
```

---

### Task 7: `host_config` check type with six seed instances

**Files:**
- Create: `src/checks/types/host-config.ts`
- Create: `knowledge/checks/host-ssh-password-auth.yaml`, `host-ssh-root-login.yaml`, `host-nginx-server-tokens.yaml`, `host-nginx-ssl-protocols.yaml`, `host-listening-databases.yaml`, `host-auto-upgrades.yaml`
- Modify: `src/checks/registry.ts`, `test/checks/registry.test.ts`
- Test: `test/checks/types/host-config.test.ts`

**Interfaces:**
- Consumes: `HostSnapshot`, `nginxDirectiveValues` (Task 3); `ObservationError`; `getSnapshot` (Task 6); `CheckType` (Plan 1)
- Produces: `hostConfigParams`, `type HostConfigParams`, `evaluateHostConfig(snapshot, params): { outcome; observed; excerpt }`, `hostConfigCheck`

- [ ] **Step 1: Write the failing test**

`test/checks/types/host-config.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { evaluateHostConfig, hostConfigCheck, hostConfigParams } from '../../../src/checks/types/host-config.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, withSection } from '../../helpers/snapshots.js';

const P = (p: Record<string, unknown>) => hostConfigParams.parse(p);
const noble = fixtureSnapshot('ubuntu-24-04');

describe('evaluateHostConfig on a real Ubuntu 24.04 snapshot', () => {
  it('checks sshd -T values', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'sshd_value', key: 'PasswordAuthentication', allowed: ['no'] }))).toMatchObject({
      outcome: 'fail',
      observed: 'passwordauthentication yes (expected no)',
    });
    expect(
      evaluateHostConfig(noble, P({ rule: 'sshd_value', key: 'permitrootlogin', allowed: ['no', 'prohibit-password', 'without-password'] })).outcome,
    ).toBe('pass');
  });

  it('checks nginx directives, applying defaults and ignoring comments', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'nginx_directive', directive: 'server_tokens', equals: 'off', absent_default: 'on' }))).toMatchObject({
      outcome: 'fail',
      observed: 'server_tokens on (not set; nginx default "on" applies) (expected off)',
    });
    expect(
      evaluateHostConfig(noble, P({ rule: 'nginx_directive', directive: 'ssl_protocols', forbid_tokens: ['SSLv3', 'TLSv1', 'TLSv1.1'] })).observed,
    ).toBe('ssl_protocols allows TLSv1, TLSv1.1');
  });

  it('checks listening sockets and unattended-upgrades', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'listening', forbid_public_ports: [5432, 6379] })).outcome).toBe('pass');
    expect(evaluateHostConfig(noble, P({ rule: 'listening', forbid_public_ports: [22] })).observed).toContain('22/sshd');
    expect(evaluateHostConfig(noble, P({ rule: 'auto_upgrades' })).outcome).toBe('pass');
  });
});

describe('evaluateHostConfig edge cases', () => {
  const env = fixtureEnvelope('ubuntu-24-04');

  it('passes when sshd or nginx is not installed, and is unverifiable when unreadable', () => {
    const noSshd = decodeSnapshot(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127));
    expect(evaluateHostConfig(noSshd, P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] })).observed).toBe(
      'sshd is not installed on this host',
    );
    const notRoot = decodeSnapshot(withSection(env, 'sshd', 'sshd: no hostkeys available -- exiting.', 255));
    expect(() => evaluateHostConfig(notRoot, P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] }))).toThrow(ObservationError);
  });

  it('treats an unset ssl_protocols as unverifiable, a missing ss as unverifiable, and a missing unattended-upgrades as fail', () => {
    const noProtocols = decodeSnapshot(withSection(env, 'nginx', 'http { server { listen 80; } }'));
    expect(() => evaluateHostConfig(noProtocols, P({ rule: 'nginx_directive', directive: 'ssl_protocols', forbid_tokens: ['TLSv1'] }))).toThrow(
      /depends on the nginx version/,
    );
    const noSs = decodeSnapshot(withSection(env, 'listening', 'sh: 1: ss: not found', 127));
    expect(() => evaluateHostConfig(noSs, P({ rule: 'listening', forbid_public_ports: [5432] }))).toThrow(ObservationError);
    const noUu = decodeSnapshot(withSection(env, 'auto_upgrades', '', 1));
    expect(evaluateHostConfig(noUu, P({ rule: 'auto_upgrades' })).observed).toBe('unattended-upgrades is not installed');
  });
});

describe('host_config check', () => {
  it('reads the snapshot through the context and stores only an excerpt as evidence', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(noble) });
    const out = await hostConfigCheck.run(ctx, hostSubject(ctx), P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] }), {} as never);
    expect(out.outcome).toBe('fail');
    const ev = await ctx.evidence.get(out.evidence_id);
    expect(ev.kind).toBe('snapshot');
    expect(ev.data).toEqual({ snapshot: '20261028T143146Z.json', collected_at: '2026-10-28T14:31:46Z', rule: 'sshd_value', excerpt: { passwordauthentication: 'yes' } });
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run test/checks/types/host-config.test.ts`
Expected: FAIL, because the module can't be resolved.

- [ ] **Step 3: Implement `src/checks/types/host-config.ts`**

```ts
import path from 'node:path';
import { z } from 'zod';
import { nginxDirectiveValues } from '../../host/parse.js';
import type { HostSnapshot } from '../../host/snapshot.js';
import type { CheckType } from '../check-type.js';
import { getSnapshot } from '../context.js';
import { ObservationError } from '../errors.js';

const Port = z.number().int().min(1).max(65535);

export const hostConfigParams = z.discriminatedUnion('rule', [
  z.object({
    rule: z.literal('sshd_value'),
    key: z
      .string()
      .min(1)
      .transform((k) => k.toLowerCase()),
    allowed: z.array(z.string()).min(1),
  }),
  z.object({
    rule: z.literal('nginx_directive'),
    directive: z.string().regex(/^[a-z_]+$/),
    equals: z.string().optional(),
    forbid_tokens: z.array(z.string()).optional(),
    /** nginx's built-in default when the directive is never set (e.g. server_tokens → "on"). */
    absent_default: z.string().optional(),
    when_absent: z.enum(['pass', 'fail', 'unverifiable']).default('unverifiable'),
  }),
  z.object({ rule: z.literal('listening'), forbid_public_ports: z.array(Port).min(1) }),
  z.object({ rule: z.literal('auto_upgrades') }),
]);
export type HostConfigParams = z.infer<typeof hostConfigParams>;

export interface HostConfigVerdict {
  outcome: 'pass' | 'fail';
  observed: string;
  /** The part of the snapshot the verdict rests on (stored as evidence). */
  excerpt: unknown;
}

const WILDCARD = new Set(['0.0.0.0', '::', '*']);

export function evaluateHostConfig(snap: HostSnapshot, p: HostConfigParams): HostConfigVerdict {
  switch (p.rule) {
    case 'sshd_value': {
      if (snap.sshd.state === 'absent') return { outcome: 'pass', observed: 'sshd is not installed on this host', excerpt: snap.sshd };
      if (snap.sshd.state === 'error') {
        throw new ObservationError('SSHD_UNREADABLE', `"sshd -T" failed (${snap.sshd.reason}); run the collector as root.`);
      }
      const value = snap.sshd.value[p.key];
      if (value === undefined) throw new ObservationError('SSHD_KEY_MISSING', `"sshd -T" did not report ${p.key}.`);
      const ok = p.allowed.some((a) => a.toLowerCase() === value.toLowerCase());
      return {
        outcome: ok ? 'pass' : 'fail',
        observed: ok ? `${p.key} ${value}` : `${p.key} ${value} (expected ${p.allowed.join(' or ')})`,
        excerpt: { [p.key]: value },
      };
    }
    case 'nginx_directive': {
      if (snap.nginx.state === 'absent') return { outcome: 'pass', observed: 'nginx is not installed on this host', excerpt: snap.nginx };
      if (snap.nginx.state === 'error') {
        throw new ObservationError('NGINX_UNREADABLE', `"nginx -T" failed (${snap.nginx.reason}); run the collector as root.`);
      }
      let values = nginxDirectiveValues(snap.nginx.value, p.directive);
      let note = '';
      if (values.length === 0) {
        if (p.absent_default !== undefined) {
          values = [p.absent_default];
          note = ` (not set; nginx default "${p.absent_default}" applies)`;
        } else if (p.when_absent === 'unverifiable') {
          throw new ObservationError(
            'NGINX_DIRECTIVE_ABSENT',
            `${p.directive} is not set anywhere, so the effective value depends on the nginx version; set it explicitly.`,
          );
        } else {
          return { outcome: p.when_absent, observed: `${p.directive} is not set`, excerpt: { [p.directive]: [] } };
        }
      }
      const excerpt = { [p.directive]: values };
      if (p.equals !== undefined) {
        const expected = p.equals.toLowerCase();
        const bad = [...new Set(values.filter((v) => v.toLowerCase() !== expected))];
        if (bad.length > 0) return { outcome: 'fail', observed: `${p.directive} ${bad.join(' / ')}${note} (expected ${p.equals})`, excerpt };
      }
      if (p.forbid_tokens) {
        const forbidden = new Set(p.forbid_tokens.map((t) => t.toLowerCase()));
        const hits = [...new Set(values.flatMap((v) => v.split(/\s+/)).filter((t) => forbidden.has(t.toLowerCase())))];
        if (hits.length > 0) return { outcome: 'fail', observed: `${p.directive} allows ${hits.join(', ')}${note}`, excerpt };
      }
      return { outcome: 'pass', observed: `${p.directive} ${[...new Set(values)].join(' / ')}${note}`, excerpt };
    }
    case 'listening': {
      if (snap.listening.state !== 'ok') {
        throw new ObservationError('LISTENING_UNREADABLE', `"ss -tlnp" was not available (${snap.listening.reason}).`);
      }
      const ports = new Set(p.forbid_public_ports);
      const relevant = snap.listening.value.filter((s) => ports.has(s.port));
      const exposed = relevant.filter((s) => WILDCARD.has(s.address));
      if (exposed.length > 0) {
        return {
          outcome: 'fail',
          observed: `listening on all interfaces: ${exposed.map((s) => `${s.port}${s.process ? `/${s.process}` : ''}`).join(', ')}`,
          excerpt: exposed,
        };
      }
      return { outcome: 'pass', observed: `none of ${ports.size} database/admin ports listen on all interfaces`, excerpt: relevant };
    }
    case 'auto_upgrades': {
      const a = snap.auto_upgrades;
      if (!a.installed) return { outcome: 'fail', observed: 'unattended-upgrades is not installed', excerpt: a };
      if (!a.enabled) return { outcome: 'fail', observed: 'unattended-upgrades is installed but APT::Periodic::Unattended-Upgrade is not "1"', excerpt: a };
      return { outcome: 'pass', observed: 'unattended-upgrades is installed and enabled', excerpt: a };
    }
  }
}

export const hostConfigCheck: CheckType<HostConfigParams> = {
  type: 'host_config',
  supports: ['host'],
  params: hostConfigParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'host') throw new Error('host_config runs on hosts only');
    const { snapshot, file } = await getSnapshot(ctx, subject.host);
    const verdict = evaluateHostConfig(snapshot, p);
    const evidence_id = await ctx.evidence.put('snapshot', subject.host.name, `${p.rule} from snapshot ${snapshot.collected_at}`, {
      snapshot: path.basename(file),
      collected_at: snapshot.collected_at,
      rule: p.rule,
      excerpt: verdict.excerpt,
    });
    return { outcome: verdict.outcome, observed: verdict.observed, evidence_id };
  },
};
```

- [ ] **Step 4: Register the type and write the seed instances**

In `src/checks/registry.ts`, import `hostConfigCheck` from `./types/host-config.js` and append it to `ALL`. In `test/checks/registry.test.ts`, add `'host_config'` to the expected sorted list, between `'header_budget'` and `'http_cookie'`.

`knowledge/checks/host-ssh-password-auth.yaml`:
```yaml
id: host-ssh-password-auth
type: host_config
title: SSH password authentication is disabled
severity: medium
applies_to: [host]
params:
  rule: sshd_value
  key: passwordauthentication
  allowed: ['no']
fix_hints:
  any: 'Set "PasswordAuthentication no" (and "KbdInteractiveAuthentication no") in /etc/ssh/sshd_config or a drop-in under /etc/ssh/sshd_config.d/, run "sshd -t", then reload ssh. Make sure key-based access works first.'
source_url: https://man.openbsd.org/sshd_config
added_by: seed
review: approved
```

`knowledge/checks/host-ssh-root-login.yaml`:
```yaml
id: host-ssh-root-login
type: host_config
title: SSH root login is disabled or key-only
severity: medium
applies_to: [host]
params:
  rule: sshd_value
  key: permitrootlogin
  allowed: ['no', 'prohibit-password', 'without-password', 'forced-commands-only']
fix_hints:
  any: 'Set "PermitRootLogin no" (or prohibit-password) in sshd_config, run "sshd -t", then reload ssh.'
source_url: https://man.openbsd.org/sshd_config
added_by: seed
review: approved
```

`knowledge/checks/host-nginx-server-tokens.yaml`:
```yaml
id: host-nginx-server-tokens
type: host_config
title: nginx hides its version (server_tokens off)
severity: low
applies_to: [host]
params:
  rule: nginx_directive
  directive: server_tokens
  equals: 'off'
  absent_default: 'on'
fix_hints:
  nginx: 'server_tokens off;  in the http block of /etc/nginx/nginx.conf, then nginx -t && systemctl reload nginx'
source_url: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
added_by: seed
review: approved
```

`knowledge/checks/host-nginx-ssl-protocols.yaml`:
```yaml
id: host-nginx-ssl-protocols
type: host_config
title: nginx ssl_protocols excludes SSLv3, TLS 1.0 and TLS 1.1
severity: medium
applies_to: [host]
params:
  rule: nginx_directive
  directive: ssl_protocols
  forbid_tokens: [SSLv2, SSLv3, TLSv1, TLSv1.1]
  when_absent: unverifiable
fix_hints:
  nginx: 'ssl_protocols TLSv1.2 TLSv1.3;  in every http/server block that sets it (Ubuntu and Debian ship TLSv1 and TLSv1.1 in nginx.conf), then nginx -t && systemctl reload nginx'
source_url: https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols
added_by: seed
review: approved
```

`knowledge/checks/host-listening-databases.yaml`:
```yaml
id: host-listening-databases
type: host_config
title: Databases and admin services do not listen on all interfaces
severity: high
applies_to: [host]
params:
  rule: listening
  forbid_public_ports: [2375, 3306, 5432, 6379, 9200, 11211, 27017]
fix_hints:
  any: 'Bind the service to 127.0.0.1 or a private interface (e.g. postgresql listen_addresses, redis bind, mysqld bind-address) and keep the security group closed to the internet.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/host-auto-upgrades.yaml`:
```yaml
id: host-auto-upgrades
type: host_config
title: Automatic security updates are enabled
severity: medium
applies_to: [host]
params:
  rule: auto_upgrades
fix_hints:
  any: 'apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades (writes APT::Periodic::Unattended-Upgrade "1" to /etc/apt/apt.conf.d/20auto-upgrades).'
source_url: https://wiki.debian.org/UnattendedUpgrades
added_by: seed
review: approved
```

- [ ] **Step 5: Run the full suite and typecheck**

Run: `npx vitest run && npx tsc -p tsconfig.json`
Expected: all PASS, including the seed catalog (22 instances) and the registry test; `tsc` exits 0.

- [ ] **Step 6: Commit**

```bash
git add src/checks/types/host-config.ts src/checks/registry.ts knowledge/checks/host-ssh-password-auth.yaml knowledge/checks/host-ssh-root-login.yaml knowledge/checks/host-nginx-server-tokens.yaml knowledge/checks/host-nginx-ssl-protocols.yaml knowledge/checks/host-listening-databases.yaml knowledge/checks/host-auto-upgrades.yaml test/checks/types/host-config.test.ts test/checks/registry.test.ts
git commit -m "feat(checks): add host_config checks for sshd, nginx, listeners and auto-updates"
```

---

### Task 8: `host_package` check type with three seed instances

**Files:**
- Create: `src/checks/types/host-package.ts`, `knowledge/checks/host-package-advisories.yaml`, `host-package-third-party.yaml`, `host-reboot-pending.yaml`
- Modify: `src/checks/registry.ts`, `test/checks/registry.test.ts`
- Test: `test/checks/types/host-package.test.ts`

**Interfaces:**
- Consumes: `HostSnapshot`, `classifyOrigin`, `aptListsEmpty` (Task 3); `distroOf`, `fixedVersionFor`, `cveIdsOf`, `ubuntuPriority`, `Advisories`, `PackageQuery` (Tasks 4–5); `compareDebVersions` (Task 1); `getSnapshot`, `ObservationError`; `maxSeverity`, `Severity` (Plan 1)
- Produces:
  - `hostPackageParams`
  - `distroSources(snapshot, codename): PackageQuery[]`
  - `interface FixablePackage`
  - `findFixable(advisories, ecosystem, sources): Promise<{ fixable; unfixed; kev_available }>`
  - `hostPackageCheck`

- [ ] **Step 1: Write the failing test**

`test/checks/types/host-package.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { distroSources, findFixable, hostPackageCheck, hostPackageParams } from '../../../src/checks/types/host-package.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { fixtureAdvisories } from '../../helpers/advisories.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion } from '../../helpers/snapshots.js';
import { tempDir } from '../../helpers/tmp.js';

const P = (p: Record<string, unknown>) => hostPackageParams.parse(p);

async function run(snapshot: ReturnType<typeof decodeSnapshot>, params: Record<string, unknown>, extraKev: string[] = []) {
  const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(snapshot), advisories: fixtureAdvisories(await tempDir(), extraKev) });
  return hostPackageCheck.run(ctx, hostSubject(ctx), P(params), {} as never);
}

describe('distroSources', () => {
  it('returns one entry per source package at its highest installed version', () => {
    const sources = distroSources(fixtureSnapshot('ubuntu-24-04'), 'noble');
    expect(sources.filter((s) => s.name === 'openssh')).toEqual([{ name: 'openssh', version: '1:9.6p1-3ubuntu13.20' }]);
    expect(new Set(sources.map((s) => s.name)).size).toBe(sources.length);
  });
});

describe('host_package advisories', () => {
  it('passes a fully patched host', async () => {
    const out = await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('no security fixes pending');
  });

  it('fails an outdated openssh with the fixed versions, at the highest Ubuntu priority', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const out = await run(old, { assert: 'advisories' });
    expect(out).toMatchObject({ outcome: 'fail', severity: 'high' });
    expect(out.observed).toContain('CVE-2024-6387 high fixed in 1:9.6p1-3ubuntu13.3');
  });

  it('escalates to critical when a CVE is on the CISA KEV list', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const out = await run(old, { assert: 'advisories' }, ['CVE-2025-26465']);
    expect(out.severity).toBe('critical');
    expect(out.observed).toContain('KEV');
  });

  it('counts advisories without a released fix but does not fail on them', async () => {
    const out = await run(fixtureSnapshot('ubuntu-22-04'), { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('1 advisories have no released fix yet');
  });

  it('is unverifiable for non-Debian hosts', async () => {
    const rhel = decodeSnapshot(withSection(fixtureEnvelope('ubuntu-24-04'), 'os_release', 'ID=rhel\nVERSION_ID="9.4"\n'));
    await expect(run(rhel, { assert: 'advisories' })).rejects.toBeInstanceOf(ObservationError);
  });

  it('reports KEV unavailability instead of failing the whole check', async () => {
    const snapshot = fixtureSnapshot('ubuntu-24-04');
    const advisories = fixtureAdvisories(await tempDir());
    advisories.kev = {
      catalog: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'offline');
      },
    };
    const sources = distroSources(snapshot, 'noble');
    expect((await findFixable(advisories, 'Ubuntu:24.04:LTS', sources)).kev_available).toBe(false);
  });
});

describe('host_package third_party and reboot', () => {
  const env = fixtureEnvelope('ubuntu-24-04');

  it('passes when every package comes from distro repositories', async () => {
    expect((await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'third_party' })).outcome).toBe('pass');
  });

  it('fails packages from vendor repositories or installed locally', async () => {
    const policy = `${sectionOf(env, 'apt_policy')}\nnginx:\n  Installed: 1.30.6-1~noble\n *** 1.30.6-1~noble 500\n        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages\n        100 /var/lib/dpkg/status\n`;
    const packages = sectionOf(env, 'packages').replace(/^ii \tnginx\t[^\n]*$/m, 'ii \tnginx\t1.30.6-1~noble\tnginx\t1.30.6-1~noble');
    const snap = decodeSnapshot(withSection(withSection(env, 'apt_policy', policy), 'packages', packages));
    const out = await run(snap, { assert: 'third_party' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('nginx 1.30.6-1~noble (http://nginx.org/packages/ubuntu noble/nginx amd64 Packages)');
  });

  it('is unverifiable when apt lists are empty', async () => {
    const policy = sectionOf(env, 'apt_policy').replace(/^ {8}\d+ http\S*.*$/gm, '');
    const snap = decodeSnapshot(withSection(env, 'apt_policy', policy));
    await expect(run(snap, { assert: 'third_party' })).rejects.toMatchObject({ code: 'APT_LISTS_EMPTY' });
  });

  it('flags a pending reboot', async () => {
    expect((await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'reboot' })).outcome).toBe('pass');
    const snap = decodeSnapshot(withSection(env, 'reboot', 'required\nlinux-image-6.8.0-90-generic\n'));
    expect((await run(snap, { assert: 'reboot' })).observed).toBe('a reboot is pending (packages: linux-image-6.8.0-90-generic)');
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run test/checks/types/host-package.test.ts`
Expected: FAIL, because the module can't be resolved.

- [ ] **Step 3: Implement `src/checks/types/host-package.ts`**

```ts
import path from 'node:path';
import { z } from 'zod';
import { distroOf } from '../../advisories/distro.js';
import { cveIdsOf, fixedVersionFor, ubuntuPriority } from '../../advisories/osv.js';
import type { Advisories, PackageQuery } from '../../advisories/types.js';
import { aptListsEmpty, classifyOrigin } from '../../host/origin.js';
import type { HostSnapshot } from '../../host/snapshot.js';
import { maxSeverity, SEVERITY_RANK, type Severity } from '../../types.js';
import { compareDebVersions } from '../../util/debver.js';
import type { CheckType } from '../check-type.js';
import { getSnapshot } from '../context.js';
import { ObservationError } from '../errors.js';

export const hostPackageParams = z.discriminatedUnion('assert', [
  z.object({ assert: z.literal('advisories'), max_listed: z.number().int().min(1).default(5) }),
  z.object({ assert: z.literal('third_party'), max_listed: z.number().int().min(1).default(10) }),
  z.object({ assert: z.literal('reboot') }),
]);
export type HostPackageParams = z.infer<typeof hostPackageParams>;

const PRIORITY: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', negligible: 'info' };

export interface FixablePackage {
  package: string;
  installed: string;
  advisories: Array<{ id: string; cves: string[]; fixed: string; severity: Severity; kev: boolean }>;
}

/**
 * Source packages to check against distro advisories, one per source at its highest installed version.
 * Third-party and locally installed packages are skipped, unless apt lists are empty and origins can't be known.
 */
export function distroSources(snap: HostSnapshot, codename: string): PackageQuery[] {
  const listsEmpty = aptListsEmpty(snap.origins);
  const best = new Map<string, string>();
  for (const pkg of snap.packages) {
    const kind = classifyOrigin(snap.origins[pkg.name], codename).kind;
    if (!listsEmpty && (kind === 'third_party' || kind === 'local')) continue;
    const current = best.get(pkg.source);
    if (current === undefined || compareDebVersions(pkg.source_version, current) > 0) best.set(pkg.source, pkg.source_version);
  }
  return [...best].map(([name, version]) => ({ name, version }));
}

export async function findFixable(
  advisories: Advisories,
  ecosystem: string,
  sources: readonly PackageQuery[],
): Promise<{ fixable: FixablePackage[]; unfixed: number; kev_available: boolean }> {
  const affected = await advisories.osv.affected(ecosystem, sources);
  let kev = new Set<string>();
  let kev_available = true;
  try {
    kev = await advisories.kev.catalog();
  } catch {
    kev_available = false;
  }
  const fixable: FixablePackage[] = [];
  let unfixed = 0;
  for (const q of sources.filter((s) => affected.has(s.name))) {
    const items: FixablePackage['advisories'] = [];
    for (const v of await advisories.osv.vulnsFor(ecosystem, q)) {
      const fixed = fixedVersionFor(v, ecosystem, q.name);
      if (!fixed) {
        unfixed += 1;
        continue;
      }
      if (compareDebVersions(q.version, fixed) >= 0) continue;
      const cves = cveIdsOf(v);
      const isKev = cves.some((c) => kev.has(c));
      items.push({ id: v.id, cves, fixed, severity: isKev ? 'critical' : (PRIORITY[ubuntuPriority(v) ?? ''] ?? 'medium'), kev: isKev });
    }
    if (items.length > 0) fixable.push({ package: q.name, installed: q.version, advisories: items });
  }
  return { fixable, unfixed, kev_available };
}

function describeFixable(f: FixablePackage): string {
  const sorted = [...f.advisories].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const top = sorted[0];
  const head = top ? `${top.cves[0] ?? top.id} ${top.severity}${top.kev ? ' KEV' : ''} fixed in ${top.fixed}` : '';
  return `${f.package} ${f.installed} (${f.advisories.length}: ${head}${f.advisories.length > 1 ? ', ...' : ''})`;
}

export const hostPackageCheck: CheckType<HostPackageParams> = {
  type: 'host_package',
  supports: ['host'],
  params: hostPackageParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'host') throw new Error('host_package runs on hosts only');
    const { snapshot, file } = await getSnapshot(ctx, subject.host);
    const name = subject.host.name;
    const base = { snapshot: path.basename(file), collected_at: snapshot.collected_at };
    const osName = snapshot.os.pretty_name || snapshot.os.id;

    if (p.assert === 'reboot') {
      const evidence_id = await ctx.evidence.put('snapshot', name, 'reboot-required state', { ...base, excerpt: snapshot.reboot });
      if (!snapshot.reboot.required) return { outcome: 'pass', observed: 'no reboot pending', evidence_id };
      const pkgs = snapshot.reboot.packages.join(', ') || 'unspecified';
      return { outcome: 'fail', observed: `a reboot is pending (packages: ${pkgs})`, evidence_id };
    }

    if (p.assert === 'third_party') {
      if (aptListsEmpty(snapshot.origins)) {
        throw new ObservationError(
          'APT_LISTS_EMPTY',
          'apt package lists are empty on this host (cleaned or never fetched), so package origins cannot be determined. Run "apt-get update" before the collector.',
        );
      }
      const seen = new Set<string>();
      const items: Array<{ package: string; version: string; origin: string }> = [];
      for (const pkg of snapshot.packages) {
        if (seen.has(pkg.name)) continue;
        seen.add(pkg.name);
        const o = classifyOrigin(snapshot.origins[pkg.name], snapshot.os.codename);
        if (o.kind === 'third_party') items.push({ package: pkg.name, version: pkg.version, origin: o.repo ?? 'unknown repository' });
        if (o.kind === 'local') items.push({ package: pkg.name, version: pkg.version, origin: 'installed locally, not from any configured repository' });
      }
      const evidence_id = await ctx.evidence.put('snapshot', name, `package origins (${items.length} non-distro)`, { ...base, excerpt: items });
      if (items.length === 0) return { outcome: 'pass', observed: `all ${seen.size} packages come from ${osName} repositories`, evidence_id };
      const listed = items.slice(0, p.max_listed).map((i) => `${i.package} ${i.version} (${i.origin})`);
      const more = items.length > p.max_listed ? `, and ${items.length - p.max_listed} more` : '';
      return {
        outcome: 'fail',
        observed: `${items.length} package(s) are not from ${osName} repositories, so distro security updates and unattended-upgrades do not cover them: ${listed.join('; ')}${more}`,
        evidence_id,
        details: { third_party: items },
      };
    }

    const distro = distroOf(snapshot.os);
    if (!distro) throw new ObservationError('UNSUPPORTED_DISTRO', `Package advisories are checked for Ubuntu and Debian only; this host runs "${osName}".`);
    if (snapshot.packages.length === 0) throw new ObservationError('NO_PACKAGES', 'The snapshot lists no installed packages (dpkg-query was unavailable).');
    const sources = distroSources(snapshot, distro.codename);
    const { fixable, unfixed, kev_available } = await findFixable(ctx.advisories, distro.ecosystem, sources);
    const evidence_id = await ctx.evidence.put('advisory', name, `${sources.length} packages checked against ${distro.ecosystem}`, {
      ...base,
      ecosystem: distro.ecosystem,
      checked: sources.length,
      fixable,
      unfixed,
      kev_available,
    });
    const kevNote = kev_available ? '' : '; CISA KEV was unavailable, so known-exploited CVEs were not escalated';
    if (fixable.length === 0) {
      const unfixedNote = unfixed > 0 ? `; ${unfixed} advisories have no released fix yet` : '';
      return {
        outcome: 'pass',
        observed: `${sources.length} distro source packages checked against ${distro.ecosystem} advisories; no security fixes pending${unfixedNote}${kevNote}`,
        evidence_id,
      };
    }
    const severity = maxSeverity(fixable.flatMap((f) => f.advisories.map((a) => a.severity)));
    const more = fixable.length > p.max_listed ? `; and ${fixable.length - p.max_listed} more` : '';
    return {
      outcome: 'fail',
      severity,
      observed: `${fixable.length} package(s) have security fixes not installed: ${fixable.slice(0, p.max_listed).map(describeFixable).join('; ')}${more}${kevNote}`,
      evidence_id,
      details: { fixable },
    };
  },
};
```

- [ ] **Step 4: Register the type and write the seed instances**

In `src/checks/registry.ts`, import `hostPackageCheck` and append it to `ALL`. In `test/checks/registry.test.ts`, add `'host_package'` after `'host_config'`.

`knowledge/checks/host-package-advisories.yaml`:
```yaml
id: host-package-advisories
type: host_package
title: Installed packages have no distro security fixes pending
severity: high
applies_to: [host]
params:
  assert: advisories
  max_listed: 5
fix_hints:
  any: 'apt-get update && apt-get upgrade (or unattended-upgrade -d for security-only), then reboot if /var/run/reboot-required exists.'
source_url: https://ubuntu.com/security/notices
added_by: seed
review: approved
```

`knowledge/checks/host-package-third-party.yaml`:
```yaml
id: host-package-third-party
type: host_package
title: Packages outside distro repositories are known and patched separately
severity: medium
applies_to: [host]
params:
  assert: third_party
  max_listed: 10
fix_hints:
  any: 'For each listed package, either switch to the distro package or add its vendor repository to unattended-upgrades (Unattended-Upgrade::Origins-Pattern) and track the vendor security advisories (e.g. nginx.org/en/security_advisories.html).'
source_url: https://wiki.debian.org/UnattendedUpgrades
added_by: seed
review: approved
```

`knowledge/checks/host-reboot-pending.yaml`:
```yaml
id: host-reboot-pending
type: host_package
title: No reboot is pending after updates
severity: medium
applies_to: [host]
params:
  assert: reboot
fix_hints:
  any: 'Schedule a reboot (or use livepatch for the kernel); until then the running kernel and libraries are the old, vulnerable versions.'
source_url: https://wiki.debian.org/UnattendedUpgrades
added_by: seed
review: approved
```

- [ ] **Step 5: Run the full suite and typecheck**

Run: `npx vitest run && npx tsc -p tsconfig.json`
Expected: all PASS (the seed catalog now has 25 instances); `tsc` exits 0.

- [ ] **Step 6: Commit**

```bash
git add src/checks/types/host-package.ts src/checks/registry.ts knowledge/checks/host-package-advisories.yaml knowledge/checks/host-package-third-party.yaml knowledge/checks/host-reboot-pending.yaml test/checks/types/host-package.test.ts test/checks/registry.test.ts
git commit -m "feat(checks): add host_package checks for advisories, third-party packages and reboots"
```

---

### Task 9: `verifyClaim`

**Files:**
- Create: `src/verify/claim.ts`
- Test: `test/verify/claim.test.ts`

**Interfaces:**
- Consumes: `SnapshotReader`, `StoredSnapshot` (Task 6); `distroOf`, `fixedVersionFor`, `Advisories` (Task 5); `compareDebVersions`; `EvidenceStore`; `Host`
- Produces:
  - `CLAIM_VERDICTS`, `type ClaimVerdict`
  - `interface PackageVerdict { package; installed?; distro_status; fixed?; verdict; note }`
  - `interface ClaimResult { cve; host; verdict; reason; packages; kev; source_url; snapshot; evidence_id }`
  - `interface ClaimDeps { host; snapshots; advisories; evidence; now? }`
  - `verifyClaim(deps, { cve, package? }): Promise<ClaimResult>`

Verdict rules (spec §7.1 and §8.5):
- **Precedence:** when several packages match, the overall verdict is the first one in `vulnerable`, `no_fix_available`, `unverifiable`, `fixed_in_installed`, `not_affected`.
- **Ubuntu:** use `https://ubuntu.com/security/cves/<CVE>.json`, the status for the host's codename and each installed source package:
  - `released` → compare the installed version with the fixed version.
  - `not-affected` and `DNE` → `not_affected`.
  - Any other status → `no_fix_available`.
- **Debian:** use OSV `DEBIAN-<CVE>`, the entry for `Debian:<major>` and each installed source package. A `fixed` event → compare; no fixed event → `no_fix_available`.
- **Not installed:** if no package the advisory tracks is installed → `not_affected`.
- **Unverifiable:** no snapshot, an unsupported distro, or no advisory record.

- [ ] **Step 1: Write the failing test**

`test/verify/claim.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import type { Advisories } from '../../src/advisories/types.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import { decodeSnapshot, type HostSnapshot } from '../../src/host/snapshot.js';
import { validateProject } from '../../src/project/schema.js';
import { verifyClaim } from '../../src/verify/claim.js';
import { fixtureAdvisories } from '../helpers/advisories.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion } from '../helpers/snapshots.js';
import { tempDir } from '../helpers/tmp.js';

const host = validateProject({ version: 1, name: 't', hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] }).hosts[0]!;

async function verify(snapshot: HostSnapshot | undefined, cve: string, opts: { pkg?: string; kev?: string[]; advisories?: Advisories } = {}) {
  const dir = await tempDir();
  return verifyClaim(
    {
      host,
      snapshots: readerFor(snapshot),
      advisories: opts.advisories ?? fixtureAdvisories(await tempDir(), opts.kev ?? []),
      evidence: new EvidenceStore(dir, 'test'),
      now: () => new Date('2026-10-28T15:00:00Z'),
    },
    { cve, ...(opts.pkg ? { package: opts.pkg } : {}) },
  );
}

describe('verifyClaim on Ubuntu', () => {
  it('fixed_in_installed: CVE-2024-6387 on patched noble openssh', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387');
    expect(r).toMatchObject({ verdict: 'fixed_in_installed', source_url: 'https://ubuntu.com/security/CVE-2024-6387', kev: false });
    expect(r.packages).toEqual([
      { package: 'openssh', installed: '1:9.6p1-3ubuntu13.20', distro_status: 'released', fixed: '1:9.6p1-3ubuntu13.3', verdict: 'fixed_in_installed', note: 'installed 1:9.6p1-3ubuntu13.20 >= fixed 1:9.6p1-3ubuntu13.3' },
    ]);
    expect(r.evidence_id).toMatch(/^ev_/);
  });

  it('vulnerable: same CVE with an older openssh', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    expect((await verify(old, 'CVE-2024-6387')).verdict).toBe('vulnerable');
  });

  it('not_affected: Ubuntu marks noble not-affected', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2021-41617');
    expect(r.verdict).toBe('not_affected');
    expect(r.packages[0]?.distro_status).toBe('not-affected');
  });

  it('no_fix_available: Ubuntu ignores CVE-2016-20012 on jammy', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-22-04'), 'CVE-2016-20012');
    expect(r.verdict).toBe('no_fix_available');
    expect(r.packages[0]).toMatchObject({ package: 'openssh', distro_status: 'ignored' });
  });

  it('not_affected when no tracked package is installed', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const withoutSsh = sectionOf(env, 'packages')
      .split('\n')
      .filter((l) => l.split('\t')[3] !== 'openssh')
      .join('\n');
    const r = await verify(decodeSnapshot(withSection(env, 'packages', withoutSsh)), 'CVE-2024-6387');
    expect(r.verdict).toBe('not_affected');
    expect(r.reason).toContain('none of the packages Ubuntu tracks for CVE-2024-6387 (openssh, openssh-ssh1) are installed');
  });

  it('maps a binary package name to its source', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { pkg: 'openssh-server' });
    expect(r.packages.map((p) => p.package)).toEqual(['openssh']);
  });

  it('flags CISA KEV listing', async () => {
    expect((await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { kev: ['CVE-2024-6387'] })).kev).toBe(true);
  });
});

describe('verifyClaim on Debian and edge cases', () => {
  it('fixed_in_installed: CVE-2024-6387 on Debian 12 via the OSV Debian record', async () => {
    const r = await verify(fixtureSnapshot('debian-12'), 'CVE-2024-6387');
    expect(r).toMatchObject({ verdict: 'fixed_in_installed', source_url: 'https://security-tracker.debian.org/tracker/CVE-2024-6387' });
    expect(r.packages[0]).toMatchObject({ package: 'openssh', fixed: '1:9.2p1-2+deb12u3' });
  });

  it('unverifiable without an advisory record or without a snapshot', async () => {
    expect((await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-1999-0001')).verdict).toBe('unverifiable');
    const none = await verify(undefined, 'CVE-2024-6387');
    expect(none.verdict).toBe('unverifiable');
    expect(none.reason).toContain('No collector snapshot');
  });

  it('rejects a malformed CVE id', async () => {
    await expect(verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-24-1')).rejects.toThrow(/Not a CVE id/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run test/verify/claim.test.ts`
Expected: FAIL, because the module can't be resolved.

- [ ] **Step 3: Implement `src/verify/claim.ts`**

```ts
import path from 'node:path';
import { distroOf } from '../advisories/distro.js';
import { fixedVersionFor } from '../advisories/osv.js';
import type { Advisories } from '../advisories/types.js';
import type { EvidenceStore } from '../evidence/store.js';
import type { HostSnapshot } from '../host/snapshot.js';
import type { SnapshotReader } from '../host/store.js';
import type { Host } from '../project/schema.js';
import { compareDebVersions } from '../util/debver.js';

/** In precedence order: when several packages are involved, the first verdict present wins. */
export const CLAIM_VERDICTS = ['vulnerable', 'no_fix_available', 'unverifiable', 'fixed_in_installed', 'not_affected'] as const;
export type ClaimVerdict = (typeof CLAIM_VERDICTS)[number];

export interface PackageVerdict {
  package: string;
  installed?: string;
  distro_status: string;
  fixed?: string;
  verdict: ClaimVerdict;
  note: string;
}

export interface ClaimResult {
  cve: string;
  host: string;
  verdict: ClaimVerdict;
  reason: string;
  packages: PackageVerdict[];
  kev: boolean;
  source_url: string;
  snapshot: string;
  evidence_id: string;
}

export interface ClaimDeps {
  host: Host;
  snapshots: SnapshotReader;
  advisories: Advisories;
  evidence: EvidenceStore;
  now?: () => Date;
}

const NOT_AFFECTED_STATUSES = new Set(['not-affected', 'DNE']);

function overall(packages: PackageVerdict[]): ClaimVerdict {
  return CLAIM_VERDICTS.find((v) => packages.some((p) => p.verdict === v)) ?? 'unverifiable';
}

function compareInstalled(pkg: string, installed: string, fixed: string, status: string): PackageVerdict {
  const ok = compareDebVersions(installed, fixed) >= 0;
  return {
    package: pkg,
    installed,
    distro_status: status,
    fixed,
    verdict: ok ? 'fixed_in_installed' : 'vulnerable',
    note: ok ? `installed ${installed} >= fixed ${fixed}` : `installed ${installed} < fixed ${fixed}`,
  };
}

/** Source package → highest installed source version. */
function installedSources(snap: HostSnapshot): Map<string, string> {
  const map = new Map<string, string>();
  for (const p of snap.packages) {
    const cur = map.get(p.source);
    if (cur === undefined || compareDebVersions(p.source_version, cur) > 0) map.set(p.source, p.source_version);
  }
  return map;
}

/** A binary package name maps to its source; anything else is taken as a source name. */
function sourceFilter(snap: HostSnapshot, pkg: string | undefined): string | undefined {
  if (!pkg) return undefined;
  return snap.packages.find((p) => p.name === pkg)?.source ?? pkg;
}

interface Judgement {
  packages: PackageVerdict[];
  reason: string;
  source_url: string;
  /** The verdict when no installed package could be judged. */
  whenEmpty: ClaimVerdict;
}

async function judge(snap: HostSnapshot, cve: string, advisories: Advisories, only: string | undefined): Promise<Judgement> {
  const distro = distroOf(snap.os);
  if (!distro) {
    const os = snap.os.pretty_name || snap.os.id;
    return { packages: [], reason: `Only Ubuntu and Debian hosts can be verified; this host runs "${os}".`, source_url: '', whenEmpty: 'unverifiable' };
  }
  const installed = installedSources(snap);

  if (distro.family === 'ubuntu') {
    const source_url = `https://ubuntu.com/security/${cve}`;
    const record = await advisories.ubuntu.cve(cve);
    if (!record) return { packages: [], reason: `Ubuntu has no record of ${cve}.`, source_url, whenEmpty: 'unverifiable' };
    const tracked = record.packages.filter((p) => only === undefined || p.name === only);
    const packages: PackageVerdict[] = [];
    for (const p of tracked) {
      const version = installed.get(p.name);
      if (version === undefined) continue;
      const s = p.statuses.find((x) => x.release_codename === distro.codename);
      if (!s) {
        packages.push({ package: p.name, installed: version, distro_status: 'unknown', verdict: 'unverifiable', note: `Ubuntu lists no status for ${distro.codename}` });
      } else if (s.status === 'released' && s.description) {
        packages.push(compareInstalled(p.name, version, s.description, s.status));
      } else if (NOT_AFFECTED_STATUSES.has(s.status)) {
        packages.push({ package: p.name, installed: version, distro_status: s.status, verdict: 'not_affected', note: s.description || `Ubuntu: ${s.status}` });
      } else {
        packages.push({ package: p.name, installed: version, distro_status: s.status, verdict: 'no_fix_available', note: `Ubuntu status "${s.status}"${s.description ? ` (${s.description})` : ''}` });
      }
    }
    if (packages.length === 0) {
      const names = tracked.map((p) => p.name).join(', ') || 'none';
      return { packages, reason: `none of the packages Ubuntu tracks for ${cve} (${names}) are installed on this host.`, source_url, whenEmpty: 'not_affected' };
    }
    return { packages, reason: `Ubuntu ${distro.codename} status for ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  }

  const source_url = `https://security-tracker.debian.org/tracker/${cve}`;
  const record = await advisories.osv.vuln(`DEBIAN-${cve}`);
  if (!record) return { packages: [], reason: `The Debian security tracker (via OSV) has no record of ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  const entries = (record.affected ?? []).filter((a) => only === undefined || a.package.name === only);
  const forRelease = entries.filter((a) => a.package.ecosystem === distro.ecosystem);
  const packages: PackageVerdict[] = [];
  for (const a of forRelease) {
    const version = installed.get(a.package.name);
    if (version === undefined) continue;
    const fixed = fixedVersionFor(record, distro.ecosystem, a.package.name);
    packages.push(
      fixed
        ? compareInstalled(a.package.name, version, fixed, 'fixed')
        : { package: a.package.name, installed: version, distro_status: 'open', verdict: 'no_fix_available', note: `no fixed version for ${distro.ecosystem}` },
    );
  }
  if (packages.length > 0) return { packages, reason: `${distro.ecosystem} status for ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  if (entries.some((a) => installed.has(a.package.name))) {
    return {
      packages,
      reason: `The Debian record for ${cve} has no entry for ${distro.ecosystem}, so this release can't be judged.`,
      source_url,
      whenEmpty: 'unverifiable',
    };
  }
  const names = [...new Set(entries.map((a) => a.package.name))].join(', ') || 'none';
  return { packages, reason: `none of the packages Debian tracks for ${cve} (${names}) are installed on this host.`, source_url, whenEmpty: 'not_affected' };
}

/** Deterministic verdict on a third-party scanner's claim that `cve` affects `host` (spec §7.1). */
export async function verifyClaim(deps: ClaimDeps, claim: { cve: string; package?: string }): Promise<ClaimResult> {
  const cve = claim.cve.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) throw new Error(`Not a CVE id: ${claim.cve}`);
  const now = deps.now ?? (() => new Date());
  const stored = await deps.snapshots.latest(deps.host.name);

  let packages: PackageVerdict[] = [];
  let reason: string;
  let source_url = '';
  let snapshot = '';
  let verdict: ClaimVerdict = 'unverifiable';
  if (!stored) {
    reason = `No collector snapshot for host "${deps.host.name}"; run "secagent collector --host ${deps.host.name}" first.`;
  } else {
    snapshot = path.basename(stored.file);
    const judged = await judge(stored.snapshot, cve, deps.advisories, sourceFilter(stored.snapshot, claim.package));
    ({ packages, reason, source_url } = judged);
    verdict = packages.length > 0 ? overall(packages) : judged.whenEmpty;
    const ageDays = Math.floor((now().getTime() - Date.parse(stored.snapshot.collected_at)) / 86_400_000);
    if (ageDays > 7) reason += ` Note: the snapshot is ${ageDays} days old.`;
  }

  let kev = false;
  try {
    kev = (await deps.advisories.kev.catalog()).has(cve);
  } catch {
    reason += ' (CISA KEV was unavailable.)';
  }

  const evidence_id = await deps.evidence.put('advisory', deps.host.name, `verify_claim ${cve}: ${verdict}`, {
    cve,
    host: deps.host.name,
    snapshot,
    verdict,
    reason,
    packages,
    kev,
    source_url,
  });
  return { cve, host: deps.host.name, verdict, reason, packages, kev, source_url, snapshot, evidence_id };
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/verify/claim.test.ts && npx tsc -p tsconfig.json`
Expected: 10 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/verify/claim.ts test/verify/claim.test.ts
git commit -m "feat(verify): add evidence-backed verdicts for third-party CVE claims"
```

---

### Task 10: CLI commands `collector`, `snapshot add`, `verify` and `learn`

**Files:**
- Modify: `src/cli.ts`, `.gitignore`
- Test: `test/cli.test.ts` (extend)

**Interfaces:**
- Consumes: `makeCollector` (Task 2); `SnapshotStore` (Task 6); `verifyClaim`, `ClaimResult` (Task 9); `createAdvisories`, `distroOf`, `defaultCacheDir`, `Advisories` (Tasks 4–5); `distroSources` (Task 8); `Scope`, `ScopeError`, `loadProject`, `EvidenceStore`, `ObservationError`
- Produces:
  - `main(argv, deps?: CliDeps)` with `interface CliDeps { advisories?: Advisories }`
  - `formatClaim(result): string[]`
  - commands `collector`, `snapshot add`, `verify`, `learn`
  - `ScopeError` and `ObservationError` both exit 1 with their message

- [ ] **Step 1: Write the failing tests**

Append to `test/cli.test.ts`. Merge these imports into the existing block:
```ts
import { readFileSync } from 'node:fs';
import { COLLECTOR_PATH } from '../src/host/collector.js';
import { SnapshotStore } from '../src/host/store.js';
import { initProject } from '../src/project/init.js';
import { fixtureAdvisories } from './helpers/advisories.js';
import { writeFiles } from './helpers/tmp.js';
```
```ts
describe('host commands', () => {
  async function projectWithHost(): Promise<string> {
    const dir = await tempDir();
    await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
    return dir;
  }

  it('collector prints the script to stdout and instructions to stderr', async () => {
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const dir = await projectWithHost();
    expect(await main(['collector', '--dir', dir, '--host', 'web-1'])).toBe(0);
    expect(out).toHaveBeenCalledWith(readFileSync(COLLECTOR_PATH, 'utf8'));
    expect(err).toHaveBeenCalledWith(expect.stringContaining('secagent snapshot add --host web-1 web-1.json'));
  });

  it('collector refuses hosts that are not in project.yaml', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['collector', '--dir', await projectWithHost(), '--host', 'nope'])).toBe(1);
    expect(err).toHaveBeenCalledWith(expect.stringContaining('Unknown host "nope"'));
  });

  it('snapshot add validates and stores collector output', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    const fixture = readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');
    await writeFiles(dir, { 'web-1.json': fixture, 'bad.json': '{}' });
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/web-1.json`])).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Ubuntu 24.04'));
    expect((await new SnapshotStore(dir).latest('web-1'))?.snapshot.os.codename).toBe('noble');
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/bad.json`])).toBe(1);
  });

  it('verify prints a verdict using the stored snapshot', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    await new SnapshotStore(dir).add('web-1', readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    const code = await main(['verify', '--dir', dir, '--host', 'web-1', '--cve', 'CVE-2024-6387'], { advisories: fixtureAdvisories(await tempDir()) });
    expect(code).toBe(0);
    expect(log).toHaveBeenCalledWith('CVE-2024-6387 on web-1: fixed_in_installed');
  });

  it('learn warms the advisory cache for stored snapshots', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    await new SnapshotStore(dir).add('web-1', readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    expect(await main(['learn', '--dir', dir], { advisories: fixtureAdvisories(await tempDir()) })).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/^web-1: \d+ packages checked against Ubuntu:24\.04:LTS/));
  });
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `npx vitest run test/cli.test.ts`
Expected: the new tests FAIL with `Unknown command "collector"` and similar errors.

- [ ] **Step 3: Implement in `src/cli.ts`**

Add imports:
```ts
import { readFile, writeFile } from 'node:fs/promises';
import { defaultCacheDir } from './advisories/cache.js';
import { distroOf } from './advisories/distro.js';
import { createAdvisories } from './advisories/index.js';
import type { Advisories } from './advisories/types.js';
import { ObservationError } from './checks/errors.js';
import { distroSources } from './checks/types/host-package.js';
import { EvidenceStore } from './evidence/store.js';
import { makeCollector } from './host/collector.js';
import { SnapshotStore } from './host/store.js';
import { loadProject } from './project/schema.js';
import { Scope, ScopeError } from './project/scope.js';
import { verifyClaim, type ClaimResult } from './verify/claim.js';
```
Extend the existing `./project/schema.js` import instead of duplicating it.

Append to `USAGE`, before the closing backtick:
```
  collector  Print the read-only host collector script (stdout) and how to run it (stderr)
            --dir <path>   --host <name>   --out <file>
  snapshot add  Validate and store collector output for a host
            --dir <path>   --host <name>   <file>
  verify     Verdict on a scanner's CVE claim for a host, from its snapshot and distro advisories
            --dir <path>   --host <name>   --cve <CVE-id>   [--package <name>]   [--json]
  learn      Refresh CISA KEV and the package advisories for every stored host snapshot
            --dir <path>
```

Add:
```ts
export interface CliDeps {
  /** Injected advisory sources (tests); defaults to live clients with the user cache. */
  advisories?: Advisories;
}

export function formatClaim(r: ClaimResult): string[] {
  return [
    `${r.cve} on ${r.host}: ${r.verdict}${r.kev ? ' (CISA KEV: known exploited)' : ''}`,
    `  ${r.reason}`,
    ...r.packages.map(
      (p) => `  ${p.package}: installed ${p.installed ?? '-'}, distro status ${p.distro_status}${p.fixed ? `, fixed in ${p.fixed}` : ''} → ${p.verdict}`,
    ),
    ...(r.source_url ? [`  source: ${r.source_url}`] : []),
    `  evidence: ${r.evidence_id}`,
  ];
}

async function runCollector(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: { dir: { type: 'string', default: '.' }, host: { type: 'string' }, out: { type: 'string' } },
  });
  const dir = path.resolve(values.dir);
  if (values.host) new Scope(await loadProject(dir)).host(values.host);
  const bundle = await makeCollector(dir, values.host ?? 'HOST');
  if (values.out) {
    await writeFile(values.out, bundle.script, 'utf8');
    console.error(`Wrote ${values.out}`);
  } else {
    process.stdout.write(bundle.script);
  }
  console.error(bundle.instructions);
  return 0;
}

async function runSnapshot(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  const usage = 'Usage: secagent snapshot add --host <name> [--dir <path>] <file>';
  if (sub !== 'add') throw new UsageError(usage);
  const { values, positionals } = parseArgs({
    args: rest,
    strict: true,
    allowPositionals: true,
    options: { dir: { type: 'string', default: '.' }, host: { type: 'string' } },
  });
  const file = positionals[0];
  if (!values.host || !file) throw new UsageError(usage);
  const dir = path.resolve(values.dir);
  new Scope(await loadProject(dir)).host(values.host);
  const { snapshot, file: stored } = await new SnapshotStore(dir).add(values.host, await readFile(path.resolve(file), 'utf8'));
  const rootNote = snapshot.is_root ? '' : ' (not run as root: sshd/nginx sections may be unreadable)';
  console.log(`Stored ${stored}: ${snapshot.os.pretty_name || snapshot.os.id}, ${snapshot.packages.length} packages, collected ${snapshot.collected_at}${rootNote}`);
  return 0;
}

async function runVerify(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: {
      dir: { type: 'string', default: '.' },
      host: { type: 'string' },
      cve: { type: 'string' },
      package: { type: 'string' },
      json: { type: 'boolean', default: false },
    },
  });
  if (!values.host || !values.cve) throw new UsageError('Usage: secagent verify --host <name> --cve <CVE-id> [--package <name>] [--dir <path>] [--json]');
  const dir = path.resolve(values.dir);
  const project = await loadProject(dir);
  const host = new Scope(project).host(values.host);
  const result = await verifyClaim(
    {
      host,
      snapshots: new SnapshotStore(dir),
      advisories: deps.advisories ?? createAdvisories(),
      evidence: new EvidenceStore(dir, project.network.scan_label),
    },
    { cve: values.cve, ...(values.package ? { package: values.package } : {}) },
  );
  if (values.json) console.log(JSON.stringify(result, null, 2));
  else for (const line of formatClaim(result)) console.log(line);
  return 0;
}

async function runLearn(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: { dir: { type: 'string', default: '.' } } });
  const dir = path.resolve(values.dir);
  const project = await loadProject(dir);
  const advisories = deps.advisories ?? createAdvisories();
  const store = new SnapshotStore(dir);
  console.log(`CISA KEV: ${(await advisories.kev.catalog()).size} known-exploited CVEs cached`);
  for (const host of project.hosts) {
    const stored = await store.latest(host.name);
    if (!stored) {
      console.log(`${host.name}: no snapshot, skipped`);
      continue;
    }
    const distro = distroOf(stored.snapshot.os);
    if (!distro) {
      console.log(`${host.name}: ${stored.snapshot.os.id || 'unknown OS'} is not supported, skipped`);
      continue;
    }
    const sources = distroSources(stored.snapshot, distro.codename);
    const affected = await advisories.osv.affected(distro.ecosystem, sources);
    for (const q of sources.filter((s) => affected.has(s.name))) await advisories.osv.vulnsFor(distro.ecosystem, q);
    console.log(`${host.name}: ${sources.length} packages checked against ${distro.ecosystem}; ${affected.size} with advisories cached`);
  }
  console.log(`Advisory cache: ${defaultCacheDir()}`);
  return 0;
}
```

Change `main` to `export async function main(argv: readonly string[], deps: CliDeps = {}): Promise<number>` and add these cases to its switch:
```ts
      case 'collector':
        return await runCollector(rest);
      case 'snapshot':
        return await runSnapshot(rest);
      case 'verify':
        return await runVerify(rest, deps);
      case 'learn':
        return await runLearn(rest, deps);
```
Extend the handled-error condition to `e instanceof UsageError || e instanceof ProjectConfigError || e instanceof CatalogError || e instanceof ScopeError || e instanceof ObservationError`.

Append to `.gitignore`:
```
lab/.snapshot-*.json
```

- [ ] **Step 4: Run the full suite, typecheck and build**

Run: `npx vitest run && npx tsc -p tsconfig.json && npm run build`
Expected: all PASS; `tsc` exits 0; the build succeeds.

- [ ] **Step 5: Smoke test**

Run:
```bash
D=$(mktemp -d) && npm run --silent dev -- init --dir "$D" --host web-1=203.0.113.10,prod >/dev/null && npm run --silent dev -- collector --dir "$D" --host web-1 --out "$D/collect.sh" && sh -n "$D/collect.sh" && npm run --silent dev -- snapshot add --dir "$D" --host web-1 test/fixtures/collector/ubuntu-24-04.json
```
Expected: the instructions (with sha256) on stderr, then `Stored …/hosts/web-1/20261028T143146Z.json: Ubuntu 24.04… LTS, … packages, collected 2026-10-28T14:31:46Z`.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts .gitignore test/cli.test.ts
git commit -m "feat(cli): add collector, snapshot add, verify and learn commands"
```

---

### Task 11: Lab host snapshots and the end-to-end test

**Files:**
- Create: `lab/collect-snapshots.sh`, `test/lab-host.e2e.test.ts`
- Modify: `lab/README.md`

**Interfaces:**
- Consumes: the CLI `snapshot add`, `assets/collector.sh`, `scanNoAi`, and the lab from Plan 1
- Produces: an opt-in host-check e2e test (`SECAGENT_LAB=1`, with the lab running and snapshots collected)

- [ ] **Step 1: Write `lab/collect-snapshots.sh`**

```sh
#!/bin/sh
# Runs the secagent collector inside both lab containers and stores the snapshots in lab/project.
# Needs the lab running (docker compose -f lab/docker-compose.yml up -d) and network access from the containers (apt-get update).
set -eu
cd "$(dirname "$0")/.."
for pair in bad-site:bad-host good-site:good-host; do
  service=${pair%%:*}
  host=${pair#*:}
  docker compose -f lab/docker-compose.yml exec -T "$service" sh -c 'apt-get update -qq >/dev/null 2>&1 || true'
  docker compose -f lab/docker-compose.yml exec -T "$service" sh -s < assets/collector.sh > "lab/.snapshot-$host.json"
  npm run --silent dev -- snapshot add --dir lab/project --host "$host" "lab/.snapshot-$host.json"
  rm -f "lab/.snapshot-$host.json"
done
```

- [ ] **Step 2: Write `test/lab-host.e2e.test.ts`**

```ts
import { cp, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanNoAi } from '../src/scan/no-ai.js';
import { tempDir } from './helpers/tmp.js';

const LAB = path.join(import.meta.dirname, '..', 'lab', 'project', '.secagent');
const ready = process.env.SECAGENT_LAB === '1' && existsSync(path.join(LAB, 'hosts', 'bad-host'));

// The lab images are nginx:1.30.6 (Debian 13): nginx from nginx.org, no sshd, no ss, no unattended-upgrades.
const EXPECTED: Array<[check: string, host: string, outcome: string]> = [
  ['host-ssh-password-auth', 'bad-host', 'pass'],
  ['host-ssh-root-login', 'bad-host', 'pass'],
  ['host-nginx-server-tokens', 'bad-host', 'fail'],
  ['host-nginx-server-tokens', 'good-host', 'pass'],
  ['host-nginx-ssl-protocols', 'bad-host', 'fail'],
  ['host-nginx-ssl-protocols', 'good-host', 'pass'],
  ['host-listening-databases', 'bad-host', 'unverifiable'],
  ['host-auto-upgrades', 'bad-host', 'fail'],
  ['host-package-third-party', 'bad-host', 'fail'],
  ['host-package-third-party', 'good-host', 'fail'],
  ['host-reboot-pending', 'good-host', 'pass'],
];

describe.runIf(ready)('lab host checks (run lab/collect-snapshots.sh first)', () => {
  it('evaluates the collected lab snapshots', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'), { recursive: true });
    await cp(path.join(LAB, 'project.yaml'), path.join(dir, '.secagent', 'project.yaml'));
    await cp(path.join(LAB, 'hosts'), path.join(dir, '.secagent', 'hosts'), { recursive: true });
    const record = await scanNoAi(dir);
    const actual = EXPECTED.map(([check, host]) => {
      const r = record.results.find((x) => x.check_id === check && x.target === host);
      return `${check}@${host}=${r?.outcome ?? 'missing'}`;
    });
    expect(actual).toEqual(EXPECTED.map(([check, host, outcome]) => `${check}@${host}=${outcome}`));
    const third = record.results.find((x) => x.check_id === 'host-package-third-party' && x.target === 'bad-host');
    expect(third?.observed).toContain('nginx 1.30.6-1~trixie (installed locally, not from any configured repository)');
    const advisories = record.results.filter((x) => x.check_id === 'host-package-advisories');
    expect(advisories.map((a) => a.outcome)).not.toContain('error');
  }, 180_000);
});
```

- [ ] **Step 3: Document it in `lab/README.md`**

Append:
````markdown
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
````

- [ ] **Step 4: Run it**

Run:
```bash
docker compose -f lab/docker-compose.yml up -d && sleep 3
sh lab/collect-snapshots.sh
SECAGENT_LAB=1 npx vitest run test/lab-host.e2e.test.ts test/lab.e2e.test.ts
npm run --silent dev -- verify --dir lab/project --host bad-host --cve CVE-2024-6387
docker compose -f lab/docker-compose.yml down
```
Expected:
- `collect-snapshots.sh` prints `Stored …` twice.
- Both e2e files PASS.
- `verify` prints a verdict for Debian 13, for example `fixed_in_installed` or `not_affected`. Record the actual output in the report.
- The containers are removed.

If a row differs from `EXPECTED`, compare it with the evidence file named in the scan's `latest.json`, and report it rather than editing check logic.

- [ ] **Step 5: Run the full default suite and commit**

Run: `npx vitest run && npx tsc -p tsconfig.json`. Every test passes, with the lab and live tests skipped.
```bash
git add lab/collect-snapshots.sh lab/README.md test/lab-host.e2e.test.ts
git commit -m "test(lab): collect host snapshots in the lab and check them end to end"
```

---

### Task 12: Spec amendments

**Files:**
- Modify: `docs/superpowers/specs/2026-10-28-secagent-design.md`

- [ ] **Step 1: Apply these edits**

1. §7, after the field table: replace the sentence that starts `**Redaction** happens on the host before output:` and its list with:
   > **Output format:** one JSON object: `{"schema":1,"collector":"secagent-collector/1","collected_at":…,"sections":{"<name>":{"rc":<exit code>,"b64":"<base64 of redacted output>"}}}`. Base64 keeps arbitrary command output JSON-safe in POSIX sh. Exit code 127 means the tool isn't installed. Any other nonzero exit means it couldn't be read, usually because the collector wasn't run as root.
   >
   > **Redaction** happens on the host before encoding, and targets values, not config keys:
   > - nginx `$variables` whose names contain secret, token, passw, api-key or private;
   > - credential-bearing header directives (`proxy_set_header` and friends, for Authorization, Cookie, token, secret and api-key headers);
   > - Bearer tokens;
   > - `user:pass@` in URLs.
   >
   > This was verified against planted secrets on Ubuntu 22.04/24.04 and Debian 12. Multi-line nginx `map` blocks are not redacted, a documented limitation.
2. §7, `analyze_host` paragraph: append:
   > Snapshots are added with `secagent snapshot add --host <name> <file>`, which validates the output. Package origin comes from the apt suite and component, not the mirror host: a source whose suite is the host codename (or `codename-*`) with a distro component is distro, and anything else (PPAs, nginx.org, docker) is third-party. When apt lists are empty, origins are unknowable and the third-party check is `unverifiable`.
3. §8.7 cache TTL table: append:
   > The cache lives in `$SECAGENT_CACHE_DIR`, or `~/.cache/secagent/advisories` when that isn't set, never inside the installed package. NVD is deferred: severity comes from Ubuntu's priority, falls back to medium, and CISA KEV forces critical.
4. §11 CLI table: add rows:
   - `secagent collector [--host h] [--out f]`: print the read-only collector and how to run it.
   - `secagent snapshot add --host h <file>`: validate and store collector output.
   - `secagent verify --host h --cve <id> [--package p] [--json]`: `verify_claim` from the CLI.

   Change the `learn` row to: `Refresh CISA KEV and OSV advisories for every stored host snapshot (deterministic; the research channel needs an agent)`.
5. §6.2 `host_config` row: append:
   > Rules: `sshd_value`, `nginx_directive` (with `absent_default`/`when_absent`), `listening`, `auto_upgrades`.

   §6.2 `host_package` row: append:
   > Asserts: `advisories` (OSV querybatch by source package; fail only on fixes not installed, and count unfixed advisories as informational), `third_party`, `reboot`.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-10-28-secagent-design.md
git commit -m "docs: amend spec for collector format, origins, cache and new CLI commands"
```

---

## Done when

- `npx vitest run` passes, with the lab and live tests skipped by default. `npx tsc -p tsconfig.json` is clean, and `npm run build` succeeds.
- With the lab running and `lab/collect-snapshots.sh` run, both lab e2e files pass with `SECAGENT_LAB=1`.
- `secagent collector`, `snapshot add`, `verify --cve` and `learn` work on any Debian- or Ubuntu-hosted project.
- Host checks are `unverifiable`, never `pass`, when a snapshot is missing or stale, a tool is missing, or advisories are unavailable.
- No secrets in snapshots, evidence or fixtures. Advisory traffic goes only to `api.osv.dev`, `ubuntu.com` and `www.cisa.gov` over verified HTTPS.

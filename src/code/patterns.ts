import { createHash } from 'node:crypto';

export const PATTERN_IDS = [
  'aws-access-key-id',
  'private-key-block',
  'github-token',
  'slack-token',
  'stripe-live-key',
  'google-api-key',
  'jwt',
  'url-credentials',
  'generic-secret-assignment',
] as const;
export type PatternId = (typeof PATTERN_IDS)[number];

interface Pattern {
  id: PatternId;
  regex: RegExp;
  /** High-confidence patterns have a fixed, recognisable shape; the generic one is a heuristic. */
  highConfidence: boolean;
}

// The generic expression also accepts a closing quote after the name, so JSON ("password": "...") is covered.
// Every expression is linear in the line length: no nested unbounded quantifiers, and the generic one bounds its name suffix.
const PATTERNS: readonly Pattern[] = [
  { id: 'aws-access-key-id', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, highConfidence: true },
  { id: 'private-key-block', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, highConfidence: true },
  { id: 'github-token', regex: /gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}/g, highConfidence: true },
  { id: 'slack-token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g, highConfidence: true },
  { id: 'stripe-live-key', regex: /(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, highConfidence: true },
  { id: 'google-api-key', regex: /AIza[0-9A-Za-z_-]{35}/g, highConfidence: true },
  { id: 'jwt', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, highConfidence: true },
  { id: 'url-credentials', regex: /:\/\/([^/\s:@'"]+):([^/\s@'"]{3,})@/g, highConfidence: true },
  {
    id: 'generic-secret-assignment',
    regex: /(?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_]{0,40}['"]?\s*[:=]\s*['"]([^'"\s]{12,})['"]/gi,
    highConfidence: false,
  },
];

/** Patterns that are safe to run over diffs and docs alike. */
export const HIGH_CONFIDENCE_PATTERN_IDS: readonly PatternId[] = PATTERNS.filter((p) => p.highConfidence).map((p) => p.id);

export const IGNORE_MARKER = 'secagent:ignore';

/** The generic pattern is a heuristic over very long lines (minified bundles) it cannot judge; high-confidence patterns still run. */
const GENERIC_MAX_LINE = 2000;
const MIN_ENTROPY = 3.5;

const PLACEHOLDER_WORDS = [
  'changeme',
  'change_me',
  'change-me',
  'example',
  'your_',
  'your-',
  'xxx',
  'dummy',
  'test',
  'sample',
  'placeholder',
  'process.env',
  'os.environ',
  'getenv',
  'config.',
];
const PLACEHOLDER_LITERALS = new Set(['null', 'none', 'nil', 'undefined', 'true', 'false']);

/** Values that stand for a secret rather than being one: template markers, env lookups, "changeme" and friends. */
export function isPlaceholderValue(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (PLACEHOLDER_LITERALS.has(v)) return true;
  if (/\$\{|\{\{|<[^<>]*>/.test(v)) return true;
  return PLACEHOLDER_WORDS.some((w) => v.includes(w));
}

const URL_PLACEHOLDER_PASSWORDS = new Set(['pass', 'password', 'passwd', 'pwd', 'secret', 'user', 'username']);

const TEMPLATE_MARKER = /^\$|\$\{|\{\{|<[^<>]*>/;

function isPlaceholderUrlCredential(user: string, password: string): boolean {
  if (TEMPLATE_MARKER.test(user) || TEMPLATE_MARKER.test(password)) return true;
  if (URL_PLACEHOLDER_PASSWORDS.has(password.toLowerCase()) || /^\*+$/.test(password)) return true;
  return isPlaceholderValue(password);
}

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = [...s].length;
  let h = 0;
  for (const c of counts.values()) h -= (c / n) * Math.log2(c / n);
  return h;
}

/** First 8 hex digits of the value's SHA-256: enough to tell two secrets apart, useless for recovering one. */
export function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 8);
}

export interface LineHit {
  pattern: PatternId;
  fingerprint: string;
}

export interface ScanOptions {
  /** Run the generic-secret-assignment heuristic (code, not docs or lockfiles; never over history). */
  generic: boolean;
}

/** Hits on one line. Reports only the pattern and a fingerprint: the matched value never leaves this function. */
export function scanLine(line: string, opts: ScanOptions): LineHit[] {
  if (line.includes(IGNORE_MARKER)) return [];
  const hits: LineHit[] = [];
  for (const p of PATTERNS) {
    if (p.id === 'generic-secret-assignment' && (!opts.generic || line.length > GENERIC_MAX_LINE)) continue;
    for (const m of line.matchAll(p.regex)) {
      const matched = m[0];
      let value = matched;
      if (p.id === 'aws-access-key-id' && matched.endsWith('EXAMPLE')) continue; // the AWS documentation's sample keys
      if (p.id === 'url-credentials') {
        if (isPlaceholderUrlCredential(m[1] ?? '', m[2] ?? '')) continue;
        value = `${m[1]}:${m[2]}`;
      }
      if (p.id === 'generic-secret-assignment') {
        value = m[1] ?? '';
        if (isPlaceholderValue(value) || shannonEntropy(value) < MIN_ENTROPY) continue;
      }
      hits.push({ pattern: p.id, fingerprint: fingerprint(value) });
    }
  }
  // A generic hit on a value that a high-confidence pattern already reported is the same finding.
  const confident = new Set(hits.filter((h) => h.pattern !== 'generic-secret-assignment').map((h) => h.fingerprint));
  return hits.filter((h) => h.pattern !== 'generic-secret-assignment' || !confident.has(h.fingerprint));
}

export interface TextHit extends LineHit {
  line: number;
}

/** Hits in a whole file, ordered by line then pattern, one per distinct (line, pattern, value). */
export function scanText(text: string, opts: ScanOptions): TextHit[] {
  const out = new Map<string, TextHit>();
  const lines = text.split('\n');
  lines.forEach((raw, i) => {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    for (const h of scanLine(line, opts)) out.set(`${i + 1}\0${h.pattern}\0${h.fingerprint}`, { line: i + 1, ...h });
  });
  return [...out.values()].sort((a, b) => a.line - b.line || a.pattern.localeCompare(b.pattern) || a.fingerprint.localeCompare(b.fingerprint));
}

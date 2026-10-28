import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import { maxSeverity, SEVERITIES, type Severity } from '../../types.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

const Regex = z.string().refine(
  (s) => {
    try {
      new RegExp(s);
      return true;
    } catch {
      return false;
    }
  },
  { message: 'invalid regular expression' },
);

export const exposedPathParams = z.object({
  paths: z
    .array(z.object({ path: z.string().startsWith('/'), signature: Regex, severity: z.enum(SEVERITIES) }))
    .min(1),
  source_maps: z
    .object({
      enabled: z.boolean().default(true),
      max_scripts: z.number().int().min(0).max(20).default(5),
      severity: z.enum(SEVERITIES).default('low'),
    })
    .prefault({}),
});
export type ExposedPathParams = z.infer<typeof exposedPathParams>;

const SOURCE_MAP_SIGNATURE = /"mappings"\s*:/;

/** Exposed = 200, different from the random-path baseline (SPA fallback), and matching the file's signature. */
export function isExposed(obs: HttpObservation, baseline: HttpObservation, signature: RegExp): boolean {
  if (obs.status !== 200) return false;
  if (baseline.status === 200 && obs.bodySnippet === baseline.bodySnippet) return false;
  return signature.test(obs.bodySnippet);
}

export function scriptSources(html: string, pageUrl: string): string[] {
  const found: string[] = [];
  for (const match of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi)) {
    const src = match[1];
    if (!src) continue;
    try {
      found.push(new URL(src, pageUrl).href);
    } catch {
      // Unparseable src attributes are skipped.
    }
  }
  return [...new Set(found)];
}

interface Hit {
  path: string;
  severity: Severity;
  status: number;
}

export const exposedPathCheck: CheckType<ExposedPathParams> = {
  type: 'exposed_path',
  supports: ['web', 'api'],
  params: exposedPathParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('exposed_path runs on targets only');
    const origin = new URL(subject.target.url).origin;
    const baselineUrl = `${origin}/secagent-baseline-${randomBytes(6).toString('hex')}`;
    const baseline = await ctx.net.http(baselineUrl);
    const checked: Array<{ path: string; status: number }> = [];
    const hits: Hit[] = [];

    for (const entry of p.paths) {
      const obs = await ctx.net.http(`${origin}${entry.path}`);
      checked.push({ path: entry.path, status: obs.status });
      if (isExposed(obs, baseline, new RegExp(entry.signature, 'm'))) hits.push({ path: entry.path, severity: entry.severity, status: obs.status });
    }

    if (p.source_maps.enabled && p.source_maps.max_scripts > 0) {
      const page = await getPage(ctx, subject);
      const scripts = scriptSources(page.obs.bodySnippet, page.obs.url)
        .filter((src) => new URL(src).origin === origin)
        .slice(0, p.source_maps.max_scripts);
      for (const src of scripts) {
        const mapUrl = new URL(src);
        mapUrl.search = '';
        mapUrl.pathname = `${mapUrl.pathname}.map`;
        const obs = await ctx.net.http(mapUrl.href);
        checked.push({ path: mapUrl.pathname, status: obs.status });
        if (isExposed(obs, baseline, SOURCE_MAP_SIGNATURE)) hits.push({ path: mapUrl.pathname, severity: p.source_maps.severity, status: obs.status });
      }
    }

    // Statuses and paths only: never persist the contents of an exposed file.
    const evidence_id = await ctx.evidence.put('http', subject.target.id, `exposed-path probe of ${checked.length} path(s)`, {
      baseline: { url: baselineUrl, status: baseline.status, bodyBytes: baseline.bodyBytes },
      checked,
      hits,
    });
    if (hits.length === 0) {
      return {
        outcome: 'pass',
        observed: `none of ${checked.length} sensitive path(s) served (SPA fallback ruled out against a random-path baseline)`,
        evidence_id,
      };
    }
    return {
      outcome: 'fail',
      severity: maxSeverity(hits.map((h) => h.severity)),
      observed: `served: ${hits.map((h) => h.path).join(', ')}`,
      evidence_id,
      details: { hits },
    };
  },
};

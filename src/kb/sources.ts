import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { isPrivateAddress, resolveAddresses } from '../net/ip.js';
import { GLOBAL_KNOWLEDGE_DIR, projectKnowledgeDir } from '../paths.js';
import { KbError } from './lesson.js';

const MAX_BYTES = 2_000_000;
const TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 3;

export async function loadSourceHosts(file = path.join(GLOBAL_KNOWLEDGE_DIR, 'sources.yaml')): Promise<Set<string>> {
  const parsed = z.object({ hosts: z.array(z.string().min(1)) }).parse(parse(await readFile(file, 'utf8')));
  return new Set(parsed.hosts.map((h) => h.toLowerCase()));
}

/** Why a URL may not be fetched or cited, or undefined when it may: https, no port or credentials, an allowlisted host name. */
export function sourceProblem(url: string, hosts: ReadonlySet<string>): string | undefined {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return `"${url}" is not a URL`;
  }
  if (u.protocol !== 'https:') return 'only https:// sources are allowed';
  if (u.username || u.password || u.port) return 'source URLs may not carry credentials or a port';
  if (!hosts.has(u.hostname.toLowerCase())) return `${u.hostname} is not on the source allowlist (knowledge/sources.yaml)`;
  return undefined;
}

/** Visible text of an HTML page: no scripts or styles, entities decoded, whitespace collapsed. */
export function htmlToText(html: string): string {
  return html
    .replace(/<(script|style|noscript|svg)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#(?:39|x27);/gi, "'")
    .replace(/&#(\d+);/g, (_m, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Text compared for quotes: whitespace collapsed, curly quotes and dashes made plain. */
export function normaliseQuote(text: string): string {
  return text.replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/\s+/g, ' ').trim();
}

export interface FetchedSource {
  id: string;
  url: string;
  final_url: string;
  fetched_at: string;
  text: string;
}

export function fetchedDir(projectDir: string): string {
  return path.join(projectKnowledgeDir(projectDir), 'fetched');
}

function cacheFile(projectDir: string, url: string): string {
  return path.join(fetchedDir(projectDir), `${createHash('sha256').update(url).digest('hex').slice(0, 16)}.json`);
}

export async function readFetched(projectDir: string, url: string): Promise<FetchedSource | undefined> {
  try {
    return JSON.parse(await readFile(cacheFile(projectDir, url), 'utf8')) as FetchedSource;
  } catch {
    return undefined;
  }
}

export interface FetchDeps {
  now: () => Date;
  fetchImpl?: typeof fetch;
  resolve?: (host: string) => Promise<string[]>;
  hosts?: ReadonlySet<string>;
}

async function readCapped(res: Response): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BYTES) {
      await reader.cancel();
      throw new KbError(`the page is larger than ${MAX_BYTES} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Fetches an allowlisted page for the learning loop and caches its text under .secagent/knowledge/fetched/. Every hop (redirects
 * included) must be https on an allowlisted host that does not resolve to a private address.
 */
export async function fetchSource(projectDir: string, url: string, deps: FetchDeps): Promise<FetchedSource> {
  const hosts = deps.hosts ?? (await loadSourceHosts());
  const doFetch = deps.fetchImpl ?? fetch;
  const resolve = deps.resolve ?? ((h: string) => resolveAddresses(h, 4));
  let current = url;
  for (let hop = 0; ; hop += 1) {
    const problem = sourceProblem(current, hosts);
    if (problem) throw new KbError(hop === 0 ? problem : `redirected to ${current}: ${problem}`);
    const host = new URL(current).hostname;
    const addresses = isIP(host) ? [host] : await resolve(host);
    if (addresses.length === 0 || addresses.some(isPrivateAddress)) throw new KbError(`${host} resolves to a private address`);
    const res = await doFetch(current, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS), headers: { 'user-agent': 'secagent-learn', accept: 'text/html,text/plain' } });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location || hop >= MAX_REDIRECTS) throw new KbError(`too many or broken redirects from ${url}`);
      current = new URL(location, current).href;
      continue;
    }
    if (res.status !== 200) throw new KbError(`${current} answered ${res.status}`);
    const type = res.headers.get('content-type') ?? '';
    if (!/text\/(html|plain)/i.test(type)) throw new KbError(`${current} is not a text page (${type || 'no content type'})`);
    const body = await readCapped(res);
    const text = /html/i.test(type) ? htmlToText(body) : body.replace(/\s+/g, ' ').trim();
    const doc: FetchedSource = { id: path.basename(cacheFile(projectDir, url), '.json'), url, final_url: current, fetched_at: deps.now().toISOString(), text };
    await mkdir(fetchedDir(projectDir), { recursive: true });
    await writeFile(cacheFile(projectDir, url), `${JSON.stringify(doc)}\n`, 'utf8');
    return doc;
  }
}

import { readFile } from 'node:fs/promises';
import path from 'node:path';

/** .env keys whose value is usually the site's public address. Only these keys are read; no other value is looked at. */
const URL_KEYS = ['PUBLIC_URL', 'SITE_URL', 'APP_URL', 'BASE_URL', 'NEXT_PUBLIC_SITE_URL', 'NEXT_PUBLIC_APP_URL', 'VITE_APP_URL', 'REACT_APP_URL', 'DEPLOY_URL'];
const ENV_FILES = ['.env.production', '.env.example', '.env.sample', '.env'];

async function text(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return '';
  }
}

/** A plain public http(s) address, or undefined: no credentials, no localhost, no placeholder. */
function clean(raw: string): string | undefined {
  const value = raw.trim().replace(/^['"]|['"]$/g, '');
  let u: URL;
  try {
    u = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return undefined;
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password) return undefined;
  const host = u.hostname.toLowerCase();
  if (!host.includes('.') || host === 'localhost' || host.endsWith('.local') || /example\.(com|org|net)$/.test(host) || /^[\d.]+$/.test(host)) return undefined;
  return `${u.protocol}//${u.host}`;
}

/**
 * Addresses the project itself mentions as its deployed site: package.json "homepage", a GitHub Pages CNAME file, and the public
 * URL keys of .env files. The person confirms or replaces them; nothing is probed from here.
 */
export async function suggestUrls(dir: string): Promise<string[]> {
  const found: string[] = [];
  try {
    const home = (JSON.parse(await text(path.join(dir, 'package.json'))) as { homepage?: unknown }).homepage;
    if (typeof home === 'string') found.push(home);
  } catch {
    // no package.json, or not JSON
  }
  for (const rel of ['CNAME', 'public/CNAME', 'docs/CNAME', 'static/CNAME']) found.push((await text(path.join(dir, rel))).split('\n')[0] ?? '');
  for (const file of ENV_FILES) {
    for (const line of (await text(path.join(dir, file))).split('\n')) {
      const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (m?.[1] && URL_KEYS.includes(m[1])) found.push(m[2] ?? '');
    }
  }
  return [...new Set(found.map(clean).filter((u): u is string => u !== undefined))].slice(0, 5);
}

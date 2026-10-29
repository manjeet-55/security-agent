import { createHash } from 'node:crypto';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ProjectConfig } from './schema.js';

/**
 * Which projects' websites and servers a person on this machine has confirmed may be probed. It lives in the user's config
 * directory, never in the project, so a cloned repository cannot confirm its own project.yaml.
 */
export function consentFile(): string {
  const base = process.env.SECAGENT_CONFIG_DIR ?? path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'secagent');
  return path.join(base, 'consent.json');
}

/** A fingerprint of everything that decides what can be probed: target URLs, host addresses and their allow_private flags. */
export function scopeHash(p: ProjectConfig): string {
  const scope = {
    targets: p.targets.map((t) => `${t.url} ${t.allow_private}`).sort(),
    hosts: p.hosts.map((h) => `${h.address} ${h.allow_private}`).sort(),
  };
  return createHash('sha256').update(JSON.stringify(scope)).digest('hex');
}

type Store = Record<string, { scope_hash: string; confirmed_at: string }>;

async function readStore(): Promise<Store> {
  try {
    return JSON.parse(await readFile(consentFile(), 'utf8')) as Store;
  } catch {
    return {};
  }
}

export async function recordConsent(projectDir: string, config: ProjectConfig, now: Date): Promise<void> {
  const store = await readStore();
  store[await realpath(projectDir)] = { scope_hash: scopeHash(config), confirmed_at: now.toISOString() };
  await mkdir(path.dirname(consentFile()), { recursive: true });
  await writeFile(consentFile(), `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

/** True when nothing can be probed, or a person confirmed exactly this scope for this folder. */
export async function hasConsent(projectDir: string, config: ProjectConfig): Promise<boolean> {
  if (config.targets.length === 0 && config.hosts.length === 0) return true;
  const entry = (await readStore())[await realpath(projectDir)];
  return entry?.scope_hash === scopeHash(config);
}

export const NOT_CONFIRMED =
  'The websites and servers in this project.yaml have not been confirmed on this machine, so the AI assistant may not probe them. Ask the person to run `secagent` (or `secagent scan --no-ai`) in this folder once to confirm them; the code checks (groups ["code"]) work without it.';

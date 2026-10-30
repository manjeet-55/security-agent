import { isIP } from 'node:net';
import path from 'node:path';
import { parseSnapshotText } from '../host/store.js';
import { isPrivateAddress, resolveAddresses, stripBrackets } from '../net/ip.js';
import { validateProject, type Host, type ProjectConfig, type Target } from '../project/schema.js';
import type { StackDetection } from '../project/stack.js';
import type { ScanGroup } from '../scan/no-ai.js';
import type { Choice, Prompter } from '../ui/prompt.js';
import { suggestUrls } from './suggest.js';

export interface WizardPlan {
  /** Validated settings; written by runWizard, not here. */
  config: ProjectConfig;
  /** What to scan this run. */
  groups: ScanGroup[];
  /** Set when the person confirmed they may test the websites and servers in scope. */
  consentAt?: Date;
  /** Collector output that passed validation, to be stored when the plan is saved. */
  snapshots: Array<{ host: string; text: string }>;
}

export interface AskDeps {
  dir: string;
  existing?: ProjectConfig;
  /** For a project that is already set up: scan again with its settings, change them, or start over. Without it, I ask. */
  start?: 'again' | 'change' | 'fresh';
  detection: StackDetection;
  now: () => Date;
  /** DNS lookup for the internal-address question; injectable for tests. */
  resolve?: (hostname: string) => Promise<string[]>;
  readFile?: (file: string) => Promise<string>;
  /** Writes the read-only collector for a host and returns where; without it the wizard does not offer to. */
  writeCollector?: (host: string) => Promise<string>;
  /** Addresses the project mentions as its deployed site (default: read from package.json, CNAME and .env files). */
  suggest?: (dir: string) => Promise<string[]>;
}

const DEFAULT_GROUPS: ScanGroup[] = ['code'];
const CONSENT = 'I own these systems or have written permission to test them';
const URL_HELP = 'Enter a full address starting with https:// or http://';
const ENVIRONMENTS: Array<Choice<string>> = [
  { value: 'prod', label: 'Production (prod)' },
  { value: 'staging', label: 'Staging' },
  { value: 'dev', label: 'Development (dev)' },
  { value: 'other', label: 'Something else' },
];
const NETWORKS: Array<Choice<string>> = [
  { value: 'office', label: 'The office network' },
  { value: 'home', label: 'Home' },
  { value: 'vpn', label: 'A VPN' },
  { value: 'ci', label: 'Cloud or CI' },
  { value: 'other', label: 'Something else' },
];

/** portal.example.com → portal-example-com; -2, -3 ... when the id is taken. */
export function targetIdFor(url: string, taken: ReadonlySet<string>): string {
  const host = stripBrackets(new URL(url).hostname).toLowerCase();
  const base = host.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'site';
  if (!taken.has(base)) return base;
  for (let n = 2; ; n += 1) if (!taken.has(`${base}-${n}`)) return `${base}-${n}`;
}

function validateUrl(value: string, known: readonly Target[]): string | undefined {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return URL_HELP;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return URL_HELP;
  if (u.username || u.password) return 'Leave out user names and passwords';
  if (known.some((t) => t.url === value)) return 'That address is already in the list';
  return undefined;
}

async function askEnvironment(p: Prompter, current?: string): Promise<string> {
  const known = ENVIRONMENTS.some((e) => e.value === current);
  const choice = await p.select({ message: 'Which environment is it?', choices: ENVIRONMENTS, default: known ? current : 'prod' });
  if (choice !== 'other') return choice;
  return p.text({ message: 'Environment name', ...(current && !known ? { default: current } : {}), validate: (v) => (v.trim() === '' ? 'Enter a name' : undefined) });
}

async function askNetwork(p: Prompter, current?: string): Promise<string> {
  const choices = current && !NETWORKS.some((n) => n.value === current) ? [{ value: current, label: current }, ...NETWORKS] : NETWORKS;
  const choice = await p.select({ message: 'Where are you scanning from?', choices, default: current ?? 'office' });
  if (choice !== 'other') return choice;
  return p.text({ message: 'Name this network', validate: (v) => (v.trim() === '' ? 'Enter a name' : undefined) });
}

/** The internal addresses a URL points at; empty for a public one, and for a name that cannot be looked up (noted). */
async function internalAddresses(p: Prompter, url: string, resolve: (hostname: string) => Promise<string[]>): Promise<string[]> {
  const host = stripBrackets(new URL(url).hostname);
  if (isIP(host)) return isPrivateAddress(host) ? [host] : [];
  try {
    return (await resolve(host)).filter(isPrivateAddress);
  } catch (e) {
    p.note(`Could not look up ${host} (${(e as Error).message}). I will keep it, and the scan will say if it cannot be reached.`);
    return [];
  }
}

interface Draft {
  name: string;
  groups: ScanGroup[];
  targets: Target[];
  hosts: Host[];
  scanLabel: string;
  snapshots: Array<{ host: string; text: string }>;
}

async function askWebsites(p: Prompter, deps: AskDeps, seed: readonly Target[]): Promise<Target[]> {
  const resolve = deps.resolve ?? ((h: string) => resolveAddresses(h, 4));
  let targets: Target[] = [];
  if (seed.length > 0 && (await p.confirm({ message: `Keep these websites and APIs? ${seed.map((t) => t.url).join(', ')}`, default: true }))) targets = [...seed];
  let more = targets.length === 0;
  for (;;) {
    if (!more) more = await p.confirm({ message: 'Add another website or API?', default: false });
    if (!more) return targets;
    more = false;
    const known = new Set(targets.map((t) => t.url));
    const ideas = targets.length === 0 ? (await (deps.suggest ?? suggestUrls)(deps.dir)).filter((u) => !known.has(u)) : [];
    const picked =
      ideas.length > 0
        ? await p.select({ message: 'I found these addresses in the project. Which one is deployed?', choices: [...ideas.map((u) => ({ value: u, label: u })), { value: '', label: 'None of these: type the address' }], default: ideas[0] as string })
        : '';
    const url =
      picked !== ''
        ? picked
        : (await p.text({ message: 'Address of the deployed website or API (https://...)', validate: (v) => validateUrl(v.trim(), targets) })).trim();
    const internal = await internalAddresses(p, url, resolve);
    const host = stripBrackets(new URL(url).hostname);
    if (internal.length > 0) {
      const where = isIP(host) ? '' : ` (${internal.join(', ')})`;
      if (!(await p.confirm({ message: `${host} is an internal address${where}. Scan it anyway?`, default: false }))) continue;
    }
    const type = await p.select({ message: 'Is it a website or an API?', choices: [{ value: 'web' as const, label: 'A website' }, { value: 'api' as const, label: 'An API' }], default: 'web' as const });
    const env = await askEnvironment(p);
    targets.push({ id: targetIdFor(url, new Set(targets.map((t) => t.id))), url, type, env, allow_private: internal.length > 0 });
  }
}

/** How to run the collector on a server and what to bring back. */
export function collectorSteps(file: string, host: string): string {
  return `Copy ${file} to ${host}, read it, then run it there:\n  sudo sh ${path.basename(file)} > ${host}.json\nand bring ${host}.json back.`;
}

/** Reads and validates collector output; undefined means the person skipped it. */
export async function askSnapshot(p: Prompter, deps: Pick<AskDeps, 'dir' | 'now' | 'readFile'>, host: string): Promise<string | undefined> {
  const read = deps.readFile;
  if (!read) return undefined;
  for (;;) {
    const entered = (await p.text({ message: `Path to ${host}.json, the collector's output (Enter to skip)`, default: '' })).trim();
    if (entered === '') return undefined;
    try {
      const text = await read(path.resolve(deps.dir, entered));
      parseSnapshotText(text, deps.now());
      return text;
    } catch (e) {
      p.note(`That file cannot be used: ${(e as Error).message}`);
      if (!(await p.confirm({ message: 'Try another file?', default: true }))) return undefined;
    }
  }
}

async function askServers(p: Prompter, deps: AskDeps, seed: readonly Host[], pending: Draft['snapshots']): Promise<{ hosts: Host[]; snapshots: Draft['snapshots'] }> {
  let hosts: Host[] = [];
  if (seed.length > 0 && (await p.confirm({ message: `Keep these servers? ${seed.map((h) => `${h.name} (${h.address})`).join(', ')}`, default: true }))) hosts = [...seed];
  const snapshots = pending.filter((s) => hosts.some((h) => h.name === s.host));
  let more = hosts.length === 0;
  for (;;) {
    if (!more) more = await p.confirm({ message: 'Add another server?', default: false });
    if (!more) return { hosts, snapshots };
    more = false;
    const name = (
      await p.text({
        message: 'Name for the server (letters, digits and dashes, e.g. web-1)',
        validate: (v) => (/^[a-z0-9][a-z0-9-]*$/.test(v.trim()) ? (hosts.some((h) => h.name === v.trim()) ? `${v.trim()} is already in the list` : undefined) : 'Use lowercase letters, digits and dashes, e.g. web-1'),
      })
    ).trim();
    const address = (await p.text({ message: `Address of ${name} (IP or hostname)`, validate: (v) => (/^\S+$/.test(v.trim()) ? undefined : 'Enter an address without spaces') })).trim();
    const env = await askEnvironment(p);
    hosts.push({ name, address, env, reachable_from: [], serves: [], allow_private: false, distro_mirrors: [] });
    if (deps.writeCollector && (await p.confirm({ message: `Write the read-only collector for ${name} so you can run it on the server?`, default: true }))) {
      const file = await deps.writeCollector(name);
      p.note(collectorSteps(file, name));
    }
    const text = await askSnapshot(p, deps, name);
    if (text) snapshots.push({ host: name, text });
    else p.note(`${name} will be reported as not checked until you add its collector output (secagent snapshot add --host ${name} <file>).`);
  }
}

function consentNeeded(groups: readonly ScanGroup[], targets: readonly Target[], hosts: readonly Host[]): boolean {
  return (groups.includes('web') && targets.length > 0) || (groups.includes('host') && hosts.length > 0);
}

function reviewNote(deps: AskDeps, groups: readonly ScanGroup[], targets: readonly Target[], hosts: readonly Host[]): string {
  const lines = ['Here is what I will do:'];
  if (groups.includes('web') && targets.length > 0) lines.push(`  • Send read-only requests (page fetches, TLS handshakes) to: ${targets.map((t) => t.url).join(', ')}`);
  if (groups.includes('host') && hosts.length > 0) lines.push(`  • Try TCP connections to a fixed list of admin and database ports on: ${hosts.map((h) => h.address).join(', ')}`);
  if (groups.includes('host') && hosts.length > 0) {
    lines.push('  • Look up the packages installed on those servers in public advisory databases (OSV, Ubuntu Security, CISA); only package names and versions are sent.');
  }
  if (groups.includes('code')) {
    lines.push(`  • Read the files and git history in ${deps.dir}`);
    lines.push('  • Look up the npm packages in package-lock.json, if there is one, in the OSV advisory database; only package names and versions are sent.');
  }
  lines.push('  Nothing is changed. Your files and secrets are never sent anywhere.');
  return lines.join('\n');
}

/**
 * Asks what to scan and builds the plan. Writes nothing (apart from a collector script the person asked for). Returns undefined
 * when the person backs out.
 */
export async function askPlan(p: Prompter, deps: AskDeps): Promise<WizardPlan | undefined> {
  const { existing } = deps;
  let seed = existing;
  let draftGroups: ScanGroup[] | undefined;
  let snapshots: Draft['snapshots'] = [];

  if (existing) {
    const action = deps.start ?? await p.select({
      message: 'This project is already set up. What now?',
      choices: [
        { value: 'again' as const, label: 'Scan again with these settings' },
        { value: 'change' as const, label: 'Change the settings' },
        { value: 'fresh' as const, label: 'Start over' },
      ],
      default: 'again' as const,
    });
    if (action === 'again') {
      const groups = initialGroups(existing);
      const consentAt = await askConsent(p, deps, groups, existing.targets, existing.hosts);
      if (consentAt === 'quit') return undefined;
      if (consentAt === 'declined') return codeOnly(p, existing, existing);
      if (consentAt !== 'back') return { config: existing, groups, ...(consentAt ? { consentAt } : {}), snapshots: [] };
      // "go back" after declining: carry on into the questions, starting from the saved settings
    }
    if (action === 'fresh') seed = undefined;
  }

  for (;;) {
    const name = (await p.text({ message: 'Project name', default: seed?.name ?? path.basename(deps.dir), validate: (v) => (v.trim() === '' ? 'Enter a name' : undefined) })).trim();
    const picked = await p.multiselect({
      message: 'What should I check?',
      choices: [
        { value: 'code' as const, label: "This project's code", hint: 'secrets, .env files, git history, npm dependencies' },
        { value: 'web' as const, label: 'Deployed websites or APIs', hint: 'headers, TLS, exposed files' },
        { value: 'host' as const, label: 'Servers', hint: 'SSH, nginx, packages (needs the collector)' },
      ],
      initial: draftGroups ?? (seed ? initialGroups(seed, true) : DEFAULT_GROUPS),
      min: 1,
    });
    const targets = picked.includes('web') ? await askWebsites(p, deps, seed?.targets ?? []) : [];
    let scanLabel = seed?.network.scan_label ?? 'local';
    let labelled = false;
    if (targets.length > 0) {
      scanLabel = await askNetwork(p, seed?.network.scan_label);
      labelled = true;
    }
    let hosts: Host[] = [];
    if (picked.includes('host')) {
      const asked = await askServers(p, deps, seed?.hosts ?? [], snapshots);
      hosts = asked.hosts;
      snapshots = asked.snapshots;
    }
    if (!labelled && hosts.length > 0) scanLabel = await askNetwork(p, seed?.network.scan_label);

    const groups: ScanGroup[] = [...(picked.includes('code') ? (['code'] as const) : []), ...(targets.length > 0 ? (['web'] as const) : []), ...(hosts.length > 0 ? (['host'] as const) : [])];
    if (groups.length === 0) {
      p.note('Nothing is left to scan.');
      return undefined;
    }
    const config = validateProject({
      version: 1,
      name,
      stack: { ...deps.detection.stack, ...seed?.stack },
      network: { ip_family: seed?.network.ip_family ?? 4, scan_label: scanLabel },
      code: { ...seed?.code, enabled: picked.includes('code') },
      targets,
      hosts,
    });

    const consentAt = await askConsent(p, deps, groups, targets, hosts);
    if (consentAt === 'quit') return undefined;
    if (consentAt === 'declined') return codeOnly(p, existing, config);
    if (consentAt === 'back') {
      seed = config;
      draftGroups = picked;
      continue;
    }
    return { config, groups, ...(consentAt ? { consentAt } : {}), snapshots };
  }
}

/** The groups a project's saved settings imply: its code (if enabled), its websites and its servers. */
function initialGroups(config: ProjectConfig, includeCodeByDefault = false): ScanGroup[] {
  return [
    ...(config.code.enabled || includeCodeByDefault ? (['code'] as const) : []),
    ...(config.targets.length > 0 ? (['web'] as const) : []),
    ...(config.hosts.length > 0 ? (['host'] as const) : []),
  ];
}

type Consent = Date | undefined | 'declined' | 'back' | 'quit';

/** Shows what will happen and asks for consent; undefined when nothing needs it. 'declined' is handled by the caller. */
async function askConsent(p: Prompter, deps: AskDeps, groups: readonly ScanGroup[], targets: readonly Target[], hosts: readonly Host[]): Promise<Consent> {
  if (!consentNeeded(groups, targets, hosts)) return undefined;
  p.note(reviewNote(deps, groups, targets, hosts));
  if (await p.confirm({ message: CONSENT, default: false })) return deps.now();
  const next = await p.select({
    message: 'Without that confirmation I will not probe any website or server. What now?',
    choices: [
      { value: 'back' as const, label: 'Go back and change the answers' },
      { value: 'code' as const, label: 'Scan only the code' },
      { value: 'quit' as const, label: 'Quit' },
    ],
    default: 'back' as const,
  });
  return next === 'code' ? 'declined' : next;
}

/** A code-only scan: needs no consent, and saves none of the new websites or servers. */
function codeOnly(p: Prompter, existing: ProjectConfig | undefined, config: ProjectConfig): WizardPlan {
  p.note('Scanning only the code. The websites and servers you entered were not saved.');
  const base = existing ?? validateProject({ ...config, targets: [], hosts: [], code: { ...config.code, enabled: true } });
  return { config: base, groups: ['code'], snapshots: [] };
}

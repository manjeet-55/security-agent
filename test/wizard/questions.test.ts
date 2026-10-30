import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { validateProject, type ProjectConfig } from '../../src/project/schema.js';
import { askPlan, collectorSteps, targetIdFor, type AskDeps } from '../../src/wizard/questions.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { fixtureEnvelope } from '../helpers/snapshots.js';

const NOW = new Date('2027-01-01T00:00:00.000Z');
const PUBLIC = async () => ['93.184.216.34'];

function deps(overrides: Partial<AskDeps> = {}): AskDeps {
  return {
    dir: '/work/shop',
    detection: { stack: { frontend: 'angular' }, markers: [] },
    now: () => NOW,
    resolve: PUBLIC,
    readFile: async (file) => {
      throw new Error(`ENOENT: ${file}`);
    },
    writeCollector: async (host) => `/work/shop/.secagent/hosts/${host}/collector.sh`,
    ...overrides,
  };
}

function existing(): ProjectConfig {
  return validateProject({
    version: 1,
    name: 'shop',
    network: { scan_label: 'office' },
    targets: [{ id: 'portal-example-com', url: 'https://portal.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
  });
}

describe('targetIdFor', () => {
  it('turns the hostname into an id and avoids ids already taken', () => {
    expect(targetIdFor('https://Portal.Example.com/app', new Set())).toBe('portal-example-com');
    expect(targetIdFor('http://127.0.0.1:8080', new Set())).toBe('127-0-0-1');
    expect(targetIdFor('https://portal.example.com/b', new Set(['portal-example-com', 'portal-example-com-2']))).toBe('portal-example-com-3');
  });
});

describe('askPlan', () => {
  it('code only: two questions, no network label, no consent', async () => {
    const p = new ScriptedPrompter([undefined, ['code']]);
    const plan = await askPlan(p, deps());
    p.done();
    expect(p.asked).toEqual(['Project name', 'What should I check?']);
    expect(plan).toMatchObject({ groups: ['code'], snapshots: [] });
    expect(plan?.consentAt).toBeUndefined();
    expect(plan?.config).toMatchObject({ name: 'shop', network: { scan_label: 'local' }, stack: { frontend: 'angular' }, targets: [], hosts: [] });
  });

  it('a website: asks address, kind, environment and where you are, then needs consent', async () => {
    const p = new ScriptedPrompter([undefined, ['code', 'web'], 'https://portal.example.com', 'web', 'prod', false, 'office', true]);
    const plan = await askPlan(p, deps());
    p.done();
    expect(plan?.groups).toEqual(['code', 'web']);
    expect(plan?.consentAt).toEqual(NOW);
    expect(plan?.config.targets).toEqual([{ id: 'portal-example-com', url: 'https://portal.example.com', type: 'web', env: 'prod', allow_private: false }]);
    expect(plan?.config.network.scan_label).toBe('office');
    expect(p.asked.at(-1)).toBe('I own these systems or have written permission to test them');
  });

  it('re-asks for an address that is not a web address', async () => {
    const p = new ScriptedPrompter([undefined, ['web'], 'portal.example.com', 'ftp://x.example.com', 'https://user:pw@x.example.com', 'https://x.example.com', 'api', 'staging', false, 'home', true]);
    const plan = await askPlan(p, deps());
    p.done();
    expect(p.rejected.map((r) => r.error)).toEqual([
      'Enter a full address starting with https:// or http://',
      'Enter a full address starting with https:// or http://',
      'Leave out user names and passwords',
    ]);
    expect(plan?.config.targets[0]).toMatchObject({ url: 'https://x.example.com', type: 'api', env: 'staging' });
  });

  it('asks before scanning an internal address, and drops it on a no', async () => {
    const internal = async () => ['10.0.0.5'];
    const no = new ScriptedPrompter([undefined, ['code', 'web'], 'https://intranet.example.com', false, false]);
    const dropped = await askPlan(no, deps({ resolve: internal }));
    no.done();
    expect(no.asked).toContain('intranet.example.com is an internal address (10.0.0.5). Scan it anyway?');
    expect(dropped?.config.targets).toEqual([]);
    expect(dropped?.groups).toEqual(['code']);
    expect(dropped?.consentAt).toBeUndefined();

    const yes = new ScriptedPrompter([undefined, ['web'], 'http://127.0.0.1:8080', true, 'web', 'dev', false, 'office', true]);
    const kept = await askPlan(yes, deps());
    yes.done();
    expect(kept?.config.targets[0]).toMatchObject({ id: '127-0-0-1', url: 'http://127.0.0.1:8080', allow_private: true });
  });

  it('an address that cannot be looked up is kept, with a note that the scan will say so', async () => {
    const p = new ScriptedPrompter([undefined, ['web'], 'https://nowhere.invalid', 'web', 'prod', false, 'office', true]);
    const plan = await askPlan(p, deps({ resolve: async () => Promise.reject(new Error('ENOTFOUND')) }));
    p.done();
    expect(plan?.config.targets).toHaveLength(1);
    expect(p.notes.join('\n')).toContain('Could not look up nowhere.invalid');
  });

  it('a declined consent offers to scan only the code, and keeps the new systems out of the settings', async () => {
    const p = new ScriptedPrompter([undefined, ['code', 'web'], 'https://portal.example.com', 'web', 'prod', false, 'office', false, 'code']);
    const plan = await askPlan(p, deps());
    p.done();
    expect(plan?.groups).toEqual(['code']);
    expect(plan?.consentAt).toBeUndefined();
    expect(plan?.config.targets).toEqual([]);
  });

  it('a declined consent can go back to the questions, with the answers kept as defaults', async () => {
    const p = new ScriptedPrompter([
      undefined, ['web'], 'https://portal.example.com', 'web', 'prod', false, 'office', false, 'back',
      undefined, undefined, true, false, undefined, true,
    ]);
    const plan = await askPlan(p, deps());
    p.done();
    expect(plan?.config.targets.map((t) => t.url)).toEqual(['https://portal.example.com']);
    expect(plan?.consentAt).toEqual(NOW);
  });

  it('a declined consent can quit', async () => {
    const p = new ScriptedPrompter([undefined, ['web'], 'https://portal.example.com', 'web', 'prod', false, 'office', false, 'quit']);
    expect(await askPlan(p, deps())).toBeUndefined();
    p.done();
  });

  describe('servers', () => {
    it('writes the collector on request, takes a valid snapshot, and stores nothing yet', async () => {
      const text = JSON.stringify(fixtureEnvelope('ubuntu-24-04'));
      const written: string[] = [];
      const p = new ScriptedPrompter([undefined, ['host'], 'web-1', '203.0.113.10', 'prod', true, 'snap.json', false, 'office', true]);
      const plan = await askPlan(
        p,
        deps({
          readFile: async (file) => (path.basename(file) === 'snap.json' ? text : Promise.reject(new Error('ENOENT'))),
          writeCollector: async (host) => {
            written.push(host);
            return `/work/shop/.secagent/hosts/${host}/collector.sh`;
          },
        }),
      );
      p.done();
      expect(written).toEqual(['web-1']);
      expect(p.notes.join('\n')).toContain('sudo sh collector.sh > web-1.json');
      expect(plan?.config.hosts).toEqual([expect.objectContaining({ name: 'web-1', address: '203.0.113.10', env: 'prod' })]);
      expect(plan?.snapshots).toEqual([{ host: 'web-1', text }]);
      expect(plan?.groups).toEqual(['host']);
    });

    it('re-asks after an unreadable or invalid snapshot, and can skip it', async () => {
      const p = new ScriptedPrompter([undefined, ['host'], 'web-1', '203.0.113.10', 'prod', false, 'bad.json', true, 'missing.json', false, false, 'office', true]);
      const plan = await askPlan(p, deps({ readFile: async (file) => (path.basename(file) === 'bad.json' ? 'not json' : Promise.reject(new Error('ENOENT: no such file'))) }));
      p.done();
      expect(p.notes.join('\n')).toContain('Snapshot is not JSON');
      expect(p.notes.join('\n')).toContain('no such file');
      expect(p.notes.join('\n')).toContain('web-1 will be reported as not checked');
      expect(plan?.snapshots).toEqual([]);
    });

    it('the review screen says server scans look up package names and versions in public advisory databases, and never claims nothing is sent', async () => {
      const p = new ScriptedPrompter([undefined, ['host'], 'web-1', '203.0.113.10', 'prod', false, '', false, 'office', true]);
      await askPlan(p, deps());
      const review = p.notes.find((n) => n.startsWith('Here is what I will do')) ?? '';
      expect(review).toContain('public advisory databases (OSV, Ubuntu Security, CISA)');
      expect(review).toContain('only package names and versions');
      expect(review).not.toContain('nothing is sent anywhere');
      expect(review).toContain('Your files and secrets are never sent anywhere.');
      const web = new ScriptedPrompter([undefined, ['web'], 'https://portal.example.com', 'web', 'prod', false, 'office', true]);
      await askPlan(web, deps());
      expect(web.notes.find((n) => n.startsWith('Here is what I will do'))).not.toContain('advisory databases');
    });

    it('rejects a server name that is not an id, and a name used twice', async () => {
      const p = new ScriptedPrompter([undefined, ['host'], 'Web 1', 'web-1', '203.0.113.10', 'prod', false, '', true, 'web-1', 'web-2', '203.0.113.11', 'prod', false, '', false, 'office', true]);
      const plan = await askPlan(p, deps());
      p.done();
      expect(p.rejected.map((r) => r.error)).toEqual([
        'Use lowercase letters, digits and dashes, e.g. web-1',
        'web-1 is already in the list',
      ]);
      expect(plan?.config.hosts.map((h) => h.name)).toEqual(['web-1', 'web-2']);
    });
  });

  describe('an existing project', () => {
    it('Scan again asks only for consent', async () => {
      const p = new ScriptedPrompter(['again', true]);
      const plan = await askPlan(p, deps({ existing: existing() }));
      p.done();
      expect(p.asked).toEqual(['This project is already set up. What now?', 'I own these systems or have written permission to test them']);
      expect(plan?.groups).toEqual(['code', 'web', 'host']);
      expect(plan?.config).toEqual(existing());
    });

    it('Change settings starts from the current answers', async () => {
      const p = new ScriptedPrompter(['change', undefined, undefined, true, false, undefined, true, false, true]);
      const plan = await askPlan(p, deps({ existing: existing() }));
      p.done();
      expect(p.asked).toEqual([
        'This project is already set up. What now?',
        'Project name',
        'What should I check?',
        'Keep these websites and APIs? https://portal.example.com',
        'Add another website or API?',
        'Where are you scanning from?',
        'Keep these servers? web-1 (203.0.113.10)',
        'Add another server?',
        'I own these systems or have written permission to test them',
      ]);
      expect(plan?.config.targets).toEqual(existing().targets);
      expect(plan?.config.hosts).toEqual(existing().hosts);
      expect(plan?.config.network.scan_label).toBe('office');
    });

    it('declining consent on Scan again can fall back to the code only, leaving the saved settings alone', async () => {
      const p = new ScriptedPrompter(['again', false, 'code']);
      const plan = await askPlan(p, deps({ existing: existing() }));
      p.done();
      expect(plan).toMatchObject({ groups: ['code'], snapshots: [] });
      expect(plan?.config).toEqual(existing());
      expect(plan?.consentAt).toBeUndefined();
    });

    it('declining consent on Scan again can go back into the questions', async () => {
      const p = new ScriptedPrompter(['again', false, 'back', undefined, undefined, true, false, undefined, true, false, true]);
      const plan = await askPlan(p, deps({ existing: existing() }));
      p.done();
      expect(plan?.consentAt).toEqual(NOW);
      expect(plan?.config.targets).toEqual(existing().targets);
    });

    it('start: again goes straight to consent, without the "already set up" question', async () => {
      const p = new ScriptedPrompter([true]);
      const plan = await askPlan(p, deps({ existing: existing(), start: 'again' }));
      p.done();
      expect(p.asked).toEqual(['I own these systems or have written permission to test them']);
      expect(plan?.config).toEqual(existing());
    });

    it('start: change and fresh skip the question too', async () => {
      const change = new ScriptedPrompter([undefined, undefined, true, false, undefined, true, false, true]);
      expect((await askPlan(change, deps({ existing: existing(), start: 'change' })))?.config.targets).toEqual(existing().targets);
      change.done();
      expect(change.asked[0]).toBe('Project name');
      const fresh = new ScriptedPrompter(['newname', ['code']]);
      expect((await askPlan(fresh, deps({ existing: existing(), start: 'fresh' })))?.config).toMatchObject({ name: 'newname', targets: [], hosts: [] });
      fresh.done();
    });

    it('Start over asks everything again with nothing kept', async () => {
      const p = new ScriptedPrompter(['fresh', 'newname', ['code']]);
      const plan = await askPlan(p, deps({ existing: existing() }));
      p.done();
      expect(plan?.config).toMatchObject({ name: 'newname', targets: [], hosts: [] });
    });
  });
});

describe('collectorSteps', () => {
  it('says how to run the collector on the server and what to bring back', () => {
    expect(collectorSteps('/work/shop/.secagent/hosts/web-1/collector.sh', 'web-1')).toBe(
      'Copy /work/shop/.secagent/hosts/web-1/collector.sh to web-1, read it, then run it there:\n  sudo sh collector.sh > web-1.json\nand bring web-1.json back.',
    );
  });
});

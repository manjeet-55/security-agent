import { describe, expect, it } from 'vitest';
import { suggestUrls } from '../../src/wizard/suggest.js';
import { askPlan } from '../../src/wizard/questions.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

describe('suggestUrls', () => {
  it('finds the deployed address in package.json, CNAME and public URL keys, and nothing else', async () => {
    const dir = await tempDir();
    await writeFiles(dir, {
      'package.json': JSON.stringify({ homepage: 'https://shop.acme-store.io/app' }),
      CNAME: 'www.acme-store.io\n',
      '.env': 'DB_PASSWORD=hunter2hunter2\nSITE_URL="https://acme-store.io"\nAPP_URL=http://localhost:3000\nBASE_URL=https://user:pw@internal.acme-store.io\nPUBLIC_URL=https://example.com\n',
    });
    expect(await suggestUrls(dir)).toEqual(['https://shop.acme-store.io', 'https://www.acme-store.io', 'https://acme-store.io']);
  });

  it('is empty for a folder with nothing to suggest, and the wizard offers a pick that skips the typing', async () => {
    expect(await suggestUrls(await tempDir())).toEqual([]);
    const p = new ScriptedPrompter([undefined, ['web'], 'https://shop.acme-store.io', 'web', 'prod', false, 'office', true]);
    const plan = await askPlan(p, { dir: '/work/shop', detection: { stack: {}, markers: [] }, now: () => new Date('2027-01-01T00:00:00Z'), resolve: async () => ['93.184.216.34'], suggest: async () => ['https://shop.acme-store.io'] });
    p.done();
    expect(p.asked).toContain('I found these addresses in the project. Which one is deployed?');
    expect(p.asked).not.toContain('Address of the deployed website or API (https://...)');
    expect(plan?.config.targets[0]?.url).toBe('https://shop.acme-store.io');
  });
});

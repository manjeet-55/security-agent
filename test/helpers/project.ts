import { initProject } from '../../src/project/init.js';
import { tempDir } from './tmp.js';

/** A temp project with one web target "app" and one host "web-1" (documentation addresses only). */
export async function makeProject(
  opts: { targets?: NonNullable<Parameters<typeof initProject>[1]>['targets']; hosts?: NonNullable<Parameters<typeof initProject>[1]>['hosts'] } = {},
): Promise<string> {
  const dir = await tempDir();
  await initProject(dir, {
    name: 'test',
    scanLabel: 'test-net',
    targets: opts.targets ?? [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
    hosts: opts.hosts ?? [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
  });
  return dir;
}

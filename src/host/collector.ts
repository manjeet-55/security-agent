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

import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';

export type EvidenceKind = 'http' | 'tls' | 'tcp' | 'note' | 'snapshot' | 'advisory';

export interface EvidenceRecord {
  id: string;
  kind: EvidenceKind;
  /** Target id or host name. */
  target: string;
  /** Network the observation was made from (project.yaml network.scan_label). */
  scan_label: string;
  captured_at: string;
  summary: string;
  data: unknown;
}

export const EVIDENCE_ID_PATTERN = /^ev_\d{8}T\d{6}Z_[0-9a-f]{8}$/;

export function newEvidenceId(now: Date): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return `ev_${stamp}_${randomBytes(4).toString('hex')}`;
}

export class EvidenceStore {
  readonly dir: string;

  constructor(
    projectDir: string,
    private readonly scanLabel: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.dir = path.join(projectStateDir(projectDir), 'evidence');
  }

  async put(kind: EvidenceKind, target: string, summary: string, data: unknown): Promise<string> {
    const at = this.now();
    const id = newEvidenceId(at);
    const record: EvidenceRecord = { id, kind, target, scan_label: this.scanLabel, captured_at: at.toISOString(), summary, data };
    await mkdir(this.dir, { recursive: true });
    await writeFile(path.join(this.dir, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`, 'utf8');
    return id;
  }

  async get(id: string): Promise<EvidenceRecord> {
    if (!EVIDENCE_ID_PATTERN.test(id)) throw new Error(`Invalid evidence id "${id}"`);
    return JSON.parse(await readFile(path.join(this.dir, `${id}.json`), 'utf8')) as EvidenceRecord;
  }
}

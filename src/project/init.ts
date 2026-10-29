import { access, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';
import { loadProject, projectFile, saveProject, validateProject, type ProjectConfig } from './schema.js';
import { detectStack, type StackDetection } from './stack.js';

export interface InitOptions {
  name?: string;
  scanLabel?: string;
  targets?: Array<{ id: string; url: string; type: 'web' | 'api'; env: string; allow_private?: boolean }>;
  hosts?: Array<{ name: string; address: string; env: string }>;
}

export interface InitResult {
  created: boolean;
  config: ProjectConfig;
  detection: StackDetection;
  stateDir: string;
}

const STATE_SUBDIRS = ['hosts', 'external', 'evidence', 'findings/history', 'reports', 'knowledge'];

const GITIGNORE = `# Sensitive, machine-specific scan state. Only project.yaml and knowledge/ are committed.
hosts/
external/
evidence/
findings/
reports/
knowledge/fetched/
`;

const NOTES = `# Project security notes

Facts learned about this project. Every line cites an evidence ID.
`;

const EXCEPTIONS = `# Accepted risks. Each entry: finding_id, owner, reason, expires (YYYY-MM-DD).
exceptions: []
`;

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function writeIfMissing(file: string, content: string): Promise<void> {
  if (!(await exists(file))) await writeFile(file, content, 'utf8');
}

export async function initProject(projectDir: string, opts: InitOptions = {}): Promise<InitResult> {
  const stateDir = projectStateDir(projectDir);
  for (const sub of STATE_SUBDIRS) await mkdir(path.join(stateDir, sub), { recursive: true });
  await writeIfMissing(path.join(stateDir, '.gitignore'), GITIGNORE);
  await writeIfMissing(path.join(stateDir, 'knowledge', 'notes.md'), NOTES);
  await writeIfMissing(path.join(stateDir, 'knowledge', 'exceptions.yaml'), EXCEPTIONS);

  const detection = await detectStack(projectDir);
  const created = !(await exists(projectFile(projectDir)));
  let config: ProjectConfig;
  if (created) {
    config = validateProject({
      version: 1,
      name: opts.name ?? path.basename(path.resolve(projectDir)),
      stack: detection.stack,
      network: { scan_label: opts.scanLabel ?? 'unlabelled' },
      targets: opts.targets ?? [],
      hosts: opts.hosts ?? [],
    });
  } else {
    // Re-running init only fills in stack values the user has not set. Targets and hosts are never touched.
    const existing = await loadProject(projectDir);
    config = validateProject({ ...existing, stack: { ...detection.stack, ...existing.stack } });
  }
  await saveProject(projectDir, config);
  return { created, config, detection, stateDir };
}

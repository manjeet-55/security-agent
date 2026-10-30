import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the secagent package. src/paths.ts and dist/paths.js both sit one level below it. */
export const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
export const GLOBAL_KNOWLEDGE_DIR = path.join(PACKAGE_ROOT, 'knowledge');
export const GLOBAL_CHECKS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'checks');
export const GLOBAL_LESSONS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'lessons');
export const GLOBAL_CHECKLISTS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'checklists');

export const SECAGENT_DIRNAME = '.secagent';

export function projectStateDir(projectDir: string): string {
  return path.join(projectDir, SECAGENT_DIRNAME);
}

/** <project>/.secagent/knowledge: notes.md, exceptions.yaml and the project's own lessons (these are committed). */
export function projectKnowledgeDir(projectDir: string): string {
  return path.join(projectStateDir(projectDir), 'knowledge');
}

/** The version in the package's own package.json ("0.0.0" if it cannot be read). */
export function packageVersion(): string {
  try {
    return (JSON.parse(readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as { version?: string }).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

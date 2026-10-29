import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the secagent package. src/paths.ts and dist/paths.js both sit one level below it. */
export const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
export const GLOBAL_KNOWLEDGE_DIR = path.join(PACKAGE_ROOT, 'knowledge');
export const GLOBAL_CHECKS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'checks');
export const GLOBAL_LESSONS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'lessons');

export const SECAGENT_DIRNAME = '.secagent';

export function projectStateDir(projectDir: string): string {
  return path.join(projectDir, SECAGENT_DIRNAME);
}

/** <project>/.secagent/knowledge: notes.md, exceptions.yaml and the project's own lessons (these are committed). */
export function projectKnowledgeDir(projectDir: string): string {
  return path.join(projectStateDir(projectDir), 'knowledge');
}

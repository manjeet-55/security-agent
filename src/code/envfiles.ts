import path from 'node:path';
import { isPlaceholderValue } from './patterns.js';

export type SensitiveKind = 'env-file' | 'private-key-file' | 'credentials-file' | 'terraform-state' | 'aws-credentials' | 'npmrc';

/** What each kind of file is, for the sentence that names it. */
export const KIND_LABEL: Record<SensitiveKind, string> = {
  'env-file': 'environment file',
  'private-key-file': 'key or certificate file',
  'credentials-file': 'credentials file',
  'terraform-state': 'Terraform state',
  'aws-credentials': 'AWS credentials file',
  npmrc: 'npm config with an auth token',
};

/** A .env.<suffix> file whose last suffix says it is a template is safe to commit. */
const ENV_TEMPLATE_SUFFIXES = new Set(['example', 'sample', 'template', 'dist', 'defaults']);
const KEY_EXTENSIONS = new Set(['pem', 'key', 'p12', 'pfx']);
const SSH_KEY_PREFIXES = ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa'];

/**
 * Files that normally hold secrets, judged by name alone. `.npmrc` is only a candidate: it counts once `npmrcHoldsAuthToken` says
 * it carries a literal token. A `.pem` may be a public certificate; list it in `code.exclude` if so.
 */
export function classifySensitiveFile(rel: string): SensitiveKind | undefined {
  const base = path.posix.basename(rel).toLowerCase();
  if (base === '.env') return 'env-file';
  if (base.startsWith('.env.')) return ENV_TEMPLATE_SUFFIXES.has(base.slice(base.lastIndexOf('.') + 1)) ? undefined : 'env-file';
  if (base === '.npmrc') return 'npmrc';
  if (base === 'credentials' && path.posix.basename(path.posix.dirname(rel)) === '.aws') return 'aws-credentials';
  if (base.startsWith('terraform.tfstate')) return 'terraform-state';
  if (base.startsWith('credentials') && base.endsWith('.json')) return 'credentials-file';
  if (SSH_KEY_PREFIXES.some((p) => base.startsWith(p))) return base.endsWith('.pub') ? undefined : 'private-key-file';
  const dot = base.lastIndexOf('.');
  if (dot > 0 && KEY_EXTENSIONS.has(base.slice(dot + 1))) return 'private-key-file';
  return undefined;
}

/** Does an .npmrc hold a literal `_authToken`? An empty value or a ${VAR} / $VAR reference does not count, nor does a comment. */
export function npmrcHoldsAuthToken(text: string): boolean {
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('#') || line.startsWith(';')) continue;
    const m = /_authToken\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const value = (m[1] ?? '').trim().replace(/^(['"])(.*)\1$/, '$2');
    if (value !== '' && !value.startsWith('$') && !isPlaceholderValue(value)) return true;
  }
  return false;
}

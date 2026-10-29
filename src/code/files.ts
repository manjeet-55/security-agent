import { constants as fsConstants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { SECAGENT_DIRNAME } from '../paths.js';
import type { CodeConfig } from '../project/schema.js';
import { compileExcludes } from './exclude.js';
import { gitListFiles } from './git.js';

const WALK_EXCLUDED_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'vendor', 'coverage', '.next']);

const LOCKFILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'gemfile.lock',
  'pipfile.lock',
  'poetry.lock',
  'cargo.lock',
  'go.sum',
  'bun.lockb',
]);

const BINARY_EXTENSIONS = new Set(
  ('png jpg jpeg gif webp ico bmp tif tiff psd pdf zip gz tgz bz2 xz 7z rar jar war ear class so dll dylib exe bin o a ' +
    'woff woff2 ttf otf eot mp3 mp4 m4a mov avi webm wav ogg flac wasm sqlite sqlite3 pyc').split(' '),
);

const DOC_EXTENSIONS = new Set(['md', 'markdown', 'mdx', 'rst', 'adoc', 'txt']);

function extensionOf(rel: string): string {
  const base = path.posix.basename(rel).toLowerCase();
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot + 1);
}

export function isLockfile(rel: string): boolean {
  const base = path.posix.basename(rel).toLowerCase();
  return LOCKFILES.has(base) || base.endsWith('.lock');
}

export function hasBinaryExtension(rel: string): boolean {
  return BINARY_EXTENSIONS.has(extensionOf(rel));
}

/** Documentation and lockfiles are full of example credentials and hashes: only the high-confidence patterns run over them. */
export function isGenericExempt(rel: string): boolean {
  return isLockfile(rel) || DOC_EXTENSIONS.has(extensionOf(rel));
}

/** Generated artefacts the directory walk leaves out. A git listing keeps them: what is tracked is what ships. */
function isWalkNoise(rel: string): boolean {
  const base = path.posix.basename(rel).toLowerCase();
  return isLockfile(rel) || base.endsWith('.min.js') || base.endsWith('.map');
}

/** Paths come from git or the file system, but are checked anyway: nothing absolute, nothing that climbs out, nothing in .secagent. */
function isScannablePath(rel: string): boolean {
  if (rel === '' || rel.includes('\0') || path.posix.isAbsolute(rel) || path.win32.isAbsolute(rel)) return false;
  const segments = rel.split('/');
  return !segments.includes('..') && segments[0] !== SECAGENT_DIRNAME;
}

export interface FileListing {
  mode: 'git' | 'walk';
  /** Posix paths relative to the project directory, sorted, at most max_files of them. */
  files: string[];
  /** Files beyond max_files that were left unread. For a walk this is a lower bound: the walk stops once the cap is passed. */
  over_max_files: number;
  /** Directories the walk could not read. */
  unreadable_dirs: string[];
}

/** The files a code scan covers when the project is a git repository: tracked, plus untracked and not ignored. */
export async function listGitFiles(dir: string, cfg: CodeConfig): Promise<FileListing> {
  const excluded = compileExcludes(cfg.exclude);
  const all = (await gitListFiles(dir, 'tracked-and-untracked')).filter((rel) => isScannablePath(rel) && !hasBinaryExtension(rel) && !excluded(rel, false));
  return { mode: 'git', files: all.slice(0, cfg.max_files), over_max_files: Math.max(0, all.length - cfg.max_files), unreadable_dirs: [] };
}

/** The files a code scan covers when the project is not a git repository: everything below it except the default and configured excludes. */
export async function listWalkedFiles(dir: string, cfg: CodeConfig): Promise<FileListing> {
  const excluded = compileExcludes(cfg.exclude);
  const files: string[] = [];
  const unreadable: string[] = [];
  const pending = [''];
  while (pending.length > 0 && files.length <= cfg.max_files) {
    const rel = pending.pop() as string;
    let entries;
    try {
      entries = await readdir(path.join(dir, rel), { withFileTypes: true });
    } catch {
      unreadable.push(rel === '' ? '.' : rel);
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (!isScannablePath(child) || entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!WALK_EXCLUDED_DIRS.has(entry.name) && !excluded(child, true)) pending.push(child);
      } else if (entry.isFile() && !hasBinaryExtension(child) && !isWalkNoise(child) && !excluded(child, false)) {
        files.push(child);
      }
    }
  }
  files.sort();
  return {
    mode: 'walk',
    files: files.slice(0, cfg.max_files),
    over_max_files: Math.max(0, files.length - cfg.max_files),
    unreadable_dirs: unreadable.sort(),
  };
}

export type ReadResult =
  | { kind: 'text'; text: string }
  /** Not text (a NUL byte in the first 8 KiB): nothing to scan, and not a gap in coverage. */
  | { kind: 'binary' }
  | { kind: 'too_large'; size: number }
  /** Listed but gone, a directory (submodule), a special file, or a link: not project content, not a gap in coverage. */
  | { kind: 'absent' }
  | { kind: 'unreadable'; code: string };

export interface ProjectReader {
  read(rel: string, maxBytes: number): Promise<ReadResult>;
}

/**
 * Reads files below `root` and nowhere else: symbolic links are never followed (the final component is opened with O_NOFOLLOW,
 * and a parent directory that resolves outside the root is refused), and anything that is not a regular file is skipped.
 */
export function createProjectReader(root: string): ProjectReader {
  let rootReal: Promise<string> | undefined;
  const parents = new Map<string, Promise<boolean>>();

  async function parentInside(dir: string): Promise<boolean> {
    rootReal ??= realpath(root);
    const resolved = await realpath(dir).catch(() => undefined);
    const base = await rootReal;
    return resolved !== undefined && (resolved === base || resolved.startsWith(base + path.sep));
  }

  return {
    async read(rel, maxBytes) {
      if (!isScannablePath(rel)) return { kind: 'absent' };
      const full = path.join(root, rel);
      const parent = path.dirname(full);
      let inside = parents.get(parent);
      if (!inside) {
        inside = parentInside(parent);
        parents.set(parent, inside);
      }
      if (!(await inside)) return { kind: 'absent' };
      try {
        const link = await lstat(full);
        if (!link.isFile()) return { kind: 'absent' };
        if (link.size > maxBytes) return { kind: 'too_large', size: link.size };
        const handle = await open(full, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
        try {
          const stat = await handle.stat();
          if (!stat.isFile()) return { kind: 'absent' };
          if (stat.size > maxBytes) return { kind: 'too_large', size: stat.size };
          const buf = Buffer.alloc(stat.size);
          let read = 0;
          while (read < buf.length) {
            const { bytesRead } = await handle.read(buf, read, buf.length - read, read);
            if (bytesRead === 0) break;
            read += bytesRead;
          }
          const data = buf.subarray(0, read);
          if (data.subarray(0, 8192).includes(0)) return { kind: 'binary' };
          return { kind: 'text', text: data.toString('utf8') };
        } finally {
          await handle.close();
        }
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code ?? 'UNKNOWN';
        if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'ELOOP') return { kind: 'absent' };
        return { kind: 'unreadable', code };
      }
    },
  };
}

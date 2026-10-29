/**
 * A small gitignore-style matcher for `code.exclude`. A pattern without a slash matches a file or directory of that name at any
 * depth; one with a slash is anchored at the project root; a trailing slash limits it to directories. `*` stays inside one path
 * segment, `**` crosses segments, `?` is one non-slash character. A match excludes everything below a matched directory.
 * No negation and no character classes.
 */
function escapeRegExp(c: string): string {
  return c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function globToRegExp(glob: string): RegExp {
  let out = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i] as string;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i += 1;
        if (glob[i + 1] === '/') {
          i += 1;
          out += '(?:.*/)?';
        } else {
          out += '.*';
        }
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else {
      out += escapeRegExp(c);
    }
  }
  return new RegExp(`^${out}$`);
}

interface Rule {
  regex: RegExp;
  dirOnly: boolean;
  anchored: boolean;
}

function compile(pattern: string): Rule | undefined {
  let p = pattern.trim();
  if (p === '' || p.startsWith('#')) return undefined;
  if (p.startsWith('./')) p = p.slice(2);
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);
  if (p === '') return undefined;
  return { regex: globToRegExp(p), dirOnly, anchored };
}

/** `excluded(relPath, isDir)`: relPath is posix, relative to the project directory. */
export function compileExcludes(patterns: readonly string[]): (relPath: string, isDir: boolean) => boolean {
  const rules = patterns.map(compile).filter((r): r is Rule => r !== undefined);
  if (rules.length === 0) return () => false;
  return (relPath, isDir) => {
    const segments = relPath.split('/').filter((s) => s !== '');
    for (let i = 0; i < segments.length; i += 1) {
      const prefixIsDir = i < segments.length - 1 || isDir;
      const prefix = segments.slice(0, i + 1).join('/');
      for (const r of rules) {
        if (r.dirOnly && !prefixIsDir) continue;
        if (r.regex.test(r.anchored ? prefix : (segments[i] as string))) return true;
      }
    }
    return false;
  };
}

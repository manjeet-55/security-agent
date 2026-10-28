import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Stack } from './schema.js';

export interface StackDetection {
  stack: Stack;
  /** Human-readable reasons, e.g. "web/angular.json → frontend: angular". */
  markers: string[];
}

const SKIP = new Set(['node_modules', 'dist', 'build', 'coverage']);

async function listDir(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch {
    return [];
  }
}

async function readDeps(dir: string): Promise<Set<string>> {
  try {
    const pkg = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
  } catch {
    return new Set();
  }
}

/** Looks at the project root and its immediate subdirectories. The result only picks fix hints; checks never depend on it. */
export async function detectStack(projectDir: string): Promise<StackDetection> {
  const stack: Stack = {};
  const markers: string[] = [];
  const dirs = [projectDir];
  for (const entry of await listDir(projectDir)) {
    if (SKIP.has(entry) || entry.startsWith('.')) continue;
    const full = path.join(projectDir, entry);
    if ((await listDir(full)).length > 0) dirs.push(full);
  }

  for (const dir of dirs) {
    const entries = await listDir(dir);
    const has = (name: string) => entries.includes(name);
    const hasPrefix = (prefix: string) => entries.some((e) => e.startsWith(prefix));
    const deps = await readDeps(dir);
    const rel = path.relative(projectDir, dir) || '.';
    const mark = (field: keyof Stack, value: string, marker: string) => {
      markers.push(`${rel}/${marker} → ${field}: ${value}`);
      stack[field] ??= value;
    };

    if (has('angular.json')) mark('frontend', 'angular', 'angular.json');
    if (hasPrefix('next.config.')) mark('frontend', 'nextjs', 'next.config.*');
    if (deps.has('vue') && (hasPrefix('vite.config.') || hasPrefix('vue.config.'))) mark('frontend', 'vue', 'vue + vite/vue config');
    if (has('nest-cli.json')) mark('backend', 'nestjs', 'nest-cli.json');
    else if (deps.has('express') && !deps.has('@nestjs/core')) mark('backend', 'express', 'package.json express');
    if (has('nginx.conf')) mark('proxy', 'nginx', 'nginx.conf');
    else if (has('nginx') && (await listDir(path.join(dir, 'nginx'))).some((f) => f.endsWith('.conf'))) {
      mark('proxy', 'nginx', 'nginx/*.conf');
    }
    if (has('vercel.json')) mark('hosting', 'vercel', 'vercel.json');
    if (has('Dockerfile')) mark('hosting', 'container', 'Dockerfile');
  }
  return { stack, markers };
}

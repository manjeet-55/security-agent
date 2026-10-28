import { describe, expect, it } from 'vitest';
import { detectStack } from '../../src/project/stack.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

async function project(files: Record<string, string>): Promise<string> {
  const dir = await tempDir('secagent-stack-');
  await writeFiles(dir, files);
  return dir;
}

describe('detectStack', () => {
  it('detects an Angular + NestJS monorepo behind nginx', async () => {
    const dir = await project({
      'web/angular.json': '{}',
      'api/nest-cli.json': '{}',
      'api/package.json': JSON.stringify({ dependencies: { '@nestjs/core': '1', express: '1' } }),
      'deploy/nginx.conf': '',
    });
    const r = await detectStack(dir);
    expect(r.stack).toEqual({ frontend: 'angular', backend: 'nestjs', proxy: 'nginx' });
    expect(r.markers.some((m) => m.includes('angular.json'))).toBe(true);
  });

  it('detects Vue only with a Vite or Vue config present', async () => {
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { vue: '3' } }), 'vite.config.ts': '' }))).stack).toEqual({ frontend: 'vue' });
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { vue: '3' } }) }))).stack).toEqual({});
  });

  it('detects plain Express but not Express under Nest', async () => {
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { express: '4' } }) }))).stack).toEqual({ backend: 'express' });
  });

  it('detects Next.js on Vercel', async () => {
    expect((await detectStack(await project({ 'next.config.mjs': '', 'vercel.json': '{}' }))).stack).toEqual({ frontend: 'nextjs', hosting: 'vercel' });
  });

  it('detects nginx configs in an nginx/ folder and containers', async () => {
    expect((await detectStack(await project({ 'nginx/site.conf': '', Dockerfile: 'FROM node' }))).stack).toEqual({ proxy: 'nginx', hosting: 'container' });
  });

  it('ignores node_modules and hidden folders', async () => {
    expect((await detectStack(await project({ 'node_modules/angular.json': '{}', '.cache/nest-cli.json': '{}' }))).stack).toEqual({});
  });
});

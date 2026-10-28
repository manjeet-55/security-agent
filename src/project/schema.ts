import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse, stringify } from 'yaml';
import { z } from 'zod';
import { projectStateDir } from '../paths.js';

const Id = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'use lowercase letters, digits and dashes, starting with a letter or digit');

export const StackSchema = z.object({
  frontend: z.string().optional(),
  backend: z.string().optional(),
  proxy: z.string().optional(),
  hosting: z.string().optional(),
});

export const TargetSchema = z.object({
  id: Id,
  url: z.url({ protocol: /^https?$/ }),
  type: z.enum(['web', 'api']),
  env: z.string().min(1),
  allow_private: z.boolean().default(false),
});

export const HostSchema = z.object({
  name: Id,
  address: z.string().min(1),
  env: z.string().min(1),
  role: z.string().optional(),
  reachable_from: z.array(z.string()).default([]),
  serves: z.array(z.string()).default([]),
  allow_private: z.boolean().default(false),
});

export const ProjectSchema = z
  .object({
    version: z.literal(1),
    name: z.string().min(1),
    stack: StackSchema.default({}),
    network: z
      .object({
        ip_family: z.union([z.literal(4), z.literal(6)]).default(4),
        scan_label: z.string().min(1).default('unlabelled'),
      })
      .prefault({}),
    targets: z.array(TargetSchema).default([]),
    hosts: z.array(HostSchema).default([]),
  })
  .superRefine((p, ctx) => {
    const targetIds = new Set<string>();
    p.targets.forEach((t, i) => {
      if (targetIds.has(t.id)) {
        ctx.addIssue({ code: 'custom', path: ['targets', i, 'id'], message: `duplicate target id "${t.id}"` });
      }
      targetIds.add(t.id);
    });
    const hostNames = new Set<string>();
    p.hosts.forEach((h, i) => {
      if (hostNames.has(h.name)) {
        ctx.addIssue({ code: 'custom', path: ['hosts', i, 'name'], message: `duplicate host name "${h.name}"` });
      }
      hostNames.add(h.name);
      for (const s of h.serves) {
        if (!targetIds.has(s)) {
          ctx.addIssue({ code: 'custom', path: ['hosts', i, 'serves'], message: `unknown target id "${s}"` });
        }
      }
    });
  });

export type Stack = z.infer<typeof StackSchema>;
export type Target = z.infer<typeof TargetSchema>;
export type Host = z.infer<typeof HostSchema>;
export type ProjectConfig = z.infer<typeof ProjectSchema>;

export class ProjectConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProjectConfigError';
  }
}

export function projectFile(projectDir: string): string {
  return path.join(projectStateDir(projectDir), 'project.yaml');
}

export function validateProject(raw: unknown, source = 'project.yaml'): ProjectConfig {
  const result = ProjectSchema.safeParse(raw);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
    throw new ProjectConfigError(`${source} is invalid:\n${lines.join('\n')}`);
  }
  return result.data;
}

export function parseProject(text: string, source = 'project.yaml'): ProjectConfig {
  let raw: unknown;
  try {
    raw = parse(text);
  } catch (e) {
    throw new ProjectConfigError(`${source}: invalid YAML: ${(e as Error).message}`);
  }
  return validateProject(raw, source);
}

export async function loadProject(projectDir: string): Promise<ProjectConfig> {
  const file = projectFile(projectDir);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new ProjectConfigError(`No project config at ${file}. Run "secagent init" first.`);
  }
  return parseProject(text, file);
}

const HEADER = '# secagent project config. Targets and hosts listed here are the ONLY things secagent will probe.\n';

export async function saveProject(projectDir: string, config: ProjectConfig): Promise<void> {
  const valid = validateProject(config);
  await writeFile(projectFile(projectDir), HEADER + stringify(valid), 'utf8');
}

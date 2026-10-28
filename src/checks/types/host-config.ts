import path from 'node:path';
import { z } from 'zod';
import { nginxDirectiveValues } from '../../host/parse.js';
import type { HostSnapshot } from '../../host/snapshot.js';
import type { CheckType } from '../check-type.js';
import { getSnapshot } from '../context.js';
import { ObservationError } from '../errors.js';

const Port = z.number().int().min(1).max(65535);

export const hostConfigParams = z.discriminatedUnion('rule', [
  z.object({
    rule: z.literal('sshd_value'),
    key: z
      .string()
      .min(1)
      .transform((k) => k.toLowerCase()),
    allowed: z.array(z.string()).min(1),
  }),
  z
    .object({
      rule: z.literal('nginx_directive'),
      directive: z.string().regex(/^[a-z_]+$/),
      equals: z.string().optional(),
      forbid_tokens: z.array(z.string()).optional(),
      /** nginx's built-in default when the directive is never set (e.g. server_tokens → "on"). */
      absent_default: z.string().optional(),
      when_absent: z.enum(['pass', 'fail', 'unverifiable']).default('unverifiable'),
    })
    .refine((p) => p.equals !== undefined || p.forbid_tokens !== undefined, { message: 'nginx_directive needs "equals" or "forbid_tokens"' }),
  z.object({ rule: z.literal('listening'), forbid_public_ports: z.array(Port).min(1) }),
  z.object({ rule: z.literal('auto_upgrades') }),
]);
export type HostConfigParams = z.infer<typeof hostConfigParams>;

export interface HostConfigVerdict {
  outcome: 'pass' | 'fail';
  observed: string;
  /** The part of the snapshot the verdict rests on (stored as evidence). */
  excerpt: unknown;
}

const WILDCARD = new Set(['0.0.0.0', '::', '*']);

/**
 * A missing tool (rc 127) counts as "not installed" only when the collector ran as root and dpkg lists no package
 * that would provide it; otherwise the tool may simply be off the collector's PATH or the package list unreadable.
 */
function assertProvablyAbsent(snap: HostSnapshot, tool: 'sshd' | 'nginx', reason: string, isProvider: (name: string) => boolean): void {
  if (!snap.is_root) throw new ObservationError('NOT_ROOT', `"${tool}" could not be run (${reason}); run the collector as root.`);
  if (snap.packages_error !== undefined || snap.packages.length === 0) {
    throw new ObservationError('TOOL_MISSING', `"${tool}" was not found (${reason}) and the package list is unusable, so its absence is unproven.`);
  }
  const found = snap.packages.find((pkg) => isProvider(pkg.name));
  if (found) throw new ObservationError('TOOL_MISSING', `"${tool}" was not found (${reason}) but package ${found.name} is installed; run the collector as root with a full PATH.`);
}

export function evaluateHostConfig(snap: HostSnapshot, p: HostConfigParams): HostConfigVerdict {
  switch (p.rule) {
    case 'sshd_value': {
      if (snap.sshd.state === 'absent') {
        assertProvablyAbsent(snap, 'sshd', snap.sshd.reason, (n) => n === 'openssh-server');
        return { outcome: 'pass', observed: 'sshd is not installed on this host', excerpt: snap.sshd };
      }
      if (snap.sshd.state === 'error') {
        if (!snap.is_root) throw new ObservationError('NOT_ROOT', `"sshd -T" failed (${snap.sshd.reason}); run the collector as root.`);
        throw new ObservationError('SSHD_UNREADABLE', `"sshd -T" failed (${snap.sshd.reason}); run the collector as root.`);
      }
      const value = snap.sshd.value[p.key];
      if (value === undefined) throw new ObservationError('SSHD_KEY_MISSING', `"sshd -T" did not report ${p.key}.`);
      const ok = p.allowed.some((a) => a.toLowerCase() === value.toLowerCase());
      return {
        outcome: ok ? 'pass' : 'fail',
        observed: ok ? `${p.key} ${value}` : `${p.key} ${value} (expected ${p.allowed.join(' or ')})`,
        excerpt: { [p.key]: value },
      };
    }
    case 'nginx_directive': {
      if (snap.nginx.state === 'absent') {
        assertProvablyAbsent(snap, 'nginx', snap.nginx.reason, (n) => n.startsWith('nginx') || n === 'openresty');
        return { outcome: 'pass', observed: 'nginx is not installed on this host', excerpt: snap.nginx };
      }
      if (snap.nginx.state === 'error') {
        if (!snap.is_root) throw new ObservationError('NOT_ROOT', `"nginx -T" failed (${snap.nginx.reason}); run the collector as root.`);
        throw new ObservationError('NGINX_UNREADABLE', `"nginx -T" failed (${snap.nginx.reason}); run the collector as root.`);
      }
      let values = nginxDirectiveValues(snap.nginx.value, p.directive);
      let note = '';
      if (values.length === 0) {
        if (p.absent_default !== undefined) {
          values = [p.absent_default];
          note = ` (not set; nginx default "${p.absent_default}" applies)`;
        } else if (p.when_absent === 'unverifiable') {
          throw new ObservationError(
            'NGINX_DIRECTIVE_ABSENT',
            `${p.directive} is not set anywhere, so the effective value depends on the nginx version; set it explicitly.`,
          );
        } else {
          return { outcome: p.when_absent, observed: `${p.directive} is not set`, excerpt: { [p.directive]: [] } };
        }
      }
      const excerpt = { [p.directive]: values };
      if (p.equals !== undefined) {
        const expected = p.equals.toLowerCase();
        const bad = [...new Set(values.filter((v) => v.toLowerCase() !== expected))];
        if (bad.length > 0) return { outcome: 'fail', observed: `${p.directive} ${bad.join(' / ')}${note} (expected ${p.equals})`, excerpt };
      }
      if (p.forbid_tokens) {
        const forbidden = new Set(p.forbid_tokens.map((t) => t.toLowerCase()));
        const hits = [...new Set(values.flatMap((v) => v.split(/\s+/)).filter((t) => forbidden.has(t.toLowerCase())))];
        if (hits.length > 0) return { outcome: 'fail', observed: `${p.directive} allows ${hits.join(', ')}${note}`, excerpt };
      }
      return { outcome: 'pass', observed: `${p.directive} ${[...new Set(values)].join(' / ')}${note}`, excerpt };
    }
    case 'listening': {
      if (snap.listening.state !== 'ok') {
        throw new ObservationError('LISTENING_UNREADABLE', `"ss -tlnp" was not available (${snap.listening.reason}).`);
      }
      const ports = new Set(p.forbid_public_ports);
      const relevant = snap.listening.value.filter((s) => ports.has(s.port));
      const exposed = relevant.filter((s) => WILDCARD.has(s.address));
      if (exposed.length > 0) {
        return {
          outcome: 'fail',
          observed: `listening on all interfaces: ${exposed.map((s) => `${s.port}${s.process ? `/${s.process}` : ''}`).join(', ')}`,
          excerpt: exposed,
        };
      }
      return { outcome: 'pass', observed: `none of ${ports.size} database/admin ports listen on all interfaces`, excerpt: relevant };
    }
    case 'auto_upgrades': {
      const a = snap.auto_upgrades;
      if (!a.installed) return { outcome: 'fail', observed: 'unattended-upgrades is not installed', excerpt: a };
      if (!a.enabled) return { outcome: 'fail', observed: 'unattended-upgrades is installed but APT::Periodic::Unattended-Upgrade is not "1"', excerpt: a };
      return { outcome: 'pass', observed: 'unattended-upgrades is installed and enabled', excerpt: a };
    }
  }
}

export const hostConfigCheck: CheckType<HostConfigParams> = {
  type: 'host_config',
  supports: ['host'],
  params: hostConfigParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'host') throw new Error('host_config runs on hosts only');
    const { snapshot, file } = await getSnapshot(ctx, subject.host);
    const verdict = evaluateHostConfig(snapshot, p);
    const evidence_id = await ctx.evidence.put('snapshot', subject.host.name, `${p.rule} from snapshot ${snapshot.collected_at}`, {
      snapshot: path.basename(file),
      collected_at: snapshot.collected_at,
      rule: p.rule,
      excerpt: verdict.excerpt,
    });
    return { outcome: verdict.outcome, observed: verdict.observed, evidence_id };
  },
};

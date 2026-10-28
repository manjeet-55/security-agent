import { isIP } from 'node:net';
import { isPrivateAddress, resolveAddresses, stripBrackets } from '../net/ip.js';
import type { Host, ProjectConfig, Target } from './schema.js';

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

interface ScopeEntry {
  hostname: string;
  allowPrivate: boolean;
}

function normalise(hostname: string): string {
  return stripBrackets(hostname).toLowerCase();
}

/**
 * The allowlist every probe goes through. A hostname is in scope when it is a listed target's hostname
 * or a listed host's address. Private addresses are only reachable when listed as an IP literal or when
 * the entry sets allow_private.
 */
export class Scope {
  private readonly entries: ScopeEntry[];
  private readonly checked = new Map<string, Promise<string[]>>();

  constructor(private readonly project: ProjectConfig) {
    this.entries = [
      ...project.targets.map((t) => ({ hostname: normalise(new URL(t.url).hostname), allowPrivate: t.allow_private })),
      ...project.hosts.map((h) => ({ hostname: normalise(h.address), allowPrivate: h.allow_private })),
    ];
  }

  target(id: string): Target {
    const target = this.project.targets.find((t) => t.id === id);
    if (!target) {
      const known = this.project.targets.map((t) => t.id).join(', ') || '(none)';
      throw new ScopeError(`Unknown target "${id}". Targets in project.yaml: ${known}`);
    }
    return target;
  }

  host(name: string): Host {
    const host = this.project.hosts.find((h) => h.name === name);
    if (!host) {
      const known = this.project.hosts.map((h) => h.name).join(', ') || '(none)';
      throw new ScopeError(`Unknown host "${name}". Hosts in project.yaml: ${known}`);
    }
    return host;
  }

  async assertHostnameAllowed(hostname: string): Promise<string[]> {
    const h = normalise(hostname);
    const matches = this.entries.filter((e) => e.hostname === h);
    if (matches.length === 0) {
      throw new ScopeError(
        `"${hostname}" is not in project.yaml (targets/hosts). secagent only probes listed targets; add it there if it belongs to this project.`,
      );
    }
    let pending = this.checked.get(h);
    if (!pending) {
      pending = this.resolveChecked(h, matches.some((m) => m.allowPrivate));
      this.checked.set(h, pending);
    }
    return pending;
  }

  async assertUrlAllowed(url: string): Promise<string[]> {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new ScopeError(`Only http(s) URLs can be probed: ${url}`);
    return this.assertHostnameAllowed(u.hostname);
  }

  private async resolveChecked(hostname: string, allowPrivate: boolean): Promise<string[]> {
    const addresses = await resolveAddresses(hostname, this.project.network.ip_family);
    if (!allowPrivate && !isIP(hostname)) {
      const priv = addresses.filter(isPrivateAddress);
      if (priv.length > 0) {
        throw new ScopeError(
          `"${hostname}" resolves to private address(es) ${priv.join(', ')}. Set allow_private: true on its project.yaml entry to probe it.`,
        );
      }
    }
    return addresses;
  }
}

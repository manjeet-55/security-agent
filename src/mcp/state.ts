import type { Advisories } from '../advisories/types.js';
import { loadCheckInstances, type CheckInstance } from '../checks/catalog.js';
import { CHECK_TYPES } from '../checks/registry.js';
import type { NetClient } from '../net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../paths.js';

export interface ServerOptions {
  /** The project directory (the one holding .secagent/). */
  projectDir: string;
  now?: () => Date;
  /** Injected network and advisory sources (tests); the scan uses the live ones otherwise. */
  net?: NetClient;
  advisories?: Advisories;
  checksDir?: string;
}

/** What the tools share: the options and whether a scan is running (two at once would race on the findings file). */
export class ServerState {
  scanning = false;
  private checks: Promise<CheckInstance[]> | undefined;

  constructor(readonly opts: ServerOptions) {}

  get dir(): string {
    return this.opts.projectDir;
  }

  /** The check catalog, loaded once per server. */
  instances(): Promise<CheckInstance[]> {
    this.checks ??= loadCheckInstances(this.opts.checksDir ?? GLOBAL_CHECKS_DIR, CHECK_TYPES);
    return this.checks;
  }

  now(): Date {
    return this.opts.now ? this.opts.now() : new Date();
  }
}

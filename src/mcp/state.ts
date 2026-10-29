import type { Advisories } from '../advisories/types.js';
import type { NetClient } from '../net/scoped.js';

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

  constructor(readonly opts: ServerOptions) {}

  get dir(): string {
    return this.opts.projectDir;
  }

  now(): Date {
    return this.opts.now ? this.opts.now() : new Date();
  }
}

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvVuln {
  id: string;
  upstream?: string[];
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { ecosystem: string; name: string };
    ranges?: Array<{ type: string; events: OsvEvent[] }>;
  }>;
}

export interface UbuntuCveStatus {
  release_codename: string;
  status: string;
  description: string;
  pocket?: string | null;
}

export interface UbuntuCve {
  id: string;
  priority?: string;
  packages: Array<{ name: string; statuses: UbuntuCveStatus[] }>;
}

export interface PackageQuery {
  name: string;
  version: string;
}

export interface OsvSource {
  /** Names (from `queries`) that have at least one OSV advisory affecting the given version. */
  affected(ecosystem: string, queries: readonly PackageQuery[]): Promise<Set<string>>;
  vulnsFor(ecosystem: string, query: PackageQuery): Promise<OsvVuln[]>;
  vuln(id: string): Promise<OsvVuln | null>;
}

export interface UbuntuSource {
  cve(id: string): Promise<UbuntuCve | null>;
}

export interface KevSource {
  catalog(): Promise<Set<string>>;
}

export interface Freshness {
  /** The oldest fetch time of any advisory data read, the CISA KEV catalog included. */
  as_of: string;
  /**
   * True when any OSV or Ubuntu data read came from a cached copy because its source was unreachable. The KEV catalog is
   * reported through `as_of` only: it never changes a version comparison, so it does not make a result stale.
   */
  stale: boolean;
}

export interface Advisories {
  osv: OsvSource;
  ubuntu: UbuntuSource;
  kev: KevSource;
  /**
   * Runs `fn` and reports the freshness (oldest `as_of`, OR of `stale`) of exactly the advisory data read inside its async
   * scope, KEV included, on any cache. Concurrent calls are isolated from each other. `freshness` is `undefined` when
   * nothing was read or the source cannot tell; callers must treat that as unknown freshness, never as fresh: a check does
   * not pass and a verdict does not dismiss a finding on it.
   */
  track<T>(fn: () => Promise<T>): Promise<{ value: T; freshness: Freshness | undefined }>;
}

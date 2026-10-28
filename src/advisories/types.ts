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

export interface Advisories {
  osv: OsvSource;
  ubuntu: UbuntuSource;
  kev: KevSource;
}

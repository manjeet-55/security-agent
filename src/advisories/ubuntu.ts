import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { UbuntuCve, UbuntuCveStatus, UbuntuSource } from './types.js';

export class UbuntuCveClient implements UbuntuSource {
  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  async cve(id: string): Promise<UbuntuCve | null> {
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new Error(`Not a CVE id: ${id}`);
    const { value } = await this.cache.getOrFetch('ubuntu', id, TTL.ubuntu, async () => {
      const json = (await this.fetchJson(`https://ubuntu.com/security/cves/${id}.json`)).json as {
        id?: string;
        priority?: string;
        packages?: Array<{ name: string; statuses?: UbuntuCveStatus[] }>;
      } | null;
      if (!json) return null;
      return {
        id: json.id ?? id,
        ...(json.priority ? { priority: json.priority } : {}),
        packages: (json.packages ?? []).map((p) => ({
          name: p.name,
          statuses: (p.statuses ?? []).map((s) => ({
            release_codename: s.release_codename,
            status: s.status,
            description: s.description ?? '',
            pocket: s.pocket ?? null,
          })),
        })),
      };
    });
    return value;
  }
}

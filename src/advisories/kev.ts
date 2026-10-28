import { TTL, type AdvisoryCache } from "./cache.js";
import type { FetchJson } from "./fetch.js";
import type { KevSource } from "./types.js";

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export class KevClient implements KevSource {
  private loaded: Promise<Set<string>> | undefined;

  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  catalog(): Promise<Set<string>> {
    this.loaded ??= this.cache
      .getOrFetch("kev", KEV_URL, TTL.kev, async () => {
        const res = await this.fetchJson(KEV_URL);
        if (res.status === 404) throw new Error("KEV catalog returned 404");
        const json = res.json as {
          vulnerabilities?: Array<{ cveID?: unknown }>;
        } | null;
        if (
          json === null ||
          typeof json !== "object" ||
          !Array.isArray(json.vulnerabilities)
        ) {
          throw new Error("KEV catalog is malformed: no vulnerabilities array");
        }
        return json.vulnerabilities
          .map((v) => v.cveID)
          .filter((id): id is string => typeof id === "string");
      })
      .then(
        (c) => new Set(c.value),
        (e: unknown) => {
          this.loaded = undefined;
          throw e;
        },
      );
    return this.loaded;
  }
}

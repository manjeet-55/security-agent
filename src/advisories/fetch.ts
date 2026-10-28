import https from 'node:https';
import { USER_AGENT } from '../net/http.js';

export const ADVISORY_HOSTS: ReadonlySet<string> = new Set(['api.osv.dev', 'ubuntu.com', 'www.cisa.gov']);

export interface JsonResponse {
  status: number;
  /** Parsed body, or null for 404. */
  json: unknown;
}

export type FetchJson = (url: string, init?: { method?: 'GET' | 'POST'; body?: unknown }) => Promise<JsonResponse>;

/** HTTPS JSON fetch restricted to allowlisted advisory hosts. Verifies certificates, follows no redirects, enforces an idle timeout, a total deadline and a size cap. */
export function createFetchJson(
  opts: { timeoutMs?: number; totalTimeoutMs?: number; maxBytes?: number; allowHosts?: ReadonlySet<string> } = {},
): FetchJson {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const totalTimeoutMs = opts.totalTimeoutMs ?? 30_000;
  const maxBytes = opts.maxBytes ?? 8 * 1024 * 1024;
  const allow = opts.allowHosts ?? ADVISORY_HOSTS;
  return (url, init = {}) =>
    new Promise<JsonResponse>((resolve, reject) => {
      const u = new URL(url);
      if (u.protocol !== 'https:' || !allow.has(u.hostname)) {
        reject(new Error(`${u.hostname} is not an allowlisted advisory source`));
        return;
      }
      const body = init.body === undefined ? undefined : JSON.stringify(init.body);
      const req = https.request(
        u,
        {
          method: init.method ?? 'GET',
          timeout: timeoutMs,
          rejectUnauthorized: true,
          headers: {
            accept: 'application/json',
            'user-agent': USER_AGENT,
            ...(body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) {
              req.destroy(new Error(`response from ${u.hostname} exceeds ${maxBytes} bytes`));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const status = res.statusCode ?? 0;
            if (status === 404) return resolve({ status, json: null });
            if (status < 200 || status >= 300) return reject(new Error(`${u.hostname} answered HTTP ${status}`));
            try {
              resolve({ status, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
            } catch (e) {
              reject(new Error(`invalid JSON from ${u.hostname}: ${(e as Error).message}`));
            }
          });
          res.on('error', reject);
        },
      );
      const deadline = setTimeout(
        () => req.destroy(new Error(`${u.hostname} did not finish answering within ${totalTimeoutMs}ms`)),
        totalTimeoutMs,
      );
      req.on('close', () => clearTimeout(deadline));
      req.on('timeout', () => req.destroy(new Error(`${u.hostname} did not answer within ${timeoutMs}ms`)));
      req.on('error', reject);
      req.end(body);
    });
}

import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';

const PAGE = '<!doctype html><html><head><title>Demo shop</title></head><body><h1>Demo shop</h1><p>A deliberately weak site for secagent demos.</p></body></html>';

/**
 * A local web server with deliberate weaknesses, for demos: no security headers, a version in the Server header, X-Powered-By, a
 * cookie without flags, a CORS policy that reflects any origin with credentials, and a readable .env and .git/HEAD. It listens on 127.0.0.1 only.
 */
export function startDemoServer(port = 8080): Promise<{ url: string; close(): Promise<void> }> {
  const server = http.createServer((req, res) => {
    const url = (req.url ?? '/').split('?')[0];
    res.setHeader('Server', 'nginx/1.18.0 (Ubuntu)');
    res.setHeader('X-Powered-By', 'Express 4.17.1');
    // A common mistake: echo back whatever Origin asked, with credentials.
    if (req.headers.origin) {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (url === '/') {
      res.setHeader('Set-Cookie', 'session=demo-session-value; Path=/');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(PAGE);
    } else if (url === '/.env') {
      res.setHeader('Content-Type', 'text/plain');
      res.end('API_KEY=demo-value\nDB_PASSWORD=demo-value\n');
    } else if (url === '/.git/HEAD') {
      res.setHeader('Content-Type', 'text/plain');
      res.end('ref: refs/heads/main\n');
    } else {
      res.statusCode = 404;
      res.end('not found');
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const { port: bound } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${bound}`,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
            server.closeAllConnections();
          }),
      });
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startDemoServer(process.argv[2] ? Number(process.argv[2]) : 8080).then(
    (s) => console.log(`Demo server on ${s.url} (Ctrl+C to stop)\nIn secagent, enter this address and answer yes to the internal-address question.`),
    (e: unknown) => {
      console.error(e instanceof Error ? e.message : e);
      process.exitCode = 1;
    },
  );
}

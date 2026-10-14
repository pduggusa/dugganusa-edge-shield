/**
 * Test the origin edge secret (2.14.0).
 *
 * Loads the WHOLE worker and drives its fetch handler with a mocked fetch() that
 * records the headers of every request leaving the worker. The cases that matter:
 *   - the secret is attached ONLY to forwards to our own origin (ORIGIN_EDGE_HOSTS),
 *   - never to a third-party origin (www/apex = Wix), never to the DugganUSA API calls
 *     the worker makes itself (feed pulls, honeypot/feed-hit reports),
 *   - never at all when ORIGIN_EDGE_SECRET is unset (and a warning is logged once),
 *   - a client-supplied x-dugganusa-edge is stripped on every forward.
 *
 *   node test-origin-edge.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const realLog = console.log;
let pass = 0, fail = 0;
const check = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  const ok = g === w;
  ok ? pass++ : fail++;
  realLog(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${g}, want ${w})`}`);
};

const SECRET = 'edge-test-secret-not-real-0123456789abcdef';
const sent = [];
globalThis.fetch = async (input, init) => {
  const req = input instanceof Request ? input : new Request(input, init);
  sent.push({ url: req.url, edge: req.headers.get('x-dugganusa-edge') });
  if (req.url.includes('/stix-feed/ips.csv')) return new Response('ip,confidence\n');
  if (req.url.includes('/stix-feed/domains.csv')) return new Response('domain,confidence\n');
  return new Response('origin ok', { status: 200, headers: { 'content-type': 'text/plain' } });
};
const store = new Map();
globalThis.caches = { default: {
  match: async (k) => { const v = store.get(typeof k === 'string' ? k : k.url); return v ? v.clone() : undefined; },
  put: async (k, v) => { store.set(typeof k === 'string' ? k : k.url, v.clone()); },
} };
const logs = [];
console.log = (...a) => { logs.push(a.join(' ')); };

const worker = (await import('data:text/javascript,' + encodeURIComponent(src))).default;

const run = async (env, { host, path = '/api/v1/search/stats', headers = {} }) => {
  sent.length = 0;
  store.clear();
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const req = new Request(`https://${host}${path}`, {
    headers: { 'user-agent': 'Mozilla/5.0 Chrome/125.0', 'cf-connecting-ip': '192.0.2.10', ...headers },
  });
  const res = await worker.fetch(req, env, ctx);
  await Promise.all(waits);
  // The worker's OWN calls to the DugganUSA API (feed pulls, honeypot / feed-hit reports) also go
  // to analytics.dugganusa.com, so they are told apart by path, not host.
  const isApi = (u) => /\/api\/v1\/(stix-feed\/|feed\/hit|threat-intel\/honeypot)/.test(new URL(u).pathname);
  return { res, out: sent.filter(s => new URL(s.url).hostname === host && !isApi(s.url)), api: sent.filter(s => isApi(s.url)) };
};

const env = { ORIGIN_EDGE_SECRET: SECRET, DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'false' };

// 1. Our origin gets the secret.
let r = await run(env, { host: 'analytics.dugganusa.com' });
check('analytics origin fetch carries the secret', r.out.map(s => s.edge), [SECRET]);
check('worker-originated API calls never carry it', r.api.every(s => s.edge === null), true);

// 2. A forged client header is replaced, not forwarded.
r = await run(env, { host: 'analytics.dugganusa.com', headers: { 'x-dugganusa-edge': 'forged' } });
check('client-supplied header replaced by the real secret on our origin', r.out.map(s => s.edge), [SECRET]);

// 3. Third-party origin (Wix www / customer site): never sent, client copy stripped.
r = await run(env, { host: 'www.dugganusa.com', path: '/about' });
check('www (Wix origin) never gets the secret', r.out.map(s => s.edge), [null]);
r = await run(env, { host: 'www.example.com', path: '/', headers: { 'x-dugganusa-edge': 'forged' } });
check('customer origin: client copy stripped, secret not sent', r.out.map(s => s.edge), [null]);

// 4. Beacon pass-through (embed.js) is an origin fetch too.
r = await run(env, { host: 'analytics.dugganusa.com', path: '/api/v1/blog-tracking/embed.js' });
check('embed.js pass-through carries the secret', r.out.map(s => s.edge), [SECRET]);
r = await run(env, { host: 'analytics.dugganusa.com', path: '/api/v1/blog-tracking/track' });
check('track beacon carries the secret', r.out.map(s => s.edge), [SECRET]);

// 5. Secret unset: nothing sent, client copy still stripped, warning logged once.
logs.length = 0;
const noSecret = { DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'false' };
r = await run(noSecret, { host: 'analytics.dugganusa.com', headers: { 'x-dugganusa-edge': 'forged' } });
check('secret unset: header absent on our origin (client copy stripped)', r.out.map(s => s.edge), [null]);
r = await run(noSecret, { host: 'analytics.dugganusa.com', path: '/api/v1/blog-tracking/embed.js' });
check('secret unset: embed.js sends nothing', r.out.map(s => s.edge), [null]);
check('secret unset: config warning logged exactly once', logs.filter(l => l.includes('ORIGIN_EDGE_SECRET unset')).length, 1);
check('the warning never contains a secret value', logs.some(l => l.includes(SECRET)), false);

// 6. ORIGIN_EDGE_HOSTS override; empty string falls back to the default.
r = await run({ ...env, ORIGIN_EDGE_HOSTS: 'api.example.net' }, { host: 'analytics.dugganusa.com' });
check('host not in ORIGIN_EDGE_HOSTS gets nothing', r.out.map(s => s.edge), [null]);
r = await run({ ...env, ORIGIN_EDGE_HOSTS: ' API.example.net ' }, { host: 'api.example.net' });
check('listed host (case/space-insensitive) gets the secret', r.out.map(s => s.edge), [SECRET]);
r = await run({ ...env, ORIGIN_EDGE_HOSTS: '' }, { host: 'analytics.dugganusa.com' });
check('empty ORIGIN_EDGE_HOSTS = default list', r.out.map(s => s.edge), [SECRET]);

// 7. Canary paths answer at the edge: no origin fetch, so no secret anywhere.
r = await run({ ...env, HONEYPOTS_ENABLED: 'true' }, { host: 'analytics.dugganusa.com', path: '/.env' });
check('canary hit never reaches origin', r.out.length, 0);
check('canary report to the API does not carry the secret', r.api.length > 0 && r.api.every(s => s.edge === null), true);

console.log = realLog;
realLog(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

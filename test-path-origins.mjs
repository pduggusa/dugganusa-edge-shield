/**
 * Test PATH_ORIGINS (2.19.0).
 *
 * Loads the WHOLE worker and drives its fetch handler with a mocked fetch() that records
 * every request leaving the worker. The cases that matter:
 *   - unset: nothing changes (apex /post/x still goes to the original host),
 *   - a mapping re-aims ONLY matching host+prefix paths, keeps the rest of the path + query,
 *     and attaches the origin edge secret because the target is our origin,
 *   - a target outside ORIGIN_EDGE_HOSTS is ignored (no open proxy) with a config warning,
 *   - the shield still runs first: a scanner UA gets 418 and nothing is fetched,
 *   - non-GET methods are never re-aimed, and the bare prefix itself is not re-aimed.
 *
 *   node test-path-origins.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const realLog = console.log;
let pass = 0, fail = 0;
const check = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  const ok = g === w; ok ? pass++ : fail++;
  realLog(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${g}, want ${w})`}`);
};
const SECRET = 'edge-test-secret-not-real-0123456789abcdef';
const sent = [];
globalThis.fetch = async (input, init) => {
  const req = input instanceof Request ? input : new Request(input, init);
  sent.push({ url: req.url, method: req.method, edge: req.headers.get('x-dugganusa-edge') });
  if (req.url.includes('/stix-feed/ips.csv')) return new Response('ip,confidence\n');
  if (req.url.includes('/stix-feed/domains.csv')) return new Response('domain,confidence\n');
  return new Response('origin ok', { status: 200, headers: { 'content-type': 'text/plain' } }); // text/plain: HTML would hit HTMLRewriter (Workers-only)
};
const store = new Map();
globalThis.caches = { default: {
  match: async (k) => { const v = store.get(typeof k === 'string' ? k : k.url); return v ? v.clone() : undefined; },
  put: async (k, v) => { store.set(typeof k === 'string' ? k : k.url, v.clone()); },
} };
const logs = [];
console.log = (...a) => { logs.push(a.join(' ')); };
const worker = (await import('data:text/javascript,' + encodeURIComponent(src))).default;
const isApi = (u) => /\/api\/v1\/(stix-feed\/|feed\/hit|feed\/observation|threat-intel\/honeypot)/.test(new URL(u).pathname);
const run = async (env, { host, path, method = 'GET', ua = 'Mozilla/5.0 Chrome/125.0' }) => {
  sent.length = 0; store.clear();
  const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
  const res = await worker.fetch(new Request(`https://${host}${path}`, { method, headers: { 'user-agent': ua, 'cf-connecting-ip': '192.0.2.10' } }), env, ctx);
  await Promise.all(waits);
  return { res, out: sent.filter(s => !isApi(s.url)) };
};
const base = { ORIGIN_EDGE_SECRET: SECRET, DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'false', HARVESTED_OBSERVE: 'false' };
const MAP = 'dugganusa.com/post/=>https://analytics.dugganusa.com/render/post/';

let r = await run(base, { host: 'dugganusa.com', path: '/post/hello' });
check('unset: apex /post/x goes to the original host', r.out.map(s => s.url), ['https://dugganusa.com/post/hello']);

r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'dugganusa.com', path: '/post/hello-world?utm_source=x' });
check('mapped: re-aimed to the renderer, path rest + query kept', r.out.map(s => s.url), ['https://analytics.dugganusa.com/render/post/hello-world?utm_source=x']);
check('mapped: origin edge secret attached (target is our origin)', r.out.map(s => s.edge), [SECRET]);

r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'dugganusa.com', path: '/about' });
check('mapped: other paths untouched', r.out.map(s => s.url), ['https://dugganusa.com/about']);
r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'www.dugganusa.com', path: '/post/hello' });
check('mapped: other hosts untouched', r.out.map(s => s.url), ['https://www.dugganusa.com/post/hello']);
r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'dugganusa.com', path: '/post/' });
check('mapped: the bare prefix is not re-aimed', r.out.map(s => s.url), ['https://dugganusa.com/post/']);
r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'dugganusa.com', path: '/post/hello', method: 'POST' });
check('mapped: POST is never re-aimed', r.out.map(s => s.url), ['https://dugganusa.com/post/hello']);

r = await run({ ...base, PATH_ORIGINS: MAP }, { host: 'dugganusa.com', path: '/post/hello', ua: 'leakix/1.0' });
check('shield runs first: scanner gets 418', r.res.status, 418);
check('shield runs first: nothing fetched from origin', r.out.length, 0);

logs.length = 0;
r = await run({ ...base, PATH_ORIGINS: 'dugganusa.com/post/=>https://evil.example/' }, { host: 'dugganusa.com', path: '/post/hello' });
check('target outside ORIGIN_EDGE_HOSTS ignored (no open proxy)', r.out.map(s => s.url), ['https://dugganusa.com/post/hello']);
check('ignored entry logs a config warning', logs.some(l => l.includes('PATH_ORIGINS entry ignored')), true);
r = await run({ ...base, PATH_ORIGINS: 'dugganusa.com/post/=>http://analytics.dugganusa.com/render/post/' }, { host: 'dugganusa.com', path: '/post/hello' });
check('plain http target ignored', r.out.map(s => s.url), ['https://dugganusa.com/post/hello']);

realLog(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

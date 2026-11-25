/**
 * Re-review of 17995ff (fixes for the f5864ec trap review). FINDING tests assert the SAFE behavior (FAIL = finding);
 * TRIED-SAFE tests are labeled and expected to pass. Same harness as test-harvested-observe.mjs.
 *   node test-trap-rereview.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
let pass = 0, fail = 0;
const t = (name, fn) => { try { fn(); pass++; console.log('  ok', name); } catch (e) { fail++; console.log('  FAIL', name, '-', e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m || ''} expected ${JSON.stringify(b)} got ${JSON.stringify(a)}`); };
const unit = () => new Function([
  "const APPLIANCE_OWN_ZONES = ['dugganusa.com', 'aipmsec.com'];",
  slice('function safeDecode(', 'function getCanary('),
  "const HARVESTED_PATHS_GENERATED_AT = 'b'; const HARVESTED_PATHS = new Map([['/bundled/one.php','CVE-2026-1']]);",
  slice('function cfVerifiedCategory(', 'async function isVerifiedCrawler('),
  slice('function harvestedObserveEnabled(', 'async function postHarvestedObservation('),
  'return { harvestedTrapFirst, trapStatusCounts, trapLooksInduced, trapNetKey };',
].join('\n'))();

console.log('FINDING R3: the global per-isolate budget is still a shared weapon; the per-net map clear() resets every net cap');
{
  const T = unit(); const now = 3e12;
  for (let i = 0; i < 60; i++) T.harvestedTrapFirst(`2001:db8:${(0x100 + i).toString(16)}::1`, '/api/session/properties', now + i); // 60 distinct /48s
  t('R3a: after one actor files from 60 distinct /48s, a different source in the same minute is still filed', () =>
    eq(T.harvestedTrapFirst('45.138.12.32', '/api/session/properties', now + 1000), true, 'ARTEX-style probe dropped:'));
  const U = unit(); let t0 = 4e12;
  let n = 0; for (let i = 0; i < 10; i++) if (U.harvestedTrapFirst(`203.0.113.${i}`, '/p', t0 + i)) n++;
  eq(n, 4, 'precondition: /24 capped at 4');
  // 5100 other nets, paced under the global 60/min budget (~85 minutes), all within the same 24h.
  for (let i = 0; i < 5100; i++) U.harvestedTrapFirst(`2001:db8:${(i >> 8).toString(16)}${(i & 0xff).toString(16).padStart(2, '0')}::1`, '/p', t0 + 1000 + Math.floor(i / 60) * 60001 + (i % 60));
  t('R3b: the capped /24 stays capped for the day after other nets churn the map', () =>
    eq(U.harvestedTrapFirst('203.0.113.200', '/p', t0 + 2 * 3600e3), false, 'per-/24 cap reset by map clear():'));
}

// ---------------- full handler ----------------
const honey = [];
let originStatus = 404;
const list = { generated_at: '2026-11-25T00:00:00Z', paths: Array.from({ length: 120 }, (_, i) => [`/live${i}/x.php`, `CVE-2026-${2000 + i}`]) };
list.paths.push(['/api/session/properties', 'CVE-2026-72898']); list.trap = [['/api/session/properties', 'CVE-2026-72898']];
globalThis.fetch = async (input, init) => {
  const req = input instanceof Request ? input : new Request(input, init);
  const u = new URL(req.url);
  if (u.pathname.endsWith('/feed/observation')) return new Response('{"success":true}');
  if (u.pathname.endsWith('/feed/observation/paths')) return new Response(JSON.stringify(list));
  if (u.pathname.includes('/stix-feed/')) return new Response('ip,confidence\n');
  if (u.pathname.includes('/threat-intel/honeypot')) { honey.push(JSON.parse(await req.text())); return new Response('{}'); }
  if (u.pathname.includes('/feed/hit')) return new Response('{}');
  return new Response(req.method === 'HEAD' || [204, 304].includes(originStatus) ? null : 'x', { status: originStatus, headers: { 'content-type': 'text/plain' } });
};
const store = new Map();
globalThis.caches = { default: { match: async (k) => store.get(k.url)?.clone(), put: async (k, v) => { store.set(k.url, v.clone()); } } };
const realLog = console.log; console.log = () => {};
const worker = (await import('data:text/javascript,' + encodeURIComponent(src + '\n// trap-rereview'))).default;
let n = 0;
const run = async (path, status, { ua = 'python-requests/2.31', headers = {}, env = {}, method = 'GET', cf = null } = {}) => {
  originStatus = status; honey.length = 0; n++;
  const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
  const req = new Request(`https://dugganusa.com${path}`, { method, headers: { 'user-agent': ua, 'cf-connecting-ip': `198.51.${n}.7`, ...headers } });
  if (cf) Object.defineProperty(req, 'cf', { value: cf });
  const res = await worker.fetch(req, { DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'true', ...env }, ctx);
  if (method !== 'HEAD') await res.text();
  await Promise.all(waits);
  return { res, traps: honey.filter((d) => d.source === 'edge-harvested-trap') };
};
await run('/warmup', 404);
// <img> in an HTML email: native mail clients and mail image proxies send no Sec-Fetch-* headers.
const gmailProxy = await run('/api/session/properties', 404, { ua: 'Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)' });
const outlook = await run('/api/session/properties', 404, { ua: 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)' });
const yahoo = await run('/api/session/properties', 404, { ua: 'YahooMailProxy; https://help.yahoo.com/kb/yahoo-mail-proxy-SLN28749.html' });
const appleMail = await run('/api/session/properties', 404, { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)' });
// tried-safe
const s401 = await run('/api/session/properties', 401), s403 = await run('/api/session/properties', 403), s429 = await run('/api/session/properties', 429), s500 = await run('/api/session/properties', 500);
const s410 = await run('/api/session/properties', 410);
const typed = await run('/api/session/properties', 404, { ua: 'Mozilla/5.0 Chrome/131', headers: { 'sec-fetch-site': 'none', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } });
const sameOrigin = await run('/api/session/properties', 404, { headers: { 'sec-fetch-site': 'same-origin' } });
const scanner418 = await run('/api/session/properties', 404, { ua: 'zgrab/0.x' });
const scannerObserve = await run('/api/session/properties', 404, { ua: 'zgrab/0.x', env: { SHIELD_MODE: 'observe' } });
console.log = realLog;

console.log('FINDING R4: induced <img> loads with no Sec-Fetch headers still file (mail image proxies, native mail clients)');
t('R4a: Gmail image proxy (GoogleImageProxy) is not filed', () => eq(gmailProxy.traps.length, 0));
t('R4b: Outlook desktop rendering an HTML email is not filed', () => eq(outlook.traps.length, 0));
t('R4c: Yahoo Mail image proxy is not filed', () => eq(yahoo.traps.length, 0));
t('R4d: Apple Mail (WebKit, no Sec-Fetch, no browser token) is not filed', () => eq(appleMail.traps.length, 0));

console.log('TRIED-SAFE');
t('safe: 401/403/429/500 file nothing; 410 files', () => { eq([s401, s403, s429, s500].map((r) => r.traps.length), [0, 0, 0, 0]); eq(s410.traps.length, 1); });
t('safe: typed navigation (Sec-Fetch-Site: none) files; same-origin is screened (one-header evasion, accepted)', () => { eq(typed.traps.length, 1); eq(sameOrigin.traps.length, 0); });
t('safe: edge scanner 418 files; observe-mode scanner reaching origin 404 files as 404', () => { eq(scanner418.res.status, 418); eq(scanner418.traps.length, 1); eq(scannerObserve.traps.length, 1); });
t('safe: 418 counts only when the edge produced it', () => { const T = unit(); eq(T.trapStatusCounts(418, false), false); eq(T.trapStatusCounts(418, true), true); });
t('safe: net keys', () => { const T = unit(); eq(T.trapNetKey('2001:DB8:aa:bb::1'), '2001:db8:aa::/48'); eq(T.trapNetKey('2001:db8::1'), '2001:db8:0::/48'); eq(T.trapNetKey('203.0.113.9'), '203.0.113.0/24'); });

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

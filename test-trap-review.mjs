/**
 * Independent adversarial review of f5864ec (2.36.0 harvested-path TRAP). Every FINDING test asserts the
 * SAFE behavior, so a FAIL is a finding. TRIED-SAFE tests are labeled and expected to pass.
 * Same harness as test-harvested-observe.mjs: shipped src/worker.js, imported via a data: URL with stubbed
 * fetch/caches; unit cases slice the shipped functions out of the source.
 *
 *   node test-trap-review.mjs
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
  slice('function harvestedObserveEnabled(', 'async function postHarvestedObservation('),
  'return { isPlainIp, trapIpKey, harvestedTrapFirst };',
].join('\n'))();

console.log('FINDING W2: rotating IPv6 inside ONE /48 is filed once per /64, bounded only by the per-isolate minute budget');
{
  const T = unit();
  let filed = 0;
  // One attacker, one /48 (65,536 /64s), one path, one isolate, one day.
  for (let min = 0; min < 60; min++) for (let i = 0; i < 25; i++) if (T.harvestedTrapFirst(`2001:db8:77:${(min * 25 + i).toString(16)}::1`, '/api/session/properties', 1e12 + min * 60000 + i)) filed++;
  t('W2: one /48 produces at most a handful of trap docs per path per day (observed one hour of a 24h window)', () => {
    if (filed > 4) throw new Error(`${filed} trap docs in ONE HOUR from one /48 on one path in one isolate (x24 per day, x every isolate/colo). Each is a separate iocs doc of type ipv6.`);
  });
}

console.log('FINDING W3: one actor exhausts the shared per-isolate minute budget and suppresses every other filing');
{
  const T = unit();
  const now = 2e12;
  for (let i = 0; i < 20; i++) T.harvestedTrapFirst(`2001:db8:66:${i.toString(16)}::1`, '/api/session/properties', now + i);
  t('W3: a different source probing in the same minute is still filed', () =>
    eq(T.harvestedTrapFirst('45.138.12.32', '/api/session/properties', now + 1000), true, 'ARTEX-style probe dropped by budget:'));
}

console.log('TRIED (unit): isPlainIp accepts some non-IP strings (only reachable if cf-connecting-ip carried them; Cloudflare sets it)');
{
  const T = unit();
  const odd = ['1.2.3.4:80', '::', ':', 'a:b', 'ffff:1.2.3.4.5.6'].filter((v) => T.isPlainIp(v));
  console.log('  note: accepted non-literals ->', JSON.stringify(odd), '(server side honeypot-ingest does not validate value either)');
  t('safe: IPv4-mapped / zone-id / overlong forms', () => {
    eq(T.isPlainIp('fe80::1%eth0'), false); eq(T.isPlainIp('1'.repeat(46) + ':'), false); eq(T.isPlainIp('::ffff:1.2.3.4'), false); // stricter after review: embedded-IPv4 forms are not filed (Cloudflare sends plain IPv4)
  });
}

// ---------------- full handler ----------------
const honey = [];
let originStatus = 404, originHeaders = { 'content-type': 'text/plain' };
const originBody = '<html>wix 404</html>';
const list = { generated_at: '2026-11-25T00:00:00Z', paths: Array.from({ length: 120 }, (_, i) => [`/live${i}/x.php`, `CVE-2026-${2000 + i}`]) };
list.paths.push(['/api/session/properties', 'CVE-2026-72898']);
list.trap = [['/api/session/properties', 'CVE-2026-72898']];
globalThis.fetch = async (input, init) => {
  const req = input instanceof Request ? input : new Request(input, init);
  const u = new URL(req.url);
  if (u.pathname.endsWith('/feed/observation')) return new Response('{"success":true}');
  if (u.pathname.endsWith('/feed/observation/paths')) return new Response(JSON.stringify(list));
  if (u.pathname.includes('/stix-feed/')) return new Response('ip,confidence\n');
  if (u.pathname.includes('/threat-intel/honeypot')) { honey.push(JSON.parse(await req.text())); return new Response('{}'); }
  if (u.pathname.includes('/feed/hit')) return new Response('{}');
  return new Response(req.method === 'HEAD' || [204, 304].includes(originStatus) ? null : originBody, { status: originStatus, headers: originHeaders });
};
const store = new Map();
globalThis.caches = { default: { match: async (k) => store.get(k.url)?.clone(), put: async (k, v) => { store.set(k.url, v.clone()); } } };
const realLog = console.log; console.log = () => {};
const worker = (await import('data:text/javascript,' + encodeURIComponent(src + '\n// trap-review'))).default;
let n = 0;
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const run = async (path, status, { host = 'dugganusa.com', env = {}, ua = CHROME, cf = null, ip = null, headers = {}, method = 'GET', oh = null } = {}) => {
  originStatus = status; originHeaders = oh || { 'content-type': 'text/plain' }; honey.length = 0; n++;
  const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
  const req = new Request(`https://${host}${path}`, { method, headers: { 'user-agent': ua, 'cf-connecting-ip': ip ?? `198.51.${n}.7`, ...headers } });
  if (cf) Object.defineProperty(req, 'cf', { value: cf });
  const res = await worker.fetch(req, { DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'true', ...env }, ctx);
  const body = method === 'HEAD' ? '' : await res.text();
  await Promise.all(waits);
  return { res, body, hdrs: [...res.headers].sort(), traps: honey.filter((d) => d.source === 'edge-harvested-trap') };
};
await run('/warmup', 404);

// A victim's browser renders <img src="https://dugganusa.com/api/session/properties"> on an attacker page / in an email.
const img = await run('/api/session/properties', 404, { headers: {
  'sec-fetch-dest': 'image', 'sec-fetch-mode': 'no-cors', 'sec-fetch-site': 'cross-site', referer: 'https://attacker.example/page', accept: 'image/avif,image/webp,*/*' } });
// A cross-origin fetch() with a custom header: the browser sends a CORS preflight first.
const preflight = await run('/api/session/properties', 404, { method: 'OPTIONS', headers: {
  origin: 'https://attacker.example', 'access-control-request-method': 'GET', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site' } });
// The link pasted in Slack: Cloudflare VERIFIED the previewer (verifiedBotCategory), but its UA is not in
// CRAWLER_UA_TO_DOMAINS, so isVerifiedCrawler() returns false and the trap files Slack's egress address.
const slack = await run('/api/session/properties', 404, { ua: 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)', cf: { verifiedBotCategory: 'Page Preview', asn: 16509 } });
const claudeUser = await run('/api/session/properties', 404, { ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)', cf: { verifiedBotCategory: 'AI Assistant' } });
// tried-safe probes
const redirect = await run('/api/session/properties', 302, { oh: { location: '/x' } });
const notMod = await run('/api/session/properties', 304);
const head404 = await run('/api/session/properties', 404, { method: 'HEAD' });
const onA = await run('/api/session/properties', 404, { ip: '192.0.2.200' });
const offA = await run('/api/session/properties', 404, { ip: '192.0.2.201', env: { HARVESTED_TRAP: 'false' } });
const scanner = await run('/api/session/properties', 404, { ua: 'zgrab/0.x', ip: '192.0.2.202' });
console.log = realLog;

console.log('FINDING W1: induced requests are filed (the record then reads "suspicious / block" in enrichment, see analytics A1)');
t('W1a: a cross-site <img> subresource load (Sec-Fetch-Dest: image) is not filed', () => eq(img.traps.length, 0, `filed ${JSON.stringify(img.traps.map((d) => d.value))}:`));
t('W1b: a CORS preflight (OPTIONS) is not filed', () => eq(preflight.traps.length, 0, `filed ${preflight.traps.length} (status ${preflight.res.status}):`));
t('W1c: a Cloudflare-verified link previewer (Slackbot, cf.verifiedBotCategory set) is not filed', () => eq(slack.traps.length, 0, `filed ${JSON.stringify(slack.traps.map((d) => d.honeypot_meta.cf_verified_bot_category))}:`));
t('W1d: a Cloudflare-verified AI assistant fetch (Claude-User) is not filed', () => eq(claudeUser.traps.length, 0, `filed ${claudeUser.traps.length}:`));

console.log('TRIED-SAFE (full handler)');
t('safe: 302 and 304 file nothing', () => { eq(redirect.traps.length, 0); eq(notMod.traps.length, 0); eq(redirect.res.status, 302); });
t('safe (by design): HEAD 404 files (a probe), body empty', () => eq(head404.traps.length, 1));
t('safe: trap on/off does not change status, headers or body bytes', () => { eq(onA.res.status, offA.res.status); eq(onA.body, offA.body); eq(onA.hdrs, offA.hdrs); eq(onA.traps.length, 1); eq(offA.traps.length, 0); });
t('safe: posted doc has a Meili-safe id and no query string', () => { for (const d of [...onA.traps, ...img.traps]) if (!/^[a-zA-Z0-9_-]+$/.test(d.id)) throw new Error(d.id); });
t('note: a scanner 418 on a trap path files (scanner, acceptable)', () => eq(scanner.traps.length, scanner.res.status >= 400 ? 1 : 0));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

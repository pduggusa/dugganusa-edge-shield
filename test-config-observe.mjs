/**
 * Test the [vars] policy config (2.5.0) and the observe-mode path.
 *
 * Part 1 extracts loadConfig() from src/worker.js, same as the other tests, so the
 * test cannot drift from what runs. Part 2 loads the WHOLE worker and drives its
 * fetch handler with a mocked fetch(), because observe mode is a property of the
 * handler, not of any one function. Part 3 adds a mocked data-center cache to prove
 * the feed is pulled once per data center and keyed per configuration.
 *
 * The cases that matter most: absent vars must reproduce pre-2.5.0 behavior, a
 * typo must never loosen the posture, and observe mode must NOT block while still
 * logging and reporting what it would have blocked.
 *
 *   node test-config-observe.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};

const realLog = console.log;
let pass = 0, fail = 0;
const check = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  const ok = g === w;
  ok ? pass++ : fail++;
  realLog(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${g}, want ${w})`}`);
};

// ---------------------------------------------------------------------------
// Part 1: config parsing
// ---------------------------------------------------------------------------
const cfgCode = slice('const DEFAULT_CONFIG', 'function logObserved');
const cfgMod = await import('data:text/javascript,' + encodeURIComponent(
  cfgCode + '\nexport { loadConfig, isSensorHost, DEFAULT_CONFIG };'));
const { loadConfig, isSensorHost } = cfgMod;

const d = loadConfig({});
check('absent vars: mode block', d.mode, 'block');
check('absent vars: observe false', d.observe, false);
check('absent vars: IOC blocking on', d.iocBlocking, true);
check('absent vars: min_confidence 80', d.iocMinConfidence, 80);
check('absent vars: feed window 7 days', d.iocFeedDays, 7);
check('absent vars: refresh 60 min', d.iocRefreshMinutes, 60);
check('absent vars: scanner 418 on', d.scanner418, true);
check('absent vars: RL_ANON 100', d.rlAnon, 100);
check('absent vars: RL_AUTH 500', d.rlAuth, 500);
check('absent vars: feed-hit reporting on (pre-2.5.0 behavior)', d.feedHitReporting, true);
check('absent vars: schema hosts are the pre-2.5.0 list', d.schemaInjectHosts, ['www.dugganusa.com', 'dugganusa.com', 'aipmsec.com']);
check('absent vars: no sensor hosts', d.sensorHosts, []);
check('absent vars: no warnings', d.warnings, []);
check('undefined env does not throw', loadConfig(undefined).mode, 'block');

const c = loadConfig({
  SHIELD_MODE: 'Observe', IOC_BLOCKING: 'false', IOC_MIN_CONFIDENCE: '30', IOC_FEED_DAYS: '14',
  IOC_REFRESH_MINUTES: '30', SCANNER_418: 'off', RL_ANON: '0', RL_AUTH: 1000, FEED_HIT_REPORTING: 'no',
  SCHEMA_INJECT_HOSTS: '', SENSOR_HOSTS: 'Sensor.Example.com, *.lab.example.com',
});
check('SHIELD_MODE is case-insensitive', c.mode, 'observe');
check('observe flag set', c.observe, true);
check('IOC_BLOCKING "false"', c.iocBlocking, false);
check('IOC_MIN_CONFIDENCE "30"', c.iocMinConfidence, 30);
check('IOC_FEED_DAYS "14"', c.iocFeedDays, 14);
check('IOC_REFRESH_MINUTES "30"', c.iocRefreshMinutes, 30);
check('SCANNER_418 "off"', c.scanner418, false);
check('RL_ANON "0" disables (0)', c.rlAnon, 0);
check('RL_AUTH as a TOML number', c.rlAuth, 1000);
check('FEED_HIT_REPORTING "no"', c.feedHitReporting, false);
check('SCHEMA_INJECT_HOSTS "" means none', c.schemaInjectHosts, []);
check('SENSOR_HOSTS parsed, lowercased', c.sensorHosts, ['sensor.example.com', '*.lab.example.com']);
check('log-only is an alias for observe', loadConfig({ SHIELD_MODE: 'log-only' }).mode, 'observe');

// A typo must fall back to the default, never to something looser, and must warn.
const bad = loadConfig({ SHIELD_MODE: 'obsrve', IOC_MIN_CONFIDENCE: '800', IOC_FEED_DAYS: 'seven', SCANNER_418: 'maybe', RL_ANON: '-5' });
check('typo SHIELD_MODE falls back to block', bad.mode, 'block');
check('out-of-range min_confidence falls back to 80', bad.iocMinConfidence, 80);
check('non-numeric feed days falls back to 7', bad.iocFeedDays, 7);
check('non-boolean SCANNER_418 falls back to on', bad.scanner418, true);
check('negative RL_ANON falls back to 100', bad.rlAnon, 100);
check('each bad var produces a warning', bad.warnings.length, 5);

check('sensor: exact host', isSensorHost('sensor.example.com', c), true);
check('sensor: exact host, mixed case', isSensorHost('SENSOR.example.com', c), true);
check('sensor: wildcard subdomain', isSensorHost('box1.lab.example.com', c), true);
check('sensor: wildcard does not match the bare apex', isSensorHost('lab.example.com', c), false);
check('sensor: lookalike suffix does not match', isSensorHost('evil-lab.example.com', c), false);
check('sensor: product host is not a sensor', isSensorHost('www.example.com', c), false);

// ---------------------------------------------------------------------------
// Part 2: the fetch handler, observe vs block
// ---------------------------------------------------------------------------
const BAD_IP = '203.0.113.66';      // on the mocked feed
const CIDR_IP = '198.51.100.23';    // inside a mocked /24
const fetchLog = [];
const feedHits = [];
globalThis.fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input.url;
  fetchLog.push(url);
  if (url.includes('/stix-feed/ips.csv')) return new Response(`ip,confidence\n${BAD_IP},90\n198.51.100.0/24,90\n`);
  if (url.includes('/stix-feed/domains.csv')) return new Response('domain,confidence\n');
  if (url.endsWith('/feed/hit')) { feedHits.push(JSON.parse(init.body)); return new Response('{}'); }
  return new Response('origin ok', { status: 200, headers: { 'content-type': 'text/plain' } });
};
const logs = [];
console.log = (...a) => { logs.push(a.join(' ')); };

const worker = (await import('data:text/javascript,' + encodeURIComponent(src))).default;

const run = async (env, { host = 'www.example.com', path = '/', ua = 'Mozilla/5.0 Chrome/125.0', ip = '192.0.2.10', headers = {} } = {}) => {
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const req = new Request(`https://${host}${path}`, {
    headers: { 'user-agent': ua, 'cf-connecting-ip': ip, 'cf-ray': `ray${Math.random().toString(16).slice(2, 10)}`, ...headers },
  });
  const res = await worker.fetch(req, env, ctx);
  await Promise.all(waits);
  return res;
};

const KEY = 'test-key-not-real';
const BLOCK = { DUGGANUSA_API_KEY: KEY, SCHEMA_INJECT_HOSTS: '', IOC_MIN_CONFIDENCE: '75', IOC_FEED_DAYS: '3' };
const OBSERVE = { ...BLOCK, SHIELD_MODE: 'observe' };

// The first request warms the IOC cache (refresh runs in waitUntil).
await run(BLOCK);
const feedUrl = fetchLog.find(u => u.includes('ips.csv')) || '';
check('refresh uses IOC_FEED_DAYS + IOC_MIN_CONFIDENCE', feedUrl.endsWith('ips.csv?days=3&min_confidence=75'), true);

// Block mode: unchanged behavior.
let r = await run(BLOCK, { ip: BAD_IP });
check('block: IOC IP gets 403', r.status, 403);
check('block: feed hit reported as blocked', feedHits.at(-1)?.hits?.[0]?.action, 'blocked');
check('block: feed hit carries the indicator only', Object.keys(feedHits.at(-1)?.hits?.[0] || {}).sort(), ['action', 'count', 'direction', 'event_id', 'indicator', 'ts']);
check('block: customer zone never sent', 'zone' in (feedHits.at(-1) || {}), false);
r = await run(BLOCK, { ip: CIDR_IP });
check('block: CIDR match gets 403', r.status, 403);
r = await run(BLOCK, { ua: 'leakix/1.0', ip: '192.0.2.11' });
check('block: scanner gets 418', r.status, 418);
check('block: 418 carries X-Powered-By', r.headers.get('x-powered-by'), 'DugganUSA Edge Shield');
r = await run(BLOCK, { ip: '192.0.2.12' });
check('block: normal traffic passes 200', r.status, 200);
check('block: normal traffic has no Observed header', r.headers.get('x-dugganusa-observed'), null);

// Observe mode: must NOT block, must log, must report 'observed'.
const hitsBefore = feedHits.length;
logs.length = 0;
r = await run(OBSERVE, { ip: BAD_IP });
check('observe: IOC IP is NOT blocked', r.status, 200);
check('observe: origin body served', await r.text(), 'origin ok');
check('observe: X-DugganUSA-Observed: ioc', r.headers.get('x-dugganusa-observed'), 'ioc');
check('observe: exactly one feed hit sent', feedHits.length - hitsBefore, 1);
check('observe: feed hit action is observed', feedHits.at(-1)?.hits?.[0]?.action, 'observed');
check('observe: feed hit indicator is the IP', feedHits.at(-1)?.hits?.[0]?.indicator, BAD_IP);
check('observe: would-block logged', logs.some(l => l.includes('"shield":"observe"') && l.includes('"would":"ioc-403"') && l.includes(BAD_IP)), true);

logs.length = 0;
r = await run(OBSERVE, { ua: 'leakix/1.0', ip: '192.0.2.13' });
check('observe: scanner is NOT 418', r.status, 200);
check('observe: X-DugganUSA-Observed: scanner', r.headers.get('x-dugganusa-observed'), 'scanner');
check('observe: scanner logged', logs.some(l => l.includes('"would":"scanner-418"')), true);

r = await run(OBSERVE, { ua: 'leakix/1.0', ip: BAD_IP });
check('observe: scanner + IOC both recorded', r.headers.get('x-dugganusa-observed'), 'scanner,ioc');

// Observe-mode rate limit: passes, logs once per window, not per request.
logs.length = 0;
const RL = { ...OBSERVE, RL_ANON: '3' };
for (let i = 0; i < 5; i++) r = await run(RL, { ip: '192.0.2.14' });
check('observe: over-limit request NOT 429', r.status, 200);
check('observe: X-DugganUSA-Observed: rate-limit', r.headers.get('x-dugganusa-observed'), 'rate-limit');
check('observe: rate limit logged once, not per request', logs.filter(l => l.includes('rate-limit-429')).length, 1);
const RLB = { ...BLOCK, RL_ANON: '3' };
for (let i = 0; i < 4; i++) r = await run(RLB, { ip: '192.0.2.15' });
check('block: RL_ANON=3 → 4th request is 429', r.status, 429);
const RL0 = { ...BLOCK, RL_ANON: '0' };
for (let i = 0; i < 150; i++) r = await run(RL0, { ip: '192.0.2.16' });
check('block: RL_ANON=0 disables the anonymous limit', r.status, 200);

// Feed-hit reporting opt-out: still blocks, sends nothing.
const before = feedHits.length;
r = await run({ ...BLOCK, FEED_HIT_REPORTING: 'false' }, { ip: BAD_IP });
check('reporting off: still 403', r.status, 403);
check('reporting off: no feed hit sent', feedHits.length - before, 0);

// Knobs off.
r = await run({ ...BLOCK, IOC_BLOCKING: 'false' }, { ip: BAD_IP });
check('IOC_BLOCKING=false: IOC IP passes', r.status, 200);
r = await run({ ...BLOCK, SCANNER_418: 'false' }, { ua: 'leakix/1.0', ip: '192.0.2.17' });
check('SCANNER_418=false: scanner passes', r.status, 200);

// Sensor hosts: untouched, even for a scanner on an IOC IP probing a canary path.
const SENSOR = { ...BLOCK, SENSOR_HOSTS: 'sensor.example.com' };
r = await run(SENSOR, { host: 'sensor.example.com', ua: 'leakix/1.0', ip: BAD_IP, path: '/.env' });
check('sensor: scanner+IOC+canary all pass to origin', r.status, 200);
check('sensor: origin body, not a decoy', await r.text(), 'origin ok');
check('sensor: no shield header', r.headers.get('x-powered-by'), null);
r = await run(SENSOR, { host: 'www.example.com', ua: 'leakix/1.0', ip: '192.0.2.18' });
check('sensor list does not exempt product hosts', r.status, 418);

// ---------------------------------------------------------------------------
// Part 3: data-center feed cache — one pull per data center, keyed per config
// ---------------------------------------------------------------------------
// A fresh module instance per config (the IOC cache is module state), sharing one
// mocked caches.default the way every isolate in a data center does.
const store = new Map();
globalThis.caches = { default: {
  match: async (req) => { const r = store.get(req.url); return r ? r.clone() : undefined; },
  put: async (req, res) => { store.set(req.url, res.clone()); },
} };
const freshWorker = async (tag) =>
  (await import('data:text/javascript,' + encodeURIComponent(src + `\n// instance ${tag}`))).default;
const originPulls = () => fetchLog.filter(u => u.includes('/stix-feed/ips.csv')).length;

let pulls0 = originPulls();
const w1 = await freshWorker('a');
const ctxs = [];
const fire = (w, env, ip) => {
  const ctx = { waitUntil: (p) => ctxs.push(p) };
  return w.fetch(new Request('https://www.example.com/', { headers: { 'user-agent': 'Mozilla/5.0', 'cf-connecting-ip': ip } }), env, ctx);
};
// Ten concurrent requests in one isolate → one refresh, one origin pull.
await Promise.all(Array.from({ length: 10 }, (_, i) => fire(w1, BLOCK, `192.0.2.${100 + i}`)));
await Promise.all(ctxs.splice(0));
check('10 concurrent requests in one isolate → 1 origin pull', originPulls() - pulls0, 1);
check('cache key carries the configured query', [...store.keys()].includes('https://edge-shield-feed-cache.invalid/ips?days=3&min_confidence=75'), true);
check('cache key is on an unrequestable .invalid host', [...store.keys()].every(k => new URL(k).hostname.endsWith('.invalid')), true);

// A second isolate with the SAME config reads the data-center copy, no origin pull.
pulls0 = originPulls();
const w2 = await freshWorker('b');
await fire(w2, BLOCK, '192.0.2.120'); await Promise.all(ctxs.splice(0));
check('second isolate, same config → 0 origin pulls', originPulls() - pulls0, 0);
r = await fire(w2, BLOCK, BAD_IP); await Promise.all(ctxs.splice(0));
check('second isolate blocks from the cached feed', r.status, 403);

// A DIFFERENT config must not share the entry.
pulls0 = originPulls();
const w3 = await freshWorker('c');
await fire(w3, { ...BLOCK, IOC_MIN_CONFIDENCE: '30' }, '192.0.2.121'); await Promise.all(ctxs.splice(0));
check('different min_confidence → its own origin pull', originPulls() - pulls0, 1);
check('different min_confidence → its own cache key', [...store.keys()].includes('https://edge-shield-feed-cache.invalid/ips?days=3&min_confidence=30'), true);

console.log = realLog;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

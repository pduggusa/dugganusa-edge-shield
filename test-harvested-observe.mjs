/**
 * Test harvested-path OBSERVATION (2.15.0) and its generator.
 *
 * Extracts the shipped code from src/worker.js (same approach as the other tests), so the test
 * cannot drift from what runs. The cases that matter most: observation never changes the
 * response, it is off on a customer's zone by default, and the generator keeps generic,
 * static-asset and filesystem paths out of the list.
 *
 *   node test-harvested-observe.mjs
 */
import { readFileSync } from 'node:fs';
import { buildPaths, isDistinctive, render, splice, BEGIN, END } from './scripts/generate-harvested-paths.mjs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};

let pass = 0, fail = 0;
const t = (name, fn) => { try { fn(); pass++; console.log('  ok', name); } catch (e) { fail++; console.log('  FAIL', name, '-', e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m || ''} expected ${JSON.stringify(b)} got ${JSON.stringify(a)}`); };

// ---- worker functions, from the shipped source (with a small fixed list) ----
const fnSrc = [
  "const APPLIANCE_OWN_ZONES = ['dugganusa.com', 'aipmsec.com'];",
  slice('function safeDecode(', 'function getCanary('),
  "const HARVESTED_PATHS_GENERATED_AT = '2026-10-18T00:00:00Z';",
  "const HARVESTED_PATHS = new Map([['/rest/api/2/serverinfo','CVE-2026-21589'],['/dana-na/auth/url_default/welcome.cgi','CVE-2025-0282,CVE-2025-22457']]);",
  slice('function harvestedObserveEnabled(', 'async function postHarvestedObservation('),
  'return { harvestedObserveEnabled, getHarvestedMatch, sourceNet, harvestedFirstInWindow };',
].join('\n');
const W = new Function(fnSrc)();

console.log('worker');
t('exact path matches, CVEs returned', () => eq(W.getHarvestedMatch('/rest/api/2/serverinfo'), { path: '/rest/api/2/serverinfo', cves: 'CVE-2026-21589' }));
t('case-insensitive and trailing slash', () => eq(W.getHarvestedMatch('/REST/api/2/serverInfo/').cves, 'CVE-2026-21589'));
t('percent-encoded path matches its decoded form', () => eq(W.getHarvestedMatch('/dana-na/auth/url_default/welcome%2Ecgi').cves, 'CVE-2025-0282,CVE-2025-22457'));
t('malformed escape does not throw', () => eq(W.getHarvestedMatch('/%E0%A4%A'), null));
t('no prefix matching: a sub-path is not a match', () => eq(W.getHarvestedMatch('/rest/api/2/serverinfo/extra'), null));
t('ordinary pages do not match', () => { for (const p of ['/', '/post/x', '/api/v1/search', '/blog']) eq(W.getHarvestedMatch(p), null, p); });
t('own zones on by default', () => { eq(W.harvestedObserveEnabled({}, 'www.dugganusa.com'), true); eq(W.harvestedObserveEnabled({}, 'aipmsec.com'), true); });
t('customer zone OFF by default', () => eq(W.harvestedObserveEnabled({}, 'www.example.com'), false));
t('flag true opts a customer in; false turns ours off', () => {
  eq(W.harvestedObserveEnabled({ HARVESTED_OBSERVE: 'true' }, 'www.example.com'), true);
  eq(W.harvestedObserveEnabled({ HARVESTED_OBSERVE: 'false' }, 'www.dugganusa.com'), false);
});
t('lookalike zone is not ours', () => eq(W.harvestedObserveEnabled({}, 'dugganusa.com.evil.net'), false));
t('source net: IPv4 /24, IPv6 /48, junk empty', () => {
  eq(W.sourceNet('203.0.113.77'), '203.0.113.0/24');
  eq(W.sourceNet('2001:db8:abcd:12::1'), '2001:db8:abcd::/48');
  eq(W.sourceNet(''), ''); eq(W.sourceNet('::1'), '');
});
t('dedupe: one report per net+path per 10 minutes', () => {
  eq(W.harvestedFirstInWindow('n|/p', 1000), true);
  eq(W.harvestedFirstInWindow('n|/p', 1000 + 60000), false);
  eq(W.harvestedFirstInWindow('n|/p', 1000 + 11 * 60000), true);
});

// ---- live list refresh (2.16.0, set and forget) ----
const mkRefresh = (fetchImpl, cacheStore = new Map()) => new Function('fetch', 'caches', [
  "const DUGGANUSA_API = 'https://api.test/api/v1'; const SHIELD_UA = 'test';",
  "const APPLIANCE_OWN_ZONES = ['dugganusa.com'];",
  slice('function safeDecode(', 'function getCanary('),
  "const HARVESTED_PATHS_GENERATED_AT = 'bundled-1'; const HARVESTED_PATHS = new Map([['/bundled/one.php','CVE-2026-1']]);",
  slice('function harvestedObserveEnabled(', 'async function postHarvestedObservation('),
  'return { parseHarvestedList, refreshHarvested, getHarvestedMatch, active: () => harvestedActive };',
].join('\n'))(fetchImpl, { default: { match: async (k) => cacheStore.get(k.url) ? new Response(cacheStore.get(k.url)) : undefined, put: async (k, r) => cacheStore.set(k.url, await r.text()) } });
const liveBody = (n, gen = '2026-10-19T00:00:00Z') => JSON.stringify({ generated_at: gen, paths: Array.from({ length: n }, (_, i) => [`/live${i}/x.php`, `CVE-2026-${2000 + i}`]) });
t('parse: a valid list of >= 100 entries becomes a Map', () => {
  const R = mkRefresh(async () => { throw new Error('no'); });
  const p = R.parseHarvestedList(liveBody(120)); eq(p.map.size, 120); eq(p.generatedAt, '2026-10-19T00:00:00Z');
});
t('parse: too few, malformed, oversized or hostile entries never replace the list', () => {
  const R = mkRefresh(async () => { throw new Error('no'); });
  eq(R.parseHarvestedList(liveBody(50)), null);
  eq(R.parseHarvestedList('not json'), null);
  eq(R.parseHarvestedList(JSON.stringify({ paths: 'x' })), null);
  eq(R.parseHarvestedList(liveBody(10001)), null);
  const bad = JSON.parse(liveBody(100)); bad.paths.push(['/Upper/X.php', 'CVE-2026-1'], ['/a b', 'CVE-2026-1'], ['/ok/y.php', 'rm -rf'], ['/q?x', 'CVE-2026-1'], [1, 2]);
  eq(R.parseHarvestedList(JSON.stringify(bad)).map.size, 100);
});
await (async () => {
  let calls = 0;
  const R = mkRefresh(async (url) => { calls++; return new Response(liveBody(150), { status: 200 }); });
  t('before any pull, the bundled list is served', () => eq(R.getHarvestedMatch('/bundled/one.php').cves, 'CVE-2026-1'));
  await R.refreshHarvested({ DUGGANUSA_API_KEY: 'k' });
  t('after a pull, the live list replaces the bundled one', () => {
    eq(R.active().source, 'live'); eq(R.getHarvestedMatch('/live7/x.php').cves, 'CVE-2026-2007'); eq(R.getHarvestedMatch('/bundled/one.php'), null);
  });
  t('no second pull inside 6 hours', () => { eq(R.refreshHarvested({ DUGGANUSA_API_KEY: 'k' }), null); eq(calls, 1); });
  const B = mkRefresh(async () => new Response('{}', { status: 503 }));
  await B.refreshHarvested({ DUGGANUSA_API_KEY: 'k' });
  t('a failed pull keeps the bundled list and retries later, not now', () => {
    eq(B.active().source, 'bundled'); eq(B.getHarvestedMatch('/bundled/one.php').cves, 'CVE-2026-1');
    eq(B.refreshHarvested({ DUGGANUSA_API_KEY: 'k' }), null);
  });
  const E = mkRefresh(async () => new Response(liveBody(3), { status: 200 }));
  await E.refreshHarvested({ DUGGANUSA_API_KEY: 'k' });
  t('an emptied list (200 with 3 entries) is refused: no silent blinding', () => eq(E.active().source, 'bundled'));
  const N = mkRefresh(async () => { throw new Error('must not fetch'); });
  t('no key, no pull', () => eq(N.refreshHarvested({}), null));
  const store = new Map(); let fetched = 0;
  const C1 = mkRefresh(async () => { fetched++; return new Response(liveBody(130), { status: 200 }); }, store);
  await C1.refreshHarvested({ DUGGANUSA_API_KEY: 'k' });
  const C2 = mkRefresh(async () => { fetched++; return new Response(liveBody(130), { status: 200 }); }, store);
  await C2.refreshHarvested({ DUGGANUSA_API_KEY: 'k' });
  t('a second isolate in the same data center reads the cache, not the origin', () => { eq(fetched, 1); eq(C2.active().source, 'live'); });
})();

// The hook must never change the response: no return, no Response, only waitUntil.
// Comments are stripped first: this is a property of the CODE, and prose in this window
// (2.21.0 moved the honeypot opt-out note here, which contains the word "return") is not a
// control-flow change. Matching comment text made this fail on a pure documentation move.
const stripComments = s => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const hook = stripComments(slice('// LAYER 0.5: Harvested-path OBSERVATION', '// LAYER 1:'));
t('Layer 0.5 never returns, answers or posts: it only notes the match', () => {
  if (/\breturn\b/.test(hook) || /new Response/.test(hook)) throw new Error('hook returns or answers');
  if (!/ctx\.waitUntil\(pull\)/.test(hook)) throw new Error('refresh not in waitUntil');
  if (/postHarvestedObservation/.test(hook)) throw new Error('hook posts before the response is known');
  if (!/obs\.pending = \{/.test(hook)) throw new Error('hook does not note the match');
});
t('Layer 0.5 runs before scanner and IOC enforcement', () => {
  if (!(src.indexOf('// LAYER 0.5') < src.indexOf('// LAYER 1:') && src.indexOf('// LAYER 1:') < src.indexOf('// LAYER 2:'))) throw new Error('order');
});
t('observation posts carry no full IP field', () => {
  const post = slice('obs.pending = {', '};');
  if (/\bip\b\s*[:,]/.test(post.replace(/src_net/g, ''))) throw new Error('raw ip in the report');
});
t('customer zone report omits host, UA, network and AS org', () => {
  const post = slice('obs.pending = {', '};');
  const always = post.slice(0, post.indexOf('...(own'));
  for (const f of ['host:', 'src_net:', 'ua:', 'as_org:', 'colo:']) if (always.includes(f)) throw new Error(`${f} sent for customer zones`);
  if (!/\.\.\.\(own \? \{ host: hostname, src_net: net/.test(post)) throw new Error('own-zone fields not gated on own');
});
t('the shipped list parses and is non-empty', () => {
  const block = src.slice(src.indexOf(BEGIN), src.indexOf(END));
  const m = new Function(block + ';return HARVESTED_PATHS')();
  if (!(m instanceof Map) || m.size < 100) throw new Error(`list size ${m && m.size}`);
  for (const [p, c] of m) {
    if (p !== p.toLowerCase() || !p.startsWith('/') || p.includes('?')) throw new Error(`bad key ${p}`);
    if (!/^CVE-\d{4}-\d+(,CVE-\d{4}-\d+){0,2}$/.test(c)) throw new Error(`bad cves ${c}`);
  }
});

// ---- generator ----
console.log('generator');
const rule = (cve, value, tags = ['endpoint']) => ({ malware_family: cve, value, tags, harvested_at: '2026-10-06T00:00:00Z' });
t('distinctive vs generic', () => {
  for (const p of ['/rest/api/2/serverinfo', '/scp/login.php', '/_layouts/15/notify.aspx', '/simplesaml/module.php']) eq(isDistinctive(p), true, p);
  for (const p of ['/api/users', '/login', '/admin/config', '/api/v1/auth', '/index.php', '/node']) eq(isDistinctive(p), false, p);
});
t('junk, static, filesystem, glob and own-site paths are dropped', () => {
  const { paths } = buildPaths([rule('CVE-2026-1', '/proc/self/environ | /static/js/app.js | /sw.js | /realms/*/x | /api/v1/search | /post/foo | /etc/passwd | /x.java | /keep/me/please.php')]);
  eq(paths, [['/keep/me/please.php', 'CVE-2026-1']]);
});
t('non-endpoint rules and non-CVE families ignored', () => {
  eq(buildPaths([rule('CVE-2026-2', '/a/b/c.php', ['header-injection']), rule('NOTACVE', '/a/b/d.php')]).paths, []);
});
t('a path shared by more than 3 CVEs is dropped as generic', () => {
  const rules = ['CVE-2026-11', 'CVE-2026-12', 'CVE-2026-13', 'CVE-2026-14'].map(c => rule(c, '/shared/thing.php'));
  eq(buildPaths(rules).paths, []);
  eq(buildPaths(rules.slice(0, 3)).paths, [['/shared/thing.php', 'CVE-2026-11,CVE-2026-12,CVE-2026-13']]);
});
t('query strings and trailing slashes normalized, lowercased', () => {
  eq(buildPaths([rule('CVE-2026-3', '/Foo/Bar.PHP?x=1')]).paths, [['/foo/bar.php', 'CVE-2026-3']]);
});
const realRules = Array.from({ length: 300 }, (_, i) => ({ id: `real${i}`, malware_family: `CVE-2026-${10000 + i}`, tags: ['endpoint'],
  harvested_at: '2026-10-01T00:00:00Z', references: [`https://github.com/researcher${i % 30}/poc${i}`], value: `/product${i}/vuln/endpoint.php` }));
const floodRules = (owners) => Array.from({ length: 3000 }, (_, i) => ({ id: `fake${i}`, malware_family: `CVE-2026-${900000 + i}`, tags: ['endpoint'],
  harvested_at: '2026-12-31T00:00:00Z', references: [`https://github.com/evil${i % owners}/r${i}`],
  value: Array.from({ length: 100 }, (_, j) => `/zz${i}x${j}/aa.php`).join(' | ') }));
t('flood from one GitHub owner: every real path kept, fakes capped at the owner cap', () => {
  const f = buildPaths(realRules.concat(floodRules(1))); const m = new Map(f.paths);
  if (!realRules.every(r => m.has(r.value))) throw new Error('real path evicted');
  eq(f.paths.filter(r => r[0].startsWith('/zz')).length, 200);
});
t('flood from 3000 owners: every real path kept (older harvest wins ties under the cap)', () => {
  const f = buildPaths(realRules.concat(floodRules(3000))); const m = new Map(f.paths);
  if (!realRules.every(r => m.has(r.value))) throw new Error('real path evicted');
  eq(f.paths.length, 4000);
});
t('one owner with many repos cannot buy corroboration rank (owners counted, not repos)', () => {
  const inflate = Array.from({ length: 3000 }, (_, i) => ({ id: `g${i}`, malware_family: `CVE-2026-${800000 + (i % 60)}`, tags: ['endpoint'],
    harvested_at: '2026-12-31T00:00:00Z', references: [`https://github.com/evil/repo${i}`], value: `/yy${i}/bb.php` }));
  const m = new Map(buildPaths(realRules.concat(floodRules(3000), inflate)).paths);
  if (!realRules.every(r => m.has(r.value))) throw new Error('real path evicted');
});
t('paths dropped as shared do not spend a CVE\'s slots', () => {
  const victim = 'CVE-2026-10001';
  const attack = Array.from({ length: 50 }, (_, i) => ({ id: `h${i}`, malware_family: i % 2 ? victim : `CVE-2026-7777${i}`, tags: ['endpoint'],
    harvested_at: '2000-01-01T00:00:00Z', references: [`https://github.com/x${i}/r`], value: Array.from({ length: 25 }, (_, j) => `/shared${j}/c.php`).join(' | ') }));
  const m = new Map(buildPaths(realRules.concat(attack)).paths);
  eq(m.get('/product1/vuln/endpoint.php'), victim);
});
t('one rule contributes at most 25 paths; one CVE at most 10', () => {
  eq(buildPaths([{ id: 'x', malware_family: 'CVE-2026-5', tags: ['endpoint'], value: Array.from({ length: 500 }, (_, j) => `/p${j}/q.php`).join(' | ') }]).paths.length, 10);
});
t('render + splice round-trips and keeps the markers', () => {
  const built = buildPaths([rule('CVE-2026-4', '/one/two.php')]);
  const fake = `a\n${BEGIN}\nold\n${END}\nb`;
  const out = splice(fake, render(built, '2026-10-18T00:00:00Z'));
  if (!out.startsWith('a\n') || !out.endsWith('\nb') || !out.includes(END) || out.includes('\nold\n')) throw new Error('splice');
  const m = new Function(out.slice(out.indexOf(BEGIN), out.indexOf(END)) + ';return HARVESTED_PATHS')();
  eq(m.get('/one/two.php'), 'CVE-2026-4');
});

// ---- the INVARIANT, end to end through the shipped handler (2.17.0) ----
console.log('invariant (full handler)');
{
  const posted = [];
  let originStatus = 200;
  globalThis.fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const u = new URL(req.url);
    if (u.pathname.endsWith('/feed/observation')) { posted.push(JSON.parse(await req.text())); return new Response('{"success":true}'); }
    if (u.pathname.endsWith('/feed/observation/paths')) return new Response('{}', { status: 503 });
    if (u.pathname.includes('/stix-feed/')) return new Response('ip,confidence\n');
    if (u.pathname.includes('/threat-intel/honeypot') || u.pathname.includes('/feed/hit')) return new Response('{}');
    return new Response('origin', { status: originStatus, headers: { 'content-type': 'text/plain' } });
  };
  const store = new Map();
  globalThis.caches = { default: { match: async (k) => store.get(k.url)?.clone(), put: async (k, v) => { store.set(k.url, v.clone()); } } };
  const realLog = console.log; console.log = () => {};
  const worker = (await import('data:text/javascript,' + encodeURIComponent(src))).default;
  const env = { DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'true' };
  let n = 0;
  const run = async (path, status) => {
    originStatus = status; posted.length = 0; n++;
    const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
    const res = await worker.fetch(new Request(`https://www.dugganusa.com${path}`, {
      headers: { 'user-agent': 'Mozilla/5.0 Chrome/125.0', 'cf-connecting-ip': `198.51.${n}.7` } }), env, ctx);
    await Promise.all(waits);
    return { res, posted: [...posted] };
  };
  const r200 = await run('/scp/login.php', 200);
  const r404 = await run('/scp/login.php', 404);
  const rNon = await run('/an/ordinary/page', 404);
  const rDecoy = await run('/_layouts/15/notify.aspx', 200);
  console.log = realLog;
  t('a harvested path that returns REAL content records nothing (list poisoning is inert)', () => { eq(r200.res.status, 200); eq(r200.posted.length, 0); });
  t('a harvested path that 404s at the origin records one arrival', () => { eq(r404.posted.length, 1); eq(r404.posted[0].path, '/scp/login.php'); });
  t('a non-harvested 404 records nothing', () => eq(rNon.posted.length, 0));
  t('a harvested path answered by an edge decoy records an arrival', () => { eq(rDecoy.posted.length, 1); eq(rDecoy.posted[0].cves, 'CVE-2026-32201'); });
  t('the response is never changed by observation', () => { eq(r404.res.status, 404); });
}

// ---- HARVESTED-PATH TRAP (2.36.0) ----
console.log('trap (units)');
{
  const T = new Function([
    "const APPLIANCE_OWN_ZONES = ['dugganusa.com', 'aipmsec.com'];",
    slice('function safeDecode(', 'function getCanary('),
    "const HARVESTED_PATHS_GENERATED_AT = 'b'; const HARVESTED_PATHS = new Map([['/bundled/one.php','CVE-2026-1']]);",
    slice('function harvestedObserveEnabled(', 'async function postHarvestedObservation('),
    slice('function cfVerifiedCategory(', 'async function isVerifiedCrawler('),
    slice('function buildHarvestedTrapDoc(', 'async function indexHarvestedTrapHit('),
    'return { parseHarvestedList, parseHarvestedTrap, harvestedTrapEnabled, getHarvestedTrap, isPlainIp, trapIpKey, harvestedTrapFirst, buildHarvestedTrapDoc, active: () => harvestedActive, HARVESTED_TRAP_CONFIDENCE, HARVESTED_TRAP_SOURCE };',
  ].join('\n'))();
  const base = JSON.parse(liveBody(120)); base.paths.push(['/api/session/properties', 'CVE-2026-72898'], ['/multi/x.php', 'CVE-2026-1,CVE-2026-2']);
  t('backward compatible: a list WITHOUT trap still parses, with an empty trap', () => {
    const p = T.parseHarvestedList(JSON.stringify(base)); eq(p.map.size, 122); eq(p.trap.size, 0);
  });
  t('backward compatible: a list WITH trap still parses for the old parser shape (paths unchanged)', () => {
    const p = T.parseHarvestedList(JSON.stringify({ ...base, trap: [['/api/session/properties', 'CVE-2026-72898']] }));
    eq(p.map.size, 122); eq([...p.trap], [['/api/session/properties', 'CVE-2026-72898']]);
  });
  t('trap entries must be on the list, for one of that path\'s CVEs; junk and off-list ignored', () => {
    const p = T.parseHarvestedList(JSON.stringify({ ...base, trap: [
      ['/not/on/list.php', 'CVE-2026-72898'], ['/api/session/properties', 'CVE-2026-99999'], ['/multi/x.php', 'CVE-2026-2'],
      ['/multi/x.php', 'CVE-2026-1,CVE-2026-2'], [1, 2], 'x', ['/', 'CVE-2026-1'], ['/live1/x.php', 'CVE-2026-2001'] ] }));
    eq([...p.trap].sort(), [['/live1/x.php', 'CVE-2026-2001'], ['/multi/x.php', 'CVE-2026-2']]);
  });
  t('a malformed or oversized trap field empties the trap, never rejects the list', () => {
    for (const trap of ['x', { a: 1 }, null, Array.from({ length: 501 }, () => ['/live1/x.php', 'CVE-2026-2001'])]) {
      const p = T.parseHarvestedList(JSON.stringify({ ...base, trap })); eq(p.map.size, 122); eq(p.trap.size, 0);
    }
  });
  t('trap gating: own zones by default, customer zone off unless opted in, false and HONEYPOTS_ENABLED=false turn it off', () => {
    eq(T.harvestedTrapEnabled({}, 'www.dugganusa.com'), true);
    eq(T.harvestedTrapEnabled({}, 'www.example.com'), false);
    eq(T.harvestedTrapEnabled({}, 'dugganusa.com.evil.net'), false);
    eq(T.harvestedTrapEnabled({ HARVESTED_TRAP: 'true' }, 'www.example.com'), true);
    eq(T.harvestedTrapEnabled({ HARVESTED_TRAP: 'false' }, 'www.dugganusa.com'), false);
    eq(T.harvestedTrapEnabled({ HONEYPOTS_ENABLED: 'false' }, 'www.dugganusa.com'), false);
    eq(T.harvestedTrapEnabled({ HONEYPOTS_ENABLED: 'false', HARVESTED_TRAP: 'true' }, 'www.example.com'), false);
  });
  t('only a bare IP literal is filed', () => {
    for (const v of ['45.138.12.32', '2001:db8::1', '2001:db8:1:2:3:4:5:6']) eq(T.isPlainIp(v), true, v);
    for (const v of ['', '1.2.3.4, 5.6.7.8', '1.2.3', '999.1.1.1', 'evil.com', '1.2.3.4 ', '2001:db8::1::2', '<script>', 'a'.repeat(50) + ':1']) eq(T.isPlainIp(v), false, v);
  });
  t('dedupe key: exact IPv4, IPv6 /64', () => {
    eq(T.trapIpKey('45.138.12.32'), '45.138.12.32');
    eq(T.trapIpKey('2001:db8:aa:bb:1::2'), '2001:db8:aa:bb::/64');
    eq(T.trapIpKey('2001:db8:aa:bb:9:9:9:9'), '2001:db8:aa:bb::/64');
    eq(T.trapIpKey('2001:db8::1'), '2001:db8:0:0::/64');
  });
  t('dedupe: one filing per IP (or /64) and path per 24h, per isolate', () => {
    eq(T.harvestedTrapFirst('45.138.12.32', '/p', 1000), true);
    eq(T.harvestedTrapFirst('45.138.12.32', '/p', 1000 + 3600e3), false);
    eq(T.harvestedTrapFirst('45.138.12.32', '/q', 1000 + 3600e3), true);
    eq(T.harvestedTrapFirst('2001:db8:aa:bb::1', '/p', 5e9), true);
    eq(T.harvestedTrapFirst('2001:db8:aa:bb::2', '/p', 5e9 + 1), false);
    eq(T.harvestedTrapFirst('45.138.12.32', '/p', 1000 + 25 * 3600e3), true);
  });
  t('a rotating-address flood is bounded per isolate per minute', () => {
    let filed = 0; for (let i = 0; i < 200; i++) if (T.harvestedTrapFirst(`10.9.${i}.1`, '/f', 9e9)) filed++;
    eq(filed, 20);
    eq(T.harvestedTrapFirst('10.10.10.10', '/f', 9e9 + 61000), true);
  });
  t('the filed doc: own source, confidence 25 (< 30 STIX default, < 50 ips.csv, < 80 edge), labelled with the CVE', () => {
    const req = new Request('https://www.dugganusa.com/api/session/properties?token=secret', { headers: { 'user-agent': 'python-requests/2.31' } });
    const d = T.buildHarvestedTrapDoc(req, { asn: 64500, asOrganization: 'X', country: 'NL' },
      { ip: '45.138.12.32', cve: 'CVE-2026-72898', path: '/api/session/properties' }, 404, 1764000000000);
    eq(d.source, 'edge-harvested-trap'); eq(d.value, '45.138.12.32'); eq(d.type, 'ipv4');
    if (!(d.confidence < 30 && d.confidence < 50 && d.confidence < 80)) throw new Error(`confidence ${d.confidence}`);
    eq(d.malware_family, 'harvested-trap:CVE-2026-72898'); eq(d.threat_type, 'harvested-trap-probe');
    if (!/^[a-zA-Z0-9_-]+$/.test(d.id)) throw new Error(`id not Meili-safe: ${d.id}`);
    if (JSON.stringify(d).includes('token=secret')) throw new Error('query string leaked into the doc');
    eq(d.source === 'edge-honeypot', false);
  });
  t('IPv6 doc id is Meili-safe', () => {
    const d = T.buildHarvestedTrapDoc(new Request('https://www.dugganusa.com/x'), {}, { ip: '2001:db8::1', cve: 'CVE-2026-1', path: '/x' }, 404, 1);
    if (!/^[a-zA-Z0-9_-]+$/.test(d.id)) throw new Error(d.id); eq(d.type, 'ipv6');
  });
}

console.log('trap (full handler)');
{
  const posted = [], honey = [];
  let originStatus = 404, originBody = 'origin-bytes-é\u0000x';
  const trapList = JSON.parse(liveBody(120));
  trapList.paths.push(['/api/session/properties', 'CVE-2026-72898'], ['/observe/only.php', 'CVE-2026-5'],
    ['/_layouts/15/notify.aspx', 'CVE-2026-32201'], ['/@fs/etc/passwd', 'CVE-2026-7']);
  trapList.trap = [['/api/session/properties', 'CVE-2026-72898'], ['/_layouts/15/notify.aspx', 'CVE-2026-32201'], ['/@fs/etc/passwd', 'CVE-2026-7']];
  globalThis.fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const u = new URL(req.url);
    if (u.pathname.endsWith('/feed/observation')) { posted.push(JSON.parse(await req.text())); return new Response('{"success":true}'); }
    if (u.pathname.endsWith('/feed/observation/paths')) return new Response(JSON.stringify(trapList));
    if (u.pathname.includes('/stix-feed/')) return new Response('ip,confidence\n');
    if (u.pathname.includes('/threat-intel/honeypot')) { honey.push(JSON.parse(await req.text())); return new Response('{}'); }
    if (u.pathname.includes('/feed/hit')) return new Response('{}');
    return new Response(originBody, { status: originStatus, headers: { 'content-type': 'text/plain' } });
  };
  const store = new Map();
  globalThis.caches = { default: { match: async (k) => store.get(k.url)?.clone(), put: async (k, v) => { store.set(k.url, v.clone()); } } };
  const realLog = console.log; console.log = () => {};
  // A fresh module instance (the trailing comment makes a distinct URL), so module state starts empty.
  const worker = (await import('data:text/javascript,' + encodeURIComponent(src + '\n// trap-suite'))).default;
  let n = 0;
  const run = async (path, status, { host = 'www.dugganusa.com', env = {}, ua = 'python-requests/2.31', cf = null, ip = null, headers = {} } = {}) => {
    originStatus = status; posted.length = 0; honey.length = 0; n++;
    const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
    const req = new Request(`https://${host}${path}`, { headers: { 'user-agent': ua, 'cf-connecting-ip': ip ?? `203.0.${n}.9`, ...headers } });
    if (cf) Object.defineProperty(req, 'cf', { value: cf });
    const res = await worker.fetch(req, { DUGGANUSA_API_KEY: 'k', HONEYPOTS_ENABLED: 'true', ...env }, ctx);
    const body = await res.text();
    await Promise.all(waits);
    return { res, body, posted: [...posted], honey: [...honey] };
  };
  await run('/warmup', 404); // first request pulls the live list (waitUntil)
  const trap404 = await run('/api/session/properties', 404);
  const trap200 = await run('/api/session/properties', 200);
  const trap401 = await run('/API/Session/Properties/', 401);
  const observeOnly = await run('/observe/only.php', 404);
  const crawler = await run('/api/session/properties', 404, { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)', cf: { verifiedBotCategory: 'Search Engine Crawler' } });
  const customer = await run('/api/session/properties', 404, { host: 'www.example.com' });
  const customerIn = await run('/api/session/properties', 404, { host: 'www.example.com', env: { HARVESTED_TRAP: 'true' } });
  const trapOff = await run('/api/session/properties', 404, { env: { HARVESTED_TRAP: 'false' } });
  const hpOff = await run('/api/session/properties', 404, { env: { HONEYPOTS_ENABLED: 'false' } });
  const decoy = await run('/_layouts/15/notify.aspx', 200);
  const secret = await run('/@fs/etc/passwd', 404);
  const spoof = await run('/api/session/properties', 404, { ip: '198.18.7.7', headers: { 'x-forwarded-for': '8.8.8.8', 'x-real-ip': '8.8.4.4', 'true-client-ip': '1.1.1.1' } });
  const badIp = await run('/api/session/properties', 404, { ip: '9.9.9.9, 45.138.12.32' });
  const dup1 = await run('/api/session/properties', 404, { ip: '192.0.2.55' });
  const dup2 = await run('/api/session/properties', 404, { ip: '192.0.2.55' });
  const sensor = await run('/api/session/properties', 404, { host: 'sensor.dugganusa.com', env: { SENSOR_HOSTS: 'sensor.dugganusa.com' } });
  console.log = realLog;
  const traps = (r) => r.honey.filter(d => d.source === 'edge-harvested-trap');
  t('a >= 400 probe of a trap path files the source IP once, at 25, own source', () => {
    eq(traps(trap404).length, 1); const d = traps(trap404)[0];
    eq(d.value, `203.0.${n - 15}.9`); eq(d.confidence, 25); eq(d.malware_family, 'harvested-trap:CVE-2026-72898');
    eq(d.honeypot_meta.status, 404);
  });
  t('the response is unchanged: status and bytes', () => { eq(trap404.res.status, 404); eq(trap404.body, originBody); eq(trap401.res.status, 401); eq(trap401.body, originBody); });
  t('a trap path that returns real content (200) files NOTHING', () => { eq(traps(trap200).length, 0); eq(trap200.res.status, 200); eq(trap200.body, originBody); });
  t('case and trailing slash normalize to the trap path; 401 files', () => eq(traps(trap401).length, 1));
  t('a harvested path NOT in the trap set files nothing (observation only)', () => { eq(traps(observeOnly).length, 0); eq(observeOnly.posted.length, 1); });
  t('a verified crawler never files', () => eq(traps(crawler).length, 0));
  t('a customer zone never files unless opted in', () => { eq(traps(customer).length, 0); eq(traps(customerIn).length, 1); });
  t('HARVESTED_TRAP=false and HONEYPOTS_ENABLED=false turn it off on our own zone', () => { eq(traps(trapOff).length, 0); eq(traps(hpOff).length, 0); });
  t('an edge decoy (200) files the canary record only, never a trap record', () => {
    eq(traps(decoy).length, 0); eq(decoy.honey.filter(d => d.source === 'edge-honeypot').length, 1); eq(decoy.res.status, 200);
  });
  t('a secret-file probe (404 at the edge) is never filed, even on a trap path', () => { eq(secret.res.status, 404); eq(secret.honey.length, 0); });
  t('client IP comes from cf-connecting-ip only; spoofed forwarding headers are ignored', () => { eq(traps(spoof).length, 1); eq(traps(spoof)[0].value, '198.18.7.7'); });
  t('a non-literal cf-connecting-ip is never filed', () => eq(traps(badIp).length, 0));
  t('the same IP and path files once per isolate window', () => { eq(traps(dup1).length, 1); eq(traps(dup2).length, 0); eq(dup2.res.status, 404); });
  t('a SENSOR host never files', () => eq(sensor.honey.length, 0));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

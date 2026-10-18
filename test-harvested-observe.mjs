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
const hook = slice('// LAYER 0.5: Harvested-path OBSERVATION', '// LAYER 1:');
t('Layer 0.5 never returns or builds a response', () => {
  if (/\breturn\b/.test(hook) || /new Response/.test(hook)) throw new Error('hook returns or answers');
  if (!/ctx\.waitUntil\(pull\)/.test(hook)) throw new Error('refresh not in waitUntil');
  if (!/ctx\.waitUntil\(postHarvestedObservation/.test(hook)) throw new Error('hook does not report via waitUntil');
});
t('Layer 0.5 runs before scanner and IOC enforcement', () => {
  if (!(src.indexOf('// LAYER 0.5') < src.indexOf('// LAYER 1:') && src.indexOf('// LAYER 1:') < src.indexOf('// LAYER 2:'))) throw new Error('order');
});
t('observation posts carry no full IP field', () => {
  const post = slice('ctx.waitUntil(postHarvestedObservation(env, {', '}));');
  if (/\bip\b\s*[:,]/.test(post.replace(/src_net/g, ''))) throw new Error('raw ip in the report');
});
t('customer zone report omits host, UA, network and AS org', () => {
  const post = slice('ctx.waitUntil(postHarvestedObservation(env, {', '}));');
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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

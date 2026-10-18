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

// The hook must never change the response: no return, no Response, only waitUntil.
const hook = slice('// LAYER 0.5: Harvested-path OBSERVATION', '// LAYER 1:');
t('Layer 0.5 never returns or builds a response', () => {
  if (/\breturn\b/.test(hook) || /new Response/.test(hook)) throw new Error('hook returns or answers');
  if (!/ctx\.waitUntil\(postHarvestedObservation/.test(hook)) throw new Error('hook does not report via waitUntil');
});
t('Layer 0.5 runs before scanner and IOC enforcement', () => {
  if (!(src.indexOf('// LAYER 0.5') < src.indexOf('// LAYER 1:') && src.indexOf('// LAYER 1:') < src.indexOf('// LAYER 2:'))) throw new Error('order');
});
t('observation posts carry no full IP field', () => {
  const post = slice('ctx.waitUntil(postHarvestedObservation(env, {', '}));');
  if (/\bip\b\s*[:,]/.test(post.replace(/src_net/g, ''))) throw new Error('raw ip in the report');
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

/**
 * Test the SWEEP detector (2.26.0): path diversity, not volume.
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it, same as the other
 * suites, so the test cannot drift from what runs. The cases that matter most are the ones that
 * must NOT flag: a hammer on one path (that is the rate limiter's job), a wide crawl of ordinary
 * paths, MCP / security.txt discovery under /.well-known/, and a different IP's traffic.
 *
 *   node test-sweep-detector.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
const det = slice('const SWEEP_MAX_TRACKED_PATHS', 'async function handleFetch');
const cfgSrc = slice('const DEFAULT_CONFIG', 'function getConfig');
const mod = await import('data:text/javascript,' + encodeURIComponent(
  cfgSrc + '\n' + det + '\nexport { sweepSignal, sweepResponse, isSecretShapedPath, sweepBuckets, loadConfig, DEFAULT_CONFIG };'));
const { sweepSignal, sweepResponse, isSecretShapedPath, sweepBuckets, loadConfig, DEFAULT_CONFIG } = mod;

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
};
const cfg = { sweepMode: 'observe', sweepDistinct: 20, sweepSecretShare: 60, sweepWindowS: 60 };
const T0 = 1_000_000_000_000;
const feed = (ip, paths, t0 = T0, step = 100, c = cfg) => { let last = null; paths.forEach((p, i) => { last = sweepSignal(ip, p, c, t0 + i * step); }); return last; };
const secrets = (n, tag = 'a') => Array.from({ length: n }, (_, i) => `/.env.${tag}${i}`);
const plain = (n, tag = 'a') => Array.from({ length: n }, (_, i) => `/blog/post-${tag}${i}`);
const reset = () => sweepBuckets.clear();

// 1. The threshold: 19 distinct secret-shaped paths do not flag; the 20th does, once.
reset();
check('19 distinct secret paths: not flagged', feed('1.1.1.1', secrets(19)), null);
const s20 = sweepSignal('1.1.1.1', '/.env.x19', cfg, T0 + 5000);
check('20th distinct secret path: flagged', !!s20 && s20.first && s20.distinct === 20 && s20.share === 100, true);
check('21st: still flagged but not first', (() => { const s = sweepSignal('1.1.1.1', '/.env.x20', cfg, T0 + 5100); return !!s && !s.first; })(), true);

// 2. Must NOT flag.
reset();
check('one path hammered 500 times: distinct=1, not flagged', feed('2.2.2.2', Array(500).fill('/.env')), null);
reset();
check('30 distinct ORDINARY paths (a crawl): not flagged', feed('3.3.3.3', plain(30)), null);
reset();
check('30 distinct /.well-known/ paths: not secret-shaped, not flagged', feed('4.4.4.4', Array.from({ length: 30 }, (_, i) => `/.well-known/mcp/x${i}.json`)), null);
reset();
feed('5.5.5.5', secrets(19, 'p'));
check('different IP does not inherit the count', feed('6.6.6.6', secrets(19, 'q')), null);

// 3. The share boundary (60%): 12 secret + 8 plain = 60% flags; 11 + 9 = 55% does not.
reset();
check('20 distinct, 12 secret-shaped (60%): flagged', !!feed('7.7.7.7', [...secrets(12), ...plain(8)]), true);
reset();
check('20 distinct, 11 secret-shaped (55%): not flagged', feed('8.8.8.8', [...secrets(11), ...plain(9)]), null);

// 4. The window: entries expire, a quiet IP is not flagged on one late request, and a returning
// sweep is flagged again as a NEW first.
reset();
feed('9.9.9.9', secrets(20), T0, 100);
check('one request 61s later: old paths expired, not flagged', sweepSignal('9.9.9.9', '/.env.late', cfg, T0 + 61_000), null);
const firstFlag = (ip, paths, t0, step) => { for (let i = 0; i < paths.length; i++) { const s = sweepSignal(ip, paths[i], cfg, t0 + i * step); if (s) return s; } return null; };
const again = firstFlag('9.9.9.9', secrets(20, 'r'), T0 + 62_000, 100);
check('a returning sweep flags again, and the first flag has first=true', !!again && again.first, true);

// 5. Modes and inputs.
reset();
check('mode off: never flags', feed('10.0.0.1', secrets(40), T0, 100, { ...cfg, sweepMode: 'off' }), null);
check('no IP: never flags', sweepSignal('', '/.env', cfg, T0), null);

// 6. Memory bound: one IP asking for 1000 distinct paths is tracked to at most 300 and stays flagged.
reset();
const wide = feed('11.0.0.1', secrets(1000, 'w'), T0, 10);
check('1000-path sweep: still flagged', !!wide, true);
check('tracking is bounded to 300 paths', sweepBuckets.get('11.0.0.1').paths.size <= 300, true);

// 7. Sample, shape and the block response.
reset();
const f = feed('12.0.0.1', secrets(25));
check('sample carries recent paths, at most 8', Array.isArray(f.sample) && f.sample.length === 8 && f.sample.every((p) => p.startsWith('/.env.')), true);
const r = sweepResponse('1.2.3.4');
check('block response is 403 with the shield header', r.status === 403 && r.headers.get('x-dugganusa-shield') === 'sweep', true);

// 8. Secret-shaped vs not.
for (const p of ['/.env', '/.env.bkp', '/.git/config', '/wp-config.php.bak', '/.claude/settings.json', '/.amazonq/mcp.json', '/actuator/env', '/backup.sql', '/docker-compose.yml', '/id_rsa']) check(`secret-shaped: ${p}`, isSecretShapedPath(p), true);
for (const p of ['/', '/blog/hello', '/pricing', '/api/v1/search', '/.well-known/mcp.json', '/.well-known/security.txt', '/llms.txt', '/robots.txt']) check(`NOT secret-shaped: ${p}`, isSecretShapedPath(p), false);

// 9. Config: defaults, parsing and bad values fall back with a warning (a typo must never change the posture).
const d = loadConfig({});
check('defaults: observe, 20 distinct, 60% share, 60s', [d.sweepMode, d.sweepDistinct, d.sweepSecretShare, d.sweepWindowS], ['observe', 20, 60, 60]);
check('SWEEP_MODE=block parses', loadConfig({ SWEEP_MODE: 'block' }).sweepMode, 'block');
check('SWEEP_MODE is case-insensitive', loadConfig({ SWEEP_MODE: ' OFF ' }).sweepMode, 'off');
const bad = loadConfig({ SWEEP_MODE: 'blok', SWEEP_DISTINCT: '3', SWEEP_SECRET_SHARE: '250', SWEEP_WINDOW_S: 'abc' });
check('bad values fall back to defaults', [bad.sweepMode, bad.sweepDistinct, bad.sweepSecretShare, bad.sweepWindowS], ['observe', 20, 60, 60]);
check('bad values each leave a warning', bad.warnings.filter((w) => /SWEEP_/.test(w)).length, 4);
check('custom thresholds parse', (() => { const c = loadConfig({ SWEEP_DISTINCT: '40', SWEEP_SECRET_SHARE: '80', SWEEP_WINDOW_S: '120' }); return [c.sweepDistinct, c.sweepSecretShare, c.sweepWindowS]; })(), [40, 80, 120]);
check('SWEEP_MODE is independent of SHIELD_MODE', (() => { const c = loadConfig({ SHIELD_MODE: 'block' }); return [c.mode, c.sweepMode]; })(), ['block', 'observe']);

// 10. The handler hook, checked on the shipped source (comments stripped): the early block only
// records and logs and NEVER returns; enforcement is a separate line that is gated on block mode,
// the global observe switch and the canary stand-aside; and the early block sits before every
// enforcement layer so a sweep that LAYER 1/2 would answer is still counted.
const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const early = strip(slice('// LAYER 0.2: SWEEP detector', '// LAYER 0.5:'));
check('LAYER 0.2 never returns', /\breturn\b/.test(early), false);
check('LAYER 0.2 skips verified crawlers and key-bearing requests', /!verifiedCrawler/.test(early) && /sweepAuthed/.test(early), true);
const enforce = strip(slice('// LAYER 2.5: SWEEP enforcement', '// LAYER 3:'));
check('enforcement is gated on block mode, the observe switch and the canary stand-aside', /cfg\.sweepMode === 'block'/.test(enforce) && /!cfg\.observe/.test(enforce) && /!canary/.test(enforce), true);
check('LAYER 0.2 precedes LAYER 1 (counts what a later layer answers)', src.indexOf('// LAYER 0.2: SWEEP') < src.indexOf('// LAYER 1: Scanner detection'), true);
check('enforcement follows LAYER 2 and precedes LAYER 3', src.indexOf('// LAYER 2: IOC blocking') < src.indexOf('// LAYER 2.5: SWEEP enforcement') && src.indexOf('// LAYER 2.5: SWEEP enforcement') < src.indexOf('// LAYER 3: Honeypot canaries'), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

/**
 * Every door a decoy advertises must open.
 *
 * Each appliance decoy serves a login form whose `action` tells the scanner where to
 * submit. Those action URLs were never canary paths themselves, so a scanner that took
 * the lure and actually submitted credentials fell through to the blocker and got a 418
 * or 403 — no decoy, no IOC, no record of the attempt. We lured the most committed
 * attacker on the edge and then hung up on them.
 *
 * Measured 2026-10-26: 3 hits on /php/login.php since the 2.20.0 deploy, two of them
 * l9scan/2.0 (LeakIX), all blocked, none indexed.
 *
 * This asserts the INVARIANT rather than the six paths that happened to be missing:
 * the action URLs are extracted from the shipped source at test time, so a new decoy
 * with a new action fails here until its door is a canary too.
 *
 *   node test-decoy-actions.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
const code = slice('const CANARY_PATHS', 'function honeypotResponse');
const mod = await import('data:text/javascript,' + encodeURIComponent(
  code + '\nexport { getCanary, getApplianceCanary, applianceCanariesEnabled };'));
const { getCanary, getApplianceCanary } = mod;

// Appliance canaries are on for our own zones; that is where the decoys serve.
const resolves = p => Boolean(getCanary(p) || getApplianceCanary(p));

// Pull every form action out of the shipped decoy markup. Two shapes appear:
// a literal action="/path", and a ternary inside action="${...}" whose branches are
// quoted literals. A `${action}` indirection is resolved from the `const action =`
// ternary that feeds it.
function advertisedActions(source) {
  const found = new Set();
  for (const m of source.matchAll(/action="(\/[^"${]*)"/g)) found.add(m[1]);
  for (const m of source.matchAll(/action="\$\{[^}]*\}"/g)) {
    for (const lit of m[0].matchAll(/'(\/[^']+)'/g)) found.add(lit[1]);
  }
  for (const m of source.matchAll(/const action\s*=\s*[^;]+;/g)) {
    for (const lit of m[0].matchAll(/'(\/[^']+)'/g)) found.add(lit[1]);
  }
  return [...found];
}

// A canary match is on the pathname; a scanner posts to the whole string.
const pathOf = a => a.split('?')[0];

let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); pass++; console.log('  ok  ', name); } catch (e) { fail++; console.log('  FAIL', name, '\n      ', e.message); }
}

const actions = advertisedActions(src);

test('the extractor actually found the decoy doors (guards against a silent regex miss)', () => {
  if (actions.length < 8) throw new Error(`only found ${actions.length} actions; the markup shape probably changed`);
  for (const known of ['/wp-login.php', '/php/login.php', '/dana-na/auth/url_default/login.cgi']) {
    if (!actions.includes(known)) throw new Error(`extractor missed a known action: ${known}`);
  }
});

// Deliberately NOT trapped, with the reason. An exception has to be cheaper than the rule
// it breaks, and has to be written down where the next person will read it.
const TOO_GENERIC_TO_TRAP = new Map([
  ['/login/', 'cPanel posts here, and so does half the web. The cPanel decoy is in the ' +
              'always-on CANARY_PATHS set, so trapping /login/ would answer a decoy on a ' +
              'real login route for every customer running honeypots. Losing the ' +
              'follow-through on one decoy costs us less than breaking a customer sign-in.'],
]);

test('THE INVARIANT: every advertised form action is itself a canary path', () => {
  const orphans = actions
    .map(pathOf)
    .filter(p => !resolves(p) && !TOO_GENERIC_TO_TRAP.has(p));
  if (orphans.length) {
    throw new Error('decoys advertise doors that are not canaries, so a submitted login is ' +
      'blocked instead of indexed:\n       ' + JSON.stringify(orphans, null, 2));
  }
});

test('the documented exceptions are still real exceptions, not stale ones', () => {
  for (const [p, why] of TOO_GENERIC_TO_TRAP) {
    if (!actions.map(pathOf).includes(p)) {
      throw new Error(`${p} is excepted but no decoy advertises it any more — drop the exception. (${why})`);
    }
    if (resolves(p)) throw new Error(`${p} is excepted but now resolves as a canary — drop the exception`);
  }
});

test('the specific door PHP2Shell scanners walked through: /php/login.php', () => {
  if (!resolves('/php/login.php')) throw new Error('/php/login.php still falls through to the blocker');
});

test('GlobalProtect sibling door is a canary too', () => {
  if (!resolves('/global-protect/login.esp')) throw new Error('/global-protect/login.esp still falls through');
});

// The fix is an ORDERING property of handleFetch, which cannot be imported in isolation.
// These assert it structurally against the shipped source — brittle by design: if someone
// moves the resolution back below the guards, this fails rather than going quiet.
const at = needle => { const i = src.indexOf(needle); if (i < 0) throw new Error(`not found: ${needle}`); return i; };

test('canary is resolved BEFORE the scanner-418 layer', () => {
  const resolvedAt = at('const canary = (honeypotsEnabled && !verifiedCrawler)');
  const scannerAt = at('LAYER 1: Scanner detection');
  if (resolvedAt > scannerAt) throw new Error('canary is resolved after LAYER 1; a scanner on a trapped path will be 418d before the decoy runs');
});

test('scanner-418 stands aside on a canary path', () => {
  if (!/if \(cfg\.scanner418 && !verifiedCrawler && !canary && detectScanner/.test(src)) {
    throw new Error('LAYER 1 no longer carries the !canary guard');
  }
});

test('IOC 403 stands aside on a canary path, but the feed hit is still reported', () => {
  if (!/if \(!cfg\.observe && !canary\) return blockedResponse\(ip\);/.test(src)) {
    throw new Error('LAYER 2 no longer withholds the 403 on a canary path');
  }
  // The report must sit OUTSIDE the !canary guard, or feed-efficacy loses every trapped hit.
  if (!/if \(cfg\.iocBlocking && !verifiedCrawler && ip && checkIOC\(ip\)\) \{/.test(src)) {
    throw new Error('LAYER 2 match test now skips canary paths entirely — the feed hit would go unreported');
  }
});

test('the secret-file probe handler still outranks the canary', () => {
  if (at('const secretProbe =') > at('if (canary) {')) {
    throw new Error('secret-probe must still be answered before the canary; /vpn/%2eenv is a config probe, not a decoy');
  }
});

test('real site paths still do NOT trap', () => {
  for (const p of ['/', '/index.html', '/post/some-article', '/api/v1/search', '/sitemap.xml']) {
    if (resolves(p)) throw new Error(`${p} must not be a canary`);
  }
});

console.log(`\n${pass} passed, ${fail} failed  (${actions.length} advertised doors checked)`);
process.exit(fail ? 1 : 0);

/**
 * Test the webshell-hunt canary (2.27.0).
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it, same as
 * test-agent-config-canaries.mjs, so the test cannot drift from what runs.
 *
 * The cases that matter most are the ones that must NOT trap: a bare cache.php, and real
 * CMS paths. A canary over a path a customer actually serves breaks their site. The decoy
 * is a lure that must stay INERT (no active content), and the gate must keep customer zones off unless
 * they opt in.
 *
 *   node test-webshell-hunt-canaries.mjs
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
  code + '\nexport { getWebshellHuntCanary, webshellHuntCanariesEnabled, FAKE_RESPONSES, getCanary };'));
const { getWebshellHuntCanary, webshellHuntCanariesEnabled, FAKE_RESPONSES, getCanary } = mod;

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${got}, want ${want})`}`);
};
const kind = (p) => { const c = getWebshellHuntCanary(p); return c ? c.type : null; };

// 1. The measured paths (our own edge blocks, 2026-10-01 to 10-31).
for (const p of [
  '//images/images/images/images/images/images/images/images/cache.php',
  '//images/images/images/cache.php',
  '//assets/images/images/cache.php',
  '//blogs/media/media/cache.php',
  '//cgi-bin/cgi-bin/cgi-bin/cgi-bin/cache.php',
  '/wp-content/plugins/plugins/cache.php',
  '/images/images/cache.php',
  '/IMAGES/Images/cache.php',
  '/wp-content/plugins/plugins/%63ache.php',
]) check(`traps ${p}`, kind(p), 'webshell_hunt');

// 2. Must NOT trap: what a real site serves.
for (const p of [
  '/cache.php', '/cache/cache.php', '/wp-content/cache.php', '/wp-content/plugins/foo/cache.php',
  '/wp-content/plugins/w3-total-cache/cache.php', '/images/cache.php', '/a/b/c/cache.php',
  '/images/images/cache.phpx', '/images/images/cache.php.bak', '/images/images/', '/images/images',
  '/images/images/index.php', '/', '', '/media/media/readme.txt', '/.well-known/mcp.json',
]) check(`does not trap ${p || '(empty)'}`, kind(p), null);

// 3. The marker for the WAF-bypass variant is set only when the raw path differs.
check('encoded path is marked', (getWebshellHuntCanary('/wp-content/plugins/plugins/%63ache.php') || {}).encoded_path, true);
check('plain path is not marked', (getWebshellHuntCanary('/images/images/cache.php') || {}).encoded_path, undefined);

// 4. The trap is its own thing: the generic canary does not already answer these paths.
check('generic getCanary does not already trap it', getCanary('/images/images/cache.php'), null);

// 5. The decoy is a LURE and stays INERT (2.28.0). It must carry what public shell finders match on,
//    and nothing active: no form, input, script, link, command or credential. A door that has to
//    open (a form action) would fall through to the blocker, so there must be no door at all.
check('decoy exists', typeof FAKE_RESPONSES.webshell_hunt, 'function');
const lure = FAKE_RESPONSES.webshell_hunt();
check('lure carries the 403WebShell title', lure.includes('<title>403WebShell</title>'), true);
check('lure carries a "User :" line', lure.includes('User :'), true);
for (const bad of ['<form', '<input', '<script', '<a ', 'href=', 'src=', 'action=', 'onload', 'onerror', 'eval(', 'exec(', 'system(', 'passthru', 'base64', 'http://', 'https://', 'password', 'passwd', 'token', 'key=']) {
  check(`lure has no ${bad}`, lure.toLowerCase().includes(bad), false);
}
check('lure is small (under 300 bytes)', lure.length < 300, true);
check('lure is served as text/html', /\['wp', 'cpanel', 'webshell_hunt'\]\.includes\(canary\.fake\) \? 'text\/html'/.test(src), true);

// 6. The gate: our own zones by default, customers only on opt-in, "false" off everywhere.
check('own zone, unset', webshellHuntCanariesEnabled({}, 'dugganusa.com'), true);
check('own subdomain, unset', webshellHuntCanariesEnabled({}, 'www.dugganusa.com'), true);
check('own second zone, unset', webshellHuntCanariesEnabled({}, 'aipmsec.com'), true);
check('customer zone, unset', webshellHuntCanariesEnabled({}, 'www.example.com'), false);
check('lookalike host, unset', webshellHuntCanariesEnabled({}, 'dugganusa.com.evil.example'), false);
check('customer opt-in', webshellHuntCanariesEnabled({ WEBSHELL_HUNT_CANARIES: 'true' }, 'www.example.com'), true);
check('opt-out beats own zone', webshellHuntCanariesEnabled({ WEBSHELL_HUNT_CANARIES: 'false' }, 'dugganusa.com'), false);
check('flag is case-insensitive', webshellHuntCanariesEnabled({ WEBSHELL_HUNT_CANARIES: 'TRUE' }, 'www.example.com'), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

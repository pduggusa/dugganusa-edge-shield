/**
 * PHP2Shell is not a path. CVE-2026-109618/109619 hits ordinary endpoints — /, /index.php,
 * an upload handler — so no path-list canary (PHP_CANARY_PREFIXES/EXACT) can trap it. What
 * IS enumerable, per Zscaler's own research, is the literal multipart Content-Type boundary
 * four known tool families stamp instead of generating a random one. getPhp2ShellBoundaryCanary
 * reads that one header, with zero body bytes pulled off the wire, regardless of path.
 *
 * Called out in public first: our own 2026-10-28 post ("Two of the 23 PHP2Shell Attacker
 * IPs...") named this exact gap — "Our canaries trap paths. A path trap cannot see an attack
 * whose distinguishing feature is a header." This is the fix.
 *
 *   node test-php2shell-boundary.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
const code = slice('const PHP2SHELL_BOUNDARY_MARKERS', '// ================================================================\n// APP-CONSOLE CANARIES');
const mod = await import('data:text/javascript,' + encodeURIComponent(
  code + '\nexport { getPhp2ShellBoundaryCanary, PHP2SHELL_BOUNDARY_MARKERS };'));
const { getPhp2ShellBoundaryCanary } = mod;

let pass = 0, fail = 0;
function test(name, fn) {
  return Promise.resolve().then(fn).then(() => { pass++; console.log('  ok  ', name); },
    (e) => { fail++; console.log('  FAIL', name, '\n      ', e.message); });
}
const ok = (v, m) => { if (!v) throw new Error(m); };
const req = (ctype, method = 'POST') => new Request('https://x.test/', {
  method, headers: ctype ? { 'content-type': ctype } : {},
});

await test('ShellFlow boundary is caught', async () => {
  const c = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=----shellflow-php2shell'));
  ok(c && c.tool === 'shellflow', `expected shellflow, got ${JSON.stringify(c)}`);
  ok(c.type === 'php2shell_boundary' && c.fake === 'shell' && c.product === 'php-cve-2026-109618-109619', 'canary shape');
});

await test('Active RCE Operator boundary (--VERIFY) is caught', async () => {
  const c = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=--VERIFY'));
  ok(c && c.tool === 'active-rce-operator', `got ${JSON.stringify(c)}`);
});

await test('Nuclei CVE template boundary is caught', async () => {
  const c = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=------Nuclei1234'));
  ok(c && c.tool === 'nuclei-template', `got ${JSON.stringify(c)}`);
});

await test('Neo Scanner boundary is caught, both build-name variants', async () => {
  const a = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=--NeoMM2026'));
  const b = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=--NeoMM2026b'));
  ok(a && a.tool === 'neo-scanner', `NeoMM2026: got ${JSON.stringify(a)}`);
  ok(b && b.tool === 'neo-scanner', `NeoMM2026b: got ${JSON.stringify(b)}`);
});

await test('an ordinary browser multipart boundary does not match', async () => {
  const c = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'));
  ok(c === null, `false positive on an ordinary boundary: ${JSON.stringify(c)}`);
});

await test('non-multipart content types never match, even if the string appears', async () => {
  const c = getPhp2ShellBoundaryCanary(req('application/json'));
  ok(c === null, 'json should never match');
  const c2 = getPhp2ShellBoundaryCanary(new Request('https://x.test/?c=shellflow-php2shell', { method: 'GET' }));
  ok(c2 === null, 'GET with no content-type header should never match');
});

await test('look-alikes we deliberately do NOT match (Fastly-reported, different CVE/campaign)', async () => {
  // React2Shell (CVE-2025-55182) is a different bug entirely; wp2shell is a WordPress
  // campaign, not this PHP core CVE pair. Matching either mislabels unrelated traffic.
  const react2shell = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=----reactboundary'));
  ok(react2shell === null, 'React2Shell shape must not match');
  const wp2shell = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=----wp2shell9f8a'));
  ok(wp2shell === null, 'wp2shell boundary must not match php2shell');
});

await test('a GET or HEAD with a multipart content-type header (nonsensical but possible) still only cares about the header', async () => {
  const c = getPhp2ShellBoundaryCanary(req('multipart/form-data; boundary=----shellflow-php2shell', 'GET'));
  ok(c && c.tool === 'shellflow', 'this is a header check, not a method check — matches by design');
});

await test('a boundary-only match is never indexed without body corroboration (security review finding)', async () => {
  // The four boundary strings are now public (our own post names one, Zscaler's writeup
  // names all four), so a header-only check is forgeable by anyone with zero exploit
  // knowledge — a browser fetch() with the right Content-Type is enough. Static check: the
  // call site must gate indexHoneypotHit on a body-corroborating tell, not fire on the
  // canary match alone.
  const callSite = src.slice(src.indexOf('const tell = {'), src.indexOf('// Return convincing fake response'));
  ok(/boundaryUncorroborated/.test(callSite), 'the call site has no corroboration gate — this would re-expose the finding');
  ok(/php2shell_boundary/.test(callSite), 'the gate must be scoped to the boundary canary type');
  ok(/if\s*\(\s*boundaryUncorroborated\s*\)/.test(callSite) &&
     /else\s*{[^}]*ctx\.waitUntil\(indexHoneypotHit/.test(callSite),
     'indexHoneypotHit must be in the ELSE branch of the uncorroborated check, not unconditional');
});

await test('the corroborating-tells set only accepts BODY evidence, not the boundary string itself', async () => {
  const setSrc = slice('const PHP2SHELL_CORROBORATING_TELLS', ';');
  ok(/upload-progress/.test(setSrc) && /php-object-injection/.test(setSrc) && /unserialize/.test(setSrc),
    'expected the three real-exploit body markers');
  ok(!/shellflow|NeoMM2026|VERIFY|Nuclei/.test(setSrc),
    'the corroboration set must not accept the boundary strings themselves as their own proof');
});

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);

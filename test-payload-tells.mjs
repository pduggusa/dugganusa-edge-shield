/**
 * The tarpit has to tell us what they SENT, not only which door they tried.
 *
 * Measured over 25,915 canary hits (30d to 2026-10-26) before 2.22.0:
 *   - 4,973 POSTs (19.2%), zero bodies captured, ever
 *   - 1,920 hits with a query string the markers never saw (getApplianceCanary takes pathname)
 *   - exploit_path fired ONCE, while the stored URLs held 332 traversals, 21 double-encoded
 *     and 19 phpinfo probes
 *
 * A GET sweep reading a path list and a POST carrying a working exploit are different animals
 * at the same door. Separating them is the left-of-boom instrument; the privacy line is that
 * we keep the TELL and never the credential.
 *
 *   node test-payload-tells.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
// safeDecode lives above; pull it in with the marker block.
const code = slice('function safeDecode', '// How a secret probe arrived');
const mod = await import('data:text/javascript,' + encodeURIComponent(
  code + '\nexport { urlTells, bodyTell, PAYLOAD_MARKERS, SECRET_FIELD_RX };'));
const { urlTells, bodyTell } = mod;

let pass = 0, fail = 0;
function test(name, fn) {
  return Promise.resolve().then(fn).then(() => { pass++; console.log('  ok  ', name); },
    (e) => { fail++; console.log('  FAIL', name, '\n      ', e.message); });
}
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m}: got ${JSON.stringify(a)} want ${JSON.stringify(b)}`); };
const has = (arr, v, m) => { if (!arr || !arr.includes(v)) throw new Error(`${m}: ${JSON.stringify(arr)} lacks ${v}`); };
const req = (method, ctype, body) => new Request('https://x.test/wp-login.php', {
  method, headers: ctype ? { 'content-type': ctype } : {}, ...(body === undefined ? {} : { body }),
});

await test('THE QUERY BUG: markers now see the query string, not just the path', async () => {
  eq(urlTells('/x', ''), [], 'clean request should tell nothing');
  has(urlTells('/x', '?file=../../etc/passwd'), 'traversal', 'traversal in QUERY was invisible before 2.22.0');
  has(urlTells('/x', '?f=%252e%252e%252f'), 'double-encoded', 'double-encoded in query');
  has(urlTells('/_profiler/phpinfo', ''), 'phpinfo', 'marker in path still works');
});

await test('the real shapes from the 30-day census are caught', async () => {
  has(urlTells('/cache/original/%2e%2e/.env', ''), 'traversal', 'the 332-hit shape');
  has(urlTells('/@fs/..%252f..%252f..%252froot/.env', '?raw'), 'double-encoded', 'the 21-hit shape');
});

await test('markers cover payload classes the census found zero of (because we were not looking)', async () => {
  has(urlTells('/x', '?id=1%20union%20select%201'), 'sqli', 'sqli');
  has(urlTells('/x', '?q=${jndi:ldap://a}'), 'jndi', 'log4shell');
  has(urlTells('/x', '?c=;cat%20/etc/passwd'), 'command-injection', 'command injection');
  has(urlTells('/x', '?d=O:8:"stdClass"'), 'php-object-injection', 'php object injection');
});

await test('GET has no body tell; a POST does', async () => {
  eq(await bodyTell(req('GET'), false), null, 'GET must not read a body');
  const t = await bodyTell(req('POST', 'application/x-www-form-urlencoded', 'a=1&b=2'), false);
  if (!t || t.body_bytes !== 7) throw new Error(`expected 7 bytes, got ${JSON.stringify(t)}`);
  eq(t.body_type, 'application/x-www-form-urlencoded', 'content type');
});

await test('field NAMES are kept; a marker in the body is reported', async () => {
  const t = await bodyTell(req('POST', 'application/x-www-form-urlencoded', 'user=bob&cmd=;whoami'), false);
  has(t.body_fields, 'user', 'field names');
  has(t.body_fields, 'cmd', 'field names');
  has(t.body_tells, 'command-injection', 'body marker');
});

await test('PRIVACY: a credential VALUE is never stored, in either mode', async () => {
  const body = 'username=bob&password=hunter2&csrf=abc';
  const off = await bodyTell(req('POST', 'application/x-www-form-urlencoded', body), false);
  eq(JSON.stringify(off).includes('hunter2'), false, 'default mode must not contain the password');
  if (!off.body_has_secret_field) throw new Error('a password field should be flagged as present');
  has(off.body_fields, 'password', 'the NAME is kept — that it is a login form is the signal');

  const on = await bodyTell(req('POST', 'application/x-www-form-urlencoded', body), true);
  eq(JSON.stringify(on).includes('hunter2'), false, 'even with sampling ON the value must be redacted');
  if (!on.body_sample.includes('[redacted]')) throw new Error('sample should carry a redaction marker');
});

await test('PRIVACY: JSON credential values are redacted too', async () => {
  const body = JSON.stringify({ user: 'bob', api_key: 'sk-live-12345', note: 'hi' });
  const on = await bodyTell(req('POST', 'application/json', body), true);
  eq(JSON.stringify(on).includes('sk-live-12345'), false, 'json secret value leaked');
  has(on.body_fields, 'api_key', 'json key names are kept');
});

await test('raw sampling is OFF unless explicitly enabled', async () => {
  const off = await bodyTell(req('POST', 'text/plain', 'hello world'), false);
  if (off.body_sample !== undefined) throw new Error('body_sample must be absent by default');
  const on = await bodyTell(req('POST', 'text/plain', 'hello world'), true);
  if (on.body_sample !== 'hello world') throw new Error('sample should appear when enabled');
});

await test('A TARPIT THAT THROWS IS NOT A TARPIT: a bad body never raises', async () => {
  const weird = new Request('https://x.test/a', { method: 'POST', body: new Uint8Array([0xff, 0xfe, 0x00, 0x01]) });
  const t = await bodyTell(weird, true);
  if (t === null || t === undefined) throw new Error('should return a tell, not nothing');
  if (typeof t.body_bytes !== 'number') throw new Error('should still report a length');
});

await test('RESOURCE EXHAUSTION: an oversized body is never buffered whole', async () => {
  // The first version called arrayBuffer() then sliced, capping the DECODE and not the READ.
  // A canary path is exactly where an attacker goes, so that pointed a memory lever at us.
  const big = 'A'.repeat(2 * 1024 * 1024); // 2 MB, 512x the 4 KB limit

  // With Content-Length, as a real HTTP request carries: the DECLARED size is recorded, never
  // how much we chose to read, or a 2 MB attempt would be filed as a 4 KB one.
  const withLen = new Request('https://x.test/wp-login.php', {
    method: 'POST', headers: { 'content-type': 'text/plain', 'content-length': String(big.length) }, body: big,
  });
  const t = await bodyTell(withLen, true);
  if (!t.body_truncated) throw new Error('a 2 MB body must be reported as truncated');
  if (t.body_read > 4096) throw new Error(`read ${t.body_read} bytes, must stop at 4096`);
  if (t.body_bytes !== big.length) throw new Error(`body_bytes ${t.body_bytes} should be the declared ${big.length}`);
  if (t.body_sample && t.body_sample.length > 512) throw new Error('sample must stay capped');

  // Without Content-Length (chunked), we must NOT claim to know the size. -2 means
  // "at least BODY_LIMIT, exact size unknown" — an honest unknown rather than a false 4096.
  const noLen = await bodyTell(req('POST', 'text/plain', big), false);
  if (!noLen.body_truncated) throw new Error('chunked oversize must still be truncated');
  if (noLen.body_bytes !== -2) throw new Error(`unknown length should be -2, got ${noLen.body_bytes}`);
  if (noLen.body_read > 4096) throw new Error('chunked read must also stop at the limit');
});

await test('a truncated body still yields markers from what was read', async () => {
  const payload = ';cat /etc/passwd' + 'B'.repeat(1024 * 1024);
  const t = await bodyTell(req('POST', 'text/plain', payload), false);
  if (!t.body_truncated) throw new Error('should be truncated');
  has(t.body_tells, 'command-injection', 'markers must still fire on the portion we read');
});

await test('an empty body is distinguishable from an unread one', async () => {
  const t = await bodyTell(req('POST', 'application/json', ''), false);
  eq(t.body_bytes, 0, 'empty body');
  if (t.body_tells) throw new Error('an empty body tells nothing');
});

await test('the worker wires it in and flags carried_payload', async () => {
  if (!/ctx\.waitUntil\(indexHoneypotHit\(env, request, cf, canary, tell\)\)/.test(src)) {
    throw new Error('indexHoneypotHit no longer receives the tell');
  }
  if (!/carried_payload: true/.test(src)) throw new Error('carried_payload flag missing');
  if (!/await bodyTell\(request/.test(src)) throw new Error('bodyTell must be awaited before the response closes');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

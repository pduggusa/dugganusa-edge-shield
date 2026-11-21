/**
 * IOC IP matching by value, not spelling (2.32.0).
 *
 * checkIOC compared exact IPv6 IOCs as strings, so "2001:DB8::1" or "2001:db8:0:0::1" from
 * cf-connecting-ip missed a feed row "2001:db8::1". Since 2026-11-21 canary IPv6 is kept off the
 * Cloudflare IP list (Cloudflare widens list items to /64), so this match is the only block those
 * hosts get on our zones. The parsers also accepted junk ("0x10" octets, 5-digit groups, two "::")
 * and mis-parsed IPv4-mapped addresses.
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it.
 *   node test-ioc-ip-match.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const a = src.indexOf('// --- CIDR support'), b = src.indexOf('function blockedResponse', a);
if (a < 0 || b < 0) throw new Error('could not locate the CIDR/checkIOC block in worker.js');
const lo = src.indexOf('if (ipsRes.ok) {'), hi = src.indexOf('if (domainsRes.ok) {', lo);
if (lo < 0 || hi < 0) throw new Error('could not locate the ips.csv loader in worker.js');
const loaderBody = src.slice(src.indexOf('{', lo) + 1, src.lastIndexOf('}', hi));

const make = new Function('ipsText', `
  let iocCache = { ips: new Set(), ips6: new Set(), ips4: new Set(), cidrs4: [], cidrs6: [], domains: new Set() };
  ${src.slice(a, b)}
  const ipsRes = { ok: true, text: async () => ipsText };
  return (async () => { ${loaderBody} ; return { checkIOC, ipv4ToInt, ipv6ToBigInt, iocCache }; })();
`);

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
};

const feed = [
  'ip,confidence,threat_type,source,first_seen',
  '2001:db8::1,95,scanner,edge-honeypot,2026-11-21',
  '2001:db8:a:b::5,95,scanner,edge-honeypot,2026-11-21',
  '203.0.113.9,90,c2,manual-batch-x,2026-11-21',
  '2001:db8:cafe::/48,85,c2,feed-x,2026-11-21',
  '198.51.100.0/24,85,c2,feed-x,2026-11-21',
  'not-an-ip,80,x,feed-x,2026-11-21',
].join('\n');
const { checkIOC, ipv4ToInt, ipv6ToBigInt, iocCache } = await make(feed);

// exact IPv6 by value
check('feed spelling matches', checkIOC('2001:db8::1'), true);
check('upper case matches', checkIOC('2001:DB8::1'), true);
check('expanded zeros match', checkIOC('2001:0db8:0000:0000:0000:0000:0000:0001'), true);
check('non-minimal :: placement matches', checkIOC('2001:db8:0:0::1'), true);
check('second v6 row, different spelling', checkIOC('2001:0DB8:000A:000B:0:0:0:5'), true);
check('neighbor in same /64 is NOT matched (exact rows never widen)', checkIOC('2001:db8::2'), false);
check('v6 CIDR still matches', checkIOC('2001:db8:cafe:1::1'), true);
// IPv4 and IPv4-mapped
check('exact IPv4 matches', checkIOC('203.0.113.9'), true);
check('IPv4 CIDR matches', checkIOC('198.51.100.77'), true);
check('::ffff:a.b.c.d matches the IPv4 row', checkIOC('::ffff:203.0.113.9'), true);
check('::ffff: hex form matches the IPv4 row', checkIOC('::ffff:cb00:7109'), true);
check('::ffff:a.b.c.d inside an IPv4 CIDR matches', checkIOC('::ffff:198.51.100.5'), true);
check('unlisted IPv4 does not match', checkIOC('203.0.113.10'), false);
// strict parsing: junk never matches, never throws
check('0x octet rejected', ipv4ToInt('0xcb.0.113.9'), null);
check('empty octet rejected', ipv4ToInt('203..113.9'), null);
check('5-digit group rejected', ipv6ToBigInt('2001:db8::10001'), null);
check('two :: rejected', ipv6ToBigInt('2001::db8::1'), null);
check('zone id rejected', ipv6ToBigInt('fe80::1%eth0'), null);
check(':: with 8 groups rejected', ipv6ToBigInt('1:2:3:4::5:6:7:8'), null);
check('bad mapped octet rejected', ipv6ToBigInt('::ffff:300.1.1.1'), null);
check('junk feed row not loaded as v6', iocCache.ips6.size, 2);
check('junk feed row not loaded as v4', iocCache.ips4.size, 1);
check('junk client IP no match', checkIOC('not-an-ip'), false);
check('mapped value is right', ipv6ToBigInt('::ffff:1.2.3.4') === ipv6ToBigInt('::ffff:102:304'), true);

console.log(`\nioc-ip-match: ${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);

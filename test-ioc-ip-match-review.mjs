/**
 * Adversarial review probes for the 2.32.0 IOC IP matcher (by-value IPv6, IPv4-mapped, strict parsers).
 * Same extraction harness as test-ioc-ip-match.mjs: the shipped code from src/worker.js, not a copy.
 * Each assertion states the SAFE behavior. A FAIL is a finding.
 *   node test-ioc-ip-match-review.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const a = src.indexOf('// --- CIDR support'), b = src.indexOf('function blockedResponse', a);
const lo = src.indexOf('if (ipsRes.ok) {'), hi = src.indexOf('if (domainsRes.ok) {', lo);
if (a < 0 || b < 0 || lo < 0 || hi < 0) throw new Error('could not locate shipped code');
const loaderBody = src.slice(src.indexOf('{', lo) + 1, src.lastIndexOf('}', hi));
const make = new Function('ipsText', `
  let iocCache = { ips: new Set(), ips6: new Set(), ips4: new Set(), cidrs4: [], cidrs6: [], domains: new Set() };
  ${src.slice(a, b)}
  const ipsRes = { ok: true, text: async () => ipsText };
  return (async () => { ${loaderBody} ; return { checkIOC, ipv4ToInt, ipv6ToBigInt, parseCidr, iocCache }; })();
`);

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got, (k, v) => typeof v === 'bigint' ? v.toString() : v) ===
             JSON.stringify(want, (k, v) => typeof v === 'bigint' ? v.toString() : v);
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${String(got)}, want ${String(want)})`}`);
};
const H = 'ip,confidence,threat_type,source,first_seen';
const row = (ip) => `${ip},90,c2,feed-x,2026-11-21`;

// ---------- over-blocking ----------
{
  const { checkIOC } = await make([H, row('1.2.3.4'), row('198.51.100.0/24'), row('2001:db8::1')].join('\n'));
  check('IPv4-COMPATIBLE ::1.2.3.4 does not match v4 row 1.2.3.4', checkIOC('::1.2.3.4'), false);
  check('::ffff:0:1.2.3.4 (SIIT translated) does not match v4 row', checkIOC('::ffff:0:1.2.3.4'), false);
  check('NAT64 64:ff9b::1.2.3.4 does not match v4 row', checkIOC('64:ff9b::1.2.3.4'), false);
  check('1::ffff:1.2.3.4 (not mapped: high bits set) does not match', checkIOC('1::ffff:1.2.3.4'), false);
  check('ffff:1.2.3.4 (no ::) does not match', checkIOC('ffff:1.2.3.4'), false);
  check('::ffff:198.51.101.1 outside the v4 /24 does not match', checkIOC('::ffff:198.51.101.1'), false);
  check('2001:db8::1:0 (adjacent) does not match 2001:db8::1', checkIOC('2001:db8::1:0'), false);
  check('2001:db8::10 does not match 2001:db8::1', checkIOC('2001:db8::10'), false);
  check('1:: (trailing ::) does not collide with ::1', checkIOC('1::'), false);
  check('::ffff:1.2.3.40 does not match 1.2.3.4', checkIOC('::ffff:1.2.3.40'), false);
}
{ // parser collision sweep: distinct canonical addresses must give distinct values
  const { ipv6ToBigInt } = await make(H);
  const forms = ['::', '::1', '1::', '1::1', '::1:0', '0:1::', '::ffff:0:0', '::ffff:1.2.3.4',
    '::1.2.3.4', '::ffff:0:1.2.3.4', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8',
    '1:2:3:4:5:6:1.2.3.4', 'ffff::', '::ffff', 'ffff::1.2.3.4'];
  const seen = new Map(); let dup = null;
  for (const f of forms) { const v = ipv6ToBigInt(f); if (v === null) { dup = `${f} -> null`; break; }
    if (seen.has(v)) { dup = `${f} == ${seen.get(v)}`; break; } seen.set(v, f); }
  check('no two distinct valid forms parse to the same value', dup, null);
  check('1:2:3:4:5:6:1.2.3.4 == 1:2:3:4:5:6:102:304', ipv6ToBigInt('1:2:3:4:5:6:1.2.3.4') === ipv6ToBigInt('1:2:3:4:5:6:102:304'), true);
  check('dotted quad in the middle rejected', ipv6ToBigInt('::1.2.3.4:5'), null);
  check('9 groups via dotted tail rejected', ipv6ToBigInt('1:2:3:4:5:6:7:1.2.3.4'), null);
  check('leading single colon rejected', ipv6ToBigInt(':1::'), null);
  check('trailing single colon rejected', ipv6ToBigInt('1:2:3:4:5:6:7:8:'), null);
  check(':::  rejected', ipv6ToBigInt(':::'), null);
  check('7 groups without :: rejected', ipv6ToBigInt('1:2:3:4:5:6:7'), null);
}
{ // ::/0-like CIDRs: a feed row like this would block every v6 client (pre-existing, not new)
  const { parseCidr } = await make(H);
  check('INFO ::/0 parses (pre-existing: feed hygiene must keep it out)', parseCidr('::/0') !== null, true);
  check('INFO 0.0.0.0/0 parses (pre-existing)', parseCidr('0.0.0.0/0') !== null, true);
}

// ---------- under-blocking / regressions ----------
{
  const { checkIOC, ipv4ToInt, ipv6ToBigInt, parseCidr } = await make(H);
  check('uppercase hex parses', ipv6ToBigInt('2001:DB8::ABCD') === ipv6ToBigInt('2001:db8::abcd'), true);
  check(':: alone parses to 0', ipv6ToBigInt('::'), 0n);
  check('::1 parses to 1', ipv6ToBigInt('::1'), 1n);
  check('full 8-group parses', ipv6ToBigInt('2001:db8:0:0:0:0:0:1') === ipv6ToBigInt('2001:db8::1'), true);
  check('4-digit leading-zero group parses', ipv6ToBigInt('2001:0db8::0001') === ipv6ToBigInt('2001:db8::1'), true);
  check('255.255.255.255 parses', ipv4ToInt('255.255.255.255'), 4294967295);
  check('0.0.0.0 parses', ipv4ToInt('0.0.0.0'), 0);
  check('256 octet rejected', ipv4ToInt('256.1.1.1'), null);
  check('999 octet rejected', ipv4ToInt('999.1.1.1'), null);
  check('high-bit v4 correct', ipv4ToInt('203.0.113.9'), 0xcb007109);
  check('CIDR 1.2.3.0/24 parses', JSON.stringify(parseCidr('1.2.3.0/24')), JSON.stringify({ v6: false, base: 0x01020300, mask: 0xffffff00 }));
  check('CIDR 2001:db8::/32 parses', parseCidr('2001:db8::/32')?.v6, true);
  check('CIDR /32 host parses', parseCidr('1.2.3.4/32')?.base, 0x01020304);
  check('CIDR ::ffff:1.2.3.0/120 parses', parseCidr('::ffff:1.2.3.0/120')?.v6, true);
  check('checkIOC never throws on odd input', [':', '::::::', '.', '1.2.3.4.5', '%', 'a'.repeat(50)].map(checkIOC).every((x) => x === false), true);
}
{ // FINDING-L1: non-canonical v4 feed row -> mapped client blocked, native v4 client not
  const { checkIOC } = await make([H, row('010.1.1.1')].join('\n'));
  check('[L1] feed "010.1.1.1": native and mapped spellings agree', checkIOC('10.1.1.1'), checkIOC('::ffff:10.1.1.1'));
}
{ // FINDING-L2: mapped v6 feed row does not cover the native v4 client (asymmetric with the new mapped path)
  const { checkIOC } = await make([H, row('::ffff:1.2.3.4'), row('::ffff:5.6.7.0/120')].join('\n'));
  check('[L2] feed "::ffff:1.2.3.4" also blocks native 1.2.3.4', checkIOC('1.2.3.4'), true);
  check('[L2] feed "::ffff:5.6.7.0/120" also blocks native 5.6.7.8', checkIOC('5.6.7.8'), true);
}
{ // FINDING-L3: old parser accepted whitespace inside the base; strict one drops the CIDR row
  const { parseCidr, iocCache } = await make([H, row('1.2.3.0 /24')].join('\n'));
  // L3 ACCEPTED (2.32.0): strict parsing rejects a space inside a CIDR value; the feed never emits one.
  check('[L3/ACCEPTED] "1.2.3.0 /24" is rejected by the strict parser', iocCache.cidrs4.length, 0);
}
{ // loader keeps only parseable rows, but CRLF and padding are trimmed first
  const { iocCache, checkIOC } = await make([H, '1.2.3.4,90,c2,x,y\r', ' 5.6.7.8 ,90,c2,x,y', '2001:db8::9\r'].join('\n'));
  check('CRLF / padded rows still load', [iocCache.ips4.size, iocCache.ips6.size], [2, 1]);
  check('padded v4 row matches canonical client', checkIOC('5.6.7.8'), true);
}

// ---------- performance ----------
{
  const rows = [H];
  for (let i = 0; i < 10000; i++) rows.push(row(`10.${(i >> 8) & 255}.${i & 255}.1`));
  for (let i = 0; i < 2000; i++) rows.push(row(`2001:db8:${i.toString(16)}::1`));
  for (let i = 0; i < 2000; i++) rows.push(row(`172.${16 + (i >> 8)}.${i & 255}.0/24`));
  for (let i = 0; i < 500; i++) rows.push(row(`2001:db9:${i.toString(16)}::/48`));
  const { checkIOC } = await make(rows.join('\n'));
  const N = 20000;
  let t = performance.now(); for (let i = 0; i < N; i++) checkIOC('2600:1f18::' + (i % 65535).toString(16)); const v6us = (performance.now() - t) * 1000 / N;
  t = performance.now(); for (let i = 0; i < N; i++) checkIOC('::ffff:8.8.' + (i & 255) + '.1'); const m4us = (performance.now() - t) * 1000 / N;
  t = performance.now(); for (let i = 0; i < N; i++) checkIOC('8.8.' + (i & 255) + '.1'); const v4us = (performance.now() - t) * 1000 / N;
  console.log(`      per-call miss cost: v6 ${v6us.toFixed(1)}us, mapped ${m4us.toFixed(1)}us, v4 ${v4us.toFixed(1)}us (2000 v4 CIDRs, 500 v6 CIDRs)`);
  check('v6 miss < 200us with 500 v6 CIDRs', v6us < 200, true);
  check('mapped miss < 200us', m4us < 200, true);
  const evil = [':' + '1:'.repeat(50000) + '1.1.1', '1'.repeat(100000) + ':', ':'.repeat(100000), '::ffff:' + '1.'.repeat(50000) + '1'];
  t = performance.now(); for (const e of evil) checkIOC(e); const ms = performance.now() - t;
  console.log(`      100KB pathological inputs: ${ms.toFixed(1)}ms total`);
  check('pathological 100KB inputs < 50ms total (no regex blowup)', ms < 50, true);
}

console.log(`\nioc-ip-match-review: ${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);

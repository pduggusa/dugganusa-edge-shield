/**
 * Test the verified-crawler allowlist against REAL DNS.
 *
 * Extracts the shipped logic out of src/worker.js rather than reimplementing it,
 * so a drift between this test and what actually runs cannot hide.
 *
 * The cases that matter are the FALSE ones: an impostor claiming to be Googlebot
 * from a rented cloud box is the whole attack this allowlist could otherwise open
 * up, so it is tested with real IPs and real resolution, not mocks.
 *
 *   node test-crawler-verify.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
const code = slice('const CRAWLER_UA_TO_DOMAINS', '// ================================================================\n// IN-MEMORY IOC CACHE');
const mod = await import('data:text/javascript,' + encodeURIComponent(code + '\nexport { isVerifiedCrawler, CRAWLER_UA_TO_DOMAINS, ptrName, expandIPv6 };'));

const req = (ua, ip) => ({ headers: { get: (h) => (h === 'user-agent' ? ua : h === 'cf-connecting-ip' ? ip : null) } });

const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36';

const cases = [
  // The attack this allowlist must not open: a rented box claiming to be Googlebot.
  ['impostor: Googlebot UA from a Google CLOUD box (not Googlebot)', GOOGLEBOT_UA, '34.174.192.151', {}, false],
  ['impostor: Googlebot UA from an AWS box',                          GOOGLEBOT_UA, '47.128.119.165', {}, false],
  ['impostor: Googlebot UA from a Tencent box',                       GOOGLEBOT_UA, '43.155.9.179',   {}, false],
  // Real Googlebot — forward-confirmed rDNS must pass.
  ['real: Googlebot from crawl-66-249-66-1.googlebot.com',            GOOGLEBOT_UA, '66.249.66.1',    {}, true],
  // Ordinary traffic is not a crawler and must not be allowlisted.
  ['ordinary Chrome UA is not a crawler',                             CHROME_UA,    '34.174.192.151', {}, false],
  ['empty UA is not a crawler',                                       '',           '1.2.3.4',        {}, false],
  // Cloudflare's own verdict is authoritative and skips DNS entirely.
  ['CF verifiedBot flag short-circuits to allow',                     GOOGLEBOT_UA, '203.0.113.9', { botManagement: { verifiedBot: true } }, true],
  // Deliberate exclusion.
  ['Bytespider is deliberately NOT allowlisted', 'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)', '110.249.201.1', {}, false],
];

let pass = 0, fail = 0;
const check = (label, got, want) => {
  if (got === want) { pass++; console.log(`  ✅ ${label}`); }
  else { fail++; console.log(`  ❌ ${label}\n       want ${want}, got ${got}`); }
};

for (const [label, ua, ip, cf, want] of cases) {
  let got;
  try { got = await mod.isVerifiedCrawler(req(ua, ip), cf); }
  catch (e) { got = `ERROR ${e.message}`; }
  check(label, got, want);
}

// --- FAIL-CLOSED regression suite -------------------------------------------
// The first cut of isVerifiedCrawler failed OPEN on missing IP, on IPv6, and on
// any DNS exception. Because the UA gate is the only thing upstream, that made
// the entire shield — scanner detection, IOC blocking, honeypot AND rate limit —
// bypassable by setting a header and connecting over IPv6. These cases exist so
// that hole cannot be reintroduced quietly.
console.log('\nFail-closed regression suite\n');

check('no client IP → NOT verified (was: fail open)',
  await mod.isVerifiedCrawler(req(GOOGLEBOT_UA, ''), {}), false);

check('IPv6 impostor claiming Googlebot → NOT verified (was: fail open)',
  await mod.isVerifiedCrawler(req(GOOGLEBOT_UA, '2a03:2880:f802:37::1'), {}), false);

check('garbage IP claiming Googlebot → NOT verified',
  await mod.isVerifiedCrawler(req(GOOGLEBOT_UA, 'not-an-ip'), {}), false);

check('out-of-range octets claiming Googlebot → NOT verified',
  await mod.isVerifiedCrawler(req(GOOGLEBOT_UA, '999.1.1.1'), {}), false);

// IPv6 is genuinely supported now, not skipped — Meta's crawler is largely IPv6.
check('IPv6 PTR is nibble-form under ip6.arpa (not skipped)',
  mod.ptrName('2a03:2880:f802:37::1'),
  '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.3.0.0.2.0.8.f.0.8.8.2.3.0.a.2.ip6.arpa');

check('IPv6 expansion pads and fills correctly',
  mod.expandIPv6('2a03:2880:f802:37::1'), '2a032880f80200370000000000000001');

check('IPv4 PTR is in-addr.arpa', mod.ptrName('66.249.66.1'), '1.66.249.66.in-addr.arpa');

// --- Policy exclusions: these must NEVER be allowlisted ----------------------
// Meta, Yandex and Bytespider are declined by decision, not by accident
// (Patrick, 2026-08-16: "meta and yandex are fine in the sin bin"). These cases
// exist so a future well-meaning edit that re-adds them fails the suite loudly.
const META_UA = 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)';
const YANDEX_UA = 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)';

check('GENUINE Meta (AS32934) is still NOT allowlisted — policy exclusion',
  await mod.isVerifiedCrawler(req(META_UA, '2a03:2880:f800:42::'), { asn: 32934 }), false);

check('facebookexternalhit is not allowlisted — policy exclusion',
  await mod.isVerifiedCrawler(req('facebookexternalhit/1.1', '2a03:2880:f800:42::'), { asn: 32934 }), false);

check('YandexBot is not allowlisted — policy exclusion',
  await mod.isVerifiedCrawler(req(YANDEX_UA, '5.255.253.1'), {}), false);

check('policy exclusions are absent from the allowlist table',
  ['meta-externalagent','facebookexternalhit','yandexbot','bytespider']
    .some(u => mod.CRAWLER_UA_TO_DOMAINS.some(c => c.ua === u)), false);

check('Googlebot UA does NOT get an ASN shortcut (AS15169 is rentable)',
  await mod.isVerifiedCrawler(req(GOOGLEBOT_UA, '34.145.203.169'), { asn: 15169 }), false);

console.log(`\npass ${pass} | fail ${fail}`);
process.exit(fail ? 1 : 0);

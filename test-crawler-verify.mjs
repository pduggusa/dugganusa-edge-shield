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
const mod = await import('data:text/javascript,' + encodeURIComponent(code + '\nexport { isVerifiedCrawler, CRAWLER_UA_TO_DOMAINS };'));

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
for (const [label, ua, ip, cf, want] of cases) {
  let got;
  try { got = await mod.isVerifiedCrawler(req(ua, ip), cf); }
  catch (e) { got = `ERROR ${e.message}`; }
  if (got === want) { pass++; console.log(`  ✅ ${label}`); }
  else { fail++; console.log(`  ❌ ${label}\n       want ${want}, got ${got}`); }
}
console.log(`\npass ${pass} | fail ${fail}`);
process.exit(fail ? 1 : 0);

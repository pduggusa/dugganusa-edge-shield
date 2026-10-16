/**
 * honeypot_meta carries Cloudflare's verified-bot category (2.14.2), never the dead bot_score.
 *
 * Extracts the shipped helper out of src/worker.js rather than reimplementing it, so a drift
 * between this test and what actually runs cannot hide.
 *
 *   node test-honeypot-meta.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const a = src.indexOf('function cfVerifiedCategory'), b = src.indexOf('async function isVerifiedCrawler', a);
if (a < 0 || b < 0) throw new Error('could not locate cfVerifiedCategory in worker.js');
const { cfVerifiedCategory } = await import('data:text/javascript,' + encodeURIComponent(src.slice(a, b) + '\nexport { cfVerifiedCategory };'));

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  if (got === want) { pass++; console.log(`  ok  ${name}`); }
  else { fail++; console.log(`  FAIL ${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); }
};

eq('verified category passes through', cfVerifiedCategory({ verifiedBotCategory: 'AI Crawler' }), 'AI Crawler');
eq('empty string (Pro, not verified) is null', cfVerifiedCategory({ verifiedBotCategory: '' }), null);
eq('absent field is null', cfVerifiedCategory({}), null);
eq('"Not Verified" sentinel is null', cfVerifiedCategory({ verifiedBotCategory: 'Not Verified' }), null);
eq('non-string is null', cfVerifiedCategory({ verifiedBotCategory: 7 }), null);
eq('null cf is null (never throws)', cfVerifiedCategory(null), null);
eq('whitespace trimmed', cfVerifiedCategory({ verifiedBotCategory: ' Search Engine Crawler ' }), 'Search Engine Crawler');
eq('length capped at 64', cfVerifiedCategory({ verifiedBotCategory: 'x'.repeat(200) }).length, 64);

// The honeypot IOC builder: new field present, dead field gone.
const meta = src.slice(src.indexOf('honeypot_meta: {'), src.indexOf('// Fire and forget'));
eq('honeypot_meta records cf_verified_bot_category', /cf_verified_bot_category:\s*cfVerifiedCategory\(cf\)/.test(meta), true);
eq('honeypot_meta no longer writes bot_score', /^\s*bot_score:/m.test(meta), false);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

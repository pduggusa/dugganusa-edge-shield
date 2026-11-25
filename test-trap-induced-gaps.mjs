// OWASP round 3, W1 (2026-11-25): induced requests that used to pass trapLooksInduced(). Each asserts
// the SAFE behavior. Run: node test-trap-induced-gaps.mjs  (optional arg: path to worker.js)
import { readFileSync } from 'node:fs';
const src = readFileSync(process.argv[2] || new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (a, b) => { const i = src.indexOf(a), j = src.indexOf(b, i); return src.slice(i, j); };
const T = new Function([
  slice('function cfVerifiedCategory(', 'async function isVerifiedCrawler('),
  slice('const TRAP_INDUCED_UA', 'function trapWideKey('),
  'return { trapLooksInduced };'].join('\n'))();
const req = (h, method = 'GET') => ({ method, headers: new Headers(h) });
let fail = 0; const t = (n, ok) => { console.log((ok ? '  ok ' : '  FAIL ') + n); if (!ok) fail++; };
// 1. One toot with the link => every federated instance fetches a preview (no Sec-Fetch, Accept text/html).
t('Mastodon link-preview fetch is screened', T.trapLooksInduced(req({ 'user-agent': 'http.rb/5.2.0 (Mastodon/4.3.2; +https://mastodon.social/)', accept: 'text/html' }), {}));
t('Bluesky card fetch is screened', T.trapLooksInduced(req({ 'user-agent': 'Mozilla/5.0 (compatible; Bluesky Cardyb/1.1; +mailto:support@bsky.app)' }), {}));
t('Matrix Synapse preview is screened', T.trapLooksInduced(req({ 'user-agent': 'Synapse (bot; +https://github.com/element-hq/synapse)' }), {}));
t('Mattermost preview is screened', T.trapLooksInduced(req({ 'user-agent': 'Mattermost-Bot/1.1' }), {}));
// 2. <script src>/<iframe> on an attacker page, visitor on Safari < 16.4 (no Sec-Fetch-* headers, carries "Safari/").
t('old-Safari <script src> subresource is screened', T.trapLooksInduced(req({ 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1', accept: '*/*' }), {}));
for (const ua of ['Mozilla/5.0 (compatible; Zoombot/1.0)', 'kakaotalk-scrap/1.0 (+https://devtalk.kakao.com/)', 'Discourse Forum Onebox v3.3.0', 'Mozilla/5.0 (Linux) (Nextcloud, 30.0.0)'])
  t(`previewer screened: ${ua}`, T.trapLooksInduced(req({ 'user-agent': ua }), {}));
t('old-Firefox <iframe>/<script> subresource (no Sec-Fetch, Accept */*) is screened', T.trapLooksInduced(req({ 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0', accept: '*/*' }), {}));
// Controls: what the trap is FOR still files.
t('control: a scripted scanner (python-requests) is NOT screened', !T.trapLooksInduced(req({ 'user-agent': 'python-requests/2.31.0', accept: '*/*' }), {}));
t('control: ZoomEye (a scanner) is NOT screened as Zoom', !T.trapLooksInduced(req({ 'user-agent': 'Mozilla/5.0 (compatible; ZoomEye/1.0)' }), {}));
// 3. ACCEPTED RESIDUAL (CHANGELOG 2.36.0): a URL submitted to a public scanner (urlscan.io-style headless
// Chrome, top-level nav, Sec-Fetch-Site: none) is indistinguishable from a typed or clicked navigation.
// It files a sub-floor, unpromoted record. Asserted so a change in this behavior is noticed.
t('accepted residual: a typed/clicked navigation (Sec-Fetch-Site: none) cannot be screened', !T.trapLooksInduced(req({ 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'sec-fetch-site': 'none', accept: 'text/html' }), {}));
console.log(`\n${fail ? 'FAILED' : 'all passed'}`);
process.exit(fail ? 1 : 0);

/**
 * Test the NetScaler appliance canaries and the canary decode guard.
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it,
 * same as test-crawler-verify.mjs, so the test cannot drift from what runs.
 *
 * The cases that matter most are the ones that must NOT trap: a customer's own
 * NetScaler behind this Worker, real site paths, and the existing canaries that
 * must keep precedence.
 *
 *   node test-appliance-canaries.mjs
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
  code + '\nexport { getCanary, getApplianceCanary, applianceCanariesEnabled, netscalerResponse, fortigateResponse, safeDecode };'));
const { getCanary, getApplianceCanary, applianceCanariesEnabled, netscalerResponse, fortigateResponse } = mod;

// The same precedence the fetch handler uses.
const pick = (env, host, path) =>
  getCanary(path) || (applianceCanariesEnabled(env, host) ? getApplianceCanary(path) : null);

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${got}, want ${want})`}`);
};
const kind = (c) => (c ? c.type : null);

// Own zones: canaries on by default.
for (const p of ['/vpn/index.html', '/vpn', '/vpns/cfg/smb.conf', '/logon/LogonPoint/tmindex.html',
                 '/nf/auth/doAuthentication.do', '/gwtest/formssso', '/Citrix/XenApp', '/epa/scripts/win/nsepa_setup.exe',
                 '/oauth/idp/.well-known/openid-configuration', '/cgi/login', '/saml/login', '/menu/ss', '/menu/neo',
                 '/menu/stc', '/vpn/js/rdx/core/lang/rdx_en.json.gz', '/VPN/INDEX.HTML']) {
  check(`own zone traps ${p}`, kind(pick({}, 'analytics.dugganusa.com', p)), 'netscaler_scan');
}
check('apex dugganusa.com traps', kind(pick({}, 'dugganusa.com', '/vpn/index.html')), 'netscaler_scan');
check('aipmsec.com traps', kind(pick({}, 'www.aipmsec.com', '/logon/LogonPoint/index.html')), 'netscaler_scan');

// Customer zones: a real NetScaler must never be answered by a decoy.
check('customer host does NOT trap by default', kind(pick({}, 'vpn.customer.example', '/vpn/index.html')), null);
check('lookalike host does NOT trap', kind(pick({}, 'evildugganusa.com', '/vpn/index.html')), null);
check('lookalike suffix host does NOT trap', kind(pick({}, 'dugganusa.com.attacker.net', '/vpn/index.html')), null);
check('customer opt-in traps', kind(pick({ APPLIANCE_CANARIES: 'true' }, 'vpn.customer.example', '/vpn/index.html')), 'netscaler_scan');
check('"false" disables even on own zone', kind(pick({ APPLIANCE_CANARIES: 'false' }, 'analytics.dugganusa.com', '/vpn/index.html')), null);

// Real paths pass through.
for (const p of ['/', '/post/some-real-slug', '/menu', '/menus/ss', '/cgi/logout', '/vpnx', '/api/v1/stix-feed/domains.csv', '/oauth/token']) {
  check(`real path passes: ${p}`, kind(pick({}, 'www.dugganusa.com', p)), null);
}

// Existing canaries keep precedence.
check('/vpn/%2eenv stays a config probe', kind(pick({}, 'analytics.dugganusa.com', '/vpn/%2eenv')), 'config_probe');
check('/saml/%2eenv stays a config probe', kind(pick({}, 'analytics.dugganusa.com', '/saml/%2eenv')), 'config_probe');

// A malformed escape must not throw.
let threw = false;
try { getCanary('/foo/%E0%A4%A'); getApplianceCanary('/vpn/%E0%A4%A'); } catch { threw = true; }
check('malformed escape does not throw', threw, false);
check('malformed escape under /vpn/ still traps', kind(getApplianceCanary('/vpn/%E0%A4%A')), 'netscaler_scan');

// Tagging + response shape.
check('product tag set', getApplianceCanary('/vpn/index.html').product, 'citrix-netscaler');
const r = netscalerResponse();
check('response 200', r.status, 200);
check('NSC_TEMP cookie set', /^NSC_TEMP=/.test(r.headers.get('set-cookie') || ''), true);
check('no nginx misdirection header', r.headers.get('server'), null);
check('title says NetScaler Gateway', (await r.text()).includes('<title>NetScaler Gateway</title>'), true);

// ---- Fortinet FortiGate (2026-10-06) ----
for (const p of ['/remote/login', '/remote/login?lang=en', '/remote/logincheck', '/remote/fgt_lang',
                 '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession', '/remote/saml/start',
                 '/remote/info', '/api/v2/cmdb/system/admin', '/api/v2/monitor/system/status', '/ng/', '/REMOTE/LOGIN', '/remote',
                 '/%72emote/login']) {
  check(`own zone traps FortiGate ${p}`, kind(pick({}, 'analytics.dugganusa.com', p.split('?')[0])), 'fortinet_scan');
}
check('customer FortiGate NOT trapped by default', kind(pick({}, 'vpn.customer.example', '/remote/login')), null);
check('customer opt-in traps FortiGate', kind(pick({ APPLIANCE_CANARIES: 'true' }, 'vpn.customer.example', '/remote/login')), 'fortinet_scan');
check('"false" disables FortiGate on own zone', kind(pick({ APPLIANCE_CANARIES: 'false' }, 'www.dugganusa.com', '/remote/login')), null);
for (const p of ['/login', '/remotes/login', '/api/v2/', '/api/v2/stix', '/api/v1/finops/report', '/ngx', '/.env.fortify']) {
  check(`not a FortiGate trap: ${p}`, kind(pick({}, 'www.dugganusa.com', p)) === 'fortinet_scan', false);
}
check('FortiGate product tag', getApplianceCanary('/remote/login').product, 'fortinet-fortigate');
check('NetScaler unaffected', kind(getApplianceCanary('/vpn/index.html')), 'netscaler_scan');
const fr = fortigateResponse();
check('FortiGate response 200', fr.status, 200);
check('SVPNCOOKIE set', /^SVPNCOOKIE=/.test(fr.headers.get('set-cookie') || ''), true);
check('form posts to /remote/logincheck', (await fr.text()).includes('action="/remote/logincheck"'), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

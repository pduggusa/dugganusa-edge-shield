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
  code + '\nexport { getCanary, getApplianceCanary, applianceCanariesEnabled, netscalerResponse, fortigateResponse, ivantiResponse, ciscoResponse, paloResponse, sonicwallResponse, safeDecode };'));
const { getCanary, getApplianceCanary, applianceCanariesEnabled, netscalerResponse, fortigateResponse, ivantiResponse, ciscoResponse, paloResponse, sonicwallResponse } = mod;

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

// Ivanti Connect Secure (2.10.0)
for (const p of ['/dana-na/auth/url_default/welcome.cgi', '/dana-ws/metadata', '/dana-cached/hc/HostCheckerInstaller.osx', '/dana/home/index.cgi', '/DANA-NA/auth/saml-sso.cgi', '/dana']) {
  check(`Ivanti trap: ${p}`, kind(pick({}, 'www.dugganusa.com', p)), 'ivanti_scan');
}
check('Ivanti product tag', getApplianceCanary('/dana-na/').product, 'ivanti-connect-secure');
check('Ivanti exploit marker on traversal', getApplianceCanary('/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd').exploit_path, true);
check('Ivanti encoded-path marker', getApplianceCanary('/%64ana-na/auth/url_default/welcome.cgi').encoded_path, true);
check('plain Ivanti probe carries no exploit marker', getApplianceCanary('/dana-na/auth/url_default/welcome.cgi').exploit_path, undefined);
for (const p of ['/api/v1/totp/user-backup-code', '/api/v1/configuration/users', '/api/v1/license/keys-status', '/api/v1/search/stats', '/danawhite', '/post/dana-na-explained']) {
  check(`not an Ivanti trap: ${p}`, kind(pick({}, 'www.dugganusa.com', p)) === 'ivanti_scan', false);
}
check('customer Ivanti NOT trapped by default', kind(pick({}, 'vpn.customer.example', '/dana-na/')), null);
check('customer opt-in traps Ivanti', kind(pick({ APPLIANCE_CANARIES: 'true' }, 'vpn.customer.example', '/dana-na/')), 'ivanti_scan');
const ir = ivantiResponse();
check('Ivanti response 200', ir.status, 200);
check('DSSignInURL set', /^DSSignInURL=/.test(ir.headers.get('set-cookie') || ''), true);
check('form posts to login.cgi', (await ir.text()).includes('action="/dana-na/auth/url_default/login.cgi"'), true);

// Cisco (2.11.0)
const ciscoCases = { '/+CSCOE+/logon.html': 'cisco-asa-webvpn', '/+webvpn+/index.html': 'cisco-asa-webvpn', '/CSCOSSLC/config-auth': 'cisco-asa-webvpn',
  '/webui/logoutconfirm.html': 'cisco-iosxe-webui', '/api/fmc_platform/v1/auth/generatetoken': 'cisco-fmc', '/ers/sdk': 'cisco-ise',
  '/dataservice/device': 'cisco-sdwan-manager', '/j_security_check': 'cisco-sdwan-manager', '/ccmadmin/showHome.do': 'cisco-unified-cm',
  '/cucm-uds/users': 'cisco-unified-cm', '/webdialer/Webdialer': 'cisco-unified-cm' };
for (const [p, prod] of Object.entries(ciscoCases)) {
  check(`Cisco trap: ${p}`, kind(pick({}, 'analytics.dugganusa.com', p)), 'cisco_scan');
  check(`Cisco product: ${p}`, getApplianceCanary(p).product, prod);
}
check('Cisco exploit marker: IOS XE logon_hash', getApplianceCanary('/webui/logoutconfirm.html?logon_hash=1').exploit_path, true);
check('Cisco exploit marker: UCM installClusterStatusExecute', getApplianceCanary('/cmplatform/installClusterStatusExecute').exploit_path, true);
check('plain Cisco probe no exploit marker', getApplianceCanary('/ccmadmin/showHome.do').exploit_path, undefined);
// Palo Alto (2.11.0)
for (const p of ['/global-protect/login.esp', '/global-protect/prelogin.esp', '/ssl-vpn/hipreport.esp', '/php/login.php', '/php/ztp_gate.php', '/unauth/%252e%252e/php/ztp_gate.php']) {
  check(`Palo Alto trap: ${p}`, kind(pick({}, 'analytics.dugganusa.com', p)), 'paloalto_scan');
}
check('GlobalProtect product', getApplianceCanary('/global-protect/portal/').product, 'paloalto-globalprotect');
check('PAN-OS mgmt product', getApplianceCanary('/php/login.php').product, 'paloalto-panos-mgmt');
check('PAN-OS exploit marker ztp_gate', getApplianceCanary('/php/ztp_gate.php').exploit_path, true);
check('GlobalProtect exploit marker hipreport', getApplianceCanary('/ssl-vpn/hipreport.esp').exploit_path, true);
check('PAN-OS encoded marker', getApplianceCanary('/unauth/%252e%252e/php/ztp_gate.php').encoded_path, true);
// must NOT trap (real routes / generic shapes on our zones)
for (const p of ['/api/v1/search/stats', '/api/scheduler/jobs', '/api/fmc', '/admin/login', '/status', '/guest/', '/portal/', '/auth/login', '/phpmyadmin-x', '/phpinfo', '/webuix', '/erss', '/dataservices']) {
  const k = kind(pick({}, 'analytics.dugganusa.com', p));
  check(`not a Cisco/Palo trap: ${p}`, k === 'cisco_scan' || k === 'paloalto_scan', false);
}
check('phpMyAdmin canary keeps precedence', kind(pick({}, 'analytics.dugganusa.com', '/phpmyadmin/')), 'admin_scan');
check('customer Cisco NOT trapped by default', kind(pick({}, 'vpn.customer.example', '/+CSCOE+/logon.html')), null);
check('customer Palo NOT trapped by default', kind(pick({}, 'vpn.customer.example', '/global-protect/login.esp')), null);
const asa = ciscoResponse('cisco-asa-webvpn');
check('ASA decoy 200 + webvpnlogin cookie', asa.status === 200 && /^webvpnlogin=/.test(asa.headers.get('set-cookie') || ''), true);
check('FMC decoy answers 401 JSON', ciscoResponse('cisco-fmc').status, 401);
const pre = paloResponse('globalprotect', '/global-protect/prelogin.esp');
check('GlobalProtect prelogin answers XML', (pre.headers.get('content-type') || '').includes('xml') && (await pre.text()).includes('<prelogin-response>'), true);
const gp = paloResponse('globalprotect', '/global-protect/login.esp');
check('GlobalProtect portal title', (await gp.text()).includes('<title>GlobalProtect Portal</title>'), true);
check('PAN-OS mgmt PHPSESSID', /^PHPSESSID=/.test(paloResponse('panos', '/php/login.php').headers.get('set-cookie') || ''), true);

// SonicWall SMA1000 (2.12.0) — CVE-2026-102255 WorkPlace/Extraweb CouchDB SSRF
for (const p of ['/workplace/', '/workplace/access/home', '/WorkPlace/', '/__api__/login', '/__api__/logout',
                 '/__extraweb__/x', '/workplace/extraweb/_rewrite', '/foo/_rewrite', '/x?u=http://127.0.0.1:5984/',
                 '/proxy/127.0.0.1%3A5984/_utils']) {
  check(`SonicWall trap: ${p}`, kind(pick({}, 'analytics.dugganusa.com', p)), 'sonicwall_scan');
}
// Previdian's published 10-09 capture: OPTIONS to /__EXTRAWEB__TRANSLATE/.../../u/_design/<id>/_rewrite/.../__extraweb__
const prev = getApplianceCanary('/__EXTRAWEB__TRANSLATE/a/../u/_design/abc/_rewrite/x/__extraweb__');
check('Previdian capture shape traps with exploit marker', prev && prev.type === 'sonicwall_scan' && prev.exploit_path === true, true);
check('SonicWall product tag', getApplianceCanary('/workplace/').product, 'sonicwall-sma1000');
check('SonicWall exploit marker on _rewrite', getApplianceCanary('/workplace/extraweb/_db/_design/x/_rewrite').exploit_path, true);
check('SonicWall exploit marker on :5984', getApplianceCanary('/extraweb/http://127.0.0.1:5984/').exploit_path, true);
check('plain WorkPlace probe carries no exploit marker', getApplianceCanary('/workplace/access/home').exploit_path, undefined);
for (const p of ['/post/cve-2026-15984-something', '/api/v1/search/stats', '/_api/blog', '/workplaces', '/__api', '/api/login',
                 '/post/extra-web-security']) {
  check(`not a SonicWall trap: ${p}`, kind(pick({}, 'www.dugganusa.com', p)) === 'sonicwall_scan', false);
}
check('customer SonicWall NOT trapped by default', kind(pick({}, 'vpn.customer.example', '/workplace/')), null);
check('customer opt-in traps SonicWall', kind(pick({ APPLIANCE_CANARIES: 'true' }, 'vpn.customer.example', '/__api__/login')), 'sonicwall_scan');
check('Ivanti still wins its own prefix', kind(pick({}, 'www.dugganusa.com', '/dana-na/auth/')), 'ivanti_scan');
const sw = sonicwallResponse('/workplace/');
check('WorkPlace decoy 200 + title', sw.status === 200 && (await sw.text()).includes('<title>WorkPlace - Log in</title>'), true);
check('/__api__/ decoy answers 401 JSON', sonicwallResponse('/__api__/login').status, 401);
// The indexer must persist exploit_path (dropped before 2.12.0) and never the credential itself.
check('indexer persists exploit_path', /canary\.exploit_path \? \{ exploit_path: true \}/.test(src), true);
check('indexer stores default_creds as a boolean only', /default_creds: true/.test(src) && !/default_creds: request/.test(src), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

/**
 * Test the app-console canaries (Tomcat / JBoss / Zabbix / Nagios / Yii / dbadmin), added
 * 2026-10-28 after measuring our own Cloudflare firewall events: /manager/html was the most
 * probed path we own (508 req/24h) and appeared NOWHERE in this worker.
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it, same as
 * test-appliance-canaries.mjs, so the test cannot drift from what runs.
 *
 * The cases that matter most are the ones that must NOT trap. A canary on a path a real
 * visitor or our own API uses is not a sensor, it is an outage — see the worker's own note
 * that a canary on /_api/ would break the Wix blog and one on /api/v1/ would hijack analytics.
 *
 *   node test-appconsole-canaries.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};

const code = slice('const APPCONSOLE_CANARIES = [', 'function getApplianceCanary(path) {');
const getAppConsoleCanary = new Function(`${code}; return getAppConsoleCanary;`)();

const lower = (p) => p.toLowerCase();
const withSlash = (p) => (lower(p).endsWith('/') ? lower(p) : lower(p) + '/');
const hit = (p) => getAppConsoleCanary(lower(p), withSlash(p));

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log('  ok  ' + name); } else { fail++; console.log('  FAIL ' + name); } };

console.log('\nmust TRAP — measured in our own edge data, 24h to 2026-10-28:');
for (const [p, type] of [
  ['/manager/html', 'tomcat_scan'],              // 508 requests
  ['/manager/status', 'tomcat_scan'],
  ['/manager/text/list', 'tomcat_scan'],
  ['/host-manager/html', 'tomcat_scan'],
  ['/debug/default/view', 'yii_debug_probe'],    // 153
  ['/frontend/web/debug/default/view', 'yii_debug_probe'],  // 83
  ['/zabbix/', 'zabbix_scan'],                   // 112
  ['/zabbix/index.php', 'zabbix_scan'],
  ['/nagios/', 'nagios_scan'],                   // 86
  ['/dbadmin', 'dbadmin_probe'],                 // 82
  ['/jmx-console/', 'jboss_scan'],               // 80
]) {
  const r = hit(p);
  ok(`${p} -> ${type}`, r && r.type === type && r.fake === 'admin' && !!r.product);
}

console.log('\nmust TRAP case-insensitively (scanners vary case):');
ok('/Manager/HTML', (hit('/Manager/HTML') || {}).type === 'tomcat_scan');
ok('/ZABBIX/', (hit('/ZABBIX/') || {}).type === 'zabbix_scan');

console.log('\nmust NOT trap — our own surface and ordinary visitors:');
for (const p of [
  '/', '/blog', '/pricing', '/health', '/llms.txt', '/robots.txt',
  '/api/v1/search/stats', '/api/v1/stix-feed/ips.csv', '/api/v1/mcp',
  '/_api/members/v1/members/my',          // Wix frontend — a canary here breaks the blog
  '/post/one-bug-five-names-and-cisa-filed-it-under-none-of-them',
  '/assets/app.js', '/static/main.css', '/favicon.ico',
  '/management', '/managers', '/manager-report',   // near-misses, not Tomcat
  '/debugging', '/debug', '/debug/',               // bare /debug is NOT a Yii probe
  '/nagios-report', '/zabbixing',
]) {
  ok(`${p} does not trap`, hit(p) === null);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

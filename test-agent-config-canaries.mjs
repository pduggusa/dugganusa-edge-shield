/**
 * Test the AI-agent / MCP client config canaries (2.25.0).
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it, same as
 * test-appliance-canaries.mjs, so the test cannot drift from what runs.
 *
 * The cases that matter most are the ones that must NOT trap: our own MCP discovery routes
 * (/.well-known/mcp*), the MCP endpoint itself, and ordinary paths. A canary over a path we
 * actually serve breaks the site. The decoy must also be INERT: no command, no credential.
 *
 *   node test-agent-config-canaries.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const slice = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`could not locate ${from} in worker.js`);
  return src.slice(a, b);
};
const code = slice('const CANARY_PATHS', 'function honeypotResponse');
const mod = await import('data:text/javascript,' + encodeURIComponent(code + '\nexport { getCanary, FAKE_RESPONSES };'));
const { getCanary, FAKE_RESPONSES } = mod;

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${got}, want ${want})`}`);
};
const kind = (p) => { const c = getCanary(p); return c ? c.type : null; };

// 1. The measured paths (the 6 seen in our own blocks, 2026-10-14 to 10-30) and near siblings.
for (const p of ['/.claude/settings.json', '/.claude/settings.local.json', '/.claude/', '/.claude',
                 '/.cursor/mcp.json', '/.cursor/rules/x.mdc', '/.mcp.json', '/mcp.json',
                 '/claude_desktop_config.json', '/.vscode/mcp.json',
                 '/%2eclaude/settings.json', '/.cursor%2fmcp.json']) {
  check(`traps ${p}`, kind(p), 'agent_config_probe');
}
check('trapped paths use the inert decoy', getCanary('/.mcp.json').fake, 'agent_config');

// 2. Must NOT trap: what we or our customers legitimately serve.
for (const p of ['/.well-known/mcp.json', '/.well-known/mcp', '/.well-known/mcp/server-card.json',
                 '/mcp', '/api/v1/mcp', '/api/v1/mcp/tools', '/llms.txt', '/jeevesus', '/membrane',
                 '/claude', '/claude.json', '/cursor/', '/docs/mcp.json', '/blog/mcp.json',
                 '/.vscode/settings.json', '/.vscode/launch.json']) {
  check(`does NOT trap ${p}`, kind(p), null);
}

// 3. Existing canaries keep their families (precedence unchanged).
check('/.env stays config_probe', kind('/.env'), 'config_probe');
check('/.git/config stays source_exposure', kind('/.git/config'), 'source_exposure');
check('/.aws/credentials stays cloud_creds', kind('/.aws/credentials'), 'cloud_creds');
check('encoded .env still caught as config_probe', kind('/x/%2eenv'), 'config_probe');

// 4. The decoy is inert: valid JSON, a reserved .invalid host, no command, no credential.
const body = FAKE_RESPONSES.agent_config();
let parsed = null;
try { parsed = JSON.parse(body); } catch (_) { /* reported below */ }
check('decoy is valid JSON', parsed !== null, true);
const flat = JSON.stringify(parsed).toLowerCase();
for (const bad of ['"command"', '"args"', '"env"', '"headers"', 'bearer', 'token', 'secret', 'password', 'apikey', 'api_key', 'sk-', 'authorization']) {
  check(`decoy contains no ${bad}`, flat.includes(bad), false);
}
const urls = [...body.matchAll(/https?:\/\/([^/"']+)/g)].map((m) => m[1]);
check('decoy has at least one URL', urls.length > 0, true);
check('every decoy host is reserved .invalid (can never resolve)', urls.every((h) => h.endsWith('.invalid')), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

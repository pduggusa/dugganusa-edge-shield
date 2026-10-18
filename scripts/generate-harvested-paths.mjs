#!/usr/bin/env node
// generate-harvested-paths.mjs — turn the exploit harvester's endpoint rules into the worker's
// OBSERVE list, written INLINE into src/worker.js between the HARVESTED_PATHS markers (the
// worker is single-file by design: customers copy it as-is).
//
// WHY (2026-10-18): the harvester held a public PoC for Atlassian CVE-2026-21589 on 10-06, nine
// days before CISA listed it, and the edge recorded nothing: every appliance canary was written
// by hand AFTER a KEV listing exposed the blind spot. This makes the harvester's paths observable
// at the edge the day they are harvested, so "first probe" can be timed against the KEV date.
//
// OBSERVE, NOT DECOY. A matched request is passed through untouched; the worker only records the
// match (CVE, path, ASN, hashed IP) to edge_observations. Never an IOC, never a block: a hit can
// be induced (link previewers, prompt-injected fetchers), and nothing a machine generated from
// someone else's PoC gets to put an address in the feed.
//
// FREE-PLAN SHAPE. One exact-match Map lookup per request; the list is bundled (no KV reads) and
// capped (MAX_PATHS) so the script stays far under the free plan's size limit.
//
// Input: a JSON array of iocs docs (source=exploit-harvester, type=detection_rule) with
// id, value, malware_family, tags, harvested_at. Pull with the internal key, e.g. the search
// API filter `source = "exploit-harvester" AND type = "detection_rule"`, paged by offset.
//
//   node scripts/generate-harvested-paths.mjs rules.json [src/harvested-paths.generated.js]

import { readFileSync, writeFileSync } from 'node:fs';

export const MAX_PATHS = 4000;
export const MAX_CVES_PER_PATH = 3; // a path many PoCs share identifies nothing

// Words that do not identify a product on their own. A path made only of these is generic.
const COMMON = new Set(('api v1 v2 v3 v4 rest admin administrator users user auth login logout signin signup ' +
  'config configuration settings setting status health healthz system sys logs log audit secrets secret ' +
  'protected me jwks token tokens oauth import importer index legacy upload uploads file files data debug ' +
  'test tests exfil dispatcher public private static assets js css img images media include includes lib ' +
  'app apps web www home default main portal console dashboard manager management service services ' +
  'cgi-bin bin server info version graphql query search account accounts profile session sessions ' +
  'password reset register core common internal external v callback webhook webhooks plugin plugins ' +
  'download downloads export backup backups tmp temp cache cgi shell cmd exec run proxy').split(/\s+/));

// Paths our own properties serve or that every crawler requests: never an exploit signal here.
const OWN_PREFIXES = ['/api/v1/', '/post/', '/blog/', '/stix/', '/docs', '/_api/', '/_partials/', '/_serverless/',
  '/membrane', '/pricing', '/updates', '/.well-known/', '/mcp', '/taxii', '/robots.txt', '/sitemap', '/favicon'];

const FS_ROOTS = /^\/(proc|etc|usr|tmp|var|dev|bin|sbin|sys|home|root|opt|lib|lib64|run|mnt|boot|srv|windows|program files)(\/|$)/i;

// Same junk rules as scripts/canary-gap.mjs: payload fragments, not web routes.
function isJunk(p) {
  return !p.startsWith('/') || p.length < 3 || p.length > 200 ||
    /^\/[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|org|net|io|dev|ai|co|xyz|me|cn|ru|gov|edu|us|uk|de|jp|sh|app)(\/|:|$)/i.test(p) ||
    /^\/[^/]*\/cve-\d{4}/i.test(p) || /^\/refs\/heads\//i.test(p) ||
    /^\/(cve-\d|\*)/i.test(p) || /[\s"'`{}<>\\]/.test(p) || /\$\{|%\{|\.\.\//.test(p) ||
    (/\.(log|json\.bak|sh|py|so|dll|exe|elf|conf|txt|md)$/i.test(p) && !/\.(php|aspx?|jsp|cgi|do|action)/i.test(p)) ||
    FS_ROOTS.test(p) || /[*]/.test(p) ||
    // static assets and source files: not exploit endpoints, and real sites serve them
    /\.(m?js|ts|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|html?|java|cpp|cc|c|h|go|rs|img|ipa|apk|ya?ml|lock)$/i.test(p);
}

// A path is distinctive if some segment names something: not a common word, not a bare number,
// at least 3 chars — or it ends in a specific server-side file that is not an index/login page.
export function isDistinctive(p) {
  const segs = p.toLowerCase().split('/').filter(Boolean);
  if (!segs.length) return false;
  const last = segs[segs.length - 1];
  const named = segs.some(s => {
    const base = s.replace(/\.(php|aspx?|jsp|jspx|cgi|do|action|html?|json|xml)$/, '');
    return base.length >= 3 && !COMMON.has(base) && !/^\d+$/.test(base) && !/^v\d+$/.test(base);
  });
  if (!named) return false;
  // One bare word (/node, /maps, /survey) is too common to attribute; a server-side file is not.
  if (segs.length === 1 && !/\.(php|aspx?|jsp|jspx|cgi|do|action|pl|asmx|ashx|svc|nsf|esp)$/.test(last)) return false;
  // A single generic segment with an extension (/index.php, /login.jsp) names nothing.
  if (segs.length === 1 && /^(index|login|admin|default|home|main|test|info|upload)\./.test(last)) return false;
  return true;
}

export function buildPaths(rules) {
  const byPath = new Map(); // lowercase path -> { cves:Set, first }
  let considered = 0, junk = 0, generic = 0, own = 0;
  for (const d of rules) {
    if (!(d.tags || []).includes('endpoint')) continue;
    const cve = String(d.malware_family || '').toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cve)) continue;
    const t = d.harvested_at || d.timestamp || '';
    for (const raw of String(d.value || '').split(' | ')) {
      let p = raw.trim().split('?')[0].split('#')[0];
      if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
      considered++;
      if (isJunk(p)) { junk++; continue; }
      const lower = p.toLowerCase();
      if (OWN_PREFIXES.some(pre => lower === pre.replace(/\/$/, '') || lower.startsWith(pre))) { own++; continue; }
      if (!isDistinctive(lower)) { generic++; continue; }
      const e = byPath.get(lower) || { cves: new Set(), first: t };
      e.cves.add(cve);
      if (t && (!e.first || t < e.first)) e.first = t;
      byPath.set(lower, e);
    }
  }
  let shared = 0;
  const rows = [];
  for (const [p, e] of byPath) {
    if (e.cves.size > MAX_CVES_PER_PATH) { shared++; continue; }
    rows.push([p, [...e.cves].sort().join(','), e.first]);
  }
  // Newest harvests first: if the cap ever binds, the freshest PoCs (the left-of-boom ones) stay.
  rows.sort((a, b) => String(b[2]).localeCompare(String(a[2])) || a[0].localeCompare(b[0]));
  const kept = rows.slice(0, MAX_PATHS);
  return { paths: kept.map(([p, c]) => [p, c]).sort((a, b) => a[0].localeCompare(b[0])),
    stats: { considered, junk, own, generic, shared, distinct: rows.length, kept: kept.length, capped: rows.length - kept.length,
      cves: new Set(kept.flatMap(r => r[1].split(','))).size } };
}

export const BEGIN = '// BEGIN HARVESTED_PATHS';
export const END = '// END HARVESTED_PATHS';

export function render({ paths, stats }, generatedAt) {
  return `${BEGIN} — GENERATED by scripts/generate-harvested-paths.mjs, do not edit by hand.
// ${generatedAt}: ${stats.kept} paths, ${stats.cves} CVEs (considered ${stats.considered}; dropped junk ${stats.junk},
// own-site ${stats.own}, generic ${stats.generic}, shared by >${MAX_CVES_PER_PATH} CVEs ${stats.shared}, over cap ${stats.capped}).
// Lowercase, no query string, no trailing slash. Value: comma-separated CVE ids.
const HARVESTED_PATHS_GENERATED_AT = ${JSON.stringify(generatedAt)};
const HARVESTED_PATHS = new Map(${JSON.stringify(paths)});
${END}`;
}

export function splice(workerSrc, block) {
  const a = workerSrc.indexOf(BEGIN), b = workerSrc.indexOf(END);
  if (a < 0 || b < a) throw new Error('HARVESTED_PATHS markers not found in worker.js');
  return workerSrc.slice(0, a) + block + workerSrc.slice(b + END.length);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [, , input, worker = new URL('../src/worker.js', import.meta.url).pathname] = process.argv;
  if (!input) { console.error('usage: generate-harvested-paths.mjs rules.json [src/worker.js]'); process.exit(2); }
  const built = buildPaths(JSON.parse(readFileSync(input, 'utf8')));
  writeFileSync(worker, splice(readFileSync(worker, 'utf8'), render(built, new Date().toISOString())));
  console.log(JSON.stringify(built.stats));
}

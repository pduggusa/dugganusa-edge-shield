/**
 * DugganUSA Edge Shield
 *
 * Cloudflare Worker that protects your site with DugganUSA's threat feed,
 * scanner detection, geo analytics, and enterprise visitor tagging.
 *
 * Powered by DugganUSA Threat Intelligence API.
 *
 * Deploy: npx wrangler deploy
 * Register: https://analytics.dugganusa.com/stix/register
 *
 * © 2026 DugganUSA LLC — Minnetrista, MN
 */

// ================================================================
// CONFIGURATION — Set via wrangler.toml secrets or dashboard
// ================================================================

const DUGGANUSA_API = 'https://analytics.dugganusa.com/api/v1';
// Full refresh interval is the IOC_REFRESH_MINUTES var (default 60), see loadConfig().
const IOC_RETRY_INTERVAL = 600;    // 10 min retry after a FAILED refresh (was: wait the full hour; 5 min fed the herd)
// Identify the shield on every subrequest. A UA-less request from Cloudflare's shared
// Workers egress is indistinguishable from a scraper — which is how the shield's own
// IOC refresh got 403'd for 96 days (2026-07-01 → 2026-10-05).
const SHIELD_UA = 'DugganUSA-Edge-Shield/2026.10 (+https://analytics.dugganusa.com/stix/register)';

// DugganUSA's OWN properties. A feed-hit report carries `zone` ONLY for these, so a
// customer's hostname never leaves their worker (privacy contract). For anyone else
// running this shield, firstPartyZone() always returns null and nothing is sent.
function firstPartyZone(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === 'security.dugganusa.com') return 'security.dugganusa.com';
  if (h === 'aipmsec.com' || h.endsWith('.aipmsec.com')) return 'aipmsec.com';
  if (h === 'dugganusa.com' || h.endsWith('.dugganusa.com')) return 'dugganusa.com';
  return null;
}

// ================================================================
// POLICY CONFIG — every knob is a [vars] entry in wrangler.toml (2.5.0)
// ================================================================
// An ABSENT var falls back to the default below, and the defaults are exactly the
// values this Worker hard-coded before 2.5.0, so an existing deployment with no
// [vars] behaves the way it always did. wrangler.example.toml documents each one.
//
// A var that is present but unparseable also falls back to its default, and says
// so once in Workers Logs. A typo must never silently change the security posture.
const DEFAULT_CONFIG = {
  mode: 'block',               // SHIELD_MODE: "block" enforces, "observe" logs what it WOULD have done
  iocBlocking: true,           // IOC_BLOCKING
  iocMinConfidence: 80,        // IOC_MIN_CONFIDENCE: the customer's dial. 30 = broad, 80 = high precision
  iocFeedDays: 7,              // IOC_FEED_DAYS: feed lookback window
  iocRefreshMinutes: 60,       // IOC_REFRESH_MINUTES: full refresh interval (each refresh = 2 API calls)
  scanner418: true,            // SCANNER_418
  rlAnon: 100,                 // RL_ANON: req/min per anonymous IP (0 disables)
  rlAuth: 500,                 // RL_AUTH: req/min per IP presenting an API key (0 disables)
  feedHitReporting: true,      // FEED_HIT_REPORTING: indicator-only liveness report on a match
  // SCHEMA_INJECT_HOSTS: hosts that get DugganUSA's own Organization LD-JSON. It is OUR
  // record, so this is only ever meaningful on our hosts. Customers set it to "".
  schemaInjectHosts: ['www.dugganusa.com', 'dugganusa.com', 'aipmsec.com'],
  sensorHosts: [],             // SENSOR_HOSTS: never shielded, see isSensorHost()
};

function parseBool(raw, dflt, name, warnings) {
  if (raw === undefined || raw === null || raw === '') return dflt;
  const s = String(raw).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(s)) return true;
  if (['false', '0', 'no', 'off'].includes(s)) return false;
  warnings.push(`${name}="${raw}" is not a boolean, using default ${dflt}`);
  return dflt;
}

function parseIntRange(raw, dflt, min, max, name, warnings) {
  if (raw === undefined || raw === null || raw === '') return dflt;
  const s = String(raw).trim();
  const n = /^\d+$/.test(s) ? parseInt(s, 10) : NaN;
  if (!Number.isFinite(n) || n < min || n > max) {
    warnings.push(`${name}="${raw}" is not an integer in ${min}..${max}, using default ${dflt}`);
    return dflt;
  }
  return n;
}

// Comma- or whitespace-separated host list. ABSENT → default; "" → explicitly none.
function parseList(raw, dflt) {
  if (raw === undefined || raw === null) return dflt;
  return String(raw).split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
}

function loadConfig(env) {
  const e = env || {};
  const warnings = [];
  const d = DEFAULT_CONFIG;

  let mode = d.mode;
  if (e.SHIELD_MODE !== undefined && e.SHIELD_MODE !== null && e.SHIELD_MODE !== '') {
    const m = String(e.SHIELD_MODE).trim().toLowerCase();
    if (m === 'block' || m === 'observe') mode = m;
    else if (m === 'log-only' || m === 'log') mode = 'observe';
    else warnings.push(`SHIELD_MODE="${e.SHIELD_MODE}" is not "block" or "observe", using default ${d.mode}`);
  }

  return {
    mode,
    observe: mode === 'observe',
    iocBlocking: parseBool(e.IOC_BLOCKING, d.iocBlocking, 'IOC_BLOCKING', warnings),
    iocMinConfidence: parseIntRange(e.IOC_MIN_CONFIDENCE, d.iocMinConfidence, 0, 100, 'IOC_MIN_CONFIDENCE', warnings),
    iocFeedDays: parseIntRange(e.IOC_FEED_DAYS, d.iocFeedDays, 1, 90, 'IOC_FEED_DAYS', warnings),
    iocRefreshMinutes: parseIntRange(e.IOC_REFRESH_MINUTES, d.iocRefreshMinutes, 5, 1440, 'IOC_REFRESH_MINUTES', warnings),
    scanner418: parseBool(e.SCANNER_418, d.scanner418, 'SCANNER_418', warnings),
    rlAnon: parseIntRange(e.RL_ANON, d.rlAnon, 0, 1000000, 'RL_ANON', warnings),
    rlAuth: parseIntRange(e.RL_AUTH, d.rlAuth, 0, 1000000, 'RL_AUTH', warnings),
    feedHitReporting: parseBool(e.FEED_HIT_REPORTING, d.feedHitReporting, 'FEED_HIT_REPORTING', warnings),
    schemaInjectHosts: parseList(e.SCHEMA_INJECT_HOSTS, d.schemaInjectHosts),
    sensorHosts: parseList(e.SENSOR_HOSTS, d.sensorHosts),
    warnings,
  };
}

// `env` is the same object for every request an isolate serves, so parse it once.
const configCache = new WeakMap();
function getConfig(env) {
  if (!env || typeof env !== 'object') return loadConfig({});
  let cfg = configCache.get(env);
  if (!cfg) {
    cfg = loadConfig(env);
    for (const w of cfg.warnings) console.log(`config: ${w}`);
    configCache.set(env, cfg);
  }
  return cfg;
}

// SENSOR hosts are never shielded. A honeypot, research box or telemetry endpoint
// exists to see raw traffic: scanners, probes, IOC-listed IPs. A shield in front of
// it 418s and 403s exactly what it is there to observe. Routing is the first guard
// (no catch-all route on a sensor); this is the second, for the day someone adds
// one anyway. Entries are exact hosts or "*.example.com" (subdomains only).
function isSensorHost(hostname, cfg) {
  const h = String(hostname || '').toLowerCase();
  return cfg.sensorHosts.some(s => s.startsWith('*.') ? h.endsWith(s.slice(1)) : h === s);
}

// Observe mode records every decision it did NOT enforce. Evidence is never
// discarded just because enforcement is off; that is the whole point of a trial.
// This lands in the operator's OWN Workers Logs, on their own account.
function logObserved(would, ip, hostname, path, rayId) {
  console.log(JSON.stringify({ shield: 'observe', would, ip, host: hostname, path, ray: rayId || null }));
}

// ================================================================
// ORIGIN EDGE SECRET (2.14.0) — DugganUSA-only; customer deployments leave it unset
// ================================================================
// The origin behind this worker can only trust cf-connecting-ip if it can tell that a
// request really came through our edge: its public FQDN can be found and hit directly,
// with a forged Host AND a forged cf-connecting-ip. So every request this worker forwards
// to one of OUR origins carries `x-dugganusa-edge: <ORIGIN_EDGE_SECRET>` (a wrangler
// secret, never in wrangler.toml or code), and the origin compares it in constant time.
//
// Scoped to ORIGIN_EDGE_HOSTS (default: analytics.dugganusa.com), so the secret never goes
// to a third-party origin (www/apex are Wix). A client-supplied copy of the header is
// stripped on every forward, everywhere. Secret unset: nothing is sent, and a config
// warning is logged once per isolate (only for a listed host, so customers never see it).
const ORIGIN_EDGE_HEADER = 'x-dugganusa-edge';
const DEFAULT_ORIGIN_EDGE_HOSTS = ['analytics.dugganusa.com'];
let originEdgeWarned = false;

function originEdgeHosts(env) {
  const raw = env && env.ORIGIN_EDGE_HOSTS;
  if (typeof raw !== 'string' || !raw.trim()) return DEFAULT_ORIGIN_EDGE_HOSTS;
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

// Mutates a Headers object bound for origin. Returns true when it changed anything.
function applyOriginEdge(headers, env, hostname) {
  const had = headers.has(ORIGIN_EDGE_HEADER);
  headers.delete(ORIGIN_EDGE_HEADER);
  const h = String(hostname || '').toLowerCase();
  if (!originEdgeHosts(env).includes(h)) return had;
  const secret = env && typeof env.ORIGIN_EDGE_SECRET === 'string' ? env.ORIGIN_EDGE_SECRET : '';
  if (!secret) {
    if (!originEdgeWarned) {
      originEdgeWarned = true;
      console.log(JSON.stringify({ shield: 'config', warning: 'ORIGIN_EDGE_SECRET unset: origin cannot verify edge requests', host: h }));
    }
    return had;
  }
  headers.set(ORIGIN_EDGE_HEADER, secret);
  return true;
}

// For pass-through fetches that forward the original request unchanged.
function withOriginEdge(request, env, hostname) {
  const headers = new Headers(request.headers);
  return applyOriginEdge(headers, env, hostname) ? new Request(request, { headers }) : request;
}
// END ORIGIN EDGE SECRET

// ================================================================
// KNOWN SCANNER SIGNATURES
// ================================================================

const SCANNER_UA = [
  'leakix', 'censys', 'zgrab', 'masscan', 'nuclei', 'httpx',
  'gobuster', 'dirbuster', 'nikto', 'sqlmap', 'nmap', 'wpscan',
  'burpsuite', 'zap', 'acunetix', 'nessus', 'qualys', 'openvas',
  'shodan', 'binaryedge', 'onyphe', 'netcraft'
];

const SCANNER_ORGS = [
  'leakix', 'censys', 'shadowserver', 'internet-measurement',
  'stretchoid', 'binaryedge', 'shodan', 'onyphe'
];

// SASE/SSE proxies — these are NOT scanners or competitors.
// Enterprise users behind these proxies are CUSTOMERS, not threats.
// A request from Zscaler is an employee at a Fortune 500, not Zscaler itself.
const SASE_PROXY_ORGS = [
  'zscaler', 'netskope', 'palo alto', 'prisma', 'cloudflare warp',
  'cisco umbrella', 'forcepoint', 'iboss', 'menlo security',
  'skyhigh security', 'cato networks', 'versa networks'
];

// ================================================================
// VERIFIED CRAWLERS — the allowlist that has to survive to the edge
// ================================================================
//
// 2026-08-16: measuring the shield showed it refusing self-identifying,
// legitimate crawlers — Meta's crawler 332 times across 112 hosts while it was
// fetching our sitemap and article pages, plus Amazon's, Google's and Yandex's.
// We HAD a known-good bot allowlist. It was enforced at the ORIGIN, and blocking
// had since moved out here to the edge. The allowlist never made the trip.
//
// For a small site that cost is bigger than the attack: link previews stop
// rendering when customers share you, and pages quietly fall out of a search
// index. Nothing alerts on it, because the shield is doing exactly what it was
// told. Hence this list, and hence checking it FIRST.
//
// HARD — a user-agent string is NOT verification. Most of what we block is
// already lying about being a browser, so "it said it was Googlebot" is the
// weakest possible signal. Two acceptable proofs, in order:
//
//   1. Cloudflare's own verified-bot flag. CF does the forward-confirmed reverse
//      DNS itself and is authoritative. Free tiers may not populate it, so it is
//      a fast path, not the only path.
//   2. Forward-confirmed reverse DNS, done here over DoH: PTR the client IP, check
//      the hostname ends in an operator-owned domain, then resolve that hostname
//      back and confirm it returns the same IP. Both halves are required — a PTR
//      alone is attacker-controlled.
//
// ASN is deliberately NOT a proof. Googlebot and ordinary Google Cloud rentals
// share AS15169, so an ASN allowlist would wave through the exact GCP-hosted
// scrapers this shield exists to stop.
const CRAWLER_UA_TO_DOMAINS = [
  { ua: 'googlebot',          domains: ['.googlebot.com', '.google.com'] },
  { ua: 'storebot-google',    domains: ['.googlebot.com', '.google.com'] },
  { ua: 'google-inspectiontool', domains: ['.googlebot.com', '.google.com'] },
  { ua: 'bingbot',            domains: ['.search.msn.com'] },
  { ua: 'adidxbot',           domains: ['.search.msn.com'] },
  { ua: 'twitterbot',         domains: ['.twttr.com', '.twitter.com'] },
  { ua: 'applebot',           domains: ['.applebot.apple.com'] },
  { ua: 'duckduckbot',        domains: ['.duckduckgo.com'] },
  { ua: 'amazonbot',          domains: ['.crawl.amazon.com'] },
  // AI crawlers are deliberately included. Our reach is disproportionately
  // AI-mediated, and an AI assistant that cannot read us cannot cite us.
  { ua: 'gptbot',             domains: ['.openai.com'] },
  { ua: 'oai-searchbot',      domains: ['.openai.com'] },
  { ua: 'chatgpt-user',       domains: ['.openai.com'] },
  { ua: 'claudebot',          domains: ['.anthropic.com'] },
  { ua: 'claude-web',         domains: ['.anthropic.com'] },
  { ua: 'perplexitybot',      domains: ['.perplexity.ai'] },
];

// DELIBERATELY NOT ALLOWLISTED — policy, not oversight. Do not "fix" these back
// in; the omissions are the decision (Patrick, 2026-08-16: "meta and yandex are
// fine in the sin bin").
//
//   Bytespider (ByteDance) — our single noisiest crawler by volume, 671 events
//     across 61 hosts in sixteen days. Plenty of sites decline it.
//   meta-externalagent / facebookexternalhit — 332 events / 112 hosts, and
//     confirmed GENUINE Meta (332/332 AS32934, 2a03:2880::/32). Declining it is
//     a deliberate choice about who gets to read us, not a false positive.
//   yandexbot — same call.
//
// These are ALSO blocked upstream by a Cloudflare WAF custom rule, which runs
// BEFORE Workers, so today the worker never sees them. That is exactly why the
// omission is written down: if the WAF rule is ever relaxed, this file must not
// silently start admitting them again. Code and policy agree on purpose.
//
// The Meta ASN-verification path was removed with them. If Meta is ever let back
// in, note that rDNS CANNOT verify it — Meta publishes none — so it needs
// `asns: [32934]`. AS32934 is Meta-exclusive and unrentable, which is what makes
// ASN valid there. Never do this for AS15169: Googlebot shares it with every GCP
// customer, and the fake "Amazonbot" fleet we caught was riding exactly that.

// Verification is a network round trip, so cache the verdict per IP. Bounded —
// an unbounded Map in a long-lived isolate is a memory leak with extra steps.
const crawlerVerdicts = new Map();
const CRAWLER_CACHE_MAX = 2000;
const CRAWLER_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h

function cacheVerdict(key, ok) {
  if (crawlerVerdicts.size >= CRAWLER_CACHE_MAX) {
    // Cheapest sane eviction: drop the oldest insertion.
    const oldest = crawlerVerdicts.keys().next().value;
    if (oldest !== undefined) crawlerVerdicts.delete(oldest);
  }
  crawlerVerdicts.set(key, { ok, at: Date.now() });
  return ok;
}

async function dohQuery(name, type) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) return [];
  const body = await res.json();
  return (body.Answer || []).map(a => String(a.data || '').replace(/\.$/, ''));
}

/** Expand an IPv6 address to its full 32 hex nibbles. Returns null if malformed. */
function expandIPv6(ip) {
  const bare = ip.split('%')[0];
  if (!/^[0-9a-fA-F:]+$/.test(bare)) return null;
  const halves = bare.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  return groups.map(g => g.padStart(4, '0')).join('').toLowerCase();
}

function ptrName(ip) {
  if (ip.includes(':')) {
    // IPv6 reverse: 32 nibbles, reversed, dotted, under ip6.arpa. Implemented
    // rather than skipped — Meta's crawler is largely IPv6, and "skip" used to
    // mean "fail open," which was a hole you could drive a truck through.
    const hex = expandIPv6(ip);
    if (!hex || hex.length !== 32) return null;
    return hex.split('').reverse().join('.') + '.ip6.arpa';
  }
  const p = ip.split('.');
  if (p.length !== 4) return null;
  if (!p.every(o => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return null;
  return `${p[3]}.${p[2]}.${p[1]}.${p[0]}.in-addr.arpa`;
}

/**
 * Is this request a legitimate, verified crawler?
 *
 * FAILS CLOSED, everywhere, without exception.
 *
 * The first cut of this function failed OPEN on missing IP, on IPv6, and on any
 * DNS exception, reasoning that a resolver blip must not deindex us. That was
 * wrong, and it was wrong in the dangerous direction: since the UA gate is the
 * only thing upstream of it, anyone could set their user-agent to "Googlebot",
 * connect over IPv6, and bypass scanner detection, IOC blocking, the honeypot
 * AND the rate limiter in one move. A shield with a spoofable full-bypass is not
 * a shield.
 *
 * The reasoning error was treating "not allowlisted" as "blocked." It is not.
 * Failing verification simply means the request is handled as ORDINARY TRAFFIC —
 * it still passes straight through every layer unless it independently trips
 * scanner detection, appears on a high-confidence IOC list, requests a honeypot
 * canary, or floods. A real crawler does none of those things. So the true cost
 * of failing closed is very close to zero, while the cost of failing open is a
 * trivially spoofable bypass of the entire product.
 *
 * IPv6 is fully supported via nibble-form PTR (see ptrName) rather than skipped,
 * because Meta's crawler is largely IPv6 and "skip" previously meant "fail open."
 */
/**
 * Cloudflare's verified-bot category for this request, normalized: a category string
 * ("AI Crawler", "Search Engine Crawler", ...) when Cloudflare verified the client, else null.
 * Never throws; never reads a client header.
 */
function cfVerifiedCategory(cf) {
  const c = cf && typeof cf.verifiedBotCategory === 'string' ? cf.verifiedBotCategory.trim() : '';
  return c && c !== 'Not Verified' ? c.slice(0, 64) : null;
}

async function isVerifiedCrawler(request, cf) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  if (!ua) return false;

  const match = CRAWLER_UA_TO_DOMAINS.find(c => ua.includes(c.ua));
  if (!match) return false;

  // Fast path: Cloudflare already did forward-confirmed rDNS for us and is
  // authoritative. This is a CF-populated field on request.cf, not a client
  // header, so it is not attacker-controlled.
  if (cf.botManagement?.verifiedBot === true) return true;
  if (cf.verifiedBotCategory && cf.verifiedBotCategory !== 'Not Verified') return true;

  // Operator-exclusive ASN. Only set for operators that publish no usable rDNS
  // AND own space nobody can rent — currently Meta (AS32934). cf.asn is derived
  // by Cloudflare from the BGP table, not from anything the client sends, so it
  // is as trustworthy as the connection itself. Never add a cloud provider's ASN
  // here: AS15169 would admit every GCP-hosted scraper on the internet.
  if (match.asns && cf.asn && match.asns.includes(Number(cf.asn))) return true;

  const ip = request.headers.get('cf-connecting-ip') || '';
  if (!ip) return false; // nothing to verify against → not verified

  // Key the cache on IP **and** the crawler family being claimed. Keying on IP
  // alone would let a verdict earned as one operator be replayed as another: a
  // genuine Googlebot address verifies true, and a later request from that same
  // address claiming to be meta-externalagent would inherit the cached pass
  // without its own forward-confirmation.
  const key = `${ip}|${match.ua}`;
  const cached = crawlerVerdicts.get(key);
  if (cached && (Date.now() - cached.at) < CRAWLER_CACHE_TTL_MS) return cached.ok;

  const rev = ptrName(ip);
  if (!rev) return false; // unparseable address → not verified

  try {
    const ptrs = await dohQuery(rev, 'PTR');
    if (!ptrs.length) return cacheVerdict(key, false); // no PTR → not a real crawler

    const host = ptrs.find(h => match.domains.some(d => h.toLowerCase().endsWith(d)));
    if (!host) return cacheVerdict(key, false); // PTR exists but is not the operator's

    // Forward-confirm: the operator's hostname must resolve back to this same IP.
    // A PTR record alone is controlled by whoever owns the reverse zone.
    const fwd = await dohQuery(host, ip.includes(':') ? 'AAAA' : 'A');
    const ok = fwd.some(a => a.toLowerCase() === ip.toLowerCase());
    return cacheVerdict(key, ok);
  } catch (e) {
    // Resolver trouble → NOT verified. Deliberately not cached: a transient DNS
    // failure must not pin a real crawler to "unverified" for the cache TTL.
    console.log(`crawler verify error for ${ip}: ${e.message}`);
    return false;
  }
}

// ================================================================
// IN-MEMORY IOC CACHE
// ================================================================

let iocCache = {
  ips: new Set(),
  cidrs4: [], // [{ base, mask }] — IPv4 CIDR blocks (shitlist /24s were INERT before 2026-07-10)
  cidrs6: [], // [{ base:BigInt, mask:BigInt }] — IPv6 CIDR blocks
  domains: new Set(),
  lastRefresh: 0,
  lastFailure: 0,
  count: 0
};

// ONE origin pull per data center, not per isolate (2026-10-05). The feed CSV costs the
// origin ~8-24s to build. Once the shield could actually fetch it again, every isolate in
// every PoP pulled its own copy (75 pulls / 5 min, 503s + 499s) — a thundering herd against
// the product. The data-center cache is shared by all isolates there. The key lives on a
// hostname nobody can request (.invalid), so the cached feed can never be served to a
// visitor without a key. Any Cache API failure falls back to a direct fetch.
const FEED_EDGE_CACHE_TTL = 600; // seconds
//
// The key carries the feed query (window + min_confidence) so two configurations
// never share an entry: a min_confidence=30 deployment must not be served an 80 feed.
// It also floors the effective refresh at the TTL: IOC_REFRESH_MINUTES below 10 still
// re-reads the data-center copy, it just does not re-pull the origin.
async function cachedFeedFetch(url, name, headers, qs) {
  const key = new Request(`https://edge-shield-feed-cache.invalid/${name}?${qs}`);
  let cache = null;
  try {
    cache = caches.default;
    const hit = await cache.match(key);
    if (hit) return hit;
  } catch (e) { cache = null; }
  const res = await fetch(url, { headers });
  if (!res.ok || !cache) return res;
  const body = await res.text();
  const fresh = () => new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/csv', 'Cache-Control': `max-age=${FEED_EDGE_CACHE_TTL}` }
  });
  try { await cache.put(key, fresh()); } catch (e) { /* uncached is still correct */ }
  return fresh();
}

// One refresh at a time per isolate: concurrent requests each kicked off their own.
let refreshInFlight = null;
function refreshIOCs(apiKey, cfg = DEFAULT_CONFIG) {
  if (!refreshInFlight) refreshInFlight = doRefreshIOCs(apiKey, cfg).finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}

async function doRefreshIOCs(apiKey, cfg) {
  const now = Date.now();
  const wait = iocCache.lastFailure > iocCache.lastRefresh ? IOC_RETRY_INTERVAL : cfg.iocRefreshMinutes * 60;
  if (now - Math.max(iocCache.lastRefresh, iocCache.lastFailure) < wait * 1000) return;

  try {
    const headers = { 'Authorization': `Bearer ${apiKey}`, 'User-Agent': SHIELD_UA };
    const qs = `days=${cfg.iocFeedDays}&min_confidence=${cfg.iocMinConfidence}`;
    const [ipsRes, domainsRes] = await Promise.all([
      cachedFeedFetch(`${DUGGANUSA_API}/stix-feed/ips.csv?${qs}`, 'ips', headers, qs),
      cachedFeedFetch(`${DUGGANUSA_API}/stix-feed/domains.csv?${qs}`, 'domains', headers, qs)
    ]);

    // A failed refresh used to be swallowed silently: the cache stayed EMPTY, LAYER 2
    // matched nothing, and no feed hit was ever reported. Say so in Workers Logs.
    if (!ipsRes.ok || !domainsRes.ok) {
      console.log(`IOC refresh FAILED: ips.csv ${ipsRes.status}, domains.csv ${domainsRes.status} — ` +
        `IOC blocking runs on ${iocCache.count ? 'a stale' : 'an EMPTY'} cache (${iocCache.count} IOCs)`);
    }

    if (ipsRes.ok) {
      const text = await ipsRes.text();
      const ips = new Set(); const cidrs4 = []; const cidrs6 = [];
      for (const line of text.split('\n')) {
        if (line.startsWith('#') || line.startsWith('ip,')) continue;
        const ip = line.split(',')[0]?.trim();
        if (!ip) continue;
        if (ip.includes('/')) {           // CIDR (shitlist /24, ASN prefixes) — parse, don't drop
          const c = parseCidr(ip);
          if (c) (c.v6 ? cidrs6 : cidrs4).push(c);
        } else { ips.add(ip); }
      }
      iocCache.ips = ips; iocCache.cidrs4 = cidrs4; iocCache.cidrs6 = cidrs6;
    }

    if (domainsRes.ok) {
      const text = await domainsRes.text();
      const domains = new Set();
      for (const line of text.split('\n')) {
        if (line.startsWith('#') || line.startsWith('domain,')) continue;
        const domain = line.split(',')[0]?.trim();
        if (domain) domains.add(domain);
      }
      iocCache.domains = domains;
    }

    if (ipsRes.ok && domainsRes.ok) iocCache.lastRefresh = now;
    else iocCache.lastFailure = now;
    iocCache.count = iocCache.ips.size + iocCache.cidrs4.length + iocCache.cidrs6.length + iocCache.domains.size;
  } catch (e) {
    iocCache.lastFailure = now;
    console.log(`IOC refresh error: ${e.message} — using ${iocCache.count ? 'stale' : 'EMPTY'} cache`);
  }
}

// ================================================================
// SCANNER DETECTION
// ================================================================

function detectScanner(ua, asnOrg) {
  const uaLower = ua.toLowerCase();
  const orgLower = asnOrg.toLowerCase();

  // NEVER flag SASE/SSE proxy users as scanners — they're enterprise customers
  if (SASE_PROXY_ORGS.some(p => orgLower.includes(p))) return false;

  return SCANNER_UA.some(p => uaLower.includes(p)) ||
         SCANNER_ORGS.some(p => orgLower.includes(p));
}

function scannerResponse(request, cf) {
  return new Response(JSON.stringify({
    message: "We see you. We indexed you.",
    your_ip: request.headers.get('cf-connecting-ip'),
    your_asn: `AS${cf.asn || 'unknown'}`,
    your_org: cf.asOrganization || 'unknown',
    your_city: cf.city || 'unknown',
    your_country: cf.country || 'unknown',
    detected_at: new Date().toISOString(),
    protected_by: "DugganUSA Edge Shield",
    threat_feed: `${DUGGANUSA_API}/stix-feed`,
    score: "You scored 0/95 on our scanner detection. Congratulations."
  }, null, 2), {
    status: 418,
    headers: {
      'Content-Type': 'application/json',
      'X-Powered-By': 'DugganUSA Edge Shield',
      'X-Scanner-Detected': 'true',
      'Cache-Control': 'no-store'
    }
  });
}

// ================================================================
// IOC BLOCKING
// ================================================================

// --- CIDR support (added 2026-07-10 — shitlist /24s + ASN prefixes were inert before) ---
function ipv4ToInt(ip) {
  const p = ip.split('.'); if (p.length !== 4) return null;
  let n = 0; for (const o of p) { const x = +o; if (!(x >= 0 && x <= 255)) return null; n = (n << 8) + x; }
  return n >>> 0;
}
function ipv6ToBigInt(ip) {
  if (ip.indexOf(':') < 0) return null;
  let [head, tail] = ip.split('::');
  const h = head ? head.split(':').filter(Boolean) : [];
  const t = tail !== undefined ? (tail ? tail.split(':').filter(Boolean) : []) : null;
  let parts;
  if (t === null) { parts = h; } else { parts = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]; }
  if (parts.length !== 8) return null;
  let n = 0n; for (const x of parts) { const v = parseInt(x || '0', 16); if (isNaN(v)) return null; n = (n << 16n) + BigInt(v); }
  return n;
}
function parseCidr(cidr) {
  const [base, bitsStr] = cidr.split('/'); const bits = parseInt(bitsStr, 10);
  if (isNaN(bits)) return null;
  if (base.includes(':')) {
    const b = ipv6ToBigInt(base); if (b === null || bits < 0 || bits > 128) return null;
    const mask = bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits));
    return { v6: true, base: b & mask, mask };
  }
  const b = ipv4ToInt(base); if (b === null || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (-1 << (32 - bits)) >>> 0;
  return { v6: false, base: (b & mask) >>> 0, mask };
}
function checkIOC(ip) {
  if (iocCache.ips.has(ip)) return true;               // exact match (fast path)
  if (ip.includes(':')) {
    const v = ipv6ToBigInt(ip); if (v === null) return false;
    for (const c of iocCache.cidrs6) if ((v & c.mask) === c.base) return true;
    return false;
  }
  const v = ipv4ToInt(ip); if (v === null) return false;
  for (const c of iocCache.cidrs4) if (((v & c.mask) >>> 0) === c.base) return true;
  return false;
}

function blockedResponse(ip) {
  return new Response(JSON.stringify({
    blocked: true,
    reason: "IP matched DugganUSA threat intelligence feed",
    ip: ip,
    feed: `${DUGGANUSA_API}/stix-feed`,
    report: `${DUGGANUSA_API}/threat-intel/enrichment?ip=${ip}`,
    protected_by: "DugganUSA Edge Shield"
  }, null, 2), {
    status: 403,
    headers: {
      'Content-Type': 'application/json',
      'X-Powered-By': 'DugganUSA Edge Shield',
      'X-Blocked-Reason': 'ioc-match',
      'Cache-Control': 'no-store'
    }
  });
}

// ================================================================
// HONEYPOT CANARIES — 100% malicious, zero false positives
// ================================================================

const CANARY_PATHS = {
  // Config/credential exposure — every scanner hits these
  '/.env':                { type: 'config_probe',    fake: 'env' },
  '/.env.bak':            { type: 'config_probe',    fake: 'env' },
  '/.env.production':     { type: 'config_probe',    fake: 'env' },
  '/.env.local':          { type: 'config_probe',    fake: 'env' },
  '/.git/config':         { type: 'source_exposure', fake: 'git' },
  '/.git/HEAD':           { type: 'source_exposure', fake: 'git' },
  '/.aws/credentials':    { type: 'cloud_creds',     fake: 'aws' },

  // WordPress — we don't run WP, any hit is recon
  '/wp-admin/':                  { type: 'wordpress_scan', fake: 'wp' },
  '/wp-login.php':               { type: 'wordpress_scan', fake: 'wp' },
  '/wp-admin/setup-config.php':  { type: 'wordpress_scan', fake: 'wp' },
  '/xmlrpc.php':                 { type: 'wordpress_scan', fake: 'wp' },

  // Database/backup exposure
  '/backup.sql':          { type: 'data_theft',      fake: 'sql' },
  '/backup.sql.gz':       { type: 'data_theft',      fake: 'sql' },
  '/dump.sql':            { type: 'data_theft',      fake: 'sql' },
  '/db.sqlite':           { type: 'data_theft',      fake: 'sql' },

  // ILIAS LMS — CVE-2026-80428 unauthenticated PHP object injection via ltiauth.php.
  // Public PoCs since 2026-09-03 (a weaponized one 2026-10-09); we run no ILIAS, so any
  // hit is targeting. Paths are the PoCs' own candidate list. Added 2026-10-09 (2.7.0).
  '/ltiauth.php':                { type: 'ilias_scan', fake: 'admin' },
  '/LTI/ltiauth.php':            { type: 'ilias_scan', fake: 'admin' },
  '/lti/ltiauth.php':            { type: 'ilias_scan', fake: 'admin' },
  '/shibboleth/ltiauth.php':     { type: 'ilias_scan', fake: 'admin' },
  '/ilias/':                     { type: 'ilias_scan', fake: 'admin' },

  // Admin panels we don't have
  '/phpmyadmin/':         { type: 'admin_scan',      fake: 'admin' },
  '/adminer.php':         { type: 'admin_scan',      fake: 'admin' },
  '/administrator/':      { type: 'admin_scan',      fake: 'admin' },
  '/_debug/':             { type: 'debug_probe',     fake: 'admin' },

  // API key/token fishing
  '/api/v1/internal/keys':       { type: 'api_probe', fake: 'api' },
  '/api/v1/internal/config':     { type: 'api_probe', fake: 'api' },
  '/api/v1/admin/users':         { type: 'api_probe', fake: 'api' },
  '/graphql':                    { type: 'api_probe', fake: 'api' },

  // Shell/webshell attempts
  '/shell.php':           { type: 'webshell',        fake: 'shell' },
  '/cmd.php':             { type: 'webshell',        fake: 'shell' },
  '/c99.php':             { type: 'webshell',        fake: 'shell' },
  '/r57.php':             { type: 'webshell',        fake: 'shell' },

  // Actuator/Spring — wrong stack, 100% recon
  '/actuator':            { type: 'framework_scan',  fake: 'actuator' },
  '/actuator/env':        { type: 'framework_scan',  fake: 'actuator' },
  '/server-status':       { type: 'framework_scan',  fake: 'actuator' },

  // cPanel/WHM/webmail recon — non-app surface, 100% recon (CVE-2026-41940 wave, June 2026).
  // Trailing-slash entries prefix-match bare path + subpaths (/cpanel, /cpanel/login, etc.)
  '/cpanel/':             { type: 'cpanel_scan',     fake: 'cpanel' },
  '/whm/':                { type: 'cpanel_scan',     fake: 'cpanel' },
  '/webmail/':            { type: 'cpanel_scan',     fake: 'cpanel' },
  '/cgi-sys/':            { type: 'cpanel_scan',     fake: 'cpanel' },
};

// Convincing fake responses — waste their time, harvest their fingerprint
const FAKE_RESPONSES = {
  cpanel: () => `<!DOCTYPE html><html><head><title>cPanel Login</title><meta name="referrer" content="no-referrer"></head><body><div id="cpanel-login"><h1>cPanel</h1><form action="/login/?login_only=1" method="post"><input type="text" name="user" placeholder="Username" autocomplete="off"><input type="password" name="pass" placeholder="Password"><button type="submit">Log in</button></form><div class="footer">cPanel, L.L.C. &#169; 2026 &#8226; Version 124.0.9</div></div></body></html>`,

  env: () => `# Generated by deploy pipeline — DO NOT COMMIT\nDB_HOST=internal-db-01.dugganusa.local\nDB_USER=app_readonly\nDB_PASS=k8s_rotated_${Date.now().toString(36)}\nAWS_ACCESS_KEY_ID=AKIA${randomHex(16)}\nAWS_SECRET_ACCESS_KEY=${randomHex(40)}\nSTRIPE_SK=sk_live_${randomHex(24)}\nJWT_SECRET=${randomHex(32)}\nREDIS_URL=redis://cache-01.dugganusa.local:6379\n`,

  git: () => `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:dugganusa/analytics-platform.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`,

  aws: () => `[default]\naws_access_key_id = AKIA${randomHex(16)}\naws_secret_access_key = ${randomHex(40)}\nregion = us-east-1\n\n[production]\naws_access_key_id = AKIA${randomHex(16)}\naws_secret_access_key = ${randomHex(40)}\nregion = us-east-2\n`,

  wp: () => `<!DOCTYPE html><html><head><title>Log In &lsaquo; DugganUSA &#8212; WordPress</title></head><body class="login"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In" /></p></form></div></body></html>`,

  sql: () => `-- MySQL dump 10.13  Distrib 8.0.36\n-- Host: internal-db-01.dugganusa.local\n-- Database: analytics_prod\n-- Table: users (${Math.floor(Math.random() * 500) + 200} rows)\nCREATE TABLE users (\n  id INT PRIMARY KEY AUTO_INCREMENT,\n  email VARCHAR(255) NOT NULL,\n  password_hash VARCHAR(255),\n  api_key VARCHAR(64),\n  tier ENUM('free','starter','pro','enterprise'),\n  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);\n-- Dumping data...\nINSERT INTO users VALUES (1,'admin@dugganusa.com','$2b$12$fake_hash_to_waste_your_time','dugusa_FAKE_KEY_ENJOY','enterprise','2025-10-07');\n`,

  admin: () => JSON.stringify({ status: 'ok', version: '4.8.1', environment: 'production', users: 847, uptime: '127d 4h', database: 'connected' }, null, 2),

  api: () => JSON.stringify({ keys: [{ id: 'key_1', prefix: 'dugusa_', tier: 'enterprise', created: '2025-10-07', last_used: new Date().toISOString() }, { id: 'key_2', prefix: 'dugusa_', tier: 'free', created: '2026-01-15' }], total: 2, _warning: 'internal endpoint — do not expose' }, null, 2),

  shell: () => `<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)\n$ `,

  actuator: () => JSON.stringify({ status: 'UP', components: { db: { status: 'UP', details: { database: 'PostgreSQL', validationQuery: 'isValid()' } }, redis: { status: 'UP' }, diskSpace: { status: 'UP', details: { total: 107374182400, free: 42949672960 } } } }, null, 2),
};

function randomHex(len) {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < len; i++) result += chars[Math.floor(Math.random() * 16)];
  return result;
}

// A malformed escape (%E0%A4%A) makes decodeURIComponent throw, and an uncaught
// throw here turns a scanner's garbage path into a Worker exception. Fall back to
// the raw path instead.
function safeDecode(path) {
  try { return decodeURIComponent(path); } catch { return path; }
}

function getCanary(path) {
  // Decode URL encoding (%2e = ., %2f = /) to catch WAF bypass attempts
  const decoded = safeDecode(path);
  // Check both raw and decoded paths
  for (const p of [path, decoded]) {
    if (CANARY_PATHS[p]) return CANARY_PATHS[p];
    // Prefix match for directory paths
    const normalized = p.endsWith('/') ? p : p + '/';
    for (const [canary, config] of Object.entries(CANARY_PATHS)) {
      if (canary.endsWith('/') && normalized.startsWith(canary)) return config;
    }
  }
  // Catch encoded .env/.py probes anywhere in path (config harvester pattern)
  if (decoded.includes('.env') || decoded.endsWith('.py') || decoded.endsWith('settings.py')) {
    return { type: 'config_probe', fake: 'env' };
  }
  // Catch /logs/ directory listing attempts
  if (decoded === '/logs' || decoded === '/logs/') {
    return { type: 'debug_probe', fake: 'admin' };
  }
  return null;
}

// ================================================================
// APPLIANCE CANARIES — NetScaler ADC / Gateway (2026-09-29)
// ================================================================
// CVE-2026-88771/88772 were exploited for weeks before disclosure. Across 126,873
// edge-honeypot records we held 2 Citrix-shaped paths, both generic .env sprays:
// nothing here looked like a NetScaler, so nobody fingerprinting NetScalers had a
// reason to touch us. These paths are what NetScaler scanners probe first.
//
// SCOPED TO OUR OWN ZONES BY DEFAULT. This Worker also runs on customer
// infrastructure, and a customer may run a real NetScaler behind the same zone.
// Answering its login page with a decoy would break their VPN. Customers opt in
// with APPLIANCE_CANARIES="true"; "false" turns them off everywhere.
//
// Known limit: CVE-2026-88772 is reached over DTLS (UDP). An HTTP Worker never
// sees it. These canaries catch the HTTP fingerprinting that precedes it.
const APPLIANCE_CANARY_PREFIXES = [
  '/vpn/', '/vpns/', '/logon/logonpoint/', '/nf/auth/', '/gwtest/',
  '/citrix/', '/epa/scripts/', '/oauth/idp/',
];
const APPLIANCE_CANARY_EXACT = new Set([
  '/cgi/login', '/saml/login', '/menu/ss', '/menu/neo', '/menu/stc',
  '/vpn/js/rdx/core/lang/rdx_en.json.gz',
]);
const APPLIANCE_OWN_ZONES = ['dugganusa.com', 'aipmsec.com'];

function applianceCanariesEnabled(env, hostname) {
  const flag = String(env.APPLIANCE_CANARIES ?? '').toLowerCase();
  if (flag === 'false') return false;
  if (flag === 'true') return true;
  const host = String(hostname || '').toLowerCase();
  return APPLIANCE_OWN_ZONES.some(z => host === z || host.endsWith('.' + z));
}

// ================================================================
// APPLIANCE CANARIES — Fortinet FortiGate / FortiOS (2026-10-06)
// ================================================================
// Same blind spot, measured: 134,357 edge-honeypot records, zero FortiOS-shaped probes
// (the four "/.env.fortify" hits are Laravel Fortify .env sprays, not Fortinet). Fortinet
// has 31 CISA KEV entries and added 8 in each of 2025 and 2026, and we could not time a
// single one to a first probe. These are the paths FortiGate scanners hit first:
// SSL-VPN portal + login (/remote/*, incl. the CVE-2018-13379 fgt_lang traversal still
// sprayed for credential dumps), FortiCloud SSO start (CVE-2026-24858 class), the
// FortiOS REST API abused by CVE-2022-40684, and the FortiOS 7 admin UI (/ng/).
// Deliberately NOT bare /login or /api/v2/ — too generic. Same scoping as NetScaler.
const FORTINET_CANARY_PREFIXES = ['/remote/', '/api/v2/cmdb/', '/api/v2/monitor/', '/ng/'];
const FORTINET_CANARY_EXACT = new Set(['/remote/login', '/remote/logincheck', '/remote/fgt_lang']);

// ================================================================
// APPLIANCE CANARIES — Oracle PeopleSoft (2026-10-12, 2.8.0)
// ================================================================
// ShinyHunters (GTIG: UNC6240) is mass-exploiting CVE-2026-35273 in the PeopleSoft
// Environment Management Hub, and since September dodges WAF rules by percent-encoding
// the path (/%50SEMHUB/ — WebLogic decodes it, path-literal rules miss it). ttp-check
// 2026-10-12: 22,348 blocks + 51,071 canary hits since 09-01, zero PeopleSoft-shaped —
// we run no PeopleSoft, so that zero was blindness. PSEMHUB is the exploited endpoint;
// PSIGW (Integration Gateway) and the /psp/ /psc/ portal servlets are what PeopleSoft
// fingerprinting hits first. All PeopleSoft-specific — nothing generic.
const PEOPLESOFT_CANARY_PREFIXES = ['/psemhub/', '/psigw/', '/psp/', '/psc/'];

// ================================================================
// APPLIANCE CANARIES — Microsoft SharePoint (2026-10-13, 2.9.0)
// ================================================================
// SharePoint took two CISA KEV entries with 3-day deadlines in 60 days (CVE-2026-55040
// 08-18, CVE-2026-65660 09-25), and ToolShell (CVE-2025-53770) before that. ttp-check
// 2026-10-13: 37,730 blocks + 63,103 canary docs since 08-13, ZERO SharePoint-shaped —
// we run no SharePoint, so that zero was blindness, not quiet. ToolPane.aspx and
// spinstall0.aspx are the ToolShell exploit and webshell paths; /_layouts/, /_vti_bin/
// and /_vti_pvt/ are what SharePoint fingerprinting hits first.
// NOT /_api/: Wix (www) serves its own frontend from /_api/ — a canary there breaks the blog.
const SHAREPOINT_CANARY_PREFIXES = ['/_layouts/', '/_vti_bin/', '/_vti_pvt/', '/_windows/default.aspx/'];
const SHAREPOINT_EXPLOIT_MARKERS = ['toolpane.aspx', 'spinstall0.aspx', 'signout.aspx'];

// ================================================================
// APPLIANCE CANARIES — Ivanti Connect Secure / Pulse Secure (2026-10-13, 2.10.0)
// ================================================================
// CISA added CVE-2026-104935 (Connect Secure auth bypass -> unauthenticated command
// execution) to KEV on Patch Tuesday with a 3-day deadline; Ivanti holds 36 KEV entries and
// Connect Secure has been a repeat target since Pulse Secure (2019-2021, 2024, 2025, 2026).
// ttp-check 2026-10-13: 2,941,882 blocks + 139,334 canary docs since 01-01, ZERO
// dana-na/dana-ws-shaped — we run no Ivanti, so that zero was blindness, not quiet.
// /dana-na/ (login, welcome.cgi, SAML) and /dana-ws/ /dana-cached/ /dana/ are what Connect
// Secure fingerprinting hits first.
// NOT /api/v1/totp/ or /api/v1/configuration/ (the CVE-2023-46805 / CVE-2024-21887 chain):
// analytics serves our own /api/v1/ on these zones, so a canary there would hijack the real API.
const IVANTI_CANARY_PREFIXES = ['/dana-na/', '/dana-ws/', '/dana-cached/', '/dana/'];
const IVANTI_EXPLOIT_MARKERS = ['/../', '%2e%2e', 'license/keys-status', 'totp/user-backup-code'];

// ================================================================
// APPLIANCE CANARIES — Cisco + Palo Alto Networks (2026-10-13, 2.11.0)
// ================================================================
// First packs chosen by measurement instead of by a KEV listing: scripts/canary-gap.mjs joined
// 2,318 exploit-harvester endpoint rules to CISA KEV and the shipped matchers. Cisco: 10 of 10
// KEV CVEs with harvested web paths had NO canary (Cisco holds 100 KEV entries); Palo Alto 3 of
// 3 (15 KEV, ransomware-flagged). Prefixes are the ones those harvested PoCs and the products'
// well-known fingerprinting hit first:
//   Cisco ASA/FTD WebVPN (+CSCOE+ etc.), IOS XE web UI (/webui/, CVE-2023-20198 class), FMC
//   REST (/api/fmc_platform/, /api/fmc_config/), ISE ERS (/ers/), SD-WAN Manager (/dataservice/,
//   /j_security_check), Unified CM (/ccmadmin/, /cucm-uds/, /cmplatform/, /webdialer/).
//   Palo Alto GlobalProtect (/global-protect/, /ssl-vpn/), PAN-OS management (/php/, /unauth/;
//   CVE-2024-0012 ztp_gate.php, CVE-2025-0108 /unauth/%252e%252e/).
// Deliberately NOT generic shapes the harvested PoCs also touched (/api/v1/, /admin/, /status,
// /guest/, /auth/, /portal/): they collide with real routes on our own zones.
const CISCO_CANARY_PREFIXES = ['/+cscoe+/', '/+cscou+/', '/+cscot+/', '/+webvpn+/', '/cscossl', '/webui/',
  '/api/fmc_platform/', '/api/fmc_config/', '/ers/', '/dataservice/', '/ccmadmin/', '/cucm-uds/', '/cmplatform/', '/webdialer/'];
const CISCO_CANARY_EXACT = new Set(['/j_security_check', '/webui', '/+cscoe+/logon.html']);
const CISCO_EXPLOIT_MARKERS = ['logon_hash', '/../', '%2e%2e', 'installclusterstatusexecute', '/upload', 'translation-table', 'cmdexec', 'generatetoken'];
const PALO_CANARY_PREFIXES = ['/global-protect/', '/ssl-vpn/', '/php/', '/unauth/'];
const PALO_EXPLOIT_MARKERS = ['hipreport.esp', 'ztp_gate.php', '%252e%252e', '/../', '%2e%2e', 'uid.php'];

// ================================================================
// APPLIANCE CANARIES — SonicWall SMA1000 (2026-10-14, 2.12.0)
// ================================================================
// CVE-2026-102255: pre-auth SSRF in the SMA1000 Appliance WorkPlace interface, CVSS 10.0,
// hotfixed 2026-10-06 (SNWLID-2026-0017), exploitation attempts from 2026-10-08 (Previdian,
// Defused): crafted OPTIONS requests at the WorkPlace "Extraweb" interface aimed at the
// appliance's internal CouchDB (127.0.0.1:5984, _rewrite design docs, Basic admin:admin).
// ttp-check 2026-10-14 for Extraweb|workplace|5984: 0 in 17,241 blocks, 37,738 canary docs and
// 1,602 origin captures since 09-14, and canary-gap had SMA1000 blind on 2 KEV CVEs whose
// harvested PoCs hit /__api__/login. We run no SonicWall, so that zero was blindness.
// The exact exploit URL is not published, so besides the WorkPlace and /__api__/ prefixes the
// CouchDB SSRF markers trap ANYWHERE on our zones (nothing of ours serves /_rewrite, :5984 or
// "extraweb"). Bare 5984 is NOT a marker: Wix slugs carry CVE numbers like cve-2026-15984.
// NOT /api/ or /_api/: ours (analytics) and Wix's (www).
const SONICWALL_CANARY_PREFIXES = ['/workplace/', '/__api__/'];
const SONICWALL_ANYWHERE_MARKERS = ['extraweb', '/_rewrite', ':5984', '%3a5984'];
const SONICWALL_EXPLOIT_MARKERS = ['/_rewrite', ':5984', '%3a5984', '127.0.0.1', '%2e%2e', '/../'];

function getApplianceCanary(path) {
  // ENCODED-PATH MARKER: a hit whose RAW path differs from its decoded form is the
  // WAF-bypass variant, which is worth knowing separately from a plain probe.
  const encoded = safeDecode(path) !== path;
  for (const p of [path, safeDecode(path)]) {
    const lower = p.toLowerCase();
    const withSlash = lower.endsWith('/') ? lower : lower + '/';
    if (APPLIANCE_CANARY_EXACT.has(lower) ||
        APPLIANCE_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      return { type: 'netscaler_scan', fake: 'netscaler', product: 'citrix-netscaler' };
    }
    if (FORTINET_CANARY_EXACT.has(lower) ||
        FORTINET_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      return { type: 'fortinet_scan', fake: 'fortigate', product: 'fortinet-fortigate' };
    }
    if (PEOPLESOFT_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      return { type: 'peoplesoft_scan', fake: 'peoplesoft', product: 'oracle-peoplesoft', ...(encoded ? { encoded_path: true } : {}) };
    }
    if (CISCO_CANARY_EXACT.has(lower) || CISCO_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre) || (pre === '/cscossl' && lower.startsWith(pre)))) {
      const exploit = CISCO_EXPLOIT_MARKERS.some(m => path.toLowerCase().includes(m) || lower.includes(m));
      return { type: 'cisco_scan', fake: 'cisco', product: ciscoProduct(lower),
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
    if (PALO_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      const exploit = PALO_EXPLOIT_MARKERS.some(m => path.toLowerCase().includes(m) || lower.includes(m));
      const gp = withSlash.startsWith('/global-protect/') || withSlash.startsWith('/ssl-vpn/');
      return { type: 'paloalto_scan', fake: gp ? 'globalprotect' : 'panos', product: gp ? 'paloalto-globalprotect' : 'paloalto-panos-mgmt',
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
    if (SONICWALL_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre)) ||
        SONICWALL_ANYWHERE_MARKERS.some(m => lower.includes(m))) {
      const exploit = SONICWALL_EXPLOIT_MARKERS.some(m => path.toLowerCase().includes(m) || lower.includes(m));
      return { type: 'sonicwall_scan', fake: 'sonicwall', product: 'sonicwall-sma1000',
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
    if (IVANTI_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      const exploit = IVANTI_EXPLOIT_MARKERS.some(m => path.toLowerCase().includes(m) || lower.includes(m));
      return { type: 'ivanti_scan', fake: 'ivanti', product: 'ivanti-connect-secure',
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
    if (SHAREPOINT_CANARY_PREFIXES.some(pre => withSlash.startsWith(pre))) {
      const exploit = SHAREPOINT_EXPLOIT_MARKERS.some(m => lower.includes(m));
      return { type: 'sharepoint_scan', fake: 'sharepoint', product: 'microsoft-sharepoint',
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
  }
  return null;
}

// ================================================================
// SECRET-FILE PROBES (2026-10-14, 2.13.0)
// ================================================================
// Wix's AI Bot Visits report (30d) showed ~15% of AI-fetcher hits on www asking for secrets:
// /credentials.json, /.zshrc, /key.pem, /sa.json, /firebase-adminsdk.json, /rclone.conf,
// /@fs/.../serviceaccount/ca.crt. None was trapped; all reached origin. These get a plain 404 AT
// THE EDGE for everyone, and no fake secret is ever served: a decoy key gets scraped and reported
// as "DugganUSA leaked credentials", and an AI fetcher relays it to its user as fact. Hits are
// LOGGED, never indexed (2.13.2, see the handler): these paths are trivially induced.
// /@fs/ is Vite's dev-server file read (CVE-2025-30208 class) and /__vite_rsc_findSourceMapURL
// is the Vite RSC source-map endpoint; both carry exploit_path. Own zones by default, same
// scoping as the appliance canaries. Bare /config.json is NOT trapped: too generic.
const SECRET_PROBE_EXACT = new Set([
  '/credentials.json', '/.zshrc', '/.bashrc', '/.bash_history', '/.profile', '/.zsh_history',
  '/key.pem', '/private.pem', '/privkey.pem', '/server.key', '/private.key', '/id_rsa', '/id_ed25519', '/id_ecdsa',
  '/sa.json', '/service-account.json', '/serviceaccount.json', '/gcp-key.json', '/rclone.conf',
  '/.npmrc', '/.pypirc', '/.netrc', '/.git-credentials', '/.docker/config.json', '/.kube/config',
  '/runtime-config.js', '/api/config',
]);
const SECRET_PROBE_PREFIXES = ['/@fs/', '/__vite', '/.ssh/', '/.kube/', '/.docker/'];
const SECRET_PROBE_PATTERNS = [/^\/firebase-adminsdk[^/]*\.json$/, /\/var\/run\/secrets\//, /^\/[^/]+\.(pem|p12|pfx)$/];

function getSecretProbe(path) {
  const encoded = safeDecode(path) !== path;
  for (const p of [path, safeDecode(path)]) {
    const lower = p.toLowerCase();
    if (SECRET_PROBE_EXACT.has(lower) || SECRET_PROBE_PREFIXES.some(pre => lower.startsWith(pre)) ||
        SECRET_PROBE_PATTERNS.some(re => re.test(lower))) {
      const exploit = lower.startsWith('/@fs/') || lower.startsWith('/__vite') || lower.includes('/var/run/secrets/');
      return { type: 'secret_probe', fake: 'notfound', product: 'secret-file',
        ...(exploit ? { exploit_path: true } : {}), ...(encoded ? { encoded_path: true } : {}) };
    }
  }
  return null;
}

// How a secret probe arrived. Telemetry only: a label for counting, never a reason to block.
const AI_FETCHER_UA = ['chatgpt-user', 'oai-searchbot', 'gptbot', 'perplexity-user', 'perplexitybot', 'claude-user',
  'claude-searchbot', 'claudebot', 'claude-web', 'meta-externalfetcher', 'meta-externalagent', 'gemini',
  'mistralai-user', 'duckassistbot', 'youbot', 'cohere-ai', 'bytespider', 'amazonbot', 'applebot'];

function secretProbeVia(request, ua, verifiedCrawler) {
  if (verifiedCrawler) return 'verified-crawler';
  const lower = String(ua || '').toLowerCase();
  if (AI_FETCHER_UA.some(t => lower.includes(t))) return 'claims-ai-fetcher';
  const site = (request.headers.get('sec-fetch-site') || '').toLowerCase();
  const dest = (request.headers.get('sec-fetch-dest') || '').toLowerCase();
  if (site === 'cross-site' || site === 'same-site') return 'browser-cross-site';
  if (dest && dest !== 'document' && dest !== 'empty') return 'browser-subresource';
  return 'direct';
}

// A plain, honest 404. No decoy content: see SECRET-FILE PROBES above.
function secretProbeResponse() {
  return new Response('Not found\n', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

// Minimal original markup: a PeopleSoft-style sign-in that posts where PeopleSoft posts.
// No Oracle assets are copied. PS_LOGINLIST / PS_TOKEN are what fingerprinters key on.
function peoplesoftResponse() {
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Oracle PeopleSoft Sign-in</title></head><body><form action="/psp/ps/?cmd=login&languageCd=ENG" method="post" name="login" autocomplete="off"><label for="userid">User ID</label><input type="text" id="userid" name="userid"><label for="pwd">Password</label><input type="password" id="pwd" name="pwd"><input type="hidden" name="timezoneOffset" value="0"><input type="submit" name="Submit" value="Sign In"></form></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': `PS_LOGINLIST=; Path=/; Secure; HttpOnly`,
      'Cache-Control': 'no-store',
    }
  });
}

// Minimal original markup: enough for a fingerprinting scanner to believe it found
// a gateway login. No Citrix assets are copied.
function netscalerResponse() {
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>NetScaler Gateway</title></head><body><div id="logonbox"><form action="/cgi/login" method="post" autocomplete="off"><label for="login">User name</label><input type="text" id="login" name="login"><label for="passwd">Password</label><input type="password" id="passwd" name="passwd"><input type="submit" value="Log On"></form></div></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': `NSC_TEMP=xyz${randomHex(24)}; Path=/; Secure; HttpOnly`,
      'Cache-Control': 'no-store',
    }
  });
}

// Minimal original markup: an SSL-VPN login that posts where FortiOS posts. No Fortinet
// assets are copied. The cookie name is what scanners key on to confirm a FortiGate.
function fortigateResponse() {
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Please Login</title></head><body><div class="login"><form action="/remote/logincheck" method="post" autocomplete="off"><label for="username">Username</label><input type="text" id="username" name="username"><label for="credential">Password</label><input type="password" id="credential" name="credential"><input type="hidden" name="realm" value=""><button type="submit">Login</button></form></div></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      // SVPNCOOKIE is FortiOS's. 2.9.0 overwrote it with PeopleSoft's PS_LOGINLIST while fixing the
      // PeopleSoft decoy (the bug was in peoplesoftResponse, not here); restored 2.10.0.
      'Set-Cookie': `SVPNCOOKIE=; path=/; secure; httponly`,
      'Cache-Control': 'no-store',
    }
  });
}

// Minimal original markup, SharePoint-shaped headers. MicrosoftSharePointTeamServices and
// SPRequestGuid are what fingerprinters key on. No Microsoft assets are copied.
function sharepointResponse() {
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign In</title></head><body><form method="post" action="/_layouts/15/Authenticate.aspx" id="aspnetForm"><input type="hidden" name="__VIEWSTATE" value=""><label for="user">User name</label><input type="text" id="user" name="user"><label for="pass">Password</label><input type="password" id="pass" name="pass"><input type="submit" value="Sign in"></form></body></html>`;
  return new Response(body, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'MicrosoftSharePointTeamServices': '16.0.0.10417',
      'SPRequestGuid': crypto.randomUUID(),
      'X-AspNet-Version': '4.0.30319',
      'Cache-Control': 'no-store',
    }
  });
}

function ciscoProduct(lower) {
  if (/^\/(\+csco|\+webvpn|cscossl)/.test(lower)) return 'cisco-asa-webvpn';
  if (lower.startsWith('/webui')) return 'cisco-iosxe-webui';
  if (lower.startsWith('/api/fmc_')) return 'cisco-fmc';
  if (lower.startsWith('/ers/')) return 'cisco-ise';
  if (lower.startsWith('/dataservice/') || lower === '/j_security_check') return 'cisco-sdwan-manager';
  return 'cisco-unified-cm';
}

// Minimal original markup per Cisco surface. No Cisco assets are copied. webvpnlogin (ASA) and
// the page titles are what fingerprinters key on.
function ciscoResponse(product) {
  const title = { 'cisco-asa-webvpn': 'SSL VPN Service', 'cisco-iosxe-webui': 'Web UI Login', 'cisco-fmc': 'Login',
    'cisco-ise': 'Identity Services Engine', 'cisco-sdwan-manager': 'Cisco vManage', 'cisco-unified-cm': 'Cisco Unified CM Administration' }[product] || 'Login';
  if (product === 'cisco-fmc' || product === 'cisco-ise') {
    return new Response(JSON.stringify({ error: { category: 'FRAMEWORK', messages: [{ description: 'Authentication required' }], severity: 'ERROR' } }), {
      status: 401, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title></head><body><form method="post" action="${product === 'cisco-asa-webvpn' ? '/+webvpn+/index.html' : '/j_security_check'}" autocomplete="off"><label for="username">Username</label><input type="text" id="username" name="${product === 'cisco-asa-webvpn' ? 'username' : 'j_username'}"><label for="password">Password</label><input type="password" id="password" name="${product === 'cisco-asa-webvpn' ? 'password' : 'j_password'}"><input type="submit" value="Login"></form></body></html>`;
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' };
  if (product === 'cisco-asa-webvpn') headers['Set-Cookie'] = 'webvpnlogin=1; path=/; secure';
  return new Response(body, { status: 200, headers });
}

// Minimal original markup. No Palo Alto assets are copied. GlobalProtect clients and scanners
// first hit prelogin.esp, which answers XML; the portal title and PHPSESSID on the management
// UI are what PAN-OS fingerprinters key on.
function paloResponse(fake, lower) {
  if (fake === 'globalprotect' && lower.endsWith('prelogin.esp')) {
    return new Response('<?xml version="1.0" encoding="UTF-8" ?><prelogin-response><status>Success</status><ccusername/><autosubmit>false</autosubmit><msg/><newmsg/><authentication-message>Enter login credentials</authentication-message><username-label>Username</username-label><password-label>Password</password-label><panos-version>1</panos-version><region>US</region></prelogin-response>', {
      status: 200, headers: { 'Content-Type': 'application/xml; charset=UTF-8', 'Cache-Control': 'no-store' } });
  }
  const title = fake === 'globalprotect' ? 'GlobalProtect Portal' : 'Login';
  const action = fake === 'globalprotect' ? '/global-protect/login.esp' : '/php/login.php';
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title></head><body><form method="post" action="${action}" name="login" autocomplete="off"><label for="user">Name</label><input type="text" id="user" name="user"><label for="passwd">Password</label><input type="password" id="passwd" name="passwd"><input type="submit" value="Log In"></form></body></html>`;
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' };
  if (fake === 'panos') headers['Set-Cookie'] = 'PHPSESSID=; path=/; secure; httponly';
  return new Response(body, { status: 200, headers });
}

// Minimal original markup: a Connect Secure-style sign-in that posts where it posts. No Ivanti
// assets are copied. DSSignInURL / DSID are the cookies Connect Secure fingerprinters key on.
function ivantiResponse() {
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Ivanti Connect Secure</title></head><body><form name="frmLogin" action="/dana-na/auth/url_default/login.cgi" method="post" autocomplete="off"><input type="hidden" name="tz_offset" value=""><input type="hidden" name="realm" value="Users"><label for="username">Username</label><input type="text" id="username" name="username"><label for="password">Password</label><input type="password" id="password" name="password"><input type="submit" name="btnSubmit" value="Sign In"></form></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': `DSSignInURL=/; path=/; secure; httponly`,
      'Cache-Control': 'no-store',
    }
  });
}

// Minimal original markup: a WorkPlace-style sign-in. No SonicWall assets are copied. The
// /__api__/ surface answers 401 JSON, which is what the SMA1000 login API returns unauthenticated.
function sonicwallResponse(lower) {
  if (lower.startsWith('/__api__/')) {
    return new Response(JSON.stringify({ status: 'error', message: 'Unauthorized' }), {
      status: 401, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }
  const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WorkPlace - Log in</title></head><body><form method="post" action="/__api__/login" name="loginForm" autocomplete="off"><label for="username">Username</label><input type="text" id="username" name="username"><label for="password">Password</label><input type="password" id="password" name="password"><input type="submit" value="Log in"></form></body></html>`;
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

// ================================================================
// HARVESTED-PATH OBSERVATION (2.15.0, 2026-10-18)
// ================================================================
// The exploit harvester indexes the endpoint paths of public PoCs, often before CISA lists the
// CVE (Atlassian CVE-2026-21589: harvested 10-06, KEV 10-15). Every appliance canary above was
// written by hand AFTER a KEV listing exposed the blind spot, so the edge recorded nothing in
// between. This list is generated from the harvest (scripts/generate-harvested-paths.mjs) so the
// first probe of a harvested path can be timed against the PoC date and the KEV date.
//
// OBSERVE ONLY. A match is passed through untouched: no decoy, no block, no IOC. The worker
// reports {cves, path, coarse source net, ASN} to /feed/observation and nothing else. A probe can
// be INDUCED (link previewers, prompt-injected fetchers), so a hit says a path ARRIVED, never
// who sent it. Scoped to our own zones by default (HARVESTED_OBSERVE = unset); customers may opt
// in with "true", and "false" turns it off everywhere.
//
// FREE-PLAN SHAPE: one Map lookup per request on a bundled list (no KV), work only on a match,
// and at most one report per source net and path per isolate per 10 minutes.
// BEGIN HARVESTED_PATHS — GENERATED by scripts/generate-harvested-paths.mjs, do not edit by hand.
// 2026-10-18T21:18:24.457Z: 1894 paths, 700 CVEs (considered 10522; dropped junk 5578,
// own-site 357, generic 1396, shared by >3 CVEs 21, over cap 0).
// Lowercase, no query string, no trailing slash. Value: comma-separated CVE ids.
const HARVESTED_PATHS_GENERATED_AT = "2026-10-18T21:18:24.457Z";
const HARVESTED_PATHS = new Map([["/__api__/login","CVE-2026-15409"],["/__api__/login.","CVE-2026-15409"],["/__api__/logout","CVE-2026-15409"],["/__api__/logout.","CVE-2026-15409"],["/_controltemplates/15/acleditor.ascx","CVE-2025-53770"],["/_layouts/15/metadata/json/1","CVE-2026-55040,CVE-2026-63520"],["/_layouts/15/notify.aspx","CVE-2026-32201"],["/_layouts/15/spinstall0.aspx","CVE-2025-53770"],["/_layouts/15/start.aspx","CVE-2026-32201"],["/_layouts/15/toolpane.aspx","CVE-2025-53770"],["/_layouts/signout.aspx","CVE-2025-53770"],["/_next/chunks","CVE-2026-44578"],["/_next/image","CVE-2026-96889"],["/_next/static","CVE-2025-29927,CVE-2025-55182,CVE-2026-44578"],["/_next/static/build_id","CVE-2025-29927"],["/_next/static/chunks/framework-","CVE-2025-29927"],["/_next/static/chunks/webpack-runtime-","CVE-2025-29927"],["/_rels/.rels","CVE-2026-21509"],["/_rels/document.xml.rels","CVE-2026-21509"],["/_trust/default.aspx","CVE-2026-50522"],["/_vti_bin/client.svc","CVE-2026-56164"],["/_vti_pvt/buildversion.xml","CVE-2025-53770"],["/--sid/--upn","CVE-2026-55040"],["/-/user/settings/applications","CVE-2026-52806"],["/.git/config","CVE-2026-64638"],["/.n8n/config","CVE-2026-21858"],["/.n8n/database.sqlite","CVE-2026-21858"],["/.nxc/modules","CVE-2026-54121"],["/.phtml/.phar/...","CVE-2026-48908"],["/.phtml/.php7","CVE-2026-65694"],["/.ssh/authorized_keys","CVE-2025-27590,CVE-2025-30208,CVE-2026-22804"],["/.ssh/config","CVE-2026-99999"],["/.ssh/id_rsa","CVE-2026-53613"],["/.ssh/id_rsa.pub","CVE-2026-33017"],["//root/.ssh/id_rsa","CVE-2025-10952"],["/0/62ggmc45pk9ba7qbzopdi9omrtprym3zr9raee3b7hspmxnaydtuftngdvwvzkzik9teouohxhffj3crjxhrzloupl","CVE-2025-53770"],["/1.0/_/download/resources","CVE-2026-21589"],["/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-internal","CVE-2026-21589"],["/1/_/download/resources","CVE-2026-21589"],["/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images","CVE-2026-21589"],["/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..","CVE-2026-21589"],["/1/cgroup","CVE-2025-30208"],["/1/config/set","CVE-2025-60787"],["/1/configeditor","CVE-2023-27350"],["/1/configeditor/quickfindform","CVE-2023-27350"],["/1/printerdetails","CVE-2023-27350"],["/1/printerdetails/printeroptionstab.tab","CVE-2023-27350"],["/1/printerlist/selectprinter","CVE-2023-27350"],["/1/setupcompleted","CVE-2023-27350"],["/1/v2/evaluate","CVE-2026-96872"],["/10.0.0.5.8000/pwned","CVE-2025-6000"],["/10.0.0.5/payload.ps1","CVE-2026-3462"],["/10.129.23.10/terminal/ws","CVE-2026-39987"],["/10.58.8.213/scriptcase/devel/iface/login.php","CVE-2025-47227"],["/10.58.8.213/scriptcase/prod/lib/php/devel/iface/login.php","CVE-2025-47227"],["/127.0.0.1/openeclass","CVE-2026-22241"],["/127.0.0.1/pocshare","CVE-2026-104715"],["/127.0.0.1/wolfcms","CVE-2026-67206"],["/127.0.0.1/wordpress","CVE-2025-39538,CVE-2026-3576"],["/16/64-bit","CVE-2026-39987"],["/169.254.169.254/latest/meta-data","CVE-2026-12944,CVE-2026-75898"],["/169.254.169.254/latest/meta-data/iam/security-credentials","CVE-2026-91136"],["/172.23.71.121/wordpress","CVE-2026-19500"],["/192.168.1.47/jobs","CVE-2025-45346"],["/192.168.1.50/librenms","CVE-2026-26988"],["/192.168.100.50/pa","CVE-2026-9586"],["/1e4c911a3fd2244596863ddbfa6f3600/7970621079b41658dcd6c205640b3602/fake","CVE-2025-30208"],["/2022/subed","CVE-2026-45659"],["/2026/06/10/hello-world","CVE-2026-9067"],["/2lhdxqojcpf01qheg1tz5pc/yumfcual6qtk","CVE-2025-29775"],["/3jn/pf2/75zhd","CVE-2026-45833"],["/3vyaabbm8gbwyjl/rkvz2fbnwiaahhwaaaaanvyaatbm8gcrpmx","CVE-2025-24813"],["/3xx/4xx/5xx","CVE-2025-57819"],["/3zn5zu87ekhfnlolpqerp8npztfod4vlbjgy1tcjlwq6ajsjmusp1naac/cbvwluxbs0nhbem227wv527u8m3hx2lpkokkiy","CVE-2026-45833"],["/4k/kaslr","CVE-2026-43499"],["/4qcqds/l42prl","CVE-2026-77276"],["/4wrx2uzmbtg7/0ukvs06ihjqb3zbgobg1tyeo9oy6ybjpgtdhbfvudvu44x6fukpn9","CVE-2025-53770"],["/5/sha256","CVE-2026-1281"],["/9fxd9mjpmi3tavdqqvzdmiirllmupbaprii1ri/hnrw7uei176uwce7720g7hh2wheyove9xgva6fgpjixiynntog","CVE-2026-77276"],["/9vagaaaaaaaadcawaaaaaaamidaaaaaaaacgaaaaaaaaaeaaaaaaaaaaiaaaaaaaaaagaaaaaaaaboaaaa/v","CVE-2026-24018"],["/access/api/v1/registry/join","CVE-2026-82329"],["/access/api/v1/tokens","CVE-2026-82329"],["/access/api/v1/users","CVE-2026-82329"],["/access/api/v1/users/admin","CVE-2026-82329"],["/access/api/v2/users","CVE-2026-82329"],["/access/set","CVE-2024-1212"],["/account/lost-password","CVE-2026-11387,CVE-2026-8206"],["/actions.php","CVE-2025-69212"],["/actions/assets/generate-transform","CVE-2025-32432"],["/actions/element-indexes/count-elements","CVE-2026-31857"],["/actions/element-search/search","CVE-2026-28695,CVE-2026-79987"],["/actions/elements/save","CVE-2026-79987"],["/actions/users/save-user","CVE-2026-79987"],["/actuator/beans","CVE-2026-40976"],["/actuator/configprops","CVE-2026-40976"],["/actuator/custom-shutdown","CVE-2026-40976"],["/actuator/env","CVE-2026-40976"],["/actuator/health","CVE-2026-40976"],["/actuator/mappings","CVE-2026-40976"],["/actuator/shutdown","CVE-2026-40976"],["/actuator/threaddump","CVE-2026-40976"],["/add/post","CVE-2025-25062"],["/adm/index.php","CVE-2026-48611"],["/admin/actions/app/set-license-shun-cookie","CVE-2026-92592"],["/admin/actions/assets/generate-transform","CVE-2025-32432"],["/admin/actions/element-search/search","CVE-2026-44011"],["/admin/actions/users/login","CVE-2026-92592"],["/admin/ajax.php","CVE-2025-57819"],["/admin/ajaxconfig","CVE-2025-7404"],["/admin/api/jsonrpc","CVE-2025-34071"],["/admin/api/jsonrpc/upload","CVE-2025-34071"],["/admin/api/malicious","CVE-2025-20281"],["/admin/cores","CVE-2026-44825"],["/admin/file-manager.php","CVE-2026-92247"],["/admin/gravity.php","CVE-2024-34361"],["/admin/groups-adlists.php","CVE-2024-34361"],["/admin/internal/dologin.php","CVE-2025-34071"],["/admin/mail/compose","CVE-2026-38526"],["/admin/mail/inbox","CVE-2026-38526"],["/admin/master/console","CVE-2026-18963,CVE-2026-4282"],["/admin/modules","CVE-2025-57819"],["/admin/myaccount","CVE-2026-79987"],["/admin/plugin/file_manager","CVE-2026-67206"],["/admin/plugin/file_manager/create_file","CVE-2026-67206"],["/admin/plugin/file_manager/save","CVE-2026-67206"],["/admin/plugin/file_manager/view/shell.php","CVE-2026-67206"],["/admin/rbacuser/index","CVE-2026-3786"],["/admin/realms","CVE-2026-18963"],["/admin/realms/poc","CVE-2026-18963"],["/admin/realms/poc/clients","CVE-2026-18963"],["/admin/realms/poc/users","CVE-2026-18963"],["/admin/register-admin","CVE-2026-22599"],["/admin/rooms.php","CVE-2026-14762"],["/admin/scripts/pi-hole/php/gravity.sh.php","CVE-2024-34361"],["/admin/scripts/pi-hole/php/groups.php","CVE-2024-34361"],["/admin/servers","CVE-2026-54415"],["/admin/servers/create","CVE-2026-54415"],["/admin/settings/custom_fields","CVE-2026-66748"],["/admin/tinymce/upload","CVE-2026-38526"],["/admin/vpn","CVE-2026-16348,CVE-2026-22226"],["/administrator/components/com_acym/acym.xml","CVE-2026-94132"],["/administrator/components/com_acym/com_acym.xml","CVE-2026-94132"],["/administrator/components/com_baforms/baforms.xml","CVE-2026-102425,CVE-2026-56291"],["/administrator/components/com_baforms/com_baforms.xml","CVE-2026-102425"],["/administrator/components/com_booklibrary/booklibrary.xml","CVE-2026-101110"],["/administrator/components/com_booklibrary/com_booklibrary.xml","CVE-2026-101110"],["/administrator/components/com_djclassifieds/djclassifieds.xml","CVE-2026-61424"],["/administrator/components/com_icagenda/icagenda.xml","CVE-2026-48939"],["/administrator/components/com_jce/jce.xml","CVE-2026-48907"],["/administrator/components/com_os_cck","CVE-2026-102428"],["/administrator/components/com_os_cck/com_os_cck.xml","CVE-2026-102428"],["/administrator/components/com_os_cck/os_cck.xml","CVE-2026-102428"],["/administrator/components/com_osgallery_light/osgallery.xml","CVE-2026-88854"],["/administrator/components/com_osgallery/com_osgallery.xml","CVE-2026-88854"],["/administrator/components/com_osgallery/osgallery.xml","CVE-2026-88854"],["/administrator/components/com_realestatemanager/com_realestatemanager.xml","CVE-2026-100752"],["/administrator/components/com_realestatemanager/realestatemanager.xml","CVE-2026-100752"],["/administrator/components/com_rsfiles/rsfiles.xml","CVE-2026-57827"],["/administrator/components/com_simplemembership/com_simplemembership.xml","CVE-2026-102782"],["/administrator/components/com_simplemembership/simplemembership.xml","CVE-2026-102782"],["/administrator/components/com_sppagebuilder","CVE-2026-48908"],["/administrator/components/com_sppagebuilder/sppagebuilder.xml","CVE-2026-48908"],["/administrator/components/com_vehiclemanager/com_vehiclemanager.xml","CVE-2026-101108"],["/administrator/components/com_vehiclemanager/vehiclemanager.xml","CVE-2026-101108"],["/administrator/components/com_youtubegallery/com_youtubegallery.xml","CVE-2026-94130"],["/administrator/components/com_youtubegallery/youtubegallery.xml","CVE-2026-94130"],["/administrator/manifests/files/joomla.xml","CVE-2026-48907,CVE-2026-90907"],["/administrator/manifests/files/joomla.xml.","CVE-2026-90907"],["/ajax_table.php","CVE-2026-26988"],["/ajax-api/2.0/mlflow/registered-models/search","CVE-2024-37054"],["/ajax/api/ad/replaceadtemplate","CVE-2026-61511"],["/ajax/api/ad/wrapadtemplate","CVE-2025-48827"],["/ajax/api/content_infraction/getindexablecontent","CVE-2026-61511"],["/ajax/api/content_privatemessage/getindexablecontent","CVE-2026-61511"],["/ajax/api/content_redirect/getindexablecontent","CVE-2026-61511"],["/ajax/api/content_report/getindexablecontent","CVE-2026-61511"],["/ajax/api/content_text/getindexablecontent","CVE-2026-61511"],["/ajax/api/content_video/getindexablecontent","CVE-2026-61511"],["/ajax/common.tabs.php","CVE-2025-24801,CVE-2026-26026"],["/ajax/compose.php","CVE-2026-58455"],["/ajax/fileupload.php","CVE-2025-24801"],["/ajax/render/pagenav","CVE-2026-61511"],["/ajax/render/widget_php","CVE-2026-61511"],["/ajax/render/widget_tabbedcontainer_tab_panel","CVE-2026-61511"],["/ajax/status.php","CVE-2026-27470"],["/ajax/teledeployoptions.php","CVE-2026-16475"],["/amc/api/auth/login","CVE-2026-15410"],["/amc/api/diagnostic","CVE-2026-15410"],["/amc/diagnostic/ping","CVE-2026-15410"],["/amc/diagnostic/traceroute","CVE-2026-15410"],["/amc/login","CVE-2026-15410"],["/amc/maintenance/hotfix","CVE-2026-15410"],["/android/sdk/ndk","CVE-2025-21479"],["/ansible_user/ansible_port","CVE-2026-99999"],["/apache/airflow","CVE-2026-59243"],["/apache/airflow/security-advisories","CVE-2026-59243"],["/api_jsonrpc.php","CVE-2024-42327"],["/api/%s/export-preview","CVE-2026-105844"],["/api/2.0/mlflow-artifacts/artifacts","CVE-2024-37054,CVE-2025-11201"],["/api/2.0/mlflow/experiments/create","CVE-2025-11201"],["/api/2.0/mlflow/experiments/search","CVE-2024-37054"],["/api/2.0/mlflow/model-versions/create","CVE-2024-37054,CVE-2025-11201"],["/api/2.0/mlflow/model-versions/transition-stage","CVE-2024-37054"],["/api/2.0/mlflow/registered-models/create","CVE-2024-37054,CVE-2025-11201"],["/api/2.0/mlflow/runs/create","CVE-2024-37054,CVE-2025-11201"],["/api/2.0/mlflow/webhooks","CVE-2026-64849"],["/api/3.0/mlflow/traces","CVE-2026-53995"],["/api/3/action/datastore_search_sql","CVE-2026-42031"],["/api/access","CVE-2026-105844"],["/api/accounts/prelogin","CVE-2026-26012"],["/api/acs","CVE-2026-9090"],["/api/actions/frontend/formaction.php","CVE-2026-10196"],["/api/ad/replaceadtemplate","CVE-2025-48827,CVE-2025-48828"],["/api/admin/stats","CVE-2026-29000"],["/api/agent/tabs/agentdata","CVE-2022-28219"],["/api/ai-import","CVE-2026-59970"],["/api/ai-step-sort","CVE-2026-59970"],["/api/am/admin/v1/tenant-config","CVE-2026-5430"],["/api/am/admin/v2/key-managers","CVE-2026-5430"],["/api/am/admin/v2/tenant-config","CVE-2026-5430"],["/api/am/admin/v3/key-managers","CVE-2026-5430"],["/api/am/admin/v3/tenant-config","CVE-2026-5430"],["/api/am/admin/v4/key-managers","CVE-2026-5430"],["/api/am/admin/v4/tenant-config","CVE-2026-5430"],["/api/am/admin/v4/throttling/policies/application","CVE-2026-5430"],["/api/am/publisher/v2/apis","CVE-2026-5430"],["/api/am/publisher/v3/apis","CVE-2026-5430"],["/api/am/publisher/v4/apis","CVE-2026-5430"],["/api/archive","CVE-2026-101894"],["/api/attachments/signature","CVE-2026-104100"],["/api/auth/validate-sso","CVE-2026-34908,CVE-2026-34910"],["/api/auth/validate-sso/..%2f..%2f..%2f","CVE-2026-34908,CVE-2026-34910"],["/api/auth/validate-sso/..%2f..%2f..%2fapp-assets","CVE-2026-34910"],["/api/avatar.php","CVE-2024-2961"],["/api/azlink/password","CVE-2026-54415"],["/api/backup.","CVE-2026-27944"],["/api/check_user","CVE-2026-58048"],["/api/ciphers/organization-details","CVE-2026-26012"],["/api/code/run","CVE-2026-100721"],["/api/collections","CVE-2026-26012,CVE-2026-44166"],["/api/collections/_superusers/auth-with-password","CVE-2026-44166"],["/api/collections/members/auth-with-oauth2","CVE-2026-44166"],["/api/command","CVE-2026-15410"],["/api/common/system/getinitdata","CVE-2026-88629"],["/api/config/load","CVE-2026-56158"],["/api/config/raw","CVE-2026-25643"],["/api/config/save","CVE-2026-25643"],["/api/configurations/all","CVE-2026-44613"],["/api/core/chat/gethistories","CVE-2026-79483"],["/api/create_database","CVE-2026-58048"],["/api/customnode/install/git_url","CVE-2026-22777"],["/api/dashboard...","CVE-2026-29000"],["/api/database","CVE-2026-72898"],["/api/dataset","CVE-2026-59827,CVE-2026-72898"],["/api/datasources","CVE-2026-21721"],["/api/decompress","CVE-2026-101894"],["/api/demo","CVE-2026-22785"],["/api/deserialize","CVE-2026-56158"],["/api/docs","CVE-2026-22730"],["/api/documents/upload","CVE-2026-105314"],["/api/dump","CVE-2026-56782"],["/api/echo","CVE-2026-42945"],["/api/endpoints","CVE-2026-44848"],["/api/eval","CVE-2026-100721"],["/api/events.json","CVE-2026-76060"],["/api/execute","CVE-2026-100721"],["/api/exploit/exfiltration","CVE-2025-30065"],["/api/exploit/exploit","CVE-2025-30065"],["/api/exploit/init","CVE-2025-30065"],["/api/exploit/mitigation","CVE-2025-30065"],["/api/exploit/privilege","CVE-2025-30065"],["/api/exploit/recon","CVE-2025-30065"],["/api/exploit/summary","CVE-2025-30065"],["/api/extract","CVE-2026-101894"],["/api/fabric/device/status","CVE-2025-25257"],["/api/filetree/searchdocs","CVE-2026-69084"],["/api/filter","CVE-2025-64459"],["/api/firmware/update","CVE-2026-8065"],["/api/firmware/upload","CVE-2026-8065"],["/api/flows","CVE-2026-27966"],["/api/fmc_config/v1/upgradesession","CVE-2026-20079"],["/api/fmc_platform/v1/auth/generatetoken","CVE-2026-20131"],["/api/get-application","CVE-2026-9090"],["/api/get-providers","CVE-2026-9090"],["/api/health_check","CVE-2026-88533"],["/api/host/login.json","CVE-2026-76060"],["/api/install","CVE-2026-107806"],["/api/instances","CVE-2026-55559"],["/api/instances/%s","CVE-2026-55559"],["/api/integrations","CVE-2026-31816"],["/api/interpreter","CVE-2026-44613"],["/api/interpreter/setting","CVE-2026-44613"],["/api/interpreter/setting/restart/md","CVE-2026-44613"],["/api/items","CVE-2025-64459"],["/api/jobs","CVE-2025-62593"],["/api/jobs/%s/logs","CVE-2025-62593"],["/api/jolokia","CVE-2026-34197,CVE-2026-42588"],["/api/jolokia/list","CVE-2026-34197"],["/api/jolokia/read/org.apache.activemq","CVE-2026-34197"],["/api/jolokia/search","CVE-2026-34197"],["/api/jolokia/version","CVE-2026-34197"],["/api/json","CVE-2026-84645"],["/api/list","CVE-2025-64459"],["/api/list_databases","CVE-2026-58048"],["/api/local_doc_qa/new_knowledge_base","CVE-2026-88533"],["/api/local_doc_qa/upload_files","CVE-2026-88533"],["/api/mcp/connect","CVE-2026-23520,CVE-2026-23744"],["/api/metadata/workflow","CVE-2026-58138"],["/api/method/frappe.auth.get_csrf_token","CVE-2026-111389"],["/api/method/hrms.api.get_company_currencies","CVE-2026-111389"],["/api/method/hrms.payroll.doctype.salary_structure.salary_structure.get_salary_component","CVE-2026-111389"],["/api/method/login","CVE-2026-111389"],["/api/modular-connector/login","CVE-2026-23550"],["/api/monitors.json","CVE-2026-76060"],["/api/myinappchannels","CVE-2026-52887"],["/api/nginx/test","CVE-2026-107806"],["/api/notebook","CVE-2026-44613"],["/api/notebook/job/note_id","CVE-2026-44613"],["/api/notebook/note_id/paragraph","CVE-2026-44613"],["/api/olivetin.api.v1.olivetinapiservice/executionstatus","CVE-2026-27626"],["/api/olivetin.api.v1.olivetinapiservice/startaction","CVE-2026-27626"],["/api/opencode","CVE-2026-88899"],["/api/opencode/session","CVE-2026-88899"],["/api/orders","CVE-2025-64459"],["/api/package.json","CVE-2026-100721"],["/api/pages","CVE-2026-25099"],["/api/playground/run","CVE-2026-100721"],["/api/posts","CVE-2025-64459"],["/api/process","CVE-2026-41242"],["/api/products","CVE-2025-64459"],["/api/remote","CVE-2025-0868"],["/api/rename_database","CVE-2026-58048"],["/api/repositories","CVE-2026-82329"],["/api/restore","CVE-2026-107806,CVE-2026-56158,CVE-2026-56782"],["/api/sandbox/run","CVE-2026-100721"],["/api/scheduler","CVE-2026-25939"],["/api/search/fulltextsearchassetcontent","CVE-2026-69083"],["/api/search/searchembedblock","CVE-2026-69084"],["/api/security/user","CVE-2026-44613"],["/api/services/winrest/powershell/nodes/dc/invokecommand","CVE-2026-26119"],["/api/session/properties","CVE-2026-72898"],["/api/session/reset_password","CVE-2026-72898"],["/api/set_sql_mode","CVE-2026-58048"],["/api/settings/test_notification","CVE-2026-55494"],["/api/smartfilters/testexecutions","CVE-2026-5562"],["/api/support/mcp/client/gettools","CVE-2026-88629"],["/api/sync","CVE-2026-26012"],["/api/sync...","CVE-2026-26012"],["/api/system/loginauth","CVE-2026-69084"],["/api/ticket","CVE-2026-44613"],["/api/token-auth","CVE-2025-54123"],["/api/tools/exec","CVE-2026-28363"],["/api/trpc/chat.conversation.delete","CVE-2026-65013"],["/api/trpc/member.remove","CVE-2026-65013"],["/api/trpc/project.get","CVE-2026-65013"],["/api/two-factor/send-email-login","CVE-2026-43914"],["/api/update_profile.php","CVE-2024-2961"],["/api/upgrade/current","CVE-2026-107806"],["/api/user/current","CVE-2026-72898"],["/api/user/key","CVE-2026-26119"],["/api/users/admin/init","CVE-2026-44848"],["/api/users/current","CVE-2026-61628"],["/api/users/onboarding/finish","CVE-2026-61628"],["/api/users/onboarding/status","CVE-2026-61628"],["/api/v1beta/agent","CVE-2026-75898"],["/api/v1beta/chat","CVE-2026-75898"],["/api/v2/api-token-auth","CVE-2026-16764"],["/api/v2/dags/%s/dagruns","CVE-2026-59243"],["/api/v2/hoverfly/middleware","CVE-2025-54123"],["/api/v2/mcp/servers","CVE-2026-12940,CVE-2026-5027,CVE-2026-93674"],["/api/v2/products","CVE-2026-16764"],["/api/v2/sentry/mics-config/handlemessage","CVE-2026-10520"],["/api/v4/projects","CVE-2026-85706"],["/api/v4/projects/1/repository/commits","CVE-2026-85706"],["/api/verify","CVE-2026-4444"],["/api/viewstate","CVE-2026-56158"],["/api/vnc/start","CVE-2026-25089"],["/api/workflow","CVE-2026-58138"],["/apiremoting30/webservice.asmx","CVE-2025-59287,CVE-2026-24061,CVE-2026-41940"],["/apirest.php","CVE-2026-53625"],["/apirest.php/changeactiveprofile","CVE-2026-53625"],["/apirest.php/getfullsession","CVE-2026-53625"],["/apirest.php/getglpiconfig","CVE-2026-53625"],["/apirest.php/getmyprofiles","CVE-2026-53625"],["/apirest.php/initsession","CVE-2026-53625"],["/apirest.php/killsession","CVE-2026-53625"],["/apirest.php/user","CVE-2026-53625"],["/app-cache/seed","CVE-2026-75604"],["/app.local/search","CVE-2026-111444"],["/app/.venv/lib/python3.14/site-packages","CVE-2026-105314"],["/app/agents/v1/commands/error","CVE-2026-63077"],["/app/agents/v1/register","CVE-2026-63077"],["/app/base/session/login","CVE-2026-67599"],["/app/certifi.zip","CVE-2026-25645"],["/app/composer.json","CVE-2026-84361"],["/app/log_viewer/index","CVE-2026-67599"],["/app/orders/processorder.action","CVE-2026-104711"],["/app/rest/debug/processes","CVE-2024-27198"],["/app/saved_model","CVE-2026-0596"],["/application/api/api.php","CVE-2025-34299"],["/applications/splunk/etc/apps/splunk_secure_gateway/lib","CVE-2026-20251"],["/apply.cgi","CVE-2026-58457"],["/apps/account-ui/package.json","CVE-2026-18963"],["/apps/admin-ui/package.json","CVE-2026-18963"],["/apps/openssl","CVE-2025-69421"],["/apps/sap.com","CVE-2025-31324"],["/apps/user_oidc/id4me","CVE-2026-45156"],["/apps/user_oidc/id4me/code","CVE-2026-45156"],["/appshome.do","CVE-2026-11374"],["/archive/master.tar.gz","CVE-2026-27180"],["/array/method","CVE-2026-23489"],["/artifactory/api/repositories","CVE-2026-66384,CVE-2026-82329"],["/artifactory/api/security/users","CVE-2026-82329"],["/artifactory/api/system/configuration","CVE-2026-82329"],["/artifactory/api/system/info","CVE-2026-82329"],["/artifactory/api/system/ping","CVE-2026-66384,CVE-2026-82329"],["/artifactory/api/system/version","CVE-2026-66384,CVE-2026-82329"],["/artifactory/webapp","CVE-2026-82329"],["/artifacts/credentials","CVE-2026-32604"],["/artifacts/fetch","CVE-2026-32604"],["/aspnet_client/system_web/shell.aspx","CVE-2026-62911"],["/assessment_thanks.do","CVE-2026-6875"],["/assets/generate-transform","CVE-2025-32432"],["/attachment/upload","CVE-2026-27636"],["/attachments/img/avatar/..%2f..%2f..%2f..%2f..","CVE-2025-57231"],["/attacker.local/evil.mov","CVE-2025-24271"],["/attacker/evil.xml","CVE-2026-34197"],["/attacker/pwn","CVE-2026-35204"],["/attributes/attr","CVE-2026-58073"],["/audio/audio.mp3","CVE-2025-2249"],["/auth/approle/login","CVE-2026-15911,CVE-2026-57836"],["/auth/auth/oidc/callback","CVE-2026-48558"],["/auth/callback/oidc","CVE-2026-48558"],["/auth/login/azure","CVE-2026-59243"],["/auth/oidc","CVE-2026-48558"],["/auth/oidc/callback","CVE-2026-48558"],["/auth/realms/...","CVE-2026-18963"],["/authenticate/login","CVE-2024-2044"],["/author/admin","CVE-2026-85984"],["/authorization.do","CVE-2026-11374"],["/authorizationserver/oauth/token","CVE-2026-58231"],["/automation-web-platform.php","CVE-2026-14281"],["/avatar/..","CVE-2026-21589"],["/awk/grep/cp/id","CVE-2026-43499"],["/b/com1","CVE-2026-27199"],["/backslashes/colons","CVE-2026-49179"],["/baculaweb.domain/jobfiles/29/1","CVE-2025-45346"],["/badger/exchange-session","CVE-2026-72001"],["/badger/verify-session","CVE-2026-72001"],["/baforms/uploads","CVE-2026-102425"],["/base/export/settings.php","CVE-2026-34838"],["/base/model/abstractsettingscollection.php","CVE-2026-34838"],["/batch/v1","CVE-2026-60137,CVE-2026-63030"],["/bddc3t4tpq3mn8zn9bvkgbhmwdjxr77hf0zletenbdp3buk4slzyu/kowe1n/2gry4rb","CVE-2025-34028"],["/bea_wls_internal/proxyservlet","CVE-2026-21962"],["/blog.splitline.tw/hitcon-ctf-2022","CVE-2026-22200"],["/bolt/async/upload-url","CVE-2025-25599"],["/bolt/login","CVE-2025-25599"],["/bolt/profile-edit","CVE-2025-25599"],["/bricks/v1/render_element","CVE-2024-25600"],["/bricksforge/v1/form_file_upload","CVE-2026-85097"],["/bricksforge/v1/form_submit","CVE-2026-85097"],["/bridge/etc","CVE-2025-32463"],["/browser/servers","CVE-2026-17566"],["/build/classes","CVE-2025-30065"],["/build/exploit","CVE-2026-68138"],["/burst/v1/mainwp-auth","CVE-2026-8181"],["/cabyabwpf7galaded4puab4azw/b4ad","CVE-2025-49113"],["/cabyabwpf7galaded4puab4azw/b6gahadoh4puac4ary/byga3aco3wmuag4ax","CVE-2025-49113"],["/cache/breeze-extra/gravatars/shell.php","CVE-2026-3844"],["/cache/podlove","CVE-2026-13001"],["/callback/remote-classloader","CVE-2026-33439"],["/callback/saml","CVE-2026-9090"],["/campaign/1","CVE-2026-33937"],["/capability/app-password","CVE-2026-49772"],["/cbdc-gateway.financial/api/v2/mint","CVE-2026-78904"],["/cbdc-gateway.financial/api/v2/redeem","CVE-2026-78904"],["/cbdc-gateway.financial/api/v2/status","CVE-2026-78904"],["/cbguwr4n7fd2zuvk1jaflx6nrzbwgr3dptdf/ywuoywzq1eq3dxhupn","CVE-2026-90817"],["/ccm/system/user/autocomplete","CVE-2026-18110"],["/ccmadmin/showhome.do","CVE-2026-20230"],["/cdm/files","CVE-2025-5840"],["/cdm/user_update_customer_order.php","CVE-2025-5840"],["/certifi/cacert.pem","CVE-2026-25645"],["/certificate/upload","CVE-2026-20245"],["/cfide/main/ide.cfm","CVE-2026-48282"],["/cgi-bin/api/internet/ping","CVE-2022-31898"],["/cgi-bin/api/router/login","CVE-2022-31898"],["/cgi-bin/koha/mainpage.pl","CVE-2026-31844"],["/cgi-bin/koha/suggestion/suggestion.pl","CVE-2026-31844"],["/cgi-bin/luci","CVE-2026-2670"],["/cgi-bin/luci/admin/openvpn_apply","CVE-2026-2670"],["/cgi-bin/luci/api/xqsystem/login","CVE-2026-26898"],["/cgi-bin/php","CVE-2024-4577"],["/cgi-bin/php-cgi","CVE-2024-4577"],["/cgi-bin/privilegedscripthandler.cgi","CVE-2026-20079"],["/cgi-bin/system_status","CVE-2024-54767"],["/cgi-bin/x.cgi.","CVE-2025-25257"],["/cgi-sys/defaultwebpage.cgi","CVE-2026-65643"],["/cgi-sys/domainpark.cgi","CVE-2026-65643"],["/cgi-sys/entropysearch.cgi","CVE-2026-58048,CVE-2026-65643"],["/cgi/cgi_bin/api_mgr","CVE-2025-5349"],["/cgi/getparm","CVE-2026-75616"],["/cgi/iux_set.cgi","CVE-2026-90847"],["/cgi/samlauth","CVE-2026-19490,CVE-2026-8452"],["/character/new","CVE-2026-33937"],["/chat/completions","CVE-2026-42208,CVE-2026-49468"],["/chunk/end","CVE-2026-0014"],["/class_error/method_error.","CVE-2026-21627"],["/class-addify-request-for-quote.php","CVE-2026-18143"],["/class-mootp.php","CVE-2026-85984"],["/classes/crowd.properties","CVE-2026-21589"],["/classes/router/response/exception_response.php","CVE-2025-32044"],["/classintrospector/incompatibleimprovements","CVE-2026-63077"],["/client/x","CVE-2026-33656"],["/clientwebservice/client.asmx","CVE-2025-59287,CVE-2026-24061,CVE-2026-41940"],["/cmd.gz/cmd.jsp","CVE-2026-20127"],["/cmplatform/installclusterstatusexecute","CVE-2026-20230"],["/cms/wp-login.php","CVE-2026-19949"],["/cockpit/socket","CVE-2026-4802"],["/com_acym/upload","CVE-2026-94132"],["/com_djclassifieds/tmp/djupload","CVE-2026-61424"],["/com_pagebuilderck/fonts","CVE-2026-56290"],["/com_pagebuilderck/gfonts","CVE-2026-56290"],["/com_sppagebuilder/assets/iconfont","CVE-2026-48908"],["/com/samsung/sve/poc/sveserviceexploit.class","CVE-2026-21018"],["/commandcenter/deployservicecommcell.do","CVE-2025-34028"],["/comments/feed","CVE-2026-15013"],["/common/conf/config.php","CVE-2026-3786"],["/common/footer.aspx","CVE-2026-5426"],["/common/header.aspx","CVE-2026-5426"],["/components/com_baforms/baforms.php","CVE-2026-56291"],["/components/com_baforms/baforms.xml","CVE-2026-102425,CVE-2026-56291"],["/components/com_booklibrary","CVE-2026-101110"],["/components/com_djclassifieds/djclassifieds.xml","CVE-2026-61424"],["/components/com_icagenda/icagenda.php","CVE-2026-48939"],["/components/com_jce","CVE-2026-48907"],["/components/com_jce/editor/libraries/classes/editor.php","CVE-2026-48907"],["/components/com_jce/jce.php","CVE-2026-48907"],["/components/com_jce/jce.xml","CVE-2026-65891"],["/components/com_os_cck","CVE-2026-102428"],["/components/com_osgallery","CVE-2026-88854"],["/components/com_realestatemanager","CVE-2026-100752"],["/components/com_rsfiles/controllers/rsfiles.php","CVE-2026-57827"],["/components/com_rsfiles/downloads","CVE-2026-57827"],["/components/com_rsfiles/rsfiles.php","CVE-2026-57827"],["/components/com_rsfiles/rsfiles.xml","CVE-2026-57827"],["/components/com_simplemembership","CVE-2026-102782"],["/components/com_splms/assets/x.php","CVE-2026-48909"],["/components/com_sppagebuilder/sppagebuilder.php","CVE-2026-48908"],["/components/com_sppagebuilder/sppagebuilder.xml","CVE-2026-48908"],["/components/com_users/forms/profile.xml","CVE-2026-90907"],["/components/com_vehiclemanager","CVE-2026-101108"],["/components/com_youtubegallery/youtubegallery.xml","CVE-2026-94130"],["/computed/foreign-plugin","CVE-2026-15748"],["/concerto/services/repositoryservice","CVE-2025-49493"],["/conf/db.php","CVE-2026-3786"],["/config/0/set","CVE-2025-60787"],["/config/commit","CVE-2026-21902"],["/config/database.php","CVE-2026-70553"],["/config/list","CVE-2025-60787"],["/config/register-key","CVE-2026-13610"],["/config/teledeploy/options","CVE-2026-16475"],["/configservice/admin.aspx","CVE-2026-2699"],["/configuration/system/commandexec","CVE-2026-10520"],["/configurationprofiles/cloudconfigurationdetails.plist","CVE-2025-24104"],["/confluence/bitbucket","CVE-2026-21589"],["/console/login/loginform.jsp","CVE-2026-60206"],["/container/create","CVE-2026-55494"],["/container/dockerfile","CVE-2026-18963"],["/containers/create","CVE-2025-9074"],["/content-type-builder/content-types","CVE-2026-22599"],["/content/up","CVE-2026-97160,CVE-2026-97161,CVE-2026-97163"],["/contents/link","CVE-2025-8110"],["/contents/rce","CVE-2025-8110"],["/controle/control.php","CVE-2026-23723"],["/controllers/public_frontend_controller.php","CVE-2026-94503"],["/cool/convert-to","CVE-2026-77276"],["/core/ajax/selectobject.php","CVE-2026-34036"],["/core/groups","CVE-2026-94609"],["/core/lib/functions.lib.php","CVE-2026-89012"],["/course/list.aspx","CVE-2026-5426"],["/course/view.aspx","CVE-2026-5426"],["/cpanel/ea-php81/root/usr/share/pear/pearcmd","CVE-2026-87902"],["/cpanel/ea-php82/root/usr/share/pear/pearcmd","CVE-2026-87902"],["/cpanel/ea-php83/root/usr/share/pear/pearcmd","CVE-2026-87902"],["/cpmws/performancetestsvcremote","CVE-2026-16232"],["/cpmws/upgradesvcremote","CVE-2026-93616"],["/cpsessxxx/json-api/cpanel","CVE-2026-67401"],["/cpsessxxxxxxxxxx/...","CVE-2026-41940"],["/crowd/download/resources/crowd.webresources","CVE-2026-21589"],["/crowd/rest/usermanagement/1/search","CVE-2026-21589"],["/crowd/rest/usermanagement/latest","CVE-2026-21589"],["/crumbissuer/api/json","CVE-2026-53435"],["/ctcwebapp/shell.jsp","CVE-2025-31324"],["/cucm-uds/users","CVE-2026-20045"],["/cusrev/abc123def4567","CVE-2026-89055"],["/customer/address_file/upload","CVE-2025-54236"],["/customnode/install/git_url","CVE-2026-22777"],["/cve63030-lab/v1/probe","CVE-2026-63030"],["/cwp_c5f32ae18b2d0a1b_login/index.php","CVE-2026-57517"],["/dana-na/auth/url_admin/welcome.cgi","CVE-2025-0282,CVE-2025-22457"],["/dana-na/auth/url_default/welcome.cgi","CVE-2025-0282,CVE-2025-22457"],["/dana-na/setup/psaldownload.cgi","CVE-2025-22457"],["/dashboard-apis/monitor-bar","CVE-2026-105030"],["/dashboard/_middleware","CVE-2025-29927"],["/dashboard/panel/_middleware","CVE-2025-29927"],["/dashboard/products","CVE-2025-29927"],["/data/...","CVE-2026-43499"],["/data/adb/modules","CVE-2026-43499"],["/data/adb/modules/chuxin_permissive_netfix","CVE-2026-43499"],["/data/git","CVE-2025-68937"],["/data/git/gogs-repositories","CVE-2024-44625"],["/data/local/tmp","CVE-2026-43499"],["/data/local/tmp/ksu-module","CVE-2026-43499"],["/data/local/tmp/ksu-module/chuxin_permissive_netfix","CVE-2026-43499"],["/data/local/tmp/linuxloader_unlock.efi","CVE-2026-43499"],["/data/local/tmp/poc_sve.dex","CVE-2026-21018"],["/data/local/tmp/trigger","CVE-2026-43499"],["/data/meta-data","CVE-2026-31431"],["/data/misc/adb/adb_keys","CVE-2026-0073"],["/data/target_hash","CVE-2025-24104"],["/data/user-data","CVE-2026-31431"],["/datahubadapter/health","CVE-2026-58231"],["/datahubadapter/import","CVE-2026-58231"],["/datahubadapter/ping","CVE-2026-58231"],["/datahubadapter/status","CVE-2026-58231"],["/dataservice/device/auditlog/export","CVE-2026-20224"],["/dataservice/device/backup/restore","CVE-2026-20224"],["/dataservice/device/certificate/upload","CVE-2026-20224"],["/dataservice/device/config/upload","CVE-2026-20224"],["/dataservice/device/policy/import","CVE-2026-20224"],["/dataservice/device/software/upload","CVE-2026-20224"],["/dataservice/device/template/feature/upload","CVE-2026-20224"],["/dataservice/device/template/import","CVE-2026-20224"],["/dataservice/settings/sdra/anyconnect/profile","CVE-2026-20262"],["/dataservice/smartlicensing/uploadack","CVE-2026-20127"],["/dataservice/system/device/upload","CVE-2026-20245"],["/dataservice/template/upload","CVE-2026-20245"],["/dataservice/tenant/upload","CVE-2026-20245"],["/dataservice/vsmart/upload_serial_numbers","CVE-2026-20245"],["/dbgate/dbgate","CVE-2026-47668"],["/default/index.twig","CVE-2024-56145"],["/default/preferences","CVE-2026-54433"],["/definitions/l0","CVE-2026-34308"],["/destroy/delete","CVE-2026-19478"],["/dev.to/whyshell","CVE-2026-38751"],["/devel/iface/login.php","CVE-2025-47227"],["/developer/template/import","CVE-2026-77578"],["/developer/template/import.","CVE-2026-77578"],["/developer/template/view","CVE-2026-77578"],["/developmentserver/metadatauploader","CVE-2025-31324"],["/developmentserver/temp/shell.jsp","CVE-2025-31324"],["/device/action/upload","CVE-2026-20245"],["/device/code","CVE-2026-22005"],["/devserver_metadataupload_ear/servlet_jsp/developmentserver/root/meta-inf/manifest.mf","CVE-2025-31324"],["/devserver/shell.jsp","CVE-2025-31324"],["/diagnostic/ping","CVE-2026-0709"],["/dist/bin","CVE-2026-74939"],["/docker/docker","CVE-2026-17106"],["/docprops/app.xml","CVE-2026-21509"],["/docprops/core.xml","CVE-2026-21509"],["/document.php","CVE-2026-89013"],["/documents/upload","CVE-2026-105314"],["/doing/done","CVE-2026-68582"],["/domainblk.asp","CVE-2026-11499"],["/dont/will/wont","CVE-2026-24061"],["/download/%s/%s%s%s","CVE-2026-21589"],["/download/resources","CVE-2026-21589"],["/download/resources/...","CVE-2026-21589"],["/download/resources/bam.admin","CVE-2026-21589"],["/download/resources/jira.webresources","CVE-2026-21589"],["/doyftixk2wy8tyzafbgnvhsmegdawgbssmxaj4ki2a9/doyft","CVE-2025-29775"],["/drivers/mssql.inc.php","CVE-2026-56705"],["/eaggskatmhexwayfmrpdddweyiyq6zajawh/5llnl/kcjxmr0nrmjpwstzovyvpcgsn57c1fis6hwl20fwiwuc8zq146w8u","CVE-2026-77276"],["/ebs/payments","CVE-2026-46817"],["/echo.fcgi/api/login","CVE-2025-52689"],["/editors/jce/jce.xml","CVE-2026-65891"],["/element-search/search","CVE-2026-28695,CVE-2026-44011"],["/email/hash","CVE-2026-14962"],["/email/message/tnefattachmentfromtempfile","CVE-2026-25512"],["/email/password","CVE-2026-41452"],["/emails/src/oauth2/google.php","CVE-2026-29782"],["/embed/su_daemon_aarch64_pie","CVE-2026-43499"],["/embeddings/oleobject1.bin","CVE-2026-21509"],["/en-us/splunkd/__raw/v1/postgres/recovery","CVE-2026-20253"],["/en-us/splunkd/__raw/v1/postgres/recovery/backup","CVE-2026-20253"],["/en/system-config","CVE-2026-49865"],["/endpoint/field-name/context","CVE-2026-85097"],["/ers/sdk","CVE-2025-20281"],["/erusev/parsedown-extra/parsedownextra.php","CVE-2026-44401"],["/erusev/parsedown/parsedown.php","CVE-2026-44401"],["/esp6/rxrpc","CVE-2026-43503"],["/event/lab-event","CVE-2026-78159"],["/eventreports/deleteselection","CVE-2026-56423"],["/events-manager/v1/tickets","CVE-2026-93661"],["/evershop/.env","CVE-2026-25993"],["/evershop/.evershop/build","CVE-2026-25993"],["/evershop/media","CVE-2026-25993"],["/evershop/public","CVE-2026-25993"],["/evil/%s","CVE-2018-20250"],["/evince/xreader","CVE-2026-46529"],["/ews/exchange.asmx","CVE-2026-45504"],["/exact/path/to/webroot","CVE-2026-24418"],["/example.internal/protected","CVE-2026-24733"],["/examples//jsp/num/numguess.jsp","CVE-2026-50229"],["/examples//jsp/security/protected/login.jsp","CVE-2026-50229"],["/examples/jsp/num/numguess.jsp","CVE-2026-50229"],["/examples/jsp/security/protected/error.jsp","CVE-2026-50229"],["/examples/jsp/security/protected/index.jsp","CVE-2026-50229"],["/examples/jsp/security/protected/login.jsp","CVE-2026-50229"],["/examples/jsp/sessions/carts.jsp","CVE-2026-50229"],["/examples/jsp/sessions/shopping.jsp","CVE-2026-50229"],["/examples/jsp/tagplugin/choose.jsp","CVE-2026-50229"],["/examples/jsp/tagplugin/foreach.jsp","CVE-2026-50229"],["/execute/email/list_deliveries","CVE-2026-67401"],["/execute/email/track_delivery","CVE-2026-67401"],["/execute/mysql/create_database","CVE-2026-58048"],["/execute/mysql/delete_database","CVE-2026-58048"],["/execute/version/get_version","CVE-2026-58048"],["/execution/tab_id","CVE-2026-18963"],["/executions/configs/configs","CVE-2026-49869"],["/extra/images","CVE-2024-56426"],["/extra/nos3/gsw/yamcs/yamcs-core/src/main/java/org/yamcs","CVE-2026-55511"],["/extra/payloads","CVE-2024-56426"],["/extra/secret.php","CVE-2024-40275"],["/extra/yamcs-official-current/yamcs-core/src/main/java/org/yamcs","CVE-2026-55511"],["/f5-oauth2/v1/userinfo","CVE-2026-94127"],["/fake/addr","CVE-2025-1974"],["/features/fileformats/build.gradle","CVE-2026-18718"],["/features/fileformats/src/main/java/ghidra/file/formats","CVE-2026-18718"],["/federationmetadata/2007-06/federationmetadata.xml","CVE-2026-19490"],["/feed/atom","CVE-2026-87902"],["/fgpduajrpmfbowdaukkesaztc/gdafbghfohuzexlpmjfiwhif1n9i9nern","CVE-2026-77276"],["/fhydpw2q2hkvmwll/5","CVE-2026-77276"],["/figure_it_out.cohort.htb/terminal/ws","CVE-2026-39987"],["/file_manager/init","CVE-2024-2044"],["/file_server/get_file","CVE-2026-41551"],["/file-manager.php","CVE-2026-92247"],["/file/content","CVE-2026-22812"],["/filemanager/upload-file","CVE-2026-100520"],["/files/add","CVE-2026-55040"],["/filter/convert.base64-encode","CVE-2024-52806"],["/filter/convert.base64-encode/convert.base64-encode/resource","CVE-2024-52806"],["/filter/convert.base64-encode/resource","CVE-2024-2961,CVE-2024-34102"],["/filter/read","CVE-2026-90817"],["/filter/resource","CVE-2024-52806"],["/filter/write","CVE-2026-90817"],["/filter/zlib.inflate/resource","CVE-2024-2961"],["/fineract-provider/api/v1/offices","CVE-2026-57821"],["/firmware/update","CVE-2026-8065"],["/firmware/upload","CVE-2026-8065"],["/fisheye/download/resources/fisheye.webresources","CVE-2026-21589"],["/fixtures/files/assignments/sample-timed-assessment-good","CVE-2026-25057"],["/flash/nsconfig","CVE-2026-88771"],["/flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow","CVE-2026-33017"],["/flowforms/v1/forms","CVE-2026-11991,CVE-2026-12400"],["/flows/configs","CVE-2026-49869"],["/fluent/plugin/output.rb","CVE-2026-44024"],["/fofa.info/api/v1/search/all","CVE-2025-30208,CVE-2026-8181"],["/folder/export","CVE-2026-34838"],["/fonts/%s","CVE-2026-48908"],["/fonts/%s.%s","CVE-2026-48908"],["/fonts/%s.php","CVE-2026-48908"],["/form/smacfilter_conf","CVE-2026-58457"],["/forminator.php","CVE-2026-92229"],["/forms/class-wpresetpassword.php","CVE-2026-11387"],["/forms/pdfengines/metadata/read","CVE-2026-40281"],["/forms/pdfengines/metadata/write","CVE-2026-40281,CVE-2026-42589"],["/fortisandbox/job-detail/tracer-behavior","CVE-2026-39808"],["/free/use-after-free","CVE-2025-30400"],["/freeopcua/server","CVE-2026-21018"],["/front/central.php","CVE-2026-23489"],["/front/computer.form.php","CVE-2025-24801"],["/front/config.form.php","CVE-2025-24801"],["/front/document.form.php","CVE-2025-24801"],["/front/documenttype.form.php","CVE-2025-24801"],["/front/form/form.form.php","CVE-2026-26026"],["/front/login.php","CVE-2025-24801,CVE-2026-26026"],["/front/preference.php","CVE-2025-24801"],["/front/report.dynamic.php","CVE-2025-24801"],["/front/ticket.form.php","CVE-2025-24801"],["/gajim/avatars","CVE-2025-49091"],["/gantt/table/kanban","CVE-2026-68582"],["/geoserver/web/wicket/bookmarkable/org.geoserver.web.aboutgeoserverpage","CVE-2024-36401"],["/geoserver/wfs","CVE-2026-76904"],["/get/config/callbacks","CVE-2026-49468"],["/ghost/api/admin/authentication/setup","CVE-2026-29053"],["/ghost/api/admin/pages","CVE-2026-29053"],["/ghost/api/admin/session","CVE-2026-29053"],["/ghost/api/admin/themes/upload","CVE-2026-29053"],["/git/...","CVE-2026-89012"],["/give-tributes/give-tributes.php","CVE-2026-19658"],["/gkkbnjhbrlm6kdgcm/moknwjebbnlstkk7fn7dj0z6foliemnkvy20ekbumegiqh6oazp5fw5ofqmmlepfvlodthkfmuwhk6s5rddv3fwdmg7vzl4rai7h2jpcablgqd5h0","CVE-2026-45833"],["/global-protect/getconfig.esp","CVE-2026-0227"],["/global-protect/getip.esp","CVE-2026-0227"],["/global-protect/login.esp","CVE-2026-0227,CVE-2026-0257"],["/global-protect/portal","CVE-2026-0227"],["/global-protect/prelogin.esp","CVE-2026-0227,CVE-2026-0265"],["/gmfeed/feed.php","CVE-2026-85520"],["/goform/smacfilter_conf","CVE-2026-58457"],["/gradio_api/call","CVE-2026-69098"],["/graph_image.php","CVE-2026-39949"],["/graph_templates.php","CVE-2026-39949"],["/graphs_new.php","CVE-2026-39949"],["/group/user/direct","CVE-2026-21589"],["/h/printcalendar","CVE-2025-68645"],["/h3/text","CVE-2025-29927"],["/handler.ashx","CVE-2026-56158"],["/he/cve-lab-seed","CVE-2026-19632"],["/header.jsp","CVE-2026-86350"],["/headless/login","CVE-2026-107268"],["/heads/main","CVE-2026-42826"],["/heads/master","CVE-2025-8110"],["/heads/output-leak","CVE-2026-60004"],["/heads/rce-proof","CVE-2026-60004"],["/health/readiness","CVE-2026-42208,CVE-2026-42271"],["/health/ready","CVE-2026-18963"],["/help/about.cgi","CVE-2026-20079"],["/help/about.cgi.","CVE-2026-20079"],["/helpdesk/webobjects/helpdesk.woa/ra/oriontickets","CVE-2024-28987"],["/heyitsas.im/posts/ovswrap","CVE-2026-64531"],["/hooks/post-index-change","CVE-2026-600004,CVE-2026-60004"],["/hooks/pre-receive","CVE-2024-44625"],["/host_alias/d","CVE-2025-32463"],["/host.php","CVE-2026-39949"],["/host/api/index.php/users","CVE-2026-89012"],["/host/blog","CVE-2026-85097"],["/host/geoserver/wfs","CVE-2026-76904"],["/host/module.php/...","CVE-2024-52806"],["/host/openam","CVE-2026-33439"],["/host/port.","CVE-2026-65694"],["/host/search","CVE-2025-55182"],["/host/share","CVE-2026-39363"],["/html/body/header/div","CVE-2025-29306"],["/html/login.php","CVE-2026-23723"],["/html5/html5lib/v2.103/mwembedloader.php","CVE-2026-19912"],["/html5/html5lib/v2.45/mwembedloader.php","CVE-2026-19912"],["/htmlb/shell.jsp","CVE-2025-31324"],["/hxbdoor.one/raw/o7dxydlc","CVE-2026-57811"],["/ibews/ibe","CVE-2026-104286"],["/id/slug","CVE-2026-78006"],["/idp.aerobook.internal/saml/metadata","CVE-2026-9090"],["/idp.ctf.lab/saml/sso","CVE-2026-8452"],["/idp.test.local/saml","CVE-2026-19490"],["/iface/login.php","CVE-2025-47227"],["/ifconfig/netstat/ip","CVE-2025-3248"],["/ilias/lti/ltiauth.php","CVE-2026-80428"],["/ilias/ltiauth.php","CVE-2026-80428"],["/ilias/ltiauth/ltiauth.php","CVE-2026-80428"],["/ilias/shib_logout.php","CVE-2026-80428"],["/images/.cve65891_","CVE-2026-65891"],["/images/baforms/uploads","CVE-2026-56291"],["/images/baforms/uploads/form-%d/%s","CVE-2026-56291"],["/images/baforms/uploads/form-0","CVE-2026-56291"],["/images/com_booklibrary","CVE-2026-101110"],["/images/com_osgallery","CVE-2026-88854"],["/images/com_realestatemanager","CVE-2026-100752"],["/images/com_vehiclemanager","CVE-2026-101108"],["/images/icagenda","CVE-2026-48939"],["/images/icagenda/frontend","CVE-2026-48939"],["/images/icagenda/frontend/attachments","CVE-2026-48939"],["/images/rsfiles","CVE-2026-57827"],["/import_export/job","CVE-2026-17566"],["/inc/ajax/document.ajax.php","CVE-2026-29041"],["/includes/files/certs_c6","CVE-2026-3891"],["/includes/header.php","CVE-2026-58455"],["/includes/jtl_object.php","CVE-2026-54390"],["/index.php/ajax","CVE-2025-24799"],["/index.php/apps/user_oidc/id4me","CVE-2026-45156"],["/index.php/apps/user_oidc/id4me/code","CVE-2026-45156"],["/index.php/contact","CVE-2026-82901"],["/index.php/wp-json","CVE-2026-63030"],["/index.php/wp-json/sureforms/v1/submit-form","CVE-2026-19500"],["/info/alternates","CVE-2026-60004"],["/ingress-nginx-controller.ingress-nginx.svc/fake/addr","CVE-2025-1974"],["/insert/update","CVE-2026-69084"],["/install/api/admin-config-setup","CVE-2026-41452"],["/interface/login/login.php","CVE-2026-24849"],["/interface/main/main_screen.php","CVE-2026-24849"],["/interface/modules/custom_modules/oe-module-faxsms/index.php","CVE-2026-24849"],["/invoke/wm.server.admin","CVE-2026-12118"],["/invoker/ejbinvokerservlet","CVE-2026-20131"],["/invoker/jmxinvokerservlet","CVE-2026-20131"],["/io/mobile_application/set_property.php","CVE-2026-14483"],["/ipp/print","CVE-2026-34990,CVE-2026-39875"],["/irj/cache.jsp","CVE-2025-31324"],["/irj/helper.jsp","CVE-2025-31324"],["/irj/servlet_jsp/irj/root","CVE-2025-31324"],["/irj/servlet_jsp/irj/work","CVE-2025-31324"],["/irj/servlet_jsp/irj/work/sync","CVE-2025-31324"],["/isee857/session","CVE-2025-24813"],["/issuer/audience","CVE-2026-59243"],["/ivole.php","CVE-2026-89055"],["/jbx/box","CVE-2026-23744"],["/jcuvaaaph0qaapmphvry/yw9lwaadx9eaadzdx76vuij5b8aaaaa6n7","CVE-2026-24018"],["/jdk/bin/java","CVE-2026-47858"],["/joomla.example/article-with-up-shortcode","CVE-2026-97163"],["/joomla.example/index.php","CVE-2026-97160"],["/joomla.example/media/com_acym/upload/shell.php","CVE-2026-94132"],["/jpeg/png","CVE-2026-63223"],["/js/common.js.","CVE-2026-87915"],["/jsm/confluence/...","CVE-2026-21589"],["/json-api/account_list","CVE-2026-41940"],["/json-api/api_token_create","CVE-2026-41940"],["/json-api/cpanel","CVE-2026-41940,CVE-2026-65643,CVE-2026-67401"],["/json-api/domain","CVE-2026-65643"],["/json-api/domain_info","CVE-2026-41940"],["/json-api/email_stats","CVE-2026-41940"],["/json-api/get_hostname","CVE-2026-41940"],["/json-api/listaccts","CVE-2026-41940"],["/json-api/listaccts...","CVE-2026-41940"],["/json-api/load_session","CVE-2026-41940"],["/json-api/loadavg","CVE-2026-41940"],["/json-api/php_ini","CVE-2026-41940"],["/json-api/scripts/exec","CVE-2026-41940"],["/json-api/server_info","CVE-2026-41940"],["/json-api/service_status","CVE-2026-41940"],["/json-api/version","CVE-2026-41940,CVE-2026-58048"],["/json-api/whoami","CVE-2026-65643"],["/jsp/num/numguess.jsp","CVE-2026-50229"],["/jts/authenticated/j_security_check","CVE-2026-20127"],["/kernel.dmesg_restrict/d","CVE-2026-46331"],["/kernel.randomize_va_space/d","CVE-2026-46331"],["/kernel.unprivileged_userns_clone/d","CVE-2026-46331"],["/kernel/net/openvswitch/openvswitch.ko","CVE-2026-64531"],["/kernel/net/xfrm","CVE-2026-46300"],["/key/generate","CVE-2026-49468"],["/keycloak/keycloak","CVE-2026-18963"],["/keys/idp-cert.pem","CVE-2025-29775"],["/keys/idp-key.pem","CVE-2025-29775"],["/kirkicomponentlibrary/v1/kirki-forgot-password","CVE-2026-8206"],["/ksbhrb/jt9cfs","CVE-2025-34028"],["/ksrc/opluskernelenvconfig.mk","CVE-2025-21479"],["/ksrc/out","CVE-2025-21479"],["/ksrc/out/.config","CVE-2025-21479"],["/lab/chrome-profile/default/preferences","CVE-2026-54433"],["/lab/sink_between","CVE-2026-111444"],["/lab/sink_escape","CVE-2026-111444"],["/lab/sink_func","CVE-2026-111444"],["/lab/sink_inlist","CVE-2026-111444"],["/lab/sink_paramfalse","CVE-2026-111444"],["/label-studio/data","CVE-2025-25296"],["/labelcolumns/datapoints/dataid","CVE-2026-19626"],["/lang/class","CVE-2025-24813"],["/lang/exception","CVE-2025-24813"],["/lang/object","CVE-2025-24813"],["/lang/reflect/constructor","CVE-2025-24813"],["/lang/reflect/method","CVE-2025-24813"],["/language/en-gb/en-gb.xml","CVE-2026-48907"],["/laravel-filemanager/delete","CVE-2024-21546"],["/laravel-filemanager/jsonitems","CVE-2024-21546"],["/laravel-filemanager/rename","CVE-2024-21546"],["/laravel-filemanager/upload","CVE-2024-21546"],["/latest/meta-data","CVE-2025-4123,CVE-2026-67620"],["/latest/meta-data/iam/security-credentials","CVE-2026-67620"],["/latest/meta-data/ram/security-credentials","CVE-2026-67620"],["/layout/%s","CVE-2026-49049"],["/layouts/%s","CVE-2026-49049"],["/leak/...","CVE-2026-42533"],["/leak/hello","CVE-2026-42533"],["/libnss_/bridge90.so.2","CVE-2025-32463"],["/libraries/cms/version/version.php","CVE-2026-48907"],["/library/android/sdk/ndk","CVE-2025-21479"],["/library/application","CVE-2026-7574"],["/library/launchagents/com.adobe.update.plist","CVE-2026-3462"],["/libs/keycloak-admin-client/package.json","CVE-2026-18963"],["/libs/ui-shared/package.json","CVE-2026-18963"],["/linux/http/x64/meterpreter/reverse_tcp","CVE-2024-7954"],["/livewire/components","CVE-2025-54068"],["/livewire/message","CVE-2025-54068"],["/livewire/update","CVE-2026-48500"],["/local/config","CVE-2025-71243"],["/local/lib/php","CVE-2026-12227"],["/local/lib/php/pearcmd","CVE-2026-87902"],["/local/share/pear/pearcmd","CVE-2026-87902"],["/locales/locale.json","CVE-2025-49132"],["/localhost/api/graphql","CVE-2026-19478"],["/localhost/api/v4/version","CVE-2026-85706"],["/localhost/chamilo","CVE-2026-29041"],["/localhost/graphql","CVE-2026-22014"],["/localhost/locales/locale.json","CVE-2025-49132"],["/localhost/roundcube","CVE-2025-49113"],["/localhost/version","CVE-2026-53576"],["/localhost/vulnerable.php","CVE-2026-21015"],["/log/cpm.elg","CVE-2026-93616"],["/log/system/httpaccess","CVE-2025-31324"],["/login_handler.cgi","CVE-2026-90847"],["/login-actions/reset-credentials","CVE-2026-18963"],["/login/azure","CVE-2026-59243"],["/login/lost-password","CVE-2026-8206"],["/login/oidc/callback","CVE-2026-48558"],["/logon/logonpoint/authentication/getusername","CVE-2025-5777"],["/lower/digit/symbol","CVE-2026-19632"],["/lpinfo/cupsctl","CVE-2026-34990"],["/lti/ltiauth.php","CVE-2026-80428"],["/ltiauth.php","CVE-2026-80428"],["/lts-6.6.75/arch/x86/boot/bzimage","CVE-2025-21756"],["/mailman/private/mailman","CVE-2025-43919"],["/main/inc/ajax/document.ajax.php","CVE-2026-29041"],["/main/inc/ajax/install.ajax.php","CVE-2026-33715"],["/main/login_form.php","CVE-2026-22241"],["/main/portfolio.php","CVE-2026-22241"],["/mainui/sogorootpage.m","CVE-2026-93453"],["/manage/applications","CVE-2026-13249"],["/manage/config","CVE-2026-13249"],["/manage/display","CVE-2026-13249"],["/manage/fonts","CVE-2026-13249"],["/manage/forms","CVE-2026-13249"],["/manage/images","CVE-2026-13249"],["/manage/profiles","CVE-2026-13249"],["/manage/ssh","CVE-2026-24126"],["/manage/webforms","CVE-2026-13249"],["/manager/originate","CVE-2026-89026"],["/manifest/data","CVE-2025-24104"],["/manual/extra","CVE-2026-15748"],["/markers/names","CVE-2026-43499"],["/masscan/nmap","CVE-2026-50751"],["/mb091bs3xdk7cjmzoddkahicgctgqdwt7em65vwm67ir5oyznc7qurm0mdfs/e4pwcdsro38hvrietkkj5ucqd2om9kshswrkakttcedsetuijdotpd9","CVE-2026-45833"],["/media/com_acym/upload","CVE-2026-94132"],["/media/com_booklibrary","CVE-2026-101110"],["/media/com_icagenda","CVE-2026-48939"],["/media/com_jem/css","CVE-2026-77991"],["/media/com_os_cck","CVE-2026-102428"],["/media/com_osgallery","CVE-2026-88854"],["/media/com_realestatemanager","CVE-2026-100752"],["/media/com_simplemembership","CVE-2026-102782"],["/media/com_sppagebuilder/assets/iconfont","CVE-2026-48908"],["/media/com_sppagebuilder/assets/iconfont/%s/%s","CVE-2026-48908"],["/media/com_vehiclemanager","CVE-2026-101108"],["/media/custom_options/quote","CVE-2025-20720"],["/media/jui","CVE-2026-56290"],["/members/password-reset","CVE-2026-8206"],["/message/tnefattachmentfromtempfile","CVE-2026-25512"],["/meta-inf/shell.jsp","CVE-2025-31324"],["/metabase/auth_identity/core.clj","CVE-2026-72898"],["/metabase/auth_identity/provider.clj","CVE-2026-72898"],["/metabase/session/api.clj","CVE-2026-72898"],["/metadata.php","CVE-2026-15981"],["/meterpreter/reverse_tcp","CVE-2024-7954,CVE-2026-21514"],["/mgmt/shared/authn/login","CVE-2026-94127"],["/mgmt/tm/apm/oauth","CVE-2026-94127"],["/mgmt/tm/apm/profile/access","CVE-2026-94127"],["/mgmt/tm/ltm/virtual","CVE-2026-94127"],["/mgmt/tm/sys/version","CVE-2026-94127"],["/mi/custom","CVE-2026-1281"],["/mi/poc","CVE-2026-1281"],["/mics/api/v2/sentry/mics-config/handlemessage","CVE-2026-10520"],["/mics/services/micslogservice","CVE-2023-38035"],["/mifs/c/aftstore/fob","CVE-2026-1281"],["/mifs/c/appstore/fob","CVE-2026-1281"],["/mifs/c/appstore/fob/3/5/sha256","CVE-2026-1281"],["/mifs/rs/api/v2/featureusage","CVE-2025-4427"],["/migadmin/cgi-bin/x.cgi","CVE-2025-25257"],["/miniorange-otp-verification.php","CVE-2026-85984"],["/mint-mail/v1/mint-form-submit","CVE-2026-84753"],["/model/config.pbtxt","CVE-2026-24207"],["/model/info","CVE-2026-49468"],["/models/cart.php","CVE-2026-48909"],["/module/asset","CVE-2026-77578"],["/modules/admin/theme_options.php","CVE-2026-22241"],["/modules/aggiornamenti/upload_modules.php","CVE-2026-38751"],["/modules/appagebuilder/apajax.php","CVE-2024-6648"],["/modules/editors/settings/pagetemplatescontroller.php","CVE-2026-12227"],["/modules/exploits/multi/http/langflow_unauth_rce_cve_2025_3248.rb","CVE-2025-3248"],["/modules/gmfeed","CVE-2026-85520"],["/modules/gmfeed/combinations.xml","CVE-2026-85520"],["/modules/gmfeed/config.xml","CVE-2026-85520"],["/modules/gmfeed/feed.php","CVE-2026-85520"],["/modules/gmfeed/gmfeed.php","CVE-2026-85520"],["/modules/gmfeed/products.xml","CVE-2026-85520"],["/modules/importazione_fe/import.php","CVE-2025-69212"],["/modules/importazione_fe/upload.php","CVE-2025-69212"],["/modules/mod_splms/x.php","CVE-2026-48909"],["/modules/run/evil.php","CVE-2026-38751"],["/modules/shell/shell.php","CVE-2026-38751"],["/modules/thumb/thumb.php","CVE-2023-50917"],["/moje.cert.pl/komunikaty/2026/145/aktywnie-wykorzystywana-podatnosc-w-zimbra-collaboration-suite","CVE-2026-73570"],["/mrjj3ifn3z0nyejoy9gvncof7aonsz7n2y/tze9uefrmaip5ij7apibhlugzmi","CVE-2026-90817"],["/msadeghkarimi/session","CVE-2025-24813"],["/mt2f2d9nszatdwf2/il2bgxmcdgyxclxq2kpzoqdlyd","CVE-2026-45833"],["/multipartuploadapp_jsp/upload.jsp","CVE-2025-48976"],["/my-account/lost-password","CVE-2026-11387,CVE-2026-8206"],["/navpage.do","CVE-2026-6875"],["/netcat/ncat","CVE-2026-20079"],["/netscaler/ns_gui","CVE-2026-88771"],["/networking/v1/ingresses","CVE-2025-1974"],["/news/category.php","CVE-2025-3969"],["/news/edit-category.php","CVE-2025-3969"],["/news/index.php","CVE-2025-3969"],["/nf/auth/doauthentication.do","CVE-2026-19490,CVE-2026-8452,CVE-2026-88771"],["/nf/auth/startwebview.do","CVE-2025-5777"],["/no-such-bucket-64640/probe/v1.metadata.json","CVE-2026-64640"],["/node_modules/cross-spawn/index","CVE-2026-27971"],["/node_modules/execa/index","CVE-2026-27971"],["/node_modules/next/dist/bin/next","CVE-2026-96889"],["/node_modules/node-cmd/cmd","CVE-2026-27971"],["/node_modules/sharp","CVE-2026-96889"],["/node_modules/sharp/package.json","CVE-2026-96889"],["/node_modules/vite/package.json","CVE-2025-30208"],["/nonexistent/anything","CVE-2025-27410"],["/nova/bin/login","CVE-2026-67279"],["/nscsp_violation/report_uri","CVE-2026-19490,CVE-2026-8452"],["/o4obbl3myghjpkdwy/61klgciyihh0ixz/8yb/7zido2unuetrbiwmmx/hgj4inpqffien5nzujixng7lanz95exparmaavalnfnd6rimxyt1a3rphgt2bc7o1ykphkxveesu6gmw19citipt/kcqlayvr0frhm1srbpr4nvi","CVE-2026-45833"],["/oa_html/ibytransmit","CVE-2026-46817"],["/oa_html/javascriptservlet","CVE-2026-35273"],["/oa_html/jsp/iby","CVE-2026-46817"],["/oa_html/runforms.jsp","CVE-2026-35273"],["/oauth-authorized/azure","CVE-2026-59243"],["/oauth2/callback/oidc","CVE-2026-48558"],["/object/apply","CVE-2026-10036"],["/objects/info/alternates","CVE-2026-600004,CVE-2026-60004"],["/ocs.dacoruna.gal/ajax/teledeployoptions.php","CVE-2026-16475"],["/oh323hlwiz8k/q4mlirbzly/lwdo1xpqfnx8845shetdue","CVE-2026-90817"],["/oidc/callback","CVE-2026-48558"],["/onvif/device_service","CVE-2026-104945"],["/opc/v1/identity/cert.pem","CVE-2026-67620"],["/opc/v1/instance","CVE-2026-67620"],["/opc/v2/instance","CVE-2026-67620"],["/openid_connect/cpanelid","CVE-2026-41940"],["/openid_connect/cpanelid.","CVE-2026-41940"],["/oracle/payments","CVE-2026-46817"],["/org/freedesktop/flatpak/systemhelper","CVE-2026-92162"],["/org/freedesktop/login1","CVE-2025-6018,CVE-2025-6019"],["/org/freedesktop/packagekit","CVE-2026-41651"],["/org/freedesktop/udisks2/block_devices","CVE-2025-6019"],["/org/freedesktop/udisks2/block_devices/loop0","CVE-2025-6019"],["/others/%s","CVE-2018-20250"],["/out/bin","CVE-2026-33317"],["/owa/auth.owa","CVE-2026-45504"],["/owa/service.svc","CVE-2026-45504"],["/p/u/doauthentication.do","CVE-2025-5777"],["/pages-cache/seed","CVE-2026-75604"],["/pages/shell.jsp","CVE-2025-31324"],["/papermerge/papermerge-core","CVE-2026-105314"],["/patch/waf","CVE-2026-21589"],["/patched/requires_auth","CVE-2026-67276"],["/path/addr","CVE-2026-43499"],["/path/exp","CVE-2026-43499"],["/path/to/instatic","CVE-2026-103931"],["/path/to/iphone_logs.logarchive","CVE-2025-24252"],["/path/to/openssl-build","CVE-2025-69421"],["/path/to/payload","CVE-2026-20841"],["/path/to/pdfminer","CVE-2025-64512"],["/path/to/phpggc","CVE-2025-54236"],["/path/to/qemu-system-x86_64","CVE-2026-64561"],["/path/to/read","CVE-2025-4524"],["/path/to/rustdesk","CVE-2026-57850"],["/path/to/typemill","CVE-2026-44401"],["/path/to/wrapper","CVE-2026-31431"],["/path/to/ysoserial-all.jar","CVE-2026-20131"],["/pbxapi/index.php","CVE-2026-89026"],["/pbxapi/manager/originate","CVE-2026-89026"],["/pdfbox/pdfbox-app.jar","CVE-2026-23907"],["/people/list","CVE-2025-25062"],["/phone/text/checkbox/consent","CVE-2026-15748"],["/phone/text/checkbox/consent...","CVE-2026-15748"],["/php-cgi/php-cgi","CVE-2024-4577"],["/php.php","CVE-2026-64638"],["/php/dal.php","CVE-2025-41646"],["/php/login","CVE-2026-0300"],["/php/login.php","CVE-2026-0300"],["/php/ping.php","CVE-2026-6111"],["/php/uid.php","CVE-2026-0300"],["/phpggc/phpggc","CVE-2025-54236"],["/phpinfo.php","CVE-2024-40275,CVE-2026-64638,CVE-2026-87902"],["/phpstudy/www/shell.php","CVE-2026-21440"],["/phtml/php5/php7/shtml","CVE-2026-61424"],["/pii/extract","CVE-2026-47117"],["/platform-tools/adb","CVE-2026-43499"],["/platform-tools/fastboot","CVE-2026-43499"],["/platforms/android-36/android.jar","CVE-2026-21018"],["/platinum/idsrulelist.cgi","CVE-2026-20079"],["/pls/ib","CVE-2026-46817"],["/plugin/cstudio/editor/import-project/inc/big-upload.php","CVE-2026-45140"],["/plugins/content/up/plg_up.xml","CVE-2026-97160,CVE-2026-97161,CVE-2026-97163"],["/plugins/content/up/up.xml","CVE-2026-97160,CVE-2026-97161,CVE-2026-97163"],["/plugins/divi-form-builder","CVE-2026-5118"],["/plugins/editor_markitup/preview-ajax.php","CVE-2026-3395"],["/plugins/editors/jce/jce.php","CVE-2026-48907"],["/plugins/editors/jce/jce.xml","CVE-2026-48907"],["/plugins/elementor-pro/elementor-pro.php","CVE-2026-32475"],["/plugins/fields/front/container.form.php","CVE-2026-23489"],["/plugins/fields/front/container.php","CVE-2026-23489"],["/plugins/fields/front/field.form.php","CVE-2026-23489"],["/plugins/flynax-bridge/request.php","CVE-2025-3604"],["/plugins/forminator","CVE-2026-92229"],["/plugins/importfe_zip/actions.php","CVE-2025-69212"],["/plugins/payment-gateway-pix-for-woocommerce/includes/files/certs_c6","CVE-2026-3891"],["/plugins/planyo-online-reservation-system/ulap.php","CVE-2026-3576"],["/plugins/woocommerce","CVE-2026-14962"],["/pnr588ebzq9fhc/wnpdalbh9x/fd2g1oxvytpdccfsl","CVE-2026-90817"],["/pocss/session","CVE-2025-24813"],["/port/credentials/firewall.","CVE-2026-6471"],["/port/url","CVE-2025-24016"],["/portal/wsproxy","CVE-2026-15409"],["/private/etc/pam.d","CVE-2026-43783"],["/private/etc/passwd","CVE-2025-24104"],["/private/link-local","CVE-2026-21589"],["/probe/00042-does-not-exist.metadata.json","CVE-2026-64640"],["/prod/lib/php/devel/iface/login.php","CVE-2025-47227"],["/prod/lib/php/devel/lib/php/secureimage.php","CVE-2025-47227"],["/prod/third/jquery_plugin/thickbox","CVE-2025-47227"],["/product/card.php","CVE-2026-78804"],["/product/stock/product.php","CVE-2026-78804"],["/products/stats","CVE-2026-26198"],["/programdata/crossdevice","CVE-2025-24076"],["/prompts/test","CVE-2026-42203"],["/protocol/openid-connect/auth","CVE-2026-18963"],["/protocol/openid-connect/token","CVE-2026-18963"],["/protocol/saml/descriptor","CVE-2026-15013"],["/providers/htmleditorproviders/dnnconnect.cke/browser/fileuploader.ashx","CVE-2025-52488"],["/proxy/admin/api/jsonrpc","CVE-2025-34069"],["/proxy/users/api/v2/ucs/update/latest_package","CVE-2026-34908"],["/psemhub/api/v1/version","CVE-2026-35273"],["/psemhub/hub","CVE-2026-35273"],["/psemhub/hub/deploy","CVE-2026-35273"],["/psemhub/hub/health","CVE-2026-35273"],["/psemhub/hub/status","CVE-2026-35273"],["/psemhub/hub/upload","CVE-2026-35273"],["/psigw/httplisteningconnector","CVE-2026-35273"],["/pub/media","CVE-2025-20720"],["/pub/media/custom_options/quote","CVE-2025-20720"],["/public/..%2f%5coast.pro%2f%3f%2f..%2f..","CVE-2025-4123"],["/public/%3cscript%3ealert","CVE-2025-4123"],["/public/storage/tinymce","CVE-2026-38526"],["/put/patch/delete","CVE-2026-63030"],["/qemu/build/qemu-system-aarch64","CVE-2026-33317"],["/rails/active_storage/blobs","CVE-2026-66066"],["/rails/active_storage/blobs/redirect","CVE-2026-66066"],["/rails/active_storage/direct_uploads","CVE-2026-66066"],["/rails/active_storage/disk","CVE-2026-66066"],["/rails/active_storage/representations","CVE-2026-66066"],["/rails/active_storage/representations/redirect","CVE-2026-66066"],["/rails/info/properties","CVE-2026-66066"],["/rc/proof","CVE-2026-43499"],["/re/gsrcncmnvtxiwl/km4qlxwsvlggbwiwbemjt","CVE-2026-90817"],["/read/recv/close","CVE-2026-31431"],["/realms/...","CVE-2026-18963"],["/realms/master","CVE-2026-18963"],["/realms/master/.well-known/openid-configuration","CVE-2026-4282"],["/realms/master/protocol/openid-connect/certs","CVE-2026-4282"],["/realms/master/protocol/openid-connect/token","CVE-2026-18963"],["/registry/join","CVE-2026-82329"],["/reminder/export","CVE-2026-34838"],["/remote/hostcheck_validate","CVE-2025-32756"],["/remote/info","CVE-2025-32756"],["/remotes/origin","CVE-2025-8110"],["/remove/import","CVE-2026-49049"],["/render/ad_rce","CVE-2025-48827,CVE-2025-48828"],["/render/pagenav","CVE-2026-61511"],["/replace/me/uploads","CVE-2025-64512"],["/reports/data/opt/data/containers/config/data-collection-agent/.dca","CVE-2026-20127"],["/reports/viewreport.aspx","CVE-2026-26335"],["/repository/commits","CVE-2026-85706"],["/resolute/vmlinux","CVE-2026-43501"],["/resources/jira.webresources","CVE-2026-21589"],["/rest-service/info","CVE-2026-21589"],["/rest/all/v1","CVE-2026-53587"],["/rest/api/1.0/application-properties","CVE-2026-21589"],["/rest/api/2/serverinfo","CVE-2026-21589"],["/rest/api/latest/info","CVE-2026-21589"],["/rest/api/serverinformation","CVE-2026-21589"],["/rest/default/v1/guest-carts","CVE-2025-20720,CVE-2025-43990,CVE-2026-48356"],["/rest/firmware/update","CVE-2026-8065"],["/rest/owner/setup","CVE-2026-27495,CVE-2026-44789"],["/rest/usermanagement/1","CVE-2026-21589"],["/rest/v1/system/users/loginpoc","CVE-2026-23813"],["/rest/workflows","CVE-2026-21858,CVE-2026-27495,CVE-2026-44789"],["/restapi/objects/obj-import-ts","CVE-2026-100903"],["/robot/v1/metadata/x509/securetoken","CVE-2026-13447"],["/roller-services/xmlrpc","CVE-2026-82384"],["/roller-ui/login.rol","CVE-2026-82384"],["/roller/roller-services/xmlrpc","CVE-2026-82384"],["/rps/api/json/updatereceivers.do","CVE-2026-105134"],["/ruta/al/webshell.jsp","CVE-2025-31324"],["/rw/disk/rop-sentinel","CVE-2026-67276"],["/s/1.0/_/download/resources","CVE-2026-21589"],["/s/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-internal","CVE-2026-21589"],["/s/1/_/download/resources","CVE-2026-21589"],["/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images","CVE-2026-21589"],["/sales/metadata/00007-...json","CVE-2026-64640"],["/sales/metadata/00007-tenant-b-sales.metadata.json","CVE-2026-64640"],["/sales/metadata/00042-does-not-exist.metadata.json","CVE-2026-64640"],["/saml/login","CVE-2026-8451,CVE-2026-8452"],["/saml/sso","CVE-2026-60206"],["/saml2/acs","CVE-2026-60206"],["/saml2/idp","CVE-2026-60206"],["/saml2/sp/acs","CVE-2026-60206"],["/saml2/sp/acs/post","CVE-2026-60206"],["/saml2/sso","CVE-2026-60206"],["/sample_starter_group/helpers/template.tex","CVE-2026-25057"],["/sap/public/bc/webdynpro/sap/public/bc/zmetadata_upload","CVE-2025-31324"],["/scp/login.php","CVE-2026-14871"],["/scriptcase/prod/third/jquery_plugin/thickbox","CVE-2025-47227"],["/scripts/command","CVE-2026-41940"],["/scripts/restartsrv","CVE-2026-65643"],["/scripts/upcp","CVE-2026-65643"],["/scripts2/listaccts","CVE-2026-41940"],["/scripts4/listaccts","CVE-2026-41940"],["/sd/android16/k6.12","CVE-2026-43499"],["/sdcard/poc_ui.xml","CVE-2026-0047"],["/sdk/vimservice.wsdl","CVE-2026-1961"],["/secrets/tenant-b-db.metadata.json","CVE-2026-64640"],["/security-research/wayang-poc-pack","CVE-2026-18143"],["/security/authn/twofactorauth/verify.pm","CVE-2026-41940"],["/security/user/authenticate/run_as","CVE-2025-24016"],["/self/cmdline","CVE-2025-30208"],["/self/cwd","CVE-2025-30208"],["/self/environ","CVE-2025-30208"],["/serversyncwebservice/serversync.asmx","CVE-2025-59287,CVE-2026-24061,CVE-2026-41940"],["/service.svc","CVE-2026-56158"],["/service/extension/backup","CVE-2026-73570"],["/service/extension/backup/snmptrap","CVE-2026-73570"],["/servlet/auth/oidc/callback","CVE-2026-48558"],["/servlets/servlet/sessionexample","CVE-2025-24813"],["/sg3cwmfcdowlepoeyjvd4xcnm7/id1i","CVE-2026-90817"],["/share/pear/pearcmd","CVE-2026-87902"],["/share/php","CVE-2026-12227"],["/share/php/pearcmd","CVE-2026-87902"],["/shells/shell.jsp","CVE-2025-31324"],["/shib_logout.php","CVE-2026-80428"],["/shibboleth.sso/shib_logout.php","CVE-2026-80428"],["/shibboleth/ltiauth.php","CVE-2026-80428"],["/shop/.","CVE-2026-14962"],["/sid/did","CVE-2025-2945"],["/silverpeas/credentialsservlet/forgotpassword","CVE-2025-46047"],["/simpleauthwebservice/simpleauth.asmx","CVE-2025-59287,CVE-2026-24061,CVE-2026-41940"],["/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp","CVE-2024-52806"],["/simplesaml/saml2/idp/metadata.php","CVE-2026-15981"],["/site.tld/subdir","CVE-2026-102782"],["/site2/wp-content/uploads/sites/n/upf-docs","CVE-2026-97332"],["/sites/default/files","CVE-2026-108097"],["/sites/n/upf-docs","CVE-2026-97332"],["/size/count/offset/index-like","CVE-2026-43501"],["/skins/classic/includes/export_functions.php","CVE-2026-102607"],["/slow/park","CVE-2026-42945"],["/snap/bin/mongod","CVE-2026-8053"],["/sneakynachos/wasmblazefox","CVE-2024-29943"],["/socks4/http","CVE-2026-21589,CVE-2026-67279"],["/software/taag","CVE-2026-18143"],["/sogo/changepassword","CVE-2026-93453"],["/sogo/passwordrecoveryemail","CVE-2026-93453"],["/solarwinds_arm_remoting.remoting/send","CVE-2026-28326"],["/solr/admin/cores","CVE-2026-22444"],["/solr/gettingstarted/update","CVE-2026-44825"],["/spend/logs","CVE-2026-49468"],["/spip.php","CVE-2026-77806"],["/splice/recv","CVE-2026-31431"],["/sql/json","CVE-2026-67340"],["/sqleditor/initialize/sqleditor","CVE-2025-2945"],["/src/main/androidmanifest.xml","CVE-2025-0087"],["/src/main/assets","CVE-2025-0087"],["/src/main/java/com/android/systemupdate","CVE-2025-0087"],["/src/main/java/org/yamcs","CVE-2026-55511"],["/src/resources.rc","CVE-2026-66804"],["/ssh/db/host","CVE-2026-22804"],["/ssh/file_manager/ssh/connect","CVE-2026-22804"],["/ssh/file_manager/ssh/status","CVE-2026-22804"],["/ssl-vpn/getconfig.esp","CVE-2025-0133"],["/ssl-vpn/login.esp","CVE-2026-0257"],["/sso.management.htb/openam","CVE-2026-33439"],["/sso/saml2","CVE-2026-60206"],["/ssologin.do","CVE-2026-6875"],["/status/code","CVE-2026-26988"],["/status/recon","CVE-2026-85102"],["/stdout/stderr","CVE-2026-0766"],["/steal.php","CVE-2025-26529"],["/stock/product.php","CVE-2026-78804"],["/storage/.","CVE-2026-23697"],["/storage/app/public","CVE-2026-27636"],["/storage/attachment","CVE-2026-28289"],["/storage/attachments","CVE-2026-27636"],["/storage/tinymce","CVE-2026-38526"],["/streamsql/streamsql.jj","CVE-2026-55511"],["/struts2-rest-showcase/orders/3/edit","CVE-2026-104711"],["/struts2-rest-showcase/products/create","CVE-2026-104711"],["/struts2-showcase/chain.action","CVE-2026-104711"],["/struts2-showcase/index.action","CVE-2026-104711"],["/struts2-showcase/register.action","CVE-2026-104711"],["/subgroup/project","CVE-2026-19478"],["/sun/org/apache/xalan/internal/xsltc/dom","CVE-2025-24813"],["/sun/org/apache/xalan/internal/xsltc/runtime/abstracttranslet","CVE-2025-24813"],["/sun/org/apache/xalan/internal/xsltc/transletexception","CVE-2025-24813"],["/sun/org/apache/xml/internal/dtm/dtmaxisiterator","CVE-2025-24813"],["/sun/org/apache/xml/internal/serializer/serializationhandler","CVE-2025-24813"],["/superforms/yyyy/mm/random_id","CVE-2026-14894"],["/survey/passthru","CVE-2026-90817"],["/surveys/index.php","CVE-2026-90817"],["/syncope/rest","CVE-2026-62183"],["/system/applications/calculator.app","CVE-2026-3462"],["/system/applications/calculator.app/contents/macos/calculator","CVE-2025-30374"],["/system/applications/utilities/terminal.app","CVE-2026-3462"],["/system/device/upload","CVE-2026-20245"],["/system/helixultimate/src/platform/media.php","CVE-2026-57830"],["/system/nrframework/fields","CVE-2026-21627"],["/system/panels/page/preview_as_user","CVE-2026-18110"],["/system/typemill/extensions/parsedownextension.php","CVE-2026-44401"],["/system/user/autocomplete","CVE-2026-18110"],["/system/v1/identity","CVE-2026-13753"],["/tap/swipe","CVE-2026-73296"],["/target_ip_here/wsproxy","CVE-2026-15409"],["/target_ip_or_domain/struts2-showcase/index.action","CVE-2025-30967"],["/target-ip/php/dal.php","CVE-2025-41646"],["/target-ip/user/reservation_page.php","CVE-2025-8018"],["/target/api_jsonrpc.php","CVE-2026-23921"],["/target/file.php","CVE-2026-36214"],["/target/graphql","CVE-2026-23745"],["/target/joomla","CVE-2026-49049"],["/target/librenms","CVE-2026-26988"],["/target/objects","CVE-2026-27180"],["/target/page","CVE-2026-85097"],["/target/poc.php","CVE-2026-27180"],["/target/postquerypublic","CVE-2026-2058"],["/target/spip.php","CVE-2025-71243"],["/target/vb","CVE-2025-48827"],["/target/wp","CVE-2025-5288"],["/target/wp-login.php","CVE-2026-64638"],["/target/wsproxy","CVE-2026-15409"],["/templates/%s/%s","CVE-2026-49049"],["/templates/%s/%s/%s","CVE-2026-49049"],["/templates/document-attributes.adoc","CVE-2026-18963"],["/templates/nova","CVE-2026-54390"],["/templates/shaper_helix3/templatedetails.xml","CVE-2026-49049"],["/templates/system/x.php","CVE-2026-48909"],["/tenant/upload","CVE-2026-20245"],["/terminal/ws","CVE-2026-39987"],["/testwithslash1/session","CVE-2025-24813"],["/text/plain","CVE-2024-6648,CVE-2026-15282,CVE-2026-90817"],["/tftpboot/customfw","CVE-2025-57819"],["/themes/madara/app/plugins","CVE-2025-4524"],["/tickets.php","CVE-2026-36214"],["/tinymce/upload","CVE-2026-38526"],["/tmui/login.jsp","CVE-2026-94127"],["/tool/gen","CVE-2026-38812"],["/tool/gen/createtable","CVE-2026-38812,CVE-2026-52614"],["/tool/gen/importtable","CVE-2026-52614"],["/tool/gen/list","CVE-2026-52614"],["/toolchains/llvm/prebuilt","CVE-2025-21479"],["/toolchains/llvm/prebuilt/linux-x86_64","CVE-2026-43499"],["/tools/phpggc/phpggc","CVE-2025-54236"],["/total/totalcount","CVE-2026-19626"],["/tree/commit","CVE-2026-38526"],["/trendmicro/endpointbasecamp/ui/login.aspx","CVE-2025-5777"],["/tribe/events/v1/events","CVE-2026-78006"],["/trigger/calibrate","CVE-2026-42945"],["/trigger/probe","CVE-2026-42945"],["/tspeed/naws","CVE-2026-32746"],["/type/catalog/pages","CVE-2025-64512"],["/type/font/subtype/cidfonttype2/basefont/test/cidsysteminfo","CVE-2025-64512"],["/type/page/mediabox","CVE-2025-64512"],["/type/pages/kids","CVE-2025-64512"],["/typemill/extensions/parsedownextension.php","CVE-2026-44401"],["/typename/field_name","CVE-2026-76904"],["/ucp.php","CVE-2026-48611"],["/ucp/ajax.php","CVE-2026-46376"],["/ucp/index.php","CVE-2026-46376"],["/uejydiqzavhh73rlrk3y2uzkkr5zg1b5yn3klkmorfu0afjmfkolawt/k","CVE-2026-90817"],["/ui/pwresetquestion","CVE-2026-33439"],["/ui/pwresetuservalidation","CVE-2026-33439"],["/ui/user/general","CVE-2026-20079"],["/ui/vropspluginui/rest/services/uploadova","CVE-2021-21972"],["/ui/wsproxy","CVE-2026-15409"],["/ultimate-addons-for-contact-form-7.php","CVE-2026-82901"],["/umbraco/backoffice/umbracoapi/authentication/postlogin","CVE-2025-24011"],["/umbraco/management/api/v1/security/back-office/login","CVE-2025-24011"],["/uname/hostname","CVE-2026-22738"],["/unfurl.php","CVE-2026-73320"],["/upload/avatar","CVE-2026-63223"],["/upload/chunk","CVE-2025-24971"],["/upload/image","CVE-2026-68771"],["/upload/init","CVE-2025-24971"],["/uploads/cmi-data/nxploited.php","CVE-2025-4190"],["/uploads/elementor/forms","CVE-2026-32475"],["/uploads/elementor/forms/.","CVE-2026-32475"],["/uploads/forminator","CVE-2026-15748"],["/uploads/godam/wpforms","CVE-2026-14282"],["/uploads/king-addons/forms","CVE-2025-6325"],["/uploads/sites/n/upf-docs","CVE-2026-97332"],["/uploads/smf-uploads","CVE-2026-1056"],["/uploads/tinymce","CVE-2026-38526"],["/uploads/uacf7-uploads","CVE-2026-82901"],["/uploads/upf-docs","CVE-2026-97332"],["/uploads/user_uploads","CVE-2026-12277"],["/uploads/wpl","CVE-2026-13714,CVE-2026-14483"],["/uploads/yyyy/mm","CVE-2026-75865,CVE-2026-94503"],["/uploads/yyyy/mm/.","CVE-2026-85097"],["/upnp/control/wanpppconn0","CVE-2025-45422"],["/user-setup/%20","CVE-2026-53595"],["/user/forgotpassword","CVE-2026-22794"],["/user/keys","CVE-2025-68937"],["/user/list","CVE-2026-49468"],["/user/new","CVE-2026-49468"],["/user/public_html/...","CVE-2026-48909"],["/user/repos","CVE-2025-68937"],["/user/resetpassword","CVE-2026-22794"],["/user/settings/applications","CVE-2025-8110,CVE-2026-52806"],["/user/sign_up","CVE-2026-27771,CVE-2026-52806,CVE-2026-60004"],["/user/tfa_verified/hasroot","CVE-2026-41940"],["/useragent/remote_port","CVE-2026-104051"],["/users/admin/.env","CVE-2026-39363"],["/users/api/v2/ucs/update/latest_package","CVE-2026-34910"],["/users/bellini","CVE-2026-62183"],["/users/create","CVE-2026-22804"],["/users/self","CVE-2026-62183"],["/users/session-info","CVE-2025-32432"],["/users/sid/gecko-2766/obj-browser","CVE-2026-74939"],["/users/sid/gecko-2766/obj-browser/dist/nightly.app/contents/macos/firefox","CVE-2026-74939"],["/users/sid/gecko-2766/python/mozterm","CVE-2026-74939"],["/users/sid/gecko-2766/testing/marionette/client","CVE-2026-74939"],["/users/sid/gecko-2766/testing/mozbase","CVE-2026-74939"],["/users/sign_in","CVE-2026-10053,CVE-2026-19478,CVE-2026-85706"],["/util/object.js.","CVE-2026-15598"],["/util/xml.php","CVE-2025-69212,CVE-2026-69212"],["/v1.45/containers/json","CVE-2026-78122"],["/v1/admin/save","CVE-2026-27541"],["/v1/chat/completions","CVE-2026-22778,CVE-2026-42208"],["/v1/events","CVE-2026-62062"],["/v1/mint-form-submit","CVE-2026-10196"],["/v1/models","CVE-2026-49468"],["/v1/python/file/upload","CVE-2026-73034"],["/v1/send","CVE-2026-34975"],["/v1/tools/run","CVE-2025-51482"],["/v1/v2.","CVE-2026-43499"],["/v2/_catalog","CVE-2026-27771"],["/v2/categories","CVE-2026-63030"],["/v2/myapp/manifests/latest","CVE-2026-21005"],["/vbond/upload_chassis_numbers","CVE-2026-20245"],["/vcframework/shell.jsp","CVE-2025-31324"],["/vendor/erusev/parsedown/parsedown.php","CVE-2026-44401"],["/vendor/phpoffice/phpspreadsheet/samples/index.php","CVE-2026-45034"],["/verasmart/default.aspx","CVE-2026-26335"],["/verasmart/login.aspx","CVE-2026-26335"],["/verasmart/web.config","CVE-2026-26335"],["/victim-app/app","CVE-2026-47858"],["/victim-app/app/target/app-","CVE-2026-47858"],["/victim.netscaler.local/saml/login","CVE-2026-8451"],["/victim/zm","CVE-2026-102607"],["/viewimage.php","CVE-2026-89013"],["/views/mailer/password_reset/en.html.erb.custom","CVE-2026-102489"],["/views/metadata/00003-...json","CVE-2026-64640"],["/views/metadata/00003-tenant-b-view.metadata.json","CVE-2026-64640"],["/virtuser_query/virtuser_query.php","CVE-2026-48842"],["/visualcomposer/shell.jsp","CVE-2025-31324"],["/vite/package.json","CVE-2025-30208"],["/vpn/js/rdx","CVE-2026-19490"],["/vpn/theme/x.php","CVE-2026-8452"],["/vr39fe1dajcpzq95jrlyviweebg7cew06ctebapw6ux8vy3/lc8uahwnqwwvrh21ihrervo9w4bdp3dsxmc6bfmzzlpserfp9qjrim8bkjn6wwypm42gvlbmza1kdslxgd7muybbtotjjvvvcfp3zasjfgt1q8twuh4naz8ooit1a9unkht0c9ltaz2siml/ayxyg","CVE-2025-34085"],["/vred.mbbank.com.vn/p/analysis-of-exchange-server-pre-auth","CVE-2026-62911"],["/vsmart/upload_serial_numbers","CVE-2026-20245"],["/vtsjn5pi/ezgyu5ihpvebe","CVE-2026-77276"],["/vuln/detail/cve-2025-32433","CVE-2025-32433"],["/vuln/detail/cve-2025-69212","CVE-2025-69212"],["/vuln/detail/cve-2026-99999","CVE-2026-99999"],["/vulnerable-app.example/dashboard/admin","CVE-2025-29927"],["/vvfh0vjxwp2ytdcc4deiexbmrmrcxrrovwqdojy/j1ysdzzvlher9a4vtr9epvq3l9efiewy4ieopitoi0lkkjn0s","CVE-2026-77276"],["/waf/captcha","CVE-2026-32475"],["/wasm/cpdf","CVE-2026-41653"],["/wasm/gs","CVE-2026-41653"],["/wasm/pymupdf","CVE-2026-41653"],["/watched/file.txt.","CVE-2026-17106"],["/wc/store/v1/products","CVE-2026-103889"],["/web-inf/shell.jsp","CVE-2025-31324"],["/web-inf/web.xml","CVE-2025-68645"],["/web/admin/manage_email_templates.php","CVE-2026-61343"],["/web/api/node-management/setup-initial-connection","CVE-2026-24423"],["/webapp/config/settings.cfg","CVE-2026-43637"],["/webapps/platform-services/axis2-web/aaa.jsp","CVE-2026-20230"],["/webapps/root","CVE-2026-63077"],["/webdialer/cisco_webdialer_service","CVE-2026-20230"],["/webdialer/services/adminservice/platformcom/api/v1/software/installstages","CVE-2026-20230"],["/webdialer/version.jws","CVE-2026-20230"],["/webdialer/webdialer","CVE-2026-20230"],["/webhook.site/xxxx","CVE-2026-33017"],["/webhooks/trigger","CVE-2026-31816"],["/webinterface/function","CVE-2025-2825,CVE-2025-31161"],["/weblogic/..","CVE-2026-21962"],["/webroot/web.config","CVE-2026-26335"],["/webservice.asmx","CVE-2026-56158"],["/webservice/rest/server.php","CVE-2025-32044"],["/wget/nc","CVE-2026-97229"],["/whoami/api/json","CVE-2026-53435"],["/widgets/form_builder/helpers/upload_email_file.php","CVE-2025-6325"],["/widgets/login_register_form/login_register_form_ajax.php","CVE-2025-6325"],["/wiki/special","CVE-2026-58025"],["/wizard/xhr/check-requirements","CVE-2026-92805"],["/wizard/xhr/intermediary/super-user","CVE-2026-92805"],["/wizard/xhr/load/configurations","CVE-2026-92805"],["/wizard/xhr/load/entities","CVE-2026-92805"],["/wizard/xhr/load/migrations","CVE-2026-92805"],["/wizard/xhr/load/super-user","CVE-2026-92805"],["/wizard/xhr/load/website-configure","CVE-2026-92805"],["/wizard/xhr/verify-database-credentials","CVE-2026-92805"],["/wizard/xhr/website-configure","CVE-2026-92805"],["/wmroot/invoke","CVE-2026-12118"],["/woocommerce-request-a-quote.php","CVE-2026-18143"],["/word/_rels","CVE-2026-21509"],["/word/document.xml","CVE-2026-21509"],["/word/embeddings","CVE-2026-21509"],["/word/media","CVE-2026-21509"],["/wordpress/wp-admin/admin.php","CVE-2025-32118"],["/wordpress/wp-login.php","CVE-2026-19949"],["/work/upload","CVE-2026-52680"],["/workplace/wsproxy","CVE-2026-15409"],["/workspace/knowns-project","CVE-2026-88899"],["/wp-admin/admin-post.php","CVE-2025-39538"],["/wp-admin/async-upload.php","CVE-2025-3102"],["/wp-admin/authorize-application.php","CVE-2026-64638"],["/wp-admin/index.php","CVE-2025-5701,CVE-2026-5415,CVE-2026-7465"],["/wp-admin/install","CVE-2026-87902"],["/wp-admin/install.php","CVE-2026-12277"],["/wp-admin/options-general.php","CVE-2025-2249,CVE-2026-19125"],["/wp-admin/plugin-editor.php","CVE-2026-60137"],["/wp-admin/theme-editor.php","CVE-2026-63030"],["/wp-admin/themes.php","CVE-2025-28915,CVE-2026-19125,CVE-2026-63030"],["/wp-admin/tools.php","CVE-2025-4190"],["/wp-admin/update.php","CVE-2026-60137,CVE-2026-63030,CVE-2026-64638"],["/wp-admin/user-new.php","CVE-2025-22783,CVE-2026-3228,CVE-2026-8732"],["/wp-comments-post.php","CVE-2026-78006,CVE-2026-78159"],["/wp-config-sample.php","CVE-2026-64638"],["/wp-config.php","CVE-2024-40275,CVE-2026-64638,CVE-2026-8713"],["/wp-content/mu-plugins","CVE-2025-7384"],["/wp-content/mu-plugins/lab-gadget.php","CVE-2025-7384"],["/wp-content/plugins/activecamp-contact-form","CVE-2026-9691"],["/wp-content/plugins/all-in-one-wp-migration","CVE-2026-19949"],["/wp-content/plugins/all-in-one-wp-migration/plugin.php","CVE-2026-19949"],["/wp-content/plugins/breeze/breeze.php","CVE-2026-3844"],["/wp-content/plugins/bricksforge","CVE-2026-85097"],["/wp-content/plugins/bricksforge/bricksforge.php","CVE-2026-85097"],["/wp-content/plugins/burst-statistics","CVE-2026-8181"],["/wp-content/plugins/burst-statistics/burst-statistics.php","CVE-2026-8181"],["/wp-content/plugins/calendar-booking-latepoint","CVE-2026-49083"],["/wp-content/plugins/cf7-active-campaign","CVE-2026-9691"],["/wp-content/plugins/cf7-active-campaign/cf7-active-campaign.php","CVE-2026-9691"],["/wp-content/plugins/cf7-infusionsoft","CVE-2026-49104"],["/wp-content/plugins/cf7-infusionsoft/cf7-infusionsoft.php","CVE-2026-49104"],["/wp-content/plugins/cf7-insightly","CVE-2026-49085"],["/wp-content/plugins/cf7-insightly/cf7-insightly.php","CVE-2026-49085"],["/wp-content/plugins/cf7-zendesk","CVE-2026-49105"],["/wp-content/plugins/cf7-zendesk/cf7-zendesk.php","CVE-2026-49105"],["/wp-content/plugins/cmp-premium-themes/nxploitedshell/nxploitedshell.php","CVE-2025-32118"],["/wp-content/plugins/contact-form-activecamp","CVE-2026-9691"],["/wp-content/plugins/contact-form-by-supsystic","CVE-2026-4257"],["/wp-content/plugins/contact-form-infusionsoft","CVE-2026-49104"],["/wp-content/plugins/contact-form-insightly","CVE-2026-49085"],["/wp-content/plugins/contact-form-zendesk","CVE-2026-49105"],["/wp-content/plugins/cryptopayment-gateway/vendor/cryptd/ajax.php","CVE-2026-81648"],["/wp-content/plugins/devkit-pro/devkit.php","CVE-2026-14378,CVE-2026-19660"],["/wp-content/plugins/devkit/devkit.php","CVE-2026-14378,CVE-2026-19660"],["/wp-content/plugins/digits","CVE-2025-4094"],["/wp-content/plugins/divi-ajax-filter/divi-ajax-filter.php","CVE-2026-11613"],["/wp-content/plugins/drag-and-drop-file-upload-for-contact-form-7","CVE-2026-5364"],["/wp-content/plugins/events-manager","CVE-2026-17089"],["/wp-content/plugins/events-manager/events-manager.php","CVE-2026-18366"],["/wp-content/plugins/file-away","CVE-2025-2539"],["/wp-content/plugins/forminator","CVE-2026-15748,CVE-2026-15826"],["/wp-content/plugins/fusion-builder/fusion-builder.php","CVE-2026-8713"],["/wp-content/plugins/fusion-core/fusion-core.php","CVE-2026-8713"],["/wp-content/plugins/give/give.php","CVE-2026-82222"],["/wp-content/plugins/idraw/idraw_upload.php","CVE-2025-39436"],["/wp-content/plugins/infusionsoft-contact-form","CVE-2026-49104"],["/wp-content/plugins/insert-headers-and-footers","CVE-2026-8832"],["/wp-content/plugins/insightly-contact-form","CVE-2026-49085"],["/wp-content/plugins/instant-appointment/instant-appointment.php","CVE-2026-15282"],["/wp-content/plugins/integration-activecampaign","CVE-2026-9691"],["/wp-content/plugins/integration-infusionsoft","CVE-2026-49104"],["/wp-content/plugins/integration-zendesk","CVE-2026-49105"],["/wp-content/plugins/jet-search","CVE-2026-49079"],["/wp-content/plugins/jetpack-search","CVE-2026-49079"],["/wp-content/plugins/jetsearch","CVE-2026-49079"],["/wp-content/plugins/jetsearch/jetsearch.php","CVE-2026-49079"],["/wp-content/plugins/keap-contact-form","CVE-2026-49104"],["/wp-content/plugins/latepoint","CVE-2026-49083"],["/wp-content/plugins/latepoint-calendar","CVE-2026-49083"],["/wp-content/plugins/latepoint/latepoint.php","CVE-2026-49083"],["/wp-content/plugins/miniorange-saml-20-single-sign-on","CVE-2026-15013,CVE-2026-15981"],["/wp-content/plugins/modular-ds/api/modular-connector/login","CVE-2026-23550"],["/wp-content/plugins/nextscripts-social-networks-auto-poster","CVE-2026-3228"],["/wp-content/plugins/payload/shell.php","CVE-2026-64638"],["/wp-content/plugins/payment-gateway-pix-for-woocommerce","CVE-2026-3891"],["/wp-content/plugins/podlove-podcasting-plugin-for-wordpress/podlove.php","CVE-2026-13001"],["/wp-content/plugins/pods","CVE-2026-19598"],["/wp-content/plugins/pods/init.php","CVE-2026-19598"],["/wp-content/plugins/popup-maker","CVE-2026-87915"],["/wp-content/plugins/product-slider-pro","CVE-2026-49777"],["/wp-content/plugins/real-estate-listing-realtyna-wpl/assets/migrations/basic/1.0.0.sql","CVE-2026-14483"],["/wp-content/plugins/real-estate-listing-realtyna-wpl/wpl.php","CVE-2026-14483"],["/wp-content/plugins/search-jetsearch","CVE-2026-49079"],["/wp-content/plugins/simple-file-list/ee-file-engine.php","CVE-2025-34085"],["/wp-content/plugins/simple-file-list/ee-upload-engine.php","CVE-2025-34085"],["/wp-content/plugins/simpleform","CVE-2026-104748"],["/wp-content/plugins/smart-show-post-pro/src/includes/licenseloader.php","CVE-2026-49777"],["/wp-content/plugins/social-networks-auto-poster","CVE-2026-3228"],["/wp-content/plugins/social-networks-auto-poster-facebook-twitter-g","CVE-2026-3228"],["/wp-content/plugins/sparklethemes-shortcodes","CVE-2025-2539"],["/wp-content/plugins/super-forms/super-forms.php","CVE-2026-14894"],["/wp-content/plugins/testimonial-pro/src/includes/licenseloader.php","CVE-2026-49777"],["/wp-content/plugins/ultimate-addons-for-gutenberg/ultimate-addons-for-gutenberg.php","CVE-2026-7465"],["/wp-content/plugins/ultimate-member","CVE-2026-96451"],["/wp-content/plugins/visualcomposer","CVE-2026-12227"],["/wp-content/plugins/woo-product-slider-pro","CVE-2026-49777"],["/wp-content/plugins/woo-product-slider-pro/cache","CVE-2026-49777"],["/wp-content/plugins/woo-product-slider-pro/includes/download.php","CVE-2026-49777"],["/wp-content/plugins/woo-product-slider-pro/includes/remote-loader.php","CVE-2026-49777"],["/wp-content/plugins/woo-product-slider-pro/src/includes/licenseloader.php","CVE-2026-49777"],["/wp-content/plugins/woocommerce-notification","CVE-2026-49777"],["/wp-content/plugins/woocommerce-notification/install-persistent.php","CVE-2026-49777"],["/wp-content/plugins/woocommerce-product-slider-pro","CVE-2026-49777"],["/wp-content/plugins/woocommerce-request-a-quote/uploads","CVE-2026-18143"],["/wp-content/plugins/woocommerce-request-a-quote/uploads/afrfq","CVE-2026-18143"],["/wp-content/plugins/woocommerce-request-a-quote/uploads/rfq","CVE-2026-18143"],["/wp-content/plugins/woocommerce-request-a-quote/uploads/temp","CVE-2026-18143"],["/wp-content/plugins/woocommerce-request-a-quote/uploads/tmp","CVE-2026-18143"],["/wp-content/plugins/woocommerce-subscription","CVE-2026-49777"],["/wp-content/plugins/woocommerce-subscription/class-wc-subscription-diagnostics.php","CVE-2026-49777"],["/wp-content/plugins/woocommerce-subscription/install-persistent.php","CVE-2026-49777"],["/wp-content/plugins/wp-google-map-gold/classes/wpgmp-temp-access.php","CVE-2026-8732"],["/wp-content/plugins/wp-google-map-gold/wp-google-map-gold.php","CVE-2026-8732"],["/wp-content/plugins/wp-google-map-plugin/wp-google-map-plugin.php","CVE-2026-39492"],["/wp-content/plugins/wp-insightly","CVE-2026-49085"],["/wp-content/plugins/wp-user-manager/wp-user-manager.php","CVE-2026-9290"],["/wp-content/plugins/wp-zendesk","CVE-2026-49105"],["/wp-content/plugins/wpvivid-backuprestore/wpvivid-backuprestore.php","CVE-2026-1357"],["/wp-content/plugins/zendesk-contact-form","CVE-2026-49105"],["/wp-content/plugins/zombify/zombify.php","CVE-2026-94503"],["/wp-content/poc19952/index.php","CVE-2026-19952"],["/wp-content/poc81648/index.php","CVE-2026-81648"],["/wp-content/themes","CVE-2026-87902"],["/wp-content/themes/gecko/framework/load.php","CVE-2025-69080"],["/wp-content/themes/gecko/includes/ajax.php","CVE-2025-69080"],["/wp-content/themes/gecko/page-builder/builder.php","CVE-2025-69080"],["/wp-content/themes/gecko/template-parts/content.php","CVE-2025-69080"],["/wp-content/themes/gecko/theme-options/options.php","CVE-2025-69080"],["/wp-content/uploads/%d/%02d/%s","CVE-2026-85097"],["/wp-content/uploads/%s","CVE-2026-78006,CVE-2026-85097"],["/wp-content/uploads/2025/03/shell.php","CVE-2025-28915"],["/wp-content/uploads/2025/4/19/nxploit.php","CVE-2025-39436"],["/wp-content/uploads/blocksy","CVE-2026-58480"],["/wp-content/uploads/bookingpress","CVE-2026-6960"],["/wp-content/uploads/de_fb_uploads","CVE-2026-5524"],["/wp-content/uploads/dpwap_logs/files/tmp/shell.php","CVE-2025-6586"],["/wp-content/uploads/elementor/forms","CVE-2026-32475"],["/wp-content/uploads/forminator","CVE-2026-15748"],["/wp-content/uploads/fusion-forms","CVE-2026-4782,CVE-2026-8713"],["/wp-content/uploads/gfmu-uploads-tmp","CVE-2026-87796"],["/wp-content/uploads/gh","CVE-2026-12227"],["/wp-content/uploads/ghsa7hp8-witness.php","CVE-2026-87902"],["/wp-content/uploads/gravity_forms","CVE-2025-13407"],["/wp-content/uploads/hashform/temp","CVE-2026-81780"],["/wp-content/uploads/itinerary-fonts/shell.php","CVE-2025-47549,CVE-2025-47550,CVE-2025-6220"],["/wp-content/uploads/nxploit.php","CVE-2025-26892"],["/wp-content/uploads/poc.php","CVE-2026-63030"],["/wp-content/uploads/product_input_fields","CVE-2026-19089"],["/wp-content/uploads/reviews","CVE-2026-58480"],["/wp-content/uploads/simple-file-list","CVE-2025-34085"],["/wp-content/uploads/soundslides/nxploit_shell/nxploit.php","CVE-2025-2249"],["/wp-content/uploads/superforms","CVE-2026-14894"],["/wp-content/uploads/uacf7-uploads","CVE-2026-82901"],["/wp-content/uploads/vanda_shell.php","CVE-2025-3102"],["/wp-content/uploads/wcdp-uploads/temp/alixploit/alixploit.php","CVE-2026-6440"],["/wp-content/uploads/wcdp-uploads/temp/darkarch/darkarch.php","CVE-2025-6440"],["/wp-content/uploads/wp-config.php.bak","CVE-2026-64638"],["/wp-content/uploads/wpforms/tmp","CVE-2026-10818"],["/wp-content/uploads/wpl","CVE-2026-57811"],["/wp-content/uploads/wpl/%d/%s","CVE-2026-14483"],["/wp-content/uploads/yyyy/mm","CVE-2026-85097"],["/wp-content/wp01-backup/wp-01-passwd.zip","CVE-2025-30567"],["/wp-content/wphb-logs","CVE-2026-83627"],["/wp-content/wphb-logs/page-caching-log.php","CVE-2026-83627"],["/wp-content/wpvividbackups/importandexport/hack.php","CVE-2025-5961"],["/wp-content/wpvividbackups/importandexport/shellnxploited.php","CVE-2025-5961"],["/wp-cron.php","CVE-2026-3844"],["/wp-includes/version","CVE-2026-87902"],["/wp-includes/version.php","CVE-2025-7384,CVE-2026-64638,CVE-2026-93485"],["/wp-json/...","CVE-2026-14840"],["/wp-json//bricksforge/v1/form_file_upload","CVE-2026-85097"],["/wp-json/admin/v1/query","CVE-2025-12674"],["/wp-json/api/flutter_user/firebase_sms_v2","CVE-2026-13447"],["/wp-json/batch/v1","CVE-2026-60137,CVE-2026-63030"],["/wp-json/bookingpress_pro/v1/bookings","CVE-2026-9830"],["/wp-json/bricks/v1/render_element","CVE-2024-25600"],["/wp-json/bricksforge/v1","CVE-2026-85097"],["/wp-json/bricksforge/v1/form_file_upload","CVE-2026-85097"],["/wp-json/bricksforge/v1/form_submit","CVE-2026-85097"],["/wp-json/burst/v1/mainwp-auth","CVE-2026-8181"],["/wp-json/contact-form-7/v1/contact-forms","CVE-2026-49105,CVE-2026-9691"],["/wp-json/contact-form-7/v1/contact-forms/1/feedback","CVE-2026-49104,CVE-2026-49105,CVE-2026-9691"],["/wp-json/divi-form-builder/v1","CVE-2026-5118"],["/wp-json/elicus/v1/dipl-modules/svg-animator","CVE-2026-91136"],["/wp-json/eventin/v2/events","CVE-2026-15667"],["/wp-json/eventin/v2/speakers/import","CVE-2025-47539"],["/wp-json/events-manager/v1/tickets","CVE-2026-93661"],["/wp-json/everest-forms/v1/forms","CVE-2026-3300"],["/wp-json/form-notify/v1/callback","CVE-2026-5229"],["/wp-json/form-notify/v1/login","CVE-2026-5229"],["/wp-json/fox-lms/v1/payments/create-order","CVE-2025-14156"],["/wp-json/gravitysmtp/v1/tests/mock-data","CVE-2026-4020"],["/wp-json/kirkicomponentlibrary/v1/kirki-forgot-password","CVE-2026-8206"],["/wp-json/kivicare/v1","CVE-2026-13610,CVE-2026-2991"],["/wp-json/kivicare/v1/auth/patient/social-login","CVE-2026-2991"],["/wp-json/latepoint/v1/abilities/connect-customer-to-wp-user","CVE-2026-6741"],["/wp-json/latepoint/v1/customers","CVE-2026-6741"],["/wp-json/latepoint/v2/customers","CVE-2026-6741"],["/wp-json/lazy-blocks/v1/block-builder-preview","CVE-2026-1560"],["/wp-json/mint-mail/v1/mint-form-submit","CVE-2026-10196"],["/wp-json/mwai/v1/simplefileupload","CVE-2025-7847"],["/wp-json/oembed/1.0/proxy","CVE-2026-63030"],["/wp-json/simple-history/v1/events","CVE-2026-7459"],["/wp-json/simple-history/v1/events/1/react","CVE-2026-7459"],["/wp-json/slider-future/v1/upload-image","CVE-2026-1405"],["/wp-json/snow-monkey-form/v1/view","CVE-2026-1056"],["/wp-json/stocktend/v1/stocktend_object","CVE-2025-4631"],["/wp-json/storychief/webhook","CVE-2025-7441"],["/wp-json/sure-triggers/v1/automation/action","CVE-2025-3102"],["/wp-json/suretriggers/v1/automation/action","CVE-2025-3102"],["/wp-json/tec/v1","CVE-2026-49772"],["/wp-json/tec/v1/events","CVE-2026-49772"],["/wp-json/tec/v1/events.","CVE-2026-49772"],["/wp-json/wawp/v1/signup/check_availability","CVE-2026-14281"],["/wp-json/wawp/v1/signup/signup","CVE-2026-14281"],["/wp-json/wc-hippoo/v1/ext/wp/v2/users","CVE-2026-10580"],["/wp-json/wc/store/products","CVE-2026-18143"],["/wp-json/wc/v3/settings/apply","CVE-2026-49777"],["/wp-json/wp/v1/abilities/latepoint/connect-customer-to-wp-user","CVE-2026-6741"],["/wp-json/wp/v2","CVE-2026-64638"],["/wp-json/wp/v2/abilities/latepoint/connect-customer-to-wp-user","CVE-2026-6741"],["/wp-json/wp/v2/batch","CVE-2026-63030"],["/wp-json/wp/v2/categories","CVE-2026-60137"],["/wp-json/wp/v2/comments","CVE-2026-27384"],["/wp-json/wp/v2/event","CVE-2026-18366"],["/wp-json/wp/v2/event-recurring","CVE-2026-18366"],["/wp-json/wp/v2/events","CVE-2026-18366"],["/wp-json/wp/v2/give_forms","CVE-2026-82222"],["/wp-json/wp/v2/location","CVE-2026-18366"],["/wp-json/wp/v2/locations","CVE-2026-18366"],["/wp-json/wp/v2/media","CVE-2026-15748"],["/wp-json/wp/v2/plugins","CVE-2026-64638"],["/wp-json/wp/v2/statuses/publish","CVE-2026-64638"],["/wp-json/wp/v2/tribe_events","CVE-2026-78006"],["/wp-json/wp/v2/users/1","CVE-2026-6741"],["/wp-json/wplp-react-gdpr/v1/store-auth","CVE-2026-75865"],["/wp-json/wplp-react-gdpr/v1/upload-logo","CVE-2026-75865"],["/wp-json/yop-poll/v1/votes","CVE-2026-14840"],["/wp-links-opml.php","CVE-2026-87902"],["/wp-load.php","CVE-2026-63030"],["/wp-recipe-maker.php","CVE-2026-89274"],["/wp-signup.php","CVE-2026-89079"],["/wp/v2/block-renderer/core/archives","CVE-2026-63030"],["/wp/v2/block-renderer/core/paragraph","CVE-2026-60137"],["/wp/v2/categories","CVE-2026-60137,CVE-2026-63030"],["/wp/v2/posts","CVE-2026-12793,CVE-2026-60137,CVE-2026-63030"],["/wp/v2/posts/999999","CVE-2026-60137,CVE-2026-63030"],["/wp/v2/product","CVE-2026-103889"],["/wp/v2/types","CVE-2026-63030"],["/wp/v2/users/me/application-passwords","CVE-2026-64638"],["/wp/v2/widgets","CVE-2026-60137,CVE-2026-63030"],["/wp/wp-login.php","CVE-2026-19949"],["/wphb-cache/wphb-cache.php","CVE-2026-83627"],["/wphb-logs/page-caching-log.php","CVE-2026-83627"],["/wrapper/falsemodel","CVE-2026-63077"],["/writable/uploads","CVE-2026-63223"],["/ws/cli/open","CVE-2024-55591"],["/ws/firmware/update","CVE-2026-8065"],["/www.sudo.ws/dist/sudo-1.9.17p1.tar.gz","CVE-2025-32463"],["/x/%25252e%25252e%25252fy","CVE-2026-21589"],["/x/%252e%252e/y","CVE-2026-21589"],["/x/%252e%252e%252fy","CVE-2026-21589"],["/x/%2e%2e/y","CVE-2026-21589"],["/x/x/x/vite-project","CVE-2025-31486"],["/x64/shell_reverse_tcp","CVE-2025-49132,CVE-2025-49144"],["/xampp/htdocs/wordpress/wp-config.php","CVE-2026-12277"],["/xampp/php/pear/pearcmd","CVE-2026-87902"],["/xfs.mount/bash","CVE-2025-6019"],["/xk/1hvgmw/ggnofwkkpfu2eugawvslk","CVE-2026-45833"],["/xmax/ymin/ymax","CVE-2026-86950"],["/xwiki/bin/...","CVE-2025-24893"],["/xwiki/bin/get/main/solrsearch","CVE-2025-24893"],["/xwiki/bin/login","CVE-2026-33137"],["/xwiki/bin/view/cve/rcegroovy","CVE-2026-33137"],["/xwiki/bin/view/cve/rcevelocity","CVE-2026-33137"],["/xwiki/bin/view/main","CVE-2026-33137"],["/xwiki/rest/livedata/sources/livetable/entries","CVE-2025-32429"],["/xwiki/rest/wikis","CVE-2026-33137"],["/y/aux","CVE-2026-27199"],["/yop-poll/v1/votes","CVE-2026-14840"],["/your-ip/steal.php","CVE-2025-26529"],["/your-oob.example/cb","CVE-2026-88533"],["/yyyy/mm","CVE-2026-0911,CVE-2026-94503"],["/yyyy/mm/...","CVE-2026-0911"],["/zb47/iidde8a4wv8k5d/gnqswmefaaaaagafhqnxfqqgmzt","CVE-2026-77276"],["/zftflhfojzktfbjpluy/gypzmzbvsfqw","CVE-2026-90817"],["/zip/ffmpeg","CVE-2026-76060"],["/zones/etc","CVE-2025-49113"],["/ztp/cgi-bin/handler","CVE-2022-30525"]]);
// END HARVESTED_PATHS

function harvestedObserveEnabled(env, hostname) {
  const flag = String(env.HARVESTED_OBSERVE ?? '').toLowerCase();
  if (flag === 'false') return false;
  if (flag === 'true') return true;
  const host = String(hostname || '').toLowerCase();
  return APPLIANCE_OWN_ZONES.some(z => host === z || host.endsWith('.' + z));
}

function getHarvestedMatch(path) {
  if (!HARVESTED_PATHS.size) return null;
  for (const p of [path, safeDecode(path)]) {
    let k = String(p).toLowerCase();
    if (k.length > 1 && k.endsWith('/')) k = k.slice(0, -1);
    const cves = HARVESTED_PATHS.get(k);
    if (cves) return { path: k, cves };
  }
  return null;
}

// Coarse source: /24 for IPv4, /48 for IPv6. Enough to count distinct sources; not an address.
function sourceNet(ip) {
  const s = String(ip || '');
  if (s.includes(':')) {
    const parts = s.split(':');
    return parts.length >= 3 && parts.slice(0, 3).every(Boolean) ? parts.slice(0, 3).join(':').toLowerCase() + '::/48' : '';
  }
  const o = s.split('.');
  return o.length === 4 ? `${o[0]}.${o[1]}.${o[2]}.0/24` : '';
}

const harvestedSeen = new Map(); // `${net}|${path}` -> ms, per isolate
const HARVESTED_DEDUPE_MS = 10 * 60 * 1000;
const HARVESTED_SEEN_MAX = 5000;
function harvestedFirstInWindow(key, now = Date.now()) {
  const t = harvestedSeen.get(key);
  if (t && now - t < HARVESTED_DEDUPE_MS) return false;
  if (harvestedSeen.size >= HARVESTED_SEEN_MAX) harvestedSeen.clear();
  harvestedSeen.set(key, now);
  return true;
}

async function postHarvestedObservation(env, obs) {
  if (!env.DUGGANUSA_API_KEY) return;
  try {
    const r = await fetch(`${DUGGANUSA_API}/feed/observation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.DUGGANUSA_API_KEY}`, 'User-Agent': SHIELD_UA },
      body: JSON.stringify(obs),
    });
    if (!r.ok) console.log(JSON.stringify({ shield: 'harvested-observe', post: r.status }));
  } catch (e) {
    console.log(JSON.stringify({ shield: 'harvested-observe', error: String(e && e.message || e).slice(0, 80) }));
  }
}

function honeypotResponse(request, cf, canary) {
  if (canary.fake === 'sonicwall') return sonicwallResponse(new URL(request.url).pathname.toLowerCase());
  if (canary.fake === 'netscaler') return netscalerResponse();
  if (canary.fake === 'fortigate') return fortigateResponse();
  if (canary.fake === 'peoplesoft') return peoplesoftResponse();
  if (canary.fake === 'sharepoint') return sharepointResponse();
  if (canary.fake === 'ivanti') return ivantiResponse();
  if (canary.fake === 'cisco') return ciscoResponse(canary.product);
  if (canary.fake === 'globalprotect' || canary.fake === 'panos') return paloResponse(canary.fake, new URL(request.url).pathname.toLowerCase());
  const fakeFn = FAKE_RESPONSES[canary.fake];
  const body = fakeFn ? fakeFn() : '';
  const contentType = ['api', 'admin', 'actuator'].includes(canary.fake) ? 'application/json' :
                      ['wp', 'cpanel'].includes(canary.fake) ? 'text/html' : 'text/plain';

  return new Response(body, {
    status: 200, // Looks real
    headers: {
      'Content-Type': contentType,
      'Server': 'nginx/1.24.0', // Misdirect their fingerprinting
      'X-Powered-By': 'PHP/8.2.0', // Extra misdirection
      'Cache-Control': 'no-store',
    }
  });
}

async function indexHoneypotHit(env, request, cf, canary) {
  const apiKey = env.DUGGANUSA_API_KEY;
  if (!apiKey) return;

  const ip = request.headers.get('cf-connecting-ip') || '';
  const now = new Date().toISOString();

  const ipType = ip.includes(':') ? 'ipv6' : 'ipv4';
  const ioc = {
    id: `honeypot-${ip.replace(/[.:]/g, '-')}-${Date.now()}`,
    value: ip,
    type: ipType,
    // ATTRIBUTION (2026-07-19). This Worker runs on CUSTOMER infrastructure as
    // well as ours, and previously tagged every hit `edge-honeypot` — the same
    // source our Spamhaus contributor treats as a genuinely first-hand DugganUSA
    // sensor observation. Submitting a customer's edge traffic as our own
    // observation is both an evidence-provenance problem and an accuracy risk:
    // one customer false positive lands on our externally-measured match rate.
    // deployment_host makes ours vs. theirs separable downstream.
    source: 'edge-honeypot',
    deployment_host: (() => { try { return new URL(request.url).hostname; } catch { return ''; } })(),
    threat_type: 'scanner',
    malware_family: canary.type,
    confidence: 95,
    country: cf.country || '',
    description: `Edge honeypot trap: ${canary.type} probe on ${request.url}. ` +
      `ASN: AS${cf.asn || '?'} ${cf.asOrganization || '?'}. ` +
      `UA: ${(request.headers.get('user-agent') || '').substring(0, 100)}. ` +
      `Method: ${request.method}. City: ${cf.city || '?'}, ${cf.region || '?'}.`,
    timestamp: now,
    name: `Honeypot: ${canary.type}`,
    tags: ['honeypot', 'edge-shield', 'scanner', canary.type, 'auto-indexed', ...(canary.product ? [canary.product] : [])],
    references: [request.url],
    honeypot_meta: {
      ...(canary.product ? { product: canary.product } : {}),
      ...(canary.encoded_path ? { encoded_path: true } : {}),
      // exploit_path was computed for Ivanti/Cisco/Palo/SharePoint since 2.10.0 but never
      // persisted here, so every exploit marker was dropped before indexing. Fixed 2.12.0.
      ...(canary.exploit_path ? { exploit_path: true } : {}),
      // A default-credential Basic header (admin:admin, seen in the SMA1000 CouchDB SSRF probes)
      // is recorded as a boolean only; the credential itself is never stored.
      ...(/^[Bb]asic\s+YWRtaW46YWRtaW4=?$/.test(request.headers.get('authorization') || '') ? { default_creds: true } : {}),
      path: new URL(request.url).pathname,
      method: request.method,
      ua: request.headers.get('user-agent') || '',
      asn: cf.asn,
      asn_org: cf.asOrganization,
      city: cf.city,
      region: cf.region,
      colo: cf.colo, // CF datacenter that handled the request
      tls_version: cf.tlsVersion,
      http_protocol: cf.httpProtocol,
      // Cloudflare's verdict at capture time (2.14.2). bot_score was logged until 2.14.1 but
      // cf.botManagement.score does not exist without Enterprise Bot Management: it was null on
      // 4,149 of 4,149 canary hits (2026-10-09..16). verifiedBotCategory is populated on every
      // plan when Cloudflare verified the client; '' (or absent) means not verified. Recorded
      // as a comparator only: the canary verdict never depends on it.
      cf_verified_bot_category: cfVerifiedCategory(cf),
    }
  };

  // Fire and forget — index into STIX feed
  try {
    const resp = await fetch(`${DUGGANUSA_API}/threat-intel/honeypot`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': SHIELD_UA
      },
      body: JSON.stringify(ioc)
    });
    if (!resp.ok) {
      console.log(`Honeypot index failed: ${resp.status} ${await resp.text().catch(() => '')}`);
    } else {
      console.log(`Honeypot indexed: ${ip} → ${canary.type}`);
    }
  } catch (e) {
    console.log(`Honeypot index error: ${e.message}`);
  }
}

// ================================================================
// FEED-EFFICACY REPORTING — close the liveness loop
// ================================================================

// When one of our published indicators blocks real traffic, report it back to
// the feed-efficacy axis (/api/v1/feed-efficacy). This is the LIVENESS signal:
// proof that an indicator we publish actually fires in the wild.
//
// PRIVACY CONTRACT (load-bearing): we send ONLY the indicator we already
// published (the attacker's IP — threat infra, never a victim) plus the action,
// direction and a count. No visitor/origin/asset data. The platform drops any
// victim-side field and reports it back as `stripped`. Fire-and-forget; this
// NEVER blocks or delays the 403 the visitor receives.
//
// `action` is 'blocked', or 'observed' in SHIELD_MODE="observe": the indicator
// matched real traffic and the shield let it through on purpose. Same contract.
async function reportFeedHit(env, indicator, hostname, rayId, action = 'blocked') {
  const apiKey = env.DUGGANUSA_API_KEY;
  if (!apiKey || !indicator) return;
  // `zone` only for DugganUSA's own properties (first-party dogfood); null → omitted.
  // `event_id` = the CF ray of the blocked request (the attacker's request, not a
  // visitor attribute) so each block counts once and a retry never double counts.
  const zone = firstPartyZone(hostname);
  try {
    const resp = await fetch(`${DUGGANUSA_API}/feed/hit`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': SHIELD_UA
      },
      body: JSON.stringify({
        consumer_kind: 'edge-shield',
        ...(zone ? { zone } : {}),
        hits: [{
          indicator,
          action,
          direction: 'inbound',
          count: 1,
          ts: Date.now(),
          ...(rayId ? { event_id: `cf-ray-${rayId}` } : {})
        }]
      })
    });
    if (!resp.ok) {
      console.log(`Feed-hit report failed: ${resp.status} ${await resp.text().catch(() => '')}`);
    }
  } catch (e) {
    console.log(`Feed-hit report error: ${e.message}`);
  }
}

// ================================================================
// PER-IP RATE LIMIT — trim availability guard (added 2026-07-10)
// One cheap scraper caused 1,032 origin 504s + 1,047 API extractions before
// anything reacted. We are bootstrapped — we do NOT scale the origin to absorb
// abuse; we bounce volume at the edge for free. Per-isolate in-memory window
// (no paid ratelimit binding / Durable Object / KV): a single-IP flood
// geo-routes to one PoP+isolate, so this counter catches it at zero cost.
// Two-tier so authenticated customers (valid key) get generous headroom.
// ================================================================
// Limits are RL_ANON / RL_AUTH vars (defaults 100 and 500: no human or feed customer
// hits 100/min anonymously; a presented key gets room to burst). 0 disables a tier.
const RL_WINDOW_MS = 60_000;
const rlBuckets = new Map(); // ip -> { count, windowStart }
function rateLimitLimit(authed, cfg) {
  return authed ? cfg.rlAuth : cfg.rlAnon;
}
// Returns null when under the limit, else { limit, first } — `first` is true only on
// the request that crossed it, so observe mode logs a flood once per window, not per hit.
function rateLimited(ip, authed, cfg = DEFAULT_CONFIG) {
  const limit = rateLimitLimit(authed, cfg);
  if (!ip || !limit) return null;
  const now = Date.now();
  let b = rlBuckets.get(ip);
  if (!b || now - b.windowStart >= RL_WINDOW_MS) { b = { count: 0, windowStart: now }; rlBuckets.set(ip, b); }
  b.count++;
  if (rlBuckets.size > 20000) { // bound memory — evict expired windows opportunistically
    for (const [k, v] of rlBuckets) if (now - v.windowStart >= RL_WINDOW_MS) rlBuckets.delete(k);
  }
  return b.count > limit ? { limit, first: b.count === limit + 1 } : null;
}
function rateLimitedResponse(ip, authed, limit) {
  return new Response(JSON.stringify({
    error: 'rate_limited',
    message: `Too many requests — limit ${limit}/min per IP.` + (authed ? '' : ' Register a free API key for higher limits: https://analytics.dugganusa.com/stix/register'),
    ip,
  }), { status: 429, headers: { 'content-type': 'application/json', 'retry-after': '60', 'x-dugganusa-shield': 'rate-limit' } });
}

// ================================================================
// MAIN HANDLER
// ================================================================

export default {
  async fetch(request, env, ctx) {
    const cf = request.cf || {};
    const ua = request.headers.get('user-agent') || '';
    const ip = request.headers.get('cf-connecting-ip') || '';
    const cfg = getConfig(env);
    const reqUrl = new URL(request.url);
    const hostname = reqUrl.hostname.toLowerCase();
    const rayId = request.headers.get('cf-ray');

    // ============================================================
    // LAYER -2: SENSOR hosts — never shielded, not even partly
    // ============================================================
    // Straight to origin, untouched: no 418, no 403, no canary, no rate limit, no
    // header rewrite. See isSensorHost().
    if (isSensorHost(hostname, cfg)) {
      return fetch(request);
    }

    // MTA-STS policy (RFC 8461) for dugganusa.com mail. Served by the shield so the
    // policy host needs no origin. mode: testing — receivers report via TLS-RPT but
    // never refuse delivery; flip to enforce after a clean reporting window. 2026-10-09.
    if (hostname === 'mta-sts.dugganusa.com') {
      if (reqUrl.pathname === '/.well-known/mta-sts.txt') {
        return new Response('version: STSv1\r\nmode: testing\r\nmx: dugganusa-com.mail.protection.outlook.com\r\nmax_age: 604800\r\n',
          { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'max-age=3600' } });
      }
      return new Response('Not found', { status: 404 });
    }

    // What observe mode let through on purpose. Surfaces as X-DugganUSA-Observed on
    // the response so a live probe can prove the shield saw it (scripts/verify.sh).
    const observed = [];

    // ============================================================
    // LAYER -1: BEACON SHIELD — make the beacon the edge's problem
    // ============================================================
    // Forensics 2026-08-21 (investigations/gcp-frankfurt-scraper-2026-08-21):
    // four GCP Frankfurt VMs rendered the blog with headless Chrome. Each rendered
    // page loaded embed.js from analytics and fired track back at it, and BOTH
    // reached the origin uncached — 7,559 and 7,589 requests respectively, all
    // HTTP 200. Cache hit rate across the whole event was 28%: ~259,000 requests
    // hit the origin against ~102,000 absorbed by the edge. That is what pinned the
    // app at max scale and starved a rolling deploy of a slot.
    //
    // The beacon is the ONE thing on this platform that scales with somebody else's
    // scraping. It should never touch the origin more than it has to.
    {
      const u = new URL(request.url);
      const path = u.pathname;

      // embed.js is a static file. It generated 7,559 origin requests in one evening;
      // it should generate approximately one. Served from the edge cache with a long
      // TTL, keyed without query strings so cache-busting params cannot fragment it.
      if (path === '/api/v1/blog-tracking/embed.js') {
        const cacheKey = new Request(`${u.origin}${path}`, { method: 'GET' });
        const cache = caches.default;
        const hit = await cache.match(cacheKey);
        if (hit) {
          const r = new Response(hit.body, hit);
          r.headers.set('x-dusa-beacon-cache', 'hit');
          return r;
        }
        const origin = await fetch(withOriginEdge(request, env, hostname));
        if (origin.ok) {
          const cacheable = new Response(origin.body, origin);
          cacheable.headers.set('Cache-Control', 'public, max-age=3600, s-maxage=86400');
          cacheable.headers.set('x-dusa-beacon-cache', 'miss');
          ctx.waitUntil(cache.put(cacheKey, cacheable.clone()));
          return cacheable;
        }
        return origin;
      }

      // track is a write, so it cannot be cached — it gets a per-IP ceiling instead.
      // A real visitor produces a handful of beacons per minute; 7,589 in an evening
      // from two addresses is not a visitor. Counter lives in the edge cache, so it
      // is per-colo rather than global — deliberately: a distributed scraper is a
      // different problem, and a per-colo bucket still costs a single-source flood
      // everything while adding no state, no KV binding and no origin round-trip.
      if (path.startsWith('/api/v1/blog-tracking/track')) {
        const BEACON_LIMIT = 60;          // per IP, per minute, per colo
        const minute = Math.floor(Date.now() / 60000);
        const counterKey = new Request(`https://beacon-rl.dugganusa.internal/${encodeURIComponent(ip)}/${minute}`);
        const cache = caches.default;
        let count = 0;
        const prev = await cache.match(counterKey);
        if (prev) { count = parseInt(await prev.text(), 10) || 0; }
        if (count >= BEACON_LIMIT) {
          // 429 at the edge. Never reaches the origin, never becomes a page view.
          return new Response(null, {
            status: 429,
            headers: { 'retry-after': '60', 'x-dusa-beacon-rl': 'exceeded', 'cache-control': 'no-store' }
          });
        }
        ctx.waitUntil(cache.put(counterKey, new Response(String(count + 1), {
          headers: { 'Cache-Control': 'max-age=90' }
        })));
      }
    }
    const asnOrg = cf.asOrganization || '';
    const apiKey = env.DUGGANUSA_API_KEY || '';

    // Refresh IOC cache in background
    // (Skipped entirely when IOC blocking is off: no point spending API calls.)
    if (apiKey && cfg.iocBlocking) {
      ctx.waitUntil(refreshIOCs(apiKey, cfg));
    }

    // ============================================================
    // LAYER 0: Verified crawlers — never block, never trap
    // ============================================================
    // Evaluated before every enforcement layer because a legitimate crawler must
    // not be scanner-blocked, must not be IOC-blocked (a crawler IP can land on a
    // high-confidence list), and must NOT be fed a honeypot canary — a fake 200
    // full of invented shell output is exactly what a search engine would happily
    // index against us.
    //
    // It is a SKIP, not an early return: verified crawlers still fall through to
    // Layer 4, because that is where the schema.org and ai-purpose markup is
    // injected. Short-circuiting straight to origin here would hand crawlers a
    // page stripped of the very metadata we added for them.
    const verifiedCrawler = await isVerifiedCrawler(request, cf);

    // ============================================================
    // LAYER 0.5: Harvested-path OBSERVATION — never blocks, never answers, never an IOC
    // ============================================================
    // Before scanner/IOC enforcement on purpose: a probe that a later layer 418s or 403s still
    // ARRIVED, and arrival time is the whole measurement. See HARVESTED_PATHS above.
    if (!verifiedCrawler && harvestedObserveEnabled(env, hostname)) {
      const hv = getHarvestedMatch(reqUrl.pathname);
      if (hv) {
        const net = sourceNet(ip);
        if (harvestedFirstInWindow(`${net}|${hv.path}`)) {
          // On a CUSTOMER zone (opted in) the report is minimal: the CVE, OUR list's path, ASN,
          // country and method. Never their hostname, never the visitor's UA or network.
          const own = APPLIANCE_OWN_ZONES.some(z => hostname === z || hostname.endsWith('.' + z));
          ctx.waitUntil(postHarvestedObservation(env, {
            cves: hv.cves, path: hv.path, asn: cf.asn || null, country: cf.country || '',
            method: request.method, list_generated_at: HARVESTED_PATHS_GENERATED_AT,
            ...(own ? { host: hostname, src_net: net, as_org: String(asnOrg || '').slice(0, 80), colo: cf.colo || '',
              ua: String(ua || '').substring(0, 120) } : {}),
          }));
        }
      }
    }

    // ============================================================
    // LAYER 1: Scanner detection — return 418 I'm a Teapot
    // ============================================================
    if (cfg.scanner418 && !verifiedCrawler && detectScanner(ua, asnOrg)) {
      if (!cfg.observe) return scannerResponse(request, cf);
      observed.push('scanner');
      logObserved('scanner-418', ip, hostname, reqUrl.pathname, rayId);
    }

    // ============================================================
    // LAYER 2: IOC blocking — known malicious IPs get 403
    // ============================================================
    if (cfg.iocBlocking && !verifiedCrawler && ip && checkIOC(ip)) {
      // Report the hit to the feed-efficacy (liveness) axis — non-blocking,
      // privacy-preserving (indicator only, never the visitor/asset). In observe
      // mode the match is still reported, as 'observed': the evidence is the same.
      if (apiKey && cfg.feedHitReporting) {
        ctx.waitUntil(reportFeedHit(env, ip, hostname, rayId, cfg.observe ? 'observed' : 'blocked'));
      }
      if (!cfg.observe) return blockedResponse(ip);
      observed.push('ioc');
      logObserved('ioc-403', ip, hostname, reqUrl.pathname, rayId);
    }

    // ============================================================
    // LAYER 3: Honeypot canaries — trap recon, harvest fingerprints
    // ============================================================
    // OPT-OUT (2026-07-19). Honeypots send visitor IP, User-Agent, geo and the
    // full request URL back to DugganUSA — see the Privacy section of the README.
    // They also return deception content on matching paths, which collides with
    // real routes: /graphql, /webmail/*, and anything containing `.env` all match.
    // A customer serving those legitimately needs a way off, and the README now
    // documents this flag, so it has to actually work.
    const honeypotsEnabled = String(env.HONEYPOTS_ENABLED ?? 'true').toLowerCase() !== 'false';
    // Honeypots are NOT affected by SHIELD_MODE: they are deception, not blocking,
    // and have their own switch. Observe mode does not turn them off.
    const path = reqUrl.pathname;
    // Verified crawlers are exempt: a canary returns a convincing fake 200 full of
    // invented shell output or fake API keys, and a search engine would index that
    // against the customer's own domain.
    // Secret-file probes: a 404 at the edge for EVERYONE, verified crawlers included (they are
    // exempt from decoys, not from the 404). Only unverified clients are indexed.
    const secretProbe = applianceCanariesEnabled(env, hostname) ? getSecretProbe(path) : null;
    if (secretProbe) {
      // NEVER INDEXED (2.13.2). A secret-file probe can always be INDUCED: a victim's browser via
      // <img src>, an AI fetcher via a prompt-injected URL, a link previewer (Slackbot, Discordbot)
      // or a mail link scanner (Safe Links, Proofpoint) via a pasted or emailed link, all from
      // shared egress. Enumerating those cases was a treadmill (two security reviews, two holes),
      // and any no-index exemption doubles as a detection bypass. The invariant: one hit is never
      // evidence about the requester, so it never becomes an IOC. Everyone gets the 404; every
      // hit is logged with how it arrived, for counting, not for blocking.
      console.log(JSON.stringify({ shield: 'secret-probe', path, via: secretProbeVia(request, ua, verifiedCrawler),
        exploit: !!secretProbe.exploit_path, asn: cf.asn, colo: cf.colo, ua: ua.substring(0, 80) }));
      return secretProbeResponse();
    }

    // Existing canaries take precedence, so /vpn/%2eenv still counts as a config probe.
    const canary = (honeypotsEnabled && !verifiedCrawler)
      ? (getCanary(path) || (applianceCanariesEnabled(env, new URL(request.url).hostname) ? getApplianceCanary(path) : null))
      : null;
    if (canary) {
      // Index the attacker's fingerprint into the STIX feed (non-blocking)
      ctx.waitUntil(indexHoneypotHit(env, request, cf, canary));
      // Return convincing fake response — waste their time
      return honeypotResponse(request, cf, canary);
    }

    // ============================================================
    // LAYER 3.5: Per-IP rate limit — trim availability guard
    // Runs only on origin-bound traffic (scanner/IOC/honeypot already handled
    // their cases above). Bounces a volume flood before it can strain the trim
    // origin. Anonymous IPs get cfg.rlAnon/min; a presented API key gets cfg.rlAuth/min
    // (the origin still validates the key — this only caps request RATE).
    // ============================================================
    // Verified crawlers are exempt. Googlebot legitimately crawls a large site
    // faster than the anonymous cap allows, and rate-limiting it looks to a search
    // engine exactly like an unreliable origin — which costs the customer ranking.
    const authed = !!(request.headers.get('authorization') || reqUrl.searchParams.get('api_key'));
    const rl = verifiedCrawler ? null : rateLimited(ip, authed, cfg);
    if (rl) {
      if (!cfg.observe) return rateLimitedResponse(ip, authed, rl.limit);
      observed.push('rate-limit');
      if (rl.first) logObserved(`rate-limit-429 (>${rl.limit}/min)`, ip, hostname, path, rayId);
    }

    // ============================================================
    // LAYER 4: Geo headers + analytics enrichment
    // ============================================================
    const newHeaders = new Headers(request.headers);

    // Geo data
    if (cf.city) newHeaders.set('X-CF-City', cf.city);
    if (cf.region) newHeaders.set('X-CF-Region', cf.region);
    if (cf.latitude) newHeaders.set('X-CF-Latitude', cf.latitude);
    if (cf.longitude) newHeaders.set('X-CF-Longitude', cf.longitude);
    if (cf.timezone) newHeaders.set('X-CF-Timezone', cf.timezone);
    if (cf.metroCode) newHeaders.set('X-CF-Metro-Code', cf.metroCode);
    if (cf.postalCode) newHeaders.set('X-CF-Postal-Code', cf.postalCode);
    if (cf.asOrganization) newHeaders.set('X-CF-ASN-Org', cf.asOrganization);

    // Shield metadata
    newHeaders.set('X-DugganUSA-Shield', 'active');
    newHeaders.set('X-DugganUSA-IOCs', iocCache.count.toString());

    // Origin edge secret (2.14.0): our own origins only; a client copy is always stripped.
    applyOriginEdge(newHeaders, env, hostname);

    // Pass to origin with enriched headers
    const newRequest = new Request(request, { headers: newHeaders });

    // LAYER 4.5: ARCHIVE SHIELD — see serveArchive(). Blog posts are the one surface
    // where the origin fails ~half of all cold reads, so they get cache-first with a
    // stale-if-error floor. Everything else goes straight through unchanged.
    const _au = new URL(request.url);
    const isArchive = request.method === 'GET'
      && _au.hostname === 'www.dugganusa.com'
      && _au.pathname.startsWith('/post/');
    const response = isArchive
      ? await serveArchive(request, newRequest, ctx)
      : await fetch(newRequest);

    // ============================================================
    // LAYER 5: LD-JSON injection for HTML responses
    // Fixes the AIPM problem where models think DugganUSA is metal fab
    // ============================================================
    const contentType = response.headers.get('content-type') || '';
    const host = reqUrl.hostname;

    // LAYER 5.5: TRUST PATHS — site-reputation scanners (Scam Detector and its kind) probe
    // /contact, /terms, /privacy, /pricing on the apex host and score a 404 as a missing
    // business. Ours live elsewhere (About page, analytics, a blog post). Redirect only when
    // the origin 404s, so a real Wix page added later always wins. 302, not 301, for the
    // same reason. 2026-10-13.
    if (response.status === 404 && TRUST_HOSTS.includes(hostname) && TRUST_REDIRECTS[reqUrl.pathname.replace(/\/+$/, '')]) {
      return Response.redirect(new URL(TRUST_REDIRECTS[reqUrl.pathname.replace(/\/+$/, '')], 'https://www.dugganusa.com').href, 302);
    }

    let out = response;
    if (contentType.includes('text/html') && cfg.schemaInjectHosts.includes(hostname)) {
      const rw = new HTMLRewriter().on('head', new SchemaInjector(host));
      // Server-side, so a crawler that never runs JavaScript still reads who we are.
      if (TRUST_HOSTS.includes(hostname)) rw.on('body', new TrustFooter());
      out = rw.transform(response);
    }

    if (!observed.length) return out;
    const tagged = new Response(out.body, out);
    tagged.headers.set('X-DugganUSA-Observed', observed.join(','));
    return tagged;
  }
};


// ================================================================
// ARCHIVE SHIELD — keep the corpus readable when the blog origin is not
// ================================================================
// Measured 2026-08-22 over eight days of Cloudflare data: cache-MISS requests to
// www.dugganusa.com return HTTP 504 between 28.0% and 82.5% of the time, EVERY DAY,
// at any volume. Mean 52.7%. 18 August — an ordinary day, no incident, no traffic
// event — produced 14,109 gateway timeouts that nobody noticed. During the 21 Aug
// harvest, 125,101 of 125,101 504s landed on a miss; hit, bypass, dynamic and
// revalidated responses had a ZERO percent failure rate.
//
// So the archive is not slow, it is intermittently absent, and it has been for as
// long as we have data. That directly attacks the thing we say the blog IS — durable
// institutional memory you can be pointed back at. A citation into a two-year-old
// post is a coin flip today.
//
// We do not own the blog origin, but www routes through this worker, so the fix
// lives here:
//   - serve a fresh cached copy immediately (kills the miss, and the miss is the
//     only thing that ever fails)
//   - revalidate in the background once it ages past SWR
//   - and if the origin 5xxes, serve the stale copy at ANY age rather than hand a
//     reader a gateway timeout
//
// Cached copy is stored PRE-schema-injection so the LD-JSON rewriter still runs on
// the way out. Two variants are kept, mobile and desktop, because the platform
// serves different markup to each and one cached variant would be served to both.
const ARCHIVE_FRESH_MS = 10 * 60 * 1000;        // serve without revalidating
const ARCHIVE_SWR_MS = 60 * 60 * 1000;          // serve, refresh in background
const ARCHIVE_MAX_AGE_S = 7 * 24 * 60 * 60;     // emergency copy retained a week

function archiveKey(url, ua) {
  const variant = /Mobile|Android|iPhone|iPad/i.test(ua || '') ? 'm' : 'd';
  return new Request(`${url.origin}${url.pathname}?__dusa_v=${variant}`, { method: 'GET' });
}

// Cookies the blog platform sets on every public post. Verified 2026-08-22 against a
// live response: `ssr-caching` is the platform's own SSR-cache DIAGNOSTIC string
// (`cache#desc=miss#varnish=miss_hit#dc#desc=fastly_g`, max-age 20) and
// `sec-fetch-unsupported` is a feature-detection flag. Neither carries identity,
// session or auth. Any OTHER cookie is treated as identity and blocks caching, so a
// future platform change cannot silently turn this into a session-leak.
const ARCHIVE_SAFE_COOKIES = /^(ssr-caching|sec-fetch-unsupported)=/;

function cookiesAreSafe(response) {
  // getAll is the only way to see multiple Set-Cookie headers separately.
  const all = typeof response.headers.getAll === 'function'
    ? response.headers.getAll('set-cookie')
    : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);
  return all.every((c) => ARCHIVE_SAFE_COOKIES.test(c.trim()));
}

async function storeArchive(cache, key, response, ctx) {
  if (response.status !== 200) return;
  const ct = response.headers.get('content-type') || '';
  if (!ct.includes('text/html')) return;

  // A Set-Cookie we do not recognise means the response may be personalised, and
  // caching it would hand one reader's cookie to every subsequent reader. Refuse.
  if (!cookiesAreSafe(response)) return;

  const copy = new Response(response.body, response);

  // DELIBERATE OVERRIDE. The origin sends `public, max-age=0, must-revalidate` on
  // every post, which is why cf-cache-status is BYPASS across the whole corpus and
  // why every read — including a two-year-old post nobody has touched — goes to an
  // origin that fails 28-82.5% of the time. We are overriding a platform directive
  // the platform cannot honour: it asks us to revalidate against a service that
  // returns 504 for roughly half of cold requests. Freshness is bounded by
  // ARCHIVE_FRESH_MS/ARCHIVE_SWR_MS above, not by this header.
  copy.headers.delete('set-cookie');
  copy.headers.set('Cache-Control', `public, max-age=${ARCHIVE_MAX_AGE_S}`);
  copy.headers.set('x-dusa-archive-at', String(Date.now()));
  ctx.waitUntil(cache.put(key, copy));
}

async function serveArchive(request, originRequest, ctx) {
  const url = new URL(request.url);
  const cache = caches.default;
  const key = archiveKey(url, request.headers.get('user-agent'));

  let hit = null;
  try { hit = await cache.match(key); } catch (_) { hit = null; }
  const age = hit ? Date.now() - (parseInt(hit.headers.get('x-dusa-archive-at'), 10) || 0) : Infinity;

  // Fresh enough to serve outright — this is the case that removes the miss.
  if (hit && age < ARCHIVE_FRESH_MS) {
    const r = new Response(hit.body, hit);
    r.headers.set('x-dusa-archive', 'hit');
    return r;
  }

  // Aging but usable: serve it now, refresh behind the reader's back.
  if (hit && age < ARCHIVE_SWR_MS) {
    ctx.waitUntil((async () => {
      try {
        const fresh = await fetch(originRequest);
        await storeArchive(cache, key, fresh, { waitUntil: (p) => p });
      } catch (_) { /* origin still sick; the stale copy stands */ }
    })());
    const r = new Response(hit.body, hit);
    r.headers.set('x-dusa-archive', 'swr');
    return r;
  }

  // No usable copy — go to origin, and catch it when it fails.
  let origin;
  try {
    origin = await fetch(originRequest);
  } catch (_) {
    origin = null;
  }

  if (origin && origin.status < 500) {
    const forCache = origin.clone();
    await storeArchive(cache, key, forCache, ctx);
    const r = new Response(origin.body, origin);
    r.headers.set('x-dusa-archive', hit ? 'refreshed' : 'miss');
    return r;
  }

  // Origin is down or 5xx. THIS is the 52.7% case. Serve stale at any age.
  if (hit) {
    const r = new Response(hit.body, hit);
    r.headers.set('x-dusa-archive', 'stale-if-error');
    r.headers.set('x-dusa-origin-status', origin ? String(origin.status) : 'fetch-failed');
    return r;
  }

  // Never cached and the origin is failing — nothing we can do but be honest.
  return origin || new Response('Upstream unavailable', { status: 502 });
}

// ================================================================
// LD-JSON SCHEMA — DugganUSA canonical Organization record
// Fixes AI model confusion (Gemini thinks we're Duggan Manufacturing,
// Mistral thinks we're a gun store, DeepSeek thinks we have bad reviews)
// ================================================================
const DUGGANUSA_ORGANIZATION_SCHEMA = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  '@id': 'https://www.dugganusa.com/#organization',
  // @id/name/url match the Wix embed (config/wix/org-jsonld.html) so crawlers merge the two
  // records into one entity instead of scoring two conflicting ones. The old logo URL
  // (dugganusa.com/logo.png) returned 400. 2026-10-13.
  'name': 'DugganUSA LLC',
  'legalName': 'DugganUSA LLC',
  // One entity (docs/brand/STANDARD.md, approved 2026-10-14): one alternate name, same as the Wix embed.
  'alternateName': ['DugganUSA'],
  'slogan': 'Threat intelligence you can check.',
  'url': 'https://www.dugganusa.com',
  'logo': 'https://static.wixstatic.com/media/fd5e2b_b7a0f87f83404839b4371dd9b41c70e6~mv2.png',
  'foundingDate': '2025-10-07',
  'description': 'DugganUSA LLC is an AI security and threat-intelligence company. Its story in one line: "We watched the open internet, then built the membrane between your AI agents and everything they install, call, read and obey." DugganUSA is AI security you can check: threat intelligence with receipts, and pre-flight judgment on what is about to cross into your agent. Products: DugganUSA Feed (STIX 2.1/TAXII/CSV/MISP), Jeevesus (search MCP), Dredd (MCP pre-flight), Edge Shield, AIPM (AI Presence Management, aipmsec.com) and FinOps (AI spend metering). No SOC 2 report or third-party certification is claimed.',
  'brand': ['DugganUSA Feed', 'Jeevesus', 'Dredd', 'Edge Shield', 'AIPM', 'FinOps', 'Butterbot'],
  'address': {
    '@type': 'PostalAddress',
    'addressLocality': 'Minnetrista',
    'addressRegion': 'MN',
    'addressCountry': 'US'
  },
  'contactPoint': {
    '@type': 'ContactPoint',
    'email': 'help@dugganusa.com',
    'contactType': 'customer support'
  },
  'sameAs': [
    'https://www.linkedin.com/company/dugganusa-llc',
    'https://github.com/pduggusa',
    'https://analytics.dugganusa.com',
    'https://aipmsec.com'
  ],
  'identifier': [
    { '@type': 'PropertyValue', 'name': 'D-U-N-S', 'value': '14-363-3562' },
    { '@type': 'PropertyValue', 'name': 'SAM.gov UEI', 'value': 'TP9FY7262K87' }
  ],
  'employee': [
    {
      '@type': 'Person',
      'name': 'Patrick Duggan',
      'jobTitle': 'Founder and Chief Executive Officer',
      'worksFor': { '@id': 'https://www.dugganusa.com/#organization' },
      'sameAs': [
        'https://www.linkedin.com/in/patrickdugganmn/',
        'https://bsky.app/profile/hakksaww.bsky.social',
        'https://github.com/pduggusa'
      ]
    }
  ],
  'knowsAbout': [
    'Threat Intelligence',
    'STIX 2.1',
    'Cybersecurity',
    'AI Presence Management',
    'Model Context Protocol (MCP) server security',
    'Prompt injection defense',
    'Supply Chain Security',
    'AI spend metering'
  ]
};

const DUGGANUSA_SERVICES_SCHEMA = [
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'DugganUSA Feed',
    'description': 'STIX 2.1 threat feed, TAXII server, CSV/MISP exports and an indicator search API. Free tier available; live counts at https://analytics.dugganusa.com/api/v1/search/stats.',
    'serviceType': 'Threat Intelligence',
    'provider': { '@id': 'https://www.dugganusa.com/#organization' },
    'url': 'https://analytics.dugganusa.com/api/v1/stix-feed',
    'areaServed': { '@type': 'Country', 'name': 'Worldwide' }
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'AIPM (AI Presence Management)',
    'description': 'Audits how AI language models describe a brand, using a multi-model council and seven site-structure signals, and publishes the ground truth each score is graded against.',
    'serviceType': 'AI Visibility Management',
    'provider': { '@id': 'https://www.dugganusa.com/#organization' },
    'url': 'https://aipmsec.com'
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'Edge Honeypot Network',
    'description': 'Open-source Cloudflare Worker deception endpoints that turn scanner traffic into indicators for the STIX feed.',
    'serviceType': 'Cyber Deception',
    'provider': { '@id': 'https://www.dugganusa.com/#organization' },
    'url': 'https://github.com/pduggusa/dugganusa-edge-shield'
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'Exploit Harvester',
    'description': 'Automated GitHub mining for newly published CVE proof-of-concept code. Extracts attack patterns and converts them to STIX 2.1 detection rules every 6 hours.',
    'serviceType': 'Threat Intelligence Automation',
    'provider': { '@id': 'https://www.dugganusa.com/#organization' }
  }
];

// ================================================================
// TRUST FOOTER + TRUST PATHS (2026-10-13) — DugganUSA's own hosts only
// A Scam Detector review scored www.dugganusa.com 34/100 on a stale scrape. The Wix
// footer links none of: legal name, registered town, privacy, terms, contact. This adds
// them at the edge, in plain HTML, on every page.
// ================================================================
const TRUST_HOSTS = ['www.dugganusa.com', 'dugganusa.com'];
const TRUST_REDIRECTS = {
  '/contact': '/about',
  '/contact-us': '/about',
  '/terms': 'https://analytics.dugganusa.com/terms',
  '/privacy': '/post/dugganusa-privacy-policy',
  '/pricing': 'https://analytics.dugganusa.com/pricing',
  '/research': '/blog'   // nav label 'Research' = the www blog (2026-10-16)
};
const TRUST_FOOTER_HTML =
  '<footer id="dg-trust" style="clear:both;position:relative;z-index:6;background:#f3f4f8;color:#444c63;' +
  'font:13px/1.7 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;' +
  'text-align:center;padding:18px 16px;border-top:1px solid #e3e6ee">' +
  '<span>&copy; 2026 DugganUSA LLC, a Minnesota limited liability company &middot; Minnetrista, Minnesota, USA ' +
  '&middot; D-U-N-S 14-363-3562</span><br>' +
  '<a style="color:#4f46e5" href="/about">About</a> &middot; ' +
  '<a style="color:#4f46e5" href="mailto:help@dugganusa.com">Contact: help@dugganusa.com</a> &middot; ' +
  '<a style="color:#4f46e5" href="/post/dugganusa-privacy-policy">Privacy</a> &middot; ' +
  '<a style="color:#4f46e5" href="https://analytics.dugganusa.com/terms">Terms</a> &middot; ' +
  '<a style="color:#4f46e5" href="https://analytics.dugganusa.com/pricing">Pricing</a> &middot; ' +
  '<a style="color:#4f46e5" href="https://www.linkedin.com/company/dugganusa-llc" rel="noopener">LinkedIn</a> &middot; ' +
  '<a style="color:#4f46e5" href="https://github.com/pduggusa" rel="noopener">GitHub</a>' +
  '</footer>';

class TrustFooter {
  constructor() { this.done = false; }
  element(element) {
    if (this.done) return;
    this.done = true;
    element.append(TRUST_FOOTER_HTML, { html: true });
  }
}

class SchemaInjector {
  constructor(host) {
    this.host = host;
    this.injected = false;
  }

  element(element) {
    if (this.injected) return;
    this.injected = true;

    // Inject the Organization schema — except on www/apex, where the Wix embed
    // (config/wix/org-jsonld.html) is the canonical record. Two nodes with one @id and different
    // fields made crawlers score two conflicting entities (brand audit 2026-10-14).
    const wixCanonical = this.host === 'www.dugganusa.com' || this.host === 'dugganusa.com';
    if (!wixCanonical) {
      const orgScript = `<script type="application/ld+json">${JSON.stringify(DUGGANUSA_ORGANIZATION_SCHEMA)}</script>`;
      element.append(orgScript, { html: true });
    }

    // Inject each service schema
    for (const service of DUGGANUSA_SERVICES_SCHEMA) {
      const serviceScript = `<script type="application/ld+json">${JSON.stringify(service)}</script>`;
      element.append(serviceScript, { html: true });
    }

    // Add AI-aware meta tags
    // 2026-10-12: removed ai-credentials meta and hasCredential — it asserted SOC 2 Type 2 (88%),
    // CMMC L2 (71%), GovRAMP/FedRAMP/FIPS as certifications "recognized by" AICPA/DoD. None exist.
    element.append('<meta name="ai-purpose" content="DugganUSA LLC is a threat intelligence company in Minnetrista, Minnesota (Minneapolis metro), founded October 2025. Publishes a free STIX 2.1 threat feed. Holds no SOC 2 report or third-party certification. Not Duggan Manufacturing. Not a firearms company. Not an HVAC company.">', { html: true });
    element.append('<meta name="ai-services" content="DugganUSA Feed (STIX 2.1), Jeevesus search MCP, Dredd MCP pre-flight, Edge Shield, AIPM AI Presence Management, FinOps AI spend metering">', { html: true });
  }
}

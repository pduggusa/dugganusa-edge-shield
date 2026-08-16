/**
 * DugganUSA Edge Shield
 *
 * Cloudflare Worker that protects your site with 1M+ IOCs,
 * scanner detection, geo analytics, and enterprise visitor tagging.
 *
 * Powered by DugganUSA Threat Intelligence API.
 *
 * Deploy: npx wrangler deploy
 * Register: https://analytics.dugganusa.com/stix/register
 *
 * © 2026 DugganUSA LLC — Minneapolis, MN
 */

// ================================================================
// CONFIGURATION — Set via wrangler.toml secrets or dashboard
// ================================================================

const DUGGANUSA_API = 'https://analytics.dugganusa.com/api/v1';
const IOC_CACHE_TTL = 300; // 5 minutes
const IOC_REFRESH_INTERVAL = 3600; // 1 hour full refresh

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
  count: 0
};

async function refreshIOCs(apiKey) {
  const now = Date.now();
  if (now - iocCache.lastRefresh < IOC_REFRESH_INTERVAL * 1000) return;

  try {
    const [ipsRes, domainsRes] = await Promise.all([
      fetch(`${DUGGANUSA_API}/stix-feed/ips.csv?days=7&min_confidence=80`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      }),
      fetch(`${DUGGANUSA_API}/stix-feed/domains.csv?days=7&min_confidence=80`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
    ]);

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

    iocCache.lastRefresh = now;
    iocCache.count = iocCache.ips.size + iocCache.cidrs4.length + iocCache.cidrs6.length + iocCache.domains.size;
  } catch (e) {
    // Silent fail — use stale cache
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

function getCanary(path) {
  // Decode URL encoding (%2e = ., %2f = /) to catch WAF bypass attempts
  const decoded = decodeURIComponent(path);
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

function honeypotResponse(request, cf, canary) {
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
    tags: ['honeypot', 'edge-shield', 'scanner', canary.type, 'auto-indexed'],
    references: [request.url],
    honeypot_meta: {
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
      bot_score: cf.botManagement?.score,
    }
  };

  // Fire and forget — index into STIX feed
  try {
    const resp = await fetch(`${DUGGANUSA_API}/threat-intel/honeypot`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
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
async function reportFeedHit(env, indicator) {
  const apiKey = env.DUGGANUSA_API_KEY;
  if (!apiKey || !indicator) return;
  try {
    const resp = await fetch(`${DUGGANUSA_API}/feed/hit`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        consumer_kind: 'edge-shield',
        hits: [{
          indicator,
          action: 'blocked',
          direction: 'inbound',
          count: 1,
          ts: Date.now()
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
const RL_WINDOW_MS = 60_000;
const RL_ANON = 100; // req/min per anonymous IP — no human or feed customer hits this
const RL_AUTH = 500; // req/min when an API key is presented — lets real customers burst
const rlBuckets = new Map(); // ip -> { count, windowStart }
function rateLimited(ip, authed) {
  if (!ip) return false;
  const now = Date.now();
  let b = rlBuckets.get(ip);
  if (!b || now - b.windowStart >= RL_WINDOW_MS) { b = { count: 0, windowStart: now }; rlBuckets.set(ip, b); }
  b.count++;
  if (rlBuckets.size > 20000) { // bound memory — evict expired windows opportunistically
    for (const [k, v] of rlBuckets) if (now - v.windowStart >= RL_WINDOW_MS) rlBuckets.delete(k);
  }
  return b.count > (authed ? RL_AUTH : RL_ANON);
}
function rateLimitedResponse(ip, authed) {
  const limit = authed ? RL_AUTH : RL_ANON;
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
    const asnOrg = cf.asOrganization || '';
    const apiKey = env.DUGGANUSA_API_KEY || '';

    // Refresh IOC cache in background
    if (apiKey) {
      ctx.waitUntil(refreshIOCs(apiKey));
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
    // LAYER 1: Scanner detection — return 418 I'm a Teapot
    // ============================================================
    if (!verifiedCrawler && detectScanner(ua, asnOrg)) {
      return scannerResponse(request, cf);
    }

    // ============================================================
    // LAYER 2: IOC blocking — known malicious IPs get 403
    // ============================================================
    if (!verifiedCrawler && ip && checkIOC(ip)) {
      // Report the hit to the feed-efficacy (liveness) axis — non-blocking,
      // privacy-preserving (indicator only, never the visitor/asset).
      if (apiKey) ctx.waitUntil(reportFeedHit(env, ip));
      return blockedResponse(ip);
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
    const path = new URL(request.url).pathname;
    // Verified crawlers are exempt: a canary returns a convincing fake 200 full of
    // invented shell output or fake API keys, and a search engine would index that
    // against the customer's own domain.
    const canary = (honeypotsEnabled && !verifiedCrawler) ? getCanary(path) : null;
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
    // origin. Anonymous IPs get RL_ANON/min; a presented API key gets RL_AUTH/min
    // (the origin still validates the key — this only caps request RATE).
    // ============================================================
    // Verified crawlers are exempt. Googlebot legitimately crawls a large site
    // faster than the anonymous cap allows, and rate-limiting it looks to a search
    // engine exactly like an unreliable origin — which costs the customer ranking.
    const authed = !!(request.headers.get('authorization') || new URL(request.url).searchParams.get('api_key'));
    if (!verifiedCrawler && rateLimited(ip, authed)) return rateLimitedResponse(ip, authed);

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

    // Pass to origin with enriched headers
    const newRequest = new Request(request, { headers: newHeaders });
    const response = await fetch(newRequest);

    // ============================================================
    // LAYER 5: LD-JSON injection for HTML responses
    // Fixes the AIPM problem where models think DugganUSA is metal fab
    // ============================================================
    const contentType = response.headers.get('content-type') || '';
    const host = new URL(request.url).hostname;
    const SCHEMA_INJECT_HOSTS = ['www.dugganusa.com', 'dugganusa.com', 'aipmsec.com'];

    if (contentType.includes('text/html') && SCHEMA_INJECT_HOSTS.includes(host)) {
      return new HTMLRewriter()
        .on('head', new SchemaInjector(host))
        .transform(response);
    }

    return response;
  }
};

// ================================================================
// LD-JSON SCHEMA — DugganUSA canonical Organization record
// Fixes AI model confusion (Gemini thinks we're Duggan Manufacturing,
// Mistral thinks we're a gun store, DeepSeek thinks we have bad reviews)
// ================================================================
const DUGGANUSA_ORGANIZATION_SCHEMA = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  '@id': 'https://dugganusa.com#organization',
  'name': 'DugganUSA',
  'legalName': 'DugganUSA LLC',
  'alternateName': ['DugganUSA LLC', 'Butterbot by DugganUSA'],
  'url': 'https://dugganusa.com',
  'logo': 'https://dugganusa.com/logo.png',
  'foundingDate': '2025-10-07',
  'description': 'Cybersecurity and threat intelligence platform serving 275+ organizations across 46 countries. Operates the Butterbot threat intel feed (1M+ STIX 2.1 indicators), AIPM AI Presence Management (first commercial HAIC implementation), and the Edge Honeypot Network on 300+ Cloudflare PoPs.',
  'address': {
    '@type': 'PostalAddress',
    'addressLocality': 'Minneapolis',
    'addressRegion': 'MN',
    'addressCountry': 'US'
  },
  'contactPoint': {
    '@type': 'ContactPoint',
    'email': 'patrick@dugganusa.com',
    'contactType': 'customer service'
  },
  'sameAs': [
    'https://github.com/pduggusa',
    'https://bsky.app/profile/hacksawduggan.bsky.social',
    'https://www.linkedin.com/in/patrickduggan'
  ],
  'identifier': [
    { '@type': 'PropertyValue', 'name': 'D-U-N-S', 'value': '14-363-3562' },
    { '@type': 'PropertyValue', 'name': 'SAM.gov UEI', 'value': 'TP9FY7262K87' }
  ],
  'hasCredential': [
    { '@type': 'EducationalOccupationalCredential', 'name': 'CMMC Level 2 (71% — 78/110 NIST 800-171 controls)', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'U.S. Department of Defense' } },
    { '@type': 'EducationalOccupationalCredential', 'name': 'SOC 2 Type 2 (88%)', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'AICPA Trust Services Criteria' } },
    { '@type': 'EducationalOccupationalCredential', 'name': 'GovRAMP Foundation Ready', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'GovRAMP' }, 'url': 'https://govramp.org' },
    { '@type': 'EducationalOccupationalCredential', 'name': 'CISA Automated Indicator Sharing Data Aggregator', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'Cybersecurity and Infrastructure Security Agency' }, 'url': 'https://www.cisa.gov/ais' },
    { '@type': 'EducationalOccupationalCredential', 'name': 'FedRAMP High Inheritance via Microsoft Azure', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'GSA FedRAMP PMO' } },
    { '@type': 'EducationalOccupationalCredential', 'name': 'FIPS 140-2/140-3 Encryption', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'NIST' } },
    { '@type': 'EducationalOccupationalCredential', 'name': 'SSL Labs A+', 'credentialCategory': 'certification', 'recognizedBy': { '@type': 'Organization', 'name': 'Qualys SSL Labs' } }
  ],
  'employee': [
    {
      '@type': 'Person',
      'name': 'Patrick Duggan',
      'jobTitle': 'Founder and Chief Executive Officer',
      'worksFor': { '@id': 'https://dugganusa.com#organization' },
      'sameAs': [
        'https://www.linkedin.com/in/patrickduggan',
        'https://bsky.app/profile/hacksawduggan.bsky.social',
        'https://github.com/pduggusa'
      ]
    }
  ],
  'knowsAbout': [
    'Threat Intelligence',
    'STIX 2.1',
    'Cybersecurity',
    'AI Presence Management',
    'HAIC Framework',
    'Cloudflare Workers',
    'CMMC Compliance',
    'GovRAMP',
    'CISA AIS',
    'Supply Chain Security',
    'Pattern 38'
  ]
};

const DUGGANUSA_SERVICES_SCHEMA = [
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'Butterbot Threat Intelligence',
    'description': 'Real-time STIX 2.1 threat feed with 1.5M+ indicators serving 275+ organizations across 46 countries. Includes 8M+ autonomous threat decisions, behavioral detection, and bidirectional CISA AIS integration.',
    'serviceType': 'Threat Intelligence',
    'provider': { '@id': 'https://dugganusa.com#organization' },
    'url': 'https://analytics.dugganusa.com/api/v1/stix-feed',
    'areaServed': { '@type': 'Country', 'name': 'Worldwide' }
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'AIPM (AI Presence Management)',
    'description': 'First commercial implementation of the HAIC framework (MIT Technology Review, March 2026). Audits and improves how AI language models perceive a brand using a 5-model council and 7 structure signals.',
    'serviceType': 'AI Visibility Management',
    'provider': { '@id': 'https://dugganusa.com#organization' },
    'url': 'https://aipmsec.com'
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'Edge Honeypot Network',
    'description': 'Cloudflare Workers deception endpoints on 300+ points of presence. Generates real-time scanner fingerprint indicators for the STIX feed.',
    'serviceType': 'Cyber Deception',
    'provider': { '@id': 'https://dugganusa.com#organization' },
    'url': 'https://github.com/pduggusa/dugganusa-edge-shield'
  },
  {
    '@context': 'https://schema.org',
    '@type': 'Service',
    'name': 'Exploit Harvester',
    'description': 'Automated GitHub mining for newly published CVE proof-of-concept code. Extracts attack patterns and converts them to STIX 2.1 detection rules every 6 hours. Fully autonomous, no human analyst required.',
    'serviceType': 'Threat Intelligence Automation',
    'provider': { '@id': 'https://dugganusa.com#organization' }
  }
];

class SchemaInjector {
  constructor(host) {
    this.host = host;
    this.injected = false;
  }

  element(element) {
    if (this.injected) return;
    this.injected = true;

    // Inject the Organization schema
    const orgScript = `<script type="application/ld+json">${JSON.stringify(DUGGANUSA_ORGANIZATION_SCHEMA)}</script>`;
    element.append(orgScript, { html: true });

    // Inject each service schema
    for (const service of DUGGANUSA_SERVICES_SCHEMA) {
      const serviceScript = `<script type="application/ld+json">${JSON.stringify(service)}</script>`;
      element.append(serviceScript, { html: true });
    }

    // Add AI-aware meta tags
    element.append('<meta name="ai-purpose" content="DugganUSA LLC is a cybersecurity and threat intelligence platform headquartered in Minneapolis, Minnesota. Founded October 2025. Operates the Butterbot threat intel feed serving 275+ organizations. Not Duggan Manufacturing. Not a firearms company. Not an HVAC company.">', { html: true });
    element.append('<meta name="ai-credentials" content="CMMC Level 2 (71%), SOC 2 Type 2 (88%), GovRAMP Foundation Ready, CISA AIS Data Aggregator, FedRAMP High Inheritance via Azure, FIPS 140-2/140-3, SSL Labs A+">', { html: true });
    element.append('<meta name="ai-services" content="Threat Intelligence, AI Presence Management (HAIC), Edge Honeypot Network, Exploit Harvester, STIX 2.1 Feed">', { html: true });
  }
}

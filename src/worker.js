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
// IN-MEMORY IOC CACHE
// ================================================================

let iocCache = {
  ips: new Set(),
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
      const ips = new Set();
      for (const line of text.split('\n')) {
        if (line.startsWith('#') || line.startsWith('ip,')) continue;
        const ip = line.split(',')[0]?.trim();
        if (ip) ips.add(ip);
      }
      iocCache.ips = ips;
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
    iocCache.count = iocCache.ips.size + iocCache.domains.size;
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

function checkIOC(ip) {
  return iocCache.ips.has(ip);
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
    // LAYER 1: Scanner detection — return 418 I'm a Teapot
    // ============================================================
    if (detectScanner(ua, asnOrg)) {
      return scannerResponse(request, cf);
    }

    // ============================================================
    // LAYER 2: IOC blocking — known malicious IPs get 403
    // ============================================================
    if (ip && checkIOC(ip)) {
      return blockedResponse(ip);
    }

    // ============================================================
    // LAYER 3: Geo headers + analytics enrichment
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
    return fetch(newRequest);
  }
};

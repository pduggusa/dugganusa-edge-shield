/**
 * Host Shield — Express middleware companion to Edge Shield.
 *
 * Edge Shield filters at the Cloudflare layer. If an attacker discovers your
 * origin's real FQDN (Azure Container Apps, AWS App Runner, Cloud Run, raw
 * VM IP) and connects directly, every CF-tier defense is bypassed — including
 * Edge Shield itself.
 *
 * This is the CF-Hero (https://github.com/musana/CF-Hero) class of attack.
 * Tools like CF-Hero use SecurityTrails / ZoomEye / Shodan / Censys / DNS
 * history to discover the origin behind Cloudflare, then validate the
 * candidate IP by HTTP title comparison.
 *
 * The defense: every request to your origin app must arrive with a Host
 * header your app expects. Off-list hosts (the Azure FQDN, the raw IP) get
 * 403 immediately, before any downstream middleware runs. Cloudflare-routed
 * traffic still works because Cloudflare forwards the Host header from the
 * client URL (e.g. analytics.example.com), not the origin's internal FQDN.
 *
 * Deploy-verification note: when curling a revision-pinned FQDN directly
 * (during deploys), pass `-H "Host: yourdomain.com"` so the SNI hits the
 * revision URL while the HTTP Host header passes the shield.
 *
 * Usage:
 *   const hostShield = require('./host-shield');
 *   app.use(hostShield.middleware);  // BEFORE everything else
 *
 * Config via env:
 *   HOST_SHIELD_HOSTS    comma-separated allowlist (overrides defaults)
 *   HOST_SHIELD_DISABLED set to '1' for emergency rollback without redeploy
 */

const DEFAULT_HOSTS = [
  // Override this list for your deployment via HOST_SHIELD_HOSTS env var
  'yourdomain.com',
  'www.yourdomain.com',
];

const INTERNAL_PATTERNS = [
  /^localhost(:\d+)?$/i,
  /^127\.0\.0\.1(:\d+)?$/,
  /^\[?::1\]?(:\d+)?$/,
  /^0\.0\.0\.0(:\d+)?$/,
];

const allowedHosts = (process.env.HOST_SHIELD_HOSTS || '').trim()
  ? new Set(process.env.HOST_SHIELD_HOSTS.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean))
  : new Set(DEFAULT_HOSTS.map((h) => h.toLowerCase()));

const SHIELD_DISABLED = process.env.HOST_SHIELD_DISABLED === '1';

const stats = { allowed: 0, rejected: 0, recentRejections: [] };

function isInternal(host) {
  if (!host) return true; // empty Host = liveness probe / local-dev
  return INTERNAL_PATTERNS.some((p) => p.test(host));
}

function shieldMiddleware(req, res, next) {
  if (SHIELD_DISABLED) {
    stats.allowed++;
    return next();
  }
  const rawHost = (req.headers.host || '').toLowerCase();
  const host = rawHost.split(',')[0].trim();

  if (isInternal(host) || allowedHosts.has(host)) {
    stats.allowed++;
    return next();
  }

  stats.rejected++;
  const rec = {
    timestamp: new Date().toISOString(),
    host: host.slice(0, 120),
    ip: req.ip || req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || 'unknown',
    path: (req.path || '').slice(0, 200),
    ua: (req.headers['user-agent'] || '').slice(0, 200),
  };
  stats.recentRejections.push(rec);
  if (stats.recentRejections.length > 100) stats.recentRejections.shift();

  console.warn(`[host-shield] REJECT host=${rec.host} ip=${rec.ip} path=${rec.path} ua=${rec.ua.slice(0, 60)}`);

  return res.status(403).json({
    error: 'forbidden',
    message: 'request rejected at edge',
  });
}

function getStats() {
  return {
    allowed: stats.allowed,
    rejected: stats.rejected,
    rejection_rate: stats.allowed + stats.rejected > 0
      ? +(stats.rejected / (stats.allowed + stats.rejected) * 100).toFixed(2)
      : 0,
    recent_rejections: stats.recentRejections.slice(-20),
    allowlist: Array.from(allowedHosts),
    shield_disabled: SHIELD_DISABLED,
  };
}

module.exports = { middleware: shieldMiddleware, getStats };

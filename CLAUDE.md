# CLAUDE.md — DugganUSA Edge Shield

## What This Is

A Cloudflare Worker that protects websites using DugganUSA's threat intelligence feed. It deploys to the customer's Cloudflare account and calls our API for IOC data.

## Prerequisites

Before deploying, the user needs:

1. **Cloudflare account** (free tier works) with at least one domain
2. **Node.js 18+** installed locally
3. **DugganUSA API key** — register at https://analytics.dugganusa.com/stix/register
   - Product must be `stix` or `both` (not `epstein` only)
   - Free tier: 1 STIX request/day, 48h delayed data
   - Paid tiers: real-time data, faster cache refresh
4. **Cloudflare API token** (for `wrangler deploy`) with permissions:
   - Workers Scripts: Edit
   - Workers Routes: Edit
   - Account Settings: Read
   - User Details: Read

## Deployment Steps

```bash
# Step 1: Clone the repo
git clone https://github.com/pduggusa/dugganusa-edge-shield.git
cd dugganusa-edge-shield

# Step 2: Install wrangler (if not installed)
npm install

# Step 3: Authenticate with Cloudflare
npx wrangler login
# OR set token: export CLOUDFLARE_API_TOKEN=your_cf_token

# Step 4: Set DugganUSA API key as a secret
npx wrangler secret put DUGGANUSA_API_KEY
# Paste your key when prompted (starts with dugusa_)

# Step 5: Deploy
npx wrangler deploy

# Step 6: Add route in Cloudflare dashboard
# Zone → Workers Routes → Add Route
# Pattern: *yourdomain.com/*
# Worker: dugganusa-edge-shield
```

## Verification

After deployment, verify it's working:

```bash
# Check headers on your site
curl -sD- https://yourdomain.com 2>&1 | grep -i "x-dugganusa\|x-cf-city"

# Expected:
# X-DugganUSA-Shield: active
# X-DugganUSA-IOCs: 47832
# X-CF-City: YourCity
# X-CF-Region: YourState

# Test scanner detection
curl -A "nuclei/2.0" https://yourdomain.com
# Expected: 418 JSON response with "We see you"
```

## File Structure

```
dugganusa-edge-shield/
├── src/
│   └── worker.js          # The Worker — single file, no dependencies
├── wrangler.toml           # Cloudflare Worker config
├── package.json            # npm metadata + wrangler dev dependency
├── README.md               # Full documentation
├── TROUBLESHOOTING.md      # Common issues + fixes
├── CLAUDE.md               # This file — deployment instructions for Claude
└── LICENSE                  # MIT
```

## Key Design Decisions

- **Single file** — no build step, no bundling, no frameworks
- **Zero runtime dependencies** — only Cloudflare Worker APIs
- **IOC cache in Worker memory** — refreshed hourly, no external database
- **SASE proxy safelist** — Zscaler/Netskope/PANW users are CUSTOMERS, not threats
- **Scanner list is UA + ASN org based** — not IP-based (IPs rotate)
- **418 I'm a Teapot** for scanners — because they deserve it

## Important: SASE Proxy Handling

Enterprise users often browse through SASE/SSE proxies (Zscaler, Netskope, Palo Alto Prisma). These proxies share ASN organizations with the security vendor's name. A request from "Zscaler Inc." is NOT Zscaler scanning — it's a corporate employee behind Zscaler's cloud proxy.

The Worker explicitly safelists SASE proxy organizations and NEVER flags them as scanners. If a customer reports false positives from a SASE proxy:

1. Check `SASE_PROXY_ORGS` in `src/worker.js`
2. Add the missing org name
3. Redeploy

## Updating IOC Lists

The Worker auto-refreshes from the DugganUSA STIX feed API:
- Pulls `ips.csv` and `domains.csv` with 7-day lookback, 80% minimum confidence
- Caches in Worker memory (survives within a single isolate lifetime)
- Refresh interval: 1 hour (configurable via `IOC_REFRESH_INTERVAL`)

Customers on higher tiers get fresher data because the API returns real-time vs 48h-delayed based on their key's tier.

## Revenue Model

- The Worker is free and open source (MIT)
- The intelligence requires a DugganUSA API key
- Each IOC cache refresh = 2 API calls (ips.csv + domains.csv)
- Tier determines freshness, refresh rate, and IOC depth
- Free tier: functional but 48h stale
- Paid tiers: real-time protection

## Support

- Issues: https://github.com/pduggusa/dugganusa-edge-shield/issues
- Email: butterbot@dugganusa.com
- API docs: https://analytics.dugganusa.com/api/v1/stix-feed/help

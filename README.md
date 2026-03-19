# DugganUSA Edge Shield

**1M+ IOCs at the Cloudflare edge. Deploy in 30 seconds.**

Edge Shield is a Cloudflare Worker that protects your site using DugganUSA's threat intelligence feed. It blocks known malicious IPs, detects scanners, and enriches every request with city-level geo analytics — all at the edge, before traffic hits your origin.

## What It Does

| Layer | Action | Latency |
|-------|--------|---------|
| **Scanner Detection** | Returns 418 to known scanners (LeakIX, Censys, Shodan, Nuclei, etc.) | 0ms |
| **IOC Blocking** | Blocks IPs from 1M+ indicator feed | 0ms (cached) |
| **Geo Enrichment** | Adds city, region, ASN org, lat/lon headers to every request | 0ms |

Your origin server receives enriched headers:

```
X-CF-City: Minneapolis
X-CF-Region: Minnesota
X-CF-ASN-Org: Comcast Cable Communications
X-DugganUSA-Shield: active
X-DugganUSA-IOCs: 47832
```

Malicious IPs and scanners never reach your server.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/pduggusa/dugganusa-edge-shield.git
cd dugganusa-edge-shield

# 2. Get your API key (free tier: 500 queries/day)
#    https://analytics.dugganusa.com/stix/register

# 3. Set your API key
npx wrangler secret put DUGGANUSA_API_KEY

# 4. Deploy
npx wrangler deploy
```

Then add a route in your Cloudflare dashboard:
- **Zone** → Workers Routes → Add Route
- **Pattern**: `*yourdomain.com/*`
- **Worker**: `dugganusa-edge-shield`

That's it. Your site is now protected by 1M+ IOCs.

## How It Works

```
Visitor → Cloudflare Edge → Edge Shield Worker → Your Origin
                              │
                              ├─ Scanner? → 418 "We see you."
                              ├─ Known IOC? → 403 Blocked
                              └─ Clean? → Pass through with geo headers
```

The Worker caches IOCs from the DugganUSA STIX feed in memory and refreshes every hour. Scanner detection is instant — no API call needed. Geo data comes from Cloudflare's own network, zero external lookups.

## What Scanners See

```json
{
  "message": "We see you. We indexed you.",
  "your_ip": "68.183.9.16",
  "your_asn": "AS14061",
  "your_org": "DigitalOcean, LLC",
  "your_city": "Amsterdam",
  "protected_by": "DugganUSA Edge Shield",
  "score": "You scored 0/95 on our scanner detection. Congratulations."
}
```

HTTP 418 I'm a Teapot. Because they deserve it.

## Pricing

Edge Shield requires a DugganUSA API key. The Worker is free. The intelligence behind it is tiered:

| Tier | Price | IOC Refresh | Support |
|------|-------|-------------|---------|
| Free | $0/mo | Every 24h, 48h delayed data | Community |
| Starter | $45/mo | Every 1h, real-time | Email |
| Professional | $495/mo | Every 15m, real-time + cross-index | Priority |
| Enterprise | $2,495/mo | Every 5m, real-time + full suite | Dedicated |

[Get your API key →](https://analytics.dugganusa.com/stix/register)

## Configuration

### wrangler.toml

```toml
name = "dugganusa-edge-shield"
main = "src/worker.js"
compatibility_date = "2026-03-19"
```

### Secrets

```bash
npx wrangler secret put DUGGANUSA_API_KEY
# Paste your API key when prompted
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DUGGANUSA_API_KEY` | Yes | Your API key from registration |

## Reading Geo Headers

In your origin server (Node.js example):

```javascript
app.use((req, res, next) => {
  const city = req.headers['x-cf-city'];
  const region = req.headers['x-cf-region'];
  const org = req.headers['x-cf-asn-org'];
  const shielded = req.headers['x-dugganusa-shield'] === 'active';

  console.log(`${city}, ${region} | ${org} | Shield: ${shielded}`);
  next();
});
```

## What We See

When you use Edge Shield, we see:
- API key usage (query count per day)
- Which IOC lists you pull (IPs, domains)

We do NOT see:
- Your visitors
- Your traffic
- Your origin server
- Anything about your site

The Worker runs on YOUR Cloudflare account. We provide the intelligence. You control the deployment.

## Built By

**DugganUSA LLC** — Minneapolis, MN
Cybersecurity threat intelligence. 1M+ IOCs. 42 indexes. Built with Claude.

- [STIX Feed](https://analytics.dugganusa.com/stix/pricing)
- [AI Presence Audit](https://aipmsec.com)
- [Blog](https://www.dugganusa.com)

## License

MIT

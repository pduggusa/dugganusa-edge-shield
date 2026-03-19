# Troubleshooting Guide

## Common Issues

### "My corporate users are being blocked"

**Symptom**: Employees at large companies can't access your site after deploying Edge Shield.

**Cause**: Many enterprises route traffic through SASE/SSE proxies (Zscaler, Netskope, Palo Alto Prisma, Cisco Umbrella). These proxies share IP addresses across thousands of customers. A request from "Zscaler" isn't Zscaler — it's an employee at a Fortune 500 company behind Zscaler's cloud proxy.

**Solution**: Edge Shield already safelists known SASE proxy ASN organizations. If you're seeing false positives:

1. Check the `X-CF-ASN-Org` header on the blocked request
2. If it's a SASE proxy, add it to the `SASE_PROXY_ORGS` list in `src/worker.js`
3. Redeploy: `npx wrangler deploy`

**Currently safelisted SASE proxies:**
- Zscaler
- Netskope
- Palo Alto / Prisma
- Cloudflare WARP
- Cisco Umbrella
- Forcepoint
- iboss
- Menlo Security
- Skyhigh Security
- Cato Networks
- Versa Networks

### "I'm getting 418 responses on my own site"

**Symptom**: Your monitoring tools or CI/CD pipelines get the "We see you" 418 response.

**Cause**: Your monitoring tool's User-Agent matches a scanner pattern (e.g., `curl`, `python-requests`, or a custom UA containing words like `scan` or `probe`).

**Solution**: Edge Shield does NOT flag `curl` or `python-requests` — only known attack scanners. If your tool uses a UA that matches the scanner list:

1. Change the User-Agent in your monitoring tool to something descriptive (e.g., `MyCompany-Monitor/1.0`)
2. Or add your tool's UA to an allowlist in the Worker

### "IOC cache shows 0"

**Symptom**: The `X-DugganUSA-IOCs` header shows `0`.

**Cause**:
- API key not set or invalid
- API key doesn't have STIX feed access (requires `stix` or `both` product type)
- Free tier has 1 request/day — cache may not have refreshed yet
- Network error reaching DugganUSA API

**Solution**:
1. Verify your key: `curl -H "Authorization: Bearer YOUR_KEY" "https://analytics.dugganusa.com/api/v1/api-keys/usage"`
2. Check your key has STIX access: product should be `stix` or `both`
3. If free tier, the cache refreshes once per day. Upgrade for faster refresh.
4. Check Worker logs: `npx wrangler tail`

### "Geo headers are empty"

**Symptom**: `X-CF-City` and other geo headers are empty or missing.

**Cause**: Cloudflare's geo data depends on their IP database. Some IPs (especially cloud providers, VPNs, Tor) may not resolve to a city.

**Solution**: This is expected for some traffic. The `X-CF-ASN-Org` header is more reliable than city for identifying corporate visitors. Cloud provider IPs (AWS, Azure, GCP) will show the org but typically not a meaningful city.

### "Scanner detection missed a scanner"

**Symptom**: A known scanner got through to your origin.

**Cause**: The scanner used a clean User-Agent and doesn't match any known ASN org patterns.

**Solution**:
1. Check your origin logs for the scanner's IP and User-Agent
2. Report it: email `butterbot@dugganusa.com` with the IP and UA
3. The scanner list is updated regularly — `git pull` and redeploy

### "I want to block a specific country"

**Solution**: Add a geo-fence to the Worker. In `src/worker.js`, add before the origin fetch:

```javascript
// Block specific countries
const blockedCountries = ['RU', 'CN', 'KP'];
if (blockedCountries.includes(cf.country)) {
  return new Response('Access denied', { status: 403 });
}
```

Redeploy: `npx wrangler deploy`

### "How do I see who's visiting?"

**Solution**: The Worker adds headers but doesn't store data. To build analytics:

1. Read the `X-CF-City`, `X-CF-Region`, `X-CF-ASN-Org` headers in your origin
2. Log them to your database or analytics platform
3. Or use the `X-DugganUSA-Shield: active` header to confirm Edge Shield is running

For full visitor analytics with city-level data, see the DugganUSA analytics dashboard.

### "Worker deployment fails"

**Symptom**: `npx wrangler deploy` returns an error.

**Common causes and fixes:**

| Error | Fix |
|-------|-----|
| `Authentication error` | Run `npx wrangler login` or set `CLOUDFLARE_API_TOKEN` env var |
| `Missing API token` | `export CLOUDFLARE_API_TOKEN=your_token` |
| `Script too large` | Edge Shield is <5KB — this shouldn't happen. Check for accidental file inclusions. |
| `Route already exists` | A route for this pattern already exists. Delete the old route in CF dashboard first. |

### "How do I test locally?"

```bash
npx wrangler dev
# Opens local dev server at http://localhost:8787
# Geo data won't be available locally — Cloudflare edge only
```

## Getting Help

- **Email**: butterbot@dugganusa.com
- **GitHub Issues**: https://github.com/pduggusa/dugganusa-edge-shield/issues
- **API Docs**: https://analytics.dugganusa.com/api/v1/stix-feed/help
- **Register**: https://analytics.dugganusa.com/stix/register

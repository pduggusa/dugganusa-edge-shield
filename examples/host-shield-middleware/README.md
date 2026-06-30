# Host Shield — Origin-Side Companion To Edge Shield

Edge Shield filters at the Cloudflare layer. **Host Shield filters at your origin app**, defeating the [CF-Hero](https://github.com/musana/CF-Hero) class of attack where adversaries discover your origin's real FQDN and connect directly, bypassing every CF-tier defense.

## The bypass this fixes

If your site is `analytics.example.com` behind Cloudflare and your origin is on Azure Container Apps, the origin's real FQDN looks something like:

```
analytics-dashboard-wp.<random>.<region>.azurecontainerapps.io
```

That FQDN is **publicly resolvable** because Azure publishes it via DNS and cert-transparency. Tools like CF-Hero pull it from SecurityTrails / Shodan / Censys / ZoomEye and connect directly to your origin IP. None of the following defenses apply when an attacker arrives this way:

- Cloudflare WAF
- Edge Shield (this Worker)
- Cloudflare rate-limiting
- Cloudflare Bot Management
- Cloudflare Turnstile / managed challenge

Equivalent classes exist for AWS App Runner (`*.awsapprunner.com`), Google Cloud Run (`*.run.app`), Fly.io (`*.fly.dev`), Heroku (`*.herokuapp.com`), and most managed-container platforms.

## The fix

Reject any request whose HTTP `Host` header isn't on your allowlist. Three lines of middleware. The shield runs BEFORE every other layer so off-list traffic burns zero downstream compute.

## Install

Copy `express.js` into your app, edit the `DEFAULT_HOSTS` array (or set `HOST_SHIELD_HOSTS` env var) to your canonical hostnames, and wire it as the **first** `app.use()` call.

```js
const hostShield = require('./host-shield');
app.use(hostShield.middleware);  // BEFORE session, body parser, anything
```

The shield allows by default:

- Each hostname in your allowlist (case-insensitive)
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0` (internal probes + local dev)
- Empty `Host` header (some liveness probes omit it)

Everything else gets HTTP 403 with a non-revealing body, and the rejected host + IP + path + UA is logged to stderr.

## Deploy verification

If you verify deploys by hitting a revision-pinned FQDN directly (Azure revision URLs, App Runner versions, etc.), pass the canonical Host header explicitly:

```bash
curl -H "Host: analytics.example.com" \
  "https://analytics-dashboard-wp--0000099.example.azurecontainerapps.io/health"
```

The TLS layer uses the URL hostname for SNI (so the cert validates), and the HTTP layer uses the forged Host header (so the shield allows).

## Emergency rollback

Set `HOST_SHIELD_DISABLED=1` in your environment to disable the shield without a redeploy. Useful if a new hostname needs to be added quickly and the rollout window is tight.

## Monitor

Wire the `getStats()` function to your metrics endpoint to track:

- `allowed` / `rejected` counts
- `rejection_rate` (percentage)
- `recent_rejections` (last 20, with timestamp, host, IP, path, UA)
- `allowlist` (current effective list)

Spikes in rejections that aren't from your own deploy verifications are CF-Hero attempts in the wild. Worth a Pattern 55 trigger.

## Ports for other frameworks

- **Fastify**: same shape, just register as `fastify.addHook('onRequest', ...)`
- **Koa**: register before any other middleware in the chain
- **Go (net/http)**: wrap with `http.Handler` that checks `r.Host` against the allowlist
- **Python (FastAPI)**: add as a dependency on the app instance via `app.add_middleware(...)`

The primitive ports trivially. The point is to run it BEFORE the request reaches anything that costs cycles.

## Related

- [CF-Hero](https://github.com/musana/CF-Hero) — the attack tool this defends against
- [Edge Shield](../../README.md) — the Cloudflare Worker that filters at the CF tier
- DugganUSA Pattern 55 (forthcoming): Edge-Protection-Bypass-via-OSINT — the detector

# CLAUDE.md — DugganUSA Edge Shield

A Cloudflare Worker that protects a website with DugganUSA's threat-intelligence
feed. It runs on the **customer's own** Cloudflare account and pulls indicators from
our API. Single file (`src/worker.js`), no build step, no runtime dependencies.

When someone opens this repo and asks to **set it up, install it, deploy it, or
protect their site**, follow the onboarding playbook below. DugganUSA onboards the
same way: `wrangler.toml` in this repo is our own deployment (customer #1).

---

## Onboarding playbook

### Rules for Claude while running it

- **One question at a time.** Give a recommended default with every question, and
  say why in one sentence. Accept "default" or "yes" as taking it.
- **Never ask for, accept, echo or write an API key or token in chat or a file.**
  Secrets go in with `wrangler secret put`, which prompts the user directly. If the
  user pastes a key anyway, tell them to rotate it.
- **Never deploy without an explicit "yes, deploy"** after showing the dry run.
- **Never edit or deploy `wrangler.toml`.** It is DugganUSA's deployment: its routes
  are our zones and its `account_id` is ours. The customer's config is
  `wrangler.local.toml` (gitignored), generated from `wrangler.example.toml`. Every
  wrangler command in this playbook takes `-c wrangler.local.toml`.
- **Proof is a live probe, not a config file.** Don't call a step done until its
  check passes.
- Keep a running summary of their answers. Show it before generating the config.

### Step 1 — Prerequisites

Run each check yourself and report the result. Stop and help fix any failure.

1. `node --version` (18 or newer).
2. `npx wrangler --version`. If it's missing, run `npm install` in the repo.
3. `npx wrangler whoami`. If they're not logged in, have them run
   `npx wrangler login` (it opens a browser). Note the **account ID**. If they have
   more than one account, ask which one to use.
4. Their zone(s) must be **on Cloudflare** with the website's DNS records
   **proxied (orange cloud)**. A grey-cloud (DNS-only) record bypasses Workers
   entirely. Ask them to confirm in the dashboard (DNS → Records → Proxy status), or
   check that `curl -sI https://<host>` returns `server: cloudflare`.

### Step 2 — Inventory hosts and classify each one

Ask: *"Which hostnames do you want me to look at?"* (for example `www.example.com`,
`example.com`, `api.example.com`). Then classify each host, one at a time:

| Class | Meaning | What the config does |
|---|---|---|
| **PRODUCT** | A site or API you want protected | Catch-all route `host/*` |
| **SENSOR** | A honeypot, research box, log/telemetry collector or anything that must see raw traffic | **No route**, and listed in `SENSOR_HOSTS` |
| **SKIP** | Not on Cloudflare, not yours, or not now | Nothing |

Recommended default: PRODUCT for websites and APIs. Ask directly whether any host
exists to *observe* attackers. A shield in front of a sensor blinds it.

Also ask whether another Worker already has routes on these hosts (Workers → Routes
in the dashboard). **The most specific route wins**, so an existing
`www.example.com/api/*` route keeps running there even after we add `www.example.com/*`.

### Step 3 — Security preferences (one question each)

1. **Block or observe first?** Recommended: **observe for 7 days, then block.** In
   observe mode nothing is blocked. Every request the shield *would* have blocked is
   logged as `{"shield":"observe","would":...}` in Workers Logs, and the response
   carries `X-DugganUSA-Observed`. → `SHIELD_MODE`
2. **min_confidence (0-100).** Recommended: **80.** This is *their* dial. 80 is high
   precision (what DugganUSA runs at its own edge). 30 is broad: more coverage, more
   false positives. The free feed's CSVs default to 30 for SIEM users; the shield
   asks for 80 unless told otherwise. → `IOC_MIN_CONFIDENCE`
3. **Feed window.** Recommended: **7 days** (fresh infrastructure, small memory
   footprint). → `IOC_FEED_DAYS`
4. **Scanner 418.** Recommended: **on.** Shodan, Censys, LeakIX, Nuclei and similar
   get HTTP 418. SASE proxies (Zscaler, Netskope, Prisma...) are never treated as
   scanners, because they carry real employees. → `SCANNER_418`
5. **Honeypot canaries.** Recommended: **off to start.** They answer decoy paths
   (`/.env`, `/wp-login.php`, `/graphql`, `/webmail/`...) with fake content. Say
   both costs plainly: (a) a hit sends the visitor's IP, User-Agent, geo and request
   URL to DugganUSA, which is personal data under GDPR; (b) if any decoy path is a
   real route on their site, it will break. → `HONEYPOTS_ENABLED`. NetScaler decoys
   are a separate opt-in (`APPLIANCE_CANARIES`); never enable them on a host with a
   real NetScaler behind it.
6. **Rate limits.** Recommended: **100/min anonymous, 500/min with an API key.**
   Per IP, per isolate. `0` disables a tier. → `RL_ANON`, `RL_AUTH`
7. **Crawlers.** Not a question, a statement: verified search and AI crawlers
   (Googlebot, Bingbot, GPTBot, ClaudeBot and others) are always exempt, verified by
   Cloudflare's bot flag or forward-confirmed reverse DNS, never by User-Agent alone.
   If they want a crawler blocked, that belongs in a Cloudflare WAF rule (step 8).
8. **Feed-hit reporting.** Recommended: **yes**, after reading the contract out
   loud: when a feed indicator matches, the Worker sends DugganUSA **only** that
   indicator (the attacker's IP, which we published), the action (`blocked` or
   `observed`), a count and the Cloudflare ray ID of the matched request. Never the
   visitor's identity, their hostname, URL or any asset data. The report is
   authenticated with their API key, so we know which key sent it. One caveat: a
   match on a CIDR range reports the matching address, which we may never have
   listed individually. → `FEED_HIT_REPORTING`

### Step 4 — API key (secret, never in chat)

1. Send them to **https://analytics.dugganusa.com/stix/register** for a free key.
   The product must include the STIX feed (`stix` or `both`).
2. If `wrangler.local.toml` does not exist yet, copy `wrangler.example.toml` to it
   first (step 5 fills it in). The next command needs the file.
3. Have them run this themselves, and paste the key at wrangler's prompt, not here:
   `npx wrangler secret put DUGGANUSA_API_KEY -c wrangler.local.toml`
   (It creates the Worker if it doesn't exist yet. That's expected.)
4. Confirm with `npx wrangler secret list -c wrangler.local.toml`. It shows the name,
   never the value.

### Step 5 — Generate the config, dry run, confirm, deploy

1. Fill in `wrangler.local.toml` (copied from `wrangler.example.toml` in step 4):
   - `routes`: one `{ pattern = "<host>/*", zone_name = "<zone>" }` per **PRODUCT**
     host. No route for any SENSOR host.
   - `account_id` if they have more than one account.
   - every `[vars]` value from step 3. Put SENSOR hosts in `SENSOR_HOSTS`, and set
     `SCHEMA_INJECT_HOSTS = ""` (that record describes DugganUSA, not them).
2. Show them the generated file.
3. `npx wrangler deploy --dry-run -c wrangler.local.toml`. Show the bindings it
   prints, and list the routes from the file next to their classification. Check
   that no SENSOR host has a route.
4. Ask: *"Deploy these routes now?"* Deploy only on an explicit yes:
   `npx wrangler deploy -c wrangler.local.toml`

### Step 6 — Verify live

Run the probes. Config proves intent; only probes prove behavior.

```bash
scripts/verify.sh --product www.example.com,api.example.com \
                  --sensor honeypot.example.com \
                  --mode observe        # or block
```

It checks:
- **PRODUCT, block mode:** `curl -A "leakix/1.0"` returns **418** with
  `X-Powered-By: DugganUSA Edge Shield`.
- **PRODUCT, observe mode:** the same probe passes through with
  `X-DugganUSA-Observed: scanner`.
- **PRODUCT, both modes:** a normal browser User-Agent returns **200** (a redirect
  also passes).
- **SENSOR:** the scanner probe shows **no** shield header. (A 418 the sensor's
  own app sends is fine; the script tells the two apart.)

Then run `npx wrangler tail -c wrangler.local.toml` for a minute while they browse
the site. There must be **no `IOC refresh FAILED`** line. If there is, IOC blocking
is running on an empty cache: a 401 means a bad key, 403 or 429 means quota or edge
blocking, 5xx means the feed is having trouble (it retries every 10 minutes).

If a normal probe returns 403 with `X-Blocked-Reason: ioc-match`, **their own IP
matched the feed**, often through a CIDR. Don't wave it off. Re-run from another
network, then decide with them whether to raise `IOC_MIN_CONFIDENCE`.

### Step 7 — Going from observe to block

After about 7 days, have them search Workers Logs for `"shield":"observe"` and
group by `would`. Look at what it would have blocked: their own monitoring, partners
or customers among the IOC hits means raising `IOC_MIN_CONFIDENCE` first. When the
list looks like attackers, set `SHIELD_MODE = "block"`, dry run, confirm, deploy,
and run `scripts/verify.sh --mode block`.

### Step 8 — Rollback

Fastest first:
1. **Switch to observe:** set `SHIELD_MODE = "observe"` and deploy. Nothing is
   blocked, evidence keeps flowing.
2. **Roll back the code:** `npx wrangler rollback -c wrangler.local.toml` (to the
   previous version), or pick one from `npx wrangler deployments list`.
3. **Take it off a host:** delete that route from `wrangler.local.toml` and deploy,
   or remove it in the dashboard (Workers → Routes).
4. **Remove everything:** `npx wrangler delete -c wrangler.local.toml`.

### Step 9 (optional) — Cloudflare WAF IP list

Customers on plans with IP Lists can also load the feed into a WAF custom rule.
Explain the trade-off:
- **WAF rules run BEFORE Workers.** A request the WAF blocks never reaches the
  shield, so it never shows up in the shield's logs, observe output or feed-hit
  reports. The two layers don't see each other's blocks.
- The WAF path is list-only. The shield adds scanner detection, honeypots, rate
  limits and CIDR matching on top.
- **Vendor bot scores** (Cloudflare Bot Management, Bot Fight Mode and similar):
  our stance is **observe and compare, not enforce.** A bot score is someone else's
  opinion, scored for their purposes. Treat it as a comparator: record it next to
  the shield's own decision (honeypot catches already carry `bot_score`) and see
  where the two disagree. Don't let it block on its own. Evidence is never
  discarded, and another vendor's verdict doesn't get to make ours. If they do turn
  on a bot-blocking feature, remember it also runs before the Worker.

---

## Lessons we learned the hard way

- **Never shield a sensor.** A catch-all route went onto a host that exists to
  watch attackers. The shield 418'd and 403'd exactly the traffic the sensor was
  there to record. Routing is the first guard, `SENSOR_HOSTS` is the second.
- **Cloudflare Workers egress (`2a06:98c0::/29`) is SHARED** by every Worker on
  Cloudflare. Never denylist it anywhere, not in a WAF rule, origin firewall or IP
  list. It cuts off every Worker, including your own. That silently disabled our own
  IOC blocking for three months: the shield's feed refresh was refused and it ran on
  an empty cache.
- **Send a User-Agent on every subrequest.** A UA-less request from the shared
  Workers egress looks like a scraper and trips Browser Integrity Check. The shield
  sends `DugganUSA-Edge-Shield/...` on every call it makes.
- **One feed pull per data center, never per isolate.** Every isolate in every
  data center pulling its own feed is a thundering herd against the API (75 pulls
  in 5 minutes once refresh started working again). The shield caches the feed in
  the data-center Cache API for 10 minutes and de-duplicates refreshes per isolate.
- **Most-specific route wins.** Before adding a catch-all, list the existing
  routes on that host. A narrower route belonging to another Worker keeps that path.
- **Verify with live probes, not config.** A route in a file is not a route at the
  edge. An API key in a secret is not a working feed refresh. `scripts/verify.sh`
  and `wrangler tail` are the proof.

---

## Configuration reference

All vars are optional. Absent means the default, which matches the Worker's
behavior before vars existed. Unparseable means the default, plus a `config:`
warning in Workers Logs. Full comments live in `wrangler.example.toml`.

| Var | Default | Values |
|---|---|---|
| `SHIELD_MODE` | `block` | `block`, `observe` (`log-only` is an alias) |
| `IOC_BLOCKING` | `true` | `true` / `false` (false also stops feed pulls) |
| `IOC_MIN_CONFIDENCE` | `80` | 0-100 |
| `IOC_FEED_DAYS` | `7` | 1-90 |
| `IOC_REFRESH_MINUTES` | `60` | 5-1440 (the data-center cache floors origin pulls at 10 min) |
| `SCANNER_418` | `true` | `true` / `false` |
| `RL_ANON` | `100` | requests/min per IP, `0` disables |
| `RL_AUTH` | `500` | requests/min per IP with a key, `0` disables |
| `HONEYPOTS_ENABLED` | `true` | `true` / `false` |
| `APPLIANCE_CANARIES` | unset | unset = DugganUSA zones only; `true` / `false` |
| `FEED_HIT_REPORTING` | `true` | `true` / `false` |
| `SCHEMA_INJECT_HOSTS` | DugganUSA's hosts | comma list; `""` = none |
| `SENSOR_HOSTS` | none | comma list of hosts or `*.example.com` |

Observe mode covers scanner 418, IOC 403 and rate-limit 429. Honeypots are
deception rather than blocking, so they keep their own switch.

## Design decisions (for anyone changing the code)

- **Single file, zero dependencies.** No build step, no bundling.
- **IOC cache in Worker memory**, refreshed from the data-center cache, which is
  refreshed from the API at most every 10 minutes.
- **SASE proxy safelist.** Zscaler/Netskope/Prisma traffic is employees, not
  scanners. A false positive from one means adding the org to `SASE_PROXY_ORGS`.
- **Scanner detection is UA + ASN-org based**, not IP based (IPs rotate).
- **Verified crawlers fail closed.** A failed verification means "ordinary
  traffic", not "blocked", so failing closed costs a real crawler nothing.
- **Tests extract the shipped code** rather than reimplementing it:
  `node test-config-observe.mjs`, `node test-appliance-canaries.mjs`,
  `node test-crawler-verify.mjs` (the last one uses real DNS).

## Support

- Issues: https://github.com/pduggusa/dugganusa-edge-shield/issues
- Email: butterbot@dugganusa.com
- API docs: https://analytics.dugganusa.com/api/v1/stix-feed/help

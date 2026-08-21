<div align="center">

# DugganUSA Edge Shield

### Enterprise threat intelligence at the Cloudflare edge. Free. Open source.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![IOCs](https://img.shields.io/badge/Distinct%20IOCs-653%2C342-10b981)](https://analytics.dugganusa.com/api/v1/stix-feed)
[![Reach](https://img.shields.io/badge/Reach%20vs%20List--only-30x-818cf8)](https://analytics.dugganusa.com/stix/pricing)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-4f46e5)](https://analytics.dugganusa.com/api/v1/stix-feed)

**Compliance & Posture:**

[![CMMC L2](https://img.shields.io/badge/CMMC%20L2-71%25-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance)
[![SOC 2](https://img.shields.io/badge/SOC%202%20Type%202-81%25-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance)
[![GovRAMP](https://img.shields.io/badge/GovRAMP-Foundation%20Ready-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance/govramp)
[![CISA AIS](https://img.shields.io/badge/CISA%20AIS-Data%20Aggregator-4ade80)](https://www.cisa.gov/ais)
[![SSL Labs](https://img.shields.io/badge/SSL%20Labs-A%2B-4ade80)](https://www.ssllabs.com/ssltest/analyze.html?d=analytics.dugganusa.com)
[![Headers](https://img.shields.io/badge/Security%20Headers-7%2F7-4ade80)](https://securityheaders.com/?q=analytics.dugganusa.com)
[![DNSSEC](https://img.shields.io/badge/DNSSEC-Enabled-4ade80)](https://dnssec-analyzer.verisignlabs.com/dugganusa.com)
[![Cosign](https://img.shields.io/badge/Container%20Images-Cosign%20Signed-4ade80)](https://github.com/sigstore/cosign)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-4ade80)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance/evidence/sbom)

**653,342 distinct IOCs. 30x the reach of list-only defence. Deploy in 30 seconds.**

Behavioural blocking at the edge, not just a list. Over 16 measured days the shield stopped 1,638 distinct attacking hosts where a blocklist working alone would have stopped 55 — and 81.3% of the hosts that actually attacked were on no blocklist anywhere.

[Get Your Free API Key](https://analytics.dugganusa.com/stix/register) &nbsp;&bull;&nbsp; [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed) &nbsp;&bull;&nbsp; [Blog](https://www.dugganusa.com) &nbsp;&bull;&nbsp; [AIPM](https://aipmsec.com)

---

</div>

## What's New in 2.3.0

**This Worker now closes the loop on feed liveness.** When one of our published indicators blocks real traffic at your edge, the Worker reports the hit back to the **feed-efficacy** axis — privacy-preserving (it sends only the indicator we already published, never your visitors or assets). That turns "we have 653,342 distinct IOCs" into "here's proof they fire in the wild."

Don't take our word for the feed — **verify it yourself.** The DugganUSA platform serves **four live, no-auth, durable validation endpoints** (durable across our deploys; each response carries a `source` field of `live`, `durable`, or `baseline`):

- **Novelty** — [`/api/v1/feed-uniqueness`](https://analytics.dugganusa.com/api/v1/feed-uniqueness): ~75%+ of our independently-sourced IOCs are **not** in ThreatFox. Most of what we publish, ThreatFox doesn't have.
- **Timeliness** — [`/api/v1/kev-lead`](https://analytics.dugganusa.com/api/v1/kev-lead): a live ledger of how far ahead of CISA KEV we flagged each exploited CVE — positive leads, same-day, and no-receipt all shown honestly, with receipts.
- **Accuracy** — [`/api/v1/spamhaus-validation`](https://analytics.dugganusa.com/api/v1/spamhaus-validation): Spamhaus independently corroborates our first-hand contributions.
- **Liveness** — [`/api/v1/feed-efficacy`](https://analytics.dugganusa.com/api/v1/feed-efficacy): opt-in consumer reports of when our indicators actually fire on real traffic — proof the feed is operationally live, not just large. **This Worker is a reporter for that axis.**

Feed depth also grew with **OSV malicious-package feeds (npm + PyPI)** and **daily GitHub Hunt detections**, alongside 15 external feed sources.

> **Note:** the STIX feed is **API-key-enforced**. The Worker already requires a registered key (`wrangler secret put DUGGANUSA_API_KEY`); anonymous pulls return `401`. The free tier is a **free registered key** — [register here](https://analytics.dugganusa.com/stix/register).

---

## What It Does

```
Visitor → Cloudflare Edge → Edge Shield → Your Origin
                              │
                              ├── Scanner?  → 418 "We see you. We indexed you."
                              ├── Known IOC? → 403 Blocked
                              └── Clean?     → ✅ Pass with geo headers
```

| Layer | What Happens | Latency Added |
|:-----:|:-------------|:-------------:|
| **Scanner Detection** | Returns 418 to Shodan, Censys, LeakIX, Nuclei, ZMap | **0ms** |
| **IOC Blocking** | Blocks IPs from a 653,342-indicator feed | **0ms** (cached) |
| **Geo Enrichment** | Adds city, region, ASN, lat/lon headers to every request | **0ms** |

Zero external lookups. Zero latency added. The intelligence lives in Worker memory.

---

## Quick Start

```bash
git clone https://github.com/pduggusa/dugganusa-edge-shield.git
cd dugganusa-edge-shield
npx wrangler secret put DUGGANUSA_API_KEY    # Free: analytics.dugganusa.com/stix/register
npx wrangler deploy
```

Add a route in Cloudflare: `*yourdomain.com/*` → `dugganusa-edge-shield`

**That's it.** Your site is protected by 653,342 distinct IOCs — plus behavioural blocking, which is the half a list cannot do.

---

## What Your Origin Server Receives

Every request gets enriched headers — for free:

```http
X-CF-City: Minneapolis
X-CF-Region: Minnesota
X-CF-Country: US
X-CF-ASN-Org: Comcast Cable Communications
X-CF-Latitude: 44.9778
X-CF-Longitude: -93.2650
X-DugganUSA-Shield: active
X-DugganUSA-IOCs: 1100000
```

Build geo dashboards, detect anomalies, log city-level analytics — all from headers your origin already receives.

---

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

**HTTP 418 I'm a Teapot.** Because they deserve it.

---

## The Intelligence Behind It

Edge Shield is powered by the same STIX 2.1 feed that Fortune 500 security teams consume:

<div align="center">

| Metric | Value |
|:------:|:-----:|
| **Distinct IOCs Indexed** | 653,342 (from 1.72M rows) |
| **Reach vs list-only defence** | 30x (1,638 hosts vs 55) |
| **Autonomous Decisions** | 5,764,156 |
| **Threats Blocked** | 2,038,293 |
| **Adversary Profiles** | 361 |
| **Blog Posts** | 1,655 |

</div>

We don't just aggregate — we hunt. 18 documented supply chain attacks (Pattern 38). NrodeCodeRAT discovered behaviourally, before any blocklist carried it. IRGC target analysis on 18 US tech companies. FBI wiretap breach analysis published same-day.

---

## Fix Your AI Visibility — AIPM

<div align="center">

**Is your brand invisible to ChatGPT?** Most are.

</div>

We built [**AIPM (AI Presence Management)**](https://aipmsec.com) — the tool that audits how AI models perceive your brand. Five models. Seven signals. Free.

We used it on ourselves. **0% → 23% ChatGPT visibility in 3 days.** Here's what we did:

> **On our own numbers.** This README previously claimed "275+ consumers in 46 countries" and
> that Microsoft, AT&T, Meta and Zscaler "already pull our feed." Both were removed in August
> 2026 because both were wrong. The consumer figure counted one-off curious pulls, not
> operational consumers, and we retired it publicly. The named-company claim came from our own
> feed analytics reporting top ASNs without splitting by status code — **97.5% of that traffic
> was HTTP 403 to UA-less scrapers being correctly blocked.** We were reading our own doormat
> as a customer list. The indicator count was also a record count, inflated roughly 2.6x
> against distinct indicators. If you are going to publish an honesty axis on a feed, the
> README is part of the feed.

1. **robots.txt** — invited AI crawlers explicitly (GPTBot, ClaudeBot, PerplexityBot)
2. **LD-JSON** — added Organization, Product, FAQ schema across all properties
3. **llms.txt** — deployed an AI-readable site summary (most companies don't have one)
4. **NLWeb** — built a Cloudflare Worker that serves `/.well-known/nlweb` for AI content retrieval
5. **Managed questions** — told the AI models what questions to answer about us
6. **Content velocity** — 15 blog posts in 4 days naming specific companies and CVEs

AIPM scores all of this. Run your audit. See your gaps. Fix them.

We went from "motorcycle oil company" (what GPT-4o thought we were) to accurate threat intelligence descriptions across 4 of 5 models. The structured data + content velocity + GEO optimization stack works. AIPM measures it.

<div align="center">

[**Audit Your Brand Free →**](https://aipmsec.com)

*755+ audits completed. First tool to score llms.txt and NLWeb. Wix launched a competing feature — we took that as validation.*

</div>

---

## Pricing

The Worker is **free and open source forever.** The intelligence is tiered:

| Tier | Price | IOC Refresh | Best For |
|:----:|:-----:|:-----------:|:---------|
| **Free** | $0/mo | 24h, 48h delayed | Personal sites, blogs, side projects |
| **Starter** | $45/mo | 1h, real-time | Small business, startups |
| **Professional** | $495/mo | 15m, real-time + cross-index | SOC teams, MSPs |
| **Enterprise** | $2,495/mo | 5m, full Medusa Suite | Fortune 500, government |

<div align="center">

[**Get Your Free API Key →**](https://analytics.dugganusa.com/stix/register)

</div>

---

## Reading Geo Headers

```javascript
// Node.js / Express
app.use((req, res, next) => {
  const city = req.headers['x-cf-city'];
  const region = req.headers['x-cf-region'];
  const org = req.headers['x-cf-asn-org'];
  console.log(`${city}, ${region} — ${org}`);
  next();
});
```

```python
# Python / Flask
@app.before_request
def log_geo():
    city = request.headers.get('X-CF-City', 'Unknown')
    region = request.headers.get('X-CF-Region', 'Unknown')
    print(f"{city}, {region}")
```

---

## Privacy — read this before deploying

The Worker runs on **YOUR** Cloudflare account. We provide the intelligence. But two
features do send data back to us, and you should decide about them deliberately.

### Normal traffic: we see nothing

For ordinary requests — including requests we block from the IOC feed — we receive
only:
- API key usage (query count per day)
- Which IOC lists you pull

No visitor data. No request URLs. No origin details.

### Honeypot canaries: we receive visitor data (Layer 3)

Edge Shield includes decoy paths (`.env`, `/wp-login.php`, `/webmail`, and others).
When a request hits one, `indexHoneypotHit()` sends us:

- the visitor's **IP address**
- the full **User-Agent**
- **city, region, country, ASN** and ASN organisation
- the **full request URL**, HTTP method, TLS version and Cloudflare bot score

That is visitor data and site data. **An earlier version of this README stated we
see none of it. That was wrong** — the code always sent it. We corrected the
document rather than quietly changing the behaviour, because customers made
deployment decisions against the old text.

**If you operate in the EU or handle personal data:** an IP address plus
User-Agent plus geolocation is personal data under GDPR, and this is a transfer to
a third party. Get a DPA in place or disable the feature before deploying.

**To disable honeypots entirely**, set `HONEYPOTS_ENABLED = "false"` in your
`wrangler.toml` vars. IOC blocking is unaffected.

### Feed hit reporting

If enabled, we receive the **indicator** that matched plus a hash of your API key —
never your visitor's identity. One caveat: when a match comes from a **CIDR range**
(ASN prefixes, /24 blocks), the reported IP may be an address we never published
individually. It is still an address that matched a range you chose to block.

### Canary paths may collide with your real routes

The decoy list was written for our own infrastructure. Paths like `/graphql`,
`/webmail/*`, and anything containing `.env` will return **deception content
instead of your real response**, and the requesting IP will be reported to us as a
scanner. If you serve any of those paths legitimately, disable honeypots or edit
`CANARY_PATHS` before deploying.

---

## Also From DugganUSA

| Product | What It Does |
|:--------|:-------------|
| [**AIPM**](https://aipmsec.com) | Audit how AI models perceive your brand — 0% to 23% ChatGPT visibility in 3 days |
| [**STIX Feed**](https://analytics.dugganusa.com/stix/pricing) | 653,342 distinct IOCs, Splunk ES + OPNsense + MISP, TAXII 2.1 (discovery is open, no key needed) |
| [**Epstein Files**](https://epstein.dugganusa.com) | 400,750 DOJ documents, full-text searchable, free |
| [**Butterbot Tank**](https://github.com/pduggusa/butterbot-tank) | Autonomous site survey robot — WiFi heatmaps, NDAA detection, AR HUD |
| [**Blog**](https://www.dugganusa.com) | 1,655 threat intelligence posts and counting |

---

<div align="center">

**DugganUSA LLC** — Minneapolis, MN &nbsp;&bull;&nbsp; v2.3.0

Cybersecurity threat intelligence. Built with Claude.

D-U-N-S: 14-363-3562 &nbsp;&bull;&nbsp; SAM.gov UEI: TP9FY7262K87

CMMC Level 2: 78/110 NIST SP 800-171 controls on $600/month

*"The boring architecture is the safe architecture."*

[dugganusa.com](https://www.dugganusa.com) &nbsp;&bull;&nbsp; [aipmsec.com](https://aipmsec.com) &nbsp;&bull;&nbsp; [Bluesky](https://bsky.app/profile/hakksaww.bsky.social)

</div>

---

<!-- DUGGANUSA-FAMILY-FOOTER-V1 -->
## DugganUSA Defender Family

Same threat corpus, surfaced wherever you live. Open source, MIT licensed, receipts on every repo.

| Plugin | Surface |
|---|---|
| [dugganusa-scanner-core](https://github.com/pduggusa/dugganusa-scanner-core) | Core IOC scanning engine |
| [dugganusa-vscode](https://github.com/pduggusa/dugganusa-vscode) | VS Code extension |
| [dugganusa-splunk](https://github.com/pduggusa/dugganusa-splunk) | Splunk Technology Add-on |
| [dugganusa-slack](https://github.com/pduggusa/dugganusa-slack) | Slack bot |
| [dugganusa-raycast](https://github.com/pduggusa/dugganusa-raycast) | Raycast extension |
| [dugganusa-sentinel](https://github.com/pduggusa/dugganusa-sentinel) | Microsoft Sentinel TAXII connector |
| [dugganusa-obsidian](https://github.com/pduggusa/dugganusa-obsidian) | Obsidian plugin |
| [dugganusa-nvim](https://github.com/pduggusa/dugganusa-nvim) | Neovim plugin |
| [dugganusa-elastic](https://github.com/pduggusa/dugganusa-elastic) | Elastic / OpenSearch integration |
| **dugganusa-edge-shield** _(this repo)_ | Cloudflare Worker |
| [dugganusa-cli](https://github.com/pduggusa/dugganusa-cli) | CLI scanner |
| [dugganusa-chrome](https://github.com/pduggusa/dugganusa-chrome) | Chrome extension |
| [dugganusa-action](https://github.com/pduggusa/dugganusa-action) | GitHub Action |
| [dredd-mcp](https://github.com/pduggusa/dredd-mcp) | Pre-flight MCP security (this repo) |

Backed by the live DugganUSA threat intel platform: [analytics.dugganusa.com](https://analytics.dugganusa.com).

_Jeevesus saves. Dredd judges._

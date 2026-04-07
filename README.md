<div align="center">

# DugganUSA Edge Shield

### Enterprise threat intelligence at the Cloudflare edge. Free. Open source.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![IOCs](https://img.shields.io/badge/IOCs-1%2C046%2C000%2B-10b981)](https://analytics.dugganusa.com/api/v1/stix-feed)
[![Consumers](https://img.shields.io/badge/Feed%20Consumers-275%2B-818cf8)](https://analytics.dugganusa.com/stix/pricing)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-4f46e5)](https://analytics.dugganusa.com/api/v1/stix-feed)

**Compliance & Posture:**

[![CMMC L2](https://img.shields.io/badge/CMMC%20L2-71%25-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance)
[![SOC 2](https://img.shields.io/badge/SOC%202%20Type%202-88%25-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance)
[![GovRAMP](https://img.shields.io/badge/GovRAMP-Foundation%20Ready-a5b4fc)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance/govramp)
[![CISA AIS](https://img.shields.io/badge/CISA%20AIS-Data%20Aggregator-4ade80)](https://www.cisa.gov/ais)
[![SSL Labs](https://img.shields.io/badge/SSL%20Labs-A%2B-4ade80)](https://www.ssllabs.com/ssltest/analyze.html?d=analytics.dugganusa.com)
[![Headers](https://img.shields.io/badge/Security%20Headers-7%2F7-4ade80)](https://securityheaders.com/?q=analytics.dugganusa.com)
[![DNSSEC](https://img.shields.io/badge/DNSSEC-Enabled-4ade80)](https://dnssec-analyzer.verisignlabs.com/dugganusa.com)
[![Cosign](https://img.shields.io/badge/Container%20Images-Cosign%20Signed-4ade80)](https://github.com/sigstore/cosign)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-4ade80)](https://github.com/pduggusa/enterprise-extraction-platform/tree/main/compliance/evidence/sbom)

**1,046,000+ IOCs. 275+ consumers in 46 countries. Deploy in 30 seconds.**

Microsoft, AT&T, Meta, and Zscaler already pull our feed. Now you can too — at the edge.

[Get Your Free API Key](https://analytics.dugganusa.com/stix/register) &nbsp;&bull;&nbsp; [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed) &nbsp;&bull;&nbsp; [Blog](https://www.dugganusa.com) &nbsp;&bull;&nbsp; [AIPM](https://aipmsec.com)

---

</div>

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
| **IOC Blocking** | Blocks IPs from 1M+ threat indicator feed | **0ms** (cached) |
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

**That's it.** Your site is protected by 1M+ IOCs.

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
X-DugganUSA-IOCs: 1043509
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
| **IOCs Indexed** | 1,043,509 |
| **Feed Consumers** | 275+ |
| **Countries** | 46 |
| **Autonomous Decisions** | 5,764,156 |
| **Threats Blocked** | 2,038,293 |
| **Adversary Profiles** | 361 |
| **Blog Posts** | 1,655 |

</div>

We don't just aggregate — we hunt. 18 documented supply chain attacks (Pattern 38). NrodeCodeRAT discovered 43 days before Zscaler. IRGC target analysis on 18 US tech companies. FBI wiretap breach analysis published same-day.

---

## Fix Your AI Visibility — AIPM

<div align="center">

**Is your brand invisible to ChatGPT?** Most are.

</div>

We built [**AIPM (AI Presence Management)**](https://aipmsec.com) — the tool that audits how AI models perceive your brand. Five models. Seven signals. Free.

We used it on ourselves. **0% → 23% ChatGPT visibility in 3 days.** Here's what we did:

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

## Privacy

When you use Edge Shield, we see:
- API key usage (query count per day)
- Which IOC lists you pull

We do **NOT** see:
- Your visitors
- Your traffic
- Your origin server
- Anything about your site

The Worker runs on **YOUR** Cloudflare account. We provide the intelligence. You control everything else.

---

## Also From DugganUSA

| Product | What It Does |
|:--------|:-------------|
| [**AIPM**](https://aipmsec.com) | Audit how AI models perceive your brand — 0% to 23% ChatGPT visibility in 3 days |
| [**STIX Feed**](https://analytics.dugganusa.com/stix/pricing) | 1M+ IOCs, Splunk ES + OPNsense compatible, TAXII 2.1 |
| [**Epstein Files**](https://epstein.dugganusa.com) | 400,750 DOJ documents, full-text searchable, free |
| [**Butterbot Tank**](https://github.com/pduggusa/butterbot-tank) | Autonomous site survey robot — WiFi heatmaps, NDAA detection, AR HUD |
| [**Blog**](https://www.dugganusa.com) | 1,655 threat intelligence posts and counting |

---

<div align="center">

**DugganUSA LLC** — Minneapolis, MN &nbsp;&bull;&nbsp; v2.0.0

Cybersecurity threat intelligence. Built with Claude.

D-U-N-S: 14-363-3562 &nbsp;&bull;&nbsp; SAM.gov UEI: TP9FY7262K87

CMMC Level 2: 78/110 NIST SP 800-171 controls on $600/month

*"The boring architecture is the safe architecture."*

[dugganusa.com](https://www.dugganusa.com) &nbsp;&bull;&nbsp; [aipmsec.com](https://aipmsec.com) &nbsp;&bull;&nbsp; [Bluesky](https://bsky.app/profile/hakksaww.bsky.social)

</div>

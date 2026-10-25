# Changelog

All notable changes to DugganUSA Edge Shield are documented here.

## 2.20.0 — 2026-10-25

- **PHP and NativePHP canaries, so the next PHP2Shell zero is evidence instead of blindness.** `ttp-check` for CVE-2026-109618 reported 32,954 edge blocks, 26,217 canary docs and 1,690 origin captures with zero PHP2Shell-shaped hits — while printing its own caveat that "no canary for a product = cannot appear here". We had no PHP decoy, so that zero could not have been anything else. New pack traps `/_native/` and `/_assets/` (the NativePHP async-task bridge and static-asset traversal RedEye Security reported as GHSA-83jv-8h7x-287p and GHSA-76px-r497-93p9), plus `/vendor/composer/` and `/_profiler/` — Composer-manifest and Symfony-profiler recon that our edge was *already* seeing un-trapped (`/vendor/composer/installed.json` 6 blocks, `/symfony/_profiler/phpinfo`, `/app_dev.php/_profiler/phpinfo`).
- Decoys answer in character: a fabricated Composer `installed.json` showing pre-fix NativePHP and old Laravel, and an accepted-looking async-task envelope for `/_native/api/events`. Every value is invented — a tarpit, not intel. A scanner that follows the 200 with a serialized payload has told us it carries a real exploit rather than a path list.
- `exploit_path` is set on traversal (`/../`, `%2e%2e`) and on `upload_progress`, `|O:`, `unserialize` or `phpinfo` appearing in the path or query, so a probe is separable from an attempt.
- **Not covered, deliberately:** the `session.upload_progress` primitive travels as a multipart POST **body** field, which the canary layer never sees. A body-only attempt will not appear. RedEye drew the same boundary around their own rules: "None of this sees the memory corruption write itself."
- Collision-checked before shipping — `/_assets/x.js`, `/_native/api/events` and `/vendor/composer/installed.json` all 404 on both `www` and `analytics`, and Palo Alto keeps `/php/`. Our own blog slugs contain "php2shell" and `phpinfo` is an exploit marker, so there are explicit tests that `/post/php2shell-…` stays untrapped — the same way the SonicWall pack guards against Wix slugs carrying CVE numbers. 281 assertions pass across the four suites.

## 2.19.1 — 2026-10-23

- **Scanner detection no longer 418s Python agents.** The `httpx` scanner token (ProjectDiscovery's tool) also matched `python-httpx/x`, the ordinary Python HTTP library and the official MCP SDK's default client, so every Python-built agent calling an MCP endpoint behind the shield got a teapot. The library version string is now ignored for scanner matching; the scanner token still matches.

## 2.19.0 — 2026-10-22

- **Path origins: serve chosen paths from a different origin, after the shield has run.** New optional var `PATH_ORIGINS` (`host/prefix=>https://origin/prefix`, comma-separated; default none). Built for a hosted site builder that owns your `www` hostname at the edge (its Cloudflare-for-SaaS custom hostname wins, so your Worker never runs there): on the apex, which you do own, chosen pages can come from your own renderer while the builder stays the content backend. Scanner, IOC, honeypot and rate-limit checks all run on the original request first; only the origin fetch is re-aimed (target + rest of the path + query). **A target host must be in `ORIGIN_EDGE_HOSTS`**, so a typo cannot turn the shield into an open proxy; an invalid entry is ignored with a one-time `config:` warning. Remapped anonymous query-less GETs get the archive's stale-if-error floor, keyed by the original URL. GET and HEAD only.
- A prefix ending in `/` maps the paths under it; any other entry is an exact path (`dugganusa.com/sitemap.xml`).
- On a remapped request the shield sets `x-dugganusa-apex-host` to the public host (a client copy is always stripped, on every request), so the origin can tell an edge-delivered page from a direct hit on its own hostname. On a remapped response it removes `X-Robots-Tag`: the public host is the canonical one, so a noindex the origin attached for its own hostname, or a copy cached under that hostname, never leaks through.
- DugganUSA's own deployment uses it for `dugganusa.com/post/` → `analytics.dugganusa.com/render/post/`.

## 2.18.0 — 2026-10-20

- **The signup and pricing pages survive an origin stall.** `analytics.dugganusa.com/stix/register` and `/pricing` now use the archive shield that already protects blog posts: cache-first for 10 minutes, stale-while-revalidate to an hour, and the last good copy served if the origin times out or returns 5xx. Correction (same day): the 504s that prompted this were almost all Cloudflare's own Early Hints prefetches (user-agent `nginx-ssl early hints`), not people; real visitors saw 3 failed loads of about 1,200 in a week. The archive stays as cheap insurance. Same safety rules as before: only 200 HTML with no personalised cookie is ever stored. Feed, API and form-submit requests are untouched.
- The archive now drops `cdn-cache-control` and `cloudflare-cdn-cache-control` from stored copies: our analytics origin sends `cdn-cache-control: no-store`, which the Cache API obeys, so nothing was being stored (every read reported `miss`; after the fix, `hit`).
- **Security fix (same day, review of 500ba3a):** the analytics pages are archived only for fully anonymous, query-less GETs (no Cookie, no Authorization, no query string). Before this, a logged-in request could have stored a personalised page for everyone (cache deception), and a query string the cache key ignores could have planted reflected content (cache poisoning). The analytics cache key gained a generation (`k=2`) so nothing stored during the ~7 unguarded minutes is ever served.
- Also on epstein.dugganusa.com since 2026-10-20: full route coverage (route change only, no code).

## 2.17.0 — 2026-10-18

- **An invariant instead of more cases: only a request that got no real content is an arrival.** Three security reviews in a row found a new way to game the harvested-path list (flood eviction, repo-count inflation, slot exhaustion, then list poisoning: plant one of a site's REAL page paths in a public PoC, and the worker would report that page's real visitors). The observation is now reported after the response is known, and only if the origin answered 400 or above or the edge answered with a decoy. A planted real page returns real content, so nothing is recorded and no visitor data is kept, whatever the harvest contains. Probes of paths a site does not serve, which is every real exploit probe, still count, including ones a later layer blocks. The fetch handler is now `handleFetch()` behind a thin default-export wrapper; responses are unchanged. Five end-to-end tests run the shipped handler: real content records nothing, a 404 records once, a non-harvested 404 records nothing, a decoy records, the response is never altered.

## 2.16.2 — 2026-10-18

- **Two holes in 2.16.1's flood defense, closed** (security review). Corroboration counted distinct repos, so one GitHub account could create many repos for a fake CVE and outrank real ones under the cap; it now counts distinct owners. And a path later dropped as shared by more than 3 CVEs still spent its CVE's and owner's slots, so a burst of shared paths could exhaust a real CVE's budget; the filter now drops shared paths before allocating any slot. Same output on the real harvest (1,790 paths, 700 CVEs); four simulated attacks (one-owner flood, many-owner flood, one-owner repo inflation, backdated shared-path exhaustion) keep every real path.

## 2.16.1 — 2026-10-18

- **The harvested-path list resists a flood of fake PoCs.** The harvest is built from public GitHub repos, which anyone can publish, and the cap used to keep the newest harvests first, so a burst of fresh fake repos could evict real paths (security review). Now a rule contributes at most 25 paths, a CVE at most 10, a GitHub owner at most 200; earliest-harvested rules claim slots first; and when the 4,000-path cap binds, CVEs corroborated by more repos outrank single-repo ones, older before newer. On the real harvest every one of 700 CVEs is still covered (1,790 paths). Simulated floods of 3,000 fake CVEs from one owner and from 3,000 owners kept every real path. The same filter runs server-side for the live list (parity-tested).

## 2.16.0 — 2026-10-18

- **Set and forget: the harvested-path list refreshes itself.** The list bundled in 2.15.0 is now the fallback. Every 6 hours, one pull per data center (Cache API on an unrequestable `.invalid` key, like the IOC feed) replaces it with the live list from `GET /api/v1/feed/observation/paths`, so a path the harvester indexes today is watched at the edge without a redeploy. A pull is used only if it validates: valid JSON, at least 100 and at most 10,000 entries, each a lowercase `/path` up to 200 characters and 1-3 CVE ids. Anything else keeps the current list and retries in 30 minutes, so an empty or broken response can never silently blind the observation. Refreshes run in `waitUntil` and only where observation is enabled. Tested by `node test-harvested-observe.mjs` (32).

## 2.15.0 — 2026-10-18

- **Harvested-path observation.** The exploit harvester indexes the endpoint paths of public PoCs, often before CISA lists the CVE (Atlassian CVE-2026-21589: harvested 10-06, KEV 10-15), and until now nothing at the edge watched them: every appliance canary was hand-written after a KEV listing. `scripts/generate-harvested-paths.mjs` turns the harvest into a list inlined in `worker.js` (1,894 paths, 700 CVEs on first generation; static assets, filesystem paths, globs, generic words and our own routes dropped). A request on one of those paths is **passed through untouched**; in the background the worker reports `{cves, path, coarse source net (/24 or /48), ASN, country}` to `/api/v1/feed/observation`. No decoy, no block, no IOC: a probe can be induced, so a hit records that a path arrived, never who sent it. One map lookup per request, no KV, at most one report per source net and path per isolate per 10 minutes, so it fits the free plan. Runs before scanner and IOC enforcement, so a probe a later layer blocks still counts. **Our zones only by default**; `HARVESTED_OBSERVE = "true"` opts a customer in, `"false"` turns it off. On a customer zone the report is minimal: CVE, our list's path, ASN, country and method; never their hostname, the visitor's User-Agent or network (security review of c1e7ec7). Tested by `node test-harvested-observe.mjs`.

## 2.14.3 — 2026-10-16

- **`/research` redirects to `/blog` on www.** The shared nav calls the blog "Research"; a visitor or crawler typing `/research` got a 404. It joins the trust redirects, so it only fires when the origin 404s (a real Wix page at `/research` would win). 302, like the others.
- **The trust footer is light.** It was hardcoded dark (`#07090c`) under pages that went light-first on 2026-10-16. Now `#f3f4f8` with `#444c63` text (7.77:1) and `#4f46e5` links (5.72:1), both WCAG AA.

## 2.14.2 — 2026-10-16

- **Canary hits carry Cloudflare's verdict.** `honeypot_meta.bot_score` is gone: `cf.botManagement.score` only exists with Enterprise Bot Management, so it was null on 4,149 of 4,149 canary hits in the week to 2026-10-16. In its place, `honeypot_meta.cf_verified_bot_category` records Cloudflare's verified-bot category at capture time (e.g. `AI Crawler`), or `null` when Cloudflare did not verify the client. It is a comparator only; nothing in the canary or block path reads it. Tested by `node test-honeypot-meta.mjs`.

## 2.14.1 — 2026-10-16

- Copy only: Organization schema description and README carry the brand short form ("We watched the open internet, then built the membrane between your AI agents and everything they install, call, read and obey."). American spelling in README. No behavior change.

## 2.14.0 — 2026-10-14

- **Origin edge secret (DugganUSA-only; customers leave it unset).** The analytics origin believed `cf-connecting-ip` from any connection, and its public Azure FQDN can be hit directly with a forged Host and a forged `cf-connecting-ip`, so every per-IP control at the origin (rate limits, docs-gate, behavioral blocker, auto-block, honeypot attribution) could be dodged or aimed at a victim's address. The worker now adds `x-dugganusa-edge: <ORIGIN_EDGE_SECRET>` to every request it forwards to an origin in `ORIGIN_EDGE_HOSTS` (default `analytics.dugganusa.com`): the main path, the `embed.js` pass-through and the `track` beacon. It is never sent to a third-party origin (www/apex are Wix), never on the worker's own API calls (feed pulls, honeypot and feed-hit reports), and never when the secret is unset; then a config warning is logged once per isolate, only for a listed host. A client-supplied copy of the header is stripped on every forward. The secret is a `wrangler secret`, never in `wrangler.toml` or code. Sensor hosts stay untouched by design. Tested by `node test-origin-edge.mjs`.

## 2.13.3 — 2026-10-14

- **One Organization record per page.** On www/apex the injected Organization JSON-LD duplicated the Wix embed's `@id` with different fields ("Butterbot by DugganUSA", another email), so crawlers saw two conflicting entities. The worker no longer injects it there (the Wix embed `config/wix/org-jsonld.html` is canonical). Elsewhere it is aligned to the brand standard: one alternate name, the slogan, the product brands, help@ as contact. `ai-services` meta and the feed Service name use the standard product names; "HAIC" and "Pattern 38" removed.

## 2.13.2 — 2026-10-14

- **Secret probes are logged, never indexed.** The 2.13.1 guard enumerated induced-fetch cases (AI fetchers, browser `Sec-Fetch-*`), and the second security review found both sides of that: any exemption is a detection bypass (send a ChatGPT-User UA), and the list was still incomplete (link previewers, mail link scanners like Safe Links and Proofpoint, all on shared egress, all inducible by a pasted or emailed link). The invariant replaces the list: a secret-file probe can always be induced, so one hit is never evidence about the requester and never becomes an IOC. Everyone still gets the edge 404, and no decoy is served. Every hit is logged as `{"shield":"secret-probe", path, via, exploit, asn, colo}` for counting, not blocking.

## 2.13.1 — 2026-10-14

- **Fix: secret probes could poison the feed (2.13.0 was live ~15 minutes, then rolled back; zero records indexed).** The trapped paths are trivially induced: an `<img src=".../key.pem">` on any page makes a visitor's browser fetch one, and a prompt-injected "fetch this URL" makes ChatGPT-User or Perplexity-User fetch one from shared egress. That egress often fails rDNS verification, and `perplexity-user` was not in the verify list at all. 2.13.0 indexed those at confidence 95, which would have put OpenAI/Perplexity egress into ips.csv. Now: any request claiming an AI fetcher (verified or not) is never indexed; browser-initiated subresource or cross-site fetches (`Sec-Fetch-*`) are never indexed; everything else indexes at **confidence 40**, below the ips.csv floor (50) and the edge floor (80). The 404 still applies to everyone. Found by the automated security review of 1ed45ee.

## 2.13.0 — 2026-10-14

- **Secret-file probes get a 404 at the edge.** Wix's AI Bot Visits report (30 days) showed about 15% of AI-fetcher hits on www asking for secrets (`/credentials.json`, `/.zshrc`, `/key.pem`, `/sa.json`, `/firebase-adminsdk*.json`, `/rclone.conf`, `/@fs/…/var/run/secrets/…`, `/__vite_rsc_findSourceMapURL`). None was trapped and all of them reached origin. They now get a plain `404 Not found` at the edge for everyone. **No decoy secret is ever served**: a fake key gets scraped and reported as a leak, and an AI fetcher relays it to its user as fact. Unverified clients are indexed as `secret_probe` (with `exploit_path` on Vite `@fs` / RSC and k8s secret paths). Verified crawlers and AI fetchers get the same 404 and are only logged, never indexed: their egress is shared infrastructure. Own zones only by default (`APPLIANCE_CANARIES`).

## 2.12.0 — 2026-10-14

- **SonicWall SMA1000 canaries (CVE-2026-102255).** Pre-auth SSRF in the Appliance WorkPlace interface, CVSS 10.0, hotfixed 2026-10-06 (SNWLID-2026-0017). Exploitation attempts began 2026-10-08: crafted OPTIONS requests at the WorkPlace "Extraweb" interface aimed at the appliance's internal CouchDB (`127.0.0.1:5984`, `_rewrite`, Basic `admin:admin`). `/workplace/` answers with a minimal original WorkPlace sign-in. `/__api__/` (the login API that canary-gap's harvested SMA1000 KEV PoCs hit) answers 401 JSON. The exact exploit URL is not public, so the CouchDB SSRF markers (`extraweb`, `/_rewrite`, `:5984`, `%3a5984`) trap anywhere on our zones; bare `5984` does not, because blog slugs carry CVE numbers. Tagged `sonicwall_scan` / `sonicwall-sma1000`, with `exploit_path` on the SSRF markers. Closes a measured gap: `ttp-check` found 0 matches for `Extraweb|workplace|5984` in 17,241 blocks, 37,738 canary docs and 1,602 origin captures since 2026-09-14, because we run no SonicWall. Own zones only by default (`APPLIANCE_CANARIES`).
- **Fix: `exploit_path` is now indexed.** 2.10.0 and 2.11.0 computed `exploit_path` for Ivanti, Cisco, Palo Alto and SharePoint hits, but the indexer saved only `encoded_path`, so every exploit marker was dropped before it reached `honeypot_meta`.
- **`default_creds`.** A hit carrying a Basic `admin:admin` header is flagged `default_creds: true`. The credential itself is never stored.

## 2.11.0 — 2026-10-13

- **Cisco and Palo Alto Networks canaries, the first packs picked by measurement rather than after a KEV listing.** `scripts/canary-gap.mjs` in the platform repo joined 2,318 exploit-harvester endpoint rules to CISA KEV and these matchers. Cisco had no canary for any of its 10 KEV CVEs with harvested web paths (Cisco holds 100 KEV entries); Palo Alto had none for its 3 (15 KEV entries). Overall KEV coverage of harvested paths went from 26/137 to 37/137.
  - Cisco (`cisco_scan`): ASA/FTD WebVPN (`/+CSCOE+/`, `/+CSCOU+/`, `/+CSCOT+/`, `/+webvpn+/`, `/CSCOSSL*`, `webvpnlogin` cookie), IOS XE web UI (`/webui/`), FMC REST (`/api/fmc_platform/`, `/api/fmc_config/`, answers 401 JSON), ISE ERS (`/ers/`), SD-WAN Manager (`/dataservice/`, `/j_security_check`), Unified CM (`/ccmadmin/`, `/cucm-uds/`, `/cmplatform/`, `/webdialer/`). The `product` tag names the surface.
  - Palo Alto (`paloalto_scan`): GlobalProtect (`/global-protect/`, `/ssl-vpn/`; `prelogin.esp` answers the XML a client expects) and PAN-OS management (`/php/`, `/unauth/`, `PHPSESSID`).
  - `exploit_path` markers: `logon_hash` (CVE-2023-20198 class), traversal, UCM `installClusterStatusExecute`, `hipreport.esp`, `ztp_gate.php` (CVE-2024-0012), and `%252e%252e` (CVE-2025-0108). `encoded_path` marks encoded spellings, as before.
  - Deliberately not trapped: the generic shapes those PoCs also touched (`/api/v1/`, `/admin/`, `/status`, `/guest/`, `/auth/`, `/portal/`), because they collide with real routes on our zones. Own zones only by default (`APPLIANCE_CANARIES`).

## 2.10.0 — 2026-10-13

- **Ivanti Connect Secure canaries.** `/dana-na/`, `/dana-ws/`, `/dana-cached/` and `/dana/` answer with a minimal original Connect Secure sign-in (`DSSignInURL` cookie). Tagged `ivanti_scan` / `ivanti-connect-secure`. Traversal and the CVE-2023-46805 / CVE-2024-21887 endpoints inside those prefixes carry `exploit_path: true`, and encoded spellings carry `encoded_path: true`. `/api/v1/totp/` and `/api/v1/configuration/` are deliberately NOT trapped, because our own API lives under `/api/v1/`. Closes a measured gap: CVE-2026-104935 entered CISA KEV on 2026-10-13 with a 3-day deadline, and the edge had 0 Connect Secure-shaped probes in 2,941,882 blocks and 139,334 canary docs since 2026-01-01, because we run no Ivanti. Own zones only by default (`APPLIANCE_CANARIES`).
- **Fix: FortiGate decoy cookie.** 2.9.0 replaced the FortiGate decoy's `SVPNCOOKIE` with PeopleSoft's `PS_LOGINLIST`; the test that would have caught it was failing at release. `SVPNCOOKIE` is restored.

## 2.8.0 — 2026-10-12

- **Oracle PeopleSoft canaries.** `/PSEMHUB/` (the CVE-2026-35273 Environment Management Hub endpoint ShinyHunters / UNC6240 is mass-exploiting), `/PSIGW/`, `/psp/` and `/psc/` answer with a minimal original PeopleSoft sign-in. Matching runs on the raw and the decoded path, so the WAF-bypass spelling `/%50SEMHUB/` is caught too, and such hits carry `encoded_path: true` so the bypass variant is measurable on its own. Tagged `peoplesoft_scan` / `oracle-peoplesoft`. Measured gap it closes: 22,348 edge blocks and 51,071 canary hits since 2026-09-01 with zero PeopleSoft-shaped probes, because we run no PeopleSoft.

## 2.7.0 — 2026-10-09

- **ILIAS canaries (CVE-2026-80428).** `/ltiauth.php` and the PoCs' alternate locations (`/LTI/`, `/lti/`, `/shibboleth/`, `/ilias/`) answer as a decoy and are tagged `ilias_scan`. Public PoCs since 2026-09-03; before this, our edge had no way to see the probes.
- **MTA-STS policy host.** `mta-sts.dugganusa.com/.well-known/mta-sts.txt` is served by the worker (`mode: testing`, M365 MX). Pairs with the `_mta-sts` and `_smtp._tls` TXT records.

## 2.6.0 — 2026-10-06

- **Fortinet FortiGate appliance canaries.** SSL-VPN (`/remote/*`, incl. the CVE-2018-13379 `fgt_lang` traversal), FortiCloud SSO start, FortiOS REST API (`/api/v2/cmdb/`, `/api/v2/monitor/`) and the `/ng/` admin UI answer with a minimal original FortiGate login. Same scoping as NetScaler: own zones by default, `APPLIANCE_CANARIES` opt-in/out for customers. Tagged `fortinet_scan` / `fortinet-fortigate`. Measured gap it closes: 134,357 edge-honeypot records, zero FortiOS-shaped probes.

## [2.5.0] - 2026-10-05

### Added
- **Claude-guided onboarding.** `CLAUDE.md` is now a step-by-step playbook: prerequisites, host inventory (PRODUCT / SENSOR / SKIP), security preferences one question at a time with recommended defaults, API key via `wrangler secret put` only, generated config, dry run before deploy, live verification, rollback and the optional WAF IP-list path. `.claude/skills/edge-shield-setup/SKILL.md` surfaces it in Claude Code.
- **Policy knobs as `[vars]`:** `SHIELD_MODE`, `IOC_BLOCKING`, `IOC_MIN_CONFIDENCE`, `IOC_FEED_DAYS`, `IOC_REFRESH_MINUTES`, `SCANNER_418`, `RL_ANON`, `RL_AUTH`, `FEED_HIT_REPORTING`, `SCHEMA_INJECT_HOSTS`, `SENSOR_HOSTS` (alongside the existing `HONEYPOTS_ENABLED` and `APPLIANCE_CANARIES`). Absent vars keep 2.4.0 behavior. An unparseable value falls back to the default and logs a `config:` warning.
- **Observe mode** (`SHIELD_MODE = "observe"`). Scanner 418, IOC 403 and rate-limit 429 are not enforced. Each one is logged (`{"shield":"observe","would":...}`), tagged on the response as `X-DugganUSA-Observed`, and IOC matches are still reported to feed-efficacy with `action: 'observed'`. Rate-limit observations log once per window, not per request.
- **`SENSOR_HOSTS`**: hosts passed straight to origin, untouched, as a second guard behind routing.
- `wrangler.example.toml`: placeholder routes and every var documented. Customer config lives in `wrangler.local.toml` (gitignored); `wrangler.toml` stays DugganUSA's own deployment, now with an explicit `[vars]` block equal to the defaults.
- `scripts/verify.sh`: live PASS/FAIL probes for product and sensor hosts, in block or observe mode. Flags when Cloudflare answered before the Worker, and when the prober's own IP matched the feed.
- `test-config-observe.mjs` (80 cases): config parsing, observe vs block in the real fetch handler, sensor passthrough, and the data-center feed cache.

### Changed
- The data-center feed cache key now carries the configured `days` and `min_confidence`, so two configurations never share an entry.
- Removed the unused `IOC_CACHE_TTL` and the `IOC_REFRESH_INTERVAL` constant (now `IOC_REFRESH_MINUTES`).

## [2.4.0] - 2026-09-29

### Added
- **NetScaler ADC / Gateway appliance canaries.** Paths (case-insensitive): `/vpn/`, `/vpns/`, `/logon/LogonPoint/`, `/nf/auth/`, `/gwtest/`, `/Citrix/`, `/epa/scripts/`, `/oauth/idp/` (prefixes) and `/cgi/login`, `/saml/login`, `/menu/ss`, `/menu/neo`, `/menu/stc`, `/vpn/js/rdx/core/lang/rdx_en.json.gz`. Responds with minimal original login markup and an `NSC_TEMP` cookie. Each catch carries `honeypot_meta.product = 'citrix-netscaler'` and a matching tag. Context: CVE-2026-88771/88772 were exploited for weeks before disclosure, and 126,873 edge-honeypot records held zero NetScaler probes.
- **`APPLIANCE_CANARIES`** var. Default: on only for DugganUSA's own zones (dugganusa.com, aipmsec.com and subdomains), off everywhere else so a customer's real NetScaler is never answered by a decoy. `"true"` opts in, `"false"` disables everywhere. `HONEYPOTS_ENABLED="false"` still disables all canaries.
- 26 routes on analytics. and security.dugganusa.com. Marketing hosts are already fully routed.
- `test-appliance-canaries.mjs` (40 cases, including customer hosts, lookalike hosts, real paths and precedence).

### Fixed
- `getCanary()` called `decodeURIComponent` without a guard, so a malformed escape (`%E0%A4%A`) threw inside the Worker. It now falls back to the raw path.

### Known limit
- CVE-2026-88772 is reached over DTLS (UDP). An HTTP Worker never sees that traffic; these canaries catch the HTTP fingerprinting that precedes it.

## [2.3.0] - 2026-06-30

### Added
- **Feed-efficacy reporting (liveness loop).** When a published indicator blocks real traffic (LAYER 2 IOC match), the Worker now reports the hit back to `POST /api/v1/feed/hit` via `ctx.waitUntil()` — non-blocking, so it never delays the visitor's `403`. Privacy-preserving by contract: it sends only `{ consumer_kind: 'edge-shield', hits: [{ indicator, action: 'blocked', direction: 'inbound', count, ts }] }` — the indicator we already published, never the visitor IP, asset, or any victim-side field (the platform drops those and reports them back as `stripped`).
- Documented the **fourth** live validation axis — **Liveness** (`/api/v1/feed-efficacy`) — alongside novelty, timeliness, and accuracy. This Worker is now a reporter for that axis.

### Changed
- Refreshed IOC corpus copy from `1.10M+` to `1.5M+` (README badge, header, intelligence table, `package.json`, and the `worker.js` Service schema) to match the live platform count (~1.57M indicators).
- Reworded the **Timeliness** validation bullet to point at the live `kev-lead` ledger (positive leads, same-day, and no-receipt shown honestly with receipts) instead of asserting a fixed "~31 days ahead" average — the live ledger is the source of truth.
- Synced README footer + "What's New" header to 2.3.0.

## [2.2.0] - 2026-06-27

### Added
- Documented the three live, no-auth, durable feed-validation endpoints — novelty (`/api/v1/feed-uniqueness`), timeliness (`/api/v1/kev-lead`), and accuracy (`/api/v1/spamhaus-validation`) — so operators can independently verify feed quality. Each response carries a `source` field (`live` | `durable` | `baseline`).
- Noted new feed depth: OSV malicious-package feeds (npm + PyPI) and daily GitHub Hunt detections.

### Changed
- Aligned all IOC counts to 1.10M+ across the README badge, header, geo-header sample, intelligence table, and the `worker.js` Service schema (were 1,046,000+ / 1,043,509).
- Clarified that the STIX feed is API-key-enforced: the Worker already requires a registered key via `wrangler secret put DUGGANUSA_API_KEY`; anonymous pulls return `401`.
- Synced README footer version to 2.2.0.

## [2.1.0]

- Scanner detection (418), in-memory IOC blocking, geo-enrichment headers, honeypot canary routes.

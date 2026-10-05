# Changelog

All notable changes to DugganUSA Edge Shield are documented here.

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

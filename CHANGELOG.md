# Changelog

All notable changes to DugganUSA Edge Shield are documented here.

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

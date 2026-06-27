# Changelog

All notable changes to DugganUSA Edge Shield are documented here.

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

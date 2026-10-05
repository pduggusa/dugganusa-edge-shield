---
name: edge-shield-setup
description: Guided, step-by-step setup of the DugganUSA Edge Shield Cloudflare Worker on the user's own domains. Use when someone asks to set up, install, deploy, configure, onboard, protect their site with, or verify this edge shield, or to change its security preferences (block vs observe, min_confidence, honeypots, rate limits, sensor hosts).
---

# Edge Shield setup

Follow the **Onboarding playbook in `CLAUDE.md`** at the repo root, from Step 1, in
order. Read it fully before asking the first question. Don't work from memory of an
older version: it is the single source of truth, and this skill only points at it.

The non-negotiables, repeated here because they matter most:

- One question at a time, each with a recommended default.
- Never ask for or handle an API key in chat. The user runs
  `npx wrangler secret put DUGGANUSA_API_KEY -c wrangler.local.toml` themselves.
- The customer's config is `wrangler.local.toml`, generated from
  `wrangler.example.toml`. Never edit or deploy `wrangler.toml`: that is DugganUSA's
  own deployment.
- Show `npx wrangler deploy --dry-run -c wrangler.local.toml` and the routes, and
  deploy only on an explicit yes.
- Never route a SENSOR host. List it in `SENSOR_HOSTS`.
- Finish with `scripts/verify.sh` and `npx wrangler tail`. Live probes are the
  proof, not the config.

# Contributing to DugganUSA Edge Shield

Thanks for helping. Edge Shield is a Cloudflare Worker that enforces the DugganUSA Feed at your edge, so
every change is judged by one question: does it block more real attacks without blocking real users?

## Reporting a security problem

Do not open a public issue. Email **security@dugganusa.com**, as described in [SECURITY.md](SECURITY.md)
and our [vulnerability disclosure policy](https://www.dugganusa.com/post/dugganusa-vulnerability-disclosure-policy-and-hall-of-fame).
Good-faith testing within that policy is authorized.

## Reporting a bug or asking for a feature

Open an issue: https://github.com/pduggusa/dugganusa-edge-shield/issues

For a bug, include the Edge Shield version (top of [CHANGELOG.md](CHANGELOG.md)), what you sent, what you
expected and what happened. For a detection request (a new canary, exploit path or scanner tell), include
the advisory or write-up it comes from. Requests are answered, and what ships is credited by name in the
CHANGELOG, including where we chose not to cover something and why.

## Sending a change

1. Fork, branch from `main`, and keep the change focused.
2. Run `npm run lint` and `npm test`. Both must pass. CI runs them on every push and pull request.
3. Add a CHANGELOG entry under a new version: what changed, why, and what it does not cover.
4. Open a pull request. Describe the attack or bug it addresses and how you tested it.

## Test policy

**New functionality ships with tests.** Every new detection, canary pack, matching rule or behavior change
comes with a `test-*.mjs` file, or new cases in an existing one, that fails without the change and passes
with it. Include the cases that must NOT fire (real users, real crawlers, look-alike paths), because a
false block is a defect too. Bug fixes add a test that reproduces the bug.

Tests are plain Node scripts with no test framework and no network access: `node test-<name>.mjs`.
`npm test` runs them all.

## Design rules a change must keep

- **Fail closed.** A missing binding, an unreachable feed or an error must never turn into "allow
  everything".
- **No visitor data beyond what the README's Privacy section describes.**
- **No secrets in the repository.** Use Wrangler secrets.
- **Pin GitHub Actions to a full commit SHA** of a release at least 14 days old (Dependabot enforces the
  same cooldown).

## License

By contributing you agree your contribution is licensed under the [MIT License](LICENSE).

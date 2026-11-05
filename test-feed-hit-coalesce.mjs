/**
 * Test feed-hit coalescing (2.29.0). On 2026-11-05 06:20Z one listed scanner IP sent 2,969 requests in two minutes and the Worker POSTed
 * ~2,716 separate /feed/hit reports for that single address; the origin browned out (~1,990 5xx). Reports now buffer per isolate and flush as
 * one POST per window, but every hit keeps its own event_id and count, so counting is unchanged.
 *
 * Extracts the shipped code from src/worker.js rather than reimplementing it (same as the other suites).
 *
 *   node test-feed-hit-coalesce.mjs
 */
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./src/worker.js', import.meta.url), 'utf8');
const a = src.indexOf('const FEED_HIT_WINDOW_MS'), b = src.indexOf('// PER-IP RATE LIMIT', a);
if (a < 0 || b < 0) throw new Error('could not locate the feed-hit block in worker.js');
const block = src.slice(a, b).replace(/\/\/ =+\s*$/, '');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`}`);
};

// The shipped constants, read from source: a test with a shortened window must not hide a changed production value.
check('shipped window is 1500 ms', Number(/const FEED_HIT_WINDOW_MS = (\d+)/.exec(src)[1]), 1500);
check('shipped max batch is 100 (origin route allows 1000)', Number(/const FEED_HIT_MAX_BATCH = (\d+)/.exec(src)[1]), 100);

const calls = [];
let nextStatus = 200;
globalThis.fetch = async (url, init) => { calls.push({ url, body: JSON.parse(init.body), headers: init.headers }); return { ok: nextStatus < 400, status: nextStatus, text: async () => '' }; };

const mod = await import('data:text/javascript,' + encodeURIComponent(
  `const DUGGANUSA_API = 'https://analytics.dugganusa.com/api/v1'; const SHIELD_UA = 'DugganUSA-Edge-Shield/test';
   const firstPartyZone = (h) => (h === 'aipmsec.com' || h === 'dugganusa.com' ? h : null);\n` +
  block.replace('const FEED_HIT_WINDOW_MS = 1500', 'const FEED_HIT_WINDOW_MS = 25') + '\nexport { reportFeedHit, FEED_HIT_BUFFERS };'));
const { reportFeedHit, FEED_HIT_BUFFERS } = mod;

const mkCtx = () => { const p = []; return { waitUntil: (x) => p.push(x), done: () => Promise.all(p) }; };
const env = { DUGGANUSA_API_KEY: 'test-key-not-real' };
const reset = () => { calls.length = 0; nextStatus = 200; FEED_HIT_BUFFERS.clear(); };

// 1. The incident shape: one IP, a burst of 2,969 matched requests, each with its own ray.
reset();
{
  const ctx = mkCtx();
  for (let i = 0; i < 2969; i++) reportFeedHit(env, '203.0.113.10', 'aipmsec.com', 'ray' + i, 'blocked', ctx);
  await ctx.done();
  const hits = calls.flatMap((c) => c.body.hits);
  check('2,969 reports become at most 30 POSTs (was 2,969)', calls.length <= 30, true);
  check('every report is still delivered exactly once', hits.length, 2969);
  check('every event_id (the CF ray) is preserved and unique', new Set(hits.map((h) => h.event_id)).size, 2969);
  check('no batch exceeds the cap', Math.max(...calls.map((c) => c.body.hits.length)) <= 100, true);
  check('each hit still counts 1', hits.every((h) => h.count === 1), true);
  check('first-party zone is carried on the batch', calls.every((c) => c.body.zone === 'aipmsec.com'), true);
  check('consumer_kind and auth are unchanged', [calls[0].body.consumer_kind, calls[0].headers.Authorization], ['edge-shield', 'Bearer test-key-not-real']);
}

// 2. A lone hit still goes out, after the window.
reset();
{
  const ctx = mkCtx();
  reportFeedHit(env, '203.0.113.11', 'example.org', 'rayA', 'blocked', ctx);
  check('nothing is sent before the window closes', calls.length, 0);
  await ctx.done();
  check('a lone hit is sent once after the window', [calls.length, calls[0].body.hits.length], [1, 1]);
  check('a non-first-party host sends no zone', 'zone' in calls[0].body, false);
}

// 3. Different action / zone are different buffers (the contract is per action and per zone).
reset();
{
  const ctx = mkCtx();
  reportFeedHit(env, '203.0.113.12', 'aipmsec.com', 'r1', 'blocked', ctx);
  reportFeedHit(env, '203.0.113.12', 'aipmsec.com', 'r2', 'observed', ctx);
  reportFeedHit(env, '203.0.113.12', 'dugganusa.com', 'r3', 'blocked', ctx);
  await ctx.done();
  check('blocked/observed and zones are never mixed in one POST', calls.length, 3);
  check('each POST carries a single action', calls.every((c) => new Set(c.body.hits.map((h) => h.action)).size === 1), true);
}

// 4. Fallbacks and guards.
reset();
{
  reportFeedHit(env, '203.0.113.13', 'aipmsec.com', 'r9', 'blocked');            // no ctx: old immediate behavior
  await new Promise((r) => setTimeout(r, 10));
  check('without a ctx it posts immediately, one hit', [calls.length, calls[0].body.hits.length], [1, 1]);
  reset();
  const ctx = mkCtx();
  reportFeedHit({}, '203.0.113.14', 'aipmsec.com', 'r10', 'blocked', ctx);        // no API key
  reportFeedHit(env, '', 'aipmsec.com', 'r11', 'blocked', ctx);                  // no indicator
  await ctx.done();
  check('no key or no indicator sends nothing', calls.length, 0);
  reset();
  const ctx2 = mkCtx();
  reportFeedHit(env, '203.0.113.15', 'aipmsec.com', undefined, 'blocked', ctx2);
  await ctx2.done();
  check('a hit with no ray carries no event_id', 'event_id' in calls[0].body.hits[0], false);
}

// 5. An origin that is shedding (503) is not retried: reports are liveness, and a retry storm is the failure being fixed.
reset();
{
  nextStatus = 503;
  const ctx = mkCtx();
  for (let i = 0; i < 250; i++) reportFeedHit(env, '203.0.113.16', 'aipmsec.com', 'q' + i, 'blocked', ctx);
  await ctx.done();
  check('a 503 is logged and NOT retried (one POST per batch, no more)', calls.length <= 4, true);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

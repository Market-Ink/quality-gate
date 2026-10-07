/*
 * MarketInk Quality Gate — how the AI review talks to Claude.
 *
 *   sdk   the official Anthropic SDK (@anthropic-ai/sdk), used in CI with an
 *         org API key: cached system prompt, structured JSON output, explicit
 *         effort, server-side refusal fallbacks, optional Batches API (-50%).
 *   cli   the `claude` CLI (local Claude login), driven by scan.js.
 *
 * The SDK is an optional dependency: the gate itself stays dependency-free and
 * falls back to the CLI when the SDK isn't installed or no API key is set.
 */

"use strict";

// $ per 1M tokens: [input, output, cache read]. Cache writes (5-minute TTL)
// cost 1.25x input; the Batches API halves everything. Unknown model -> no
// cost estimate (tokens are still reported).
const PRICES = {
  "claude-opus-5-5": [4, 20, 0.2],
  "claude-sonnet-5-5": [2, 10, 0.2],
  "claude-haiku-4-5": [1, 5, 0.1],
  "claude-fable-5-1": [10, 50, 0.25],
  "claude-opus-5": [5, 25, 0.5],
  "claude-sonnet-5": [2, 10, 0.2],
};

const DEFAULT_MODEL = "claude-opus-5-5";
const FALLBACK_BETA = "server-side-fallback-2026-07-01";

function estimateCost(model, u, batch) {
  const p = PRICES[model];
  if (!p) return null;
  const usd = (u.input * p[0] + u.cache_write * p[0] * 1.25 + u.cache_read * p[2] + u.output * p[1]) / 1e6;
  return Math.round(usd * (batch ? 0.5 : 1) * 100000) / 100000;
}

// Resolve @anthropic-ai/sdk from the tool's own folder (CI installs it there)
// or the current directory. Never from the scanned project.
function loadSdk(searchDirs) {
  for (const dir of searchDirs) {
    try {
      const resolved = require.resolve("@anthropic-ai/sdk", { paths: [dir] });
      const mod = require(resolved);
      return mod.default || mod.Anthropic || mod;
    } catch {
      /* not installed here */
    }
  }
  return null;
}

function hasApiCredentials() {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}

function buildParams(job, opts) {
  return {
    model: opts.model,
    max_tokens: 32000,
    // The fixed prefix (instructions, rules, project context) is identical for
    // every call in a run and across runs, so it is cached.
    system: [{ type: "text", text: job.system, cache_control: { type: "ephemeral" } }],
    messages: [{ role: "user", content: job.user }],
    output_config: {
      format: { type: "json_schema", schema: opts.schema },
      effort: opts.effort,
    },
  };
}

function fromMessage(msg, model, batch, ms) {
  const u = msg.usage || {};
  const usage = {
    input: u.input_tokens || 0,
    cache_write: u.cache_creation_input_tokens || 0,
    cache_read: u.cache_read_input_tokens || 0,
    output: u.output_tokens || 0,
    model: msg.model || model,
    duration_ms: ms,
    batch: !!batch,
  };
  usage.cost_usd = estimateCost(usage.model, usage, batch);
  if (msg.stop_reason === "refusal") {
    const cat = msg.stop_details && msg.stop_details.category;
    return { ok: false, usage, error: `request declined by safety classifiers (${cat || "no category"})` };
  }
  if (msg.stop_reason === "max_tokens") return { ok: false, usage, error: "response hit max_tokens" };
  const text = (msg.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
  try {
    return { ok: true, usage, data: JSON.parse(text), text };
  } catch {
    return { ok: false, usage, text, error: "response was not valid JSON" };
  }
}

function describeError(Anthropic, e) {
  // Most specific first; APIConnectionError is a subclass of APIError.
  if (Anthropic.NotFoundError && e instanceof Anthropic.NotFoundError) return `model or endpoint not found: ${e.message}`;
  if (Anthropic.AuthenticationError && e instanceof Anthropic.AuthenticationError) return "invalid or missing API key";
  if (Anthropic.RateLimitError && e instanceof Anthropic.RateLimitError) return `rate limited (after retries): ${e.message}`;
  if (Anthropic.APIConnectionError && e instanceof Anthropic.APIConnectionError) return `network error: ${e.message}`;
  if (Anthropic.APIError && e instanceof Anthropic.APIError) return `API error ${e.status || ""}: ${e.message}`;
  return String((e && e.message) || e);
}

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runSdk(Anthropic, jobs, opts) {
  const client = new Anthropic({ maxRetries: 4, timeout: opts.timeoutMs });
  if (opts.batch) return runBatch(Anthropic, client, jobs, opts);
  return pool(jobs, opts.concurrency, async (job) => {
    const t0 = Date.now();
    opts.log(`  claude ${opts.model} -${job.label} ...`);
    try {
      const params = buildParams(job, opts);
      const msg = opts.fallbacks
        ? await client.beta.messages.create({ ...params, betas: [FALLBACK_BETA], fallbacks: "default" })
        : await client.messages.create(params);
      const res = { id: job.id, ...fromMessage(msg, opts.model, false, Date.now() - t0) };
      opts.log(`  claude -${job.label} ${res.ok ? "done" : "FAILED: " + res.error}`);
      return res;
    } catch (e) {
      const error = describeError(Anthropic, e);
      opts.log(`  claude -${job.label} FAILED: ${error}`);
      return { id: job.id, ok: false, error };
    }
  });
}

// Message Batches: half price, asynchronous (usually minutes). Server-side
// fallbacks aren't accepted on batches, so they're omitted here.
async function runBatch(Anthropic, client, jobs, opts) {
  let batch;
  try {
    batch = await client.messages.batches.create({
      requests: jobs.map((job) => ({ custom_id: job.id, params: buildParams(job, opts) })),
    });
  } catch (e) {
    const error = describeError(Anthropic, e);
    return jobs.map((j) => ({ id: j.id, ok: false, error: `batch submit failed: ${error}` }));
  }
  opts.log(`  batch ${batch.id} submitted (${jobs.length} request(s)); waiting up to ${opts.batchWaitSec}s ...`);
  const t0 = Date.now();
  const deadline = t0 + opts.batchWaitSec * 1000;
  for (;;) {
    try {
      batch = await client.messages.batches.retrieve(batch.id);
    } catch (e) {
      opts.log(`  batch status check failed (${describeError(Anthropic, e)}); retrying`);
    }
    if (batch.processing_status === "ended") break;
    if (Date.now() > deadline) {
      return jobs.map((j) => ({
        id: j.id, ok: false, pending: true, batch_id: batch.id,
        error: `batch ${batch.id} still processing after ${opts.batchWaitSec}s`,
      }));
    }
    await sleep(10000);
  }
  const byId = new Map();
  for await (const r of await client.messages.batches.results(batch.id)) {
    if (r.result.type === "succeeded") {
      byId.set(r.custom_id, fromMessage(r.result.message, opts.model, true, Date.now() - t0));
    } else {
      const detail = r.result.type === "errored" && r.result.error ? `: ${r.result.error.type || ""}` : "";
      byId.set(r.custom_id, { ok: false, error: `batch request ${r.result.type}${detail}` });
    }
  }
  opts.log(`  batch ${batch.id} ended`);
  return jobs.map((j) => ({ id: j.id, batch_id: batch.id, ...(byId.get(j.id) || { ok: false, error: "missing batch result" }) }));
}

module.exports = {
  DEFAULT_MODEL, PRICES, estimateCost, loadSdk, hasApiCredentials, runSdk,
};

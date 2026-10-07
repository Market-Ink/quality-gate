#!/usr/bin/env node
/*
 * MarketInk Quality Gate — rule precision from real reviewer feedback.
 *
 * Reads, for one GitHub repository over the last N days:
 *   - the gate's inline AI-finding comments on PRs (marked
 *     <!-- qg:finding fp=... rule=... -->) and their 👍 / 👎 reactions;
 *   - code-scanning alerts from the gate's SARIF for AI rules (ai/<RULE>):
 *     fixed = the finding was real, dismissed as "false positive" = it wasn't.
 * and writes per-rule precision to a JSON file that scan.js reads with
 * --rule-stats. Rules below the precision threshold are demoted to advisory.
 *
 * Read-only on GitHub (GET requests only). Zero dependencies (Node 18+ fetch).
 *
 * Usage:
 *   GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo node lib/feedback.js \
 *     --days 60 --out quality-gate-stats/rule-stats.json [--previous old.json]
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { parseArgs } = require("util");

const MARKER = /<!--\s*qg:finding\s+fp=([0-9a-f]+)\s+rule=([\w-]+)\s*-->/;
const TOOL_NAME = "MarketInk Quality Gate";

async function gh(apiUrl, token, url) {
  const res = await fetch(url.startsWith("http") ? url : `${apiUrl}${url}`, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (!res.ok) {
    const err = new Error(`GitHub ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  const next = (res.headers.get("link") || "").match(/<([^>]+)>;\s*rel="next"/);
  return { body: await res.json(), next: next ? next[1] : null };
}

async function* paginate(apiUrl, token, url) {
  let u = url;
  while (u) {
    const { body, next } = await gh(apiUrl, token, u);
    for (const item of Array.isArray(body) ? body : []) yield item;
    u = next;
  }
}

async function collect({ apiUrl, token, repo, days }) {
  const since = Date.now() - days * 86400000;
  const verdicts = new Map(); // fp -> { rule, up, down, sources }
  const note = (fp, rule, kind, src) => {
    if (!verdicts.has(fp)) verdicts.set(fp, { rule, up: 0, down: 0, sources: new Set() });
    const v = verdicts.get(fp);
    v[kind]++;
    v.sources.add(src);
  };
  const warnings = [];

  // 1. Inline AI-finding comments and their reactions.
  let prs = 0;
  for await (const pr of paginate(apiUrl, token,
    `/repos/${repo}/pulls?state=all&sort=updated&direction=desc&per_page=100`)) {
    if (Date.parse(pr.updated_at) < since) break;
    prs++;
    for await (const c of paginate(apiUrl, token, `/repos/${repo}/pulls/${pr.number}/comments?per_page=100`)) {
      const m = MARKER.exec(c.body || "");
      if (!m) continue;
      const r = c.reactions || {};
      if (r["+1"]) note(m[1], m[2], "up", "reaction");
      if (r["-1"]) note(m[1], m[2], "down", "reaction");
    }
  }

  // 2. Code-scanning alerts for AI rules (needs code scanning to be enabled).
  for (const state of ["fixed", "dismissed"]) {
    try {
      for await (const a of paginate(apiUrl, token,
        `/repos/${repo}/code-scanning/alerts?tool_name=${encodeURIComponent(TOOL_NAME)}&state=${state}&per_page=100`)) {
        const ruleId = (a.rule && a.rule.id) || "";
        if (!ruleId.startsWith("ai/")) continue;
        const when = Date.parse(a.fixed_at || a.dismissed_at || a.updated_at || a.created_at);
        if (when && when < since) continue;
        const fp = `alert-${a.number}`;
        const rule = ruleId.slice(3);
        if (state === "fixed") note(fp, rule, "up", "alert fixed");
        else if (a.dismissed_reason === "false positive") note(fp, rule, "down", "alert dismissed: false positive");
        // "won't fix" / "used in tests" say nothing about correctness: ignored.
      }
    } catch (e) {
      warnings.push(`code-scanning alerts unavailable (${e.status || e.message}) - using PR reactions only`);
      break;
    }
  }

  // One verdict per finding: any 👎 / false-positive wins over 👍.
  const rules = {};
  for (const v of verdicts.values()) {
    const r = (rules[v.rule] = rules[v.rule] || { up: 0, down: 0 });
    if (v.down) r.down++;
    else if (v.up) r.up++;
  }
  return { prs, findings: verdicts.size, rules, warnings };
}

function merge(previous, current) {
  // Keep counts from a previous window when asked (rolling totals).
  const out = JSON.parse(JSON.stringify(current));
  for (const [id, r] of Object.entries((previous && previous.rules) || {})) {
    const c = (out[id] = out[id] || { up: 0, down: 0 });
    c.up += r.up || 0;
    c.down += r.down || 0;
  }
  return out;
}

async function main() {
  const { values: a } = parseArgs({
    options: {
      days: { type: "string", default: "60" },
      out: { type: "string", default: "quality-gate-stats/rule-stats.json" },
      previous: { type: "string" },
      repo: { type: "string" },
    },
  });
  const token = process.env.GITHUB_TOKEN;
  const repo = a.repo || process.env.GITHUB_REPOSITORY;
  const apiUrl = process.env.GITHUB_API_URL || "https://api.github.com";
  if (!token || !repo) {
    process.stderr.write("error: GITHUB_TOKEN and GITHUB_REPOSITORY (or --repo) are required\n");
    return 2;
  }
  const days = Math.max(1, parseInt(a.days, 10) || 60);
  const res = await collect({ apiUrl, token, repo, days });
  let rules = res.rules;
  if (a.previous && fs.existsSync(a.previous)) {
    try {
      rules = merge(JSON.parse(fs.readFileSync(a.previous, "utf8")), { rules }).rules || rules;
    } catch {
      /* ignore a broken previous file */
    }
  }
  for (const r of Object.values(rules)) {
    const n = r.up + r.down;
    r.samples = n;
    r.precision = n ? Math.round((r.up / n) * 1000) / 1000 : null;
  }
  const stats = {
    generated_at: new Date().toISOString(), repo, window_days: days,
    pull_requests: res.prs, findings_with_feedback: res.findings, rules, warnings: res.warnings,
  };
  fs.mkdirSync(path.dirname(path.resolve(a.out)), { recursive: true });
  fs.writeFileSync(a.out, JSON.stringify(stats, null, 2));

  const lines = [`## Quality Gate rule precision (${repo}, last ${days} days)`, "",
    `${res.prs} PR(s), ${res.findings} AI finding(s) with feedback.`, "",
    "| Rule | 👍 real | 👎 wrong | Precision |", "|---|---:|---:|---:|"];
  for (const [id, r] of Object.entries(rules).sort()) {
    lines.push(`| ${id} | ${r.up} | ${r.down} | ${r.precision == null ? "-" : Math.round(r.precision * 100) + "%"} |`);
  }
  for (const w of res.warnings) lines.push("", `> ${w}`);
  const md = lines.join("\n") + "\n";
  process.stdout.write(md);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
  return 0;
}

if (require.main === module) {
  main().then((c) => process.exit(c)).catch((e) => {
    process.stderr.write(`error: ${e.message}\n`);
    process.exit(1);
  });
}

module.exports = { collect, MARKER };

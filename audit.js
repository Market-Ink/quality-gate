#!/usr/bin/env node
/*
 * MarketInk Quality Gate — whole-repo security audit (manual / release / schedule).
 *
 * A sibling of scan.js, deliberately NOT part of it: scan.js promises that the
 * AI gets no tools, and this audit can't keep that promise. It runs the vendored
 * Cloudflare security-audit skill through Claude Code, with tools locked down
 * (see lib/security-audit.js). It never writes to the audited repo, installs
 * nothing, and is never run by the PR workflow or the git hooks.
 *
 * Shares scan.js's config (.quality-gate.json -> "security_audit") and helpers.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { parseArgs } = require("util");
const { C, loadConfig, globalBin, needsShell, quoteWin, isGitRepo } = require("./scan.js");
const { runSecurityAudit } = require("./lib/security-audit.js");

const HELP = `usage: node audit.js [options]

Whole-repo security audit with the vendored Cloudflare security-audit skill
(recon -> hunters -> independent verifiers -> report). Needs the claude CLI.
Slow and costly: run it by hand or on a release/schedule, not on every PR.
The agent can read the repo and write only to its run folder; it never runs
the repo's code. See README §21.

  --path PATH          repo to audit (default: current dir)
  --profile P          quick | standard (default) | deep
  --budget N           max agent invocations (the skill's strict budget)
  --max-usd N          hard spend cap (claude --max-budget-usd)
  --model M            model for the audit (default: the CLI's default)
  --timeout MIN        stop the audit after MIN minutes (default: 240)
  --fail-on SEV        none (default) | informational | low | medium | high |
                       critical: exit 1 on a confirmed finding at SEV+
  --only PATH          audit only these paths (repeatable)
  --base REF           audit only what changed since REF (e.g. the last tag)
  --out DIR            runs go to DIR/security-audit/<repo>/run-N
                       (default DIR: ./quality-reports)
  --config FILE        project config (default: <path>/.quality-gate.json)
  -h, --help           show this help and exit

Exit codes: 0 valid result, gate not hit · 1 --fail-on hit (an incomplete
run fails a set --fail-on too), or no valid result (timeout, crash, validators
failed) · 2 bad input.
`;

async function main(argv) {
  let args;
  try {
    ({ values: args } = parseArgs({
      args: argv,
      options: {
        help: { type: "boolean", short: "h", default: false },
        path: { type: "string", default: "." },
        profile: { type: "string" },
        budget: { type: "string" },
        "max-usd": { type: "string" },
        model: { type: "string" },
        timeout: { type: "string" },
        "fail-on": { type: "string" },
        only: { type: "string", multiple: true, default: [] },
        base: { type: "string" },
        out: { type: "string" },
        config: { type: "string" },
      },
      allowPositionals: false,
    }));
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }

  const target = path.resolve(args.path);
  try {
    if (!fs.statSync(target).isDirectory()) throw new Error("not a dir");
  } catch {
    process.stderr.write(`error: path not found: ${target}\n`);
    return 2;
  }
  let cfg;
  try {
    const loaded = loadConfig(target, __dirname, args.config);
    cfg = loaded.cfg;
    for (const w of loaded.warnings) process.stdout.write(`${C.warn}config: ${w}${C.end}\n`);
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n`);
    return 2;
  }
  // --only is relative to the audited repo, as in scan.js.
  const only = args.only.map((o) => path.relative(target, path.resolve(target, o)).split(path.sep).join("/"))
    .filter((o) => o && o !== ".");
  if (only.some((o) => o.startsWith(".."))) {
    process.stderr.write("error: --only must point inside --path\n");
    return 2;
  }

  return runSecurityAudit({
    target, scannerDir: __dirname, gitRepo: isGitRepo(target), cfg: cfg.security_audit, only,
    base: args.base, out: args.out, profile: args.profile, budget: args.budget, maxUsd: args["max-usd"],
    model: args.model, timeoutMin: args.timeout, failOn: args["fail-on"],
  }, { C, globalBin, needsShell, quoteWin });
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`error: ${(e && e.stack) || e}\n`);
    process.exit(2);
  });

#!/usr/bin/env node
/*
 * MarketInk Quality Gate — portable runner for the security-audit validators.
 *
 *   node lib/audit-validate.cjs findings <findings.json>
 *   node lib/audit-validate.cjs ledger   <coverage-ledger.json>
 *
 * The vendored validators (vendor/security-audit/validate-*.cjs) refuse every
 * input on platforms without O_NOFOLLOW / O_NONBLOCK (Windows), as a guard
 * against symlink races. Where those flags exist this runs the upstream CLI
 * unchanged. On Windows it reads the file with an equivalent check (lstat: not
 * a link, regular file, one hard link, size limit; then fstat on the open
 * descriptor must match) and calls the same upstream validateDocument().
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { TextDecoder } = require("util");

const SKILL = path.join(__dirname, "..", "vendor", "security-audit");
const KINDS = {
  findings: { script: "validate-findings.cjs", what: "findings JSON", unit: "findings" },
  ledger: { script: "validate-coverage-ledger.cjs", what: "coverage ledger", unit: "coverage units" },
};
const MAX_BYTES = 5 * 1024 * 1024;
// Same structural limits as upstream's enforceJsonTextLimits (findings).
const MAX_DEPTH = 64;
const MAX_ARRAY = 1000;

const hasNoFollow = () => Number.isInteger(fs.constants.O_NOFOLLOW) && fs.constants.O_NOFOLLOW !== 0 &&
  Number.isInteger(fs.constants.O_NONBLOCK) && fs.constants.O_NONBLOCK !== 0;
const clean = (s) => String(s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
  (c) => "\\u" + c.codePointAt(0).toString(16).padStart(4, "0")).slice(0, 2000);

function safeRead(file) {
  const before = fs.lstatSync(file, { bigint: true });
  if (before.isSymbolicLink()) throw new Error("input must not be a symlink");
  if (!before.isFile()) throw new Error("input must be a regular file");
  if (before.nlink !== 1n) throw new Error("input must not be hard-linked");
  if (before.size > BigInt(MAX_BYTES)) throw new Error(`input exceeds ${MAX_BYTES} byte limit`);
  const fd = fs.openSync(file, "r");
  try {
    const st = fs.fstatSync(fd, { bigint: true });
    if (!st.isFile() || st.ino !== before.ino || st.dev !== before.dev || st.size !== before.size || st.nlink !== 1n) {
      throw new Error("input changed while it was being opened");
    }
    const buf = Buffer.alloc(Number(st.size));
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    if (off !== buf.length || fs.readSync(fd, Buffer.alloc(1), 0, 1, off) !== 0) {
      throw new Error("input changed while it was being read");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
      throw new Error("input is not valid UTF-8");
    }
  } finally {
    fs.closeSync(fd);
  }
}

function checkShape(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error(`input exceeds nesting depth ${MAX_DEPTH}`);
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY) throw new Error(`input array exceeds ${MAX_ARRAY} items`);
    for (const v of value) checkShape(v, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) checkShape(v, depth + 1);
  }
}

function portable(kind, file) {
  const k = KINDS[kind];
  const mod = require(path.join(SKILL, k.script));
  let contents;
  try {
    contents = safeRead(file);
  } catch (e) {
    console.error(`Failed to read ${k.what}: ${e.code === "ENOENT" ? "file not found" : e.message}`);
    return 1;
  }
  let doc;
  let errors;
  try {
    if (kind === "ledger") mod.preflightJsonText(contents);
    doc = JSON.parse(contents);
    if (kind === "findings") checkShape(doc);
  } catch (e) {
    console.error(`Failed to parse ${k.what}: ${e instanceof SyntaxError ? "invalid JSON syntax" : e.message}`);
    return 1;
  }
  try {
    if (kind === "findings") {
      const schema = JSON.parse(fs.readFileSync(path.join(SKILL, "report-schema.json"), "utf8"));
      const bad = mod.collectSchemaErrors(schema);
      if (bad.length) throw new Error(`unsupported or invalid report schema: ${bad.join("; ")}`);
      errors = mod.validateDocument(doc, schema);
    } else {
      errors = mod.validateDocument(doc);
    }
  } catch (e) {
    console.error(`Failed to validate ${k.what}: ${e.message || "unexpected validation error"}`);
    return 1;
  }
  for (const m of errors) console.error("ERROR:", clean(m));
  if (errors.length) {
    console.error(`FAIL: ${errors.length} validation error(s)`);
    return 1;
  }
  console.log(`PASS: ${doc.length} ${k.unit} valid`);
  return 0;
}

function main(argv) {
  const [kind, file] = argv;
  if (!KINDS[kind] || !file) {
    console.error("usage: node audit-validate.cjs findings|ledger <file>");
    return 2;
  }
  if (hasNoFollow()) {
    const p = spawnSync(process.execPath, [path.join(SKILL, KINDS[kind].script), file], { stdio: "inherit" });
    return p.status === null ? 1 : p.status;
  }
  return portable(kind, path.resolve(file));
}

if (require.main === module) process.exit(main(process.argv.slice(2)));

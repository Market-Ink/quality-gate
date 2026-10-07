/*
 * MarketInk Quality Gate — per-function review cache.
 *
 * A function's review is stored under a hash of everything that can change
 * its result: the packet text (new + old body, callers, callee signatures),
 * the fixed prefix (instructions, rules, project context), the model and the
 * effort. A new push to a PR re-reviews only functions whose hash changed.
 *
 * Entries hold the model's RAW findings; scan.js re-verifies them against the
 * current files on every hit, so a cache hit can never bypass the evidence check.
 * The cache lives outside the scanned repo (default ~/.cache/marketink-quality-gate).
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CACHE_FORMAT = 1;

function sha(...parts) {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(String(p)).update("\u0000");
  return h.digest("hex");
}

class ReviewCache {
  constructor(dir, { enabled = true, days = 30 } = {}) {
    this.dir = dir || path.join(os.homedir(), ".cache", "marketink-quality-gate", "reviews");
    this.enabled = enabled;
    this.days = days;
    this.hits = 0;
    this.misses = 0;
    this.writes = 0;
  }

  key(...parts) {
    return sha(CACHE_FORMAT, ...parts);
  }

  file(key) {
    return path.join(this.dir, key.slice(0, 2), `${key}.json`);
  }

  get(key) {
    if (!this.enabled) return null;
    try {
      const entry = JSON.parse(fs.readFileSync(this.file(key), "utf8"));
      if (entry.format !== CACHE_FORMAT) throw new Error("old format");
      this.hits++;
      return entry;
    } catch {
      this.misses++;
      return null;
    }
  }

  set(key, value) {
    if (!this.enabled) return;
    try {
      const f = this.file(key);
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, JSON.stringify({ format: CACHE_FORMAT, created: new Date().toISOString(), ...value }));
      this.writes++;
    } catch {
      /* a cache that can't be written is just a cache miss next time */
    }
  }

  // Drop entries older than `days`. Cheap enough to run once per scan.
  prune() {
    if (!this.enabled) return 0;
    const cutoff = Date.now() - this.days * 86400000;
    let removed = 0;
    let shards = [];
    try {
      shards = fs.readdirSync(this.dir);
    } catch {
      return 0;
    }
    for (const s of shards) {
      let files = [];
      try {
        files = fs.readdirSync(path.join(this.dir, s));
      } catch {
        continue;
      }
      for (const f of files) {
        const p = path.join(this.dir, s, f);
        try {
          if (fs.statSync(p).mtimeMs < cutoff) {
            fs.rmSync(p, { force: true });
            removed++;
          }
        } catch {
          /* ignore */
        }
      }
    }
    return removed;
  }
}

module.exports = { ReviewCache, sha };

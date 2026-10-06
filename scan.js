#!/usr/bin/env node
/*
 * MarketInk Quality Gate — a read-only, non-destructive code scanner.
 *
 * WHAT IT DOES
 *     Runs deterministic quality tools (linters, type checkers, security &
 *     dependency scanners) in *check-only* mode, plus an optional scoped AI
 *     review with Claude, and produces a report. On a scoped scan every
 *     finding is classified as NEW (on a line you changed) or PRE-EXISTING,
 *     so legacy debt on the base branch is never blamed on your change.
 *
 * WHAT IT WILL NEVER DO  (safety guarantees)
 *     * It NEVER edits, formats, or fixes your source code.
 *     * It NEVER changes git state (no add/commit/push/checkout/worktree).
 *     * It NEVER installs anything.
 *     * Every tool is invoked in read-only / --check mode only. Tool caches
 *       that would land in the repo (tsc's .tsbuildinfo) are disabled or
 *       redirected to a temp dir.
 *     * A missing tool is skipped, never an error. It cannot break a build.
 *     * The ONLY thing it writes is a report file, in an output directory you
 *       choose (or nothing at all with --no-report). Temp files live in the OS
 *       temp dir and are removed before exit.
 *
 * REQUIREMENTS
 *     Node.js 18+ (for util.parseArgs). Nothing else — zero npm dependencies,
 *     Node built-ins only. Each scanner is optional and auto-detected; the gate
 *     only runs the tools a project already has available.
 *
 *     The language this tool is *written in* has nothing to do with the
 *     languages it *scans*: it is an orchestrator that shells out to whatever
 *     tools a project has (ruff/mypy/bandit for Python, eslint/prettier/tsc for
 *     JS/TS, gitleaks for secrets). Node being everywhere is the only reason it
 *     is in Node instead of Python.
 *
 * USAGE
 *     node scan.js                         # scan changed files in current repo
 *     node scan.js --path ../other-repo    # zero-touch scan of another repo
 *     node scan.js --base origin/master    # a whole feature branch vs master
 *     node scan.js --only src/billing      # narrow the scope to a path
 *     node scan.js --all                   # scan the whole project
 *     node scan.js --staged                # scan only git-staged changes
 *     node scan.js --include-existing      # also count pre-existing findings
 *     node scan.js --no-ai                 # skip the AI review
 *     node scan.js --strict                # exit 1 if findings (for optional CI)
 *     node scan.js --no-report             # print only; write nothing anywhere
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parseArgs } = require("util");

// --------------------------------------------------------------------------- //
//  File type groups
// --------------------------------------------------------------------------- //
const PY_EXT = [".py"];
const JS_EXT = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];
const PRETTIER_EXT = JS_EXT.concat([".json", ".css", ".scss", ".md", ".yaml", ".yml", ".html"]);
const AI_CODE_EXT = JS_EXT.concat([".py", ".sql", ".vue", ".svelte", ".astro"]);

// Directories never worth scanning (non-git discovery, and a safety net for
// tools that scan a folder).
const IGNORE_DIRS = new Set([
  ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
  "dist", "build", ".next", ".nuxt", "coverage", ".mypy_cache",
  ".ruff_cache", ".pytest_cache", "vendor", ".tox", ".turbo", ".vercel",
  ".svelte-kit", ".output", ".cache",
]);

// Generated / lock / minified files: never worth AI tokens or secret regexes.
const GENERATED_RE = new RegExp(
  "(^|/)(package-lock\\.json|npm-shrinkwrap\\.json|pnpm-lock\\.yaml|yarn\\.lock|" +
  "bun\\.lockb?|poetry\\.lock|uv\\.lock|Pipfile\\.lock|Cargo\\.lock|composer\\.lock)$|" +
  "\\.min\\.(js|css)$|\\.map$|\\.snap$", "i");

const IS_WIN = os.platform() === "win32";

// Helper: does a path end with one of the given extensions (case-insensitive)?
function endsWithExt(rel, exts) {
  const low = rel.toLowerCase();
  return exts.some((e) => low.endsWith(e));
}

// --------------------------------------------------------------------------- //
//  ANSI colors (auto-disabled when not a TTY or when NO_COLOR is set)
// --------------------------------------------------------------------------- //
const C = {
  ok: "\x1b[32m", warn: "\x1b[33m", bad: "\x1b[31m", dim: "\x1b[90m",
  bold: "\x1b[1m", cyan: "\x1b[36m", end: "\x1b[0m",
};

function noColor() {
  for (const a of ["ok", "warn", "bad", "dim", "bold", "cyan", "end"]) C[a] = "";
}

if (!process.stdout.isTTY || process.env.NO_COLOR) {
  noColor();
}

// --------------------------------------------------------------------------- //
//  Subprocess helper — always safe, never raises
// --------------------------------------------------------------------------- //
// Quote a single token for the Windows cmd shell (only used for .cmd/.bat).
function quoteWin(token) {
  if (token === "") return '""';
  if (/[\s&|()<>^"%!]/.test(token)) {
    return '"' + token.replace(/"/g, '\\"') + '"';
  }
  return token;
}

function needsShell(cmd) {
  return IS_WIN && /\.(cmd|bat)$/i.test(cmd);
}

/**
 * Run a command read-only. Returns [rcOrStatus, combinedOutput, stdout, stderr].
 *
 * rcOrStatus is a number on normal completion, or one of the strings
 * 'missing' / 'timeout' / 'error' when the command could not run.
 *
 * timeoutMs is in MILLISECONDS (Node convention). Callers convert seconds.
 * env (optional) is merged over process.env.
 */
function run(argv, cwd, timeoutMs = 600000, stdin = null, env = null) {
  const cmd = argv[0];
  const args = argv.slice(1);
  const opts = {
    cwd,
    timeout: timeoutMs,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    windowsHide: true,
  };
  if (stdin != null) opts.input = stdin;
  if (env) opts.env = { ...process.env, ...env };

  let p;
  // Node 18.20+/20.12+ refuse to spawn .cmd/.bat without a shell (EINVAL),
  // so npm/eslint/prettier/tsc shims on Windows must go through the shell.
  if (needsShell(cmd)) {
    const line = [cmd, ...args].map(quoteWin).join(" ");
    p = spawnSync(line, { ...opts, shell: true });
  } else {
    p = spawnSync(cmd, args, opts);
  }

  if (p.error) {
    if (p.error.code === "ENOENT") return ["missing", "executable not found", "", ""];
    if (p.error.code === "ETIMEDOUT") {
      return ["timeout", `timed out after ${Math.round(timeoutMs / 1000)}s`, "", ""];
    }
    return ["error", `${p.error.code || p.error.name}: ${p.error.message}`, "", ""];
  }
  if (p.signal === "SIGTERM") {
    return ["timeout", `timed out after ${Math.round(timeoutMs / 1000)}s`, "", ""];
  }
  const stdout = p.stdout || "";
  const stderr = p.stderr || "";
  let out = stdout;
  if (stderr) out += (out ? "\n" : "") + stderr;
  if (p.status === null) return ["error", `killed by ${p.signal}\n${out}`.trim(), stdout, stderr];
  return [p.status, out.trim(), stdout, stderr];
}

// Windows cmd.exe caps a command line at 8191 chars, CreateProcess at 32767.
function cmdLimit(exe) {
  if (needsShell(exe)) return 7000;
  return IS_WIN ? 30000 : 100000;
}

// Split files into batches whose full command line stays under the limit.
function batchFiles(prefixArgv, files, limit) {
  const base = prefixArgv.map(quoteWin).join(" ").length;
  const batches = [];
  let cur = [];
  let len = base;
  for (const f of files) {
    const add = quoteWin(f).length + 1;
    if (cur.length && len + add > limit) {
      batches.push(cur);
      cur = [];
      len = base;
    }
    cur.push(f);
    len += add;
  }
  if (cur.length) batches.push(cur);
  return batches;
}

// Output that means the TOOL broke, not that the code has issues.
const CRASH_PATTERNS = [
  [/command line is too long|ENAMETOOLONG|E2BIG|argument list too long/i,
    "command line too long"],
  [/heap out of memory|JavaScript heap|Allocation failed - process out of memory/i,
    "Node ran out of memory (raise node_max_old_space_mb in quality-gate.config.json)"],
  [/ENOBUFS|maxBuffer length exceeded/i, "tool output too large"],
  [/Error: Cannot find module|MODULE_NOT_FOUND/, "tool failed to load (missing module)"],
];

function crashReason(text) {
  for (const [re, why] of CRASH_PATTERNS) if (re.test(text || "")) return why;
  return null;
}

function firstLine(text, max = 200) {
  const l = (text || "").split(/\r?\n/).map((s) => s.trim()).find(Boolean) || "";
  return l.length > max ? l.slice(0, max) + "..." : l;
}

// --------------------------------------------------------------------------- //
//  Git helpers (read-only). cwd is always the target repo.
// --------------------------------------------------------------------------- //
function git(args, target) {
  const [rc, out] = run(["git", "-c", "core.quotepath=false", ...args], target, 120000);
  return rc === 0 ? out : "";
}

function gitOk(args, target) {
  const [rc] = run(["git", ...args], target, 30000);
  return rc === 0;
}

function isGitRepo(target) {
  return gitOk(["rev-parse", "--is-inside-work-tree"], target);
}

function resolveBase(target, base) {
  if (base) return base;
  // origin/HEAD names the remote's default branch when the repo was cloned.
  const head = git(["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], target).trim();
  for (const cand of [head, "origin/main", "origin/master", "main", "master"]) {
    if (cand && gitOk(["rev-parse", "--verify", "--quiet", cand], target)) return cand;
  }
  return null;
}

// The fork point, so commits that landed on base after you branched are ignored.
function mergeBase(target, base) {
  return git(["merge-base", base, "HEAD"], target).trim() || null;
}

// `git diff` args for the scope: base fork point vs the working tree (covers
// committed + staged + unstaged in one coherent diff), or the index.
function diffArgs(scope) {
  return scope.staged ? ["diff", "--cached"] : ["diff", scope.fromRef || "HEAD"];
}

function pathspec(scope) {
  return scope.only.length ? ["--", ...scope.only] : [];
}

function untrackedFiles(target, scope) {
  if (scope.staged || scope.range) return [];
  return git(["ls-files", "--others", "--exclude-standard", ...pathspec(scope)], target)
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

function existsFile(target, rel) {
  try {
    return fs.statSync(path.join(target, rel)).isFile();
  } catch {
    return false;
  }
}

const splitLines = (text) => text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

// Files touched by the commits in a --range. In final-state mode, files an
// earlier batch already touched are dropped so each file is reviewed once.
function rangeFiles(target, scope) {
  const { from, to, final } = scope.range;
  let names = splitLines(git(["diff", "--name-only", from, to, ...pathspec(scope)], target));
  if (final && scope.fromRef && scope.fromRef !== from) {
    const earlier = new Set(splitLines(
      git(["diff", "--name-only", scope.fromRef, from, ...pathspec(scope)], target)).map(keyOf));
    names = names.filter((f) => !earlier.has(keyOf(f)));
  }
  return names.filter((f) => existsFile(target, f)).sort();
}

function changedFiles(target, scope) {
  if (scope.range) return rangeFiles(target, scope);
  const found = new Set();
  const add = (text) => {
    for (const line of splitLines(text)) found.add(line);
  };
  add(git([...diffArgs(scope), "--name-only", ...pathspec(scope)], target));
  for (const f of untrackedFiles(target, scope)) found.add(f);
  return [...found].filter((f) => existsFile(target, f)).sort();
}

const ALL_LINES = "ALL";

// Map of file key -> Set of changed (added/modified) line numbers, or ALL.
function changedLineMap(target, scope) {
  const text = git([...diffArgs(scope), "-U0", "--no-color", "--no-ext-diff",
    "--src-prefix=a/", "--dst-prefix=b/", ...pathspec(scope)], target);
  const map = new Map();
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("+++ ")) {
      const p = line.slice(4).replace(/\t$/, "");
      cur = p === "/dev/null" ? null : keyOf(p.replace(/^b\//, ""));
      if (cur && !map.has(cur)) map.set(cur, new Set());
      continue;
    }
    const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (m && cur) {
      const start = Number(m[1]);
      const count = m[2] === undefined ? 1 : Number(m[2]);
      const set = map.get(cur);
      for (let n = start; n < start + count; n++) set.add(n);
    }
  }
  for (const f of untrackedFiles(target, scope)) map.set(keyOf(f), ALL_LINES);
  return map;
}

function walkFiles(target) {
  // Discover all files outside git, honoring IGNORE_DIRS.
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (IGNORE_DIRS.has(ent.name)) continue;
        walk(full);
      } else if (ent.isFile()) {
        out.push(path.relative(target, full).split(path.sep).join("/"));
      }
    }
  };
  walk(target);
  return out;
}

// Every file in the project that git doesn't ignore (tracked + untracked).
// Using git here keeps .next/, .env.local and other ignored output out of scope.
function projectFiles(target, gitRepo) {
  if (!gitRepo) return walkFiles(target);
  return git(["ls-files", "--cached", "--others", "--exclude-standard"], target)
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
    .filter((f) => existsFile(target, f));
}

// --------------------------------------------------------------------------- //
//  Paths & finding classification (new vs pre-existing)
// --------------------------------------------------------------------------- //
let TARGET = ".";

function toRel(p) {
  const abs = path.resolve(TARGET, p);
  return path.relative(TARGET, abs).split(path.sep).join("/");
}

function keyOf(p) {
  const rel = toRel(p);
  return IS_WIN ? rel.toLowerCase() : rel;
}

function underOnly(scope, rel) {
  if (!scope.only.length) return true;
  const k = keyOf(rel);
  return scope.only.some((o) => {
    const ok = keyOf(o);
    return k === ok || k.startsWith(ok + "/");
  });
}

// mode "lines": new if it touches a changed line (single-file rules).
// mode "files": new if it is in a changed file (cross-file checks like tsc,
//               where a change can surface an error anywhere in that file).
function isNew(scope, f, mode) {
  if (!scope.filter || !f.file) return true;
  const k = keyOf(f.file);
  if (mode === "files") return scope.changed.has(k);
  const entry = scope.lines.get(k);
  if (!entry) return false;
  if (entry === ALL_LINES) return true;
  if (f.line == null) return entry.size > 0;
  const end = f.endLine || f.line;
  for (let n = f.line; n <= end; n++) if (entry.has(n)) return true;
  return false;
}

function fmtFinding(f) {
  const loc = f.file ? `${f.file}${f.line ? ":" + f.line : ""}` : "(project)";
  return `${loc}  ${f.rule ? "[" + f.rule + "] " : ""}${f.message}`;
}

const LIST_NEW = 400;
const LIST_OLD = 60;

function renderFindings(fresh, old, labels) {
  const out = [];
  if (fresh.length) {
    out.push(`${labels.fresh} (${fresh.length}):`);
    for (const f of fresh.slice(0, LIST_NEW)) out.push("  " + fmtFinding(f));
    if (fresh.length > LIST_NEW) out.push(`  ... and ${fresh.length - LIST_NEW} more`);
  }
  if (old.length) {
    if (out.length) out.push("");
    out.push(`${labels.old} (${old.length}):`);
    for (const f of old.slice(0, LIST_OLD)) out.push("  " + fmtFinding(f));
    if (old.length > LIST_OLD) out.push(`  ... and ${old.length - LIST_OLD} more`);
  }
  return out.join("\n");
}

function result(spec, status, note, output, command, extra = {}) {
  return {
    id: spec.id, title: extra.title || spec.title, category: spec.cat,
    status, note: note ?? null, output: output || "",
    command: command || null, counts: extra.counts || null,
  };
}

/**
 * Turn parsed findings into a check result.
 *   FINDINGS = new errors   INFO = only warnings / pre-existing / advisory
 *   PASS     = nothing
 */
function finalize(spec, scope, findings, opts = {}) {
  const all = findings
    .map((f) => ({ ...f, file: f.file ? toRel(f.file) : null }))
    .filter((f) => !f.file || underOnly(scope, f.file));
  const mode = opts.mode || spec.mode || "lines";
  const fresh = [];
  const old = [];
  for (const f of all) (mode === "always" || isNew(scope, f, mode) ? fresh : old).push(f);

  const notes = [];
  let status;
  let labels = {
    fresh: scope.filter ? "New in this change" : "Findings",
    old: mode === "files"
      ? "Outside the files you changed - likely pre-existing, but a changed signature or " +
        "export can break untouched callers; confirm with --include-existing"
      : "Pre-existing - on lines you did not change",
  };

  if (opts.advisory && all.length) {
    status = "INFO";
    notes.push(`${all.length} ${opts.unit || "issue"}(s) - advisory: ${opts.advisory}`);
    labels = { fresh: "Advisory", old: "" };
    fresh.push(...old.splice(0));
  } else {
    const newErrors = fresh.filter((f) => f.level !== "warning").length;
    if (newErrors) {
      status = "FINDINGS";
      notes.push(`${newErrors} new`);
    } else if (fresh.length) {
      status = "INFO";
      notes.push(`${fresh.length} new warning(s)`);
    } else if (old.length) {
      status = "INFO";
      notes.push("0 new");
    } else {
      status = "PASS";
    }
    if (old.length) notes.push(`${old.length} ${mode === "files" ? "outside changed files" : "pre-existing"}`);
  }
  if (opts.extraNote) notes.push(opts.extraNote);

  return result(spec, status, notes.join("; ") || null,
    renderFindings(fresh, old, labels), opts.command,
    { title: opts.title, counts: { new: fresh.length, existing: old.length } });
}

// --------------------------------------------------------------------------- //
//  Tool resolution
// --------------------------------------------------------------------------- //
// shutil.which() equivalent: search PATH, honoring PATHEXT on Windows.
//
// On Windows this MUST try `name + <PATHEXT ext>` and NOT the bare name — a
// bare `claude`/`npm` on PATH is usually an extensionless *nix shell shim that
// Windows CreateProcess cannot launch (ENOENT). shutil.which skips it for the
// runnable `.cmd`/`.exe`; we mirror that so npm/claude/gitleaks resolve correctly.
function globalBin(name) {
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  const isFile = (p) => {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  };

  if (!IS_WIN) {
    // On POSIX, mirror shutil.which: the candidate must be a regular file AND
    // executable (X_OK). Skipping the X_OK check would "find" a non-executable
    // name-match and then fail to spawn (EACCES) instead of cleanly skipping.
    const isExec = (p) => {
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return isFile(p);
      } catch {
        return false;
      }
    };
    for (const dir of dirs) {
      const cand = path.join(dir, name);
      if (isExec(cand)) return cand;
    }
    return null;
  }

  const pathext = (process.env.PATHEXT || ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .filter(Boolean);
  // If the name already carries a known executable extension, use it as-is;
  // otherwise probe each PATHEXT extension (never the bare name).
  const hasExt = pathext.some((ext) => name.toLowerCase().endsWith(ext.toLowerCase()));
  const names = hasExt ? [name] : pathext.map((ext) => name + ext);
  for (const dir of dirs) {
    for (const n of names) {
      const cand = path.join(dir, n);
      if (isFile(cand)) return cand;
    }
  }
  return null;
}

function localBin(target, name) {
  // Resolve a JS tool from the project's own node_modules/.bin.
  const d = path.join(target, "node_modules", ".bin");
  const cands = IS_WIN ? [name + ".cmd", name] : [name];
  for (const c of cands) {
    const p = path.join(d, c);
    try {
      if (fs.statSync(p).isFile()) return p;
    } catch {
      /* not here */
    }
  }
  return null;
}

function readText(p, maxBytes = 2000000) {
  try {
    if (fs.statSync(p).size > maxBytes) return null;
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function readJson(p) {
  const t = readText(p);
  if (t === null) return null;
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------- //
//  Tool output parsers. Each returns { findings } | { error } | { skip }.
//  A finding is { file, line, endLine?, rule, message, level: error|warning }.
// --------------------------------------------------------------------------- //
function parseEslint(rc, stdout, stderr, out) {
  if (/couldn't find (an? )?(eslint\.config|config(uration)? file)|no eslint configuration found|could not find config file/i.test(out)) {
    return { skip: "no ESLint config in this project" };
  }
  let data;
  try {
    data = JSON.parse(stdout);
  } catch {
    return { error: crashReason(out) || `ESLint exited ${rc} without a report: ${firstLine(stderr || stdout)}` };
  }
  const findings = [];
  for (const file of data) {
    for (const m of file.messages || []) {
      // Explicitly passed files that the project's config ignores.
      if (!m.ruleId && /^File ignored/.test(m.message)) continue;
      findings.push({
        file: file.filePath, line: m.line || null, endLine: m.endLine || null,
        rule: m.ruleId || (m.fatal ? "parse-error" : null),
        message: m.message.split(/\r?\n/)[0],
        level: m.severity === 2 || m.fatal ? "error" : "warning",
      });
    }
  }
  return { findings };
}

function parsePrettier(rc, stdout, stderr) {
  const findings = [];
  for (const l of stdout.split(/\r?\n/)) {
    const t = l.trim();
    if (!t || t.startsWith("[")) continue;
    findings.push({ file: t, line: null, rule: "prettier",
      message: "not formatted per the project's Prettier config", level: "error" });
  }
  for (const l of stderr.split(/\r?\n/)) {
    const m = /^\[error\]\s+(.+?):\s+(SyntaxError.*)$/.exec(l.trim());
    if (m) {
      const lm = /\((\d+):\d+\)/.exec(m[2]);
      findings.push({ file: m[1], line: lm ? Number(lm[1]) : null, rule: "prettier/syntax",
        message: m[2], level: "error" });
    }
  }
  if (rc === 2 && !findings.length) return { error: firstLine(stderr) || "Prettier exited with an error" };
  return { findings };
}

function parseTsc(rc, stdout, stderr, out) {
  const findings = [];
  for (const l of out.split(/\r?\n/)) {
    let m = /^(.+?)\((\d+),(\d+)\): error (TS\d+): (.*)$/.exec(l.trim());
    if (m) {
      findings.push({ file: m[1], line: Number(m[2]), rule: m[4], message: m[5], level: "error" });
      continue;
    }
    m = /^error (TS\d+): (.*)$/.exec(l.trim());
    if (m) findings.push({ file: null, line: null, rule: m[1], message: m[2], level: "error" });
  }
  if (rc !== 0 && !findings.length) {
    return { error: crashReason(out) || `tsc exited ${rc}: ${firstLine(out)}` };
  }
  return { findings };
}

function parseRuff(rc, stdout, stderr) {
  if (rc === 2) return { error: firstLine(stderr || stdout) || "ruff exited with an error" };
  if (!stdout.trim()) return { findings: [] };
  let data;
  try {
    data = JSON.parse(stdout);
  } catch {
    return { error: `ruff produced no JSON report: ${firstLine(stderr || stdout)}` };
  }
  return { findings: data.map((d) => ({
    file: d.filename, line: d.location ? d.location.row : null,
    endLine: d.end_location ? d.end_location.row : null,
    rule: d.code, message: d.message, level: "error",
  })) };
}

function parseRuffFormat(rc, stdout, stderr, out) {
  const findings = [];
  for (const l of out.split(/\r?\n/)) {
    const m = /^Would reformat:\s+(.+)$/.exec(l.trim());
    if (m) findings.push({ file: m[1], line: null, rule: "ruff-format",
      message: "not formatted per the project's ruff config", level: "error" });
  }
  if (rc === 2 && !findings.length) return { error: firstLine(stderr || stdout) || "ruff format failed" };
  return { findings };
}

function parseMypy(rc, stdout, stderr, out) {
  const findings = [];
  for (const l of stdout.split(/\r?\n/)) {
    const m = /^(.+?):(\d+)(?::\d+)?: (error|warning): (.+?)(?:\s+\[([\w-]+)\])?$/.exec(l.trim());
    if (m) findings.push({ file: m[1], line: Number(m[2]), rule: m[5] || "mypy",
      message: m[4], level: m[3] === "warning" ? "warning" : "error" });
  }
  if (rc !== 0 && !findings.length) return { error: crashReason(out) || `mypy exited ${rc}: ${firstLine(out)}` };
  return { findings };
}

function parseBandit(rc, stdout, stderr) {
  let data;
  try {
    data = JSON.parse(stdout);
  } catch {
    if (rc === 0) return { findings: [] };
    return { error: `bandit produced no JSON report: ${firstLine(stderr || stdout)}` };
  }
  return { findings: (data.results || []).map((r) => ({
    file: r.filename, line: r.line_number,
    endLine: Array.isArray(r.line_range) && r.line_range.length ? r.line_range[r.line_range.length - 1] : null,
    rule: r.test_id, message: `${r.issue_text} (${r.issue_severity})`, level: "error",
  })) };
}

// --------------------------------------------------------------------------- //
//  Format-check enforcement detection
//  A formatter that nothing enforces (no hook, CI step, lint-staged entry or
//  ESLint plugin) is a team choice, not a defect — report it as advisory.
// --------------------------------------------------------------------------- //
function enforcementTexts(target) {
  const texts = [];
  const pkg = readJson(path.join(target, "package.json")) || {};
  for (const k of ["lint-staged", "husky", "simple-git-hooks"]) {
    if (pkg[k]) texts.push(JSON.stringify(pkg[k]));
  }
  const files = [
    ".lintstagedrc", ".lintstagedrc.json", ".lintstagedrc.yaml", ".lintstagedrc.yml",
    ".lintstagedrc.js", ".lintstagedrc.cjs", ".lintstagedrc.mjs",
    "lint-staged.config.js", "lint-staged.config.cjs", "lint-staged.config.mjs",
    ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".gitlab-ci.yml",
    "Makefile", "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
    "eslint.config.ts", ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json",
    ".eslintrc.yml", ".eslintrc.yaml",
  ];
  for (const f of files) {
    const t = readText(path.join(target, f));
    if (t) texts.push(t);
  }
  for (const dir of [".husky", ".githooks", ".github/workflows"]) {
    let entries = [];
    try {
      entries = fs.readdirSync(path.join(target, dir));
    } catch {
      /* none */
    }
    for (const e of entries) {
      const t = readText(path.join(target, dir, e));
      if (t) texts.push(t);
    }
  }
  return { pkg, texts };
}

function formatterEnforced(target, needles) {
  const { pkg, texts } = enforcementTexts(target);
  const hay = texts.map((t) => t.toLowerCase());
  if (hay.some((t) => needles.some((n) => t.includes(n)))) return true;
  // A package.json script that runs the formatter counts only if a hook/CI
  // actually invokes that script.
  const scripts = pkg.scripts || {};
  const names = Object.keys(scripts).filter((s) =>
    needles.some((n) => String(scripts[s]).toLowerCase().includes(n)));
  return names.some((s) => hay.some((t) => t.includes(s.toLowerCase())));
}

// --------------------------------------------------------------------------- //
//  Dependency audit helpers
// --------------------------------------------------------------------------- //
const AUDIT_ERR = /ENOLOCK|EAUDITNOLOCK|ERR_PNPM_\w+|ENOTFOUND|ECONNREFUSED|ECONNRESET|EAI_AGAIN|getaddrinfo|audit endpoint returned an error|requires an existing lockfile/i;

function detectJsAudit(target) {
  const has = (f) => fs.existsSync(path.join(target, f));
  if (has("pnpm-lock.yaml")) {
    return { pm: "pnpm", locks: ["pnpm-lock.yaml"], exe: globalBin("pnpm"),
      argv: (e) => [e, "audit", "--audit-level", "high"] };
  }
  if (has("bun.lock") || has("bun.lockb")) {
    return { pm: "bun", locks: ["bun.lock", "bun.lockb"], exe: globalBin("bun"),
      argv: (e) => [e, "audit", "--audit-level=high"] };
  }
  if (has("yarn.lock")) {
    const berry = has(".yarnrc.yml");
    return { pm: "yarn", locks: ["yarn.lock"], exe: globalBin("yarn"),
      argv: (e) => berry
        ? [e, "npm", "audit", "--all", "--recursive", "--severity", "high"]
        : [e, "audit", "--level", "high"] };
  }
  if (has("package-lock.json") || has("npm-shrinkwrap.json")) {
    return { pm: "npm", locks: ["package-lock.json", "npm-shrinkwrap.json"], exe: globalBin("npm"),
      argv: (e) => [e, "audit", "--audit-level=high"] };
  }
  if (has("package.json")) return { skip: "no lockfile found - a dependency audit needs one" };
  return null;
}

function detectPyAudit(target) {
  const manifests = ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    "Pipfile.lock", "poetry.lock", "uv.lock"];
  const has = (f) => fs.existsSync(path.join(target, f));
  const reqs = (() => {
    try {
      return fs.readdirSync(target).filter((n) => /^requirements.*\.txt$/i.test(n));
    } catch {
      return [];
    }
  })();
  if (!reqs.length && !manifests.some(has)) return null;
  return { pm: "pip", locks: [...manifests, ...reqs], exe: globalBin("pip-audit"),
    argv: (e) => has("requirements.txt") ? [e, "-r", "requirements.txt"] : [e] };
}

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies",
  "peerDependencies", "overrides", "resolutions", "pnpm"];

// Did this change alter the dependency set? If not, every advisory already
// exists on the base branch.
function depsChanged(target, scope, tool) {
  if (!scope.filter) return true;
  if (tool.locks.some((l) => scope.changed.has(keyOf(l)))) return true;
  if (tool.pm === "pip") return false;
  for (const rel of scope.changedRel) {
    if (path.basename(rel) !== "package.json") continue;
    const beforeRef = scope.staged ? "HEAD" : scope.fromRef || "HEAD";
    const before = git(["show", `${beforeRef}:${rel}`], target);
    const after = scope.staged ? git(["show", `:${rel}`], target) : readText(path.join(target, rel));
    try {
      const a = JSON.parse(before);
      const b = JSON.parse(after);
      if (DEP_FIELDS.some((k) => JSON.stringify(a[k] ?? null) !== JSON.stringify(b[k] ?? null))) return true;
    } catch {
      return true; // new or unparsable manifest: assume changed
    }
  }
  return false;
}

function auditSummary(out) {
  const parts = [];
  const m1 = /(\d+\s+vulnerabilit[^\n]*)/i.exec(out);
  if (m1) parts.push(m1[1].trim());
  const m2 = /Severity:[^\n]*/i.exec(out);
  if (m2) parts.push(m2[0].trim());
  return parts.join(" - ").slice(0, 200) || "vulnerabilities found";
}

function runDepsAudit(spec, target, scope, ctx) {
  const tool = spec.detect(target);
  if (!tool) return result(spec, "SKIP", "not applicable to this project");
  if (tool.skip) return result(spec, "SKIP", tool.skip);
  const title = `${tool.pm === "pip" ? "pip-audit" : tool.pm + " audit"} - dependencies`;
  if (!tool.exe) {
    return result(spec, "SKIP", `${tool.pm === "pip" ? "pip-audit" : tool.pm} not found on PATH`,
      null, null, { title });
  }
  const argv = tool.argv(tool.exe);
  const [rc, out] = run(argv, target, ctx.timeoutMs);
  const command = argv.join(" ");
  if (typeof rc === "string") return result(spec, "ERROR", out, out, command, { title });
  if (rc !== 0 && AUDIT_ERR.test(out)) {
    const line = out.split(/\r?\n/).find((l) => AUDIT_ERR.test(l)) || firstLine(out);
    return result(spec, "ERROR", `audit could not run: ${line.trim().slice(0, 160)}`, out, command, { title });
  }
  if (rc === 0) return result(spec, "PASS", null, out, command, { title });
  const summary = auditSummary(out);
  if (depsChanged(target, scope, tool)) {
    return result(spec, "FINDINGS", summary, out, command, { title });
  }
  return result(spec, "INFO",
    `${summary} - dependencies unchanged vs ${scope.base || "HEAD"}, so these already exist there`,
    out, command, { title });
}

// --------------------------------------------------------------------------- //
//  Gitleaks (secrets)
//  Scoped scans read ONLY the commits/changes in scope (never the folder, so
//  ignored build output and local .env files are not scanned). Raw secrets
//  are read from a temp JSON report and never printed — only their length.
// --------------------------------------------------------------------------- //
const PLACEHOLDER_RE = /your[_-]|example|placeholder|changeme|change[_-]me|dummy|redacted|replace[_-]?me|insert[_-]|xxxx|\.\.\.|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}/i;

function isPlaceholder(secret) {
  const s = String(secret || "").trim();
  if (s.length < 8) return true;
  if (new Set(s.toLowerCase()).size <= 3) return true;
  return PLACEHOLDER_RE.test(s);
}

function gitleaksModern(exe, target) {
  const [, out] = run([exe, "version"], target, 30000);
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(out || "");
  if (!m) return true;
  const [maj, min] = [Number(m[1]), Number(m[2])];
  return maj > 8 || (maj === 8 && min >= 19);   // `git`/`dir` subcommands
}

function runGitleaks(spec, exe, target, scope, ctx) {
  const modern = gitleaksModern(exe, target);
  const R = (rp) => ["--no-banner", "--report-format", "json", "--report-path", rp, "--exit-code", "0"];
  const gitMode = (extra) => modern
    ? (rp) => [exe, "git", ...extra, ...R(rp), "."]
    : (rp) => [exe, "detect", "--source", ".", ...extra, ...R(rp)];
  const preCommit = (staged) => modern
    ? (rp) => [exe, "git", "--pre-commit", ...(staged ? ["--staged"] : []), ...R(rp), "."]
    : (rp) => [exe, "protect", "--source", ".", ...(staged ? ["--staged"] : []), ...R(rp)];
  const dirMode = (p) => modern
    ? (rp) => [exe, "dir", ...R(rp), p]
    : (rp) => [exe, "detect", "--no-git", "--source", p, ...R(rp)];

  const passes = [];
  const notes = [];
  if (!ctx.gitRepo) {
    passes.push(["directory", dirMode(".")]);
  } else if (ctx.scopeAll) {
    passes.push(["full git history", gitMode([])]);
  } else if (scope.staged) {
    passes.push(["staged changes", preCommit(true)]);
  } else if (scope.range) {
    const { from, to } = scope.range;
    passes.push([`commits ${from.slice(0, 8)}..${to.slice(0, 8)}`, gitMode([`--log-opts=${from}..${to}`])]);
  } else {
    if (scope.fromRef && scope.fromRef !== "HEAD") {
      passes.push([`commits ${scope.fromRef.slice(0, 8)}..HEAD`, gitMode([`--log-opts=${scope.fromRef}..HEAD`])]);
    }
    if (git(["status", "--porcelain", "--untracked-files=no"], target)) {
      passes.push(["unstaged changes", preCommit(false)]);
      passes.push(["staged changes", preCommit(true)]);
    }
    const untracked = untrackedFiles(target, scope);
    if (untracked.length > 100) {
      notes.push(`${untracked.length} untracked files not secret-scanned (commit or stage them)`);
    } else {
      for (const f of untracked) passes.push([`untracked file ${f}`, dirMode(f), "untracked"]);
    }
  }
  if (!passes.length) return result(spec, "PASS", "nothing in scope to scan");

  const seen = new Set();
  const findings = [];
  let placeholders = 0;
  let command = null;
  for (let i = 0; i < passes.length; i++) {
    const [label, build] = passes[i];
    const rp = path.join(ctx.tmpDir, `gitleaks-${i}.json`);
    const argv = build(rp);
    if (!command) command = argv.join(" ").replace(rp, "<tmp-report>");
    const [rc, out] = run(argv, target, ctx.timeoutMs);
    let leaks;
    try {
      leaks = JSON.parse(fs.readFileSync(rp, "utf8"));
    } catch {
      leaks = null;
    } finally {
      try {
        fs.rmSync(rp, { force: true });
      } catch {
        /* removed with tmpDir anyway */
      }
    }
    if (typeof rc === "string" || rc !== 0 || !Array.isArray(leaks)) {
      return result(spec, "ERROR", `gitleaks failed on ${label}: ${firstLine(out)}`, out, command);
    }
    for (const lk of leaks) {
      const file = String(lk.File || "").split(path.sep).join("/");
      if (file.split("/").some((seg) => IGNORE_DIRS.has(seg))) continue;
      if (isPlaceholder(lk.Secret)) {
        placeholders++;
        continue;
      }
      const key = `${file}:${lk.StartLine}:${lk.RuleID}:${lk.Secret}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const len = String(lk.Secret || "").length;
      findings.push({
        file, line: lk.StartLine || null, rule: lk.RuleID,
        message: `${lk.Description || "secret"} - value redacted (${len} chars)` +
          (lk.Commit ? `, commit ${String(lk.Commit).slice(0, 8)}` : ""),
        level: "error",
      });
    }
  }
  if (placeholders) notes.push(`${placeholders} likely placeholder(s) ignored`);
  const nUntracked = passes.filter((p) => p[2] === "untracked").length;
  const labels = passes.filter((p) => p[2] !== "untracked").map((p) => p[0]);
  if (nUntracked) labels.push(`${nUntracked} untracked file(s)`);
  notes.push(`scanned: ${labels.join(" + ")}`);
  if (passes.length > 1) command += `  (+${passes.length - 1} more pass(es))`;
  return finalize(spec, scope, findings, { mode: "always", command, extraNote: notes.join("; ") });
}

// --------------------------------------------------------------------------- //
//  Built-in Supabase security check (pure-JS, read-only, no external tool)
//
//  Generic linters know nothing about Supabase, so this fills the gap with the
//  concrete "always/never" anti-patterns a live-DB audit would catch — adapted
//  to what is visible in code + SQL migrations. It reads files only; it never
//  connects to a database and never writes anything. Judgment calls (RLS
//  coverage, IDOR, RPC logic) are left to the AI reviewer in prompts/supabase.md.
//
//  Comments are stripped before semantic rules run, SQL is matched per
//  statement (not per line), and RLS state is collected across every
//  migration in the repo. Secret rules still run on raw text: a key pasted in
//  a comment is still a leaked key.
// --------------------------------------------------------------------------- //
const SUPA_CODE_EXT = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".py"];
const SUPA_SQL_EXT = [".sql"];
const SUPA_TEXT_EXT = [".md", ".json", ".yaml", ".yml", ".toml", ".txt"];

// Bundler prefixes that ship an env var to the browser. A service/secret key
// behind one of these is a critical leak of full database access.
const PUBLIC_ENV_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "PUBLIC_", "GATSBY_"];

const RE_SB_SECRET = /sb_secret_[A-Za-z0-9_-]{8,}/g;
const RE_PUBLIC_SERVICE = new RegExp(
  "\\b(?:" + PUBLIC_ENV_PREFIXES.join("|") + ")[A-Z0-9_]*(?:SERVICE_ROLE|SERVICE_KEY|SECRET_KEY|SB_SECRET)");
const RE_SERVICE_ROLE = /service[_-]?role/i;
const RE_JWT = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/g;
const RE_GRANT_WRITE = /\b(insert|update|delete|all|truncate|references|trigger)\b/i;

const SEV_LEVEL = { HIGH: "error", MEDIUM: "error", LOW: "warning" };

function supaKind(rel) {
  const low = rel.toLowerCase();
  const base = path.basename(low);
  if (GENERATED_RE.test(low)) return null;
  if (endsWithExt(low, SUPA_SQL_EXT)) return "sql";
  if (endsWithExt(low, SUPA_CODE_EXT)) return "code";
  if (base.startsWith(".env")) return "env";
  if (endsWithExt(low, SUPA_TEXT_EXT)) return "text";
  return null;
}

function blank(s) {
  return s.replace(/[^\n]/g, " ");
}

// Replace SQL comments with spaces (newlines kept so offsets/lines survive).
function stripSqlComments(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "-" && d === "-") {
      let j = src.indexOf("\n", i);
      if (j < 0) j = n;
      out.push(blank(src.slice(i, j)));
      i = j;
    } else if (c === "/" && d === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth) {
        if (src[j] === "/" && src[j + 1] === "*") { depth++; j += 2; }
        else if (src[j] === "*" && src[j + 1] === "/") { depth--; j += 2; }
        else j++;
      }
      out.push(blank(src.slice(i, j)));
      i = j;
    } else if (c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === "'") {
          if (src[j + 1] === "'") { j += 2; continue; }
          j++;
          break;
        }
        j++;
      }
      out.push(src.slice(i, j));
      i = j;
    } else if (c === '"') {
      let j = src.indexOf('"', i + 1);
      j = j < 0 ? n : j + 1;
      out.push(src.slice(i, j));
      i = j;
    } else {
      let j = i + 1;
      while (j < n && !"-/'\"".includes(src[j])) j++;
      out.push(src.slice(i, j));
      i = j;
    }
  }
  return out.join("");
}

// Replace JS/TS comments with spaces, leaving strings intact.
function stripJsComments(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      let j = src.indexOf("\n", i);
      if (j < 0) j = n;
      out.push(blank(src.slice(i, j)));
      i = j;
    } else if (c === "/" && d === "*") {
      let j = src.indexOf("*/", i + 2);
      j = j < 0 ? n : j + 2;
      out.push(blank(src.slice(i, j)));
      i = j;
    } else if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < n && src[j] !== c) {
        if (src[j] === "\\") j++;
        else if (c !== "`" && src[j] === "\n") break;
        j++;
      }
      j = Math.min(j + 1, n);
      out.push(src.slice(i, j));
      i = j;
    } else {
      let j = i + 1;
      while (j < n && !"/'\"`".includes(src[j])) j++;
      out.push(src.slice(i, j));
      i = j;
    }
  }
  return out.join("");
}

function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}

function lineAt(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

// Split (comment-stripped) SQL into statements on `;` outside string literals.
function splitSqlStatements(sql) {
  const starts = lineStarts(sql);
  const stmts = [];
  let begin = 0;
  let inStr = false;
  const push = (end) => {
    const raw = sql.slice(begin, end);
    const lead = raw.length - raw.trimStart().length;
    const text = raw.trim();
    if (text) {
      stmts.push({
        norm: text.replace(/\s+/g, " "),
        line: lineAt(starts, begin + lead),
        endLine: lineAt(starts, Math.max(begin + lead, end - 1)),
      });
    }
  };
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (c === "'") inStr = !inStr;
    else if (c === ";" && !inStr) {
      push(i);
      begin = i + 1;
    }
  }
  push(sql.length);
  return stmts;
}

const unquoteIdents = (s) => s.replace(/"([^"]*)"/g, "$1");

function shortTable(name) {
  return name.split(".").pop().toLowerCase();
}

// Tables that get RLS enabled anywhere in the given SQL texts.
function rlsEnabledTables(sqlTexts) {
  const set = new Set();
  const re = /^alter table (?:if exists )?(?:only )?([\w.]+) enable row level security/i;
  for (const text of sqlTexts) {
    for (const st of splitSqlStatements(stripSqlComments(text))) {
      const m = re.exec(unquoteIdents(st.norm));
      if (m) set.add(shortTable(m[1]));
    }
  }
  return set;
}

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function looksLikeSupabase(target, texts) {
  // Cheap heuristic: does this project use Supabase at all?
  try {
    if (fs.statSync(path.join(target, "supabase")).isDirectory()) return true;
  } catch {
    /* no supabase dir */
  }
  const pkg = readText(path.join(target, "package.json"));
  if (pkg && pkg.includes("@supabase/")) return true;
  for (const content of Object.values(texts)) {
    const low = content.toLowerCase();
    if (low.includes("supabase") || low.includes("createclient(")) return true;
  }
  return false;
}

function supaSecretRules(rel, raw, add) {
  const lines = raw.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const i = idx + 1;
    for (const m of line.matchAll(RE_SB_SECRET)) {
      if (isPlaceholder(m[0].slice("sb_secret_".length))) continue;
      add("HIGH", "secret-key", rel, i, i,
        "Hardcoded Supabase secret API key (sb_secret_...). Move it to a server-only env " +
        "var and rotate it - removing it from the file does not remove it from git history.");
    }
    for (const m of line.matchAll(RE_JWT)) {
      const payload = decodeJwtPayload(m[0]);
      const role = payload && payload.role;
      if (role === "service_role" || (!payload && RE_SERVICE_ROLE.test(line))) {
        const ref = payload && payload.ref ? ` for project ${payload.ref}` : "";
        const exp = payload && payload.exp
          ? `, expires ${new Date(payload.exp * 1000).toISOString().slice(0, 10)}` : "";
        add("HIGH", "service-role-jwt", rel, i, i,
          `Hardcoded Supabase service_role JWT${ref}${exp}. It bypasses all RLS - ` +
          "rotate it and load it from a server-only env var.");
      }
    }
  }
}

function supaCodeRules(rel, kind, raw, add) {
  // .env: drop comment lines; code: strip comments; strings kept.
  const code = kind === "env"
    ? raw.split(/\r?\n/).map((l) => (/^\s*#/.test(l) ? "" : l)).join("\n")
    : stripJsComments(raw);
  const clientExposed = kind === "code" && /^\s*['"]use client['"]/.test(code);
  const lines = code.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const i = idx + 1;
    if (RE_PUBLIC_SERVICE.test(line)) {
      add("HIGH", "public-service-key", rel, i, i,
        "service_role/secret key exposed through a browser-exposed env var " +
        "(NEXT_PUBLIC_/VITE_/REACT_APP_/...). This ships full DB access to the client.");
    }
    if (clientExposed && (RE_SERVICE_ROLE.test(line) || /SUPABASE_SECRET/.test(line))) {
      add("HIGH", "client-service-role", rel, i, i,
        "service_role referenced in a client-side ('use client') file. " +
        "The service role must never reach the browser.");
    }
  }
}

function supaSqlRules(rel, raw, rlsTables, add) {
  for (const st of splitSqlStatements(stripSqlComments(raw))) {
    const s = st.norm;
    const plain = unquoteIdents(s);

    if (/^alter table\b.*\bdisable row level security\b/i.test(plain)) {
      add("HIGH", "rls-disabled", rel, st.line, st.endLine,
        "Row Level Security disabled. The table becomes fully readable/writable " +
        "with the public anon key.");
      continue;
    }

    const gm = /^grant (.+?) on (.+?) to (.+?)(?: with grant option)?(?: granted by \S+)?$/i.exec(plain);
    if (gm) {
      const privs = gm[1].trim();
      const objects = gm[2].trim();
      const grantees = gm[3].split(",").map((g) => g.trim().toLowerCase());
      const exposed = grantees.filter((g) => g === "anon" || g === "public");
      if (exposed.length && !(/^schema\b/i.test(objects) && /^usage$/i.test(privs))) {
        const write = RE_GRANT_WRITE.test(privs);
        const fn = /^(function|procedure|routine)s?\b|^all (functions|procedures|routines)\b/i.test(objects);
        add(write ? "MEDIUM" : "LOW", "grant-anon", rel, st.line, st.endLine,
          fn
            ? `GRANT ${privs} on ${objects} to ${exposed.join(", ")}: callable over RPC by ` +
              "anyone - make sure the function checks auth itself."
            : `GRANT ${privs} on ${objects} to ${exposed.join(", ")}. Grants to anon/public ` +
              "expose data via the REST API; prefer RLS policies over broad grants.");
      }
      continue;
    }

    if (/^create policy\b/i.test(s)) {
      // Mask quoted identifiers so a policy NAME like "Admins to edit" can't
      // be mistaken for the TO clause; only look before USING/WITH CHECK.
      const masked = s.replace(/"[^"]*"/g, "_q_");
      const cut = masked.search(/\s(using|with check)\s*\(/i);
      const head = cut < 0 ? masked : masked.slice(0, cut);
      const tail = cut < 0 ? "" : masked.slice(cut);
      const tm = /\bto (.+)$/i.exec(head);
      const roles = tm ? tm[1].split(",").map((r) => r.trim().toLowerCase()) : [];
      if (roles.includes("service_role") || /'service_role'/i.test(tail)) {
        add("LOW", "policy-service-role", rel, st.line, st.endLine,
          "Policy targets service_role, which already bypasses RLS. Redundant and " +
          "harmless - safe to drop.");
      }
      continue;
    }

    const cm = /^create (?:(?:global|local) )?(?:unlogged )?table (?:if not exists )?([\w.]+)( partition of\b)?/i.exec(plain);
    if (cm && !cm[2]) {
      const parts = cm[1].split(".");
      const schema = parts.length > 1 ? parts[0].toLowerCase() : "public";
      if (schema === "public" && !rlsTables.has(shortTable(cm[1]))) {
        add("MEDIUM", "table-without-rls", rel, st.line, st.line,
          `Table '${cm[1]}' is in the exposed public schema and no migration enables Row ` +
          "Level Security on it. Add: alter table ... enable row level security; plus policies.");
      }
    }
  }
}

function scanSupabase(target, files, ctx) {
  // Return { skip } or { findings }. Read-only static scan for Supabase risks.
  const texts = {};
  for (const rel of files) {
    if (!supaKind(rel)) continue;
    const c = readText(path.join(target, rel));
    if (c !== null) texts[rel] = c;
  }
  if (!looksLikeSupabase(target, texts)) return { skip: "no Supabase usage detected in scope" };

  // RLS can be enabled in a later migration than the CREATE TABLE.
  const sqlTexts = ctx.allFiles
    .filter((f) => endsWithExt(f, SUPA_SQL_EXT))
    .slice(0, 5000)
    .map((f) => texts[f] ?? readText(path.join(target, f)))
    .filter((t) => t !== null);
  const rlsTables = rlsEnabledTables(sqlTexts);

  const seen = new Set();
  const findings = [];
  const add = (sev, id, rel, line, endLine, msg) => {
    const key = `${rel} ${line} ${id}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ file: rel, line, endLine, rule: `supabase/${id}`,
      message: `[${sev}] ${msg}`, level: SEV_LEVEL[sev], sev });
  };

  for (const [rel, content] of Object.entries(texts)) {
    const kind = supaKind(rel);
    supaSecretRules(rel, content, add);
    if (kind === "code" || kind === "env") supaCodeRules(rel, kind, content, add);
    if (kind === "sql") supaSqlRules(rel, content, rlsTables, add);
  }
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  findings.sort((a, b) => order[a.sev] - order[b.sev] ||
    (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  return { findings };
}

// --------------------------------------------------------------------------- //
//  Check specifications
//  level: "file" (runs on matching files) | "repo" (runs once if triggered)
//         | "deps" | "secrets" | "builtin"
//  mode:  how findings are classified new vs pre-existing (see isNew).
//  Every argv is READ-ONLY. Do not ever add fix/write flags here.
// --------------------------------------------------------------------------- //
function nodeEnv(ctx) {
  const cur = process.env.NODE_OPTIONS || "";
  if (/--max-old-space-size/.test(cur)) return null;
  return { NODE_OPTIONS: `${cur} --max-old-space-size=${ctx.heapMb}`.trim() };
}

// tsc --noEmit still writes .tsbuildinfo when the project is incremental
// (Next.js default). Turn that off, or redirect it to the temp dir when the
// project is composite (which forces incremental on).
function tscBuildInfoArgs(target, ctx) {
  const cfg = readText(path.join(target, "tsconfig.json")) || "";
  if (/"composite"\s*:\s*true/.test(cfg)) {
    return ["--tsBuildInfoFile", path.join(ctx.tmpDir, "qg.tsbuildinfo")];
  }
  return ["--incremental", "false"];
}

function buildSpecs() {
  return [
    // ---- Python ----
    {
      id: "ruff", title: "Ruff - lint", cat: "lint", lang: "python",
      level: "file", exts: PY_EXT, mode: "lines",
      resolve: () => globalBin("ruff"),
      argv: (e, f) => [e, "check", "--no-fix", "--force-exclude", "--output-format", "json", ...f],
      parse: parseRuff,
    },
    {
      id: "ruff-format", title: "Ruff - format check", cat: "format", lang: "python",
      level: "file", exts: PY_EXT, mode: "lines",
      format: ["ruff format", "ruff-format"],
      resolve: () => globalBin("ruff"),
      argv: (e, f) => [e, "format", "--check", "--force-exclude", ...f],
      parse: parseRuffFormat,
    },
    {
      id: "mypy", title: "mypy - types", cat: "types", lang: "python",
      level: "file", exts: PY_EXT, mode: "files",
      resolve: () => globalBin("mypy"),
      argv: (e, f) => [e, "--no-error-summary", ...f],
      parse: parseMypy,
    },
    {
      id: "bandit", title: "Bandit - security", cat: "security", lang: "python",
      level: "file", exts: PY_EXT, mode: "lines",
      resolve: () => globalBin("bandit"),
      argv: (e, f) => [e, "-q", "-ll", "-f", "json"].concat(
        f.length === 1 && f[0] === "." ? ["-r", "."] : [...f]),
      parse: parseBandit,
    },
    {
      id: "pip-audit", title: "pip-audit - dependencies", cat: "deps", lang: "python",
      level: "deps", detect: detectPyAudit,
    },

    // ---- JavaScript / TypeScript ----
    {
      id: "eslint", title: "ESLint - lint", cat: "lint", lang: "js",
      level: "file", exts: JS_EXT, mode: "lines", env: nodeEnv,
      resolve: (t) => localBin(t, "eslint"),
      argv: (e, f) => [e, "--no-error-on-unmatched-pattern", "-f", "json", ...f],
      parse: parseEslint,
    },
    {
      id: "prettier", title: "Prettier - format check", cat: "format", lang: "js",
      level: "file", exts: PRETTIER_EXT, mode: "lines", env: nodeEnv,
      format: ["prettier", "plugin:prettier", "eslint-plugin-prettier"],
      resolve: (t) => localBin(t, "prettier"),
      argv: (e, f) => [e, "--list-different", "--ignore-unknown", "--no-error-on-unmatched-pattern", ...f],
      parse: parsePrettier,
    },
    {
      id: "tsc", title: "TypeScript - types", cat: "types", lang: "js",
      level: "repo", trigger: ["tsconfig.json"], mode: "files", env: nodeEnv,
      resolve: (t) => localBin(t, "tsc"),
      argv: (e, _f, ctx) => [e, "--noEmit", "--pretty", "false", ...tscBuildInfoArgs(ctx.target, ctx)],
      parse: parseTsc,
    },
    {
      id: "npm-audit", title: "Dependency audit - JS", cat: "deps", lang: "js",
      level: "deps", detect: detectJsAudit,
    },

    // ---- Cross-cutting ----
    {
      id: "gitleaks", title: "Gitleaks - secrets", cat: "security", lang: "any",
      level: "secrets", resolve: () => globalBin("gitleaks"),
    },

    // ---- Supabase (built-in, no external tool required) ----
    {
      id: "supabase", title: "Supabase - security & RLS", cat: "security", lang: "any",
      level: "builtin", builtin: scanSupabase, mode: "lines",
    },
  ];
}

// Convert a simple glob (top-level only, e.g. "requirements*.txt") to a RegExp.
function globToRegExp(pattern) {
  let re = "";
  for (const ch of pattern) {
    if (ch === "*") re += "[^/]*";
    else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}

function repoTriggered(target, patterns) {
  let entries;
  try {
    entries = fs.readdirSync(target);
  } catch {
    entries = [];
  }
  for (const pat of patterns) {
    if (pat === "*") return true;
    if (!pat.includes("*") && !pat.includes("?")) {
      if (fs.existsSync(path.join(target, pat))) return true;
    } else {
      const re = globToRegExp(pat);
      if (entries.some((name) => re.test(name))) return true;
    }
  }
  return false;
}

// --------------------------------------------------------------------------- //
//  Running the deterministic checks
// --------------------------------------------------------------------------- //
function formatAdvisory(spec, target, ctx) {
  if (!spec.format) return null;
  if (ctx.formatMode === "enforce") return null;
  if (ctx.formatMode === "advisory") return "format checks set to advisory in config";
  return formatterEnforced(target, spec.format)
    ? null
    : "not enforced in this project (no hook, CI step or lint-staged entry runs it)";
}

function runToolCheck(spec, exe, target, files, scope, ctx) {
  let batches;
  let fileCount = 0;
  if (spec.level === "repo") {
    if (!repoTriggered(target, spec.trigger || ["*"])) {
      return result(spec, "SKIP", "not applicable to this project");
    }
    batches = [[]];
  } else if (ctx.scopeAll) {
    batches = [scope.only.length ? scope.only : ["."]];
  } else {
    const subset = files.filter((f) => endsWithExt(f, spec.exts));
    if (subset.length === 0) return result(spec, "SKIP", "no matching files in scope");
    fileCount = subset.length;
    batches = batchFiles(spec.argv(exe, [], ctx), subset, cmdLimit(exe));
  }

  const env = spec.env ? spec.env(ctx) : null;
  const findings = [];
  const command = batches.length > 1
    ? spec.argv(exe, ["<files>"], ctx).join(" ") + `  (${fileCount} files in ${batches.length} batches)`
    : spec.argv(exe, batches[0], ctx).join(" ");
  for (let i = 0; i < batches.length; i++) {
    const argv = spec.argv(exe, batches[i], ctx);
    const [rc, out, stdout, stderr] = run(argv, target, ctx.timeoutMs, null, env);
    const where = batches.length > 1 ? ` (batch ${i + 1}/${batches.length})` : "";
    if (typeof rc === "string") return result(spec, "ERROR", `${out}${where}`, out, command);
    const parsed = spec.parse(rc, stdout, stderr, out);
    if (parsed.skip) return result(spec, "SKIP", parsed.skip);
    // Every tool here exits non-zero only when it reports something, so a
    // non-zero exit with nothing parsed means the tool itself broke.
    const silent = rc !== 0 && !(parsed.findings || []).length;
    if (parsed.error || silent) {
      const why = parsed.error || crashReason(out) || `exited ${rc} without findings: ${firstLine(out)}`;
      return result(spec, "ERROR", `${why}${where}`, out.slice(0, 20000), command);
    }
    findings.push(...parsed.findings);
  }
  return finalize(spec, scope, findings, {
    command, advisory: formatAdvisory(spec, target, ctx), unit: "file",
  });
}

function runChecks(target, files, scope, disabled, ctx) {
  const results = [];
  for (const spec of buildSpecs()) {
    if (disabled.has(spec.id)) {
      results.push(result(spec, "OFF", "disabled in config"));
      continue;
    }

    if (spec.level === "builtin") {
      const parsed = spec.builtin(target, files, ctx);
      results.push(parsed.skip
        ? result(spec, "SKIP", parsed.skip)
        : finalize(spec, scope, parsed.findings, { command: "built-in Supabase static analysis" }));
      continue;
    }

    if (spec.level === "deps") {
      results.push(runDepsAudit(spec, target, scope, ctx));
      continue;
    }

    const exe = spec.resolve(target);
    if (!exe) {
      const where = spec.lang === "js" && spec.level !== "secrets" ? "in node_modules" : "on PATH";
      results.push(result(spec, "SKIP", `tool not available ${where}`));
      continue;
    }

    if (spec.level === "secrets") {
      results.push(runGitleaks(spec, exe, target, scope, ctx));
      continue;
    }

    results.push(runToolCheck(spec, exe, target, files, scope, ctx));
  }
  return results;
}

// --------------------------------------------------------------------------- //
//  AI review (optional, read-only, isolated)
//  Large diffs are split per file into chunks so the reviewer sees all of a
//  big branch instead of only its first 60k characters.
// --------------------------------------------------------------------------- //
// gitignore-style globs: "docs/**", "**/*.snap", "*.md" (no slash = any depth).
function globMatcher(patterns) {
  const res = (Array.isArray(patterns) ? patterns : []).map((p) => {
    const pat = String(p).trim().replace(/^\.?\//, "");
    if (!pat) return null;
    let re = "";
    for (let i = 0; i < pat.length; i++) {
      const c = pat[i];
      if (c === "*" && pat[i + 1] === "*") {
        if (pat[i + 2] === "/") { re += "(?:.*/)?"; i += 2; } else { re += ".*"; i += 1; }
      } else if (c === "*") re += "[^/]*";
      else if (c === "?") re += "[^/]";
      else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    if (pat.endsWith("/")) re += ".*";
    return new RegExp("^" + (pat.includes("/") ? "" : "(?:.*/)?") + re + "$", IS_WIN ? "i" : "");
  }).filter(Boolean);
  return (rel) => res.some((r) => r.test(rel));
}

// The diff the AI reads. Token savers: deleted files show only their header
// (--irreversible-delete), context lines and whitespace handling are
// configurable. A literal --range reads exactly those commits; final-state
// and normal scans read fork point -> working tree (latest version only).
function collectDiff(target, scope, ai) {
  const opts = ["--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
    "--irreversible-delete", "-M", `-U${ai.contextLines}`];
  if (ai.ignoreWhitespace) opts.push("--ignore-all-space");
  const head = scope.range && !scope.range.final
    ? ["diff", scope.range.from, scope.range.to]
    : diffArgs(scope);
  return git([...head, ...opts, ...pathspec(scope)], target).trim();
}

// Commit subjects for the reviewed change: cheap context about intent.
function commitContext(target, scope, max = 40) {
  if (scope.staged || !scope.fromRef || scope.fromRef === "HEAD") return "";
  const rev = scope.range ? `${scope.range.from}..${scope.range.to}` : `${scope.fromRef}..HEAD`;
  const lines = splitLines(git(["log", "--reverse", "--no-merges", "--format=%h %s", rev], target));
  if (!lines.length) return "";
  const shown = lines.length > max
    ? [...lines.slice(0, max / 2), `... ${lines.length - max} more commits ...`, ...lines.slice(-max / 2)]
    : lines;
  return shown.join("\n");
}

function planAiChunks(diff, maxChars, maxChunks, filter = {}) {
  const parts = diff.split(/^(?=diff --git )/m).map((p) => p.trim()).filter(Boolean);
  const files = [];
  const excluded = [];
  for (const text of parts) {
    const m = /^diff --git a\/.+? b\/(.+)$/m.exec(text);
    const file = m ? m[1] : "(unknown)";
    if (filter.keep && !filter.keep.has(keyOf(file))) continue;
    if (GENERATED_RE.test(file) || /^Binary files /m.test(text) || (filter.exclude && filter.exclude(file))) {
      excluded.push(file);
      continue;
    }
    files.push({ file, text, rank: endsWithExt(file, AI_CODE_EXT) ? 0 : 1 });
  }
  // Source code first; within a rank, keep a directory's files together.
  files.sort((a, b) => a.rank - b.rank || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));

  const chunks = [];
  let cur = { text: "", files: [] };
  for (const f of files) {
    let t = f.text;
    if (t.length > maxChars) t = t.slice(0, maxChars - 200) + "\n[... this file's diff truncated for review ...]";
    if (cur.files.length && cur.text.length + t.length + 1 > maxChars) {
      chunks.push(cur);
      cur = { text: "", files: [] };
    }
    cur.text += (cur.text ? "\n" : "") + t;
    cur.files.push(f.file);
  }
  if (cur.files.length) chunks.push(cur);

  const reviewed = chunks.slice(0, maxChunks);
  const skipped = chunks.slice(maxChunks).flatMap((c) => c.files);
  const chars = reviewed.reduce((n, c) => n + c.text.length, 0);
  return { chunks: reviewed, totalFiles: files.length, skipped, excluded, chars, allChunks: chunks.length };
}

// ~4 characters per token is a fair average for code diffs.
const approxTokens = (chars) => Math.round(chars / 4);

function fmtK(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n);
}

function aiReview(scannerDir, plan, runAll, timeoutMs, context = "") {
  const claude = globalBin("claude");
  if (!claude) {
    return [{ prompt: "review", status: "SKIP",
      output: "Claude CLI not found on PATH — AI review skipped." }];
  }
  if (!plan.chunks.length) {
    return [{ prompt: "review", status: "SKIP",
      output: "No diff in scope — nothing for AI to review." }];
  }

  const promptDir = path.join(scannerDir, ".quality", "prompts");
  let names = ["review"];
  if (runAll) {
    names = ["review", "security", "architecture", "performance", "business-logic", "supabase"];
  }

  const n = plan.chunks.length;
  process.stdout.write(`${C.dim}AI review: ${n} part(s) x ${names.length} reviewer(s) = ` +
    `${n * names.length} claude call(s), ~${fmtK(approxTokens(plan.chars) * names.length)} ` +
    `diff tokens in...${C.end}\n`);
  const intent = context
    ? "\n\nCommits in this change (subjects only, for intent):\n" + context + "\n"
    : "";

  const reviews = [];
  // Run Claude in a throwaway directory so it has NOTHING in the target to touch.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qg-"));
  try {
    for (const name of names) {
      const pf = path.join(promptDir, `${name}.md`);
      let instructions;
      try {
        if (!fs.statSync(pf).isFile()) continue;
        instructions = fs.readFileSync(pf, "utf8");
      } catch {
        continue;
      }
      for (let i = 0; i < n; i++) {
        const part = n > 1
          ? `\n\nThis is part ${i + 1} of ${n} of a larger change, split by file. Review ` +
            "only what is shown; do not speculate about files you cannot see.\n"
          : "";
        const full =
          instructions +
          "\n\n---\nYou are operating in READ-ONLY review mode. Do not attempt " +
          "to modify, create, or run anything — only report findings." + part + intent +
          "\n\nHere is the unified diff to review:\n\n```diff\n" +
          plan.chunks[i].text + "\n```\n";
        const [rc, out] = run([claude, "-p"], tmp, timeoutMs, full);
        reviews.push({
          prompt: n > 1 ? `${name} (part ${i + 1}/${n})` : name,
          status: rc === 0 ? "PASS" : "ERROR",
          files: plan.chunks[i].files,
          output: out || "(no output)",
        });
      }
    }
  } finally {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best effort cleanup */
    }
  }

  if (reviews.length === 0) {
    reviews.push({ prompt: "review", status: "SKIP",
      output: `No prompt files found in ${promptDir}.` });
  }
  if (plan.skipped.length || plan.excluded.length) {
    const lines = [];
    if (plan.skipped.length) {
      lines.push(`Reviewed ${plan.totalFiles - plan.skipped.length} of ${plan.totalFiles} files. ` +
        `${plan.skipped.length} file(s) were NOT reviewed - raise --ai-max-chunks or narrow with --only:`);
      for (const f of plan.skipped.slice(0, 200)) lines.push(`  ${f}`);
      if (plan.skipped.length > 200) lines.push(`  ... and ${plan.skipped.length - 200} more`);
    }
    if (plan.excluded.length) {
      lines.push(`${plan.excluded.length} lockfile/generated/binary/ai_exclude file(s) left out on purpose:`);
      for (const f of plan.excluded.slice(0, 50)) lines.push(`  ${f}`);
      if (plan.excluded.length > 50) lines.push(`  ... and ${plan.excluded.length - 50} more`);
    }
    reviews.push({ prompt: "coverage", status: plan.skipped.length ? "PARTIAL" : "PASS",
      output: lines.join("\n") });
  }
  return reviews;
}

// --------------------------------------------------------------------------- //
//  Reporting
// --------------------------------------------------------------------------- //
const STATUS_ICON = {
  PASS: "PASS", FINDINGS: "FIND", INFO: "info", SKIP: "skip",
  ERROR: "ERR ", OFF: "off ",
};

function statusColor(status) {
  return ({
    PASS: C.ok, FINDINGS: C.bad, INFO: C.cyan, ERROR: C.warn,
    SKIP: C.dim, OFF: C.dim,
  })[status] || "";
}

const isQuiet = (r) => r.status === "SKIP" || r.status === "OFF";

function skippedSummary(checks) {
  const groups = new Map();
  for (const r of checks.filter(isQuiet)) {
    const why = r.note || r.status.toLowerCase();
    if (!groups.has(why)) groups.set(why, []);
    groups.get(why).push(r.id);
  }
  return [...groups].map(([why, ids]) => `${ids.join(", ")} (${why})`);
}

function aiGroups(reviews) {
  const groups = new Map();
  for (const rv of reviews) {
    const base = rv.prompt.replace(/ \(part \d+\/\d+\)$/, "");
    if (!groups.has(base)) groups.set(base, []);
    groups.get(base).push(rv.status);
  }
  return groups;
}

function printConsole(meta, checks, reviews) {
  const P = (s) => process.stdout.write(s + "\n");
  P("");
  P(`${C.bold}${C.cyan}MarketInk Quality Gate${C.end}  ${C.dim}(read-only scanner)${C.end}`);
  P(`${C.dim}target : ${meta.target}${C.end}`);
  P(`${C.dim}scope  : ${meta.scope}  - files in scope: ${meta.file_count}${C.end}`);
  P(`${C.dim}filter : ${meta.filter}${C.end}`);
  P(`${C.dim}time   : ${meta.time}${C.end}`);
  P("-".repeat(60));

  for (const r of checks.filter((c) => !isQuiet(c))) {
    const color = statusColor(r.status);
    const label = STATUS_ICON[r.status] || r.status;
    let line = `  ${color}[${label}]${C.end}  ${r.title}`;
    if (r.note) line += `  ${C.dim}- ${r.note}${C.end}`;
    P(line);
  }
  for (const s of skippedSummary(checks)) P(`  ${C.dim}[skip]  ${s}${C.end}`);

  if (reviews.length) {
    P("");
    P(`  ${C.cyan}AI review${C.end}`);
    for (const [name, statuses] of aiGroups(reviews)) {
      const bad = statuses.filter((s) => s === "ERROR").length;
      const st = bad ? "ERROR" : statuses[0];
      const color = st === "PASS" ? C.ok : st === "ERROR" || st === "PARTIAL" ? C.warn : C.dim;
      const parts = statuses.length > 1 ? `  ${C.dim}(${statuses.length} parts${bad ? `, ${bad} failed` : ""})${C.end}` : "";
      P(`  ${color}[${st.toLowerCase().padEnd(4)}]${C.end}  claude -${name}${parts}`);
    }
  }

  P("-".repeat(60));
  const count = (s) => checks.filter((r) => r.status === s).length;
  P(`  ${C.ok}${count("PASS")} passed${C.end}  - ` +
    `${C.bad}${count("FINDINGS")} with new findings${C.end}  - ` +
    `${C.cyan}${count("INFO")} info${C.end}  - ` +
    `${C.warn}${count("ERROR")} errors${C.end}  - ` +
    `${C.dim}${checks.filter(isQuiet).length} skipped${C.end}`);
  if (meta.report_path) {
    P(`  ${C.dim}full report: ${meta.report_path}${C.end}`);
  }
  P(`  ${C.dim}This scanner made no changes to your code.${C.end}`);
  P("");
}

function buildMarkdown(meta, checks, reviews) {
  const lines = [];
  lines.push("# Quality Gate Report");
  lines.push("");
  lines.push(`- **Target:** \`${meta.target}\``);
  lines.push(`- **Scope:** ${meta.scope} (${meta.file_count} files)`);
  lines.push(`- **Filter:** ${meta.filter}`);
  lines.push(`- **Generated:** ${meta.time}`);
  lines.push(`- **Mode:** read-only scan — no files were modified`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Check | Category | Status | Note |");
  lines.push("|---|---|---|---|");
  for (const r of checks.filter((c) => !isQuiet(c))) {
    lines.push(`| ${r.title} | ${r.category} | ${r.status} | ${(r.note || "").replace(/\|/g, "\\|")} |`);
  }
  lines.push("");
  const skipped = skippedSummary(checks);
  if (skipped.length) {
    lines.push(`**Skipped:** ${skipped.join("; ")}`);
    lines.push("");
  }

  const section = (r) => {
    lines.push(`### ${r.title} — ${r.status}`);
    if (r.command) lines.push(`\`${r.command}\``);
    lines.push("");
    const body = (r.output || "(no output)").split(/\r?\n/).slice(0, 500).join("\n");
    lines.push("```");
    lines.push(body);
    lines.push("```");
    lines.push("");
  };

  const detail = checks.filter((r) => r.status === "FINDINGS" || r.status === "ERROR");
  if (detail.length) {
    lines.push("## Details");
    lines.push("");
    detail.forEach(section);
  }
  const info = checks.filter((r) => r.status === "INFO");
  if (info.length) {
    lines.push("## Informational (pre-existing, warnings or advisory)");
    lines.push("");
    for (const r of info) {
      lines.push("<details>");
      lines.push(`<summary>${r.title} — ${r.note || "info"}</summary>`);
      lines.push("");
      section(r);
      lines.push("</details>");
      lines.push("");
    }
  }

  if (reviews.length) {
    lines.push("## AI Review");
    lines.push("");
    for (const rv of reviews) {
      lines.push(`### Claude - ${rv.prompt} - ${rv.status}`);
      lines.push("");
      if (rv.files && rv.files.length > 1) {
        lines.push(`<details><summary>${rv.files.length} files in this part</summary>\n\n` +
          rv.files.map((f) => `- \`${f}\``).join("\n") + "\n</details>\n");
      }
      lines.push(rv.output);
      lines.push("");
    }
  }

  return lines.join("\n");
}

// --------------------------------------------------------------------------- //
//  Timestamp helpers (local time, mirroring datetime.strftime)
// --------------------------------------------------------------------------- //
function pad2(n) {
  return String(n).padStart(2, "0");
}

function stampHuman(d) {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function stampFile(d) {
  return `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}-` +
    `${pad2(d.getHours())}${pad2(d.getMinutes())}${pad2(d.getSeconds())}`;
}

// --------------------------------------------------------------------------- //
//  Main
// --------------------------------------------------------------------------- //
// --plan-batches N: split the branch's commits into groups of N and print each
// group's size and AI cost estimate plus a ready command. Makes no AI calls.
function planBatches(target, scope, size, ai, cmdBase) {
  const P = (s) => process.stdout.write(s + "\n");
  if (!scope.fromRef || scope.fromRef === "HEAD") {
    P("error: no base branch found - pass --base (e.g. --base origin/master).");
    return 2;
  }
  const commits = splitLines(git(["rev-list", "--reverse", "--first-parent", `${scope.fromRef}..HEAD`], target));
  if (!commits.length) {
    P(`No commits between the fork point ${scope.fromRef.slice(0, 8)} and HEAD.`);
    return 0;
  }
  const final = ai.final;
  const fullDiff = final ? collectDiff(target, { ...scope, range: null }, ai) : null;

  const rows = [];
  for (let i = 0; i < commits.length; i += size) {
    const group = commits.slice(i, i + size);
    const from = i === 0 ? scope.fromRef : commits[i - 1];
    const to = group[group.length - 1];
    const s = { ...scope, range: { from, to, final } };
    const files = changedFiles(target, s);
    const diff = final ? fullDiff : collectDiff(target, s, ai);
    const plan = planAiChunks(diff, ai.chunkChars, Number.MAX_SAFE_INTEGER,
      { keep: final ? new Set(files.map(keyOf)) : null, exclude: ai.exclude });
    rows.push({ n: rows.length + 1, from, to, commits: group.length, files: files.length, plan });
  }

  const total = rows.reduce((n, r) => n + approxTokens(r.plan.chars), 0);
  P("");
  P(`${C.bold}Review plan${C.end}  ${C.dim}${commits.length} commits since fork point ` +
    `${scope.fromRef.slice(0, 8)} (${scope.base || "base"}), batches of ${size}, ` +
    `${final ? "final-state (each file once, latest version)" : "literal ranges (each commit's own diff)"}${C.end}`);
  P("-".repeat(78));
  P("  #   range                 commits  files  AI parts  ~diff tokens (per reviewer)");
  for (const r of rows) {
    const range = `${r.from.slice(0, 8)}..${r.to.slice(0, 8)}`;
    P(`  ${String(r.n).padEnd(3)} ${range.padEnd(21)} ${String(r.commits).padStart(7)}  ` +
      `${String(r.files).padStart(5)}  ${String(r.plan.allChunks).padStart(8)}  ` +
      `${fmtK(approxTokens(r.plan.chars)).padStart(12)}`);
  }
  P("-".repeat(78));
  P(`  total ~${fmtK(total)} diff tokens per reviewer (x6 with --ai-full). ` +
    `Parts above ai_max_chunks (${ai.maxChunks}) are not reviewed - see each report's coverage entry.`);
  if (!final) {
    P(`  ${C.dim}Tip: literal ranges re-review code that later commits rewrite. ` +
      `--final-state reviews each file once.${C.end}`);
  }
  P("");
  P("Run the free deterministic checks once for the whole branch:");
  P(`  ${cmdBase} --no-ai --out quality-reports/branch`);
  P("Then AI-review one batch at a time (read each report before the next):");
  for (const r of rows) {
    P(`  ${cmdBase} --range ${r.from.slice(0, 10)}..${r.to.slice(0, 10)}` +
      `${final ? " --final-state" : ""} --ai-only --out quality-reports/batch-${String(r.n).padStart(2, "0")}`);
  }
  P("");
  return 0;
}

const HELP = `usage: node scan.js [options]

Read-only quality scanner. Never modifies your code.

  --path PATH          repo to scan (default: current dir)
  --all                scan the whole project, not just changes
  --staged             scan only git-staged changes
  --base REF           git base ref for the diff (default: auto)
  --only PATH          limit the scan to a path (repeatable)
  --include-existing   count findings on lines you did not change too
  --range A..B         review only the commits in A..B (B defaults to HEAD)
  --final-state        with --range: review the latest version of files those
                       commits touched, each file once across batches
  --plan-batches N     print N-commit batches with token estimates + commands
                       (no scanning, no AI calls)
  --no-ai              skip the AI review
  --ai-only            skip the deterministic checks, run only the AI review
  --ai-full            run all specialized AI reviewers
  --ai-max-chunks N    max diff parts sent to each AI reviewer (default: 10)
  --no-report          print only; write no files
  --out DIR            report output dir (default: ./quality-reports)
  --strict             exit 1 if new findings (for optional CI)
  --timeout SEC        per-tool timeout in seconds (default: 600)
  -h, --help           show this help and exit
`;

function positiveInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

function main(argv) {
  let args;
  try {
    ({ values: args } = parseArgs({
      args: argv,
      options: {
        help: { type: "boolean", short: "h", default: false },
        path: { type: "string", default: "." },
        all: { type: "boolean", default: false },
        staged: { type: "boolean", default: false },
        base: { type: "string" },
        only: { type: "string", multiple: true, default: [] },
        "include-existing": { type: "boolean", default: false },
        range: { type: "string" },
        "final-state": { type: "boolean", default: false },
        "plan-batches": { type: "string" },
        "ai-only": { type: "boolean", default: false },
        "no-ai": { type: "boolean", default: false },
        "ai-full": { type: "boolean", default: false },
        "ai-max-chunks": { type: "string" },
        "no-report": { type: "boolean", default: false },
        out: { type: "string" },
        strict: { type: "boolean", default: false },
        timeout: { type: "string", default: "600" },
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

  const timeoutMs = positiveInt(args.timeout, 600) * 1000;

  const target = path.resolve(args.path);
  TARGET = target;
  const scannerDir = __dirname;
  try {
    if (!fs.statSync(target).isDirectory()) throw new Error("not a dir");
  } catch {
    process.stderr.write(`error: path not found: ${target}\n`);
    return 2;
  }

  // Optional config (fully optional; safe defaults if absent).
  let cfg = {};
  const cfgPath = path.join(scannerDir, "quality-gate.config.json");
  try {
    if (fs.statSync(cfgPath).isFile()) cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) || {};
  } catch {
    // a broken config must never break the scan
  }
  const disabled = new Set(cfg.disabled_checks || []);
  const baseArg = args.base ?? cfg.base_ref ?? null;

  const gitRepo = isGitRepo(target);
  const scopeAll = args.all || !gitRepo;
  if (!gitRepo && !args.all) {
    process.stdout.write(`${C.warn}note: not a git repository - scanning the whole project.${C.end}\n`);
  }

  const only = args.only.map((o) => toRel(o)).filter((o) => o && o !== ".");
  const fail = (msg) => {
    process.stderr.write(`error: ${msg}\n`);
    return 2;
  };
  const wantsRange = args.range || args["plan-batches"];
  if (wantsRange && !gitRepo) return fail("--range / --plan-batches need a git repository");
  if (wantsRange && (args.all || args.staged)) return fail("--range / --plan-batches can't be combined with --all or --staged");
  if (args["final-state"] && !wantsRange) return fail("--final-state only applies with --range or --plan-batches");
  if (args["ai-only"] && args["no-ai"]) return fail("--ai-only and --no-ai cancel each other out");

  let base = null;
  let fromRef = null;
  if (gitRepo && !scopeAll && !args.staged) {
    if (baseArg && !gitOk(["rev-parse", "--verify", "--quiet", baseArg], target)) {
      return fail(`base ref not found: ${baseArg} (try: git fetch origin)`);
    }
    base = resolveBase(target, baseArg);
    fromRef = base ? mergeBase(target, base) || base : "HEAD";
  }

  let range = null;
  if (args.range) {
    const idx = args.range.indexOf("..");
    if (idx <= 0 || args.range.includes("...")) {
      return fail(`--range must look like A..B (two dots), got: ${args.range}`);
    }
    const m = [null, args.range.slice(0, idx), args.range.slice(idx + 2)];
    const resolve = (r) => git(["rev-parse", "--verify", "--quiet", `${r}^{commit}`], target).trim();
    const from = resolve(m[1]);
    const to = resolve(m[2] || "HEAD");
    if (!from) return fail(`range start not found: ${m[1]}`);
    if (!to) return fail(`range end not found: ${m[2]}`);
    range = { from, to, final: args["final-state"] };
    // Without a base branch, treat the range start as the fork point.
    if (!fromRef || fromRef === "HEAD") fromRef = from;
  }

  const scope = {
    target, staged: args.staged, base, fromRef, only, range,
    filter: !scopeAll && !args["include-existing"],
    lines: new Map(), changed: new Set(), changedRel: [],
  };

  const ai = {
    contextLines: Number.isInteger(cfg.ai_context_lines) && cfg.ai_context_lines >= 0 ? cfg.ai_context_lines : 3,
    ignoreWhitespace: cfg.ai_ignore_whitespace === true,
    exclude: globMatcher(cfg.ai_exclude),
    chunkChars: positiveInt(cfg.ai_chunk_chars, 60000),
    maxChunks: positiveInt(args["ai-max-chunks"] ?? cfg.ai_max_chunks, 10),
    commitContext: cfg.ai_commit_context !== false,
    final: args["final-state"],
  };

  if (args["plan-batches"]) {
    const q = (s) => (/[\s"]/.test(s) ? `"${s}"` : s);
    const cmdBase = [`node ${q(path.join(scannerDir, "scan.js"))}`, `--path ${q(target)}`,
      base ? `--base ${q(base)}` : "", ...only.map((o) => `--only ${q(o)}`)].filter(Boolean).join(" ");
    return planBatches(target, scope, positiveInt(args["plan-batches"], 10), ai, cmdBase);
  }

  const allFiles = projectFiles(target, gitRepo);
  let files;
  let scopeDesc;
  if (scopeAll) {
    files = allFiles.filter((f) => underOnly(scope, f));
    scopeDesc = "whole project";
  } else {
    files = changedFiles(target, scope);
    if (range) {
      const count = splitLines(git(["rev-list", "--count", `${range.from}..${range.to}`], target))[0] || "?";
      scopeDesc = `commits ${range.from.slice(0, 8)}..${range.to.slice(0, 8)} (${count} commits` +
        `${range.final ? ", final state, files not already covered by earlier batches" : ""})`;
    } else {
      scopeDesc = args.staged
        ? "staged changes"
        : base
          ? `changed vs ${base}${fromRef !== base ? ` (fork point ${fromRef.slice(0, 8)})` : ""}`
          : "uncommitted changes (no base branch found)";
    }
    // Always fork point -> working tree, so line numbers match the files the
    // tools read; in a --range this means "new in the branch".
    scope.lines = changedLineMap(target, { ...scope, range: null });
  }
  if (only.length) scopeDesc += `, only ${only.join(", ")}`;
  if (args["ai-only"]) scopeDesc += " - AI review only (deterministic checks skipped)";
  scope.changedRel = files;
  scope.changed = new Set(files.map(keyOf));

  const ctx = {
    target, gitRepo, scopeAll, timeoutMs, allFiles,
    heapMb: positiveInt(cfg.node_max_old_space_mb, 8192),
    formatMode: cfg.format_checks || "auto",
    tmpDir: fs.mkdtempSync(path.join(os.tmpdir(), "qg-run-")),
  };

  let checks;
  let reviews = [];
  try {
    checks = args["ai-only"] ? [] : runChecks(target, files, scope, disabled, ctx);

    if (!args["no-ai"]) {
      if (scopeAll) {
        reviews = [{ prompt: "review", status: "SKIP",
          output: "AI review is diff-based; use a scoped scan (not --all) for AI." }];
      } else {
        // Final-state reads the whole branch diff; keep only this batch's files.
        const keep = range && range.final ? scope.changed : null;
        const plan = planAiChunks(collectDiff(target, scope, ai), ai.chunkChars, ai.maxChunks,
          { keep, exclude: ai.exclude });
        const context = ai.commitContext ? commitContext(target, scope) : "";
        reviews = aiReview(scannerDir, plan, args["ai-full"], timeoutMs, context);
      }
    }
  } finally {
    try {
      fs.rmSync(ctx.tmpDir, { recursive: true, force: true });
    } catch {
      /* best effort cleanup */
    }
  }

  const now = new Date();
  const meta = {
    target,
    scope: scopeDesc,
    file_count: files.length,
    base, fork_point: fromRef && fromRef !== "HEAD" ? fromRef : null,
    range: range ? { from: range.from, to: range.to, final_state: !!range.final } : null,
    filter: scope.filter
      ? "new findings only (pre-existing ones listed as info; --include-existing to count them)"
      : "all findings",
    time: stampHuman(now),
    report_path: null,
  };

  // Write report (the only thing this tool ever writes).
  if (!args["no-report"]) {
    const outDir = args.out ? path.resolve(args.out) : path.join(process.cwd(), "quality-reports");
    try {
      fs.mkdirSync(outDir, { recursive: true });
      const stamp = stampFile(now) +
        (range ? `-range-${range.from.slice(0, 8)}-${range.to.slice(0, 8)}` : "");
      const md = buildMarkdown(meta, checks, reviews);
      fs.writeFileSync(path.join(outDir, `report-${stamp}.md`), md, "utf8");
      fs.writeFileSync(path.join(outDir, "latest.md"), md, "utf8");
      fs.writeFileSync(
        path.join(outDir, "latest.json"),
        JSON.stringify({ meta, checks, reviews }, null, 2),
        "utf8");
      meta.report_path = path.join(outDir, "latest.md");
    } catch (exc) {
      process.stdout.write(`${C.warn}note: could not write report (${exc.message}); printing only.${C.end}\n`);
    }
  }

  printConsole(meta, checks, reviews);

  if (args.strict && checks.some((r) => r.status === "FINDINGS")) {
    return 1;
  }
  return 0;
}

process.exit(main(process.argv.slice(2)));

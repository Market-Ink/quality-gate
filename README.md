# MarketInk Quality Gate

The **organisation-wide quality baseline** for MarketInk projects. It does two
kinds of review and produces one report:

1. **Deterministic checks.** Your existing linters, type checker, secret
   scanner, dependency audit and a built-in Supabase check. They run in
   check-only mode, are free, and run on every commit.
2. **A function-level AI review.** The tool works out *which functions changed
   and who calls them anywhere in the project*. Claude then checks those
   facts against a fixed rule catalog, and the tool **verifies every quoted
   line** against the real files before a finding is accepted. This runs on
   every pull request.

It is one Node script (`scan.js`) plus small helpers in `lib/`, with **zero
required npm dependencies**. The official Anthropic SDK is an *optional* extra
that CI installs into the tool's own folder. It is **read-only**: it never
edits code, never changes git state, never installs anything into your project.

**Cost and trust features:**
- **Pay once per function.** A per-function review cache means re-pushes
  re-review only the functions that changed.
- **Cheaper calls.** In CI, calls go through the SDK with prompt caching,
  optionally via the Batches API at half price.
- **Bounded spend.** Risk-ordered token budgets cap each run.
- **Learns from reviewers.** Inline AI comments collect 👍/👎. A weekly job
  turns them into **per-rule precision**, and rules that are often wrong are
  demoted to advisory automatically.

> **This README is the one and only doc.** Setup, CI/CD, configuration, the AI
> review, the rule catalog and troubleshooting are all below.

---

## Table of contents

1. [What it is & safety guarantees](#1-what-it-is--safety-guarantees)
2. [How it fits together](#2-how-it-fits-together)
3. [What it runs](#3-what-it-runs)
4. [Requirements & setup](#4-requirements--setup)
5. [Quick start & daily usage](#5-quick-start--daily-usage)
6. [Options / flags](#6-options--flags)
7. [The AI review: changed functions, verified evidence](#7-the-ai-review-changed-functions-verified-evidence)
8. [Rule catalog](#8-rule-catalog)
9. [Configuration: org baseline + project `.quality-gate.json`](#9-configuration-org-baseline--project-quality-gatejson)
10. [CI/CD with GitHub Actions](#10-cicd-with-github-actions)
11. [The merge gate (`--fail-on`)](#11-the-merge-gate---fail-on)
12. [Reading the report (Markdown, JSON, SARIF)](#12-reading-the-report-markdown-json-sarif)
13. [Big branches: scope, feature groups, batches](#13-big-branches-scope-feature-groups-batches)
14. [Supabase checks](#14-supabase-checks)
15. [Local git hooks](#15-local-git-hooks)
16. [Troubleshooting](#16-troubleshooting)
17. [Cheat sheet](#17-cheat-sheet)
18. [Versioning, migration & roadmap](#18-versioning-migration--roadmap)
19. [Cost controls: backends, cache, budgets, batches](#19-cost-controls-backends-cache-budgets-batches)
20. [Trust: inline feedback, rule precision, auto-demotion](#20-trust-inline-feedback-rule-precision-auto-demotion)

---

## 1. What it is & safety guarantees

| Layer | Owns | Runs | Cost |
|---|---|---|---|
| **Deterministic tools** | Anything mechanical: lint, types, formatting, secrets, vulnerable dependencies, Supabase anti-patterns | Every commit (CI push), pre-commit / pre-push hooks, locally | Free |
| **Function-level AI review** | What a careful human reviewer catches: null handling, ignored errors, missing `await`, caller/callee contract breaks, flow bugs, wasted I/O, obvious security holes | Every PR update (CI), or locally on demand | Cents per PR (see §10) |

The AI review is **deliberately narrow**. It does not judge business intent,
product decisions, naming or style, and it may only report a problem that
matches a rule in the [catalog](#8-rule-catalog), with quoted proof.

**It is 100% read-only.**

- ✅ **Never edits, formats or fixes your code.** Every tool runs in check-only
  mode (`ruff check --no-fix`, `prettier --list-different`, `pnpm audit`,
  `gitleaks git`, …). `tsc` runs with `--incremental false`, so it can't drop a
  `.tsbuildinfo` into your repo.
- ✅ **Never changes git state.** No add, commit, push, checkout or worktree.
- ✅ **Never installs anything.** It runs only the tools a project already has.
  The impact analysis borrows the project's own `typescript` package.
- ✅ **The AI gets no tools.** Through the SDK, a call is a plain
  `messages.create` with no tools defined. Through the CLI, `claude -p` runs
  with `--tools "" --restricted --strict-mcp-config` in an empty temp folder.
  Either way it can't read, write or run anything; it only sees the packets the
  tool built.
- ✅ **Writes nothing outside the reports and caches.** Besides the reports, the
  only writes are the review cache (`~/.cache/marketink-quality-gate`) and, in
  CI, the Actions caches. None of them are in the repo.
- ✅ **Can't break a build unless you ask it to.** A missing tool is `SKIP`.
  Exit code is `0` unless the gate configured with `--fail-on` / `gate.fail_on`
  is hit.
- ✅ **Zero-touch on the scanned project.** The only files it writes are the
  reports (Markdown, JSON, SARIF) in the folder you choose, or none with
  `--no-report`.

---

## 2. How it fits together

```
                       ┌──────────────── org: marketink/quality-gate (tag v2) ────────────────┐
                       │  scan.js · lib/impact.js · rules/catalog.json · baselines/marketink   │
                       │  .github/workflows/quality-gate.yml  (reusable workflow)              │
                       └───────────────────────────────┬───────────────────────────────────────┘
                                                       │ extends / uses @v2
                ┌──────────────────────────────────────┴───────────────────────────────┐
                │ each project repo                                                     │
                │   .quality-gate.json        → rules on/off, gate, context files, ...  │
                │   .github/workflows/quality-gate.yml  → 15 lines calling the org one  │
                └──────────────────────────────────────┬───────────────────────────────┘
                                                       │
   every push ──► deterministic checks on what the push changed ─────────► SARIF + report
   every PR   ──► deterministic checks on the PR  +  function-level AI review
                     │
                     ├─ diff ──► changed functions (parsed with the project's TypeScript)
                     ├─ impact ─► callers in ANY file · callee signatures · strictNullChecks
                     ├─ Claude ─► JSON findings, each with a rule id + quoted lines
                     └─ verify ─► quote exists in the file? location reviewed? rule enabled?
                                     │                       │
                                     ▼                       ▼
                            PR comment + SARIF        merge gate (fail-on)
```

---

## 3. What it runs

| Check | Tool | Mode | Scope |
|---|---|---|---|
| Lint (JS/TS) | `eslint` | read-only, JSON output | changed files |
| Format (JS/TS) | `prettier --list-different` | read-only; advisory unless enforced | changed files |
| Types (JS/TS) | `tsc --noEmit --incremental false` | read-only | project; errors split by changed files |
| Dependencies (JS/TS) | `pnpm` / `yarn` / `bun` / `npm audit` (picked from the lockfile) | read-only | project |
| Lint / format / types / security (Python) | `ruff`, `ruff format --check`, `mypy`, `bandit` | read-only | changed files |
| Dependencies (Python) | `pip-audit` | read-only | project |
| Secrets | `gitleaks git` | read-only, secrets never printed | **the change's commits** + working tree (`--all`: full history) |
| Supabase (RLS / keys / grants) | *built-in* | read-only | changed code + `.sql` (RLS state read from all migrations) |
| **AI review** | `claude -p` (no tools) | read-only | **changed functions + their callers anywhere** (TS/JS) |

**Built to be trusted on big repos:**

- **A crashed tool is reported as `ERROR`, never `FINDINGS`.** "Command line is
  too long", Node out-of-memory, exit code 2, a missing config, or an audit that
  couldn't run all show the tool failing, with the reason.
- **Long file lists are batched** to stay under the Windows `cmd.exe`
  8,191-character limit.
- **JS tools get a bigger heap** (`node_max_old_space_mb`, default 8192).
- **Only files git tracks are scanned.** `.next/`, `.env.local` and other
  ignored files never show up, and neither does the gate's own vendored copy
  (`.quality-gate/`, `.quality-gate-tool/`).
- **New vs pre-existing.** On a scoped scan, findings on lines you didn't change
  are listed as info and never blamed on your change (§13).

---

## 4. Requirements & setup

**Node.js 18+** (20+ recommended). No `npm install` for the tool itself.

Checks are optional and auto-detected; install what a project uses:

| Tool | Where it must live | Why |
|---|---|---|
| `eslint`, `prettier`, `typescript` | **Inside the project** (`devDependencies`) | Read from the project's `node_modules`. `typescript` also powers the AI review's impact analysis |
| `ruff`, `mypy`, `bandit`, `pip-audit` | On `PATH` (global or venv) | Python projects |
| `gitleaks` | On `PATH` | Secrets, any project (CI installs it for you) |
| `claude` (Claude Code CLI) | On `PATH` | AI review. Locally it uses your Claude login; in CI it uses the `ANTHROPIC_API_KEY` secret |

```bash
npm install -D eslint prettier typescript      # JS/TS projects, inside the project
winget install gitleaks.gitleaks               # Windows  (brew install gitleaks on macOS)
npm install -g @anthropic-ai/claude-code       # AI review
```

### One-word command (recommended)

**Windows (PowerShell `$PROFILE`):**
```powershell
function qg { node E:\MarketInk\Quality_Gate\quality-gate\scan.js @args }
```
**macOS / Linux:**
```bash
qg() { node /path/to/quality-gate/scan.js "$@"; }
```
Wrappers also ship: `quality.ps1` (Windows) and `./quality` (macOS/Linux).

---

## 5. Quick start & daily usage

```bash
qg                       # changed files vs your base branch + AI review of changed functions
qg --no-ai               # free deterministic checks only
qg --path ../service     # scan another repo without touching it
qg --all --no-ai         # whole-project audit
```

**Reports land in the folder you run from** (`./quality-reports/`), not inside
the scanned project, unless you pass `--out`.

| I want to… | Command |
|---|---|
| **Daily driver**: my changes + AI review | `qg` |
| Fast, no AI | `qg --no-ai` |
| Only what's staged | `qg --staged` |
| A whole feature branch vs master | `git fetch origin` then `qg --base origin/master` |
| One module at a time | `qg --base origin/master --only src/billing` |
| Every rule, including the off-by-default ones | `qg --ai-full` |
| The previous diff-based AI review | `qg --ai-mode diff` |
| Fail like CI would | `qg --fail-on deterministic` |
| Also write SARIF | `qg --sarif out/gate.sarif` |
| Review a big branch per feature (`Group-Id`) | `qg --base origin/master --plan-groups` |
| Review a big branch 10 commits at a time | `qg --base origin/master --plan-batches 10 --final-state` |
| Count issues that were already there | `qg --include-existing` |
| Use another config file | `qg --config path/to/.quality-gate.json` |

---

## 6. Options / flags

```
--path PATH          repo to scan (default: current directory)
--config FILE        project config (default: <path>/.quality-gate.json, else the
                     org baseline)
--all                scan the whole project (disables AI)
--staged             scan only git-staged changes
--base REF           base ref (default: origin/HEAD, origin/main, origin/master, ...)
--only PATH          limit files, findings and diff to a path; repeatable
--include-existing   count findings on lines you did NOT change as well
--range A..B         only the commits in A..B (B defaults to HEAD)
--final-state        with --range: latest version of the files, each file once
--plan-batches N     print N-commit batches + token estimates (no scan, no AI)
--plan-groups        print Group-Id feature groups + estimates (no scan, no AI)
--group ID           review one feature group
--no-ai              skip the AI review
--ai-only            skip deterministic checks; AI review only
--ai-mode MODE       functions (default) | diff (previous diff-based review)
--ai-full            functions mode: enable every rule; diff mode: 6 reviewers
--ai-max-chunks N    max AI calls per reviewer (default 10)
--fail-on LEVEL      none | deterministic | blocking | any  (exit 1 when hit)
--strict             same as --fail-on deterministic
--ai-backend B       auto (default) | sdk (Anthropic SDK + API key) | cli (claude CLI)
--ai-batch           send the AI review through the Batches API (-50%, slower)
--no-cache           don't reuse cached per-function reviews
--cache-dir DIR      review cache folder (default ~/.cache/marketink-quality-gate)
--rule-stats FILE    per-rule precision (from lib/feedback.js); demotes weak rules
--no-move-detection  treat code moved unchanged from the base as new (skip git blame -C)
--sarif FILE         also write SARIF 2.1.0 to FILE
--no-report          print only; write no files
--out DIR            report directory (default: ./quality-reports)
--timeout SEC        per-tool timeout (default 600)
```

**Exit codes:** `0` = ran and the gate passed (or no gate). `1` = the
`--fail-on` gate was hit. `2` = bad input: a missing path, a missing `--base`
ref (`git fetch origin` usually fixes it), an invalid flag value, or a broken
config file.

---

## 7. The AI review: changed functions, verified evidence

### Why it works this way

A reviewer that reads only diff hunks has to guess: it can't see the guard two
files away, the test setup that blocks the network, or the DB default that
fixes the "bug". The function review removes the guessing in three steps:

1. **The tool computes the facts.** `lib/impact.js` loads the project's own
   `typescript` package (in a child process with its own heap) and, for every
   changed TS/JS file:
   - maps each changed line to the **function** it belongs to (methods, arrow
     functions, React components, nested functions; the outermost one under
     `max_body_lines`);
   - takes the **new body** (line-numbered) and the **old body**;
   - finds **every caller in the whole project**, including files that aren't
     in the diff, with a few lines of context each;
   - resolves the **signatures of everything it calls** (so `T | null` returns
     are visible);
   - reads the compiler settings (e.g. **strictNullChecks ON/OFF**) and states
     them as facts.
2. **Claude checks those facts against a fixed list.** It gets the packets, the
   [rule catalog](#8-rule-catalog), the project's `CLAUDE.md`/`AGENTS.md` (as
   authoritative decisions) and the commit subjects (as intent only). It must
   answer in JSON (`--json-schema`). Every finding needs a **rule id**, a
   **location in the packets**, a **concrete failure scenario** and **quoted
   evidence**. Anything it can't decide from the code shown goes into
   **Questions**, not findings.
3. **The tool verifies before it reports.** A finding is **rejected** when:
   - its rule isn't enabled for this project;
   - its `file:line` isn't inside the code that was reviewed (a changed function
     or a caller snippet);
   - **any** quoted line doesn't exist in the real file within ±3 lines of the
     cited line. A quote can also be a resolved callee signature, which is a
     compiler fact;
   - it has no quote anchored to a real code line.

   Rejected findings are listed (collapsed) in the report with the reason, so
   you can see what was filtered out.

### What it will and won't report

| ✅ Reports (with proof) | ❌ Never reports |
|---|---|
| A caller in an untouched file that now dereferences a `null` the change introduced | "This business flow might be wrong" |
| `{ data, error }` used without checking `error` | Naming, formatting, comments, style |
| A promise that isn't awaited where the result matters | Test hygiene, refactors no rule asks for |
| A retry path that can send a message twice | Decisions documented in `CLAUDE.md` / context files |
| An `await` inside a loop over a large collection | Anything it can't quote |

### Example (from the test suite)

`findUser()` was changed to return `null` instead of throwing. `src/ui/banner.ts`
was **not in the diff**, but impact analysis found it as a caller:

```
#### [MEDIUM] NULL-02 — greeting reads .name on findUser's result, which can now be null
src/ui/banner.ts:4 in greeting · Caller does not handle a null the changed function can now return
Evidence (verified against the file):
- src/lib/users.ts:7 — if (!u) return null;
- src/ui/banner.ts:4 — return "Hi " + findUser(id).name;
```

### Coverage & limits
- **Language:** TS/JS (`.ts .tsx .js .jsx .mjs .cjs`). If the project has no
  `typescript` in `node_modules`, the review falls back to the diff-based review
  (`--ai-mode diff`) and says so.
- **Skipped by default:** tests, mocks, stories, `.d.ts`, e2e (`review.skip_paths`).
  The deterministic checks still scan them.
- **Big changes:** at most `max_functions` (80) functions and `ai_max_chunks`
  (10) calls per run; anything over is listed in the report's notes.
- **Callers:** up to `max_callers` (8) per function are shown; the total count is
  always given.
- **Monorepos:** each changed file uses its nearest `tsconfig.json` /
  `jsconfig.json`.
- **Not yet:** the AI review only runs on scoped scans (not `--all`), and
  Python files only get the diff-based review.

### Moved code is pre-existing, not new

Refactors move code: a page's logic extracted into `lib/data/*`, a function
moved to another module. Git shows every moved line as *added*, which would
make old issues look like the refactor's fault. The gate runs **move
detection** (`git blame -w -C -M` from the fork point on files with ≥ 20
changed lines) and marks lines **copied unchanged from code that existed at
the base**:
- Each packet tells the reviewer which ranges are **new or edited** and which
  are **moved unchanged** (pre-existing). The prompt forbids blaming moved
  code on the change.
- A finding counts as **new** only if its location or one of its quoted lines
  is a new or edited line. Findings that rest entirely on moved (or untouched)
  code go to a separate **Pre-existing** section: still reported, never
  posted inline, never in SARIF, never gating.
- Deterministic checks use the same rule: a lint or type error on a moved line
  is pre-existing.
- `review.moved_code: "skip"` doesn't review functions that are 100% moved
  code at all (cheapest for big refactors). `--no-move-detection` turns the
  whole thing off.
- Measured on a real 6-commit extraction: 4,921 changed lines in 15 files
  recognised as moved, in about a minute.

### Grounding: schema facts, decisions, unverified fixes
- **Schema facts.** The gate parses the SQL migrations (`create type … as
  enum`, `alter type … add value`, `CHECK (col IN (…))`, `= ANY (ARRAY[…])`)
  into the allowed values of each column. Packets that use a column get its
  values as **SCHEMA FACTS**, so a literal like `'contacted'` that isn't in
  `leads.status` is caught, and suggested fixes use real values. Schema facts
  are accepted as evidence. Archived/backup migration folders are ignored
  (`review.schema_exclude` adds more).
- **Project decisions** (§9) are sent as authoritative context, and the prompt
  rates severity against them. For example, if an ADR says every user may see
  every location, a missing location filter is a display bug, not an
  authorization bypass.
- **Runtime behaviour that isn't shown** (how PostgREST, the database or a
  library reacts to some input) must go to *Questions*, not findings.
- **Suggested fixes are labelled "not verified by the tool".** The evidence
  check proves the problem's quotes exist. It can't prove a fix is right.

**Risk ordering.** Functions are reviewed riskiest first. Risk goes up with:
- callers outside the diff;
- being exported;
- living in API, worker, lib, db or auth paths;
- being modified rather than new;
- the size of the change.

When a call cap or the token budget is hit, it's the lower-risk functions that
get skipped, and the report lists them.

**Type errors in impacted callers count.** If `tsc` (or `mypy`) reports an
error in a file that **calls a changed function**, that error is counted as
**new**, even though the file is outside the diff. A changed return type that
breaks an untouched caller fails `--fail-on deterministic`. This also works with
`--no-ai`: the impact analysis runs on its own whenever `tsc` has errors outside
the changed files (`review.impact_for_types`).

---

## 8. Rule catalog

`rules/catalog.json` (version `1.0.0`). The reviewer may report **only** these
ids. Projects can switch rules or whole groups on or off, and add their own
(§9).

| Id | Group | Default severity | What it catches |
|---|---|---|---|
| NULL-01 | null-safety | medium | A value the packet shows can be null/undefined is dereferenced without a guard |
| NULL-02 | null-safety | high | A caller doesn't handle a null/partial result the changed function can now return |
| ERR-01 | errors | medium | Error swallowed: catch ignores/only logs and continues as success |
| ERR-02 | errors | high | A returned error (`{ data, error }`, `{ ok:false }`, non-2xx) is ignored and data used |
| ERR-03 | errors | medium | Throw vs return-error contract changed under callers |
| ASYNC-01 | async | high | Missing `await` where the result, ordering or failure matters |
| ASYNC-02 | async | medium | Floating promise / unhandled rejection |
| ASYNC-03 | async | medium | Stale state used after an `await` (wrong target after a concurrent change) |
| CONTRACT-01 | contracts | high | Call doesn't match the (changed) signature or return shape |
| CONTRACT-02 | contracts | medium | New behaviour contradicts an assumption a caller visibly relies on |
| FLOW-01 | flow | medium | Inverted/incomplete condition, unreachable branch, unhandled state |
| FLOW-02 | flow | high | Early exit skips cleanup / a status update (e.g. stuck in "sending") |
| FLOW-03 | flow | high | Side effect can run twice on retry / redelivery / double submit |
| FLOW-04 | flow | medium | Off-by-one / boundary / empty-first-last case |
| PERF-01 | performance | medium | Sequential I/O inside a loop over a large collection |
| PERF-02 | performance | low | Repeated expensive work that can be hoisted or memoized |
| QUALITY-01 | quality | low | Re-implements logic an existing function in the packet already provides |
| QUALITY-02 | quality | low | **Off by default.** Function mixes responsibilities in a way that makes a named bug likely |
| QUALITY-03 | quality | low | Dead code introduced |
| SEC-01 | security | high | Untrusted input reaches a query / HTML / shell / path / redirect unvalidated |
| SEC-02 | security | high | Handler reads/writes by id without the auth check its siblings do |
| SEC-03 | security | medium | Secrets / tokens / personal data in logs, errors or responses |

**Severity:** high = data loss, wrong data written, security, crash in a common
path; medium = wrong behaviour in a realistic edge case; low = minor and
contained. Only findings at or above `review.min_severity` (default `medium`)
go to the PR comment, SARIF and the gate. Lower ones are listed as "minor" in
the report.

**Changing the catalog** is an org decision: edit `rules/catalog.json` by PR,
bump its `version`, and tag a new tool release.

---

## 9. Configuration: org baseline + project `.quality-gate.json`

### Layering

```
built-in defaults
  └─ baselines/marketink.json          org baseline (in this repo, versioned by tag)
       └─ <project>/.quality-gate.json  "extends": "marketink"  + project overrides
            └─ --config FILE            (optional; replaces the project file)
                 └─ CLI flags           (--fail-on, --ai-mode, --base, ...)
```

- **Objects merge key by key; arrays and scalars replace.** For example, a
  project's `review.skip_paths` replaces the baseline list.
- **No `.quality-gate.json`?** The org baseline applies as-is.
- **Comments:** keys starting with `_` are ignored. Unknown keys print a
  "typo?" warning.
- **`extends`** takes a baseline name (`"marketink"` → `baselines/marketink.json`)
  or a relative path (`"../shared/qg.json"`). Chains up to 5 deep are allowed.
- **The report shows which files were used:** `Config: quality-gate/baselines/marketink.json → .quality-gate.json`.
- The pre-2.0 `quality-gate.config.json` next to `scan.js` is still read (lowest
  priority) with a deprecation warning.

### Project file example (`examples/quality-gate.json`)

```json
{
  "extends": "marketink",
  "disabled_checks": [],
  "gate": { "fail_on": "deterministic", "ai_blocking_rules": [] },
  "review": {
    "rules": {
      "disable": [],
      "enable": [],
      "custom": [
        { "id": "PRJ-01", "title": "Supabase query result not checked",
          "check": "A supabase-js call's { error } is ignored and its data is used.",
          "severity": "high" }
      ]
    },
    "context_files": ["CLAUDE.md", "docs/decisions.md"],
    "min_severity": "medium"
  }
}
```

### Key reference

**Top level**

| Key | Default (baseline) | Meaning |
|---|---|---|
| `extends` | — | Baseline name or relative path to inherit from |
| `base_ref` | `null` | Base ref for scoped scans; `null` = auto-detect |
| `disabled_checks` | `[]` | Check ids never to run: `eslint prettier tsc npm-audit gitleaks supabase ruff ruff-format mypy bandit pip-audit` |
| `node_max_old_space_mb` | `8192` | Heap for eslint/prettier/tsc **and the impact analysis** |
| `format_checks` | `"auto"` | `auto`: formatter findings only if a hook/CI/lint-staged enforces it; `enforce`; `advisory` |

**`gate`** (see §11)

| Key | Default | Meaning |
|---|---|---|
| `gate.fail_on` | `"none"` | `none` / `deterministic` / `blocking` / `any` |
| `gate.ai_blocking_rules` | `[]` | AI rule ids that fail the gate under `blocking` (e.g. `["FLOW-03","SEC-01"]`) |

**`review`** (function-level AI review)

| Key | Default | Meaning |
|---|---|---|
| `review.mode` | `"functions"` | `functions` or `diff` (previous diff-based review) |
| `review.model` | `null` | Model passed to `claude --model` (null = the CLI's default) |
| `review.rules.enable` | `[]` | Extra rule ids **or groups** to turn on (e.g. `"QUALITY-02"`) |
| `review.rules.disable` | `[]` | Rule ids or groups to turn off (e.g. `"performance"`) |
| `review.rules.custom` | `[]` | Project rules: `{ "id", "title", "check", "severity" }` |
| `review.context_files` | `["CLAUDE.md","AGENTS.md","docs/adr/*.md","docs/decisions/*.md"]` | Authoritative project context. **Plain paths** are always sent (up to `context_file_chars` each). **Globs** form a decision library: every doc's **Decision section** is sent in brief (`context_doc_summary_chars` each); leftover budget goes to the full text of the docs most related to the code |
| `review.context_chars` | `60000` | Total context budget per call (prompt-cached on the SDK backend) |
| `review.context_file_chars` / `context_doc_chars` / `context_doc_summary_chars` | `24000` / `6000` / `700` | Caps per pinned file / per full library doc / per decision brief |
| `review.move_detection` / `move_detection_min_lines` | `true` / `20` | Treat code moved unchanged from the base as pre-existing (§7) |
| `review.moved_code` | `"classify"` | `classify`: review moved code, report its findings as pre-existing · `skip`: don't review 100%-moved functions |
| `review.schema_facts` / `schema_exclude` | `true` / `[]` | Allowed column values from SQL migrations; extra globs of SQL to ignore |
| `review.skip_paths` | tests, mocks, stories, e2e, `.d.ts` | Globs never sent to the AI review |
| `review.max_functions` | `80` | Max functions reviewed per run |
| `review.max_callers` | `8` | Caller snippets shown per function |
| `review.max_callees` | `20` | Callee signatures shown per function |
| `review.max_body_lines` | `200` | Longer functions are sent as excerpts around the changed lines |
| `review.caller_context_lines` | `4` | Lines of context around each call site |
| `review.min_severity` | `"medium"` | Lowest severity that reaches the PR comment, SARIF and the gate |
| `review.timeout_sec` | `600` | Per-call timeout |
| `review.backend` | `"auto"` | `auto`: SDK when `ANTHROPIC_API_KEY` + `@anthropic-ai/sdk` are available, else the `claude` CLI · `sdk` · `cli` (§19) |
| `review.effort` | `"high"` | SDK only: `low` / `medium` / `high` / `xhigh` / `max`. Lower is cheaper |
| `review.fallbacks` | `true` | SDK only: server-side refusal fallbacks (`fallbacks: "default"`) |
| `review.concurrency` | `4` | SDK only: parallel calls |
| `review.batch` | `"never"` | `never` / `auto` (Batches API when ≥ `batch_min_calls` calls) / `always` |
| `review.batch_min_calls` / `batch_wait_sec` | `6` / `1800` | Batch threshold; how long to wait for a batch |
| `review.cache` / `cache_dir` / `cache_days` | `true` / `~/.cache/marketink-quality-gate` / `30` | Per-function review cache (§19) |
| `review.max_input_tokens` | `400000` | Per-run input-token budget; lowest-risk functions are skipped beyond it |
| `review.rule_stats` | `null` | Path to a precision file (CI passes it automatically, §20) |
| `review.precision` | `{min_samples:10, demote_below:0.5, promote_above:0.85}` | When a rule is demoted / marked eligible to block |
| `review.impact_for_types` | `true` | Count `tsc`/`mypy` errors in callers of changed functions as new |

**AI sizing and big-branch keys** (both modes)

| Key | Default | Meaning |
|---|---|---|
| `ai_max_chunks` | `10` | Max AI calls per run |
| `ai_chunk_chars` | `60000` | Max characters of packets/diff per call |
| `ai_exclude` | `[]` | Globs the diff-mode AI never reads |
| `ai_context_lines` | `3` | Diff context lines (diff mode) |
| `ai_ignore_whitespace` | `false` | Drop whitespace-only changes (diff mode) |
| `ai_commit_context` | `true` | Send commit subjects as intent |
| `group_trailer` | `"Group-Id"` | Commit trailer naming a feature group (§13) |
| `group_message_chars` | `8000` | Commit-message budget per group (diff mode) |
| `group_hub_files` | `[]` | Globs that never link unlabelled commits |

### `CLAUDE.md`: the project's decisions

`CLAUDE.md` (and anything in `review.context_files`) is sent to the reviewer as
**authoritative**: documented decisions are intentional and are not reported as
problems. Keep it to concrete "always/never" rules and decisions, for example
"D-24: media-upload.ts uses the system upload path by design". A template ships
at `.quality/standards/CLAUDE.template.md`.

---

## 10. CI/CD with GitHub Actions

### Set up a project (once)

1. **Add the workflows.** Copy `examples/github/quality-gate.yml` to
   `.github/workflows/quality-gate.yml` in the project. Also copy
   `examples/github/quality-gate-feedback.yml`, the weekly precision job (§20).
   The main one:
   ```yaml
   on: [push, pull_request]
   jobs:
     quality-gate:
       uses: sarthakkk1212/quality-gate/.github/workflows/quality-gate.yml@v2
       permissions: { contents: read, pull-requests: write, security-events: write }
       with: { tool-ref: v2, ai: pull_request }
       secrets:
         ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
   ```
2. **Add the config.** Copy `examples/quality-gate.json` to `.quality-gate.json`
   and adjust it.
3. **Secrets.** Add `ANTHROPIC_API_KEY` as an **org secret** (CI can't use a
   Claude Team/Pro login; it bills per token to the org API account). Without it
   the AI review is skipped and everything else still runs. If the
   quality-gate repo is private, also add `QUALITY_GATE_TOKEN` (a token that can
   read it).
4. **Repo settings.** Actions → General → Workflow permissions → **Read and
   write** (for the PR comment). SARIF upload needs code scanning, which on
   private repos requires GitHub Advanced Security; without it that step is
   skipped and nothing else fails.

### What runs when

| Event | Base | Deterministic checks | AI review |
|---|---|---|---|
| `push` (any branch) | the push's previous commit (`github.event.before`), else the default branch | ✅ on what this push changed | ❌ (unless `ai: always`) |
| `pull_request` (opened / updated) | `origin/<PR base branch>` | ✅ on the whole PR | ✅ changed functions + callers |

On PRs with the AI review, the job also:
- installs `@anthropic-ai/sdk` **into the tool folder** (never the project) and
  calls Claude through it (`--ai-backend sdk`);
- restores and saves the **per-function review cache** (`actions/cache`, keyed
  per branch), so each new push pays only for changed functions;
- restores the latest **rule-precision stats** written by the feedback workflow
  and passes them with `--rule-stats`;
- posts each verified AI finding as an **inline review comment** asking for
  👍/👎 (deduplicated by fingerprint across pushes).

Every run:
- uploads **SARIF**: findings appear inline on the PR diff and in Security →
  Code scanning, matched across runs by stable fingerprints;
- uploads the **report artifact** (`latest.md`, `latest.json`, `latest.sarif`);
- **comments on the PR** once and updates the same comment on each run (gate
  verdict, check table, top AI findings, token usage);
- **enforces the gate last**, after the uploads, so a failed gate still leaves
  the full report.

### Reusable workflow inputs

| Input | Default | Meaning |
|---|---|---|
| `tool-ref` | `v2` | Tool version (tag) to run. Keep it equal to the `@v2` in `uses:` |
| `tool-repo` | `sarthakkk1212/quality-gate` | Where the tool lives |
| `base` | auto | Override the base ref |
| `ai` | `pull_request` | `never` / `pull_request` / `always` |
| `fail-on` | from `.quality-gate.json` | `none` / `deterministic` / `blocking` / `any` |
| `working-directory` | `.` | Project folder (monorepos) |
| `node-version` | `20` | Node for the tool and the project's tools |
| `gitleaks-version` | `8.30.1` | Gitleaks release installed on the runner |
| `upload-sarif` | `true` | Upload to code scanning |
| `comment` | `true` | Post / update the PR comment |
| `inline-comments` | `true` | Post each verified AI finding inline with a 👍/👎 request |
| `ai-batch` | `false` | Use the Batches API (half price, slower) |

The job installs the project's dependencies from its lockfile (pnpm, yarn or
npm), so `eslint`/`prettier`/`typescript` come from the project itself.

### Cost in CI

See §19 for all the cost controls. In short:
- **Deterministic checks:** free.
- **AI review:** a measured 2-function change took **~8k tokens (~$0.04–0.09)**.
  A re-push with no change to those functions costs **0 tokens** (cache hit).
- **Real numbers:** `latest.json → meta.ai_usage` and the PR comment show the
  actual tokens and estimated cost of every run.
- **`concurrency: cancel-in-progress`** in the example caller stops paying for
  runs that a newer push replaced.

### Recommended rollout
1. **Week 1–2:** `fail_on: "none"`. Watch the PR comments and the
   rejected-by-evidence counts.
2. **Then:** `fail_on: "deterministic"`. Lint/type/secret/audit/Supabase
   findings that your change introduced block the merge.
3. **Then:** `fail_on: "blocking"` with the AI rules your team trusts in
   `ai_blocking_rules`. Start with rules the precision table marks
   **eligible-to-block** (§20), e.g. `FLOW-03`, `SEC-01`, `ERR-02`.

---

## 11. The merge gate (`--fail-on`)

| Level | Exit 1 when |
|---|---|
| `none` (default) | never |
| `deterministic` | any deterministic check has **new** findings (status `FINDINGS`) |
| `blocking` | `deterministic`, **or** a verified AI finding (at `min_severity`+) whose rule is in `gate.ai_blocking_rules` |
| `any` | `deterministic`, **or** any verified AI finding at `min_severity`+ |

Set it in `.quality-gate.json` (`gate.fail_on`), in the workflow (`fail-on:`),
or on the CLI (`--fail-on`, or `--strict` for `deterministic`). Pre-existing
issues (§13) never trip the gate. The report and console show the gate's
result.

---

## 12. Reading the report (Markdown, JSON, SARIF)

Every run writes to `quality-reports/` (or `--out`):

| File | For |
|---|---|
| `latest.md` + `report-<timestamp>.md` | People. **Read this one** |
| `latest.json` | Automation: `{ meta, checks, reviews }`. `meta.ai_review` holds the verified findings, rejected findings, questions and impacted files; `meta.ai_usage` holds tokens; `meta.gate` holds the gate result |
| `latest.sarif` | GitHub code scanning / any SARIF viewer (also `--sarif FILE`) |

**Check statuses**

| Status | Meaning |
|---|---|
| **PASS** | Ran, nothing found |
| **FINDINGS** | Ran, found issues **your change introduced** |
| **INFO** | Only pre-existing issues, warnings, or an advisory check (e.g. an unenforced formatter) |
| **SKIP** | Tool not installed or nothing in scope (folded into one line) |
| **ERROR** | The *tool* failed (crash, OOM, timeout, missing config/lockfile), not your code |
| **OFF** | Disabled in config |

**AI review section**
- **Header:** functions reviewed, verified findings, rejected count, rule-catalog
  version, and **impacted files outside the diff**.
- **Each finding:** severity, rule, `file:line`, scenario, the **verified
  evidence** (quoted lines) and the fix.
- **Collapsed sections:** minor findings, **Questions** (things the reviewer
  couldn't decide from the code; not findings) and **Rejected by the evidence
  check**, with the reason for each.
- **AI usage:** a per-call token table (input, cache write, cache read, output,
  time, ~USD at API list price). On a Claude Pro/Max/Team login, calls count
  against plan limits instead.

**SARIF details:** rule ids are `<check>/<rule>` for deterministic findings
(e.g. `eslint/no-unused-vars`, `supabase/secret-key`) and `ai/<RULE>` for AI
findings. Only **new** findings are included. Each result has a
`partialFingerprints["qualityGate/v1"]` built from the rule, file and the
line's text, so GitHub tracks it across runs even when lines move.

---

## 13. Big branches: scope, feature groups, batches

### How scope is decided
- **Default:** changed files vs the base branch's **fork point** (`git
  merge-base`) up to your working tree. That covers every commit on the branch
  plus uncommitted and untracked work, and ignores what landed on master after
  you branched.
- **`--all`:** everything git tracks. **`--staged`:** the index only.
  **No git:** `--all`.

### How "new" is decided
- **Line-level tools** (ESLint, Ruff, Bandit, Supabase, Prettier): new when it's
  on a line you changed. Moved-but-unchanged files are pre-existing, and so are
  lines moved unchanged into other files (move detection, §7).
- **AI review:** new when the finding's location or a quoted line is new or
  edited; findings resting only on moved/untouched code are listed as
  pre-existing.
- **`tsc` / `mypy`:** new when it's in a file you changed. Errors in untouched
  files are listed as "outside changed files". A changed signature *can* break
  an untouched caller, so read that list. The AI review's NULL-02 /
  CONTRACT-01 rules look at those callers directly.
- **Dependency audit:** new only if the lockfile or a dependency field changed.
- **Gitleaks:** only the change's commits are scanned, so everything it reports
  is new.
- **`--include-existing`** counts everything.

### Feature groups (`Group-Id` trailers)

Tag commits with the feature they belong to:
```
Inbox 5i: window escape hatch

...body...

Group-Id: conversations-inbox
```
```powershell
qg --base origin/master --plan-groups                    # groups, files, ~tokens, warnings, commands (free)
qg --base origin/master --no-ai --out quality-reports/branch
qg --base origin/master --group conversations-inbox --ai-only --out quality-reports/group-conversations-inbox
```
- **What a group reviews:** only its files, at their final version. In function
  mode, the group's commit subjects are sent as intent. In diff mode
  (`--ai-mode diff`), its full messages are sent as claims to verify.
- **Commits without a trailer** are grouped by shared files (`ungrouped-N`),
  ignoring hub files (`package.json`, lockfiles, `group_hub_files`, files
  touched by more than 30% of commits).
- **Merge commits** are reviewed only for their conflict resolutions
  (`git show --remerge-diff`).
- **`Group-Id: a, b`** puts a commit in both groups.
- **The plan warns about:** commits without a trailer, single-commit groups,
  files changed by 3+ groups, and groups over `ai_max_chunks`.

### Commit batches
```powershell
qg --base origin/master --plan-batches 10 --final-state      # plan + commands (free)
qg --base origin/master --range <a>..<b> --final-state --ai-only --out quality-reports/batch-01
```
- **`--final-state`** reviews each file once, at its latest version.
- **A literal `--range`** reviews exactly those commits' diffs, so code that
  was rewritten later gets reviewed again.

### Saving tokens
- `review.skip_paths` / `ai_exclude`
- `--only src/module`
- A cheaper `review.model`
- Fewer, larger calls (`ai_chunk_chars`)
- In diff mode, also `ai_context_lines: 1` and `ai_ignore_whitespace: true`

Deleted files send only their name; lockfiles, minified files, maps and
binaries are never sent.

---

## 14. Supabase checks

Supabase exposes every `public` table over a REST API, protected by Row Level
Security, and the `service_role` key bypasses RLS. The built-in `supabase`
check (no install needed; auto-detected) scans changed code and SQL migrations:

| It flags | Severity |
|---|---|
| A `service_role`/secret key behind a browser-exposed env var (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, …) | HIGH |
| A hardcoded `sb_secret_…` key, or a JWT whose payload says `"role": "service_role"` (decoded; project ref + expiry shown) | HIGH |
| `service_role` referenced in a `'use client'` file | HIGH |
| `alter table … disable row level security` | HIGH |
| A public-schema `create table` that no migration ever enables RLS on | MEDIUM |
| `grant <write> … to anon/public` | MEDIUM |
| `grant <read>/execute … to anon/public` | LOW |
| A policy targeting `service_role` (redundant) | LOW |

**How it avoids false positives:**
- Comments are stripped before the semantic rules run.
- SQL is matched per statement.
- RLS state is collected across all migrations.
- Non-public schemas are ignored.
- Placeholders like `YOUR_…`, `xxxx` and `${…}` are ignored.

The anon key in client code is **not** flagged; it's designed to be public.

---

## 15. Local git hooks

CI is the enforcement layer. Hooks give fast local feedback before code leaves
a laptop.

```powershell
.\hooks\install-hooks.ps1 -Repo C:\path\to\project      # Windows
./hooks/install-hooks.sh /path/to/project               # macOS/Linux
```

The installer works entirely inside the target repo:
1. It vendors `scan.js`, `lib/`, `rules/`, `baselines/` and the prompts into
   `.quality-gate/`. The gate never scans this folder.
2. It creates `.quality-gate.json` from the example, if the project has none.
3. It installs `pre-commit` (staged, no AI) and `pre-push` (vs base, no AI unless
   `QG_AI=1`) into `.githooks/`.
4. It sets `git config core.hooksPath .githooks` and ignores `quality-reports/`.

Commit `.githooks .quality-gate .quality-gate.json .gitignore`. Each teammate
runs `git config core.hooksPath .githooks` once per clone, because git never
auto-enables hooks.

- `QG_BLOCK=1` blocks on findings.
- `QG_AI=1` adds the AI review on push.
- `--no-verify` bypasses a hook.

---

## 16. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `note: typescript is not installed … using the diff review instead` | The project has no `typescript` in `node_modules` (or deps weren't installed in CI) | `npm i -D typescript`; in CI check the "Install project dependencies" step |
| AI review: `no changed TS/JS source files` | Only tests, docs or skipped paths changed | Expected; adjust `review.skip_paths` to review tests |
| Many findings **rejected by the evidence check** | The model quoted code that isn't there, or pointed outside the reviewed code | Working as intended. If a rejected finding was correct, check that the code was in the packet (e.g. raise `max_callers`, `max_body_lines`) |
| Impact analysis `failed: Node ran out of memory` | Very large program | Raise `node_max_old_space_mb` |
| AI review skipped in CI | No `ANTHROPIC_API_KEY` secret, a `push` event (AI runs on PRs), or `ai: never` | Add the org secret; use `ai: always` to review pushes too |
| `ai backend 'sdk' requested but @anthropic-ai/sdk is not installed` | Local run with `--ai-backend sdk` | `npm install` in the quality-gate folder (optional dependency), or use `--ai-backend cli` |
| `ai backend 'sdk' requested but ANTHROPIC_API_KEY is not set` | SDK backend needs an API key | Set the key, or `--ai-backend cli` to use your Claude login |
| `request declined by safety classifiers` | A rare refusal on code that resembles exploits | Fallbacks are on by default; the call shows as ERROR and other calls continue |
| `batch … still processing after Ns` | The Batches API hasn't finished | Raise `review.batch_wait_sec`, or drop `--ai-batch` for PR runs |
| Cached reviews look stale | Rules, prompt, context files, model or effort changed | They're part of the cache key, so a change invalidates automatically; `--no-cache` forces a fresh review |
| Inline AI comments missing | The finding is in a file/line outside the PR diff (e.g. an impacted caller), or the token can't write | It's still in the summary comment and SARIF; check workflow permissions |
| Precision table empty | The feedback workflow hasn't run yet, or there are no reactions | Run "Quality Gate feedback" manually (`workflow_dispatch`) |
| Type errors suddenly count as new | They're in callers of a function you changed (§7) | Fix the callers, or set `review.impact_for_types: false` |
| A refactor PR shows many findings in code it only moved | Move detection didn't run (fewer than 20 changed lines, `--staged`, no base) or the code was edited while moving | They're listed under **Pre-existing** when detection applies; edited lines count as new by design |
| Move detection is slow | `git blame` on many large new files | It runs 4 at a time on files with ≥ 20 changed lines; raise `move_detection_min_lines` or use `--no-move-detection` |
| The reviewer ignored a project decision | The doc isn't matched by `review.context_files`, or has no "Decision" heading | Add its path/glob; give ADRs a `## Decision` section (the brief is taken from it) |
| Schema facts missing for a column | Its values are defined outside SQL migrations (app constants, generated types) | Only SQL `enum`/`CHECK` definitions are parsed; archive/backup folders are skipped on purpose |
| SARIF upload step warns | Private repo without GitHub Advanced Security | Expected; set `upload-sarif: false` to hide it |
| No PR comment | Workflow permissions are read-only, or the PR comes from a fork | Settings → Actions → Workflow permissions → Read and write |
| `config: unknown config key` | Typo in `.quality-gate.json` | Fix the key (see §9) |
| `error: config not found` / `extends … not found` | Wrong `--config` path or baseline name | Check the path; baselines live in `baselines/` |
| `error: base ref not found` | Ref not fetched | `git fetch origin` (CI uses `fetch-depth: 0`) |
| Dependency audit SKIP "no lockfile" / "pnpm not found" | Missing lockfile / package manager | Commit the lockfile; `corepack enable` |
| Dependency audit ERROR "audit could not run" | Registry unreachable or lockfile refused | See the message in the report |
| `tsc` ERROR "Node ran out of memory" | Big project | Raise `node_max_old_space_mb` |
| Prettier INFO "advisory: not enforced" | Nothing enforces Prettier | Enforce it (then it's a finding) or set `format_checks` |
| A tool timed out | Very large repo | `--timeout 1200` |
| First run floods with issues | `--all` or `--include-existing` on legacy code | Drop them; the default reports only new issues |

---

## 17. Cheat sheet

```
# daily
qg                                   # my changes + function-level AI review
qg --no-ai                           # free checks only
qg --staged                          # staged only
qg --fail-on deterministic           # behave like CI's gate
qg --ai-full                         # every rule, incl. off-by-default
qg --ai-mode diff                    # previous diff-based AI review
qg --sarif out/gate.sarif            # also write SARIF
qg --ai-backend sdk --ai-batch       # API key + SDK, half-price batch
qg --no-cache                        # ignore cached per-function reviews
qg --rule-stats rule-stats.json      # demote low-precision rules

# big branches
qg --base origin/master --plan-groups            # per-feature plan (Group-Id)
qg --base origin/master --group <id> --ai-only   # one feature
qg --base origin/master --plan-batches 10 --final-state
qg --base origin/master --only src/billing

# CI (per project)
.github/workflows/quality-gate.yml   -> uses: sarthakkk1212/quality-gate/.github/workflows/quality-gate.yml@v2
.quality-gate.json                   -> { "extends": "marketink", ... }
secrets: ANTHROPIC_API_KEY (org)     [+ QUALITY_GATE_TOKEN if the tool repo is private]

# statuses
PASS clean · FINDINGS new issues · INFO pre-existing/advisory · SKIP n/a · ERROR tool failed · OFF disabled
# exit codes
0 ok / gate passed · 1 gate failed · 2 bad input
```

---

## 18. Versioning, migration & roadmap

### Versions
- **Tag releases.** Projects pin a **major** tag (`@v2`) in their workflow and
  `tool-ref`. Rule-catalog or baseline changes inside a major version are
  backwards-compatible; breaking changes get a new major tag.
- **`scan.js --help`** shows the flags. Every report records the tool version
  (`meta.version`) and the config files used.

### What changed in 2.0
- **Function-level AI review is the default:** impact analysis with the
  project's TypeScript, a fixed rule catalog, JSON output and evidence
  verification. The previous diff review is `--ai-mode diff`.
- **Org baseline + per-project `.quality-gate.json` with `extends`.** The old
  `quality-gate.config.json` next to `scan.js` was removed; it is still read
  (with a warning) if present.
- **Reusable GitHub workflow** (`.github/workflows/quality-gate.yml`) +
  examples. The old copy-in `quality-scan.yml` was removed.
- **SARIF output** and **`--fail-on`** gates (`--strict` still works).
- **The gate no longer scans its own vendored copy.**
- `scan.py` (the pre-Node fallback) has none of the 1.x/2.0 features; use
  `scan.js`.

### Also in 2.0 (cost & trust)
- **Cost:**
  - SDK backend (prompt caching, structured output, effort, refusal fallbacks);
  - Batches API option;
  - per-function review cache;
  - risk-ordered budgets.
- **Trust:**
  - inline 👍/👎 comments;
  - weekly precision workflow (`quality-gate-feedback.yml`, `lib/feedback.js`);
  - automatic demotion of low-precision rules;
  - "eligible to block" hints;
  - `tsc`/`mypy` errors in impacted callers counted as new.

### Roadmap
- **More languages for the function review** (Python next).
- **Org-wide precision:** aggregate rule stats across all projects, not just
  per repo.
- **Auto-promotion:** let rules that stay "eligible-to-block" join
  `ai_blocking_rules` automatically (opt-in).

---

## 19. Cost controls: backends, cache, budgets, batches

### Backends (`review.backend`, `--ai-backend`)

| Backend | When it's used | How it calls Claude | Billing |
|---|---|---|---|
| **`sdk`** | `ANTHROPIC_API_KEY` set **and** `@anthropic-ai/sdk` installed (CI installs it into the tool folder; locally run `npm install` in the quality-gate folder) | Official Anthropic SDK: `messages.create`; the fixed prefix (instructions, rules, project context) is a **cached system prompt** (`cache_control`); **structured JSON output** (`output_config.format`); explicit `effort` (default `high`); **server-side refusal fallbacks** (`fallbacks: "default"`); 4 calls in parallel | Org API account, per token |
| **`cli`** | No API key or no SDK (typical on a laptop) | `claude -p` with no tools, `--restricted`, `--json-schema` | Your Claude login (Pro/Max/Team limits) |
| `auto` (default) | — | `sdk` if possible, else `cli` | — |

The default model is `claude-opus-5-5` on the SDK backend. Set `review.model`
(e.g. `claude-sonnet-5-5`) and/or `review.effort` (`medium`) per project for a
cheaper review, and compare quality on a few PRs before standardising.

### Per-function review cache (`review.cache`)
- **The key covers everything that can change a result:** each function's
  packet (new + old body, caller snippets, callee signatures), the prefix
  (instructions, **rule catalog**, **context files**, compiler facts), the
  model, the effort and the output schema.
- **A cache hit skips the call.** The cached findings are **re-verified against
  the current files** like fresh ones, so a cache hit can't bypass the
  evidence check.
- **Edits elsewhere can still invalidate a function.** Editing a caller changes
  that function's caller snippet, so it is reviewed again. That's intended: the
  review depends on its callers.
- **Location:** `~/.cache/marketink-quality-gate/reviews` by default (outside
  the repo); `--cache-dir`, `review.cache_dir` or `QG_CACHE_DIR` change it.
  Entries older than `cache_days` are pruned. `--no-cache` forces a fresh
  review.
- **In CI** it's restored/saved with `actions/cache` per branch, falling back
  to the repo's latest cache.

Measured: reviewing the same 2 functions again cost **0 calls / 0 tokens**.

### Budgets & risk ordering
- `review.max_input_tokens` (default 400k) is the per-run input budget, and
  `ai_max_chunks` caps the number of calls.
- Functions are packed **riskiest first** (§7), so a budget cut always drops
  the lowest-risk functions. The report lists them.
- `review.max_functions` caps the impact analysis itself.

### Batches API (`--ai-batch`, `review.batch`)
- **Half price, asynchronous** (usually minutes).
- `always` uses it every time; `auto` uses it when a run needs ≥
  `batch_min_calls` calls.
- The scan waits up to `batch_wait_sec`, then reports the batch id. Good for
  nightly, deep or big-branch reviews; keep it off for fast PR feedback.
- Server-side fallbacks aren't available on batches, so they're off there.

### Seeing the cost
Every call records input, cache write, cache read, output and time:
- the console shows it live;
- the report has a per-call table;
- `meta.ai_usage` and the PR comment show the run's total.

The `~USD` figure uses the published per-model API prices (halved for
batches). On a subscription login, calls count against plan limits instead.

---

## 20. Trust: inline feedback, rule precision, auto-demotion

### The loop

```
PR run ──► verified AI finding ──► inline PR comment "👍 real / 👎 wrong"   (+ SARIF alert)
                                                │
weekly ──► quality-gate-feedback.yml ──► lib/feedback.js reads reactions + alert fixes/dismissals
                                                │
                                                ▼
                         per-rule precision → Actions cache (default branch)
                                                │
next PR run ──► --rule-stats ──► rules often wrong → ADVISORY (not posted, not gating)
                                 rules usually right → "eligible-to-block" hint
```

### Signals counted per finding (one verdict each)

| Signal | Counts as |
|---|---|
| 👍 on the inline comment | real |
| 👎 on the inline comment (wins over 👍) | wrong |
| Code-scanning alert for `ai/<RULE>` **fixed** | real |
| Alert **dismissed as "false positive"** | wrong |
| "won't fix" / "used in tests" dismissals | ignored (they say nothing about correctness) |

### What the gate does with it (`review.precision`)

| Status | Condition (defaults) | Effect |
|---|---|---|
| `collecting` | fewer than 10 rated findings | Normal |
| `ok` | 50–85% precision | Normal |
| `demoted` | **< 50%** with ≥ 10 samples | Findings move to the report's **Advisory** section; not posted, not in SARIF, never trip the gate |
| `eligible-to-block` | **≥ 85%** with ≥ 10 samples | A hint: safe to add to `gate.ai_blocking_rules` |

The report shows the precision table (rule, 👍, 👎, precision, status). A rule
recovers on its own if later feedback improves.

### Setup
1. Keep `inline-comments: true` (the default) in the PR workflow.
2. Add `examples/github/quality-gate-feedback.yml` (weekly + manual run). It
   needs `pull-requests: read`, `security-events: read` and `actions: write`
   (to save the cache).
3. Ask reviewers to react 👍/👎 on the gate's inline comments. That's the
   whole cost of the loop.

**Run it locally:**
```bash
GITHUB_TOKEN=... GITHUB_REPOSITORY=org/repo node lib/feedback.js --days 90 --out rule-stats.json
qg --rule-stats rule-stats.json
```

---

*Read-only by design. It tells you what's wrong, with proof; it never touches
your code, your git history or your dependencies.*

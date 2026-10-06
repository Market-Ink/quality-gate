# MarketInk Quality Gate

A **read-only code scanner** that runs your existing quality tools (linters, type
checkers, security & dependency scanners) plus an optional scoped **AI review**
with Claude, and produces one clean report.

It is a single Node script (`scan.js`, **zero npm dependencies**) that is safe to
run on **any project, at any time** — including production repos — because it
**never changes anything**.

> **This README is the one and only doc.** Setup, features, daily usage,
> onboarding, config, git/CI automation, and troubleshooting are all below.

---

## Table of contents

1. [What it is & safety guarantees](#1-what-it-is--safety-guarantees)
2. [Features — what it runs](#2-features--what-it-runs)
3. [Requirements & setup](#3-requirements--setup)
4. [Quick start & daily usage](#4-quick-start--daily-usage)
5. [Options / flags](#5-options--flags)
6. [Reading the report](#6-reading-the-report)
7. [Configuration](#7-configuration)
8. [Supabase checks](#8-supabase-checks)
9. [Onboarding a project & git automation](#9-onboarding-a-project--git-automation)
10. [Troubleshooting](#10-troubleshooting)
11. [Cheat sheet](#11-cheat-sheet)
12. [Notes: migration & roadmap](#12-notes-migration--roadmap)

---

## 1. What it is & safety guarantees

The Quality Gate splits code review in a way that plays to each tool's strength:

- **Deterministic tools** (linters/type/security/dependency scanners) handle
  everything mechanical — always right, cost nothing to run.
- **Claude (AI)** handles judgment calls — reading *only your diff* against *your*
  standards (from the project's `CLAUDE.md`) and explaining real issues in plain
  language: security holes, broken business logic, bad architecture, perf traps.

**The single most important fact: it is 100% read-only.**

- ✅ **Never edits, formats, or fixes your code.** Every tool runs in check-only
  mode (`ruff check --no-fix`, `prettier --list-different`, `mypy`, `pnpm audit`,
  `gitleaks git`, …). No `--fix`/`--write` flags anywhere. `tsc` runs with
  `--incremental false` so it can't drop a `.tsbuildinfo` into your repo.
- ✅ **Never changes git state.** No add, commit, push, checkout, or worktree.
- ✅ **Never installs anything.** It only runs tools already available.
- ✅ **Can't break a build.** A missing tool is *skipped*, not failed. Exit code is
  `0` by default; `--strict` (opt-in) is the only way it returns non-zero.
- ✅ **Zero-touch on the scanned project.** Point it at a repo from outside with
  `--path`; nothing is written into that repo. The only file it ever writes is a
  report, in an output folder you choose — or nothing at all with `--no-report`.

### The mental model (four ideas explain 90% of it)

| Idea | What it means |
|---|---|
| **Read-only** | Runs everything in *check* mode. There is **no** `--fix`/`--write` anywhere. |
| **Auto-detect** | It only runs a tool that's already installed. A missing tool becomes `SKIP`, never an error. A repo with no Python tools simply shows every Python row as `SKIP`. |
| **Scoped by default** | With no flags it scans **only the files that changed** vs your base branch (`origin/main`, `main`, …) — you see issues in *new* code, not a wall of legacy noise ("clean as you code"). |
| **New vs pre-existing** | Inside those files, every finding is classified: on a line **you changed** = *new* (counts); anywhere else = *pre-existing* (listed as info, never blamed on you). |
| **AI is diff-based** | The Claude review only runs on a diff — split into per-file parts so even a 600-file branch gets reviewed. `--all` disables AI on purpose. |

> The everyday use case: run it with **no flags** on a repo you're actively working
> in, right before you commit or open a PR. You get a short list of issues **in the
> code you just wrote**, plus an AI review of your diff.

---

## 2. Features — what it runs

| Check | Tool | Mode | Scope |
|---|---|---|---|
| Lint (Python) | `ruff check` | read-only | changed files |
| Format (Python) | `ruff format --check` | read-only | changed files |
| Types (Python) | `mypy` | read-only | changed files |
| Security (Python) | `bandit` | read-only | changed files |
| Dependencies (Python) | `pip-audit` | read-only | project |
| Lint (JS/TS) | `eslint` | read-only | changed files |
| Format (JS/TS) | `prettier --list-different` | read-only, advisory unless enforced | changed files |
| Types (JS/TS) | `tsc --noEmit` | read-only | project, errors split by changed files |
| Dependencies (JS/TS) | `pnpm` / `yarn` / `bun` / `npm audit` (picked from the lockfile) | read-only | project |
| Secrets | `gitleaks git` | read-only | **your branch's commits** + working tree (`--all`: full history) |
| Supabase (RLS/keys/grants) | *built-in* (no tool) | read-only | changed code + `.sql` (RLS state read from all migrations) |
| AI review | `claude -p` | read-only | the diff, in per-file parts |

**Built to be trusted on big branches:**

- **Tool crashes are `ERROR`, never `FINDINGS`.** "Command line is too long",
  Node out-of-memory, ESLint/Prettier exit code 2, a missing config, or an audit
  that couldn't run are reported as the tool failing — with the reason.
- **Long file lists are batched** to stay under the Windows `cmd.exe` 8,191-char
  limit (a 700-file branch runs ESLint in ~11 batches and merges the results).
- **JS tools get a bigger heap** (`node_max_old_space_mb`, default 8192) so `tsc`
  on a large Next.js app doesn't die at Node's 2 GB default.
- **Only files git tracks are scanned** — `.next/`, `.env.local`, build output and
  other ignored files never show up.

Deterministic tools own anything mechanical. The AI review is reserved for
judgment — security, business logic, architecture, performance, maintainability —
and is **scoped to the diff** and run in an isolated temp directory so it has
nothing in your project to touch.

> React/Next are just JS/TS to the scanner — ESLint + Prettier + TypeScript cover
> them. The language the tool is *written in* (Node) is unrelated to the languages
> it *scans*: it's an orchestrator that shells out to each stack's tools.

---

## 3. Requirements & setup

**Node.js 18+ and nothing else** (Node 20+ recommended). The scanner is a single
dependency-free script — `node scan.js` just works, no `npm install`.

The actual checks are **optional and auto-detected** — install whichever a project
uses; the gate runs what's there and skips the rest.

### The golden rule of where tools live

| Tool type | Where it must be installed | Why |
|---|---|---|
| **Python** (`ruff`, `mypy`, `bandit`, `pip-audit`) | Global or the project's virtualenv (on your `PATH`) | The scanner looks for them on PATH |
| **JS/TS** (`eslint`, `prettier`, `typescript`) | **Inside the project** as dev deps (`node_modules/.bin`) | The scanner looks in the project's `node_modules` |
| **`gitleaks`** (secrets) | Global (on your `PATH`) | Works on any project |
| **`claude`** (AI review) | Global (on your `PATH`) | Optional; if absent, AI step is skipped |

```bash
# Python projects (global, or inside the project's venv)
pip install ruff mypy bandit pip-audit

# JS/TS/React/Next projects — install as dev deps INSIDE the project
npm install -D eslint prettier typescript

# Secret scanning (one binary, any project)
winget install gitleaks.gitleaks      # Windows
brew install gitleaks                 # macOS
# Linux: download from https://github.com/gitleaks/gitleaks/releases

# AI review (optional): install Claude Code so `claude` is on PATH
```

> You don't need all of these. With **none** installed the scanner still runs,
> skips everything gracefully, and tells you what to install.

### Make it a one-word command (recommended)

You'll run this constantly, so add an alias.

**Windows (PowerShell `$PROFILE`):**
```powershell
function qg { node E:\MarketInk\Quality_Gate\quality-gate\scan.js @args }
```

**macOS / Linux (`~/.bashrc` or `~/.zshrc`):**
```bash
qg() { node /path/to/quality-gate/scan.js "$@"; }
```

Reload your shell — now from *any* project you just type `qg`. Wrappers also ship:
`quality.ps1` on Windows and `./quality` on macOS/Linux (both pass all args through).

---

## 4. Quick start & daily usage

Run from inside a repo, or point at one with `--path`.

```bash
# Scan the changed files in the current repo (+ AI review of the diff):
node scan.js            # or: qg

# Zero-touch scan of another project (nothing written into it):
node scan.js --path ../some-service

# Full health check of the whole project (no AI):
node scan.js --all --no-ai
```

### Where reports land (the one thing people trip on)

- **`--path`** = the project you *scan* (defaults to the current folder).
- **Reports are written to the folder you *run the command from*** — as
  `./quality-reports/` — **not** into the scanned project (unless you `cd` there or
  pass `--out`).

**Option A — stand inside the project (most intuitive):**
```powershell
cd E:\path\to\my-project
qg      # report → E:\path\to\my-project\quality-reports\latest.md
```

**Option B — stand in the tool folder, scan from outside (zero-touch):**
```powershell
cd E:\MarketInk\Quality_Gate\quality-gate
node scan.js --path E:\path\to\my-project
# report → E:\MarketInk\Quality_Gate\quality-gate\quality-reports\latest.md
```

### The recipes you'll actually use

| I want to… | Command |
|---|---|
| **Daily driver** — check my changes + AI review | `qg` |
| Fast check, no AI (offline, just linters) | `qg --no-ai` |
| Deep review before a big PR (all 6 AI reviewers) | `qg --ai-full` |
| Check only what's staged (pre-commit) | `qg --staged` |
| **Whole feature branch vs master** (all its commits) | `git fetch origin` then `qg --base origin/master` |
| Same, one module at a time | `qg --base origin/master --only src/billing` |
| **AI-review a big branch one feature at a time** (`Group-Id` trailers) | `qg --base origin/master --plan-groups` (prints the commands) |
| **AI-review a big branch 10 commits at a time** | `qg --base origin/master --plan-batches 10 --final-state` (prints the commands) |
| Also count issues that were already there | `qg --base origin/master --include-existing` |
| Review everything since a release/tag | `qg --base v1.4.0` |
| Scan a **different** repo, zero-touch | `qg --path ../other-repo` |
| One-time full audit of a legacy repo (no AI) | `qg --path ../repo --all --no-ai` |
| Print only, write nothing | `qg --no-report` |
| CI gate (exit 1 on findings) | `qg --staged --no-ai --strict` |
| Slow/huge repo | `qg --timeout 1200` |
| See all options | `qg --help` |

> AI review needs `claude` on PATH and a **diff** — it's skipped on `--all` and on
> an empty diff. Deterministic checks need their tools installed (§3); missing ones
> just `SKIP`.

---

## 5. Options / flags

```
--path PATH          repo to scan (default: current directory)
--all                scan the whole project instead of just changes (disables AI)
--staged             scan only git-staged changes
--base REF           git base ref for the diff (default: auto-detect origin/HEAD,
                     origin/main, origin/master…)
--only PATH          limit the scan (files, findings, diff) to a path; repeatable
--include-existing   count findings on lines you did NOT change as well
--range A..B         review only the commits in A..B (B defaults to HEAD)
--final-state        with --range: review the latest version of the files those
                     commits touched, each file once across batches
--plan-batches N     print the branch split into N-commit batches with token
                     estimates and ready commands (no scan, no AI calls)
--plan-groups        print the feature groups (Group-Id commit trailer) with token
                     estimates and ready commands (no scan, no AI calls)
--group ID           review one feature group: its files at their final version,
                     its full commit messages as claims to verify
--no-ai              skip the AI review
--ai-only            skip the deterministic checks; run only the AI review
--ai-full            run all 6 specialized AI reviewers (review/security/architecture/
                     performance/business-logic/supabase)
--ai-max-chunks N    max diff parts per AI reviewer (default 10; each = 1 claude call)
--no-report          print to the console only; write no files anywhere
--out DIR            report output directory (default: ./quality-reports)
--strict             exit 1 if any NEW findings (for optional CI gating)
--timeout SEC        per-tool timeout (default: 600)
```

**How scope is decided:**
- In a git repo it scans **changed files vs the base branch** by default
  (auto-detects `origin/HEAD` → `origin/main` → `origin/master` → `main` →
  `master`). The diff is taken from the **fork point** (`git merge-base`) to your
  working tree, so it covers every commit on the branch plus uncommitted and
  untracked work — and ignores commits that landed on master after you branched.
- `--all` scans everything git tracks; `--staged` scans staged changes only.
- Not a git repo? It automatically falls back to `--all`.

**How "new" is decided (the baseline):**
- Line-level tools (ESLint, Ruff, Bandit, Supabase, Prettier): a finding is
  **new** if it sits on a line you added/changed. Moved-but-unchanged files are
  pre-existing.
- Cross-file tools (`tsc`, `mypy`): **new** if it's in a file you changed. Errors
  in untouched files are listed separately — usually pre-existing, but a changed
  signature can break an untouched caller, so they're shown, not hidden.
- Dependency audit: **new** only if the lockfile or a `package.json` dependency
  field changed; otherwise every advisory already exists on the base branch.
- Secrets (gitleaks): only the branch's commits and your working tree are scanned,
  so everything it reports was introduced by the change.
- `--include-existing` turns all of this off and counts everything.

**Big branches & the AI review:** the diff is split per file into ~60k-char parts
(source code first, lockfiles/minified/binary left out) and each part is reviewed
separately. With the default cap of 10 parts, a very large branch may be only
partly reviewed — the report's **coverage** entry lists every file that wasn't, so
raise `--ai-max-chunks` or review module by module with `--only`.

### Reviewing a big branch by feature (recommended): `Group-Id` trailers

A branch usually holds several features whose commits interleave (feature A in
commits 10 and 12, feature B in 11). Fixed-size batches cut features in half.
Instead, tag each commit with a git trailer naming its feature:

```
Inbox 5i: window escape hatch

...message body: intent, invariants, fixes...

Group-Id: conversations-inbox
```

Then review **one feature per run**, whatever its position in history:

```powershell
git fetch origin
qg --base origin/master --plan-groups                       # groups, files, ~tokens, warnings, commands
qg --base origin/master --no-ai --out quality-reports/branch  # free checks, once
qg --base origin/master --group conversations-inbox --ai-only --out quality-reports/group-conversations-inbox
```

**What one `--group` run sends to the AI:**
- **Only that feature's files**, at their final version. Each file appears once,
  and no other feature's files are mixed in.
- **The group's full commit messages**, oldest first (up to
  `group_message_chars`). The reviewer is told to check every concrete claim in
  them against the code: "the worker now imports it", "inserted oldest-first +
  resume token", "the client is told what it may do". It reports claims the code
  contradicts, and lists those it can't confirm. Quoted tool results such as
  `tsc 0` are skipped.
- **Shared files**, i.e. files also changed by other groups, listed by name with
  those groups. Their diff may contain other features' hunks, and the reviewer is
  told to judge them only against this group's commits.
- **A manifest** when a group needs several parts: each part lists which files
  the other parts cover, so the reviewer knows what's missing instead of
  guessing.

**Edge cases:**
- **No trailer:** commits are grouped by shared files (`ungrouped-1`, …), ignoring
  hub files like `package.json`, lockfiles, `group_hub_files`, and anything
  touched by more than 30% of commits. The plan lists every such commit so you
  can see it.
- **Merge commits:** never mixed into feature groups. A merge group is reviewed
  with `git show --remerge-diff`, which shows only the conflict resolutions; clean
  merges cost nothing.
- **A commit in two features:** `Group-Id: billing, inbox` puts it in both.
- **Gitleaks** scans only the group's commits; **linters** check the group's files
  (or run them once for the branch and use `--ai-only`).
- **Warnings in the plan:** commits without a trailer, single-commit groups
  (possible typo), files changed by 3+ groups, and groups that exceed
  `ai_max_chunks`.

### Reviewing a big branch in batches (e.g. 50 commits, 10 at a time)

Use this when commits have no `Group-Id` trailer, or when you want to review
history in order.

The deterministic checks cost no tokens — run them **once** for the whole branch.
Spend AI tokens batch by batch, reading each report before starting the next.

```powershell
git fetch origin
# 1. See the plan: batches, files, ~tokens each, and the exact commands. No AI calls.
qg --base origin/master --plan-batches 10 --final-state

# 2. Free checks once for the whole branch
qg --base origin/master --no-ai --out quality-reports/branch

# 3. AI review one batch at a time (commands are printed by step 1)
qg --base origin/master --range <fork>..<c10> --final-state --ai-only --out quality-reports/batch-01
qg --base origin/master --range <c10>..<c20> --final-state --ai-only --out quality-reports/batch-02
...
```

**Literal ranges vs `--final-state`.**

| | `--range A..B` (literal) | `--range A..B --final-state` |
|---|---|---|
| The AI reads | exactly what those commits changed | the **latest** version of the files those commits touched |
| A file edited in commits 3, 18 and 41 | reviewed 3 times, twice in versions that no longer exist | reviewed **once**, in the first batch that touched it, as it is now |
| Total tokens | higher (repeats + stale code) | ≈ one whole-branch review, just split up |
| Use it to | review history commit-group by commit-group, like a PR series | check the branch's end result in pieces you can manage |

For a "can this merge?" review, use `--final-state`.

**What a batch run does:**
- **AI**: one call per ~60k-char part, with the batch's commit subjects added as
  context (`ai_commit_context`).
- **Gitleaks**: only that batch's commits (`--log-opts=A..B`).
- **Linters** (when not `--ai-only`): the files that batch touched, as they are
  now. "New" means new in the branch, because the tools read your current
  files, not old commits.
- **Reports** are named `report-<time>-range-<from>-<to>.md`. Use `--out` per
  batch so the `latest.md` files don't overwrite each other.

**Ways to cut tokens** (`quality-gate.config.json`, AI only; linters still scan
everything):

| Setting | Effect |
|---|---|
| `"ai_exclude": ["docs/**", "*.md", "**/__snapshots__/**"]` | Files the AI never reads |
| `"ai_context_lines": 1` | 1 unchanged line around each change instead of 3 |
| `"ai_ignore_whitespace": true` | Drops whitespace-only changes (great after a reformat; keep off for Python/YAML) |
| `--only src/billing` | Review one module per run |
| `"ai_chunk_chars": 120000` | Fewer, larger parts. Every `claude -p` call carries a fixed ~25k tokens of Claude Code overhead (~9k cache write + ~16k cache read, ~$0.07 measured), so halving the number of calls saves real usage on big branches |
| always on | Deleted files send only their name, moved files only the rename, and lockfiles, minified, maps and binaries are left out |

**Exit codes:** `0` = ran fine (even with findings). `1` = only with `--strict`
*and* there were new findings. `2` = bad `--path` or a `--base` ref that doesn't
exist (`git fetch origin` usually fixes it). That's why it's safe in CI by
default — it can't fail your build unless you opt in with `--strict`.

---

## 6. Reading the report

Every run writes three files into `quality-reports/`:

- **`latest.md`** — human-readable. **Read this one.**
- **`latest.json`** — same data, machine-readable (`{ meta, checks, reviews }`), for
  dashboards/automation.
- **`report-YYYYMMDD-HHMMSS.md`** — timestamped history, one per run.

Each check has a status:

| Status | Meaning | What to do |
|---|---|---|
| **PASS** | Tool ran, found nothing | 🎉 Nothing to do |
| **FINDINGS** | Tool ran, found issues **your change introduced** | Read the **Details** section and fix them |
| **INFO** | Only pre-existing issues, warnings, low-severity notes, or an advisory check (e.g. an unenforced formatter) | Nothing blocks; worth a look when you touch that code |
| **SKIP** | Tool not installed, or nothing in scope | Install the tool (§3) if you want that check |
| **ERROR** | The *tool* failed (crash, OOM, timeout, missing config/lockfile) — not your code | See §10 |
| **OFF** | Disabled in config | You turned it off in `quality-gate.config.json` |

- The **Details** section lists `FINDINGS` and `ERROR` checks, each with the
  command it ran. Findings are grouped as **New in this change** and
  **Pre-existing**. `INFO` checks sit in a collapsed section below.
- Skipped checks are folded into one line (e.g. the Python tools on a JS repo).
- Secrets are **never printed** — only rule, file, line, commit and the length.
- **AI usage** — every `claude` call is run with `--output-format json`, and the
  report has a per-call table (input, cache write, cache read, output, total,
  time) with totals. The same data is in `latest.json` → `meta.ai_usage` and each
  review's `usage`, and the console prints it live after each call. The `~USD`
  column is the API list-price equivalent; on a Pro/Max/Team/Enterprise login the
  calls count against your plan's usage limits instead. (An older `claude` CLI
  without `--output-format` falls back to plain text with no usage.)
- The **AI Review** section is Claude's prose analysis of your diff: each issue gets
  a `file:line` estimate, a severity (high/med/low), the problem in one sentence,
  and a concrete fix. If it found nothing, it says so.

> A `SKIP` or `ERROR` never means the scanner failed — it means a *tool* was missing
> or a *project* has a gap. The scanner cannot break your build and made no changes.

---

## 7. Configuration

There are two layers:

1. **The scanner's own config** — `quality-gate.config.json` (optional).
2. **Each tool's own config** — the normal `ruff`, `eslint`, `tsconfig`, etc. files
   in the project. The gate just *runs* these; it respects the project's existing
   rules and never invents its own.

### `quality-gate.config.json`

Lives next to `scan.js`. Delete it and safe defaults still apply.

```json
{
  "base_ref": null,
  "disabled_checks": [],
  "node_max_old_space_mb": 8192,
  "format_checks": "auto",
  "ai_max_chunks": 10,
  "ai_chunk_chars": 60000
}
```

- **`base_ref`** — default git ref to diff against. `null` = auto-detect
  (`origin/main` → `main` → …). Set it if your default branch is unusual (e.g.
  `"origin/develop"`).
- **`disabled_checks`** — check ids you never want to run. Valid ids: `ruff`,
  `ruff-format`, `mypy`, `bandit`, `pip-audit`, `eslint`, `prettier`, `tsc`,
  `npm-audit`, `gitleaks`, `supabase`. Example — silence npm audit and secrets:
  `["npm-audit", "gitleaks"]`. (`npm-audit` is the id for the JS dependency audit
  whichever package manager runs it.)
- **`node_max_old_space_mb`** — heap given to eslint/prettier/tsc (via
  `NODE_OPTIONS`). Raise it if `tsc` reports "Node ran out of memory".
- **`format_checks`** — `"auto"` (default): Prettier/ruff-format are findings
  only if the project *enforces* them (lint-staged, a husky/lefthook/pre-commit
  hook, a CI workflow, or `eslint-plugin-prettier`); otherwise advisory `INFO`.
  `"enforce"` / `"advisory"` force one or the other.
- **`ai_max_chunks`** / **`ai_chunk_chars`** — how many diff parts (and how large)
  each AI reviewer gets.
- **`ai_exclude`**, **`ai_context_lines`**, **`ai_ignore_whitespace`**,
  **`ai_commit_context`** — trim what the AI reads (see *Reviewing a big branch
  in batches* in §5).
- **`group_trailer`** (default `Group-Id`), **`group_message_chars`** (8000),
  **`group_hub_files`** — feature-group review (see *Reviewing a big branch by
  feature* in §5).

### Give Claude your project's rules — `CLAUDE.md`

The highest-leverage config for context-aware review. Drop a `CLAUDE.md` at the
project root and the AI review treats its rules as the standard it reviews against.
A template ships with the tool:

```bash
cp quality-gate/.quality/standards/CLAUDE.template.md  <your-project>/CLAUDE.md
```

Fill in your stack, architecture rules, API conventions, and security rules as
concrete "always/never" statements, e.g.:

```
- Never access the database directly from controllers. Always go through the service layer.
- Never build SQL by string concatenation — use parameterized queries.
- Every API endpoint validates its input before use.
- Never log secrets, tokens, or PII.
```

The more concrete the rules, the more objective and useful the AI review.

---

## 8. Supabase checks

Many of our projects use Supabase, where **Row Level Security (RLS) is the main
access control** — every `public` table is exposed over an auto-generated REST API,
and the `service_role` key bypasses RLS entirely. Generic linters know none of
this, so the gate ships a **built-in Supabase check** plus a **Supabase AI
reviewer**. Nothing to install; it auto-detects Supabase (a `supabase/` dir,
`@supabase/*` in `package.json`, or `supabase`/`createClient` in the scanned code)
and shows `SKIP` on projects that don't use it.

**Deterministic check (`supabase`)** — concrete "always/never" signatures scanned
over changed code + `.sql` migrations:

| It flags | Severity | Why |
|---|---|---|
| `service_role`/secret key behind a browser-exposed env var (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, …) | HIGH | Ships full-DB-access credentials to the client |
| A hardcoded secret key (`sb_secret_…`) | HIGH | Leaks a key that bypasses RLS |
| A hardcoded JWT whose payload says `"role": "service_role"` (decoded — the variable name doesn't matter; project ref + expiry shown) | HIGH | Leaks a key that bypasses RLS |
| `service_role` referenced in a client (`'use client'`) file | HIGH | The service role must never reach the browser |
| `alter table … disable row level security` | HIGH | Table becomes fully readable/writable with the anon key |
| `create table` in the **public** schema that **no migration** ever enables RLS on | MEDIUM | New table left unprotected |
| `grant <write> … to anon`/`public` | MEDIUM | Exposes data via the REST API; prefer RLS policies |
| `grant <read>/execute … to anon`/`public` | LOW | Readable / RPC-callable by anyone — make sure RLS or the function checks auth |
| A policy whose `TO` clause (or `USING`) targets `service_role` | LOW | Redundant (service_role already bypasses RLS) — harmless, safe to drop |

**How it avoids false positives:**
- **Comments are stripped** before the semantic rules run — `-- service_role
  only`, `/* … disable row level security … */` or `// uses service_role` in a
  comment never fire. (Secret rules still read raw text: a key pasted in a
  comment is still a leaked key.)
- **SQL is matched per statement**, not per line, so multi-line `create policy`
  / `grant` statements are parsed whole. `GRANT EXECUTE … TO service_role` is not
  a policy and is never flagged.
- **RLS state is collected across every `.sql` file in the repo**, so a table
  created in one migration and protected in a later one is fine.
- Tables in non-public schemas (e.g. `private.audit`) aren't exposed by the REST
  API and aren't flagged. `grant usage on schema … to anon` (a Supabase default)
  is ignored.
- Placeholders (`sb_secret_xxxx…`, `YOUR_…`, `<…>`, `${…}`, `...`) are ignored.

> The anon key hardcoded in client code is **not** flagged — it's designed to be
> public. RLS, not key secrecy, is what protects your data.

**AI reviewer (`supabase`)** — runs under `qg --ai-full` and handles the judgment a
regex can't: RLS *coverage & correctness* (`USING (true)`, missing `WITH CHECK`),
ownership/IDOR (queries not scoped to `auth.uid()`), `security definer` RPC
functions, public storage buckets, and sensitive columns exposed to clients. Add
your Supabase rules to the project's `CLAUDE.md` to make it context-aware.

---

## 9. Onboarding a project & git automation

Each project is onboarded **once**, then the gate runs automatically on `git commit`
(fast, staged, deterministic) and `git push` (fuller review vs the base branch).
You have three levels of automation — adopt them in order, as trust grows.

### One-time onboarding (installs the hooks)

Windows:
```powershell
cd quality-gate
.\hooks\install-hooks.ps1 -Repo C:\path\to\your-project
```
macOS/Linux:
```bash
cd quality-gate
./hooks/install-hooks.sh /path/to/your-project
```

The installer, entirely inside the target repo:
1. Vendors the scanner into `<repo>/.quality-gate/` (so it travels with the repo).
2. Installs `pre-commit` + `pre-push` into `<repo>/.githooks/`.
3. Runs `git config core.hooksPath .githooks`.
4. Adds `quality-reports/` to `.gitignore`.

Then commit the setup so it ships with the repo:
```bash
git add .githooks .quality-gate .gitignore
git commit -m "Add MarketInk Quality Gate hooks"
```

**Files added by this setup:**

| File | Purpose |
|---|---|
| `<repo>/.quality-gate/` | vendored scanner (committed with the repo) |
| `<repo>/.githooks/pre-commit` | fast staged scan on commit |
| `<repo>/.githooks/pre-push` | fuller scan on push |

### Level 1 & 2 — Local hooks (behaviour & toggles)

| Hook | Default | Scope |
|---|---|---|
| `pre-commit` | notify only, never blocks | staged changes, no AI (fast) |
| `pre-push` | notify only, never blocks | changed vs base, no AI |

Set as env vars:
- `QG_BLOCK=1` → **abort** the commit/push if there are findings.
- `QG_AI=1` → include the Claude AI review on push (slower).
- `git commit/push --no-verify` → bypass the hook (git's built-in escape hatch).

> **The honest catch about "everyone gets it on pull":** git **deliberately** does
> not run hooks that arrive via `clone`/`pull` (auto-running fetched code would be a
> security hole). So there is always **one** action per developer per clone:
> `git config core.hooksPath .githooks`. That's unavoidable for *local* hooks — which
> is why CI (below) is the real enforcement layer.

### Level 3 — CI on every Pull Request (the team standard, unskippable)

A ready-made GitHub Actions workflow ships at `.github/workflows/quality-scan.yml`.
It runs on every PR (and manual dispatch), scans the **PR diff**
(`--base origin/<base_branch>`), is **`continue-on-error: true`** (never fails the
build yet), uploads the report as a downloadable artifact, **and posts the report
straight onto the PR as a comment** (updating the same comment on re-runs).

**Set it up in a project:**

1. Copy the workflow in:
   ```powershell
   Copy-Item E:\MarketInk\Quality_Gate\quality-gate\.github\workflows\quality-scan.yml `
             E:\path\to\my-project\.github\workflows\
   ```
2. Add to the project's `.gitignore`:
   ```
   quality-reports/
   .quality-gate-tool/
   ```
3. Commit and open a PR. The workflow clones the scanner from
   `https://github.com/sarthakkk1212/quality-gate.git` at run time, scans the PR
   diff, and posts results as a PR comment. For the comment to post, enable repo
   **Settings → Actions → General → Workflow permissions → "Read and write
   permissions"** (the workflow already declares `pull-requests: write`). PRs from
   *forks* get a read-only token, so the comment step is skipped there (the artifact
   still uploads).
4. **To run deterministic tools in CI too**, uncomment the install step and list
   what the repo uses (e.g. `pip install ruff mypy bandit pip-audit`; for JS/TS add
   an `npm ci` step so `node_modules` exists).
5. **Make it blocking later** — once the false-positive rate is low and the team
   trusts the signal, flip `continue-on-error: true` → `false` (and add `--strict`)
   so a PR with findings fails the check.

> **AI review in CI** uses `--no-ai` by default because the `claude` CLI needs
> credentials. To enable it: install Claude Code in the workflow, provide API
> credentials via GitHub **Secrets**, and drop `--no-ai`.

### The end-to-end flow (the whole point)

```
Developer writes code
        │  (local)  qg  ──► fix issues in your own diff, privately. Fast loop.
        ▼
  git commit ──► pre-commit hook (advisory)            [Level 1]
        ▼
  git push   ──► pre-push hook (QG_BLOCK=1 blocks)      [Level 2]
        ▼
  Open PR ──► quality-scan.yml runs on the PR diff      [Level 3]
        │       → report as artifact + PR comment
        ▼
  Reviewer reads findings + AI review, requests changes if needed
        ▼
  All clear → merge.  The defect never reaches main.
```

**Best practice: use both layers** — local hooks for instant feedback, CI as the
enforcement that can't be skipped.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **Everything Python shows `SKIP`** | Those tools aren't installed / not on PATH | `pip install ruff mypy bandit pip-audit` |
| **A JS tool shows `SKIP`** even though installed globally | JS tools must be **local** to the project | `npm install -D eslint prettier typescript` inside the project |
| **Dependency audit → SKIP "no lockfile found"** | The repo has `package.json` but no `pnpm-lock.yaml` / `yarn.lock` / `bun.lock` / `package-lock.json` | Commit the lockfile your package manager makes |
| **Dependency audit → SKIP "pnpm not found on PATH"** | The lockfile is pnpm's but `pnpm` isn't installed globally | `npm i -g pnpm` (or `corepack enable`) |
| **Dependency audit → ERROR "audit could not run"** | Registry unreachable, or the package manager refused the lockfile | Check network/registry; the message shows the package manager's error |
| **Dependency audit → INFO "dependencies unchanged"** | Advisories exist but your change didn't touch deps — they're on base too | Fix them separately (or `--include-existing` to count them) |
| **`tsc` → ERROR "Node ran out of memory"** | Project too big for the heap | Raise `node_max_old_space_mb` in the config (default 8192) |
| **ESLint/Prettier → ERROR "command line too long"** | Shouldn't happen any more (lists are batched) | Report it; meanwhile narrow with `--only` |
| **ESLint → SKIP "no ESLint config"** | The project has ESLint installed but no config file | Add an `eslint.config.*`, or ignore |
| **Prettier shows INFO "advisory: not enforced"** | Nothing in the project runs Prettier (no hook/CI/lint-staged) | Team decision: enforce it (then it becomes a finding) or drop it; `format_checks` in config overrides |
| **AI review "coverage – PARTIAL"** | The branch was bigger than `ai_max_chunks` parts | `--ai-max-chunks 30`, or review module by module with `--only` |
| **`error: base ref not found`** | The `--base` ref doesn't exist locally | `git fetch origin`, then retry |
| **`tsc` says "Could not find a declaration file for 'pg'"** | Real project gap, not a scanner bug | `npm i -D @types/pg` (the gate faithfully reports your `tsc` output) |
| **AI review says "skipped"** | `claude` not on PATH, **or** you used `--all`, **or** the diff is empty | Install Claude Code; drop `--all` (AI is diff-based) |
| **"not a git repository — scanning the whole project"** | You're outside a git repo | Expected; it falls back to `--all` automatically |
| **A tool timed out (`ERROR`)** | Very large repo | Raise it: `qg --timeout 1200` |
| **First run floods me with issues** | You used `--all` (or `--include-existing`) on a legacy repo | Drop it — the default reports only what *your* change introduced |
| **Report didn't appear** | You used `--no-report`, or the out dir wasn't writable | Remove `--no-report`, or set `--out` to a writable folder |

---

## 11. Cheat sheet

```
# --- daily (local) ---
qg                          # scan my changes + AI review  ← use this most
qg --no-ai                  # faster, offline, just linters/types/security
qg --ai-full                # deep 6-reviewer AI pass before an important PR
qg --staged                 # only staged changes (pre-commit)
qg --base origin/master     # a whole feature branch (all commits) vs master
qg --base origin/master --only src/billing   # ...one module at a time
qg --base origin/master --plan-groups        # plan a per-feature AI review (Group-Id)
qg --base origin/master --group <id> --ai-only   # review one feature
qg --base origin/master --plan-batches 10 --final-state   # plan a batched AI review
qg --base origin/master --range A..B --final-state --ai-only   # one batch
qg --include-existing       # also count issues already on the base branch
qg --base v1.4.0            # everything since a release
qg --path ..\repo --all --no-ai   # one-time full audit of another repo
qg --strict                 # exit 1 on findings (hooks / CI gating)
qg --no-report              # console only, write nothing

# --- what it is ---
# qg = node E:\MarketInk\Quality_Gate\quality-gate\scan.js
# Report → ./quality-reports/latest.md (in the folder you ran it from)
# READ-ONLY: never edits code, never touches git, never installs anything.

# --- install tools (only what a project uses) ---
pip install ruff mypy bandit pip-audit          # Python (on PATH)
npm install -D eslint prettier typescript       # JS/TS/React/Next (in project)
winget install gitleaks.gitleaks                # secrets (on PATH)
# + Claude Code on PATH for AI review

# --- statuses ---
PASS = clean   FINDINGS = new issues, fix these   INFO = pre-existing/advisory
SKIP = tool missing / nothing in scope   ERROR = the tool failed   OFF = disabled

# --- automate ---
# Level 1: pre-commit  → advisory (QG_BLOCK=1 to block)
# Level 2: pre-push    → fuller scan (QG_BLOCK=1 to block push on findings)
# Level 3: .github/workflows/quality-scan.yml → runs on every PR + PR comment
```

---

## 12. Notes: migration & roadmap

### Migration `scan.py` → `scan.js` (done)

The scanner was migrated from a Python file (`scan.py`) to a single Node file
(`scan.js`) with **zero npm dependencies** — because Node is already on every
machine and CI runner in an all-JS/TS org, while Python was the odd one out. It's a
**wrapper-language swap, not a redesign**: same two layers, same read-only
guarantee, same report format, and **all check specs kept** (including the Python
ones — the tool still scans Python projects by shelling out to `ruff`/`mypy`/
`bandit`/`pip-audit`). `scan.py` is kept one release as a fallback, then removed.

> Windows note: npm-installed bins are `.cmd` shims (`eslint.cmd`, `tsc.cmd`,
> `npm.cmd`); the scanner resolves the absolute path via its `which`/`localBin`
> helpers and runs it without a shell. Node's `spawnSync` timeout is in **ms** (the
> `--timeout` seconds are converted).

### Built today

- ✅ `scan.js` — read-only scanner (Node, zero deps): 11 deterministic checks +
  Claude AI review, with 6 specialized AI reviewers under `--ai-full`.
- ✅ Built-in Supabase check + dedicated Supabase AI reviewer (§8).
- ✅ Wrappers (`quality.ps1`, `quality`), optional config, `CLAUDE.template.md`.
- ✅ One-time hook installer (`hooks/install-hooks.*`) + `pre-commit`/`pre-push`.
- ✅ GitHub Actions CI workflow — non-blocking, uploads artifact, **posts the report
  as a PR comment** and updates it on re-runs.
- ✅ Markdown + JSON + timestamped reports.
- ✅ Accuracy pass (validated against a 600-file CRM branch): new-vs-pre-existing
  baseline, tool-crash detection, Windows command-line batching, lockfile-aware
  dependency audit, branch-scoped gitleaks, statement-level Supabase rules,
  enforcement-aware format checks, chunked AI review, `--only`.
  *`scan.py` (the fallback) does not have these — use `scan.js`.*

### Roadmap

- ⏳ A `quality init` command that bootstraps a project automatically.
- ⏳ A three-level `quality quick / review / release` CLI wrapper.
- ⏳ `.claude/commands/` slash-command reviewers and a pre-commit-framework config.
- ⏳ AI-in-CI (Claude review on every PR) and a team metrics dashboard.

---

*Read-only by design. It tells you what's wrong; it never touches your code, your
git history, or your dependencies. The worst it can do is write a report.*

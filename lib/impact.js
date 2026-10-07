#!/usr/bin/env node
/*
 * MarketInk Quality Gate — impact analysis for the function-level AI review.
 *
 * Given the changed TS/JS files and their changed line numbers, it finds:
 *   - which functions/methods the change touched (and their old version),
 *   - who calls them, in ANY file of the project (not just the diff),
 *   - the signatures of what they call,
 * and returns compact, line-numbered "review packets" as JSON.
 *
 * Read-only. Zero dependencies of its own: it borrows the TARGET project's
 * `typescript` package (already in its node_modules for any TS project), so
 * the gate stays dependency-free. It runs as a child process of scan.js so it
 * can get its own heap size (large Next.js projects need several GB).
 *
 * Usage (internal):  node impact.js <input.json> <output.json>
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { createRequire } = require("module");

const TEST_RE = /(^|\/)(__tests__|__mocks__|e2e)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;

function toRel(target, abs) {
  return path.relative(target, abs).split(path.sep).join("/");
}

function loadTypeScript(target) {
  try {
    const req = createRequire(path.join(target, "package.json"));
    return req("typescript");
  } catch {
    return null;
  }
}

// Nearest tsconfig.json / jsconfig.json walking up from the file to the root.
function nearestConfig(target, abs) {
  let dir = path.dirname(abs);
  const root = path.resolve(target);
  for (;;) {
    for (const name of ["tsconfig.json", "jsconfig.json"]) {
      const p = path.join(dir, name);
      if (fs.existsSync(p)) return p;
    }
    if (path.resolve(dir) === root) return null;
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

function makeService(ts, target, configPath, extraFiles, defaultRoots) {
  let fileNames;
  let options;
  if (configPath) {
    const host = { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} };
    const parsed = ts.getParsedCommandLineOfConfigFile(configPath, {}, host);
    fileNames = parsed ? parsed.fileNames : [];
    options = parsed ? parsed.options : {};
  } else {
    fileNames = defaultRoots;
    options = { allowJs: true, checkJs: false, jsx: ts.JsxEmit.Preserve };
  }
  options = { ...options, noEmit: true, incremental: false };
  const known = new Set(fileNames.map((f) => path.resolve(f)));
  for (const f of extraFiles) if (!known.has(path.resolve(f))) fileNames.push(f);

  const host = {
    getScriptFileNames: () => fileNames,
    getScriptVersion: () => "1",
    getScriptSnapshot: (f) => {
      try {
        return ts.ScriptSnapshot.fromString(fs.readFileSync(f, "utf8"));
      } catch {
        return undefined;
      }
    },
    getCurrentDirectory: () => (configPath ? path.dirname(configPath) : target),
    getCompilationSettings: () => options,
    getDefaultLibFileName: (o) => ts.getDefaultLibFilePath(o),
    fileExists: ts.sys.fileExists,
    readFile: ts.sys.readFile,
    readDirectory: ts.sys.readDirectory,
    directoryExists: ts.sys.directoryExists,
    getDirectories: ts.sys.getDirectories,
    useCaseSensitiveFileNames: () => ts.sys.useCaseSensitiveFileNames,
  };
  return ts.createLanguageService(host, ts.createDocumentRegistry());
}

function propName(ts, name) {
  if (!name) return "(anonymous)";
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return "(computed)";
}

const isFnExpr = (ts, n) => n && (ts.isArrowFunction(n) || ts.isFunctionExpression(n));

// Every named function-like declaration with a body, with a qualified name
// (Class.method, outer.inner) and the identifier node used for references.
function collectFunctions(ts, sf) {
  const out = [];
  const lineOf = (pos) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const push = (name, fnNode, declNode, nameNode, ctx) => {
    const qual = ctx ? `${ctx}.${name}` : name;
    out.push({
      name: qual, fnNode, declNode, nameNode,
      start: lineOf(declNode.getStart(sf)), end: lineOf(declNode.getEnd()),
    });
    return qual;
  };
  const visit = (node, ctx) => {
    let fn = null;
    if (ts.isFunctionDeclaration(node) && node.body) {
      fn = [node.name ? node.name.text : "default", node, node, node.name];
    } else if ((ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) ||
      ts.isSetAccessorDeclaration(node) || ts.isConstructorDeclaration(node)) && node.body) {
      fn = [ts.isConstructorDeclaration(node) ? "constructor" : propName(ts, node.name), node, node, node.name];
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && isFnExpr(ts, node.initializer)) {
      const stmt = node.parent && node.parent.parent && ts.isVariableStatement(node.parent.parent)
        ? node.parent.parent : node;
      fn = [node.name.text, node.initializer, stmt, node.name];
    } else if ((ts.isPropertyAssignment(node) || ts.isPropertyDeclaration(node)) && isFnExpr(ts, node.initializer)) {
      fn = [propName(ts, node.name), node.initializer, node, node.name];
    }
    if (fn) {
      const qual = push(fn[0], fn[1], fn[2], fn[3], ctx);
      ts.forEachChild(fn[1], (c) => visit(c, qual));
      return;
    }
    if ((ts.isClassDeclaration(node) || ts.isClassExpression(node))) {
      const cn = node.name ? node.name.text : "(class)";
      ts.forEachChild(node, (c) => visit(c, ctx ? `${ctx}.${cn}` : cn));
      return;
    }
    ts.forEachChild(node, (c) => visit(c, ctx));
  };
  visit(sf, null);
  return out;
}

function isExported(ts, decl) {
  try {
    if (ts.getCombinedModifierFlags(decl) & ts.ModifierFlags.Export) return true;
  } catch {
    /* not a declaration */
  }
  const mods = decl.modifiers || [];
  return mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

function numbered(lines, start) {
  const w = String(start + lines.length).length;
  return lines.map((l, i) => `${String(start + i).padStart(w)}| ${l}`).join("\n");
}

function excerpt(allLines, ranges, ctx) {
  // Merge [a,b] ranges (+ctx) and render each as a numbered block.
  const spans = ranges
    .map(([a, b]) => [Math.max(1, a - ctx), Math.min(allLines.length, b + ctx)])
    .sort((x, y) => x[0] - y[0]);
  const merged = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s[0] <= last[1] + 1) last[1] = Math.max(last[1], s[1]);
    else merged.push([...s]);
  }
  return merged.map(([a, b]) => numbered(allLines.slice(a - 1, b), a)).join("\n   ...\n");
}

function groupRanges(lines) {
  const sorted = [...lines].sort((a, b) => a - b);
  const out = [];
  for (const n of sorted) {
    const last = out[out.length - 1];
    if (last && n <= last[1] + 1) last[1] = n;
    else out.push([n, n]);
  }
  return out;
}

const norm = (s) => s.replace(/\s+/g, " ").trim();

function analyze(input) {
  const { target, limits } = input;
  const ts = loadTypeScript(target);
  if (!ts) return { error: "typescript is not installed in the project's node_modules" };

  const files = input.files.map((f) => ({ ...f, abs: path.resolve(target, f.rel) }));
  const byConfig = new Map();
  for (const f of files) {
    const cfg = nearestConfig(target, f.abs) || "";
    if (!byConfig.has(cfg)) byConfig.set(cfg, []);
    byConfig.get(cfg).push(f);
  }

  const packets = [];
  const notes = [];
  const compiler = [];
  let truncated = 0;
  const fileTextCache = new Map();
  const fnCache = new Map();
  const readLines = (abs) => {
    if (!fileTextCache.has(abs)) {
      let t = "";
      try {
        t = fs.readFileSync(abs, "utf8");
      } catch {
        /* missing */
      }
      fileTextCache.set(abs, t.split(/\r?\n/));
    }
    return fileTextCache.get(abs);
  };

  for (const [cfg, group] of byConfig) {
    const defaultRoots = cfg ? [] : input.defaultRoots.map((r) => path.resolve(target, r));
    const ls = makeService(ts, target, cfg || null, group.map((f) => f.abs), defaultRoots);
    const program = ls.getProgram();
    if (!program) {
      notes.push(`could not build a program for ${cfg ? toRel(target, cfg) : "default roots"}`);
      continue;
    }
    const checker = program.getTypeChecker();
    const o = program.getCompilerOptions();
    compiler.push({
      config: cfg ? toRel(target, cfg) : "(no tsconfig - plain JS roots)",
      strictNullChecks: !!(o.strictNullChecks ?? o.strict),
      checkJs: !!o.checkJs,
    });
    const fnsOf = (sf) => {
      if (!fnCache.has(sf.fileName)) fnCache.set(sf.fileName, collectFunctions(ts, sf));
      return fnCache.get(sf.fileName);
    };

    for (const f of group) {
      if (packets.length >= limits.maxFunctions) {
        truncated++;
        continue;
      }
      const sf = program.getSourceFile(f.abs) ||
        ts.createSourceFile(f.abs, readLines(f.abs).join("\n"), ts.ScriptTarget.Latest, true);
      const lines = readLines(f.abs);
      const fns = fnsOf(sf);
      const changed = f.changedLines === "ALL"
        ? lines.map((_, i) => i + 1)
        : f.changedLines.filter((n) => n >= 1 && n <= lines.length);
      if (!changed.length) continue;

      // Old version of each function, by qualified name.
      const oldFns = new Map();
      if (f.oldText != null) {
        const osf = ts.createSourceFile(f.abs, f.oldText, ts.ScriptTarget.Latest, true);
        const oldLines = f.oldText.split(/\r?\n/);
        for (const o of collectFunctions(ts, osf)) {
          if (!oldFns.has(o.name)) oldFns.set(o.name, oldLines.slice(o.start - 1, o.end).join("\n"));
        }
      }

      // Map each changed line to the function to review: the outermost
      // enclosing function that fits max_body_lines, else the innermost.
      const chosen = new Map();
      const moduleLines = [];
      for (const n of changed) {
        const enclosing = fns.filter((x) => x.start <= n && n <= x.end)
          .sort((a, b) => (b.end - b.start) - (a.end - a.start));
        if (!enclosing.length) {
          if (lines[n - 1] && lines[n - 1].trim()) moduleLines.push(n);
          continue;
        }
        const pick = enclosing.find((x) => x.end - x.start + 1 <= limits.maxBodyLines) ||
          enclosing[enclosing.length - 1];
        if (!chosen.has(pick)) chosen.set(pick, []);
        chosen.get(pick).push(n);
      }

      for (const [fn, fnChanged] of chosen) {
        if (packets.length >= limits.maxFunctions) {
          truncated++;
          continue;
        }
        const bodyText = lines.slice(fn.start - 1, fn.end).join("\n");
        const old = oldFns.has(fn.name) ? oldFns.get(fn.name) : null;
        if (old != null && norm(old) === norm(bodyText)) continue; // whitespace-only
        const tooLong = fn.end - fn.start + 1 > limits.maxBodyLines;
        const body = tooLong
          ? excerpt(lines, groupRanges(fnChanged), 15)
          : numbered(lines.slice(fn.start - 1, fn.end), fn.start);

        // Callers anywhere in the project.
        const callers = [];
        const callerFiles = new Set();
        let callerTotal = 0;
        if (fn.nameNode) {
          let refs = [];
          try {
            refs = ls.findReferences(f.abs, fn.nameNode.getStart(sf)) || [];
          } catch {
            refs = [];
          }
          const seen = new Set();
          for (const rs of refs) {
            for (const r of rs.references) {
              if (r.isDefinition) continue;
              const rsf = program.getSourceFile(r.fileName);
              if (!rsf || /[\\/]node_modules[\\/]/.test(r.fileName)) continue;
              const line = rsf.getLineAndCharacterOfPosition(r.textSpan.start).line + 1;
              if (path.resolve(r.fileName) === path.resolve(f.abs) && line >= fn.start && line <= fn.end) continue;
              const encl = fnsOf(rsf).filter((x) => x.start <= line && line <= x.end)
                .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0];
              callerFiles.add(toRel(target, r.fileName));
              const key = `${r.fileName}:${encl ? encl.name : line}`;
              if (seen.has(key)) continue;
              seen.add(key);
              callerTotal++;
              if (callers.length >= limits.maxCallers) continue;
              const rel = toRel(target, r.fileName);
              const rl = readLines(r.fileName);
              const a = Math.max(1, line - limits.callerContext);
              const b = Math.min(rl.length, line + limits.callerContext);
              callers.push({
                file: rel, line, enclosing: encl ? encl.name : "(module)",
                isTest: TEST_RE.test(rel), start: a, end: b,
                snippet: numbered(rl.slice(a - 1, b), a),
              });
            }
          }
        }

        // Signatures of what the function calls (project code first).
        const callees = [];
        const seenCallee = new Set();
        const walk = (node) => {
          if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
            try {
              const sig = checker.getResolvedSignature(node);
              const expr = node.expression;
              const name = expr.getText(sf).replace(/\s+/g, "").slice(0, 80);
              const decl = sig && sig.getDeclaration ? sig.getDeclaration() : sig && sig.declaration;
              const dsf = decl && decl.getSourceFile ? decl.getSourceFile() : null;
              const lib = !dsf || /[\\/]node_modules[\\/]/.test(dsf.fileName) || dsf.hasNoDefaultLib;
              if (sig && !seenCallee.has(name)) {
                seenCallee.add(name);
                let text = checker.signatureToString(sig, undefined, ts.TypeFormatFlags.NoTruncation);
                if (text.length > 240) text = text.slice(0, 240) + "...";
                callees.push({
                  name, signature: text, project: !lib,
                  file: !lib && dsf ? toRel(target, dsf.fileName) : null,
                  line: !lib && dsf ? dsf.getLineAndCharacterOfPosition(decl.getStart()).line + 1 : null,
                });
              }
            } catch {
              /* unresolvable call */
            }
          }
          ts.forEachChild(node, walk);
        };
        walk(fn.fnNode);
        callees.sort((a, b) => Number(b.project) - Number(a.project));

        packets.push({
          kind: "function", file: f.rel, name: fn.name,
          status: old == null ? (f.oldText == null ? "new file" : "new") : "modified",
          exported: isExported(ts, fn.declNode),
          start: fn.start, end: fn.end, excerpt: tooLong,
          changedLines: fnChanged,
          body, oldBody: old != null && old.split(/\r?\n/).length <= limits.maxBodyLines ? old : null,
          callers, callerTotal, callerFiles: [...callerFiles].sort(),
          callees: callees.slice(0, limits.maxCallees), calleeTotal: callees.length,
        });
      }

      if (moduleLines.length && packets.length < limits.maxFunctions) {
        packets.push({
          kind: "module", file: f.rel, name: "(module-level code)",
          status: f.oldText == null ? "new file" : "modified", exported: false,
          start: Math.min(...moduleLines), end: Math.max(...moduleLines), excerpt: true,
          changedLines: moduleLines,
          body: excerpt(lines, groupRanges(moduleLines), 3).split("\n").slice(0, 120).join("\n"),
          oldBody: null, callers: [], callerTotal: 0, callerFiles: [], callees: [], calleeTotal: 0,
        });
      }
    }
  }
  return { packets, truncated, notes, compiler, typescript: ts.version };
}

function main() {
  const [inFile, outFile] = process.argv.slice(2);
  let out;
  try {
    out = analyze(JSON.parse(fs.readFileSync(inFile, "utf8")));
  } catch (e) {
    out = { error: String((e && e.stack) || e) };
  }
  fs.writeFileSync(outFile, JSON.stringify(out));
}

main();

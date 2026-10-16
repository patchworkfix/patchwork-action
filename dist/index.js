var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/main.ts
var import_fs2 = require("fs");
var import_child_process = require("child_process");

// src/scanner.ts
var import_fs = require("fs");
var import_path = __toESM(require("path"));

// src/secretPatterns.ts
function mask(secret) {
  const s = secret.trim();
  if (s.length <= 8) return s.slice(0, 2) + "****";
  return s.slice(0, 4) + "****" + s.slice(-2);
}
var SECRET_RULES = [
  { id: "openai-key", title: "OpenAI API key", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g, severity: "critical", fix: "Revoke the key at platform.openai.com/api-keys, create a new one, and load it from a server-side environment variable." },
  { id: "anthropic-key", title: "Anthropic API key", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,})\b/g, severity: "critical", fix: "Revoke the key in the Anthropic console and load a new one from a server-side environment variable." },
  { id: "stripe-live", title: "Stripe live secret/restricted key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/g, severity: "critical", fix: "Roll the key immediately in the Stripe dashboard (Developers \u2192 API keys) and keep it only in server env vars." },
  { id: "stripe-test", title: "Stripe test secret key", re: /\b(sk_test_[A-Za-z0-9]{16,})\b/g, severity: "medium", fix: "Test keys can't move real money, but roll it anyway and keep it out of the repo." },
  { id: "aws-access-key", title: "AWS access key ID", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, severity: "critical", fix: "Deactivate the key in AWS IAM, check CloudTrail for misuse, and use env vars or IAM roles instead." },
  { id: "aws-secret", title: "AWS secret access key", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi, severity: "critical", group: 1, fix: "Deactivate the key pair in AWS IAM and rotate it." },
  { id: "google-api-key", title: "Google / Firebase API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: "medium", fix: "Firebase web keys are semi-public, but restrict the key (HTTP referrers + API restrictions) in Google Cloud Console, and make sure security rules protect your data." },
  { id: "github-token", title: "GitHub token", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g, severity: "critical", fix: "Revoke the token at github.com/settings/tokens and use a secret store." },
  { id: "slack-token", title: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, severity: "high", fix: "Revoke the token in your Slack app settings." },
  { id: "private-key", title: "Private key", re: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)/g, severity: "critical", fix: "Treat the key as compromised: generate a new key pair, revoke the old one, and remove it from git history (git filter-repo / BFG)." }
];
var JWT_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,})\b/g;
var GENERIC_RE = /\b([A-Za-z0-9_]*(?:secret|token|api_?key|apikey|password|passwd|private_?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']([^"'\s]{16,})["']/gi;
function shannon(s) {
  const m = /* @__PURE__ */ new Map();
  for (const c of s) m.set(c, (m.get(c) || 0) + 1);
  let h = 0;
  for (const n of m.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
var PLACEHOLDER = /(your|xxx|example|changeme|placeholder|dummy|test_?key|<|\$\{|process\.env|replace|insert|todo|\*\*\*)/i;

// src/scanner.ts
var WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2 };
var SEV_ORDER = ["critical", "high", "medium", "low"];
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", ".next", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", "coverage", ".turbo", ".vercel"]);
var TEXT_EXT = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|py|rb|go|php|java|kt|rs|json|ya?ml|toml|env|sql|rules|txt|md|sh|ini|cfg|conf|properties|html|xml|tf)$/i;
var MAX_FILE_BYTES = 512 * 1024;
var MAX_FILES = 5e3;
function decodeJwtRole(payload) {
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).role ?? null;
  } catch {
    return null;
  }
}
var isExample = (f) => /\.(example|sample|template|dist)$|\.env\.(example|sample|template)/i.test(f) || /(^|\/)(tests?|__tests__|fixtures?|spec|docs?|examples?)\//i.test(f) && false;
function isClientSide(file) {
  if (/(^|\/)(pages\/api|app\/api)\//.test(file) || /route\.(t|j)sx?$/.test(file)) return false;
  if (/\.(server)\.(t|j)sx?$/.test(file)) return false;
  return /(^|\/)(src\/)?(components|pages|app|public|client|frontend|hooks|views|web)\//.test(file) || /\.(jsx|tsx|vue|svelte)$/.test(file);
}
function isApiRoute(file, content) {
  if (/(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(file)) return true;
  if (/(^|\/)app\/(.+\/)?route\.(t|j)sx?$/.test(file)) return true;
  if (/\b(app|router)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]/.test(content) && /require\(["']express["']\)|from ["']express["']/.test(content)) return true;
  return false;
}
var AUTH_RE = /\b(getServerSession|getSession|auth\(\)|currentUser|getUser|getAuth|requireAuth|isAuthenticated|verifyToken|jwt|jsonwebtoken|jose|authorization|clerk|withAuth|session|passport|bearer|x-api-key|apiKey\s*!==|unauthori[sz]ed|401|verifyIdToken|supabase\.auth|ensureAuth|authenticate|middleware)\b/i;
var PAID_RE = [
  { name: "OpenAI", re: /(new\s+OpenAI\s*\(|openai\.(chat|completions|responses|images|embeddings|audio)|api\.openai\.com)/ },
  { name: "Anthropic", re: /(new\s+Anthropic\s*\(|anthropic\.messages|api\.anthropic\.com)/ },
  { name: "Stripe", re: /(stripe\.(charges|paymentIntents|checkout)\.|api\.stripe\.com)/ },
  { name: "Replicate", re: /(new\s+Replicate\s*\(|api\.replicate\.com)/ },
  { name: "Google Gemini", re: /(GoogleGenerativeAI|generativelanguage\.googleapis\.com)/ },
  { name: "Twilio", re: /(twilio\(|\.messages\.create\(|api\.twilio\.com)/ },
  { name: "Resend/SendGrid", re: /(resend\.emails\.send|sgMail\.send|api\.sendgrid\.com)/ },
  { name: "ElevenLabs", re: /api\.elevenlabs\.io/ }
];
var RATE_RE = /(rate.?limit|ratelimit|@upstash\/ratelimit|express-rate-limit|limiter|throttle|max_?requests|quota|usage.?(cap|limit)|credits?\s*[<>]=?|daily.?limit|slowDown|bottleneck|p-limit|tokens?Remaining)/i;
function lineOf(content, idx) {
  return content.slice(0, idx).split("\n").length;
}
function scanFile(file, content) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const add = (f) => {
    const k = f.id + f.file + f.line;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(f);
    }
  };
  const exampleFile = isExample(file);
  const base = import_path.default.posix.basename(file);
  if (/^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/i.test(base)) {
    add({
      id: "env-file",
      title: "Committed .env file",
      severity: "high",
      file,
      line: 1,
      explanation: `${file} is committed to the repo. .env files usually hold real credentials, and anyone who can read the repo (or its history) can read them.`,
      fix: "Delete the file from git (git rm --cached), add .env* (but not .env.example) to .gitignore, rotate every value it contained, and purge it from history with git filter-repo or BFG."
    });
  }
  if (!exampleFile) {
    const matchedSpans = [];
    for (const r of SECRET_RULES) {
      r.re.lastIndex = 0;
      let m;
      while (m = r.re.exec(content)) {
        const val = m[r.group ?? 1];
        if (r.id !== "private-key" && PLACEHOLDER.test(val)) continue;
        if (r.id === "openai-key" && /^sk-ant-/.test(val)) continue;
        matchedSpans.push([m.index, m.index + m[0].length]);
        add({
          id: r.id,
          title: `${r.title} exposed`,
          severity: r.severity,
          file,
          line: lineOf(content, m.index),
          evidence: r.id === "private-key" ? val : mask(val),
          explanation: `This ${r.title} is in the source code. Anyone with access to the repo can use it${r.severity === "critical" ? " to run up bills or access your data" : ""}.`,
          fix: r.fix
        });
      }
    }
    JWT_RE.lastIndex = 0;
    let j;
    while (j = JWT_RE.exec(content)) {
      const role = decodeJwtRole(j[2]);
      matchedSpans.push([j.index, j.index + j[0].length]);
      if (role === "service_role") {
        const client = isClientSide(file);
        add({
          id: "supabase-service-role",
          title: client ? "Supabase service_role key in client-side code" : "Supabase service_role key committed",
          severity: "critical",
          file,
          line: lineOf(content, j.index),
          evidence: mask(j[1]),
          explanation: "The Supabase service_role key bypasses all Row Level Security. Anyone holding it has full read/write access to your entire database.",
          fix: "Rotate the JWT secret / service key in Supabase (Settings \u2192 API), use only the anon key in the browser, and keep service_role in server-only env vars."
        });
      }
    }
    GENERIC_RE.lastIndex = 0;
    let g;
    while (g = GENERIC_RE.exec(content)) {
      const val = g[2];
      if (matchedSpans.some(([a, b]) => g.index < b && g.index + g[0].length > a)) continue;
      if (PLACEHOLDER.test(val) || shannon(val) < 3.5 || /^[a-z]+$/i.test(val) || /^https?:/.test(val) || /^(NEXT_PUBLIC_|[A-Z_]+$)/.test(val)) continue;
      add({
        id: "generic-secret",
        title: `Possible hard-coded secret (${g[1]})`,
        severity: "high",
        file,
        line: lineOf(content, g.index),
        evidence: mask(val),
        explanation: `The variable "${g[1]}" is assigned a long random-looking string, which is very likely a real credential.`,
        fix: "Move the value into an environment variable, rotate it if it was ever real, and remove it from git history."
      });
    }
  }
  if (isClientSide(file) || /NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_/.test(content)) {
    const re = /\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|OPENAI|ANTHROPIC|STRIPE_SECRET|SK_)[A-Z0-9_]*)/g;
    let m;
    while (m = re.exec(content)) {
      add({
        id: "public-env-secret",
        title: `Server secret exposed via public env var ${m[1]}`,
        severity: "critical",
        file,
        line: lineOf(content, m.index),
        explanation: `Variables prefixed with NEXT_PUBLIC_/VITE_/REACT_APP_ are bundled into the JavaScript sent to every visitor. "${m[1]}" looks like a secret that should never reach the browser.`,
        fix: "Rename it without the public prefix, use it only in server code (API routes / server actions), and rotate the value."
      });
    }
    if (isClientSide(file)) {
      const sr = /service_?role/gi;
      let s;
      while (s = sr.exec(content)) {
        add({
          id: "client-service-role",
          title: "service_role referenced in client-side code",
          severity: "high",
          file,
          line: lineOf(content, s.index),
          explanation: "Client-side code references the Supabase service_role key, which bypasses Row Level Security if it reaches the browser.",
          fix: "Only use the anon key in the browser; move privileged queries into a server route that checks the user's session."
        });
        break;
      }
    }
  }
  if (/(firestore\.rules|storage\.rules|\.rules)$/.test(file)) {
    const re = /allow\s+[a-z, ]*(read|write)[a-z, ]*:\s*if\s+true\s*;?/g;
    let m;
    while (m = re.exec(content))
      add({
        id: "firebase-open-rules",
        title: "Firebase security rules allow public access",
        severity: "critical",
        file,
        line: lineOf(content, m.index),
        evidence: m[0].trim(),
        explanation: "This rule lets anyone on the internet read or write your Firebase data without signing in.",
        fix: "Require auth, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;` and test with the Firebase Rules simulator."
      });
  }
  if (/database\.rules\.json$/.test(file)) {
    const re = /"\.(read|write)"\s*:\s*(true|"true")/g;
    let m;
    while (m = re.exec(content))
      add({
        id: "firebase-rtdb-open",
        title: "Realtime Database rules are public",
        severity: "critical",
        file,
        line: lineOf(content, m.index),
        evidence: m[0],
        explanation: `".${m[1]}": true means anyone can ${m[1]} your entire Realtime Database.`,
        fix: 'Use rules like ".read": "auth != null" and scope paths to auth.uid.'
      });
  }
  if (/\.sql$/i.test(file)) {
    const re = /alter\s+table\s+[^;]*?disable\s+row\s+level\s+security/gi;
    let m;
    while (m = re.exec(content))
      add({
        id: "supabase-rls-disabled",
        title: "Row Level Security disabled",
        severity: "high",
        file,
        line: lineOf(content, m.index),
        explanation: "This migration disables Row Level Security, so anyone with your public anon key can read and modify this table.",
        fix: "Enable RLS (`alter table ... enable row level security;`) and add policies that restrict rows to the signed-in user."
      });
    const created = [...content.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z0-9_]+)"?/gi)];
    for (const c of created) {
      const t = c[1];
      if (!new RegExp(`alter\\s+table\\s+(?:public\\.)?"?${t}"?\\s+enable\\s+row\\s+level\\s+security`, "i").test(content))
        add({
          id: "supabase-rls-missing",
          title: `Table "${t}" created without enabling RLS`,
          severity: "medium",
          file,
          line: lineOf(content, c.index),
          explanation: `The table "${t}" is created but RLS is never enabled in this migration. In Supabase, tables without RLS are readable/writable with the public anon key.`,
          fix: `Add \`alter table ${t} enable row level security;\` plus appropriate policies.`
        });
    }
  }
  if (/\.(t|j)sx?$|\.m?js$/.test(file)) {
    const api = isApiRoute(file, content);
    const hasAuth = AUTH_RE.test(content);
    if (api && !hasAuth) {
      add({
        id: "api-no-auth",
        title: "API route with no authentication check",
        severity: "medium",
        file,
        line: 1,
        explanation: "This API endpoint doesn't appear to check who is calling it (no session, getUser, JWT or API-key check). Anyone who finds the URL can call it.",
        fix: "Check the user's session at the top of the handler (e.g. getServerSession / supabase.auth.getUser / Clerk auth()) and return 401 if missing. If it's intentionally public, add input validation and rate limiting."
      });
    }
    for (const p of PAID_RE) {
      const m = p.re.exec(content);
      if (m && !RATE_RE.test(content)) {
        add({
          id: "unbounded-paid-api",
          title: `Unbounded ${p.name} usage`,
          severity: api && !hasAuth ? "high" : "medium",
          file,
          line: lineOf(content, m.index),
          explanation: `This file calls ${p.name} (a paid API) with no visible rate limiting or usage cap${api && !hasAuth ? ", from an unauthenticated endpoint \u2014 anyone could run up your bill" : ""}.`,
          fix: "Add per-user/IP rate limiting (e.g. @upstash/ratelimit), cap tokens/requests per user per day, set a hard spending limit in the provider dashboard, and require auth."
        });
      }
    }
  }
  return out;
}
async function walk(dir, root, acc) {
  if (acc.length >= MAX_FILES) return;
  const entries = await import_fs.promises.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (acc.length >= MAX_FILES) return;
    const full = import_path.default.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(full, root, acc);
    } else if (e.isFile()) {
      const rel = import_path.default.relative(root, full).split(import_path.default.sep).join("/");
      if (TEXT_EXT.test(e.name) || !/\.[^.]+$/.test(e.name) || /^\.env/.test(e.name) || /\.rules$/.test(e.name)) acc.push(rel);
    }
  }
}
function scoreFindings(findings) {
  const perRule = /* @__PURE__ */ new Map();
  let deduction = 0;
  for (const f of findings) {
    const n = perRule.get(f.id) || 0;
    perRule.set(f.id, n + 1);
    deduction += WEIGHTS[f.severity] / (n + 1);
  }
  return Math.max(0, Math.round(100 - deduction));
}
var grade = (s) => s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : s >= 40 ? "D" : "F";
async function scanDirectory(root, repo) {
  const files = [];
  await walk(root, root, files);
  let findings = [];
  for (const rel of files) {
    const st = await import_fs.promises.stat(import_path.default.join(root, rel));
    if (st.size > MAX_FILE_BYTES) continue;
    const content = await import_fs.promises.readFile(import_path.default.join(root, rel), "utf8");
    if (content.includes("\0")) continue;
    findings.push(...scanFile(rel, content));
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const score = scoreFindings(findings);
  const summary = findings.length === 0 ? "No issues found by our automated checks. Nice work \u2014 keep secrets in env vars and keep auth on every endpoint." : `We found ${findings.length} issue${findings.length > 1 ? "s" : ""}: ${SEV_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}. ` + (counts.critical ? "Fix the critical ones today \u2014 they can lead directly to stolen data or a surprise bill." : "Nothing critical, but the items below are worth fixing before you grow.");
  return { repo, scannedAt: (/* @__PURE__ */ new Date()).toISOString(), filesScanned: files.length, score, grade: grade(score), summary, counts, findings };
}

// src/main.ts
var MARKER = "<!-- patchworkfix-action -->";
var input = (n, d = "") => (process.env[`INPUT_${n.toUpperCase().replace(/ /g, "_")}`] ?? "").trim() || d;
var SEV = ["critical", "high", "medium", "low"];
var ICON = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u26AA" };
var esc = (s) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
function changedFiles(base) {
  if (!base) return null;
  try {
    (0, import_child_process.execSync)(`git fetch --no-tags --depth=1 origin ${base}`, { stdio: "ignore" });
    return new Set((0, import_child_process.execSync)(`git diff --name-only FETCH_HEAD...HEAD || git diff --name-only FETCH_HEAD HEAD`, { encoding: "utf8" }).split("\n").filter(Boolean));
  } catch {
    return null;
  }
}
function render(r, changed, failOn, failed) {
  const inPr = (f) => changed?.has(f.file);
  const rows = r.findings.slice(0, 50).map((f) => `| ${ICON[f.severity]} ${f.severity} | ${esc(f.title)} | \`${esc(f.file)}:${f.line}\`${inPr(f) ? " \u{1F195}" : ""} | ${f.evidence ? "`" + esc(f.evidence) + "`" : ""} |`);
  const counts = SEV.filter((s) => r.counts[s]).map((s) => `${ICON[s]} ${r.counts[s]} ${s}`).join(" \xB7 ") || "no findings";
  const out = [MARKER, `## \u{1FA79} Patchwork scan: **${r.score}/100 (grade ${r.grade})**`, ``, `${counts} \xB7 ${r.filesScanned} file${r.filesScanned === 1 ? "" : "s"} scanned${changed ? ` \xB7 ${r.findings.filter(inPr).length} in files changed by this PR (\u{1F195})` : ""}`, ``, r.summary, ``];
  if (rows.length) {
    out.push(`| Severity | Issue | Where | Evidence (masked) |`, `|---|---|---|---|`, ...rows);
    if (r.findings.length > 50) out.push(``, `\u2026and ${r.findings.length - 50} more (see the job summary).`);
    out.push(``, `<details><summary>How to fix</summary>`, ``);
    const seen = /* @__PURE__ */ new Set();
    for (const f of r.findings) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      out.push(`- **${esc(f.title)}**: ${f.fix}`);
    }
    out.push(``, `</details>`);
  }
  out.push(
    ``,
    failed ? `\u274C Failing because findings at or above **${failOn}** were found.` : `\u2705 Check passes (fail-on: ${failOn}).`,
    ``,
    `<sub>Static checks only: may miss issues or flag false positives. Your code never leaves this CI run. Want it fixed for you? [patchworkfix.com](https://www.patchworkfix.com/services)</sub>`
  );
  return out.join("\n");
}
async function gh(path2, method = "GET", body) {
  const r = await fetch(`${process.env.GITHUB_API_URL || "https://api.github.com"}${path2}`, {
    method,
    headers: { Authorization: `Bearer ${input("github-token")}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "patchwork-action" },
    body: body ? JSON.stringify(body) : void 0
  });
  if (!r.ok) throw new Error(`GitHub API ${method} ${path2}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.status === 204 ? null : r.json();
}
async function main() {
  const root = input("path", process.env.GITHUB_WORKSPACE || ".");
  const failOn = input("fail-on", "critical").toLowerCase();
  const event = process.env.GITHUB_EVENT_PATH ? JSON.parse(await import_fs2.promises.readFile(process.env.GITHUB_EVENT_PATH, "utf8")) : {};
  const pr = event.pull_request;
  const repo = process.env.GITHUB_REPOSITORY || "local";
  const report = await scanDirectory(root, repo);
  const changed = pr ? changedFiles(pr.base?.ref) : null;
  const idx = SEV.indexOf(failOn);
  const failed = idx >= 0 && SEV.slice(0, idx + 1).some((s) => report.counts[s] > 0);
  const md = render(report, changed, failOn, failed);
  console.log(md);
  if (process.env.GITHUB_STEP_SUMMARY) await import_fs2.promises.appendFile(process.env.GITHUB_STEP_SUMMARY, md + "\n");
  if (process.env.GITHUB_OUTPUT) await import_fs2.promises.appendFile(process.env.GITHUB_OUTPUT, `score=${report.score}
grade=${report.grade}
critical=${report.counts.critical}
high=${report.counts.high}
`);
  if (pr && input("comment", "true") === "true" && input("github-token")) {
    try {
      const comments = await gh(`/repos/${repo}/issues/${pr.number}/comments?per_page=100`);
      const mine = comments.find((c) => typeof c.body === "string" && c.body.startsWith(MARKER));
      if (mine) await gh(`/repos/${repo}/issues/comments/${mine.id}`, "PATCH", { body: md });
      else await gh(`/repos/${repo}/issues/${pr.number}/comments`, "POST", { body: md });
    } catch (e) {
      console.log(`::warning::Could not post PR comment (needs permissions: pull-requests: write). ${e.message}`);
    }
  }
  for (const f of report.findings.slice(0, 20)) {
    const lvl = f.severity === "critical" || f.severity === "high" ? "error" : "warning";
    console.log(`::${lvl} file=${f.file},line=${f.line},title=${f.title.replace(/[,:\n]/g, " ")}::${f.explanation.replace(/\n/g, " ")}`);
  }
  if (failed) {
    console.log(`::error::Patchwork found ${failOn}-or-worse issues (score ${report.score}/100).`);
    process.exitCode = 1;
  }
}
main().catch((e) => {
  console.log(`::error::${e.message}`);
  process.exitCode = 1;
});

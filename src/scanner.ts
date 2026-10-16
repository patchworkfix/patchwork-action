import { promises as fs } from "fs";
import path from "path";
import { mask, SECRET_RULES, JWT_RE, GENERIC_RE, shannon, PLACEHOLDER } from "./secretPatterns";
export { mask, shannon } from "./secretPatterns";

export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  explanation: string;
  fix: string;
  evidence?: string;
}
export interface Report {
  repo: string;
  scannedAt: string;
  filesScanned: number;
  score: number;
  grade: string;
  summary: string;
  counts: Record<Severity, number>;
  findings: Finding[];
}

export const WEIGHTS: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 2 };
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", "coverage", ".turbo", ".vercel"]);
const TEXT_EXT = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|py|rb|go|php|java|kt|rs|json|ya?ml|toml|env|sql|rules|txt|md|sh|ini|cfg|conf|properties|html|xml|tf)$/i;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 5000;

function decodeJwtRole(payload: string): string | null {
  try { return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).role ?? null; } catch { return null; }
}

const isExample = (f: string) => /\.(example|sample|template|dist)$|\.env\.(example|sample|template)/i.test(f) || /(^|\/)(tests?|__tests__|fixtures?|spec|docs?|examples?)\//i.test(f) && false;

export function isClientSide(file: string): boolean {
  if (/(^|\/)(pages\/api|app\/api)\//.test(file) || /route\.(t|j)sx?$/.test(file)) return false;
  if (/\.(server)\.(t|j)sx?$/.test(file)) return false;
  return /(^|\/)(src\/)?(components|pages|app|public|client|frontend|hooks|views|web)\//.test(file) || /\.(jsx|tsx|vue|svelte)$/.test(file);
}

export function isApiRoute(file: string, content: string): boolean {
  if (/(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(file)) return true;
  if (/(^|\/)app\/(.+\/)?route\.(t|j)sx?$/.test(file)) return true;
  if (/\b(app|router)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]/.test(content) && /require\(["']express["']\)|from ["']express["']/.test(content)) return true;
  return false;
}

const AUTH_RE = /\b(getServerSession|getSession|auth\(\)|currentUser|getUser|getAuth|requireAuth|isAuthenticated|verifyToken|jwt|jsonwebtoken|jose|authorization|clerk|withAuth|session|passport|bearer|x-api-key|apiKey\s*!==|unauthori[sz]ed|401|verifyIdToken|supabase\.auth|ensureAuth|authenticate|middleware)\b/i;
const PAID_RE: { name: string; re: RegExp }[] = [
  { name: "OpenAI", re: /(new\s+OpenAI\s*\(|openai\.(chat|completions|responses|images|embeddings|audio)|api\.openai\.com)/ },
  { name: "Anthropic", re: /(new\s+Anthropic\s*\(|anthropic\.messages|api\.anthropic\.com)/ },
  { name: "Stripe", re: /(stripe\.(charges|paymentIntents|checkout)\.|api\.stripe\.com)/ },
  { name: "Replicate", re: /(new\s+Replicate\s*\(|api\.replicate\.com)/ },
  { name: "Google Gemini", re: /(GoogleGenerativeAI|generativelanguage\.googleapis\.com)/ },
  { name: "Twilio", re: /(twilio\(|\.messages\.create\(|api\.twilio\.com)/ },
  { name: "Resend/SendGrid", re: /(resend\.emails\.send|sgMail\.send|api\.sendgrid\.com)/ },
  { name: "ElevenLabs", re: /api\.elevenlabs\.io/ },
];
const RATE_RE = /(rate.?limit|ratelimit|@upstash\/ratelimit|express-rate-limit|limiter|throttle|max_?requests|quota|usage.?(cap|limit)|credits?\s*[<>]=?|daily.?limit|slowDown|bottleneck|p-limit|tokens?Remaining)/i;

function lineOf(content: string, idx: number) { return content.slice(0, idx).split("\n").length; }

export function scanFile(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const add = (f: Finding) => { const k = f.id + f.file + f.line; if (!seen.has(k)) { seen.add(k); out.push(f); } };
  const exampleFile = isExample(file);

  // .env files
  const base = path.posix.basename(file);
  if (/^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/i.test(base)) {
    add({ id: "env-file", title: "Committed .env file", severity: "high", file, line: 1,
      explanation: `${file} is committed to the repo. .env files usually hold real credentials, and anyone who can read the repo (or its history) can read them.`,
      fix: "Delete the file from git (git rm --cached), add .env* (but not .env.example) to .gitignore, rotate every value it contained, and purge it from history with git filter-repo or BFG." });
  }

  if (!exampleFile) {
    const matchedSpans: [number, number][] = [];
    for (const r of SECRET_RULES) {
      r.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = r.re.exec(content))) {
        const val = m[r.group ?? 1];
        if (r.id !== "private-key" && PLACEHOLDER.test(val)) continue;
        if (r.id === "openai-key" && /^sk-ant-/.test(val)) continue;
        matchedSpans.push([m.index, m.index + m[0].length]);
        add({ id: r.id, title: `${r.title} exposed`, severity: r.severity, file, line: lineOf(content, m.index),
          evidence: r.id === "private-key" ? val : mask(val),
          explanation: `This ${r.title} is in the source code. Anyone with access to the repo can use it${r.severity === "critical" ? " to run up bills or access your data" : ""}.`,
          fix: r.fix });
      }
    }
    // JWTs: supabase service_role
    JWT_RE.lastIndex = 0;
    let j: RegExpExecArray | null;
    while ((j = JWT_RE.exec(content))) {
      const role = decodeJwtRole(j[2]);
      matchedSpans.push([j.index, j.index + j[0].length]);
      if (role === "service_role") {
        const client = isClientSide(file);
        add({ id: "supabase-service-role", title: client ? "Supabase service_role key in client-side code" : "Supabase service_role key committed",
          severity: "critical", file, line: lineOf(content, j.index), evidence: mask(j[1]),
          explanation: "The Supabase service_role key bypasses all Row Level Security. Anyone holding it has full read/write access to your entire database.",
          fix: "Rotate the JWT secret / service key in Supabase (Settings → API), use only the anon key in the browser, and keep service_role in server-only env vars." });
      }
    }
    // generic high-entropy assignments
    GENERIC_RE.lastIndex = 0;
    let g: RegExpExecArray | null;
    while ((g = GENERIC_RE.exec(content))) {
      const val = g[2];
      if (matchedSpans.some(([a, b]) => g!.index < b && g!.index + g![0].length > a)) continue;
      if (PLACEHOLDER.test(val) || shannon(val) < 3.5 || /^[a-z]+$/i.test(val) || /^https?:/.test(val) || /^(NEXT_PUBLIC_|[A-Z_]+$)/.test(val)) continue;
      add({ id: "generic-secret", title: `Possible hard-coded secret (${g[1]})`, severity: "high", file, line: lineOf(content, g.index), evidence: mask(val),
        explanation: `The variable "${g[1]}" is assigned a long random-looking string, which is very likely a real credential.`,
        fix: "Move the value into an environment variable, rotate it if it was ever real, and remove it from git history." });
    }
  }

  // Client-side exposure of server keys
  if (isClientSide(file) || /NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_/.test(content)) {
    const re = /\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|OPENAI|ANTHROPIC|STRIPE_SECRET|SK_)[A-Z0-9_]*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content))) {
      add({ id: "public-env-secret", title: `Server secret exposed via public env var ${m[1]}`, severity: "critical", file, line: lineOf(content, m.index),
        explanation: `Variables prefixed with NEXT_PUBLIC_/VITE_/REACT_APP_ are bundled into the JavaScript sent to every visitor. "${m[1]}" looks like a secret that should never reach the browser.`,
        fix: "Rename it without the public prefix, use it only in server code (API routes / server actions), and rotate the value." });
    }
    if (isClientSide(file)) {
      const sr = /service_?role/gi;
      let s: RegExpExecArray | null;
      while ((s = sr.exec(content))) {
        add({ id: "client-service-role", title: "service_role referenced in client-side code", severity: "high", file, line: lineOf(content, s.index),
          explanation: "Client-side code references the Supabase service_role key, which bypasses Row Level Security if it reaches the browser.",
          fix: "Only use the anon key in the browser; move privileged queries into a server route that checks the user's session." });
        break;
      }
    }
  }

  // Firebase rules
  if (/(firestore\.rules|storage\.rules|\.rules)$/.test(file)) {
    const re = /allow\s+[a-z, ]*(read|write)[a-z, ]*:\s*if\s+true\s*;?/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)))
      add({ id: "firebase-open-rules", title: "Firebase security rules allow public access", severity: "critical", file, line: lineOf(content, m.index), evidence: m[0].trim(),
        explanation: "This rule lets anyone on the internet read or write your Firebase data without signing in.",
        fix: "Require auth, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;` and test with the Firebase Rules simulator." });
  }
  if (/database\.rules\.json$/.test(file)) {
    const re = /"\.(read|write)"\s*:\s*(true|"true")/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)))
      add({ id: "firebase-rtdb-open", title: "Realtime Database rules are public", severity: "critical", file, line: lineOf(content, m.index), evidence: m[0],
        explanation: `".${m[1]}": true means anyone can ${m[1]} your entire Realtime Database.`,
        fix: 'Use rules like ".read": "auth != null" and scope paths to auth.uid.' });
  }
  // Supabase RLS
  if (/\.sql$/i.test(file)) {
    const re = /alter\s+table\s+[^;]*?disable\s+row\s+level\s+security/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)))
      add({ id: "supabase-rls-disabled", title: "Row Level Security disabled", severity: "high", file, line: lineOf(content, m.index),
        explanation: "This migration disables Row Level Security, so anyone with your public anon key can read and modify this table.",
        fix: "Enable RLS (`alter table ... enable row level security;`) and add policies that restrict rows to the signed-in user." });
    const created = [...content.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z0-9_]+)"?/gi)];
    for (const c of created) {
      const t = c[1];
      if (!new RegExp(`alter\\s+table\\s+(?:public\\.)?"?${t}"?\\s+enable\\s+row\\s+level\\s+security`, "i").test(content))
        add({ id: "supabase-rls-missing", title: `Table "${t}" created without enabling RLS`, severity: "medium", file, line: lineOf(content, c.index!),
          explanation: `The table "${t}" is created but RLS is never enabled in this migration. In Supabase, tables without RLS are readable/writable with the public anon key.`,
          fix: `Add \`alter table ${t} enable row level security;\` plus appropriate policies.` });
    }
  }

  // API routes w/o auth + paid API calls
  if (/\.(t|j)sx?$|\.m?js$/.test(file)) {
    const api = isApiRoute(file, content);
    const hasAuth = AUTH_RE.test(content);
    if (api && !hasAuth) {
      add({ id: "api-no-auth", title: "API route with no authentication check", severity: "medium", file, line: 1,
        explanation: "This API endpoint doesn't appear to check who is calling it (no session, getUser, JWT or API-key check). Anyone who finds the URL can call it.",
        fix: "Check the user's session at the top of the handler (e.g. getServerSession / supabase.auth.getUser / Clerk auth()) and return 401 if missing. If it's intentionally public, add input validation and rate limiting." });
    }
    for (const p of PAID_RE) {
      const m = p.re.exec(content);
      if (m && !RATE_RE.test(content)) {
        add({ id: "unbounded-paid-api", title: `Unbounded ${p.name} usage`, severity: api && !hasAuth ? "high" : "medium", file, line: lineOf(content, m.index),
          explanation: `This file calls ${p.name} (a paid API) with no visible rate limiting or usage cap${api && !hasAuth ? ", from an unauthenticated endpoint — anyone could run up your bill" : ""}.`,
          fix: "Add per-user/IP rate limiting (e.g. @upstash/ratelimit), cap tokens/requests per user per day, set a hard spending limit in the provider dashboard, and require auth." });
      }
    }
  }
  return out;
}

async function walk(dir: string, root: string, acc: string[]) {
  if (acc.length >= MAX_FILES) return;
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (acc.length >= MAX_FILES) return;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) await walk(full, root, acc); }
    else if (e.isFile()) {
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (TEXT_EXT.test(e.name) || !/\.[^.]+$/.test(e.name) || /^\.env/.test(e.name) || /\.rules$/.test(e.name)) acc.push(rel);
    }
  }
}

export function scoreFindings(findings: Finding[]): number {
  // weight each severity, with diminishing returns per repeated rule
  const perRule = new Map<string, number>();
  let deduction = 0;
  for (const f of findings) {
    const n = perRule.get(f.id) || 0;
    perRule.set(f.id, n + 1);
    deduction += WEIGHTS[f.severity] / (n + 1);
  }
  return Math.max(0, Math.round(100 - deduction));
}
const grade = (s: number) => s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : s >= 40 ? "D" : "F";

export async function scanDirectory(root: string, repo: string): Promise<Report> {
  const files: string[] = [];
  await walk(root, root, files);
  let findings: Finding[] = [];
  for (const rel of files) {
    const st = await fs.stat(path.join(root, rel));
    if (st.size > MAX_FILE_BYTES) continue;
    const content = await fs.readFile(path.join(root, rel), "utf8");
    if (content.includes("\u0000")) continue;
    findings.push(...scanFile(rel, content));
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  findings.forEach((f) => counts[f.severity]++);
  const score = scoreFindings(findings);
  const summary = findings.length === 0
    ? "No issues found by our automated checks. Nice work — keep secrets in env vars and keep auth on every endpoint."
    : `We found ${findings.length} issue${findings.length > 1 ? "s" : ""}: ${SEV_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}. ` +
      (counts.critical ? "Fix the critical ones today — they can lead directly to stolen data or a surprise bill." : "Nothing critical, but the items below are worth fixing before you grow.");
  return { repo, scannedAt: new Date().toISOString(), filesScanned: files.length, score, grade: grade(score), summary, counts, findings };
}

export function reportToMarkdown(r: Report): string {
  const lines = [`# Patchwork security report`, ``, `**Repo:** ${r.repo}  `, `**Scanned:** ${r.scannedAt} (${r.filesScanned} files)  `, `**Score:** ${r.score}/100 (grade ${r.grade})`, ``, r.summary, ``];
  r.findings.forEach((f, i) => {
    lines.push(`## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`, ``, `- **Where:** \`${f.file}:${f.line}\``);
    if (f.evidence) lines.push(`- **Evidence:** \`${f.evidence}\``);
    lines.push(`- **What it means:** ${f.explanation}`, `- **How to fix:** ${f.fix}`, ``);
  });
  return lines.join("\n");
}

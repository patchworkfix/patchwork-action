import { promises as fs } from "fs";
import { execSync } from "child_process";
import { scanDirectory, Finding, Report } from "./scanner";

const MARKER = "<!-- patchworkfix-action -->";
const input = (n: string, d = "") => (process.env[`INPUT_${n.toUpperCase().replace(/ /g, "_")}`] ?? "").trim() || d;
const SEV = ["critical", "high", "medium", "low"] as const;
const ICON: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪" };
const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

function changedFiles(base?: string): Set<string> | null {
  if (!base) return null;
  try {
    execSync(`git fetch --no-tags --depth=1 origin ${base}`, { stdio: "ignore" });
    return new Set(execSync(`git diff --name-only FETCH_HEAD...HEAD || git diff --name-only FETCH_HEAD HEAD`, { encoding: "utf8" }).split("\n").filter(Boolean));
  } catch { return null; }
}

function render(r: Report, changed: Set<string> | null, failOn: string, failed: boolean): string {
  const inPr = (f: Finding) => changed?.has(f.file);
  const rows = r.findings.slice(0, 50).map((f) =>
    `| ${ICON[f.severity]} ${f.severity} | ${esc(f.title)} | \`${esc(f.file)}:${f.line}\`${inPr(f) ? " 🆕" : ""} | ${f.evidence ? "`" + esc(f.evidence) + "`" : ""} |`);
  const counts = SEV.filter((s) => r.counts[s]).map((s) => `${ICON[s]} ${r.counts[s]} ${s}`).join(" · ") || "no findings";
  const out = [MARKER, `## 🩹 Patchwork scan: **${r.score}/100 (grade ${r.grade})**`, ``, `${counts} · ${r.filesScanned} file${r.filesScanned === 1 ? "" : "s"} scanned${changed ? ` · ${r.findings.filter(inPr).length} in files changed by this PR (🆕)` : ""}`, ``, r.summary, ``];
  if (rows.length) {
    out.push(`| Severity | Issue | Where | Evidence (masked) |`, `|---|---|---|---|`, ...rows);
    if (r.findings.length > 50) out.push(``, `…and ${r.findings.length - 50} more (see the job summary).`);
    out.push(``, `<details><summary>How to fix</summary>`, ``);
    const seen = new Set<string>();
    for (const f of r.findings) { if (seen.has(f.id)) continue; seen.add(f.id); out.push(`- **${esc(f.title)}**: ${f.fix}`); }
    out.push(``, `</details>`);
  }
  out.push(``, failed ? `❌ Failing because findings at or above **${failOn}** were found.` : `✅ Check passes (fail-on: ${failOn}).`,
    ``, `<sub>Static checks only: may miss issues or flag false positives. Your code never leaves this CI run. Want it fixed for you? [patchworkfix.com](https://www.patchworkfix.com/services)</sub>`);
  return out.join("\n");
}

async function gh(path: string, method = "GET", body?: unknown) {
  const r = await fetch(`${process.env.GITHUB_API_URL || "https://api.github.com"}${path}`, {
    method, headers: { Authorization: `Bearer ${input("github-token")}`, Accept: "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "patchwork-action" },
    body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`GitHub API ${method} ${path}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.status === 204 ? null : r.json();
}

async function main() {
  const root = input("path", process.env.GITHUB_WORKSPACE || ".");
  const failOn = input("fail-on", "critical").toLowerCase();
  const event = process.env.GITHUB_EVENT_PATH ? JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, "utf8")) : {};
  const pr = event.pull_request;
  const repo = process.env.GITHUB_REPOSITORY || "local";
  const report = await scanDirectory(root, repo);
  const changed = pr ? changedFiles(pr.base?.ref) : null;
  const idx = SEV.indexOf(failOn as any);
  const failed = idx >= 0 && SEV.slice(0, idx + 1).some((s) => report.counts[s] > 0);
  const md = render(report, changed, failOn, failed);
  console.log(md);
  if (process.env.GITHUB_STEP_SUMMARY) await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, md + "\n");
  if (process.env.GITHUB_OUTPUT) await fs.appendFile(process.env.GITHUB_OUTPUT, `score=${report.score}\ngrade=${report.grade}\ncritical=${report.counts.critical}\nhigh=${report.counts.high}\n`);
  if (pr && input("comment", "true") === "true" && input("github-token")) {
    try {
      const comments: any[] = await gh(`/repos/${repo}/issues/${pr.number}/comments?per_page=100`);
      const mine = comments.find((c) => typeof c.body === "string" && c.body.startsWith(MARKER));
      if (mine) await gh(`/repos/${repo}/issues/comments/${mine.id}`, "PATCH", { body: md });
      else await gh(`/repos/${repo}/issues/${pr.number}/comments`, "POST", { body: md });
    } catch (e) { console.log(`::warning::Could not post PR comment (needs permissions: pull-requests: write). ${(e as Error).message}`); }
  }
  for (const f of report.findings.slice(0, 20)) {
    const lvl = f.severity === "critical" || f.severity === "high" ? "error" : "warning";
    console.log(`::${lvl} file=${f.file},line=${f.line},title=${f.title.replace(/[,:\n]/g, " ")}::${f.explanation.replace(/\n/g, " ")}`);
  }
  if (failed) { console.log(`::error::Patchwork found ${failOn}-or-worse issues (score ${report.score}/100).`); process.exitCode = 1; }
}
main().catch((e) => { console.log(`::error::${e.message}`); process.exitCode = 1; });

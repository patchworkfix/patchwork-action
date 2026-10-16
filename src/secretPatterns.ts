/** Browser-safe secret patterns shared by the repo scanner and the client-side /tools/secret-checker. No Node APIs. */
export type Severity = "critical" | "high" | "medium" | "low";

export function mask(secret: string): string {
  const s = secret.trim();
  if (s.length <= 8) return s.slice(0, 2) + "****";
  return s.slice(0, 4) + "****" + s.slice(-2);
}

export interface SecretRule { id: string; title: string; re: RegExp; severity: Severity; fix: string; group?: number }
export const SECRET_RULES: SecretRule[] = [
  { id: "openai-key", title: "OpenAI API key", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g, severity: "critical", fix: "Revoke the key at platform.openai.com/api-keys, create a new one, and load it from a server-side environment variable." },
  { id: "anthropic-key", title: "Anthropic API key", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,})\b/g, severity: "critical", fix: "Revoke the key in the Anthropic console and load a new one from a server-side environment variable." },
  { id: "stripe-live", title: "Stripe live secret/restricted key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/g, severity: "critical", fix: "Roll the key immediately in the Stripe dashboard (Developers → API keys) and keep it only in server env vars." },
  { id: "stripe-test", title: "Stripe test secret key", re: /\b(sk_test_[A-Za-z0-9]{16,})\b/g, severity: "medium", fix: "Test keys can't move real money, but roll it anyway and keep it out of the repo." },
  { id: "aws-access-key", title: "AWS access key ID", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, severity: "critical", fix: "Deactivate the key in AWS IAM, check CloudTrail for misuse, and use env vars or IAM roles instead." },
  { id: "aws-secret", title: "AWS secret access key", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi, severity: "critical", group: 1, fix: "Deactivate the key pair in AWS IAM and rotate it." },
  { id: "google-api-key", title: "Google / Firebase API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: "medium", fix: "Firebase web keys are semi-public, but restrict the key (HTTP referrers + API restrictions) in Google Cloud Console, and make sure security rules protect your data." },
  { id: "github-token", title: "GitHub token", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g, severity: "critical", fix: "Revoke the token at github.com/settings/tokens and use a secret store." },
  { id: "slack-token", title: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, severity: "high", fix: "Revoke the token in your Slack app settings." },
  { id: "private-key", title: "Private key", re: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)/g, severity: "critical", fix: "Treat the key as compromised: generate a new key pair, revoke the old one, and remove it from git history (git filter-repo / BFG)." },
];

export const JWT_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,})\b/g;
export const GENERIC_RE = /\b([A-Za-z0-9_]*(?:secret|token|api_?key|apikey|password|passwd|private_?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']([^"'\s]{16,})["']/gi;

export function shannon(s: string): number {
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) || 0) + 1);
  let h = 0;
  for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export const PLACEHOLDER = /(your|xxx|example|changeme|placeholder|dummy|test_?key|<|\$\{|process\.env|replace|insert|todo|\*\*\*)/i;

export function b64urlJson(part: string): any {
  try {
    const b = part.replace(/-/g, "+").replace(/_/g, "/");
    const txt = typeof atob === "function" ? decodeURIComponent(escape(atob(b + "===".slice((b.length + 3) % 4)))) : "";
    return JSON.parse(txt);
  } catch { return null; }
}

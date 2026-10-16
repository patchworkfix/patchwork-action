# Patchwork security scan (GitHub Action)

Scans every pull request with the same checks as the free scanner on [patchworkfix.com](https://www.patchworkfix.com):

- Leaked keys (OpenAI, Anthropic, Stripe, AWS, Google/Firebase, GitHub, Slack, private keys) and committed `.env` files
- Server secrets in public env vars (`NEXT_PUBLIC_…SECRET`), Supabase `service_role` in client code
- Firebase/Firestore rules open to the world, Supabase tables without RLS
- API routes with no visible auth check, paid API calls (OpenAI, Anthropic, Stripe…) with no rate limit

It posts one PR comment (updated on each push) and a job summary with the 0–100 score, grade and findings. Evidence is always masked. Findings in files the PR changed are marked 🆕. **Your code never leaves your CI run**, so it works on private repos.

## Usage

```yaml
# .github/workflows/patchwork.yml
name: Patchwork scan
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: patchworkfix/patchwork-action@v1
        with:
          fail-on: critical   # critical | high | medium | low | none
```

| Input | Default | Meaning |
|---|---|---|
| `fail-on` | `critical` | Fail the check when a finding at this severity or worse exists (`none` = report only) |
| `comment` | `true` | Post/update a PR comment |
| `path` | `.` | Directory to scan |
| `github-token` | `${{ github.token }}` | Token for the PR comment |

Outputs: `score`, `grade`, `critical`, `high`.

Static checks only: it can miss things and flag false positives, and it doesn't read git history. Want the issues fixed as a PR you review? See [patchworkfix.com/services](https://www.patchworkfix.com/services).

## Development

`npm ci && npm run build` bundles `src/` into `dist/index.js` (commit `dist/`). `src/scanner.ts` and `src/secretPatterns.ts` are copied from the patchwork site repo's `lib/`.

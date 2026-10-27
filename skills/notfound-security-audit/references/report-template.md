# Report template

Write the final answer in the user's language. Keep it short at the top; details below.

```markdown
# Security audit — <project>

**Date:** <date> · **Scope:** <path / commit> · **Checks:** automated scan (offline[, OSV.dev][, live headers]) + manual review of <areas>

## In one minute
- <N> confirmed issues (<critical/high count>) — fix first: <one line each>
- <N> findings that need review
- <N> preventive recommendations
- Not covered: <e.g. infrastructure, payment flow, runtime version on the server>

## Confirmed
### 1. [CRITICAL] <title>
- **Where:** `path/file.ext:42`
- **Evidence:** `<redacted snippet or version>`
- **What it means:** <one or two sentences, no jargon>
- **Conditions:** <what has to be true for it to be exploitable — say "not verified" when unknown>
- **Fix:** <exact steps; for runtime CVEs: upgrade the runtime and redeploy>
- **References:** <advisory links>

## Needs review
<same structure + "Open question: …" explaining what would confirm or dismiss it>

## Preventive
<grouped bullets>

## Dismissed during triage
<optional: findings the scanner raised that you verified as safe, with one-line reasons>

## Next steps
<ordered list; mark which ones you can apply with the user's approval>
```

Rules: never paste full secrets; do not call a finding "exploited" or "attacked" without evidence; keep
confirmed, needs-review and preventive separate; do not promise that the audit makes the project secure.

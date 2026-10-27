# Methodology

## Statuses

| Status | Meaning | Typical source |
|---|---|---|
| `confirmed` | The evidence is unambiguous: a vulnerable version is pinned, a rule allows public writes, a secret file is committed. Still verify that the scanned file is what runs in production. | advisory match, exact config value |
| `suspected` (shown as *Needs review*) | A risky pattern. It becomes a vulnerability only if attacker-controlled data reaches it without protection. | code-pattern rules, secrets in source |
| `preventive` | Hardening. Not a vulnerability by itself. | missing headers, unpinned images, root containers |

Never upgrade a finding's status without evidence. "Confirmed vulnerable version" does not mean "attacked" or
"exploitable in this deployment": say what is needed for exploitation (e.g. *mod_php*, decompressing untrusted
Brotli data, `use cache` returning typed arrays).

## Severity

| Severity | Use when |
|---|---|
| critical | Unauthenticated remote code execution, full database exposure, live production credentials. |
| high | Injection reachable by users, auth bypass, secrets with real access, privileged CI/containers. |
| medium | Needs a precondition (logged-in user, specific config), information disclosure with impact. |
| low | Defence-in-depth gaps with a plausible path to harm. |
| info | Fingerprinting, hygiene. |

Adjust the scanner's default severity during triage when the context justifies it, and say why.

## Triage: source → sink
1. **Sink**: the line the rule flagged (query, `exec`, `innerHTML`, `fetch(url)`, `include`…).
2. **Source**: where the value comes from. Request params, body, headers, cookies, URL, uploaded files, webhook
   payloads, third-party API responses and database fields written by users are all attacker-influenced.
3. **Path**: follow assignments and function calls. Look for parameterised queries, ORM bindings, escaping by
   the template engine, allow-lists, type coercion (`Number()`, `int()`), URL host allow-lists.
4. **Try to disprove it.** If a protection holds, drop the finding and record why. If you cannot tell, keep it as
   *Needs review* with the open question.

## Usually not worth reporting
- Denial of service through heavy requests, missing rate limiting (unless it protects login/OTP brute force).
- Open redirects without a token/credential leak.
- Findings in tests, fixtures, docs, examples and generated/minified files.
- Secrets that are obvious placeholders, or keys meant to be public (Supabase anon/publishable key, Firebase web
  config, Stripe publishable key) — those rely on server-side rules (RLS, security rules), so check the rules.
- Weak hashes used for non-security purposes (cache keys, ETags, k-anonymity prefixes for breach lookups).

## Runtime and dependency CVEs
- A CVE in the runtime (PHP, Node.js) is fixed by upgrading the runtime binary or the distro package that
  backports the patch, then rebuilding/redeploying. Application changes do not fix it.
- Docker: `FROM php:8.4-apache` does not tell the patch level; images cached on a server keep the old patch until
  rebuilt with `--pull`.
- Managed hosting (shared PHP hosting, Vercel, Netlify…): the provider controls the runtime. Ask the user to check
  the version in the panel or with the provider.
- For packages, prefer the fixed version from the advisory; check whether the lockfile is the deployed one.

## What automated checks cannot see
Authentication flows, authorisation per object (IDOR), multi-tenant isolation, payment logic, race conditions,
business rules, infrastructure (firewalls, WAF, cloud IAM), and anything only present at runtime. Cover these in
the manual review with `checklists.md`, and list what was not reviewed in the report.

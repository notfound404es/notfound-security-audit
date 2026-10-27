# NotFound Security Audit report

- **Target:** `demo-vulnerable-app`
- **Date:** 2026-10-27 16:10 UTC
- **Scanner:** nfaudit 0.1.0 (read-only)
- **Checks run:** stack, secrets, code-patterns, config, docker, ci, runtimes, dependencies-offline
- **Stack:** Express, Next.js, React · languages: js, py, php · platforms: Docker, Docker Compose, Firebase, GitHub Actions
- **Files scanned:** 12 · dependencies parsed: 2

## Summary

| Status | Count |
|---|---|
| Confirmed | 4 |
| Needs review | 10 |
| Preventive | 4 |

| Severity | Count |
|---|---|
| critical | 5 |
| high | 5 |
| medium | 5 |
| low | 2 |
| info | 1 |

> **Confirmed:** Backed by an advisory database, an exact version match or an unambiguous configuration value. **Needs review:** A risky pattern. Trace the data flow before calling it a vulnerability; many will be false positives. **Preventive:** Hardening advice. Not a vulnerability on its own.

## Coverage notes

- Dependencies were only checked against the small built-in advisory list. Run with --osv (sends package names and versions to OSV.dev, never code) for full CVE coverage.

## Confirmed (4)

### 1. [CRITICAL] PHP core remote code execution (PHP2Shell)

- **Where:** `Dockerfile:1`
- **Rule:** `runtime-php2shell-2026-10` · fingerprint `131cd3e8db48a144`
- **Evidence:** `php 8.3.20`

Memory-handling flaws in the PHP runtime. On Apache with mod_php an unauthenticated request could trigger code execution before application code ran; PHP-FPM was also confirmed exploitable through application code paths. Fixing application code or plugins does not fix it: the PHP binary must be updated.

**Recommendation:** Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a distro package that backports the fix).

1. Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a distro package that backports the fix).
2. Rebuild and redeploy Docker images (docker build --pull).
3. PHP 8.1 and older have no regular upstream fix: plan the upgrade.
4. A WAF rule is defense in depth, not a fix.

References: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/ · https://blog.cloudflare.com/php-vulnerabilities-waf-protection/

### 2. [CRITICAL] Firebase rules allow public access

- **Where:** `firestore.rules:4`
- **Rule:** `firebase-open-rules` · CWE-284 · OWASP A01:2025 · fingerprint `318a08e89e096ecd`
- **Evidence:** `allow read, write: if true;`

Anyone with your public Firebase config can read or write this data.

**Recommendation:** Require request.auth and check ownership in the rules.

### 3. [CRITICAL] next 16.3.0: Next.js unauthenticated RCE (use cache typed arrays, Image Optimization SVG) and Server Actions DoS

- **Where:** `package-lock.json`
- **Rule:** `dep-nextjs-2026-10-14` · CWE-1395 · OWASP A03:2025 · fingerprint `3d4ff35107343a03`
- **Evidence:** `next@16.3.0`

Two critical unauthenticated remote code execution issues (App Router 'use cache' functions returning typed arrays; Image Optimization API with SVG on glibc Linux) and a high-severity Server Actions denial of service.

**Recommendation:** npm install next@16.4.1 (16.x) or next@15.5.28 (15.x).

1. npm install next@16.4.1 (16.x) or next@15.5.28 (15.x).
2. Make sure the resolved sharp version is 0.35.5 or later.
3. Redeploy after upgrading.

References: https://nextjs.org/blog/nextjs-security-update-october-14-2026

### 4. [HIGH] Laravel APP_DEBUG=true with APP_ENV=production

- **Where:** `.env:2`
- **Rule:** `laravel-debug-production` · CWE-489 · OWASP A02:2025 · fingerprint `44dfdf56fd0c71f5`
- **Evidence:** `APP_DEBUG=true`

Debug pages show stack traces, environment variables and queries to anyone who triggers an error.

**Recommendation:** Set APP_DEBUG=false in production.

## Needs review (10)

### 1. [CRITICAL] AWS access key ID in source

- **Where:** `lib/config.ts:1`
- **Rule:** `secret-aws-access-key-id` · CWE-798 · OWASP A07:2025 · fingerprint `c2c03a7cbed79839`
- **Evidence:** `export const aws = 'AKIA…****** (20 chars)'`

A credential appears to be stored in the repository. Anyone with access to the code, its history, a leaked build or the browser bundle can use it.

**Recommendation:** Revoke/rotate the credential first, then move it to environment variables or a secrets manager.

1. Rotate the key in the provider dashboard (assume it is compromised).
2. Load it from an environment variable / secrets manager.
3. Remove it from git history (git filter-repo) if the repository was ever shared.
4. Add a pre-commit secret scanner.

### 2. [CRITICAL] Stripe live secret/restricted key in source

- **Where:** `lib/config.ts:2`
- **Rule:** `secret-stripe-live-key` · CWE-798 · OWASP A07:2025 · fingerprint `5a4f22fe2d591951`
- **Evidence:** `export const stripe = "sk_l…****** (34 chars)"`

A credential appears to be stored in the repository. Anyone with access to the code, its history, a leaked build or the browser bundle can use it.

**Recommendation:** Revoke/rotate the credential first, then move it to environment variables or a secrets manager.

1. Rotate the key in the provider dashboard (assume it is compromised).
2. Load it from an environment variable / secrets manager.
3. Remove it from git history (git filter-repo) if the repository was ever shared.
4. Add a pre-commit secret scanner.

### 3. [HIGH] Untrusted event data interpolated into a shell step

- **Where:** `.github/workflows/triage.yml:7`
- **Rule:** `gha-script-injection` · CWE-78 · OWASP A05:2025 · fingerprint `37e2169d09ba5777`
- **Evidence:** `echo "${{ github.event.issue.title }}"`

Titles, bodies and branch names are attacker-controlled; ${{ }} is substituted before the shell runs, so they can inject commands.

**Recommendation:** Pass the value through env: and reference it as "$VAR".

References: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions

### 4. [HIGH] Shell command built from a template or concatenation

- **Where:** `app/api/run/route.ts:4`
- **Rule:** `js-command-injection` · CWE-78 · OWASP A05:2025 · fingerprint `935fb279b019e2dc`
- **Evidence:** `exec(`ls ${dir}`)`

child_process.exec runs the string through a shell. Interpolating variables lets an attacker append extra commands with characters like ; | && or $().

**Recommendation:** Use execFile/spawn with an argument array and no shell, and validate inputs against an allow-list.

1. Switch to execFile(cmd, [arg1, arg2]) or spawn(cmd, args, { shell: false }).
2. Validate every argument with an allow-list (e.g. /^[a-z0-9-]+$/).
3. Never pass request data straight to a shell.

### 5. [HIGH] Server Actions accept any origin

- **Where:** `next.config.js:1`
- **Rule:** `next-server-actions-any-origin` · CWE-352 · OWASP A01:2025 · fingerprint `6370b81c3b459047`
- **Evidence:** `module.exports = { experimental: { serverActions: { allowedOrigins: ['*'] } } }`

allowedOrigins with '*' disables the origin check that protects Server Actions from CSRF.

**Recommendation:** List only your own domains.

### 6. [HIGH] SQL query built with PHP variables

- **Where:** `public/legacy/user.php:3`
- **Rule:** `php-sql-injection` · CWE-89 · OWASP A05:2025 · fingerprint `1e9349a937f945cc`
- **Evidence:** `$r = mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);`

Concatenating or interpolating variables into SQL lets attackers rewrite the query.

**Recommendation:** Use prepared statements (PDO/mysqli) or Eloquent/Query Builder bindings.

1. $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);
2. In Laravel: DB::select('... where id = ?', [$id]) or ->whereRaw('id = ?', [$id]).
3. Cast numeric inputs with (int).

### 7. [MEDIUM] .env is not covered by .gitignore

- **Where:** `.env`
- **Rule:** `env-file-not-ignored` · CWE-538 · OWASP A02:2025 · fingerprint `3fc808ba65454632`

No .gitignore rule matches this env file, so it can be committed by accident.

**Recommendation:** Add .env* to .gitignore and keep a .env.example without values.

### 8. [MEDIUM] Django DEBUG = True

- **Where:** `backend/settings.py:1`
- **Rule:** `django-debug` · CWE-16 · OWASP A02:2025 · fingerprint `be066ef17362773f`
- **Evidence:** `DEBUG = True`

Debug pages leak settings and code if this file is used in production.

**Recommendation:** Read DEBUG from the environment and default to False.

### 9. [MEDIUM] ALLOWED_HOSTS = ['*']

- **Where:** `backend/settings.py:2`
- **Rule:** `django-allowed-hosts-any` · CWE-16 · OWASP A02:2025 · fingerprint `ffd160cd73b24795`
- **Evidence:** `ALLOWED_HOSTS = ['*']`

Any Host header is accepted, enabling host-header poisoning of password-reset links.

**Recommendation:** List your real domains.

### 10. [MEDIUM] Database port published on all interfaces

- **Where:** `docker-compose.yml:5`
- **Rule:** `compose-db-port-exposed` · CWE-250 · OWASP A02:2025 · fingerprint `551ab200b7d366cd`
- **Evidence:** `- "5432:5432"`

The database is reachable from outside the host if the firewall allows it.

**Recommendation:** Remove the ports mapping or bind it to 127.0.0.1.

## Preventive (4)

### 1. [MEDIUM] Container runs as root

- **Where:** `Dockerfile`
- **Rule:** `docker-root-user` · CWE-250 · OWASP A02:2025 · fingerprint `7524dc6703e5723e`

If the app is compromised, the attacker is root inside the container, which makes escapes and lateral movement easier.

**Recommendation:** Add a non-root USER in the final stage.

1. RUN adduser -D app (or useradd) and USER app
2. Official node images ship a 'node' user: USER node

### 2. [LOW] Express app without helmet

- **Where:** project-wide
- **Rule:** `express-no-helmet` · CWE-693 · OWASP A02:2025 · fingerprint `4455609c33ab6728`

helmet sets sensible security headers (CSP, HSTS, noSniff, frameguard) in one line.

**Recommendation:** npm install helmet and app.use(helmet()).

### 3. [LOW] No security headers configured for Next.js

- **Where:** `next.config.js`
- **Rule:** `next-missing-security-headers` · CWE-693 · OWASP A02:2025 · fingerprint `316c5fe96b0abf7c`

No Content-Security-Policy, HSTS or frame protection was found in next.config, vercel.json or middleware. Headers limit the impact of XSS and clickjacking.

**Recommendation:** Add headers() in next.config with CSP, HSTS, X-Content-Type-Options, Referrer-Policy and frame-ancestors.

1. async headers() { return [{ source: '/(.*)', headers: [...] }] }
2. Verify on the live site with: nfaudit headers https://your-site

References: https://nextjs.org/docs/app/api-reference/config/next-config-js/headers

### 4. [INFO] X-Powered-By header not disabled

- **Where:** `next.config.js`
- **Rule:** `next-powered-by` · OWASP A02:2025 · fingerprint `c5a903486d08153e`

Next.js announces itself in X-Powered-By. It does not create a vulnerability but helps fingerprinting.

**Recommendation:** Set poweredByHeader: false.

## Attack surface (2 entry points)

Inputs an attacker can reach. Review authentication and authorisation on each one manually.

| Kind | Location |
|---|---|
| Next.js route handler | `app/api/run/route.ts:2` |
| PHP entry reading request | `public/legacy/user.php:2` |

---
Generated by NotFound Security Audit. Automated checks find known patterns and known vulnerable versions; they do not prove a project is safe or that a finding is exploitable.

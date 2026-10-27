# NotFound Security Audit

A read-only security audit skill for AI coding agents. Point it at a web project and it finds vulnerable
dependencies and runtimes, leaked secrets, injection-prone code and insecure configuration — then explains each
finding, where it is and how to fix it. It does not touch your code unless you approve a fix.

Built by [NotFound](https://notfound404.es) for people shipping web apps with AI agents.

```
NotFound Security Audit 0.1.0 · demo-vulnerable-app
  stack: Express, Next.js, React | js, py, php
  findings: 18  (confirmed 4, needs review 10, preventive 4)
  - [critical/confirmed] PHP core remote code execution (PHP2Shell)  (Dockerfile:1)
  - [critical/confirmed] Firebase rules allow public access  (firestore.rules:4)
  - [critical/confirmed] next 16.3.0: Next.js unauthenticated RCE (…)  (package-lock.json)
  - [high/suspected] Shell command built from a template or concatenation  (app/api/run/route.ts:4)
```
*Output from the intentionally vulnerable test project in `tests/` — see [`examples/reports`](examples/reports).*

## What it checks

| Area | Examples |
|---|---|
| Stack | Languages, frameworks (Next.js, React, Vue, Express, Laravel, WordPress, Django, Flask, FastAPI, Spring, Rails…), Docker, Vercel, Supabase, Firebase, GitHub Actions |
| Dependencies | Lockfiles for npm, Yarn, pnpm, Composer, pip/Poetry/uv/Pipenv, Go, Cargo, Bundler, Maven/Gradle. Offline list of recent high-impact advisories; full CVE lookup through [OSV.dev](https://osv.dev) with `--osv` |
| Runtimes | PHP, Node.js and Python versions from Dockerfiles, `.nvmrc`, `.python-version`, `.tool-versions` — including PHP2Shell (CVE-2026-109618/109619) and the Node.js October 2026 releases |
| Secrets | AWS, GitHub, GitLab, OpenAI, Anthropic, Stripe, Slack, Discord, Google, SendGrid, Supabase service keys, private keys, DB URLs with passwords, generic high-entropy assignments. Always redacted in reports |
| Code patterns | SQL/NoSQL injection, XSS sinks, SSRF, command execution, eval, path traversal, unsafe deserialization, XXE, open redirects, disabled TLS checks, weak hashing/randomness, mass assignment, CSRF exemptions |
| Configuration | Security headers, CORS, cookies/sessions, debug modes, `ALLOWED_HOSTS`, Server Actions origins, Spring Actuator, `php.ini`, committed or public `.env` variables |
| External services | Supabase tables without RLS, service keys in client code, open Firebase rules |
| Docker & CI | Root containers, unpinned images, secrets in layers, `curl \| sh`, privileged/`docker.sock`, exposed DB ports, GitHub Actions script injection, `pull_request_target`, unpinned actions |
| Live headers | Optional single GET to **your** URL: HSTS, CSP, frame protection, cookies, CORS, version banners |

Every finding has a **status** so you know how much to trust it:

- **Confirmed** — backed by an advisory or an unambiguous value (a vulnerable version pinned in your lockfile, rules that allow public writes).
- **Needs review** — a risky pattern. The agent traces the data flow and tries to disprove it before calling it a vulnerability.
- **Preventive** — hardening advice, not a vulnerability.

The agent then does what a scanner cannot: reviews authentication, authorisation and business logic on every
entry point it found, using the checklists in [`references/`](skills/notfound-security-audit/references).

## Install

The skill lives in [`skills/notfound-security-audit`](skills/notfound-security-audit). It needs Python 3.9+ and
nothing else (standard library only).

**Claude Code** — personal or per-project:
```bash
git clone https://github.com/notfound404es/notfound-security-audit
cp -r notfound-security-audit/skills/notfound-security-audit ~/.claude/skills/
# or, for one project: .claude/skills/notfound-security-audit
```

**Codex** — personal or per-repository:
```bash
cp -r notfound-security-audit/skills/notfound-security-audit ~/.agents/skills/
# or, for one repository: .agents/skills/notfound-security-audit
```

Then ask: *"Audit this project for security issues"*, or invoke it directly (`/notfound-security-audit` in
Claude Code, `$notfound-security-audit` in Codex).

## Use the scanner directly

```bash
python skills/notfound-security-audit/scripts/nfaudit.py scan ./my-app                 # offline, read-only
python skills/notfound-security-audit/scripts/nfaudit.py scan ./my-app --osv           # + OSV.dev CVE lookup
python skills/notfound-security-audit/scripts/nfaudit.py scan . --format md,json,sarif --out ./reports --fail-on high
python skills/notfound-security-audit/scripts/nfaudit.py headers https://your-site.example
python skills/notfound-security-audit/scripts/nfaudit.py rules
```

Reports are written to your system temp directory by default, so nothing is added to the project. SARIF output
works with GitHub code scanning — see [`examples/github-action.yml`](examples/github-action.yml).

Optional `.nfaudit.json` in the project root ([example](examples/nfaudit.config.json)):
```json
{ "exclude": ["legacy/**"], "disable_rules": ["js-weak-hash"], "ignore": ["<fingerprint>"], "include_tests": true }
```
Add `nfaudit-ignore` in a comment on (or above) a line to silence it.

## Safety model

- **Read-only.** The scanner reads files and runs `git ls-files`. It never writes to the project, installs
  packages or executes project code.
- **No attacks.** No exploit payloads, fuzzing or crawling. The only network calls are opt-in: `--osv` sends
  package names and versions (never code) to OSV.dev, and `headers` makes one GET request to the URL you give it.
- **Secrets stay secret.** Reports show only the first characters of any credential.
- **Fixes need approval.** The skill instructs the agent to propose changes and wait for a yes before editing.
- **Honest results.** A pattern is not a vulnerability, and a vulnerable version is not an attack. Runtime CVEs
  (PHP, Node.js) are fixed by upgrading the runtime, not by changing your code.

## Compatibility

| Agent | Status |
|---|---|
| Claude Code | Tested: the skill is discovered from `.claude/skills/` and runs the full workflow. |
| Codex CLI | Tested: the skill is discovered from `.agents/skills/` (same `SKILL.md` format). |
| Other agents | Any agent that reads `SKILL.md` files should work; not tested. The scanner itself is a plain Python CLI. |

CI runs the test suite on Linux and Windows with Python 3.9–3.13.

## Limitations

- Pattern rules work line by line; they are not a full data-flow engine. Expect false positives (that is why the
  agent triages) and misses (multi-line or indirect flows).
- The offline advisory list is intentionally small and dated (`data/known-advisories.json`). Use `--osv`, or a
  dedicated tool such as OSV-Scanner, for complete dependency coverage.
- It sees the repository, not your server: the real runtime patch level, WAF, firewall and cloud settings must be
  checked where you deploy.
- No automated tool proves an application is secure. Treat the report as a starting point for review.

## Development

```bash
python -m unittest discover -s tests -v
```
Test fixtures are generated at runtime, so the repository contains no secret-shaped strings.

## References

Methodology and categories are informed by public work from the security community: the
[OWASP Top 10:2025](https://owasp.org/Top10/2025/), [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/),
[CWE](https://cwe.mitre.org/), [OSV](https://osv.dev), and the published security-review approaches of
[Cloudflare](https://github.com/cloudflare/security-audit-skill), [Anthropic](https://github.com/anthropics/claude-code-security-review)
and [OpenAI](https://github.com/openai/codex-security). No code or rules were copied from these projects.

## License

[MIT](LICENSE) © 2026 NotFound

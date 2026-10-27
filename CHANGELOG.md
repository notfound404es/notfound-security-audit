# Changelog

## 0.1.0 — 2026-10-27

First release.

- Read-only scanner (`nfaudit scan`): stack detection, lockfile parsing for 9 ecosystems, offline advisories
  (PHP2Shell, Node.js October 2026, Next.js October 2026), optional OSV.dev lookup, secrets with redaction,
  ~50 code-pattern rules, framework/Docker/CI/Supabase/Firebase configuration checks, attack-surface inventory.
- Optional live header check (`nfaudit headers`).
- Markdown, JSON and SARIF 2.1.0 reports; `.nfaudit.json` config; `--fail-on` for CI.
- Skill instructions, triage methodology, per-stack checklists and report template.

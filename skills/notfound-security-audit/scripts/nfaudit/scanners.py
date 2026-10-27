"""Source scanners: secrets, insecure code patterns and attack-surface inventory."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from .util import (RULES_DIR, Finding, entropy, lang_of, line_of, load_json, read_text, redact, rel, snippet,
                   MINIFIED_LINE, TEXT_EXT)

IGNORE_MARK = "nfaudit-ignore"
TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|mocks?)(/|$)|\.(test|spec)\.[a-z]+$")
SECRET_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", ".htpasswd", "credentials", "credentials.json", "service-account.json"}


class Rules:
    def __init__(self, disabled: set[str] | None = None):
        disabled = disabled or set()
        cp = load_json(RULES_DIR / "code-patterns.json")
        self.code = []
        for r in cp["rules"]:
            if r["id"] in disabled:
                continue
            r = dict(r)
            r["_re"] = re.compile(r["pattern"], re.M)
            r["_requires"] = re.compile(r["requires"]) if r.get("requires") else None
            r["_line_requires"] = re.compile(r["line_requires"]) if r.get("line_requires") else None
            r["_unless"] = re.compile(r["unless"]) if r.get("unless") else None
            r["_unless_file"] = re.compile(r["unless_file"]) if r.get("unless_file") else None
            self.code.append(r)
        sc = load_json(RULES_DIR / "secrets.json")
        self.placeholders = [p.lower() for p in sc["placeholders"]]
        self.secrets = []
        for r in sc["rules"]:
            if r["id"] in disabled:
                continue
            r = dict(r)
            r["_re"] = re.compile(r["pattern"])
            self.secrets.append(r)


def _scannable(path: Path) -> bool:
    name = path.name.lower()
    return (lang_of(path) is not None or path.suffix.lower() in TEXT_EXT or name.startswith(".env")
            or name in SECRET_FILE_NAMES or name in ("dockerfile",))


def _line_ignored(text: str, line: int) -> bool:
    lines = text.splitlines()
    cur = lines[line - 1] if 0 < line <= len(lines) else ""
    prev = lines[line - 2] if 1 < line <= len(lines) else ""
    return IGNORE_MARK in cur or IGNORE_MARK in prev


def _safe_evidence(text: str, line: int, secret: str) -> str:
    """Redact BEFORE truncating so no part of the secret can leak into the report."""
    full = snippet(text, line, 100_000).replace(secret, redact(secret))
    return full if len(full) <= 300 else full[:299] + "…"


def _jwt_role(token: str) -> str | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def scan_secrets(path: Path, text: str, root: Path, rules: Rules) -> list[Finding]:
    out = []
    r = rel(path, root)
    in_tests = bool(TEST_PATH.search(r))
    for rule in rules.secrets:
        for m in rule["_re"].finditer(text):
            value = m.group(rule.get("secret_group", 0))
            low = value.lower()
            if any(p in low for p in rules.placeholders):
                continue
            if rule.get("min_entropy") and entropy(value) < rule["min_entropy"]:
                continue
            ln = line_of(text, m.start())
            if _line_ignored(text, ln):
                continue
            sev = rule["severity"]
            if in_tests and sev in ("critical", "high"):
                sev = "medium"
            out.append(Finding(
                rule_id=f"secret-{rule['id']}", title=f"{rule['title']} in source", severity=sev, status="suspected",
                category="secrets", file=r, line=ln, evidence=_safe_evidence(text, ln, value),
                cwe="CWE-798", owasp="A07:2025",
                description="A credential appears to be stored in the repository. Anyone with access to the code, its history, a leaked build or the browser bundle can use it." + (" " + rule["hint"] if rule.get("hint") else ""),
                recommendation="Revoke/rotate the credential first, then move it to environment variables or a secrets manager.",
                remediation=["Rotate the key in the provider dashboard (assume it is compromised).",
                             "Load it from an environment variable / secrets manager.",
                             "Remove it from git history (git filter-repo) if the repository was ever shared.",
                             "Add a pre-commit secret scanner."],
                extra={"in_tests": in_tests}))
    # Supabase / generic JWTs carrying the service_role claim
    for m in re.finditer(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text):
        if _jwt_role(m.group(0)) == "service_role":
            ln = line_of(text, m.start())
            if _line_ignored(text, ln):
                continue
            out.append(Finding(
                rule_id="secret-supabase-service-role", title="Supabase service_role key in source", severity="critical",
                status="suspected", category="secrets", file=r, line=ln,
                evidence=_safe_evidence(text, ln, m.group(0)), cwe="CWE-798", owasp="A07:2025",
                description="The service_role key bypasses Row Level Security. If it reaches the browser or the repository, the whole database is exposed.",
                recommendation="Rotate the key and use it only on the server; the browser must use the anon/publishable key with RLS.",
                remediation=["Rotate the JWT secret / service key in Supabase.", "Keep service keys in server-only env vars (never NEXT_PUBLIC_/VITE_)."]))
    return out


def scan_code(path: Path, text: str, root: Path, rules: Rules) -> list[Finding]:
    lang = lang_of(path)
    if not lang:
        return []
    r = rel(path, root)
    if any(len(l) > MINIFIED_LINE for l in text.splitlines()[:5]):
        return []  # minified bundle
    in_tests = bool(TEST_PATH.search(r))
    out = []
    for rule in rules.code:
        if lang not in rule["languages"] and not (lang == "blade" and "php" in rule["languages"]):
            continue
        if rule["_requires"] and not rule["_requires"].search(text):
            continue
        if rule["_unless_file"] and rule["_unless_file"].search(text):
            continue
        for m in rule["_re"].finditer(text):
            ln = line_of(text, m.start())
            line_text = snippet(text, ln, 300)
            if rule["_unless"] and rule["_unless"].search(line_text):
                continue
            if rule["_line_requires"] and not rule["_line_requires"].search(line_text):
                continue
            if _line_ignored(text, ln):
                continue
            sev = rule["severity"]
            if in_tests and sev in ("critical", "high"):
                sev = "low"
            out.append(Finding(
                rule_id=rule["id"], title=rule["title"], severity=sev, status=rule["status"], category="code",
                file=r, line=ln, evidence=line_text, cwe=rule.get("cwe", ""), owasp=rule.get("owasp", ""),
                description=rule["description"], recommendation=rule["recommendation"],
                remediation=rule.get("remediation", []), references=rule.get("references", []),
                extra={"in_tests": in_tests}))
    return out


SURFACE_PATTERNS = [
    ("Next.js route handler", re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b"), ("js",), r"(^|/)app/.*route\.(t|j)sx?$"),
    ("Next.js server action", re.compile(r"^\s*['\"]use server['\"]", re.M), ("js",), None),
    ("Next.js API route", re.compile(r"export\s+default\s+(?:async\s+)?function"), ("js",), r"(^|/)pages/api/"),
    ("Express/Fastify route", re.compile(r"\b(?:app|router|server|fastify)\.(get|post|put|patch|delete|all)\s*\(\s*['\"`]([^'\"`]+)"), ("js",), None),
    ("Laravel route", re.compile(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\s*\(\s*['\"]([^'\"]+)"), ("php",), None),
    ("PHP entry reading request", re.compile(r"\$_(GET|POST|REQUEST|FILES)\b"), ("php",), None),
    ("Django URL", re.compile(r"\b(?:path|re_path)\s*\(\s*r?['\"]([^'\"]*)"), ("py",), r"urls\.py$"),
    ("Flask/FastAPI route", re.compile(r"@(?:\w+)\.(route|get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)"), ("py",), None),
    ("Spring endpoint", re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(?\s*(?:value\s*=\s*)?['\"]?([^'\")]*)"), ("java",), None),
    ("Go HTTP handler", re.compile(r"\.(?:HandleFunc|Handle|GET|POST|PUT|DELETE)\s*\(\s*\"([^\"]+)"), ("go",), None),
    ("Rails route", re.compile(r"^\s*(get|post|put|patch|delete|resources?)\s+['\":]([^'\",\s]+)", re.M), ("rb",), r"config/routes\.rb$"),
]


def surface(path: Path, text: str, root: Path) -> list[dict]:
    lang = lang_of(path)
    if not lang:
        return []
    lang = "php" if lang == "blade" else lang
    r = rel(path, root)
    out = []
    for kind, rx, langs, path_rx in SURFACE_PATTERNS:
        if lang not in langs or (path_rx and not re.search(path_rx, r)):
            continue
        if TEST_PATH.search(r):
            continue
        for m in rx.finditer(text):
            out.append({"kind": kind, "file": r, "line": line_of(text, m.start()), "match": snippet(text, line_of(text, m.start()), 140)})
            if kind == "PHP entry reading request":
                break
    return out


def scan_sources(root: Path, files: list[Path], rules: Rules) -> tuple[list[Finding], list[dict], int]:
    findings: list[Finding] = []
    entry_points: list[dict] = []
    scanned = 0
    for path in files:
        if not _scannable(path):
            continue
        text = read_text(path)
        if text is None:
            continue
        scanned += 1
        findings += scan_secrets(path, text, root, rules)
        findings += scan_code(path, text, root, rules)
        entry_points += surface(path, text, root)
    return findings, entry_points, scanned

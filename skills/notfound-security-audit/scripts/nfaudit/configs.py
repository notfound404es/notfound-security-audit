"""Configuration checks: frameworks, env files, Docker, CI and external services (Supabase, Firebase)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .util import Finding, line_of, read_text, rel, snippet


def _f(rule_id, title, severity, status, description, recommendation, file="", line=0, evidence="", cwe="", owasp="A02:2025", remediation=None, references=None, category="config"):
    return Finding(rule_id=rule_id, title=title, severity=severity, status=status, category=category,
                   description=description, recommendation=recommendation, file=file, line=line, evidence=evidence,
                   cwe=cwe, owasp=owasp, remediation=remediation or [], references=references or [])


def _first(text: str, rx: str, flags=re.M) -> tuple[int, str] | None:
    m = re.search(rx, text, flags)
    if not m:
        return None
    ln = line_of(text, m.start())
    return ln, snippet(text, ln)


def git_tracked(root: Path) -> set[str] | None:
    """Files tracked by git (read-only `git ls-files`). None when git is unavailable."""
    try:
        res = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return {p for p in res.stdout.decode("utf-8", "replace").split("\0") if p}


def check_env_files(root: Path, files: list[Path]) -> list[Finding]:
    out = []
    tracked = git_tracked(root)
    gitignore = (read_text(root / ".gitignore") or "") if (root / ".gitignore").exists() else ""
    for p in files:
        name = p.name
        if not (name == ".env" or (name.startswith(".env.") and not name.endswith((".example", ".sample", ".template", ".dist")))):
            continue
        r = rel(p, root)
        text = read_text(p) or ""
        if tracked is not None and r in tracked:
            out.append(_f("env-file-committed", f"{r} is committed to git", "high", "confirmed",
                          "Environment files usually hold credentials. Once committed they stay in the history and in every clone or fork.",
                          "Remove it from the repository, rotate every secret it contained and add it to .gitignore.",
                          file=r, cwe="CWE-538", owasp="A02:2025",
                          remediation=["git rm --cached " + r, "Add .env* (except .env.example) to .gitignore.", "Rotate all credentials it contained."]))
        elif tracked is None and not re.search(r"(?m)^\s*/?\.env", gitignore):
            out.append(_f("env-file-not-ignored", f"{r} is not covered by .gitignore", "medium", "suspected",
                          "No .gitignore rule matches this env file, so it can be committed by accident.",
                          "Add .env* to .gitignore and keep a .env.example without values.", file=r, cwe="CWE-538"))
        for m in re.finditer(r"(?m)^\s*((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN)[A-Z0-9_]*)\s*=", text):
            ln = line_of(text, m.start())
            out.append(_f("public-env-secret-name", f"Secret-looking variable exposed to the browser: {m.group(1)}", "high", "suspected",
                          "Variables with these prefixes are inlined into the client bundle and visible to every visitor.",
                          "Rename it without the public prefix and read it only on the server.", file=r, line=ln,
                          evidence=m.group(1) + "=***", cwe="CWE-200", owasp="A01:2025"))
        hit = _first(text, r"^\s*APP_DEBUG\s*=\s*true")
        if hit and re.search(r"(?m)^\s*APP_ENV\s*=\s*prod", text):
            out.append(_f("laravel-debug-production", "Laravel APP_DEBUG=true with APP_ENV=production", "high", "confirmed",
                          "Debug pages show stack traces, environment variables and queries to anyone who triggers an error.",
                          "Set APP_DEBUG=false in production.", file=r, line=hit[0], evidence=hit[1], cwe="CWE-489"))
    return out


def check_frameworks(root: Path, files: list[Path], stack: dict) -> list[Finding]:
    out = []
    fw = set(stack.get("frameworks", []))
    texts: dict[str, str] = {}

    def text_of(p: Path) -> str:
        r = rel(p, root)
        if r not in texts:
            texts[r] = read_text(p) or ""
        return texts[r]

    by_name: dict[str, list[Path]] = {}
    for p in files:
        by_name.setdefault(p.name, []).append(p)

    # --- Next.js security headers -------------------------------------------------------------
    if "Next.js" in fw:
        configs = [p for n in ("next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs") for p in by_name.get(n, [])]
        header_sources = configs + by_name.get("vercel.json", []) + [p for n in ("middleware.ts", "middleware.js", "proxy.ts", "proxy.js") for p in by_name.get(n, [])]
        joined = "\n".join(text_of(p) for p in header_sources)
        if not re.search(r"Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|frame-ancestors", joined, re.I):
            target = rel(configs[0], root) if configs else ""
            out.append(_f("next-missing-security-headers", "No security headers configured for Next.js", "low", "preventive",
                          "No Content-Security-Policy, HSTS or frame protection was found in next.config, vercel.json or middleware. Headers limit the impact of XSS and clickjacking.",
                          "Add headers() in next.config with CSP, HSTS, X-Content-Type-Options, Referrer-Policy and frame-ancestors.",
                          file=target, cwe="CWE-693", references=["https://nextjs.org/docs/app/api-reference/config/next-config-js/headers"],
                          remediation=["async headers() { return [{ source: '/(.*)', headers: [...] }] }", "Verify on the live site with: nfaudit headers https://your-site"]))
        for p in configs:
            t = text_of(p)
            if not re.search(r"poweredByHeader\s*:\s*false", t):
                out.append(_f("next-powered-by", "X-Powered-By header not disabled", "info", "preventive",
                              "Next.js announces itself in X-Powered-By. It does not create a vulnerability but helps fingerprinting.",
                              "Set poweredByHeader: false.", file=rel(p, root)))
            hit = _first(t, r"allowedOrigins\s*:\s*\[[^\]]*['\"]\*['\"]")
            if hit:
                out.append(_f("next-server-actions-any-origin", "Server Actions accept any origin", "high", "suspected",
                              "allowedOrigins with '*' disables the origin check that protects Server Actions from CSRF.",
                              "List only your own domains.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-352", owasp="A01:2025"))

    # --- Express ------------------------------------------------------------------------------
    if "Express" in fw and "helmet" not in fw:
        out.append(_f("express-no-helmet", "Express app without helmet", "low", "preventive",
                      "helmet sets sensible security headers (CSP, HSTS, noSniff, frameguard) in one line.",
                      "npm install helmet and app.use(helmet()).", cwe="CWE-693"))
    for p in files:
        if p.suffix.lower() not in (".js", ".ts", ".mjs", ".cjs"):
            continue
        t = text_of(p)
        if "express-session" in t or "cookie-session" in t:
            hit = _first(t, r"secret\s*:\s*['\"](?:keyboard cat|secret|changeme|default)['\"]")
            if hit:
                out.append(_f("session-default-secret", "Session signed with a default secret", "high", "confirmed",
                              "A known session secret lets attackers forge session cookies.",
                              "Use a long random secret from an environment variable.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-1392", owasp="A07:2025"))
        hit = _first(t, r"\bapp\.use\(\s*cors\(\s*\)\s*\)")
        if hit:
            out.append(_f("cors-open-default", "CORS enabled for every origin", "low", "preventive",
                          "cors() without options answers Access-Control-Allow-Origin: *. Fine for public read-only APIs, risky for anything else.",
                          "Pass an explicit origin list.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-942"))

    # --- Laravel ------------------------------------------------------------------------------
    for p in by_name.get("cors.php", []):
        t = text_of(p)
        if re.search(r"'allowed_origins'\s*=>\s*\[\s*'\*'", t) and re.search(r"'supports_credentials'\s*=>\s*true", t):
            hit = _first(t, r"'allowed_origins'")
            out.append(_f("laravel-cors-credentials-any", "Laravel CORS: any origin with credentials", "high", "suspected",
                          "Any website could make authenticated requests on behalf of your users.",
                          "List explicit origins in allowed_origins.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-942"))
    for p in by_name.get("session.php", []):
        t = text_of(p)
        hit = _first(t, r"'http_only'\s*=>\s*false")
        if hit:
            out.append(_f("laravel-session-http-only", "Laravel session cookie without HttpOnly", "medium", "confirmed",
                          "JavaScript (and any XSS) can read the session cookie.", "Set 'http_only' => true.",
                          file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-1004", owasp="A07:2025"))

    # --- PHP ini ------------------------------------------------------------------------------
    for p in [x for x in files if x.name in ("php.ini", ".user.ini") or x.name.endswith(".ini") and "php" in x.name.lower()]:
        t = text_of(p)
        for rx, rid, title, sev, desc in [
            (r"^\s*display_errors\s*=\s*(On|1)", "php-display-errors", "display_errors enabled", "medium", "Errors shown to visitors reveal paths, queries and configuration."),
            (r"^\s*allow_url_include\s*=\s*(On|1)", "php-allow-url-include", "allow_url_include enabled", "high", "Remote file inclusion becomes possible when combined with an include of user input."),
            (r"^\s*expose_php\s*=\s*(On|1)", "php-expose", "expose_php enabled", "info", "The PHP version is advertised in X-Powered-By, which makes it trivial to spot unpatched servers."),
        ]:
            hit = _first(t, rx, re.M | re.I)
            if hit:
                out.append(_f(rid, title, sev, "confirmed", desc, "Disable it in production php.ini.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-16"))
        if re.search(r"(?mi)^\s*session\.upload_progress\.enabled\s*=\s*(On|1)", t):
            hit = _first(t, r"^\s*session\.upload_progress\.enabled", re.M | re.I)
            out.append(_f("php-upload-progress", "session.upload_progress enabled", "info", "preventive",
                          "Upload progress tracking adds attacker-reachable code to every request that carries a session. Most apps do not use it, so disabling it reduces attack surface.",
                          "Set session.upload_progress.enabled=0 if you do not need it.", file=rel(p, root), line=hit[0], evidence=hit[1]))

    # --- Django -------------------------------------------------------------------------------
    for p in [x for x in files if x.name in ("settings.py",) or (x.suffix == ".py" and x.parent.name == "settings")]:
        t = text_of(p)
        for rx, rid, title, sev, desc, fix in [
            (r"^DEBUG\s*=\s*True", "django-debug", "Django DEBUG = True", "medium", "Debug pages leak settings and code if this file is used in production.", "Read DEBUG from the environment and default to False."),
            (r"^ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]", "django-allowed-hosts-any", "ALLOWED_HOSTS = ['*']", "medium", "Any Host header is accepted, enabling host-header poisoning of password-reset links.", "List your real domains."),
            (r"^SESSION_COOKIE_SECURE\s*=\s*False", "django-session-insecure", "SESSION_COOKIE_SECURE = False", "medium", "Session cookies may travel over HTTP.", "Set SESSION_COOKIE_SECURE = True in production."),
            (r"^CORS_ALLOW_ALL_ORIGINS\s*=\s*True", "django-cors-all", "CORS_ALLOW_ALL_ORIGINS = True", "medium", "Every website can call the API from the browser.", "Use CORS_ALLOWED_ORIGINS."),
        ]:
            hit = _first(t, rx)
            if hit:
                out.append(_f(rid, title, sev, "suspected", desc, fix, file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-16"))

    # --- Spring -------------------------------------------------------------------------------
    for p in [x for x in files if x.name.startswith("application") and x.suffix in (".properties", ".yml", ".yaml")]:
        t = text_of(p)
        hit = _first(t, r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*|include:\s*['\"]?\*")
        if hit:
            out.append(_f("spring-actuator-exposed", "All Spring Boot Actuator endpoints exposed", "high", "suspected",
                          "Endpoints like /actuator/env and /actuator/heapdump leak secrets and memory.",
                          "Expose only health/info, and protect the rest behind authentication.", file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-215"))

    # --- Firebase rules -----------------------------------------------------------------------
    for p in [x for x in files if x.name in ("firestore.rules", "storage.rules", "database.rules.json")]:
        t = text_of(p)
        hit = _first(t, r"allow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true|\"\.(?:read|write)\"\s*:\s*true")
        if hit:
            out.append(_f("firebase-open-rules", "Firebase rules allow public access", "critical", "confirmed",
                          "Anyone with your public Firebase config can read or write this data.",
                          "Require request.auth and check ownership in the rules.", file=rel(p, root), line=hit[0], evidence=hit[1],
                          cwe="CWE-284", owasp="A01:2025", category="external-services"))

    # --- Supabase: RLS and service key in client code ------------------------------------------
    migrations = [x for x in files if x.suffix == ".sql" and "migrations" in rel(x, root)]
    if migrations:
        sql = "\n".join(text_of(x) for x in migrations)
        created = {m.group(1).split(".")[-1].strip('"') for m in re.finditer(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?((?:public\.)?\"?\w+\"?)", sql)}
        with_rls = {m.group(1).split(".")[-1].strip('"') for m in re.finditer(r"(?i)alter\s+table\s+(?:only\s+)?((?:public\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security", sql)}
        missing = sorted(created - with_rls)
        if missing and ("Supabase" in stack.get("platforms", []) or "Supabase" in fw):
            out.append(_f("supabase-rls-missing", "Tables created without Row Level Security", "high", "suspected",
                          "In Supabase every table in the public schema is reachable through the auto-generated API with the public anon key. Without RLS, anyone can read or modify it. Tables: " + ", ".join(missing[:15]),
                          "Enable RLS on every public table and add policies.", file=rel(migrations[0], root),
                          cwe="CWE-284", owasp="A01:2025", category="external-services",
                          remediation=["alter table <name> enable row level security;", "create policy ... using (auth.uid() = user_id);"],
                          references=["https://supabase.com/docs/guides/database/postgres/row-level-security"]))
    for p in files:
        if p.suffix.lower() not in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"):
            continue
        t = text_of(p)
        if re.search(r"^\s*['\"]use client['\"]", t, re.M) or "/components/" in "/" + rel(p, root):
            hit = _first(t, r"SERVICE_ROLE|service_role|SUPABASE_SECRET")
            if hit:
                out.append(_f("supabase-service-key-client", "Supabase service key referenced in client code", "critical", "suspected",
                              "The service key bypasses RLS. In a client component it ends up in the browser.",
                              "Use the anon/publishable key in the browser and keep service keys in server code only.",
                              file=rel(p, root), line=hit[0], evidence=hit[1], cwe="CWE-200", owasp="A01:2025", category="external-services"))
    return out


def check_docker(root: Path, files: list[Path]) -> list[Finding]:
    out = []
    for p in files:
        n = p.name
        r = rel(p, root)
        if n == "Dockerfile" or n.startswith("Dockerfile.") or n.endswith(".Dockerfile"):
            t = read_text(p) or ""
            stages = re.split(r"(?mi)^\s*FROM\s", t)
            final = stages[-1] if len(stages) > 1 else t
            if not re.search(r"(?mi)^\s*USER\s+(?!root\b|0\b)\S+", final):
                out.append(_f("docker-root-user", "Container runs as root", "medium", "preventive",
                              "If the app is compromised, the attacker is root inside the container, which makes escapes and lateral movement easier.",
                              "Add a non-root USER in the final stage.", file=r, cwe="CWE-250", category="docker",
                              remediation=["RUN adduser -D app (or useradd) and USER app", "Official node images ship a 'node' user: USER node"]))
            for i, line in enumerate(t.splitlines(), 1):
                if re.match(r"\s*FROM\s+[\w./-]+(?::latest)?\s*(?:AS\s+\w+)?\s*$", line, re.I) and not re.search(r":(?!latest)[\w.-]+|@sha256", line) and "scratch" not in line:
                    out.append(_f("docker-unpinned-image", "Base image without a pinned version", "low", "preventive",
                                  "Unpinned images change under you and hide which security patches are included.",
                                  "Pin a version tag (and ideally a digest).", file=r, line=i, evidence=line.strip(), category="docker", owasp="A03:2025"))
                if re.match(r"\s*ADD\s+https?://", line, re.I):
                    out.append(_f("docker-add-remote", "ADD downloads a remote file", "medium", "suspected",
                                  "Remote ADD is not checksum-verified; a compromised URL injects code into the image.",
                                  "Download with curl and verify a checksum, or COPY a vendored file.", file=r, line=i, evidence=line.strip(), cwe="CWE-494", owasp="A08:2025", category="docker"))
                if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", line):
                    out.append(_f("docker-curl-pipe-sh", "Script piped from the network into a shell", "medium", "suspected",
                                  "Whatever the remote server returns at build time is executed.",
                                  "Download, verify the checksum/signature, then execute.", file=r, line=i, evidence=line.strip(), cwe="CWE-494", owasp="A08:2025", category="docker"))
                m = re.match(r"\s*(?:ENV|ARG)\s+(\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*)[ =]+(\S+)", line, re.I)
                if m and not m.group(2).startswith("$"):
                    out.append(_f("docker-secret-in-image", f"Secret baked into the image ({m.group(1)})", "high", "suspected",
                                  "ENV/ARG values are stored in image layers and visible with docker history.",
                                  "Use build secrets (RUN --mount=type=secret) or runtime environment variables.",
                                  file=r, line=i, evidence=f"{m.group(1)}=***", cwe="CWE-798", category="docker"))
        elif n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            t = read_text(p) or ""
            for rx, rid, title, sev, desc, fix in [
                (r"^\s*privileged:\s*true", "compose-privileged", "Privileged container", "high", "Privileged containers can access the host kernel and devices.", "Remove privileged and grant only the capabilities needed."),
                (r"/var/run/docker\.sock", "compose-docker-socket", "Docker socket mounted", "high", "Access to docker.sock equals root on the host.", "Do not mount the Docker socket; use a restricted proxy if unavoidable."),
                (r"^\s*-\s*['\"]?(?:0\.0\.0\.0:)?(5432|3306|27017|6379|9200|11211):\d+", "compose-db-port-exposed", "Database port published on all interfaces", "medium", "The database is reachable from outside the host if the firewall allows it.", "Remove the ports mapping or bind it to 127.0.0.1."),
                (r"^\s*network_mode:\s*['\"]?host", "compose-host-network", "Host networking", "low", "The container shares the host network stack.", "Use a bridge network unless strictly required."),
            ]:
                hit = _first(t, rx)
                if hit:
                    out.append(_f(rid, title, sev, "suspected", desc, fix, file=r, line=hit[0], evidence=hit[1], cwe="CWE-250", category="docker"))
    return out


def check_ci(root: Path, files: list[Path]) -> list[Finding]:
    out = []
    for p in files:
        r = rel(p, root)
        if "/.github/workflows/" not in "/" + r or p.suffix not in (".yml", ".yaml"):
            continue
        t = read_text(p) or ""
        if re.search(r"(?m)^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", t) and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", t):
            hit = _first(t, r"pull_request_target")
            out.append(_f("gha-pwn-request", "pull_request_target checks out untrusted PR code", "high", "suspected",
                          "Workflows triggered by pull_request_target run with secrets and a write token; checking out the PR head lets a fork run code with them.",
                          "Use pull_request, or never build/run the PR head in pull_request_target jobs.", file=r, line=hit[0], evidence=hit[1],
                          cwe="CWE-829", owasp="A08:2025", category="ci"))
        for m in re.finditer(r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|review\.body|pull_request\.head\.ref|head_commit\.message)[^}]*\}\}", t):
            ln = line_of(t, m.start())
            prev = "\n".join(t.splitlines()[max(0, ln - 6):ln])
            if re.search(r"\brun:\s*", prev) or re.search(r"\brun:", snippet(t, ln)):
                out.append(_f("gha-script-injection", "Untrusted event data interpolated into a shell step", "high", "suspected",
                              "Titles, bodies and branch names are attacker-controlled; ${{ }} is substituted before the shell runs, so they can inject commands.",
                              "Pass the value through env: and reference it as \"$VAR\".", file=r, line=ln, evidence=snippet(t, ln),
                              cwe="CWE-78", owasp="A05:2025", category="ci",
                              references=["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"]))
        hit = _first(t, r"^\s*permissions:\s*write-all")
        if hit:
            out.append(_f("gha-write-all", "Workflow token with write-all permissions", "medium", "preventive",
                          "A compromised step can push code, create releases or change settings.", "Grant the minimum permissions per job.",
                          file=r, line=hit[0], evidence=hit[1], cwe="CWE-250", category="ci"))
        unpinned = [m for m in re.finditer(r"uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)", t)
                    if not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith(("actions/", "github/"))]
        if unpinned:
            m = unpinned[0]
            out.append(_f("gha-unpinned-action", f"{len(unpinned)} third-party action(s) not pinned to a commit SHA", "low", "preventive",
                          "Tags can be moved; a compromised action repository then runs new code in your pipeline with your secrets.",
                          "Pin third-party actions to a full commit SHA.", file=r, line=line_of(t, m.start()), evidence=snippet(t, line_of(t, m.start())),
                          cwe="CWE-829", owasp="A03:2025", category="ci"))
    return out

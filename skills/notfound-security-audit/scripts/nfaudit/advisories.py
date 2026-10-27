"""Runtime version detection and the small offline advisory list (data/known-advisories.json)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .util import DATA_DIR, Finding, in_range, iter_files, load_json, parse_version, read_text, rel, version_lt

DOCKER_RUNTIMES = {"php": "php", "node": "node", "python": "python", "bitnami/php-fpm": "php", "bitnami/node": "node"}


def detect_runtimes(root: Path, excludes: list) -> list[dict]:
    """Return [{runtime, version, exact, file, line}] for every place a runtime version is declared."""
    found = []
    for path in iter_files(root, excludes):
        name = path.name
        r = rel(path, root)
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            text = read_text(path) or ""
            for i, line in enumerate(text.splitlines(), 1):
                m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?([\w./-]+?)(?::([\w.\-]+))?(?:@sha256:\w+)?(?:\s+AS\s+\w+)?\s*$", line, re.I)
                if not m:
                    continue
                image, tag = m.group(1).lower(), (m.group(2) or "latest")
                rt = DOCKER_RUNTIMES.get(image)
                if rt:
                    vm = re.match(r"(\d+(?:\.\d+){0,2})", tag)
                    if vm:
                        found.append({"runtime": rt, "version": vm.group(1), "exact": vm.group(1).count(".") == 2, "file": r, "line": i})
                    else:
                        found.append({"runtime": rt, "version": tag, "exact": False, "file": r, "line": i})
        elif name in (".nvmrc", ".node-version"):
            v = (read_text(path) or "").strip().lstrip("v")
            if re.match(r"\d", v):
                found.append({"runtime": "node", "version": v, "exact": v.count(".") == 2, "file": r, "line": 1})
        elif name == ".python-version" or name == "runtime.txt":
            v = (read_text(path) or "").strip().replace("python-", "")
            if re.match(r"\d", v):
                found.append({"runtime": "python", "version": v, "exact": v.count(".") == 2, "file": r, "line": 1})
        elif name == ".tool-versions":
            for i, line in enumerate((read_text(path) or "").splitlines(), 1):
                m = re.match(r"\s*(nodejs|node|php|python)\s+(\d[\w.]*)", line)
                if m:
                    rt = "node" if m.group(1).startswith("node") else m.group(1)
                    found.append({"runtime": rt, "version": m.group(2), "exact": m.group(2).count(".") == 2, "file": r, "line": i})
        elif name == "package.json":
            try:
                eng = (json.loads(read_text(path) or "{}").get("engines") or {}).get("node")
            except ValueError:
                eng = None
            if eng:
                found.append({"runtime": "node", "version": str(eng), "exact": False, "file": r, "line": 0, "range": True})
        elif name == "composer.json":
            try:
                req = (json.loads(read_text(path) or "{}").get("require") or {}).get("php")
            except ValueError:
                req = None
            if req:
                found.append({"runtime": "php", "version": str(req), "exact": False, "file": r, "line": 0, "range": True})
    return found


def _runtime_findings(rt: dict, data: dict) -> list[Finding]:
    out = []
    v = rt["version"]
    loc = dict(file=rt["file"], line=rt["line"], evidence=f"{rt['runtime']} {v}")
    if rt.get("range"):
        return out  # a constraint, not what runs in production; reported in the inventory only
    if not parse_version(v):
        out.append(Finding(
            rule_id="runtime-floating-tag", title=f"{rt['runtime']} image uses a floating tag ({v})",
            severity="low", status="preventive", category="runtime",
            description="A floating tag like 'latest' or 'apache' does not tell which patch release runs. Old cached images keep running vulnerable versions until rebuilt with --pull.",
            recommendation="Pin a patched version (e.g. php:8.4.27-apache) and rebuild regularly.",
            remediation=["Pin MAJOR.MINOR.PATCH in FROM.", "Rebuild with docker build --pull after security releases."], **loc))
        return out
    for adv in data.get("runtimes", []):
        if adv["runtime"] != rt["runtime"]:
            continue
        for branch in adv["affected"]:
            introduced, fixed = branch[0], branch[1]
            if rt["exact"] and in_range(v, introduced, fixed):
                eol = len(branch) > 2 or fixed is None
                out.append(Finding(
                    rule_id=f"runtime-{adv['id'].lower()}", title=adv["title"], severity=adv["severity"],
                    status="confirmed", category="runtime", description=adv["summary"],
                    recommendation=adv["remediation"][0], remediation=adv["remediation"], references=adv["references"],
                    extra={"aliases": adv["aliases"], "fixed": None if eol else fixed, "end_of_life": eol}, **loc))
            elif not rt["exact"]:
                major_minor = parse_version(v)
                lo = parse_version(introduced)
                if major_minor and lo and major_minor[:2] == lo[:2] and fixed and len(branch) == 2:
                    out.append(Finding(
                        rule_id=f"runtime-{adv['id'].lower()}-unverified", title=f"{adv['title']}: check your patch version",
                        severity="medium", status="suspected", category="runtime",
                        description=f"Only '{v}' is declared, so the exact patch release cannot be checked. Versions below {fixed} on this branch are affected.",
                        recommendation=f"Confirm the running version is {fixed} or later (php -v / node -v inside the deployed image).",
                        remediation=adv["remediation"], references=adv["references"], extra={"aliases": adv["aliases"], "fixed": fixed}, **loc))
    for e in data.get("eol", []):
        if e["runtime"] != rt["runtime"]:
            continue
        pv = parse_version(v)
        if "below_major" in e and pv and pv[0] < e["below_major"] or ("below" in e and version_lt(v, e["below"])):
            out.append(Finding(
                rule_id=f"runtime-eol-{rt['runtime']}", title=f"{rt['runtime']} {v} is end-of-life", severity="high",
                status="confirmed", category="runtime", description=e["note"],
                recommendation="Upgrade to a supported release line.", remediation=["Upgrade the runtime and redeploy."], **loc))
    return out


def check_runtimes(runtimes: list[dict]) -> list[Finding]:
    data = load_json(DATA_DIR / "known-advisories.json")
    out = []
    for rt in runtimes:
        out += _runtime_findings(rt, data)
    return out


def check_packages_offline(deps: list) -> list[Finding]:
    data = load_json(DATA_DIR / "known-advisories.json")
    out = []
    for adv in data.get("packages", []):
        for d in deps:
            if d.ecosystem != adv["ecosystem"] or d.name != adv["package"]:
                continue
            for introduced, fixed in adv["affected"]:
                if in_range(d.version, introduced, fixed):
                    out.append(Finding(
                        rule_id=f"dep-{adv['id'].lower()}", title=f"{d.name} {d.version}: {adv['title']}",
                        severity=adv["severity"], status="confirmed", category="dependency", description=adv["summary"],
                        recommendation=adv["remediation"][0], remediation=adv["remediation"], references=adv["references"],
                        file=d.file, evidence=f"{d.name}@{d.version}", cwe="CWE-1395", owasp="A03:2025",
                        extra={"aliases": adv["aliases"], "fixed": fixed, "package": d.name, "version": d.version}))
    return out

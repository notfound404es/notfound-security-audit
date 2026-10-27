"""OSV.dev lookups (opt-in with --osv). Sends only ecosystem, package name and version: never source code."""
from __future__ import annotations

import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .util import Finding

API = "https://api.osv.dev/v1"
UA = "notfound-security-audit (+https://github.com/notfound404es/notfound-security-audit)"
GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _post(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoint
        return json.loads(resp.read().decode())


def _get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoint
        return json.loads(resp.read().decode())


def _cvss_base(vector: str) -> str | None:
    """Rough severity bucket from a CVSS vector when no label is published."""
    if not vector:
        return None
    if re.search(r"CVSS:4", vector):
        crit = all(x in vector for x in ("AV:N", "AC:L", "PR:N")) and "VC:H" in vector
        return "critical" if crit else "high" if "AV:N" in vector else "medium"
    crit = all(x in vector for x in ("AV:N", "AC:L", "PR:N", "UI:N")) and "C:H" in vector and "I:H" in vector
    return "critical" if crit else "high" if "AV:N" in vector and ("C:H" in vector or "I:H" in vector) else "medium"


def _severity(vuln: dict) -> str:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in GHSA_SEVERITY:
        return GHSA_SEVERITY[label.upper()]
    for s in vuln.get("severity") or []:
        sev = _cvss_base(s.get("score", ""))
        if sev:
            return sev
    for a in vuln.get("affected") or []:
        label = (a.get("ecosystem_specific") or {}).get("severity") or (a.get("database_specific") or {}).get("severity")
        if isinstance(label, str) and label.upper() in GHSA_SEVERITY:
            return GHSA_SEVERITY[label.upper()]
    return "medium"


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    fixed = []
    for a in vuln.get("affected") or []:
        if (a.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def lookup(deps: list, timeout: float = 20.0, batch: int = 500) -> tuple[list[Finding], list[str]]:
    """Query OSV for every dependency. Returns (findings, errors)."""
    errors: list[str] = []
    hits: list[tuple] = []
    for i in range(0, len(deps), batch):
        chunk = deps[i:i + batch]
        payload = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]}
        try:
            res = _post(f"{API}/querybatch", payload, timeout)
        except Exception as exc:  # network errors are reported, never fatal
            errors.append(f"OSV querybatch failed: {exc}")
            return [], errors
        for d, r in zip(chunk, res.get("results", [])):
            for v in r.get("vulns") or []:
                hits.append((d, v["id"]))
    details: dict[str, dict] = {}

    def fetch(vid: str):
        try:
            details[vid] = _get(f"{API}/vulns/{vid}", timeout)
        except Exception as exc:
            errors.append(f"OSV vuln {vid}: {exc}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(fetch, sorted({vid for _, vid in hits})))
    findings = []
    for d, vid in hits:
        v = details.get(vid, {"id": vid})
        aliases = [a for a in v.get("aliases") or [] if a != vid]
        fixed = _fixed_versions(v, d.name)
        cves = [a for a in [vid] + aliases if a.startswith("CVE-")]
        fix_txt = f"Upgrade {d.name} to {', '.join(fixed)} or later." if fixed else f"No fixed version published for {d.name}; consider replacing it or mitigating."
        findings.append(Finding(
            rule_id=f"osv-{vid}", title=f"{d.name} {d.version}: {v.get('summary') or vid}",
            severity=_severity(v), status="confirmed", category="dependency",
            description=(v.get("details") or v.get("summary") or "Known vulnerability in this version.")[:900],
            recommendation=fix_txt, file=d.file, evidence=f"{d.name}@{d.version} ({d.ecosystem})",
            cwe=", ".join((v.get("database_specific") or {}).get("cwe_ids") or []), owasp="A03:2025",
            remediation=[fix_txt, "Regenerate the lockfile and redeploy.", "Check whether the vulnerable code path is used to prioritise."],
            references=[f"https://osv.dev/vulnerability/{vid}"] + [r["url"] for r in (v.get("references") or [])[:3] if r.get("url")],
            source="osv.dev", extra={"id": vid, "aliases": aliases, "cves": cves, "fixed": fixed, "package": d.name,
                                     "version": d.version, "ecosystem": d.ecosystem, "direct": d.direct}))
    return findings, errors

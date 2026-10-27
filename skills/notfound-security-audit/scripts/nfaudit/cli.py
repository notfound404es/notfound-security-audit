"""Command line interface.

    nfaudit scan [PATH] [--osv] [--format md,json,sarif] [--out DIR] [--fail-on high]
    nfaudit headers URL [--format ...]
    nfaudit rules

The scan never modifies the target: it reads files, runs `git ls-files` and writes reports outside the
project (system temp dir) unless --out says otherwise. Network access only happens with --osv or `headers`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
import tempfile
from pathlib import Path

from . import __version__, advisories, configs, deps as deps_mod, headers as headers_mod, osv, report, stack
from .scanners import Rules, scan_sources
from .util import DEFAULT_EXCLUDES, RULES_DIR, SEVERITY_RANK, iter_files, load_json

CONFIG_NAME = ".nfaudit.json"


def load_config(root: Path, explicit: str | None) -> dict:
    path = Path(explicit) if explicit else root / CONFIG_NAME
    if not path.exists():
        return {}
    cfg = load_json(path)
    return {"exclude": cfg.get("exclude", []), "disable_rules": cfg.get("disable_rules", []),
            "ignore": cfg.get("ignore", []), "include_tests": cfg.get("include_tests", True)}


def _dedupe(findings: list) -> list:
    seen, out = set(), []
    for f in findings:
        key = f.fingerprint + str(f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def run_scan(root: Path, use_osv: bool = False, config: dict | None = None, extra_excludes: list | None = None) -> dict:
    config = config or {}
    root = root.resolve()
    excludes = DEFAULT_EXCLUDES + list(config.get("exclude", [])) + list(extra_excludes or [])
    disabled = set(config.get("disable_rules", []))
    files = list(iter_files(root, excludes))
    notes, errors, checks = [], [], ["stack", "secrets", "code-patterns", "config", "docker", "ci", "runtimes", "dependencies-offline"]

    st = stack.detect(root, excludes)
    rules = Rules(disabled)
    findings, entry_points, scanned = scan_sources(root, files, rules)
    findings += configs.check_env_files(root, files)
    findings += configs.check_frameworks(root, files, st)
    findings += configs.check_docker(root, files)
    findings += configs.check_ci(root, files)

    runtimes = advisories.detect_runtimes(root, excludes)
    findings += advisories.check_runtimes(runtimes)

    dep_info = deps_mod.collect(root, excludes)
    errors += dep_info["errors"]
    findings += advisories.check_packages_offline(dep_info["deps"])
    if use_osv:
        checks.append("osv.dev")
        osv_findings, osv_errors = osv.lookup(dep_info["deps"])
        errors += osv_errors
        # keep the curated entry when OSV reports the same package/version under one of its aliases
        curated: dict[tuple, set] = {}
        for f in findings:
            if f.rule_id.startswith("dep-"):
                curated.setdefault((f.extra.get("package"), f.extra.get("version")), set()).update(f.extra.get("aliases", []))
        for f in osv_findings:
            known = curated.get((f.extra.get("package"), f.extra.get("version")), set())
            if known & ({f.extra.get("id")} | set(f.extra.get("aliases", []))):
                continue
            findings.append(f)
    else:
        notes.append("Dependencies were only checked against the small built-in advisory list. Run with --osv (sends package "
                     "names and versions to OSV.dev, never code) for full CVE coverage.")
    for m in dep_info["manifests_without_lock"]:
        notes.append(f"{m['file']} has no lockfile; versions of {len(m['unresolved'])} dependencies could not be resolved.")
    if not runtimes:
        notes.append("No runtime version declared (Dockerfile, .nvmrc, .python-version…). Check `php -v` / `node -v` on the server.")
    for rt in runtimes:
        if rt.get("range"):
            notes.append(f"{rt['file']} declares {rt['runtime']} '{rt['version']}': a constraint, not the version running in production.")

    tracked = configs.git_tracked(root)
    if tracked is not None:
        for f in findings:
            # a key in a local, git-ignored .env file is where keys are supposed to live: report it, but as hygiene
            if f.category == "secrets" and Path(f.file).name.startswith(".env") and f.file not in tracked:
                f.status, f.severity = "preventive", "info"
                f.title = f.title.replace(" in source", " in a local env file (not committed)")
                f.description = ("The value lives in an untracked env file, which is the expected place. Keep it out of git, "
                                 "never prefix it with NEXT_PUBLIC_/VITE_, and rotate it if the file was ever shared.")
                f.recommendation = "No action needed if this file stays local and server-side."
                f.remediation = []
    findings = _dedupe(findings)
    if not config.get("include_tests", True):
        findings = [f for f in findings if not f.extra.get("in_tests")]
    ignored = set(config.get("ignore", []))
    findings = [f for f in findings if f.fingerprint not in ignored]
    as_dicts = sorted((f.to_dict() for f in findings), key=report.sort_key)
    return {
        "tool": "notfound-security-audit",
        "version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "target": root.name,
        "checks": checks,
        "stack": st,
        "files_scanned": scanned,
        "dependency_count": len(dep_info["deps"]),
        "lockfiles": dep_info["lockfiles"],
        "runtimes": runtimes,
        "summary": report.summary(as_dicts),
        "findings": as_dicts,
        "entry_points": entry_points,
        "notes": notes,
        "errors": errors,
        "ignored_count": len(ignored),
    }


def _default_out(name: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(tempfile.gettempdir()) / "nfaudit" / f"{name}-{stamp}"


def _print_summary(result: dict, written: dict) -> None:
    s = result["summary"]
    print(f"NotFound Security Audit {result['version']} · {result['target']}")
    if result.get("stack"):
        st = result["stack"]
        print(f"  stack: {', '.join(st.get('frameworks') or []) or '-'} | {', '.join(st.get('languages') or []) or '-'}")
    print(f"  findings: {s['total']}  (confirmed {s['by_status'].get('confirmed', 0)}, "
          f"needs review {s['by_status'].get('suspected', 0)}, preventive {s['by_status'].get('preventive', 0)})")
    print("  severity: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v))
    for f in [x for x in result["findings"] if x["status"] == "confirmed" or x["severity"] in ("critical", "high")][:15]:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"  - [{f['severity']}/{f['status']}] {f['title']}  ({loc})")
    for fmt, path in written.items():
        print(f"  report ({fmt}): {path}")


def _fail(result: dict, threshold: str | None) -> bool:
    if not threshold:
        return False
    limit = SEVERITY_RANK[threshold]
    return any(SEVERITY_RANK[f["severity"]] <= limit and f["status"] != "preventive" for f in result["findings"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nfaudit", description="NotFound Security Audit: read-only security checks.")
    p.add_argument("--version", action="version", version=f"nfaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan a local project (read-only)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--osv", action="store_true", help="query OSV.dev for dependency CVEs (sends package names + versions)")
    sp.add_argument("--format", default="md,json", help="comma list: md,json,sarif (default md,json)")
    sp.add_argument("--out", help="output directory (default: system temp dir, outside the project)")
    sp.add_argument("--config", help=f"config file (default: PATH/{CONFIG_NAME})")
    sp.add_argument("--exclude", action="append", default=[], help="extra path/glob to exclude (repeatable)")
    sp.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit 1 if a non-preventive finding has this severity or higher")
    sp.add_argument("--stdout", choices=["json", "md", "sarif"], help="print the report to stdout instead of writing files")

    hp = sub.add_parser("headers", help="check security headers of ONE URL you own (single GET request)")
    hp.add_argument("url")
    hp.add_argument("--format", default="md,json")
    hp.add_argument("--out")
    hp.add_argument("--stdout", choices=["json", "md", "sarif"])

    sub.add_parser("rules", help="list the built-in rules")
    args = p.parse_args(argv)

    if args.cmd == "rules":
        for r in load_json(RULES_DIR / "code-patterns.json")["rules"]:
            print(f"{r['id']:<34} {r['severity']:<8} {r['status']:<10} {r['title']}")
        for r in load_json(RULES_DIR / "secrets.json")["rules"]:
            print(f"secret-{r['id']:<27} {r['severity']:<8} suspected  {r['title']}")
        return 0

    if args.cmd == "headers":
        try:
            findings, meta = headers_mod.check(args.url)
        except Exception as exc:  # network problems are user-facing, not crashes
            print(f"Could not fetch {args.url}: {exc}", file=sys.stderr)
            return 2
        as_dicts = sorted((f.to_dict() for f in findings), key=report.sort_key)
        result = {"tool": "notfound-security-audit", "version": __version__,
                  "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                  "target": args.url, "checks": ["live-headers"], "stack": {}, "files_scanned": 0, "dependency_count": 0,
                  "summary": report.summary(as_dicts), "findings": as_dicts, "entry_points": [], "response": meta,
                  "notes": [f"HTTP {meta['status']} from a single GET request."], "errors": []}
        name = "headers"
    else:
        root = Path(args.path)
        if not root.is_dir():
            print(f"Not a directory: {root}", file=sys.stderr)
            return 2
        cfg = load_config(root, args.config)
        result = run_scan(root, use_osv=args.osv, config=cfg, extra_excludes=args.exclude)
        name = root.resolve().name

    if args.stdout:
        fn = {"json": report.to_json, "md": report.to_markdown, "sarif": report.to_sarif}[args.stdout]
        sys.stdout.reconfigure(encoding="utf-8") if hasattr(sys.stdout, "reconfigure") else None
        print(fn(result))
    else:
        formats = [x.strip() for x in args.format.split(",") if x.strip()]
        bad = [x for x in formats if x not in ("md", "json", "sarif")]
        if bad:
            print(f"Unknown format: {', '.join(bad)}", file=sys.stderr)
            return 2
        out = Path(args.out) if args.out else _default_out(name)
        written = report.write_all(result, out, formats)
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        _print_summary(result, written)
    return 1 if _fail(result, getattr(args, "fail_on", None)) else 0


if __name__ == "__main__":
    sys.exit(main())

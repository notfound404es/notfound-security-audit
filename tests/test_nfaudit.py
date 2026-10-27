"""Tests for NotFound Security Audit. Standard library only: python -m unittest discover -s tests -v

Fixtures are written to a temporary directory at runtime. Fake credentials are assembled from pieces so
this repository never contains strings that look like real secrets (and secret scanners stay quiet).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "skills" / "notfound-security-audit" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from nfaudit import report  # noqa: E402
from nfaudit.cli import main, run_scan  # noqa: E402
from nfaudit.util import in_range, redact, version_lt  # noqa: E402

FAKE_AWS = "AKIA" + "Z7XK2M9QWLP4R8TN"
FAKE_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc9x"


def write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def npm_lock(next_version: str) -> str:
    return json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {
        "": {"name": "demo", "dependencies": {"next": next_version}},
        "node_modules/next": {"version": next_version},
        "node_modules/react": {"version": "19.2.0"},
    }})


def build_vulnerable(root: Path) -> None:
    write(root, "package.json", json.dumps({"name": "demo", "dependencies": {"next": "16.3.0", "react": "19.2.0", "express": "5.0.0"}}))
    write(root, "package-lock.json", npm_lock("16.3.0"))
    write(root, "next.config.js", "module.exports = { experimental: { serverActions: { allowedOrigins: ['*'] } } }\n")
    write(root, "app/api/run/route.ts",
          "import { exec } from 'child_process'\n"
          "export async function POST(req: Request) {\n"
          "  const { dir } = await req.json()\n"
          "  exec(`ls ${dir}`)\n"  # nfaudit-ignore (intentional fixture)
          "  return Response.json({ ok: true })\n"
          "}\n")
    write(root, "lib/config.ts", f"export const aws = '{FAKE_AWS}'\nexport const stripe = \"{FAKE_STRIPE}\"\n")
    write(root, "public/legacy/user.php",
          "<?php\n$id = $_GET['id'];\n$r = mysqli_query($db, \"SELECT * FROM users WHERE id = \" . $_GET['id']);\n")
    write(root, "Dockerfile", "FROM php:8.3.20-apache\nCOPY . /var/www/html\n")
    write(root, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n")
    write(root, ".env", "APP_ENV=production\nAPP_DEBUG=true\n")
    write(root, "firestore.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /{d=**} {\n    allow read, write: if true;\n  }\n}\n")
    write(root, ".github/workflows/triage.yml",
          "on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n")
    write(root, "backend/settings.py", "DEBUG = True\nALLOWED_HOSTS = ['*']\n")


def build_clean(root: Path) -> None:
    write(root, "package.json", json.dumps({"name": "clean", "dependencies": {"next": "16.4.1", "react": "19.2.0"}}))
    write(root, "package-lock.json", npm_lock("16.4.1"))
    write(root, "next.config.js",
          "module.exports = { poweredByHeader: false, async headers() { return [{ source: '/(.*)', headers: [\n"
          "  { key: 'Content-Security-Policy', value: \"default-src 'self'\" },\n"
          "  { key: 'Strict-Transport-Security', value: 'max-age=31536000' } ] }] } }\n")
    write(root, "app/page.tsx", "export default function Page() { return <main>Hello</main> }\n")
    write(root, "app/api/hello/route.ts", "export async function GET() { return Response.json({ hi: process.env.GREETING }) }\n")
    write(root, "Dockerfile", "FROM node:24.22.1-alpine\nWORKDIR /app\nCOPY . .\nUSER node\nCMD [\"node\", \"server.js\"]\n")
    write(root, ".nvmrc", "24.22.1\n")
    write(root, ".gitignore", ".env*\n!.env.example\n")
    write(root, ".env.example", "OPENAI_API_KEY=your_key_here\n")


def digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


class VulnerableProjectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="nfaudit-vuln-"))
        build_vulnerable(cls.tmp)
        cls.before = digest(cls.tmp)
        cls.result = run_scan(cls.tmp)
        cls.ids = {f["rule_id"] for f in cls.result["findings"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def find(self, rule_id):
        return [f for f in self.result["findings"] if f["rule_id"] == rule_id]

    def test_stack_detected(self):
        st = self.result["stack"]
        self.assertIn("Next.js", st["frameworks"])
        self.assertIn("Express", st["frameworks"])
        self.assertIn("Docker", st["platforms"])
        self.assertIn("php", st["languages"])

    def test_vulnerable_next_is_confirmed(self):
        hits = self.find("dep-nextjs-2026-10-14")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["status"], "confirmed")
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertIn("16.4.1", hits[0]["extra"]["fixed"])

    def test_vulnerable_php_runtime_is_confirmed(self):
        hits = self.find("runtime-php2shell-2026-10")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["status"], "confirmed")
        self.assertEqual(hits[0]["file"], "Dockerfile")

    def test_code_patterns(self):
        for rid in ("js-command-injection", "php-sql-injection"):
            self.assertIn(rid, self.ids)
        self.assertEqual(self.find("js-command-injection")[0]["status"], "suspected")

    def test_secrets_are_found_and_redacted(self):
        self.assertIn("secret-aws-access-key-id", self.ids)
        self.assertIn("secret-stripe-live-key", self.ids)
        for fmt in (report.to_json, report.to_markdown, report.to_sarif):
            text = fmt(self.result)
            self.assertNotIn(FAKE_AWS, text)
            self.assertNotIn(FAKE_STRIPE, text)
            self.assertNotIn(FAKE_STRIPE[:12], text)

    def test_config_checks(self):
        for rid in ("next-server-actions-any-origin", "laravel-debug-production", "firebase-open-rules",
                    "gha-script-injection", "django-debug", "django-allowed-hosts-any", "docker-root-user",
                    "compose-db-port-exposed", "express-no-helmet"):
            self.assertIn(rid, self.ids, rid)

    def test_entry_points(self):
        kinds = {e["kind"] for e in self.result["entry_points"]}
        self.assertIn("Next.js route handler", kinds)
        self.assertIn("PHP entry reading request", kinds)

    def test_statuses_are_valid(self):
        for f in self.result["findings"]:
            self.assertIn(f["status"], ("confirmed", "suspected", "preventive"))
            self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))
            self.assertTrue(f["recommendation"])

    def test_scan_is_read_only(self):
        run_scan(self.tmp)
        self.assertEqual(digest(self.tmp), self.before)

    def test_reports(self):
        sarif = json.loads(report.to_sarif(self.result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(self.result["findings"]))
        md = report.to_markdown(self.result)
        self.assertIn("## Confirmed", md)
        self.assertIn("## Needs review", md)
        json.loads(report.to_json(self.result))

    def test_ignore_by_fingerprint(self):
        fp = self.find("js-command-injection")[0]["fingerprint"]
        res = run_scan(self.tmp, config={"ignore": [fp]})
        self.assertNotIn(fp, {f["fingerprint"] for f in res["findings"]})

    def test_disable_rule(self):
        res = run_scan(self.tmp, config={"disable_rules": ["js-command-injection"]})
        self.assertNotIn("js-command-injection", {f["rule_id"] for f in res["findings"]})

    def test_cli_fail_on_and_default_output_outside_project(self):
        out = Path(tempfile.mkdtemp(prefix="nfaudit-out-"))
        try:
            code = main(["scan", str(self.tmp), "--out", str(out), "--format", "md,json,sarif", "--fail-on", "high"])
            self.assertEqual(code, 1)
            self.assertTrue((out / "nfaudit-report.sarif").exists())
        finally:
            shutil.rmtree(out, ignore_errors=True)
        self.assertFalse(any(p.name.startswith("nfaudit-report") for p in self.tmp.rglob("*")))


class CleanProjectTest(unittest.TestCase):
    def test_clean_project_has_no_confirmed_or_high(self):
        tmp = Path(tempfile.mkdtemp(prefix="nfaudit-clean-"))
        try:
            build_clean(tmp)
            res = run_scan(tmp)
            bad = [f for f in res["findings"] if f["status"] != "preventive" or f["severity"] in ("critical", "high")]
            self.assertEqual(bad, [], json.dumps(bad, indent=1))
            self.assertEqual(main(["scan", str(tmp), "--out", str(tmp / ".." / (tmp.name + "-out")), "--fail-on", "low"]), 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(str(tmp) + "-out", ignore_errors=True)


class HelpersTest(unittest.TestCase):
    def test_versions(self):
        self.assertTrue(in_range("8.3.20", "8.3.0", "8.3.36"))
        self.assertFalse(in_range("8.3.36", "8.3.0", "8.3.36"))
        self.assertTrue(in_range("7.4.33", "7.0.0", None))
        self.assertTrue(version_lt("15.5.27", "15.5.28"))
        self.assertFalse(version_lt("16.4.1", "16.4.1"))

    def test_redact_never_returns_the_secret(self):
        s = "abcd" + "efghijklmnopqrstuvwxyz0123"
        self.assertNotIn(s, redact(s))
        self.assertTrue(redact(s).startswith("abcd"))

    def test_runtime_unverified_minor(self):
        from nfaudit.advisories import check_runtimes
        res = check_runtimes([{"runtime": "php", "version": "8.4", "exact": False, "file": "Dockerfile", "line": 1}])
        self.assertEqual([f.status for f in res], ["suspected"])
        res = check_runtimes([{"runtime": "node", "version": "18.20.4", "exact": True, "file": ".nvmrc", "line": 1}])
        self.assertEqual([f.rule_id for f in res], ["runtime-eol-node"])

    def test_headers_analysis_offline(self):
        from nfaudit.headers import analyse
        res = analyse("https://example.test", 200, [("X-Powered-By", "PHP/8.4.10"), ("Set-Cookie", "PHPSESSID=abc; path=/")])
        ids = {f.rule_id for f in res}
        self.assertIn("hdr-missing-hsts", ids)
        self.assertIn("hdr-cookie-flags", ids)
        self.assertIn("runtime-php2shell-2026-10", ids)
        self.assertEqual([f.status for f in res if f.rule_id == "runtime-php2shell-2026-10"], ["suspected"])


class EntryPointTest(unittest.TestCase):
    def test_script_runs(self):
        out = subprocess.run([sys.executable, str(SCRIPTS / "nfaudit.py"), "--version"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("nfaudit", out.stdout)


if __name__ == "__main__":
    unittest.main()

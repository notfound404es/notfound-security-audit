"""Shared helpers: findings, file walking, versions and redaction."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

SKILL_DIR = Path(__file__).resolve().parents[2]
RULES_DIR = SKILL_DIR / "rules"
DATA_DIR = SKILL_DIR / "data"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# confirmed  = backed by an advisory database or an exact match (e.g. a vulnerable version is pinned)
# suspected  = a pattern that needs data-flow review before calling it a vulnerability
# preventive = hardening recommendation, not a vulnerability by itself
STATUSES = ["confirmed", "suspected", "preventive"]

DEFAULT_EXCLUDES = [
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt", ".output", ".svelte-kit",
    ".turbo", ".vercel", ".cache", "coverage", "__pycache__", ".venv", "venv", "env", ".tox",
    ".mypy_cache", ".pytest_cache", "target", "bin", "obj", ".gradle", ".idea", ".vscode",
    "storage/framework", "public/build", ".nfaudit",
]

LANG_EXT = {
    "js": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"),
    "php": (".php", ".phtml", ".inc"),
    "blade": (".blade.php",),
    "py": (".py",),
    "pytpl": (".html", ".jinja", ".jinja2", ".j2", ".djhtml"),
    "java": (".java", ".kt", ".kts", ".groovy"),
    "go": (".go",),
    "rb": (".rb", ".erb"),
}

TEXT_EXT = set(e for exts in LANG_EXT.values() for e in exts) | {
    ".json", ".yml", ".yaml", ".toml", ".ini", ".env", ".cfg", ".conf", ".properties", ".xml",
    ".txt", ".md", ".sh", ".bash", ".ps1", ".sql", ".tf", ".tfvars", ".gradle", ".lock", ".rules",
}
MAX_FILE_BYTES = 1_000_000
MINIFIED_LINE = 2000


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    status: str
    category: str
    description: str
    recommendation: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: list = field(default_factory=list)
    references: list = field(default_factory=list)
    source: str = "nfaudit"
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.file}|{self.evidence.strip()}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def is_excluded(rel: str, excludes: Iterable[str]) -> bool:
    rel = rel.replace("\\", "/")
    parts = rel.split("/")
    for pat in excludes:
        pat = pat.strip("/")
        if "/" in pat or any(ch in pat for ch in "*?["):
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or rel.startswith(pat + "/"):
                return True
        elif pat in parts:
            return True
    return False


def iter_files(root: Path, excludes: Iterable[str]) -> Iterator[Path]:
    excludes = list(excludes)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not is_excluded(f"{rel_dir}/{d}".lstrip("/"), excludes)]
        for name in filenames:
            rel = f"{rel_dir}/{name}".lstrip("/")
            if not is_excluded(rel, excludes):
                yield Path(dirpath) / name


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def lang_of(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".blade.php"):
        return "blade"
    for lang, exts in LANG_EXT.items():
        if lang == "blade":
            continue
        if name.endswith(exts):
            return lang
    return None


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def snippet(text: str, line: int, width: int = 200) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        s = lines[line - 1].strip()
        return s if len(s) <= width else s[: width - 1] + "…"
    return ""


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{'*' * 6} ({len(value)} chars)"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


_VER = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version(v: str) -> tuple | None:
    m = _VER.search(v or "")
    if not m:
        return None
    return tuple(int(x) if x is not None else 0 for x in m.groups())


def version_lt(a: str, b: str) -> bool:
    pa, pb = parse_version(a), parse_version(b)
    return bool(pa and pb and pa < pb)


def in_range(version: str, introduced: str, fixed: str | None) -> bool:
    v = parse_version(version)
    if not v:
        return False
    lo = parse_version(introduced) or (0, 0, 0)
    if v < lo:
        return False
    return fixed is None or v < (parse_version(fixed) or (0, 0, 0))


def exact_version(spec: str) -> str | None:
    """Return the version if spec pins an exact version (1.2.3, =1.2.3, ==1.2.3, v1.2.3)."""
    spec = (spec or "").strip()
    m = re.fullmatch(r"(?:==?|v)?\s*(\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?)", spec)
    return m.group(1) if m else None

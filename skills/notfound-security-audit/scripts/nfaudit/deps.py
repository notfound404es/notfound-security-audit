"""Dependency inventory from lockfiles and manifests (read-only parsing, no package manager calls)."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .util import exact_version, iter_files, read_text, rel

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10 fallback
    tomllib = None


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # OSV ecosystem name
    name: str
    version: str
    file: str
    direct: bool = True


def _npm_lock(text: str, f: str) -> list[Dep]:
    data = json.loads(text)
    out = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        root = pkgs.get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            if meta.get("version"):
                out.append(Dep("npm", name, meta["version"], f, name in direct and key.count("node_modules/") == 1))
    else:  # lockfile v1
        def walk(deps: dict, top: bool):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    out.append(Dep("npm", name, meta["version"], f, top))
                    walk(meta.get("dependencies"), False)
        walk(data.get("dependencies"), True)
    return out


def _yarn_lock(text: str, f: str) -> list[Dep]:
    out = []
    current: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
                if name:
                    current.append(name)
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and current:
                for name in set(current):
                    out.append(Dep("npm", name, m.group(1), f, False))
                current = []
    return out


def _pnpm_lock(text: str, f: str) -> list[Dep]:
    out = set()
    for m in re.finditer(r"(?m)^\s{2}['\"]?/?((?:@[^/@\s]+/)?[^@/\s'\"(]+)@(\d+\.\d+\.\d+[^:'\"(\s]*)", text):
        out.add(Dep("npm", m.group(1), m.group(2), f, False))
    return sorted(out, key=lambda d: (d.name, d.version))


def _composer_lock(text: str, f: str) -> list[Dep]:
    data = json.loads(text)
    out = []
    for key in ("packages", "packages-dev"):
        for p in data.get(key) or []:
            v = str(p.get("version", "")).lstrip("v")
            if p.get("name") and re.match(r"\d", v):
                out.append(Dep("Packagist", p["name"], v, f, True))
    return out


def _requirements(text: str, f: str) -> list[Dep]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;,]*)", line)
        if m:
            out.append(Dep("PyPI", m.group(1).lower(), m.group(2), f, True))
    return out


def _toml_packages(text: str, f: str, eco: str) -> list[Dep]:
    out = []
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
            for p in data.get("package", []):
                if p.get("name") and p.get("version"):
                    out.append(Dep(eco, p["name"].lower() if eco == "PyPI" else p["name"], str(p["version"]), f, False))
            return out
        except Exception:
            pass
    for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        out.append(Dep(eco, m.group(1), m.group(2), f, False))
    return out


def _pipfile_lock(text: str, f: str) -> list[Dep]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = exact_version(str(meta.get("version", "")))
            if v:
                out.append(Dep("PyPI", name.lower(), v, f, section == "default"))
    return out


def _go_mod(text: str, f: str) -> list[Dep]:
    out = []
    for m in re.finditer(r"(?m)^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]{2,}[^\s]*)\s+v(\d+\.\d+\.\d+[^\s]*)", text):
        out.append(Dep("Go", m.group(1), m.group(2).split("+")[0], f, "// indirect" not in text[m.end():m.end() + 20]))
    return out


def _gemfile_lock(text: str, f: str) -> list[Dep]:
    out = []
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)\s-]*)", line)
            if m:
                out.append(Dep("RubyGems", m.group(1), m.group(2), f, False))
            elif line and not line.startswith(" "):
                in_specs = False
    return out


def _pom(text: str, f: str) -> list[Dep]:
    out = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    props = {}
    pe = root.find(q("properties"), ns)
    if pe is not None:
        for child in pe:
            props[child.tag.split("}")[-1]] = (child.text or "").strip()
    for dep in root.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
        g, a, v = (dep.findtext(q(x), default="", namespaces=ns).strip() for x in ("groupId", "artifactId", "version"))
        m = re.fullmatch(r"\$\{([^}]+)\}", v)
        if m:
            v = props.get(m.group(1), "")
        if g and a and re.match(r"\d", v):
            out.append(Dep("Maven", f"{g}:{a}", v, f, True))
    return out


def _gradle(text: str, f: str) -> list[Dep]:
    out = []
    for m in re.finditer(r"['\"]([\w.\-]+):([\w.\-]+):(\d[\w.\-]*)['\"]", text):
        out.append(Dep("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), f, True))
    return out


def _package_json(text: str, f: str) -> tuple[list[Dep], list[str]]:
    """Only exact pins are usable without a lockfile; ranges are reported as unresolved."""
    data = json.loads(text)
    out, unresolved = [], []
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            v = exact_version(str(spec))
            if v:
                out.append(Dep("npm", name, v, f, True))
            else:
                unresolved.append(name)
    return out, unresolved


PARSERS = {
    "package-lock.json": _npm_lock, "npm-shrinkwrap.json": _npm_lock, "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock, "composer.lock": _composer_lock, "Pipfile.lock": _pipfile_lock,
    "go.mod": _go_mod, "Gemfile.lock": _gemfile_lock, "pom.xml": _pom, "build.gradle": _gradle,
    "build.gradle.kts": _gradle,
}


def collect(root: Path, excludes: list) -> dict:
    deps: list[Dep] = []
    lockfiles: list[str] = []
    errors: list[str] = []
    manifests_without_lock: list[dict] = []
    files = list(iter_files(root, excludes))
    names_by_dir: dict[Path, set] = {}
    for p in files:
        names_by_dir.setdefault(p.parent, set()).add(p.name)
    for path in files:
        name = path.name
        f = rel(path, root)
        text = None
        try:
            if name in PARSERS:
                text = read_text(path)
                if text is None:
                    continue
                deps += PARSERS[name](text, f)
                lockfiles.append(f)
            elif name == "requirements.txt" or re.fullmatch(r"requirements[-_.\w]*\.txt", name):
                deps += _requirements(read_text(path) or "", f)
                lockfiles.append(f)
            elif name in ("poetry.lock", "uv.lock"):
                deps += _toml_packages(read_text(path) or "", f, "PyPI")
                lockfiles.append(f)
            elif name == "Cargo.lock":
                deps += _toml_packages(read_text(path) or "", f, "crates.io")
                lockfiles.append(f)
            elif name == "package.json":
                siblings = names_by_dir.get(path.parent, set())
                if not siblings & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock"}:
                    pinned, unresolved = _package_json(read_text(path) or "{}", f)
                    deps += pinned
                    if unresolved:
                        manifests_without_lock.append({"file": f, "unresolved": unresolved})
            elif name == "composer.json" and "composer.lock" not in names_by_dir.get(path.parent, set()):
                manifests_without_lock.append({"file": f, "unresolved": ["(composer.lock missing)"]})
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"{f}: {exc}")
    unique = sorted(set(deps), key=lambda d: (d.ecosystem, d.name, d.version, d.file))
    return {"deps": unique, "lockfiles": sorted(set(lockfiles)), "errors": errors,
            "manifests_without_lock": manifests_without_lock}

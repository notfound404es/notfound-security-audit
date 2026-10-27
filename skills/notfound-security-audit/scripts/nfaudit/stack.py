"""Technology stack detection from manifests and marker files."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .util import iter_files, lang_of, read_text, rel

NPM_FRAMEWORKS = {
    "next": "Next.js", "react": "React", "vue": "Vue", "nuxt": "Nuxt", "svelte": "Svelte",
    "@sveltejs/kit": "SvelteKit", "@angular/core": "Angular", "express": "Express", "fastify": "Fastify",
    "@nestjs/core": "NestJS", "koa": "Koa", "hono": "Hono", "astro": "Astro", "@remix-run/node": "Remix",
    "react-router": "React Router", "vite": "Vite", "electron": "Electron", "prisma": "Prisma",
    "@prisma/client": "Prisma", "mongoose": "Mongoose", "@supabase/supabase-js": "Supabase",
    "firebase": "Firebase", "firebase-admin": "Firebase Admin", "stripe": "Stripe", "next-auth": "NextAuth",
    "@auth/core": "Auth.js", "@clerk/nextjs": "Clerk", "drizzle-orm": "Drizzle", "sequelize": "Sequelize",
    "typeorm": "TypeORM", "helmet": "helmet", "openai": "OpenAI SDK", "@anthropic-ai/sdk": "Anthropic SDK",
}
COMPOSER_FRAMEWORKS = {
    "laravel/framework": "Laravel", "symfony/framework-bundle": "Symfony", "slim/slim": "Slim",
    "cakephp/cakephp": "CakePHP", "codeigniter4/framework": "CodeIgniter", "livewire/livewire": "Livewire",
    "filament/filament": "Filament", "laravel/sanctum": "Sanctum", "laravel/passport": "Passport",
}
PY_FRAMEWORKS = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "starlette": "Starlette",
    "sqlalchemy": "SQLAlchemy", "celery": "Celery", "streamlit": "Streamlit", "gradio": "Gradio",
    "pyramid": "Pyramid", "tornado": "Tornado", "aiohttp": "aiohttp", "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK", "langchain": "LangChain",
}


def _deps_from_package_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        if isinstance(data.get(key), dict):
            out.update(data[key])
    return out


def detect(root: Path, excludes: list) -> dict:
    languages: dict[str, int] = {}
    frameworks: set[str] = set()
    manifests: list[str] = []
    platforms: set[str] = set()
    for path in iter_files(root, excludes):
        name = path.name
        r = rel(path, root)
        lang = lang_of(path)
        if lang:
            key = {"blade": "php", "pytpl": "html"}.get(lang, lang)
            languages[key] = languages.get(key, 0) + 1
        if name in ("tsconfig.json",):
            languages["ts"] = languages.get("ts", 0) + 1
        if name == "package.json":
            manifests.append(r)
            text = read_text(path) or ""
            for dep in _deps_from_package_json(text):
                if dep in NPM_FRAMEWORKS:
                    frameworks.add(NPM_FRAMEWORKS[dep])
                if dep == "typescript":
                    languages.setdefault("ts", 1)
        elif name == "composer.json":
            manifests.append(r)
            try:
                data = json.loads(read_text(path) or "{}")
            except ValueError:
                data = {}
            for dep in {**data.get("require", {}), **data.get("require-dev", {})}:
                if dep in COMPOSER_FRAMEWORKS:
                    frameworks.add(COMPOSER_FRAMEWORKS[dep])
        elif name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"):
            manifests.append(r)
            low = (read_text(path) or "").lower()
            for dep, fw in PY_FRAMEWORKS.items():
                if re.search(rf"(?m)^\s*['\"]?{re.escape(dep)}\b|['\"]{re.escape(dep)}[\[<>=!~ '\"]", low):
                    frameworks.add(fw)
        elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            manifests.append(r)
            low = (read_text(path) or "").lower()
            if "spring-boot" in low or "org.springframework" in low:
                frameworks.add("Spring")
            languages.setdefault("java", 1)
        elif name in ("go.mod", "Gemfile", "Cargo.toml"):
            manifests.append(r)
            low = (read_text(path) or "").lower()
            if name == "Gemfile" and "rails" in low:
                frameworks.add("Rails")
            if name == "go.mod":
                languages.setdefault("go", 1)
            if name == "Cargo.toml":
                languages.setdefault("rust", 1)
        elif name == "artisan":
            frameworks.add("Laravel")
        elif name == "wp-config.php" or name == "wp-config-sample.php":
            frameworks.add("WordPress")
        elif name == "manage.py":
            frameworks.add("Django")
        elif name.endswith(".csproj"):
            manifests.append(r)
            languages.setdefault("csharp", 1)
            frameworks.add(".NET")
        if name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            platforms.add("Docker")
        elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            platforms.add("Docker Compose")
        elif name == "vercel.json":
            platforms.add("Vercel")
        elif name == "netlify.toml":
            platforms.add("Netlify")
        elif name in ("firebase.json", "firestore.rules", "database.rules.json", "storage.rules"):
            platforms.add("Firebase")
        elif name == "wrangler.toml" or name == "wrangler.jsonc" or name == "wrangler.json":
            platforms.add("Cloudflare Workers")
        elif name.endswith(".tf"):
            platforms.add("Terraform")
        if "/.github/workflows/" in f"/{r}" and name.endswith((".yml", ".yaml")):
            platforms.add("GitHub Actions")
        if r.startswith("supabase/") or "/supabase/migrations/" in f"/{r}":
            platforms.add("Supabase")
    langs = sorted(languages.items(), key=lambda kv: -kv[1])
    return {
        "languages": [k for k, _ in langs],
        "file_counts": dict(langs),
        "frameworks": sorted(frameworks),
        "platforms": sorted(platforms),
        "manifests": sorted(manifests),
    }

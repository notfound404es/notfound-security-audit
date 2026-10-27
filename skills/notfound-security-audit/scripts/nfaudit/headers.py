"""Opt-in check of one live URL: a single GET request, no crawling, no payloads.

Only run it against a site the user owns or is authorised to test.
"""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request

from .advisories import check_runtimes
from .util import Finding

UA = "notfound-security-audit headers check (+https://github.com/notfound404es/notfound-security-audit)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # report the first response as-is
        return None


def fetch(url: str, timeout: float = 15.0) -> tuple[int, list[tuple[str, str]], str]:
    if not re.match(r"https?://", url):
        raise ValueError("URL must start with http:// or https://")
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        resp = opener.open(req, timeout=timeout)  # noqa: S310 - URL provided explicitly by the user
        return resp.status, list(resp.headers.items()), resp.geturl()
    except urllib.error.HTTPError as err:  # 3xx/4xx/5xx still carry headers
        return err.code, list(err.headers.items()), url


def _f(rule_id, title, severity, status, description, recommendation, evidence="", url="", cwe="CWE-693", owasp="A02:2025", refs=None):
    return Finding(rule_id=rule_id, title=title, severity=severity, status=status, category="headers",
                   description=description, recommendation=recommendation, file=url, evidence=evidence,
                   cwe=cwe, owasp=owasp, references=refs or [], source="live-headers")


def analyse(url: str, status: int, headers: list[tuple[str, str]]) -> list[Finding]:
    h = {}
    cookies = []
    for k, v in headers:
        if k.lower() == "set-cookie":
            cookies.append(v)
        h[k.lower()] = v
    out = []
    https = url.lower().startswith("https://")
    mdn = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
    if https and "strict-transport-security" not in h:
        out.append(_f("hdr-missing-hsts", "Missing Strict-Transport-Security", "low", "preventive",
                      "Without HSTS, a first visit over plain HTTP can be downgraded or intercepted.",
                      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", url=url, refs=[mdn + "Strict-Transport-Security"]))
    if "content-security-policy" not in h:
        out.append(_f("hdr-missing-csp", "Missing Content-Security-Policy", "low", "preventive",
                      "A CSP limits what an injected script can do. It is a second line of defence against XSS, not a fix for it.",
                      "Start with a report-only policy and tighten it.", url=url, refs=[mdn + "Content-Security-Policy"]))
    elif re.search(r"script-src[^;]*'unsafe-inline'", h["content-security-policy"]) and "nonce-" not in h["content-security-policy"]:
        out.append(_f("hdr-csp-unsafe-inline", "CSP allows 'unsafe-inline' scripts", "info", "preventive",
                      "'unsafe-inline' removes most of the XSS protection a CSP provides.", "Use nonces or hashes.",
                      evidence=h["content-security-policy"][:200], url=url))
    if "x-content-type-options" not in h:
        out.append(_f("hdr-missing-nosniff", "Missing X-Content-Type-Options: nosniff", "info", "preventive",
                      "Browsers may guess content types and execute uploaded files as scripts.", "Send X-Content-Type-Options: nosniff.", url=url))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(_f("hdr-missing-frame-protection", "No clickjacking protection", "low", "preventive",
                      "The page can be framed by other sites.", "Send CSP frame-ancestors 'self' (or X-Frame-Options: DENY).", url=url, cwe="CWE-1021"))
    if "referrer-policy" not in h:
        out.append(_f("hdr-missing-referrer-policy", "Missing Referrer-Policy", "info", "preventive",
                      "Full URLs (which may contain tokens) can leak to third parties.", "Send Referrer-Policy: strict-origin-when-cross-origin.", url=url))
    acao = h.get("access-control-allow-origin", "")
    if acao == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        out.append(_f("hdr-cors-wildcard-credentials", "CORS wildcard with credentials", "medium", "confirmed",
                      "The response combines Access-Control-Allow-Origin: * with credentials.", "Return explicit trusted origins only.",
                      evidence=f"ACAO: {acao}", url=url, cwe="CWE-942", owasp="A01:2025"))
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [flag for flag, ok in (("Secure", "secure" in low or not https), ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
        if missing and re.search(r"sess|auth|token|sid|jwt", name, re.I):
            out.append(_f("hdr-cookie-flags", f"Session-like cookie '{name}' without {', '.join(missing)}", "medium", "confirmed",
                          "Session cookies without these flags are easier to steal (XSS, plain HTTP) or to use in CSRF.",
                          "Set Secure, HttpOnly and SameSite=Lax (or Strict).", evidence=f"{name}=…; " + "; ".join(p.strip() for p in c.split(";")[1:])[:160],
                          url=url, cwe="CWE-614", owasp="A07:2025"))
    for hdr in ("x-powered-by", "server"):
        val = h.get(hdr, "")
        m = re.search(r"(PHP|Express|Next\.js|nginx|Apache)[/ ]?(\d+[\d.]*)?", val, re.I)
        if m and m.group(2):
            out.append(_f("hdr-version-disclosure", f"{hdr} discloses a version ({val[:60]})", "info", "preventive",
                          "Version banners make it trivial to find unpatched servers.", "Remove the version from the header (expose_php=Off, server_tokens off).",
                          evidence=f"{hdr}: {val[:120]}", url=url, cwe="CWE-200"))
        pm = re.search(r"PHP/(\d+\.\d+\.\d+)", val)
        if pm:
            for f in check_runtimes([{"runtime": "php", "version": pm.group(1), "exact": True, "file": url, "line": 0}]):
                f.status = "suspected"
                f.description = ("The live server announces this PHP version. Banners can be stale or rewritten by a proxy, "
                                 "so confirm with php -v on the server. " + f.description)
                f.source = "live-headers"
                out.append(f)
    return out


def check(url: str, timeout: float = 15.0) -> tuple[list[Finding], dict]:
    status, headers, final = fetch(url, timeout)
    meta = {"url": url, "status": status, "headers": {k: ("<redacted>" if k.lower() == "set-cookie" else v) for k, v in headers}}
    return analyse(url, status, headers), meta

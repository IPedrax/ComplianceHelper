#!/usr/bin/env python3
# compliance-ignore-file: probes and tracker lists quote the patterns they look for.
"""Check a running app for the compliance gaps only visible from outside. Stdlib only.

  app_scan.py URL               headers, cookies, trackers, consent, exposed files
  app_scan.py URL --json        machine-readable result
  app_scan.py URL --out DIR     also write DIR/app-report.md and DIR/app-findings.json

Point it only at an app you own or are building. It sends one GET for the page and a
handful of GETs for well-known sensitive paths (/.env, /.git/config...), the same
probes every scanner on the internet already sends. A client-rendered app only shows
its shell here, so trackers injected by JavaScript and accessibility need the browser
checks in the skill.
"""
import argparse
import concurrent.futures
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan  # noqa: E402

UA = "compliance-app-scan/1.0 (self-audit)"
LOCAL = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|[\w.-]+\.(?:localhost|local|test))$", re.I)
TRACKERS = {  # host suffix: (label, is_ad)
    "google-analytics.com": ("Google Analytics", False), "googletagmanager.com": ("Google Tag Manager", False),
    "doubleclick.net": ("Google Ads", True), "googleadservices.com": ("Google Ads", True),
    "googlesyndication.com": ("Google AdSense", True), "connect.facebook.net": ("Meta Pixel", True),
    "analytics.tiktok.com": ("TikTok Pixel", True), "snap.licdn.com": ("LinkedIn Insight", True),
    "static.ads-twitter.com": ("X Pixel", True), "bat.bing.com": ("Microsoft Ads", True), "hotjar.com": ("Hotjar", False),
    "clarity.ms": ("Microsoft Clarity", False), "cdn.segment.com": ("Segment", False), "cdn.mxpnl.com": ("Mixpanel", False),
    "cdn.amplitude.com": ("Amplitude", False), "posthog.com": ("PostHog", False), "js.hs-scripts.com": ("HubSpot", False),
    "js.hs-analytics.net": ("HubSpot", False), "s.pinimg.com": ("Pinterest Tag", True), "sc-static.net": ("Snap Pixel", True),
    "redditstatic.com": ("Reddit Pixel", True), "fullstory.com": ("FullStory", False), "cdn.logrocket.io": ("LogRocket", False),
    "heapanalytics.com": ("Heap", False), "criteo.com": ("Criteo", True), "criteo.net": ("Criteo", True),
    "taboola.com": ("Taboola", True), "outbrain.com": ("Outbrain", True), "adroll.com": ("AdRoll", True),
}
INLINE_TRACKERS = ((r"\bgtag\(\s*['\"]config", "Google tag", False), (r"\bfbq\(\s*['\"]init", "Meta Pixel", True),
                   (r"\bttq\.load\(", "TikTok Pixel", True), (r"_linkedin_partner_id", "LinkedIn Insight", True),
                   (r"\bclarity\(\s*['\"]", "Microsoft Clarity", False), (r"\bhj\(\s*['\"]", "Hotjar", False))
CMP = re.compile(r"cookieconsent|cookie-consent|klaro|osano|onetrust|otSDKStub|optanon|cookiebot|usercentrics|didomi|"
                 r"iubenda|termly|cookieyes|quantcast|tarteaucitron|complianz|__tcfapi|consentmanager|cookie[-_]?banner|"
                 r"gtag\(\s*['\"]consent['\"]\s*,\s*['\"]default", re.I)
TRACKING_COOKIE = re.compile(r"^(?:_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|ajs_|mp_|amplitude|_clck|_clsk|MUID|_uet|_ttp|_pin_|"
                             r"li_|bcookie|IDE$|NID$|_scid|_rdt_)", re.I)
SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login", re.I)
ENV_SIG = r"(?m)^[A-Z_][A-Z0-9_]*\s*=\s*\S"
PROBES = (  # path, signature, severity, what it is
    ("/.env", ENV_SIG, "critical", "environment file"), ("/.env.local", ENV_SIG, "critical", "environment file"),
    ("/.env.production", ENV_SIG, "critical", "environment file"), ("/.git/config", r"\[core\]", "critical", "git config"),
    ("/.git/HEAD", r"^ref: refs/", "critical", "git repository"), ("/.aws/credentials", r"aws_secret_access_key", "critical",
                                                                    "AWS credentials"),
    ("/.vscode/sftp.json", r'"(?:password|privateKeyPath|host)"', "critical", "SFTP deploy config"),
    ("/id_rsa", r"PRIVATE KEY", "critical", "private SSH key"), ("/server.key", r"PRIVATE KEY", "critical", "TLS private key"),
    ("/backup.sql", r"CREATE TABLE|INSERT INTO", "critical", "database dump"),
    ("/dump.sql", r"CREATE TABLE|INSERT INTO", "critical", "database dump"),
    ("/.compliance/report.md", r"# Compliance report", "high", "this compliance report"),
    ("/.compliance/findings.json", r'"findings"', "high", "compliance findings"),
    ("/.npmrc", r"_auth|//registry", "high", "npm config (can hold a token)"),
    ("/docker-compose.yml", r"(?m)^\s*services\s*:", "medium", "docker-compose file"),
    ("/Dockerfile", r"(?m)^FROM\s", "medium", "Dockerfile"), ("/deploy.sh", r"\bssh\b|\bscp\b|\brsync\b", "medium", "deploy script"),
    ("/deploy.ps1", r"\bssh\b|\bscp\b|Invoke-", "medium", "deploy script"), ("/phpinfo.php", r"PHP Version", "medium", "phpinfo page"),
    ("/.DS_Store", r"Bud1", "low", "macOS folder index (lists your files)"),
    ("/package.json", r'"dependencies"\s*:', "low", "package.json (dependency versions)"),
)
FIX = {
    "APP-TLS": "Fix the certificate (expired, self-signed or wrong host) before anything else: browsers and API clients will refuse it or train users to click through.",
    "APP-HTTP": "Serve the app over HTTPS only, and redirect every http:// request to https:// with a 301.",
    "APP-HEADERS": "Send the missing headers from the server or proxy (HSTS, CSP, nosniff, frame-ancestors or X-Frame-Options, Referrer-Policy).",
    "APP-VERSION": "Hide version numbers (server_tokens off, remove X-Powered-By). They tell attackers which exploits to try.",
    "APP-COOKIE-TRACKING": "Set analytics and ad cookies only after opt-in consent. Setting them on first load, before any choice, is what the CNIL fined Amazon 35M euros for in 2020.",
    "APP-COOKIE-FLAGS": "Mark session cookies Secure and HttpOnly (and SameSite) so scripts can't read them and they never travel over HTTP.",
    "APP-TRACKERS": "Load these tags only after opt-in consent (EU, UK, Brazil), or block them with a consent manager until the user accepts.",
    "APP-OPTOUT": 'Link "Do Not Sell or Share My Personal Information" and honor Global Privacy Control by switching ad tags off.',
    "APP-PRIVACY": "Link the privacy policy from every page (the footer is fine) and from every form that collects data.",
    "APP-LANG": 'Declare the page language, e.g. <html lang="en">, so screen readers use the right pronunciation.',
    "APP-ALT": 'Give every image alt text, or alt="" when it is decorative.',
    "APP-ZOOM": "Remove user-scalable=no and maximum-scale=1 from the viewport. People with low vision need to zoom.",
    "APP-MIXED": "Load every script, style and image over https://. Mixed content can be tampered with in transit.",
    "APP-FORM-HTTP": "Post forms to an https:// endpoint. Anything typed into this form crosses the network in cleartext.",
    "APP-EXPOSED": "Remove the file from what the server serves (.dockerignore, web root, nginx deny rule), redeploy, confirm a 404, and rotate any secret it contained.",
    "APP-SECTXT": "Publish /.well-known/security.txt (RFC 9116) with a contact so researchers can report vulnerabilities.",
}
MAPS = {
    "APP-TLS": ["SOC2|SOC 2 CC6.7", "PCI|PCI DSS 4.2.1", "GDPR|GDPR Art. 32"],
    "APP-HTTP": ["SOC2|SOC 2 CC6.7", "PCI|PCI DSS 4.2.1", "OWASP|OWASP A02:2021", "GDPR|GDPR Art. 32"],
    "APP-HEADERS": ["OWASP|OWASP A05:2021", "SOC2|SOC 2 CC6.6", "ISO27001|ISO 27001 A.8.9"],
    "APP-VERSION": ["OWASP|OWASP A05:2021"],
    "APP-COOKIE-TRACKING": ["EPRIVACY|ePrivacy Art. 5(3)", "GDPR|GDPR Art. 7", "LGPD|LGPD Art. 8"],
    "APP-COOKIE-FLAGS": ["OWASP|OWASP A07:2021", "GDPR|GDPR Art. 32"],
    "APP-TRACKERS": ["EPRIVACY|ePrivacy Art. 5(3)", "GDPR|GDPR Art. 6", "LGPD|LGPD Art. 8"],
    "APP-OPTOUT": ["CCPA|CCPA 1798.135", "CCPA|CCPA regs 7025 (opt-out signals)"],
    "APP-PRIVACY": ["GDPR|GDPR Art. 13", "CCPA|CCPA 1798.100", "LGPD|LGPD Art. 9"],
    "APP-LANG": ["A11Y|WCAG 3.1.1"], "APP-ALT": ["A11Y|WCAG 1.1.1"], "APP-ZOOM": ["A11Y|WCAG 1.4.4"],
    "APP-MIXED": ["OWASP|OWASP A02:2021", "SOC2|SOC 2 CC6.7"], "APP-FORM-HTTP": ["GDPR|GDPR Art. 32", "PCI|PCI DSS 4.2.1"],
    "APP-EXPOSED": ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.8.12", "OWASP|OWASP A05:2021", "GDPR|GDPR Art. 32"],
    "APP-SECTXT": ["CRA|EU CRA Annex I(II)", "ISO27001|ISO 27001 A.8.8"],
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, jar=None, follow=True, ctx=None, limit=2000000):
    """(status, final_url, headers, body_bytes). HTTP errors are results, not exceptions."""
    handlers = [urllib.request.HTTPSHandler(context=ctx)] if ctx else []
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    if not follow:
        handlers.append(_NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*"})
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=10) as resp:
            return resp.status, resp.geturl(), resp.headers, resp.read(limit)
    except urllib.error.HTTPError as e:
        with e:
            return e.code, url, e.headers, (e.read(limit) if e.fp else b"")


def scan_app(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    url = parsed.geturl()
    host = parsed.hostname or ""
    local = bool(LOCAL.match(host))
    ctx = ssl._create_unverified_context() if local else None
    out, notes = [], []

    def add(rule, sev, title, where=url, snippet=""):
        out.append(scan.finding(rule, sev, title, where, 0, snippet, FIX[rule], MAPS[rule]))

    jar = http.cookiejar.CookieJar()
    try:
        status, final, headers, body = fetch(url, jar, ctx=ctx)
    except urllib.error.URLError as e:
        if isinstance(getattr(e, "reason", None), ssl.SSLError):
            add("APP-TLS", "critical", "TLS certificate problem: {}".format(e.reason))
            return result(url, out, ["Stopped at the TLS error."])
        raise SystemExit("could not reach {}: {}".format(url, e.reason))
    final_p = urllib.parse.urlparse(final)
    https = final_p.scheme == "https"
    if not local:
        if not https:
            add("APP-HTTP", "high", "Served over plain HTTP")
        else:
            try:
                code, _, h, _ = fetch("http://{}{}".format(final_p.netloc, final_p.path or "/"), follow=False)
                loc = (h.get("Location") or "") if h else ""
                if not (300 <= code < 400 and loc.startswith("https://")):
                    add("APP-HTTP", "high", "http:// does not redirect to https:// (got {})".format(code))
            except (urllib.error.URLError, OSError):
                pass  # port 80 closed is fine
    get = lambda k: headers.get(k, "") if headers else ""
    csp = get("Content-Security-Policy")
    missing = [label for label, ok in (
        ("HSTS", get("Strict-Transport-Security") or not https or local), ("Content-Security-Policy", csp),
        ("X-Content-Type-Options", get("X-Content-Type-Options").lower() == "nosniff"),
        ("X-Frame-Options or frame-ancestors", get("X-Frame-Options") or "frame-ancestors" in csp),
        ("Referrer-Policy", get("Referrer-Policy"))) if not ok]
    if missing:
        add("APP-HEADERS", "medium", "Missing security headers: " + ", ".join(missing))
    leak = [v for v in (get("Server"), get("X-Powered-By")) if re.search(r"\d", v)]
    if leak:
        add("APP-VERSION", "low", "Version disclosed in headers: " + ", ".join(leak))
    for ck in jar:
        attrs = {k.lower(): v for k, v in getattr(ck, "_rest", {}).items()}
        if TRACKING_COOKIE.match(ck.name):
            add("APP-COOKIE-TRACKING", "high", "Tracking cookie {} set on first load, before any consent".format(ck.name))
        elif SESSIONISH.search(ck.name):
            flags = [f for f, ok in (("Secure", ck.secure or not https), ("HttpOnly", "httponly" in attrs)) if not ok]
            if flags:
                add("APP-COOKIE-FLAGS", "medium", "Cookie {} missing {}".format(ck.name, " and ".join(flags)))
    ctype = get("Content-Type")
    html = body.decode("utf-8", "replace") if "html" in ctype.lower() or body[:200].lstrip().lower().startswith(b"<") else ""
    if html:
        page_host = final_p.hostname or host
        found, ads = [], False
        for attrs in re.findall(r"<script\b([^>]*)>", html, re.I):
            if re.search(r"""type\s*=\s*["']text/plain["']|data-(?:category|cookieconsent|consent)""", attrs, re.I):
                continue  # held back by a consent manager until the user accepts
            m = re.search(r"""\bsrc\s*=\s*["']([^"']+)""", attrs, re.I)
            src_host = urllib.parse.urlparse(urllib.parse.urljoin(final, m.group(1))).hostname if m else ""
            for suffix, (label, ad) in TRACKERS.items():
                if src_host and src_host != page_host and (src_host == suffix or src_host.endswith("." + suffix)):
                    found.append(label)
                    ads |= ad
        for rx, label, ad in INLINE_TRACKERS:
            if re.search(rx, html):
                found.append(label)
                ads |= ad
        found = sorted(set(found))
        if found and not CMP.search(html):
            add("APP-TRACKERS", "high", "Trackers load with no consent manager on the page: " + ", ".join(found))
        if ads and not re.search(r"do[-_ ]?not[-_ ]?sell|globalPrivacyControl", html, re.I):
            add("APP-OPTOUT", "medium", "Ad tags without a Do Not Sell or Share link")
        text = re.sub(r"(?s)<(script|style)\b.*?</\1>|<[^>]+>", " ", html)
        shell = len(" ".join(text.split())) < 200 and re.search(r"""id\s*=\s*["'](?:root|app|__next|svelte)["']""", html)
        if shell:
            notes.append("Client-rendered app: only the HTML shell was checked. Run the browser checks for trackers "
                         "injected by JavaScript, cookies set after load, links and accessibility.")
        elif not re.search(r"""<a\b[^>]*href\s*=\s*["'][^"']*(?:privacy|privacidade|datenschutz|privacidad)|privacy policy|"""
                           r"""pol[ií]tica de privacidade""", html, re.I):
            add("APP-PRIVACY", "medium", "No privacy policy link on the page")
        m = re.search(r"<html\b[^>]*>", html, re.I)
        if m and not re.search(r"\blang\s*=", m.group(0), re.I):
            add("APP-LANG", "medium", "Page has no language declared")
        no_alt = [t for t in re.findall(r"<img\b[^>]*>", html, re.I) if not re.search(r"\balt\s*=", t, re.I)]
        if no_alt:
            add("APP-ALT", "medium", "{} image(s) without alt text".format(len(no_alt)))
        if re.search(r"""user-scalable\s*=\s*["']?(?:no|0)\b|maximum-scale\s*=\s*["']?1(?:\.0+)?(?![\d.])""", html, re.I):
            add("APP-ZOOM", "medium", "Zoom disabled in the viewport")
        if https:
            mixed = re.findall(r"""<(?:script|link|img|iframe|source|video|audio)\b[^>]*\b(?:src|href)\s*=\s*["'](http://[^"']+)""", html, re.I)
            if mixed:
                add("APP-MIXED", "medium", "{} resource(s) loaded over http:// on an https page".format(len(mixed)), snippet=mixed[0][:120])
        if re.search(r"""<form\b[^>]*\baction\s*=\s*["']http://""", html, re.I):
            add("APP-FORM-HTTP", "high", "A form posts to an http:// endpoint")
    bases = {"{}://{}".format(final_p.scheme, final_p.netloc)}
    path = final_p.path.rsplit("/", 1)[0] if not final_p.path.endswith("/") else final_p.path.rstrip("/")
    if path:
        bases.add("{}://{}{}".format(final_p.scheme, final_p.netloc, path))

    def probe(item):
        base, (p, sig, sev, what) = item
        try:
            code, _, _, data = fetch(base + p, follow=False, ctx=ctx, limit=65536)
        except (urllib.error.URLError, OSError):
            return None
        if code == 200 and re.search(sig, data.decode("latin-1")):
            return base + p, sev, what
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for hit in pool.map(probe, [(b, pr) for b in sorted(bases) for pr in PROBES]):
            if hit:
                add("APP-EXPOSED", hit[1], "Publicly downloadable: {}".format(hit[2]), hit[0])
    try:
        code, _, _, data = fetch("{}://{}/.well-known/security.txt".format(final_p.scheme, final_p.netloc), follow=False, ctx=ctx,
                                 limit=65536)
        if not (code == 200 and b"contact:" in data.lower()) and not local:
            add("APP-SECTXT", "info", "No /.well-known/security.txt")
    except (urllib.error.URLError, OSError):
        pass
    if local:
        notes.append("Local URL: HTTPS, HSTS and redirect checks skipped; repeat against the deployed URL before launch.")
    return result(url, out, notes)


def result(url, findings, notes):
    findings.sort(key=lambda f: scan.RANK[f["severity"]])
    for f in findings:
        f["status"], f["new"] = "open", False
    return {"url": url, "findings": findings, "notes": notes}


def render(r):
    lines = ["# App compliance check: " + r["url"], "",
             "> Outside-in checks of the running app. Pair it with the code scan (report.md); neither is certification.", ""]
    lines += ["- " + n for n in r["notes"]] + ([""] if r["notes"] else [])
    if not r["findings"]:
        lines.append("No findings from the outside-in checks.")
    for f in r["findings"]:
        lines += ["- **{}** [{}] {}{}".format(f["rule"], f["severity"], f["title"],
                                             "" if f["path"] == r["url"] else " (`{}`)".format(f["path"])),
                  "  - Fix: " + f["fix"], "  - Breaks: " + scan.display_maps(f["maps"])]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Outside-in compliance checks of a running app.")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write app-report.md and app-findings.json here")
    a = ap.parse_args(argv)
    r = scan_app(a.url)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        scan.save_json(os.path.join(a.out, "app-findings.json"), r)
        with open(os.path.join(a.out, "app-report.md"), "w", encoding="utf-8") as fh:
            fh.write(render(r))
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print("App check: {}  ({})".format(r["url"], scan.fmt_counts(scan.counts(r["findings"]))))
        for f in r["findings"]:
            print("  {:8} {:20} {}".format(f["severity"].upper(), f["rule"], f["title"]))
        for n in r["notes"]:
            print("  note: " + n)
    return 1 if any(f["severity"] in ("critical", "high") for f in r["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())

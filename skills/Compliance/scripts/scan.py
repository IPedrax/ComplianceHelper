#!/usr/bin/env python3
# compliance-ignore-file: this is the rule set, so it quotes every pattern it hunts for.
"""Scan a codebase for compliance gaps and map each one to the frameworks it breaks.

Stdlib only, offline, deterministic. Python 3.8+.

  scan.py [ROOT]                scan ROOT (default: cwd), report in ROOT/.compliance/
  scan.py ROOT --out DIR        write the report to DIR and leave ROOT untouched
  scan.py ROOT --json           print the result as JSON instead of the summary
  scan.py ROOT --fail-on high   exit 1 if an open finding is at or above that severity
  scan.py --rules               list every rule and the controls it maps to

A readiness check, not a certification. It finds technical gaps (secrets, injection,
trackers without consent, no account deletion, copyleft dependencies, inaccessible
markup...) and names the frameworks each one breaks. Policies, contracts and audits
live outside the code, so the report lists them as "still needs you" instead of
pretending to check them.

Optional project config in ROOT/.compliance/ (commit these two):
  profile.json  {"markets": ["EU", "US", "BR"], "children": false, "sectors": ["health"],
                 "sells_to": ["government"], "distributed": true, "ignore_features": [],
                 "hooks": true}
  waivers.json  [{"rule": "SEC-XFF", "path": "src/legacy/*", "reason": "...", "until": "2026-12-31"}]
Inline: `compliance-ignore: RULE-ID reason` on a line, or the line above, suppresses it.
"""
import argparse
import base64
import bisect
import datetime as dt
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys

VERSION = "1.1.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATE_DIR = ".compliance"
MAX_FILES = 5000
MAX_BYTES = 512 * 1024
LOCK_BYTES = 32 * 1024 * 1024
BASELINE_MARKETS = {"EU", "UK", "US", "BR"}

JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
PY = {".py"}
CODE = JS | PY | {".rb", ".go", ".java", ".kt", ".kts", ".swift", ".php", ".cs", ".rs", ".scala", ".dart", ".ex", ".exs"}
MARKUP = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".ejs", ".hbs", ".njk", ".erb", ".php",
          ".twig", ".liquid", ".cshtml", ".razor", ".jinja", ".j2"}
STYLE = {".css", ".scss", ".sass", ".less"}
CONFIG = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".tf", ".hcl", ".env",
          ".plist"}
SHELL = {".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"}
DOCKER = {"dockerfile"}
CODE_CFG = CODE | CONFIG | SHELL | DOCKER
SCANNABLE = CODE | MARKUP | STYLE | CONFIG | SHELL | DOCKER
NO_ENV = (CODE_CFG | MARKUP) - {".env"}

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
             ".output", ".vercel", ".netlify", ".turbo", ".cache", ".parcel-cache", "coverage", "vendor", "venv",
             ".venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "target", "Pods",
             ".gradle", ".idea", ".vscode", "storybook-static", ".expo", ".angular", "bower_components",
             ".terraform", ".serverless", ".docusaurus", "site-packages", STATE_DIR}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock", "cargo.lock",
              "go.sum", "composer.lock", "gemfile.lock", "bun.lockb", "bun.lock", "uv.lock", "pubspec.lock",
              "packages.lock.json", "npm-shrinkwrap.json"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|specs?|fixtures?|mocks?|__mocks__|examples?|samples?|e2e|cypress|"
                       r"playwright|testdata|test-data|stories)(/|$)|[._](test|spec|stories)\.[a-z]+$|(^|/)test_[^/]+\.py$|"
                       r"_test\.(py|go)$", re.I)
ENV_TEMPLATE = re.compile(r"example|sample|template|dist|default|schema|\.tpl", re.I)
COPY_ROOT = re.compile(r"(?im)^[ \t]*(?:COPY|ADD)[ \t]+(?:--\S+[ \t]+)*\.[ \t]+(\S+)")
WEB_DEST = re.compile(r"nginx/html|/var/www|/srv/|htdocs|public_html|caddy|apache2")


def c(pattern, flags=0):
    return re.compile(pattern, flags)


I = re.I


def ftype(rel):
    name = rel.rsplit("/", 1)[-1].lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return ".env"
    if name.startswith(("dockerfile", "containerfile")) or name.endswith(".dockerfile"):
        return "dockerfile"
    dot = name.rfind(".")
    return name[dot:] if dot > 0 else ""


def read(path, limit=MAX_BYTES):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def walk(root):
    """Scannable files (capped), every file name, and whether the cap was hit."""
    files, names, truncated = [], [], False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        for fn in sorted(filenames):
            rel = fn if rel_dir == "." else rel_dir + "/" + fn
            names.append(rel)
            low = fn.lower()
            if low in SKIP_FILES or low.endswith((".min.js", ".min.css", ".map", ".snap", ".d.ts")):
                continue
            if ftype(rel) in SCANNABLE:
                if len(files) >= MAX_FILES:
                    truncated = True
                else:
                    files.append(rel)
    return files, names, truncated


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)


def entropy(s):
    n = len(s)
    return -sum(k / n * math.log2(k / n) for k in (s.count(ch) for ch in set(s))) if n else 0.0


# ---------------------------------------------------------------- line rules

class Rule:
    """One pattern check. `maps` entries are "FRAMEWORK_KEY|display text"."""

    def __init__(self, id, sev, title, rx, fix, maps, types=None, hint=(), unless=None, near=None,
                 unless_near=None, window=2, unless_file=None, if_file=None, check=None, tag=False, redact=False,
                 per_file=False, comments=False):
        self.id, self.sev, self.title, self.rx, self.fix, self.maps = id, sev, title, rx, fix, maps
        self.types = CODE_CFG if types is None else types
        self.hint, self.unless, self.near, self.unless_near = hint, unless, near, unless_near
        self.window, self.unless_file, self.if_file, self.check, self.tag = window, unless_file, if_file, check, tag
        self.redact, self.per_file, self.comments = redact, per_file, comments


PLACEHOLDER = c(r"example|sample|dummy|placeholder|your[_-]|changeme|change[_-]me|replace|redacted|x{5,}|\*{3,}"
                r"|\.\.\.|<[^>]*>|\$\{|0{8,}|123456|abcdef|fake", I)
ENV_REF = c(r"process\.env|os\.environ|getenv|import\.meta\.env|ENV\[|\$\{|\{\{|%\(", I)
PUBLIC_NAME = c(r"PUBLISHABLE|PUBLIC|ANON|SITE_KEY|_ID$|KEY_ID|_URL$|_PATH$|_FILE$|_HEADER$|_NAME$")
PUBLIC_CLIENT = c(r"PUBLISHABLE|ANON|SITE_KEY|MAPS|MAPBOX|FIREBASE|MEASUREMENT|POSTHOG|SENTRY|ALGOLIA_SEARCH|"
                  r"SEARCH_ONLY|RECAPTCHA|TURNSTILE|HCAPTCHA|GA_|GTM|PUBLIC_KEY|CLARITY|PLAUSIBLE|UMAMI|MIXPANEL|"
                  r"AMPLITUDE|SEGMENT|STRIPE_PK|PK_")


def _key_check(m, line, win, rel, text):
    s = m.group("s")
    if PLACEHOLDER.search(s):
        return None
    if s.startswith("sk-") and not (re.search(r"\d", s) and entropy(s) > 3.5):
        return None
    return {}


def _jwt_check(m, line, win, rel, text):
    try:
        seg = m.group("s").split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (ValueError, IndexError):
        return None
    role = str(payload.get("role", "")) if isinstance(payload, dict) else ""
    if role in ("anon", "authenticated"):
        return None
    if role == "service_role":
        return {"sev": "critical", "title": "Supabase service_role key in code (bypasses Row Level Security)",
                "fix": "Keep it server-side only and rotate it now: anyone who reads it owns the database."}
    return {}


def _generic_check(m, line, win, rel, text):
    s = m.group("s")
    if PLACEHOLDER.search(s) or ENV_REF.search(line) or " " in s:
        return None
    if s.startswith(("http://", "https://", "/", "./", "../")):
        return None
    if not (re.search(r"[A-Za-z]", s) and re.search(r"\d", s)) or entropy(s) < 3.3:
        return None
    return {}


def _fallback_check(m, line, win, rel, text):
    name = m.group("v") or m.group("w") or m.group("x") or ""
    if PUBLIC_NAME.search(name):
        return None
    default = re.search(r"""["'`]([^"'`]+)$""", m.group(0))
    if default and text.count(default.group(1)) > 1 and re.search(r"\b(?:throw|raise|process\.exit|sys\.exit)\b", text):
        return None  # fail-closed: the default is checked for and rejected elsewhere in this file
    return {}


def _client_env_check(m, line, win, rel, text):
    name = m.group("n")
    if PUBLIC_CLIENT.search(name):
        return None
    return {"sev": "critical"} if re.search(r"SECRET|SERVICE_ROLE|PRIVATE", name) else {}


def _debug_check(m, line, win, rel, text):
    base = rel.rsplit("/", 1)[-1].lower()
    if ftype(rel) == ".env":
        return {} if re.search(r"prod", base) else None
    if re.search(r"dev|local|test|example|sample", base):
        return None
    return {"sev": "medium"} if "app.run" in m.group(0) else {}


def _cookie_check(m, line, win, rel, text):
    missing = [flag for flag, pat in (("httpOnly", r"http_?only"), ("secure", r"\bsecure\b")) if not re.search(pat, win, I)]
    return {"title": "Session cookie set without " + " and ".join(missing)} if missing else None


def _xss_check(m, line, win, rel, text):
    rhs = line[m.end():] if m.group(0).rstrip().endswith("=") else ""
    if re.match(r"""\s*(?:(["'])(?:(?!\1).)*\1\s*;?\s*$|[A-Z_][A-Z0-9_]*\b|`[^`$]*`\s*;?\s*$)""", rhs):
        return None  # a literal or a constant: nothing user-controlled reaches the sink
    return {}


def _deploy_check(m, line, win, rel, text):
    return {} if re.search(r"deploy|release|publish|ship", rel, I) else None


LOG_CALL = (r"(?:console\.(?:log|info|debug|warn|error|trace)|logger\.\w+|logging\.\w+|log\.(?:info|debug|warn|error)"
            r"|print|puts|fmt\.Print\w*|System\.out\.print\w*)\s*\(")
SENSITIVE = r"(?:password|passwd|secret|token|access_?token|refresh_?token|api_?key|authorization|card_?number|cvv|cvc|ssn|cpf)"
FALLBACK_VAR = r"[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PASS|KEY|SALT|SIGNING)[A-Z0-9_]*"
MAP_SECRET = ["PCI|PCI DSS 8.6.2", "SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.5.17", "OWASP|OWASP A07:2021"]
MAP_INJECT = ["OWASP|OWASP A03:2021", "PCI|PCI DSS 6.2.4", "ISO27001|ISO 27001 A.8.28"]
MAP_TRANSIT = ["SOC2|SOC 2 CC6.7", "ISO27001|ISO 27001 A.8.24", "PCI|PCI DSS 4.2.1", "OWASP|OWASP A02:2021",
               "GDPR|GDPR Art. 32", "HEALTH|HIPAA 164.312(e)"]
MAP_CONFIG = ["OWASP|OWASP A05:2021", "SOC2|SOC 2 CC6.6", "ISO27001|ISO 27001 A.8.9"]

RULES = [
    Rule("SEC-KEY", "critical", "Hardcoded provider secret",
         c(r"(?P<s>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"
           r"(?: BLOCK)?-----|\b(?:sk|rk)_live_[0-9A-Za-z]{20,}|\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{40,}"
           r"|\bxox[abposr]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_\-]{35}|\bsk-(?:proj-|svcacct-|admin-|ant-(?:api|admin)\d\d-)?"
           r"[A-Za-z0-9_\-]{32,}|\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|\bnpm_[A-Za-z0-9]{36}|\bGOCSPX-[A-Za-z0-9_\-]{28}"
           r"|\bhf_[A-Za-z0-9]{34,}|\bglpat-[A-Za-z0-9_\-]{20,}|\bshpat_[a-fA-F0-9]{32}|\bdop_v1_[a-f0-9]{64})"),
         "Move it to an environment variable or a secret manager, then rotate it: deleting the string does not revoke "
         "the key, and it stays in git history.", MAP_SECRET, types=NO_ENV, check=_key_check, redact=True, comments=True),
    Rule("SEC-JWT", "high", "Hardcoded JWT or bearer token",
         c(r"(?P<s>\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
         "Don't ship tokens in code: load them at runtime, and rotate this one if it was ever live.",
         MAP_SECRET[1:], types=NO_ENV, hint=("eyj",), check=_jwt_check, redact=True, comments=True),
    Rule("SEC-SECRET", "high", "Hardcoded credential",
         c(r"""\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer[_-]?token"""
           r"""|private[_-]?key|passw(?:or)?d|pwd|db[_-]?pass(?:word)?|signing[_-]?key)["']?\s*(?::|=|:=|=>)\s*["']"""
           r"""(?P<s>[^"'\s]{12,})["']""", I),
         "Load it from the environment or a secret manager, and rotate it if it was ever real.", MAP_SECRET,
         types=NO_ENV, hint=("key", "secret", "token", "pass", "pwd"), check=_generic_check, redact=True,
         comments=True),
    Rule("SEC-FALLBACK", "high", "Secret falls back to a hardcoded default",
         c(r"""(?:process\.env|import\.meta\.env)\.(?P<v>""" + FALLBACK_VAR + r""")\s*(?:\|\||\?\?)\s*["'`][^"'`\s]+"""
           r"""|(?:os\.getenv|os\.environ\.get|environ\.get|env\.str|config)\(\s*["'](?P<w>""" + FALLBACK_VAR +
           r""")["']\s*,\s*(?:default\s*=\s*)?["'][^"'\s]+|ENV\.fetch\(\s*["'](?P<x>""" + FALLBACK_VAR +
           r""")["']\s*,\s*["'][^"'\s]+"""),
         "Fail closed: refuse to start in production when the variable is missing, instead of falling back to a value "
         "anyone can read in the source. A fallback secret makes every token forgeable the day the env var goes missing.",
         ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.5.17", "OWASP|OWASP A07:2021"], types=CODE, hint=("env", "config("), check=_fallback_check),
    Rule("SEC-CLIENT-ENV", "high", "Secret in a client-exposed env var (compiled into the browser bundle)",
         c(r"\b(?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY|VUE_APP|STORYBOOK)_(?P<n>[A-Z0-9_]*"
           r"(?:SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|SERVICE_ROLE|SERVICE_KEY|API_KEY|APIKEY|ACCESS_KEY)[A-Z0-9_]*)\b"),
         "This prefix compiles the value into the client bundle, where every visitor can read it. Keep the key "
         "server-side behind an endpoint (with auth and a rate limit if it costs money), and rotate it if it has shipped.",
         ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.8.12", "OWASP|OWASP A05:2021"], types=CODE_CFG | MARKUP,
         hint=("vite_", "react_app_", "public_", "gatsby_", "vue_app_", "storybook_"), check=_client_env_check),
    Rule("SEC-TLS-OFF", "high", "TLS certificate verification disabled",
         c(r"""\bverify\s*=\s*False\b|rejectUnauthorized["']?\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[=:]\s*["']?0"""
           r"""|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b"""
           r"""|check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE"""),
         "Remove it. Certificate checks are what stop a man-in-the-middle; fix the certificate or point at the right "
         "CA bundle instead.", MAP_TRANSIT,
         hint=("verify", "reject", "insecure", "unverified", "check_hostname", "cert_none")),
    Rule("SEC-HTTP", "medium", "Cleartext http:// endpoint",
         c(r"""(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|requests\.\w+|httpx\.\w+|urlopen|http\.(?:get|request)"""
           r"""|baseURL|base_url|api_?url|endpoint|webhook_?url|redirect_?uri)["']?\s*[(:=]\s*\(?\s*["'`]http://(?!localhost"""
           r"""|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|[\w.-]+\.(?:local|localhost|test|"""
           r"""internal|example)\b|example\.(?:com|org|net)|[\w-]+(?::\d+)?[/"'`])""", I),
         "Use https://. Tokens and personal data sent over plain HTTP can be read and changed in transit.",
         MAP_TRANSIT, hint=("http://",), per_file=True),
    Rule("SEC-HASH", "high", "Password hashed with MD5 or SHA-1",
         c(r"""createHash\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\(|\b(?:md5|sha1)\s*\(|DigestUtils\.(?:md5|sha1)"""
           r"""|MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']""", I),
         "Hash passwords with argon2id, scrypt or bcrypt. MD5 and SHA-1 fall to GPU cracking in minutes.",
         ["PCI|PCI DSS 8.3.2", "OWASP|OWASP A02:2021", "ISO27001|ISO 27001 A.8.24", "GDPR|GDPR Art. 32"],
         types=CODE, hint=("md5", "sha1", "sha-1"), near=c(r"passw|pwd|secret", I)),
    Rule("SEC-RANDOM", "high", "Predictable randomness used for a secret value",
         c(r"Math\.random\(\)|\brandom\.(?:random|randint|choice|choices|getrandbits|randrange)\("),
         "Use a CSPRNG: crypto.randomUUID() or crypto.getRandomValues() in JS, the secrets module in Python. "
         "Math.random and random are predictable.", ["OWASP|OWASP A02:2021", "ISO27001|ISO 27001 A.8.24"],
         types=CODE, hint=("random",),
         near=c(r"token|secret|passw|otp|nonce|salt|session|api.?key|reset|verif|invite|coupon|csrf", I), window=1),
    Rule("SEC-SQLI", "high", "SQL built from strings (injection risk)",
         c(r"""\.(?:query|execute|raw|exec|all|get|run|prepare|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*`[^`]*\b"""
           r"""(?:select\s[^`]*\bfrom|insert\s+into|update\s[^`]*\bset|delete\s+from)\b[^`]*\$\{"""
           r"""|"[^"\n]*\b(?:select\s[^"\n]*\bfrom|insert\s+into|update\s[^"\n]*\bset|delete\s+from)\b[^"\n]*"\s*\+\s*[\w(]"""
           r"""|'[^'\n]*\b(?:select\s[^'\n]*\bfrom|insert\s+into|update\s[^'\n]*\bset|delete\s+from)\b[^'\n]*'\s*\+\s*[\w(]"""
           r"""|\.(?:execute|executemany|raw|exec_driver_sql)\s*\(\s*f["']|\btext\(\s*f["']\s*(?:select|insert|update|delete)"""
           r"""|\.(?:execute|executemany|raw)\s*\(\s*["'][^"']*\b(?:select|insert|update|delete)\b[^"']*["']\s*(?:%\s*[\w(]|\.format\()""",
           I),
         "Use parameterized queries (placeholders plus a values array) or the ORM's query builder. Never build SQL "
         "out of strings.", MAP_INJECT, types=CODE,
         hint=("select", "insert", "update", "delete", "execute", "raw")),
    Rule("SEC-CMDI", "high", "Shell command built from strings (command injection risk)",
         c(r"""(?:child_process|childProcess|cp)\.exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+)"""
           r"""|(?<![\w.$])exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+)"""
           r"""|os\.(?:system|popen)\(\s*(?:f["']|[^)\n]*["']\s*[%+]|[^)\n]*\.format\()"""),
         "Pass arguments as an array (execFile or spawn, subprocess.run([...])) and keep user input out of shell strings.",
         MAP_INJECT, types=CODE, hint=("exec", "system", "popen")),
    Rule("SEC-SHELL", "medium", "subprocess called with shell=True",
         c(r"subprocess\.(?:run|call|check_call|check_output|Popen)\([^\n]*shell\s*=\s*True"),
         "Drop shell=True and pass an argument list, or make sure no user input can reach the command.", MAP_INJECT,
         types=PY, hint=("shell",)),
    Rule("SEC-EVAL", "medium", "eval or new Function on dynamic input",
         c(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\("),
         "Avoid eval and new Function. Parse data with JSON.parse or a real parser; eval on anything user-influenced "
         "is remote code execution.", MAP_INJECT[:1] + MAP_INJECT[2:], types=JS | PY, hint=("eval", "function")),
    Rule("SEC-XSS", "medium", "Raw HTML injection sink",
         c(r"""dangerouslySetInnerHTML|\.innerHTML\s*=(?!=)|\.outerHTML\s*=(?!=)|\bv-html\s*=|\{@html\s|document\.write\s*\("""
           r"""|insertAdjacentHTML\s*\(|\bmark_safe\s*\(|\.html_safe\b"""),
         "Render text, not HTML. If HTML is unavoidable, sanitize it first (DOMPurify, bleach) and never pass raw "
         "user input.", MAP_INJECT, types=CODE | MARKUP, hint=("html", "document.write", "mark_safe"),
         unless=c(r"DOMPurify|sanitiz|purify|xss\(|escape|JSON\.stringify|ld\+json", I), check=_xss_check, per_file=True),
    Rule("SEC-XSS-TPL", "medium", "Template output marked safe or autoescape off",
         c(r"\{\{[^}\n]*\|\s*safe\s*\}\}|\{%-?\s*autoescape\s+false"),
         "Keep autoescaping on and sanitize anything you mark safe.", MAP_INJECT, types=MARKUP,
         hint=("safe", "autoescape")),
    Rule("SEC-CORS", "high", "CORS allows any origin together with credentials",
         c(r"""\borigin\s*:\s*(?:["']\*["']|true\b)|allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[,:=]"""
           r"""\s*["']\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True"""),
         "List the exact origins you trust. Reflecting any origin while allowing credentials lets any website make "
         "logged-in requests as your users.", MAP_CONFIG, hint=("origin",),
         near=c(r"""credentials["']?\s*[:=]\s*true|allow_credentials\s*=\s*True|Allow-Credentials["']?\s*[,:=]\s*["']?true"""
                r"""|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True""", I), window=12),
    Rule("SEC-COOKIE", "medium", "Session cookie missing security flags",
         c(r"""(?:res(?:ponse)?\.cookie|\.set_cookie|cookies\(\)\.set|cookies\.set|setCookie|cookie\.serialize)\s*\(\s*"""
           r"""["'`]?[\w.-]*(?:session|token|auth|sid|jwt|refresh|access)""", I),
         "Set httpOnly, secure and sameSite on session cookies so scripts can't read them and they never travel over "
         "plain HTTP.", ["OWASP|OWASP A07:2021", "SOC2|SOC 2 CC6.1", "GDPR|GDPR Art. 32"], types=CODE,
         hint=("cookie",), check=_cookie_check, window=6),
    Rule("SEC-DEBUG", "high", "Debug mode enabled",
         c(r"^\s*DEBUG\s*=\s*True\b|\bapp\.run\([^)\n]*debug\s*=\s*True|^\s*(?:FLASK_DEBUG|DEBUG|APP_DEBUG)\s*=\s*"
           r"(?:1|true|True)\s*$", re.M),
         "Turn debug off outside local development. Debug pages leak stack traces, settings and sometimes secrets, "
         "and the Werkzeug debugger runs arbitrary code.", ["OWASP|OWASP A05:2021", "ISO27001|ISO 27001 A.8.9"],
         types=PY | {".env"}, hint=("debug",), check=_debug_check),
    Rule("SEC-XFF", "high", "Client IP taken from the first X-Forwarded-For entry (spoofable)",
         c(r"x-forwarded-for|x_forwarded_for", I),
         "The first X-Forwarded-For entry is whatever the client sent, so limits and bans keyed on it can be dodged "
         "or aimed at someone else. Use the address your own proxy appended (the last entry), or have the proxy set "
         "X-Real-IP from $remote_addr and read that.", ["OWASP|OWASP A04:2021", "SOC2|SOC 2 CC6.6"], types=CODE,
         hint=("forwarded",), near=c(r"""split\(\s*["'],\s*["']\s*\)\s*(?:\[\s*0\s*\]|\.shift\(\)|\.first\b)"""), window=2),
    Rule("SEC-LOG", "medium", "Secrets or personal data written to logs",
         c(LOG_CALL + r"""[^\n]*(?:\b(?:req|request)\.(?:body|headers|cookies)\b|[,+(]\s*(?:[\w.]*\.)?""" + SENSITIVE +
           r"""\b\s*[,)+]|\$\{\s*[\w.]*""" + SENSITIVE + r"""[\w.]*\s*\}|\{\s*[\w.]*""" + SENSITIVE + r"""[\w.]*\s*[}!:])""", I),
         "Don't log secrets or personal data. Log an ID or a redacted value; logs get shipped to third-party tools and "
         "kept for years.", ["GDPR|GDPR Art. 32", "PCI|PCI DSS 3.3.1", "ISO27001|ISO 27001 A.8.11", "SOC2|SOC 2 CC6.1"],
         types=CODE, per_file=True),
    Rule("PRV-URL", "medium", "Personal data sent in a URL query string",
         c(r"""[?&](?:email|e-mail|phone|tel|mobile|ssn|cpf|cnpj|password|passwd|dob|birth_?date|birthday)=""", I),
         "Send personal data in the request body or headers, not the URL. URLs land in server logs, browser history, "
         "analytics and Referer headers.", ["GDPR|GDPR Art. 32", "LGPD|LGPD Art. 46"], types=CODE | MARKUP, per_file=True),
    Rule("PCI-CARD", "high", "Raw card number or CVV handled in your own code",
         c(r"""(?:name|id|autocomplete|autoComplete)\s*=\s*\{?\s*["'](?:card[-_]?number|cc[-_]?num(?:ber)?|cc-number|cc-csc|"""
           r"""cvv2?|cvc2?|card[-_]?(?:cvc|cvv))["']|\b(?:card_?number|cc_?num(?:ber)?|credit_?card_?(?:number|num)|cvv2?|cvc2?|"""
           r"""card_?(?:cvc|cvv))\b\s*(?:\??:|=(?!=)|\s+(?:VARCHAR|TEXT|CHAR|INT|String|BigInt)\b)|\.(?:cardNumber|card_number|cvv|cvc)\b""", I),
         "Raw card numbers or CVVs in your own code put the whole stack in PCI DSS SAQ D scope. Use the processor's "
         "hosted fields (Stripe Elements or Checkout, Adyen Drop-in) so card data never touches your servers.",
         ["PCI|PCI DSS 3.3.1", "PCI|PCI DSS scope (SAQ D)"], types=CODE | MARKUP, hint=("card", "cc_num", "ccnum", "cvv", "cvc"),
         unless=c(r"CardNumberElement|CardCvcElement|CardElement|stripe|elements|PaymentElement|braintree|hostedFields|"
                  r"adyen|last_?4|mask|brand|pagar|mercadopago|iugu|tokeniz", I), per_file=True),
    Rule("FTC-RATING", "high", "Hardcoded rating or review count in structured data",
         c(r"""["']?(?:ratingValue|reviewCount|ratingCount)["']?\s*[:=]\s*["']?\d"""),
         "Only mark up ratings that come from real, user-submitted reviews shown on the page. Invented ratings break "
         "the FTC's fake-review rule (16 CFR 465) and Google's structured-data policy.",
         ["FTC|FTC 16 CFR 465 (fake reviews)"], types=CODE | MARKUP | CONFIG,
         hint=("ratingvalue", "reviewcount", "ratingcount"), if_file=c(r"aggregateRating|schema\.org|ld\+json", I),
         per_file=True),
    Rule("PRV-PRECHECK", "medium", "Consent checkbox checked by default",
         c(r"""\bdefaultChecked\b(?!\s*=\s*\{\s*false)|\bchecked\s*=\s*\{\s*true\s*\}|<input\b[^>\n]*\bchecked(?=[\s/>])"""
           r"""|\bchecked\s*=\s*["']checked["']|\buseState\(\s*true\s*\)|\bref\(\s*true\s*\)"""),
         "Consent boxes must start unchecked. A pre-ticked box is not valid consent under GDPR (the CJEU's Planet49 "
         "ruling), LGPD or the CPRA's dark-pattern rules.",
         ["GDPR|GDPR Art. 7", "LGPD|LGPD Art. 8", "CCPA|CPRA regs 7004 (dark patterns)"], types=CODE | MARKUP,
         hint=("checked", "usestate(", "ref("),
         near=c(r"consent|newsletter|marketing|opt.?in|subscribe|promo|offers|terms|privacy|aceit|concord|termos|notifica", I)),
    Rule("SEC-FORM-GET", "high", "Password form submits with GET (the password lands in the URL)",
         c(r"""<form\b(?![^>]*\bmethod\s*=\s*\{?\s*["']?post)(?![^>]*(?:\bon[Ss]ubmit|@submit|on:submit|\baction\s*=\s*\{))"""
           r"""[^>]*>(?:(?!</form>).){0,4000}?<input\b(?=[^>]*\btype\s*=\s*\{?\s*["']password["'])(?=[^>]*\bname\s*=)"""
           r"""[^>]*>""", I | re.S),
         'Use method="post" over HTTPS. A GET form puts the password in the URL, where server logs, browser history and '
         "analytics tools keep it.", ["GDPR|GDPR Art. 32", "OWASP|OWASP A04:2021", "SOC2|SOC 2 CC6.1"], types=MARKUP,
         hint=("password",), tag=True),
    Rule("A11Y-IMG", "medium", "Image without alt text",
         c(r"<img\b(?![^>]*\balt\s*=)(?![^>]*\{\s*\.\.\.)[^>]*>", I),
         'Add alt text that says what the image shows, or alt="" if it is decorative.', ["A11Y|WCAG 1.1.1"],
         types=MARKUP, hint=("<img",), tag=True, per_file=True),
    Rule("A11Y-LANG", "medium", "Page has no language declared",
         c(r"<html\b(?![^>]*\blang\s*=)[^>]*>", I),
         'Declare the language the page is written in, e.g. <html lang="pt-BR"> or lang="en", so screen readers '
         'pronounce it correctly.',
         ["A11Y|WCAG 3.1.1"], types=MARKUP, hint=("<html",), tag=True),
    Rule("A11Y-ZOOM", "medium", "Zoom disabled in the viewport",
         c(r"""user-scalable\s*=\s*["']?(?:no|0)\b|maximum-scale\s*=\s*["']?1(?:\.0+)?(?![\d.])|maximumScale\s*:\s*1\b(?!\.)"""
           r"""|userScalable\s*:\s*false""", I),
         "Remove user-scalable=no and maximum-scale=1. People with low vision need to zoom.", ["A11Y|WCAG 1.4.4"],
         types=MARKUP | JS, hint=("scal",)),
    Rule("A11Y-CLICK", "low", "Click handler on a non-interactive element",
         c(r"<(?:div|span|li|td|p|img|section|article)\b(?![^>]*\brole\s*=)(?![^>]*\bonKey(?:Down|Up|Press)\s*=)"
           r"(?![^>]*@key)[^>]*(?:\bonClick\s*=|@click\b|v-on:click|on:click)[^>]*>"),
         "Use a <button> (or add role, tabIndex={0} and a key handler) so keyboard and screen-reader users can "
         "activate it.", ["A11Y|WCAG 2.1.1"], types=MARKUP, hint=("click",), tag=True,
         per_file=True),
    Rule("A11Y-TABINDEX", "low", "Positive tabindex",
         c(r"""\btabindex\s*=\s*\{?\s*["']?[1-9]""", I),
         "Positive tabindex breaks the natural focus order. Use 0 or -1 and fix the DOM order instead.",
         ["A11Y|WCAG 2.4.3"], types=MARKUP, hint=("tabindex",)),
    Rule("A11Y-AUTOPLAY", "low", "Media autoplays with sound",
         c(r"<(?:video|audio)\b(?![^>]*\bmuted\b)[^>]*\bautoplay\b[^>]*>", I),
         "Don't autoplay sound. Autoplay muted, or let the user start playback.", ["A11Y|WCAG 1.4.2"],
         types=MARKUP, hint=("autoplay",), tag=True),
    Rule("A11Y-OUTLINE", "low", "Focus outline removed",
         c(r"outline\s*:\s*(?:none|0)\s*[;}!]", I),
         "Removing the focus outline hides where keyboard focus is. Keep it, or replace it with a visible "
         ":focus-visible style.", ["A11Y|WCAG 2.4.7"], types=STYLE, hint=("outline",),
         unless_file=c(r"focus-visible"), unless_near=c(r"box-shadow|border|ring|outline-offset|text-decoration", I),
         window=1, per_file=True),
    Rule("INF-DOCKER-SECRET", "high", "Secret baked into a Docker image layer",
         c(r"""^[ \t]*(?:ENV|ARG)[ \t]+[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)"""
           r"""[A-Z0-9_]*(?:[ \t]*=[ \t]*|[ \t]+)["']?(?P<s>[^\s"'$]{4,})""", re.M),
         "Image layers keep ENV and ARG values forever, readable by anyone who pulls the image. Inject secrets at "
         "runtime (env file, secret mount).", ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.5.17", "OWASP|OWASP A05:2021"],
         types=DOCKER, redact=True, comments=True),
    Rule("INF-DEPLOY-MERGE", "medium", "Deploy merges instead of mirroring (deleted files stay live)",
         c(r"\btar\b[^\n]*--overwrite"),
         "tar --overwrite never deletes, so files removed from the repo stay live. Mirror each release: wipe the "
         "target (keeping runtime config such as .env) before extracting, or use rsync --delete.",
         ["ISO27001|ISO 27001 A.8.32", "SOC2|SOC 2 CC8.1"], types=SHELL, hint=("--overwrite",), check=_deploy_check),
]

SUPPRESS = c(r"compliance-ignore(?!-file)(?::\s*([A-Z0-9-]+(?:\s*,\s*[A-Z0-9-]+)*))?")


def finding(rule, sev, title, path, line, snippet, fix, maps, key=None):
    key = key or re.sub(r"\s+", " ", snippet) or title
    fp = hashlib.sha1("{}|{}|{}".format(rule, path, key).encode("utf-8")).hexdigest()[:16]
    return {"rule": rule, "severity": sev, "title": title, "path": path, "line": line, "snippet": snippet,
            "fix": fix, "maps": maps, "fingerprint": fp}


def _suppressed(lines, ln, rid):
    for i in (ln - 1, ln - 2):
        if 0 <= i < len(lines):
            m = SUPPRESS.search(lines[i])
            if m and (not m.group(1) or rid in re.split(r"\s*,\s*", m.group(1))):
                return True
    return False


HASH_COMMENT = PY | SHELL | DOCKER | {".env", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".rb", ".ex", ".exs"}


def _in_comment(line, col, kind):
    head = line[:col]
    stripped = head.lstrip()
    if stripped.startswith(("//", "/*", "*", "<!--", "{/*")) or (kind in HASH_COMMENT and stripped.startswith("#")):
        return True
    return bool(re.search(r"(?<!:)//|/\*|<!--|\{/\*", head))


def scan_text(rel, text, rules=None, stats=None):
    """Run the line rules over one file's text. Used by full scans and by the edit hook."""
    if "compliance-ignore-file" in text[:2000]:
        return []
    kind = ftype(rel)
    low = text.lower()
    test = bool(TEST_PATH.search(rel))
    starts = lines = tagged = None
    out, seen = [], set()
    for r in rules or RULES:
        if kind not in r.types or (r.hint and not any(h in low for h in r.hint)):
            continue
        if (r.unless_file and r.unless_file.search(text)) or (r.if_file and not r.if_file.search(text)):
            continue
        first = None
        if r.tag and tagged is None:
            tagged = text.replace("=>", "==")  # same length, so offsets still line up; stops `>` in arrows ending a tag
        for m in r.rx.finditer(tagged if r.tag else text):
            if starts is None:
                starts = [0] + [x.end() for x in re.finditer("\n", text)]
                lines = text.split("\n")
            ln = bisect.bisect_right(starts, m.start())
            if (r.id, ln) in seen:
                continue
            line = lines[ln - 1]
            if not r.comments and _in_comment(line, m.start() - starts[ln - 1], kind):
                continue
            win = "\n".join(lines[max(0, ln - 1 - r.window):ln + r.window])
            if (r.unless and r.unless.search(line)) or (r.near and not r.near.search(win)) or \
                    (r.unless_near and r.unless_near.search(win)):
                continue
            extra = r.check(m, line, win, rel, text) if r.check else {}
            if extra is None:
                continue
            seen.add((r.id, ln))
            if _suppressed(lines, ln, r.id):
                if stats is not None:
                    stats["suppressed"] = stats.get("suppressed", 0) + 1
                continue
            if r.per_file and first is not None:
                first["_more"] = first.get("_more", 0) + 1
                continue
            sev = extra.get("sev", r.sev)
            if test and sev != "info":
                sev = SEVERITIES[min(RANK[sev] + 1, len(SEVERITIES) - 1)]
            snippet = line.strip()
            if r.redact:
                secret = m.groupdict().get("s") or m.group(0)
                snippet = snippet.replace(secret, secret[:4] + "…[redacted]")
            title = extra.get("title", r.title) + (" (test code)" if test else "")
            out.append(finding(r.id, sev, title, rel, ln, snippet[:200], extra.get("fix", r.fix), r.maps))
            if r.per_file:
                first = out[-1]
    for f in out:
        more = f.pop("_more", 0)
        if more:
            f["title"] += " (+{} more in this file)".format(more)
    return out


# ---------------------------------------------------------------- what the product does

DEP_FEATURES = {
    "accounts": "next-auth @auth/core passport passport-local auth0 @auth0/nextjs-auth0 @auth0/auth0-react lucia "
                "better-auth @kinde-oss/kinde-auth-nextjs bcrypt bcryptjs argon2 @node-rs/argon2 @node-rs/bcrypt "
                "flask-login django-allauth djangorestframework-simplejwt devise fastapi-users passlib",
    "payments": "stripe @stripe/stripe-js @stripe/react-stripe-js braintree @paypal/react-paypal-js "
                "@paypal/checkout-server-sdk paypal-rest-sdk @adyen/adyen-web @adyen/api-library adyen square squareup "
                "mercadopago @mercadopago/sdk-react pagarme @pagarme/pagarme-js razorpay @paddle/paddle-js "
                "@paddle/paddle-node-sdk @lemonsqueezy/lemonsqueezy.js chargebee recurly iugu asaas",
    "subscriptions": "@paddle/paddle-js @paddle/paddle-node-sdk @lemonsqueezy/lemonsqueezy.js chargebee recurly "
                     "react-native-purchases @revenuecat/purchases-js",
    "analytics": "react-ga react-ga4 ga-4-react react-gtm-module @next/third-parties analytics @segment/analytics-next "
                 "@segment/analytics-node mixpanel mixpanel-browser amplitude-js @amplitude/analytics-browser posthog-js "
                 "posthog-node @hotjar/browser react-hotjar @fullstory/browser logrocket @microsoft/clarity "
                 "smartlook-client @datadog/browser-rum heap-api @sentry/replay",
    "ads": "react-facebook-pixel @meta/pixel react-tiktok-pixel",
    "cmp": "vanilla-cookieconsent react-cookie-consent cookieconsent @cookie-consent/core klaro @osano/cookieconsent "
           "tarteaucitronjs @didomi/react @usercentrics/cmp-browser-sdk",
    "sms": "twilio @vonage/server-sdk vonage nexmo plivo messagebird @sinch/sdk-core telnyx @bandwidth/messaging "
           "clicksend @zenvia/sdk africastalking",
    "email_any": "@sendgrid/mail nodemailer resend postmark mailgun.js mailgun-js @aws-sdk/client-ses sendgrid flask-mail "
                 "django-anymail mailersend",
    "email_marketing": "@mailchimp/mailchimp_marketing mailchimp-marketing klaviyo-api @klaviyo/node @getbrevo/brevo "
                       "sib-api-v3-sdk convertkit @sendgrid/client customerio-node",
    "ai": "openai @anthropic-ai/sdk anthropic @google/generative-ai @google/genai google-generativeai google-genai "
          "@mistralai/mistralai mistralai cohere-ai cohere groq-sdk groq replicate together-ai together "
          "@huggingface/inference huggingface-hub langchain llamaindex llama-index ai ollama litellm transformers vllm "
          "@xenova/transformers @openrouter/ai-sdk-provider",
    "ai_media": "elevenlabs @elevenlabs/elevenlabs-js @fal-ai/client @fal-ai/serverless-client fal-client stability-sdk "
                "diffusers @runwayml/sdk lumaai",
    "biometrics": "face-api.js @vladmandic/face-api @vladmandic/human face-recognition deepface insightface dlib "
                  "@mediapipe/face_detection @mediapipe/face_mesh @aws-sdk/client-rekognition "
                  "@azure/cognitiveservices-face @azure-rest/ai-vision-face compreface-js facenet-pytorch",
    "health": "fhir fhirclient fhir-kit-client @medplum/core fhir-resources hl7 node-hl7-client hl7apy "
              "react-native-health @kingstinct/react-native-healthkit react-native-google-fit",
    "geolocation": "expo-location react-native-geolocation-service @react-native-community/geolocation "
                   "@capacitor/geolocation geolocator",
    "fintech": "plaid react-plaid-link react-native-plaid-link-sdk dwolla-v2 @unit-finance/unit-node-sdk ethers web3 "
               "@solana/web3.js bitcoinjs-lib viem wagmi @coinbase/coinbase-sdk @moovio/sdk",
    "mobile": "react-native expo @capacitor/core @ionic/react @ionic/angular nativescript",
    "desktop": "electron @tauri-apps/api @tauri-apps/cli @neutralinojs/lib",
    "server": "express fastify koa hono @nestjs/core @hapi/hapi next nuxt @sveltejs/kit @remix-run/node django flask "
              "fastapi starlette rails sinatra laravel/framework gin-gonic/gin labstack/echo gofiber/fiber elysia "
              "@trpc/server",
    "ui": "react react-dom vue svelte @angular/core next nuxt astro solid-js preact lit jquery",
    "managed_auth": "firebase firebase-admin @supabase/supabase-js @supabase/ssr @supabase/auth-helpers-nextjs auth0 "
                    "@auth0/nextjs-auth0 @auth0/auth0-react @auth0/auth0-spa-js aws-amplify @aws-amplify/auth "
                    "amazon-cognito-identity-js better-auth keycloak-js next-auth @auth/core supertokens-node magic-sdk "
                    "supabase auth0-python django fastapi-users flask-security-too devise",
    "pw_hashing": "bcrypt bcryptjs argon2 @node-rs/argon2 @node-rs/bcrypt argon2-cffi passlib scrypt",
    "header_mw": "helmet @fastify/helmet koa-helmet flask-talisman secure django",
    "rate_limit": "express-rate-limit rate-limiter-flexible @upstash/ratelimit slowapi flask-limiter django-ratelimit "
                  "fastapi-limiter express-slow-down @fastify/rate-limit hono-rate-limiter limiter "
                  "rack-attack @nestjs/throttler",
}
DEP_FEATURES = {k: set(v.split()) for k, v in DEP_FEATURES.items()}
DEP_PREFIX = (("@segment/", "analytics"), ("@amplitude/", "analytics"), ("@langchain/", "ai"), ("@ai-sdk/", "ai"),
              ("@clerk/", "accounts"), ("@auth/", "accounts"), ("@paypal/", "payments"), ("@adyen/", "payments"),
              ("@fal-ai/", "ai_media"), ("@capacitor/", "mobile"), ("@ionic/", "mobile"), ("expo-", "mobile"),
              ("@clerk/", "managed_auth"), ("@auth/", "managed_auth"), ("@okta/", "managed_auth"),
              ("@kinde-oss/", "managed_auth"), ("@stytch/", "managed_auth"), ("@descope/", "managed_auth"),
              ("@workos-inc/", "managed_auth"), ("@privy-io/", "managed_auth"))


def feat(name, lits, pattern=None, flags=I):
    return name, tuple(lits), c(pattern, flags) if pattern else None


CODE_FEATURES = [
    feat("auth_code", ["login", "signin", "sign_in", "signup", "sign_up", "register", "authenticate"],
         r"""["'`]/(?:api/)?(?:auth/)?(?:login|signin|sign-in|signup|sign-up|register)\b|\b(?:signIn|signUp|signInWith\w+|"""
         r"""createUserWithEmailAndPassword|login_required|authenticate)\s*\("""),
    feat("email_input", ["email", "tel"], r"""type\s*[=:]\s*\{?\s*["'](?:email|tel)["']|keyboardType\s*=\s*["']email-address"""),
    feat("payments", ["stripe", "paypal", "mercadopago", "pagar.me", "braintree", "adyen"],
         r"js\.stripe\.com|checkout\.stripe\.com|paypal\.com/sdk|new\s+Stripe\s*\(|stripe\.checkout\.sessions|"
         r"loadStripe\s*\(|mercadopago|pagar\.me"),
    feat("subscriptions", ["subscription", "recurring", "renew", "trial_period", "interval"],
         r"""mode\s*[:=]\s*["']subscription["']|\bsubscriptions\.(?:create|update|cancel|del|retrieve)\b|\bcreateSubscription\b"""
         r"""|\bsubscription_data\b|\btrial_period_days\b|\brecurring\s*[:=]\s*\{|\binterval\s*:\s*["'](?:month|year)["']"""
         r"""|\bauto[-_]?renew"""),
    feat("analytics", ["googletagmanager", "google-analytics", "gtag(", "datalayer.push", "hotjar", "clarity.ms",
                       "cdn.segment.com", "analytics.load(", "mxpnl", "mixpanel", "posthog", "amplitude.init",
                       "amplitude.getinstance", "cdn.amplitude.com", "@amplitude/", "heap.load",
                       "fullstory", "logrocket", "smartlook", "mouseflow"]),
    feat("ads", ["connect.facebook.net", "fbq(", "facebook.com/tr", "googleadservices", "googlesyndication",
                 "doubleclick.net", "'aw-", '"aw-', "analytics.tiktok.com", "ttq.", "snap.licdn.com",
                 "_linkedin_partner_id", "static.ads-twitter.com", "twq(", "bat.bing.com", "uetq", "pintrk(",
                 "sc-static.net", "snaptr(", "redditstatic.com", "taboola", "outbrain", "criteo", "adroll"]),
    feat("cmp", ["cookieconsent", "cookie-consent", "cookie_consent", "klaro", "osano", "onetrust", "otsdkstub",
                 "optanon", "cookiebot", "usercentrics", "didomi", "iubenda", "termly", "cookieyes", "quantcast",
                 "tarteaucitron", "complianz", "cookiebanner", "cookie-banner", "cookie_banner", "consentbanner",
                 "hasconsent", "consentgiven", "analyticsconsent", "consentstate", "__tcfapi", "__gpp",
                 "gtag('consent'", 'gtag("consent"']),
    feat("optout", ["do not sell", "do-not-sell", "donotsell", "do_not_sell", "globalprivacycontrol", "sec-gpc",
                    "opt-out-preference", "opt out of sale"]),
    feat("sms_code", ["twilio", "vonage", "nexmo", "plivo", "messagebird", "sinch", "telnyx", "sendsms", "send_sms",
                      "zenvia"]),
    feat("newsletter", ["newsletter", "mailing list", "mailing-list", "mailinglist", "marketing email",
                        "marketing_email"]),
    feat("ai_code", ["openai", "anthropic", "genai", "generativeai", "generativelanguage", "generatecontent", "generatetext",
                     "streamtext", "completions.create", "responses.create"],
         r"""\bnew\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|GoogleGenAI|Mistral|Groq|Cohere)\s*\(|\b(?:Async)?(?:OpenAI|Anthropic)\s*\("""
         r"""|chat\.completions\.create|\bgenerateContent\s*\(|\bgenerateText\s*\(|\bstreamText\s*\(|\bresponses\.create\s*\("""
         r"""|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com"""),
    feat("ai_media_code", ["images.generate", "images.edit", "dall-e", "gpt-image", "stability.ai", "stabilityai",
                           "elevenlabs", "fal.run", "fal.subscribe", "audio.speech", "tts-1", "stable-diffusion", "sdxl",
                           "midjourney", "text-to-image"]),
    feat("chat_ui", ["chat", "assistant", "conversation"],
         r"""\b(?:Chat(?:Box|Window|Input|Panel|Bot|Message|View|Screen)|Chatbot|AssistantMessage|useChat)\b|["'`]/chat\b"""),
    feat("ai_disclosure", ["ai", "artificial", "intelig", "generated", "gerad", "powered by", "bot"],
         r"""you(?:'re| are) (?:chatting|talking) (?:with|to) an? (?:ai|bot|assistant|virtual)|\bai[- ]generated|generated """
         r"""(?:by|with|using) (?:ai|artificial intelligence)|powered by (?:ai|gpt|claude|gemini|openai|anthropic|llm)|this """
         r"""(?:is|was) an? ai|responses? (?:may be|are) (?:ai[- ])?generated|assistente virtual|intelig[eê]ncia artificial|"""
         r"""gerad[oa] por (?:ia|intelig)|\ban ai assistant\b"""),
    feat("ai_label", ["c2pa", "content credentials", "contentcredentials", "watermark", "ai-generated", "ai generated",
                      "synthetic", "gerado por ia", "gerada por ia", "made with ai", "generated by ai",
                      "generated with ai"]),
    feat("biometrics_code", ["face", "voice", "fingerprint", "liveness", "selfie", "rekognition"],
         r"face[-_ ]?(?:descriptor|embedding|recognition|match(?:er|ing)?|verification|api)|voice[-_ ]?print|"
         r"fingerprint[-_ ]?(?:scan|template)|liveness[-_ ]?(?:check|detection|verification)|selfie[-_ ]?(?:verification|check|match)|rekognition|"
         r"compareFaces|detectAllFaces"),
    feat("biometric_consent", ["consent", "consentimento"],
         r"biometric[-_ ]?consent|consent[^\n]{0,60}(?:face|biometric|voice)|(?:face|biometric|voice|biom[eé]tric)"
         r"[^\n]{0,60}(?:consent|consentimento)"),
    feat("children", ["kid", "parental", "coppa"],
         r"kids?[-_ ]?(?:mode|zone|app|account|profile|area)|parental[-_ ]?(?:consent|control)|\bcoppa\b"),
    feat("dob", ["birth", "dob", "nascimento"],
         r"\b(?:date_?of_?birth|dateOfBirth|birth_?date|birthdate|dob|data_?(?:de_?)?nascimento|dataNascimento)\b"),
    feat("age_gate", ["age", "minor", "guardian", "parental", "idade", "menor"],
         r"age[-_ ]?(?:gate|verification|verify|check)|verify[-_ ]?age|is_?under_?(?:13|16|18)|isUnder(?:13|16|18)|"
         r"min(?:imum)?[-_]?age|MIN_AGE|isMinor|is_minor|parental[-_ ]?consent|guardian[-_ ]?consent|"
         r"idade[-_ ]?m[ií]nima|menor[-_ ]?de[-_ ]?idade"),
    feat("geolocation_code", ["geolocation", "getcurrentposition", "watchposition", "cllocationmanager",
                              "fusedlocationprovider", "expo-location"],
         r"navigator\.geolocation|getCurrentPosition|watchPosition|CLLocationManager|FusedLocationProvider|"
         r"expo-location|requestForegroundPermissions"),
    feat("ugc", ["comment", "post", "review", "thread", "repl", "ugc", "user-generated", "user_generated"],
         r"""\bcreate(?:Comment|Post|Review|Thread|Reply)\b|\b(?:comments?|posts?|reviews?|replies|threads?)\.(?:create|insert"""
         r"""|add)\s*\(|\buser[-_ ]generated\b|\bUGC\b|/api/(?:comments|posts|reviews|threads|replies)\b"""),
    feat("ugc_report", ["report", "flag", "denunci", "moderat", "takedown", "dmca", "notice-and-action"],
         r"""report(?:Content|Post|Comment|User|Abuse|Message)|flag(?:Content|Post|Comment)|reportAbuse|["'`]/report\b|"""
         r"""denunci|moderat(?:ion|e|or)|takedown|\bdmca\b|notice[-_ ]and[-_ ]action"""),
    feat("fintech_code", ["treasury.", "issuing.", "kyc", "anti-money", "anti_money"]),
    feat("privacy_page", ["privacy", "privacidade", "datenschutz", "privacidad", "confidentialit"],
         r"privacy[-_ ]?(?:policy|notice)|/privacy\b|pol[ií]tica[-_ ]de[-_ ]privacidade|aviso[-_ ]de[-_ ]privacidade|"
         r"/privacidade\b|datenschutz|pol[ií]tica[-_ ]de[-_ ]privacidad|confidentialit[eé]"),
    feat("terms_page", ["terms", "termos", "condi", "/tos", "agb"],
         r"terms[-_ ]?(?:of[-_ ]?(?:service|use)|and[-_ ]conditions)|/terms\b|/tos\b|termos[-_ ]de[-_ ](?:uso|servi[cç]o)|"
         r"/termos\b|condi[cç][oõ]es[-_ ]gerais|\bAGB\b|pol[ií]tica[-_ ]de[-_ ]trocas|trocas[-_ ]e[-_ ]devolu"),
    feat("deletion", ["delete", "remove", "close", "excluir", "destroy"],
         r"""delete[-_ ]?(?:my[-_ ]?)?account|deleteAccount|delete_account|account/delete|remove[-_ ]?account|close[-_ ]?account"""
         r"""|deleteUser|delete_user|destroyUser|excluir[-_ ]?(?:minha[-_ ]?)?conta|auth\.admin\.deleteUser"""
         r"""|users?\.(?:delete|destroy|remove)\s*\("""),
    feat("export", ["export", "download", "portab", "exportar", "baixar"],
         r"export[-_ ]?(?:my[-_ ]?|user[-_ ]?)?data|download[-_ ]?(?:my[-_ ]?|your[-_ ]?)?data|data[-_ ]?export|portability|"
         r"exportUserData|exportar[-_ ]?(?:meus[-_ ]?)?dados|baixar[-_ ]?(?:meus[-_ ]?)?dados"),
    feat("cancel", ["cancel", "billing", "portal", "cancelar", "manage"],
         r"cancel[-_ ]?subscription|cancelSubscription|billing[-_ ]?portal|billingPortal|customer_portal|"
         r"subscriptions\.(?:cancel|del)\b|cancel_at_period_end|cancelar[-_ ]?(?:a[-_ ]?)?assinatura|"
         r"manage[-_ ]?subscription|customer\.portal"),
    feat("sms_consent", ["consent", "opt-in", "optin", "opt_in", "stop"],
         r"[Ss][Mm][Ss][-_ ]?(?:[Cc]onsent|[Oo]pt[-_ ]?[Ii]n)|[Oo]pt[-_ ]?[Ii]n|\bSTOP\b|[Cc]onsent", 0),
    feat("unsubscribe", ["unsubscribe", "list-unsubscribe", "opt-out", "optout", "opt_out", "descadastr",
                         "cancelar inscri"]),
    feat("password_store", ["password"],
         r"""(?:req|request)\.(?:body|form|json|get_json\(\))(?:\.|\[["']|\.get\(["'])password|\{[^}\n]*\bpassword\b[^}\n]*\}\s*=\s*"""
         r"""(?:await\s+)?(?:req|request)\.(?:body|json)|\bpassword\s*(?::\s*str\b|=\s*(?:Column|mapped_column|models\.\w+Field|"""
         r"""db\.Column|Field)\b)|\bpassword\s*:\s*(?:String\b|\{\s*type\s*:\s*String\b)""", 0),
    feat("pw_hashing", ["bcrypt", "argon2", "scrypt", "pbkdf2", "passlib", "password_hash(", "make_password", "set_password(",
                        "generate_password_hash", "hashpw", "has_secure_password", "hashpassword", "hash_password",
                        "passwordhasher"]),
    feat("header_code", ["content-security-policy", "x-content-type-options", "strict-transport-security", "helmet(",
                         "secureheaders", "talisman"]),
    feat("rate_limit_code", ["ratelimit", "rate_limit", "rate-limit", "rate limit", "limit_req", "slowdown", "slow-down"],
         r"rate[-_ ]?limit|\blimit_req\b|express-slow-down|slowDown\s*\("),
    feat("server_code", ["app.listen", "express()", "fastify(", "createserver", "flask(", "fastapi(",
                         "export async function post", "export async function get", "export default async function handler",
                         "http.handlefunc", "@app.route", "@router.", "@app.post", "@app.get"]),
]
HEALTH_TERMS = ("diagnosis", "diagnoses", "prescription", "medication", "symptom", "medical_record", "medicalrecord",
                "medical record", "allergies", "blood_pressure", "bloodpressure", "blood pressure", "heart_rate",
                "heartrate", "menstrua", "pregnan", "therapist", "mental health", "mental_health", "prontuario",
                "prontuário", "paciente", "diagnóstico", "diagnostico", "hipaa", "icd-10", "icd10", "patient")
EDU_TERMS = ("student", "classroom", "teacher", "gradebook", "school_id", "schoolid", "aluno", "turma", "matrícula",
             "coursework", "ferpa")


def _loc(rel, low, i):
    return rel, low.count("\n", 0, i) + 1


SLASH_COMMENT = JS | MARKUP | STYLE | {".java", ".kt", ".kts", ".swift", ".cs", ".go", ".rs", ".scala", ".dart", ".php"}


def strip_comments(text, kind):
    """Blank out comments, keeping length and newlines, so a mention in a comment isn't a feature."""
    blank = lambda m: re.sub(r"[^\n]", " ", m.group(0))
    if kind in MARKUP:
        text = re.sub(r"(?s)<!--.*?-->", blank, text)
    if kind in SLASH_COMMENT:
        text = re.sub(r"(?s)/\*.*?\*/", blank, text)
        text = re.sub(r"(?m)(?<![:\"'\w\\])//[^\n]*", blank, text)
    if kind in HASH_COMMENT:
        text = re.sub(r"(?m)^[ \t]*#[^\n]*", blank, text)
    return text


def detect(ctx):
    """Map what the code does to features, each with its first piece of evidence (path, line, detail)."""
    found = {}
    deps = sorted(ctx.prod | ctx.dev)
    for d in deps:
        for name, pkgs in DEP_FEATURES.items():
            if d in pkgs:
                found.setdefault(name, (ctx.dep_src.get(d, ""), 0, "dependency " + d))
        for pre, name in DEP_PREFIX:
            if d.startswith(pre):
                found.setdefault(name, (ctx.dep_src.get(d, ""), 0, "dependency " + d))
    terms = {"health": {}, "education": {}}
    for rel in ctx.texts:
        kind = ftype(rel)
        if (kind not in CODE and kind not in MARKUP) or TEST_PATH.search(rel):
            continue
        code = strip_comments(ctx.texts[rel], kind)
        low = code.lower()
        for name, lits, rx in CODE_FEATURES:
            if name in found or not any(lit in low for lit in lits):
                continue
            if rx:
                m = rx.search(code)
                if m:
                    found[name] = (rel, code.count("\n", 0, m.start()) + 1, m.group(0)[:60])
            else:
                i = min(low.find(lit) for lit in lits if lit in low)
                token = re.match(r"[^\s\"'<>`]{1,60}", code[i:])
                found[name] = _loc(rel, low, i) + (token.group(0) if token else low[i:i + 40],)
        if kind in CODE or kind in MARKUP:
            for group, words in (("health", HEALTH_TERMS), ("education", EDU_TERMS)):
                for w in words:
                    if w in low and w not in terms[group]:
                        terms[group][w] = rel
    for group, hits in terms.items():
        if len(hits) >= 2 and group not in found:
            first = sorted(hits.items())[0]
            found[group] = (first[1], 0, "terms: " + ", ".join(sorted(hits)[:4]))
    for rel in ctx.names:
        low = rel.lower()
        base = low.rsplit("/", 1)[-1]
        if re.search(r"privacy|privacidade|datenschutz|privacidad", low):
            found.setdefault("privacy_page", (rel, 0, "file"))
        if re.search(r"(^|[/_.-])(terms|termos|tos|agb|trocas|devolucoes|devoluções)([/_.-]|$)", low):
            found.setdefault("terms_page", (rel, 0, "file"))
        if base in ("androidmanifest.xml", "info.plist", "pubspec.yaml"):
            found.setdefault("mobile", (rel, 0, "file"))
        if base == "tauri.conf.json":
            found.setdefault("desktop", (rel, 0, "file"))
        if ftype(rel) in MARKUP and not TEST_PATH.search(rel):
            found.setdefault("web_ui", (rel, 0, "markup"))
    alias = (("accounts", ("auth_code",)), ("sms", ("sms_code",)), ("ai", ("ai_code",)),
             ("ai_media", ("ai_media_code",)), ("biometrics", ("biometrics_code",)), ("fintech", ("fintech_code",)),
             ("geolocation", ("geolocation_code",)), ("server", ("server_code",)), ("rate_limit", ("rate_limit_code",)),
             ("web_ui", ("ui",)))
    for name, sources in alias:
        for s in sources:
            if s in found:
                found.setdefault(name, found[s])
    if "email_any" in found and "newsletter" in found:
        found.setdefault("email_marketing", found["newsletter"])
    prof = ctx.profile
    if prof.get("children"):
        found.setdefault("children", ("", 0, "declared in profile"))
    for sector in prof.get("sectors") or []:
        key = {"finance": "fintech", "healthcare": "health", "edu": "education"}.get(sector, sector)
        found.setdefault(key, ("", 0, "declared in profile"))
    if prof.get("distributed") or "mobile" in found or "desktop" in found:
        found.setdefault("distributed", found.get("mobile") or found.get("desktop") or ("", 0, "declared in profile"))
    pd = ("accounts", "email_input", "analytics", "ads", "payments", "sms", "email_marketing", "health", "biometrics",
          "geolocation", "dob")
    for k in pd:
        if k in found:
            found.setdefault("personal_data", found[k])
            break
    for k in prof.get("ignore_features") or []:
        found.pop(k, None)
    return found


def manifests(root, names):
    """Dependency names from the common manifests: (prod, dev, name -> manifest path)."""
    prod, dev, src = set(), set(), {}

    def add(bucket, name, rel):
        bucket.add(name)
        src.setdefault(name, rel)

    norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
    for rel in names:
        base = rel.rsplit("/", 1)[-1].lower()
        path = os.path.join(root, rel)
        if base == "package.json":
            data = load_json(path, {})
            if isinstance(data, dict):
                for n in data.get("dependencies") or {}:
                    add(prod, n, rel)
                for n in data.get("devDependencies") or {}:
                    add(dev, n, rel)
        elif base.startswith("requirements") and base.endswith(".txt"):
            bucket = dev if re.search(r"dev|test|lint", base) else prod
            for line in (read(path) or "").splitlines():
                m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m and not line.lstrip().startswith(("-", "#")):
                    add(bucket, norm(m.group(1)), rel)
        elif base in ("pyproject.toml", "pipfile"):
            text = read(path) or ""
            for m in re.finditer(r"""(?m)^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[@ ]|["'])""", text):
                add(prod, norm(m.group(1)), rel)
            for m in re.finditer(r"""(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["'{]""", text):
                if m.group(1).lower() not in ("python", "name", "version", "description", "readme", "license",
                                              "requires-python", "build-backend", "url", "homepage", "repository"):
                    add(prod, norm(m.group(1)), rel)
        elif base == "gemfile":
            for m in re.finditer(r"""(?m)^\s*gem\s+["']([^"']+)""", read(path) or ""):
                add(prod, m.group(1), rel)
        elif base == "go.mod":
            for m in re.finditer(r"(?m)^\s*(?:require\s+)?[a-z0-9.-]+\.[a-z]{2,}/(\S+)\s+v", read(path) or ""):
                add(prod, m.group(1), rel)
        elif base == "composer.json":
            data = load_json(path, {})
            if isinstance(data, dict):
                for n in data.get("require") or {}:
                    add(prod, n, rel)
    return prod, dev, src


class Ctx:
    def __init__(self, root, files, names, texts, profile):
        self.root, self.files, self.names, self.texts, self.profile = root, files, names, texts, profile
        self._low = {}
        self.prod, self.dev, self.dep_src = manifests(root, names)
        declared = profile.get("markets")
        self.declared = bool(declared)
        self.markets = {str(m).upper() for m in declared} if declared else set(BASELINE_MARKETS)
        self.feats = detect(self)

    def low(self, rel):
        if rel not in self._low:
            self._low[rel] = self.texts[rel].lower()
        return self._low[rel]

    def has(self, *keys):
        return any(k in self.feats for k in keys)

    def market(self, *codes):
        return bool(self.markets & set(codes))

    def consumer(self):
        return str(self.profile.get("audience", "")).lower() not in ("business", "b2b")

    def sells_to(self, what):
        return what in (self.profile.get("sells_to") or [])

    def ev(self, key):
        path, line, detail = self.feats.get(key, ("", 0, ""))
        where = "{}:{}".format(path, line) if line else path
        return "{} ({})".format(detail, where) if where and detail else detail or where


# ---------------------------------------------------------------- project-level rules

PROJECT_RULES = {
    "INF-ENV": ("high", "Environment file with real values at risk of leaking",
                "Keep real values out of git: add the file to .gitignore, commit a .env.example with blank values, and "
                "rotate anything that was ever committed (removing it doesn't revoke it).",
                ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.5.17", "PCI|PCI DSS 8.6.2"]),
    "INF-KEYFILE": ("critical", "Private key file in the project",
                    "Move the key out of the repo into a secret store, gitignore key files, and rotate the key if it was "
                    "ever committed or deployed.", ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.8.24", "PCI|PCI DSS 3.6.1"]),
    "INF-DOCKERIGNORE": ("high", "Docker build copies the whole folder without excluding secrets",
                         "Add a .dockerignore that excludes .env*, .git, keys and scratch files, then rebuild and list the "
                         "image contents to confirm they're gone.",
                         ["SOC2|SOC 2 CC6.1", "ISO27001|ISO 27001 A.8.12", "OWASP|OWASP A05:2021"]),
    "INF-NGINX-HEADERS": ("medium", "Security headers missing from nginx",
                          "Add the missing headers (HSTS, CSP, nosniff, frame-ancestors or X-Frame-Options, "
                          "Referrer-Policy), unless something upstream already sets them.", MAP_CONFIG),
    "INF-NGINX-INHERIT": ("medium", "nginx location drops inherited security headers",
                          "An add_header inside a location discards every header inherited from the server block. "
                          "Re-declare the security headers in that location, or move them into a shared include.",
                          MAP_CONFIG),
    "INF-LOCKFILE": ("medium", "Dependencies not pinned by a lockfile",
                     "Commit a lockfile so every build installs the versions you tested. Without one, npm audit can't run "
                     "and the SBOM isn't reproducible.",
                     ["SSDF|NIST SSDF PS.3", "SOC2|SOC 2 CC8.1", "OWASP|OWASP A08:2021"]),
    "INF-SECTXT": ("low", "No security.txt vulnerability contact",
                   "Publish /.well-known/security.txt (RFC 9116) with a contact address so researchers can report "
                   "vulnerabilities. The EU Cyber Resilience Act requires a disclosure policy for products it covers.",
                   ["CRA|EU CRA Annex I(II)", "ISO27001|ISO 27001 A.8.8"]),
    "PRV-CONSENT": ("high", "Analytics or ad tags without a consent mechanism",
                    "Load analytics and ad tags only after opt-in consent (EU, UK, Brazil), with Reject as easy as Accept, "
                    "or switch to a cookieless tool. A banner that doesn't actually block the tags is not consent.",
                    ["EPRIVACY|ePrivacy Art. 5(3)", "GDPR|GDPR Art. 6", "GDPR|GDPR Art. 7", "LGPD|LGPD Art. 8"]),
    "PRV-NOTICE": ("high", "Personal data collected but no privacy policy found",
                   "Publish a privacy policy that matches what this code actually collects (the detected features in this "
                   "report are a starting list), and link it from the footer, every signup form and the store listing.",
                   ["GDPR|GDPR Art. 13", "CCPA|CCPA 1798.100", "LGPD|LGPD Art. 9", "APPSTORE|Store privacy policy URL"]),
    "PRV-DELETE": ("medium", "Accounts exist but no account deletion path found",
                   "Let users delete their account and data from inside the product (Apple and Google require it in-app "
                   "for apps with sign-up), and make sure deletion reaches backups, analytics and processors.",
                   ["GDPR|GDPR Art. 17", "CCPA|CCPA 1798.105", "LGPD|LGPD Art. 18", "APPSTORE|App Store 5.1.1(v)"]),
    "PRV-EXPORT": ("low", "No self-serve data export found",
                   "Add a self-serve data export, or document how you answer access requests (email works) inside the "
                   "deadline: one month under GDPR, 45 days under CCPA, 15 days under LGPD.",
                   ["GDPR|GDPR Art. 15", "GDPR|GDPR Art. 20", "CCPA|CCPA 1798.110", "LGPD|LGPD Art. 18"]),
    "PRV-OPTOUT": ("medium", "Ad pixels without a Do Not Sell or Share opt-out or GPC support",
                   'Add a "Do Not Sell or Share My Personal Information" link and honor the Global Privacy Control signal '
                   "(navigator.globalPrivacyControl, Sec-GPC) by switching ad pixels off. Several other US states "
                   "require the same signal.", ["CCPA|CCPA 1798.135", "CCPA|CCPA regs 7025 (opt-out signals)"]),
    "PRV-AGE": ("medium", "Birth dates or a kids audience without an age gate",
                "Act on the birth date you collect: route under-13s (US) and under-16s (EU default) to verifiable "
                "parental consent, and treat under-18s as children for India's DPDP Act.",
                ["COPPA|COPPA 16 CFR 312.5", "GDPR|GDPR Art. 8", "LGPD|LGPD Art. 14", "INDIA|DPDP Act s.9"]),
    "PRV-BIOMETRIC": ("high", "Biometric processing without a consent flow",
                      "Before capturing face, voice or fingerprint data, get written consent naming the purpose and "
                      "retention period, publish a retention and destruction schedule, and run a DPIA. BIPA allows private "
                      "suits at $1,000 to $5,000 per violation.",
                      ["BIPA|BIPA 740 ILCS 14/15", "GDPR|GDPR Art. 9", "GDPR|GDPR Art. 35"]),
    "PRV-HEALTH-TRACKING": ("high", "Health data alongside third-party tracking",
                            "Keep ad and analytics pixels off anything that touches health data, or get explicit opt-in "
                            "for that sharing. This is the pattern behind the FTC's GoodRx and BetterHelp cases.",
                            ["HEALTH|FTC Health Breach Notification Rule (16 CFR 318)", "FTC|FTC Act 5", "GDPR|GDPR Art. 9"]),
    "PRV-GEO": ("low", "Precise geolocation collected",
                "Precise geolocation is sensitive data under the CPRA and several state laws. Ask only when a feature "
                "needs it, say why, and let users limit it.", ["CCPA|CCPA 1798.121", "GDPR|GDPR Art. 6", "LGPD|LGPD Art. 7"]),
    "AI-DISCLOSE": ("medium", "AI chat without telling users they're talking to an AI",
                    "Tell people they're talking to an AI unless it's obvious from context (EU AI Act Art. 50, applying "
                    "since Aug 2, 2026). A line in the chat header is enough.", ["AIACT|EU AI Act Art. 50(1)"]),
    "AI-LABEL": ("medium", "Generated media without an AI label or watermark",
                 "Mark generated images, audio and video as AI-made in a machine-readable way (C2PA or a watermark) and "
                 "label deepfakes visibly. Systems on the market before Aug 2, 2026 have until Dec 2, 2026 for the "
                 "marking duty.", ["AIACT|EU AI Act Art. 50(2)", "AIACT|EU AI Act Art. 50(4)"]),
    "AI-COST": ("high", "Paid AI API with no rate limiting found",
                "Put auth and a per-user and per-IP rate limit in front of every endpoint that calls a paid model, or "
                "anyone can loop it and spend your money. Key the IP limit on the proxy-set address, not the first "
                "X-Forwarded-For entry.", ["OWASP|OWASP API4:2023", "SOC2|SOC 2 CC6.6"]),
    "CON-CANCEL": ("high", "Subscriptions without an online cancellation path",
                   "Let subscribers cancel online as easily as they signed up (Stripe's customer portal works), show price, "
                   "renewal and cancellation terms before charging, and send a receipt. Amazon paid $2.5B in 2025 over "
                   "Prime's sign-up and cancellation flows.",
                   ["ROSCA|ROSCA 15 USC 8403", "ROSCA|California auto-renewal law (BPC 17602)", "FTC|FTC Act 5"]),
    "CON-TERMS": ("medium", "Payments without terms of sale",
                  "Publish terms of sale (price, renewal, refunds, cancellation, seller identity and address) and show "
                  "them before checkout. Brazil and the EU also require a withdrawal right for online sales (7 and 14 days).",
                  ["ROSCA|ROSCA 15 USC 8403", "FTC|FTC Act 5", "CONSUMER|CDC Art. 49 + Decreto 7.962/2013 (Brazil)",
                   "CONSUMER|EU Consumer Rights Directive"]),
    "PLT-REPORT": ("medium", "User-generated content without a report or moderation path",
                   "Give users a way to report illegal or abusive content and act on reports (DSA notice-and-action, UK "
                   "Online Safety Act), and register a DMCA agent with the US Copyright Office.",
                   ["PLATFORM|DSA Art. 16", "PLATFORM|UK Online Safety Act", "PLATFORM|DMCA 512(c)"]),
    "MKT-SMS": ("medium", "SMS sending without consent or STOP handling",
                "Record prior express written consent before marketing texts, honor STOP at once, and keep the consent "
                "log. TCPA damages run $500 to $1,500 per message.", ["MARKETING|TCPA 47 USC 227"]),
    "MKT-UNSUB": ("medium", "Marketing email without an unsubscribe",
                  "Every marketing email needs a working unsubscribe honored within 10 business days and a one-click "
                  "List-Unsubscribe header (Gmail and Yahoo bulk-sender rules).",
                  ["MARKETING|CAN-SPAM 15 USC 7704", "MARKETING|CASL s.11", "GDPR|GDPR Art. 21"]),
    "SEC-PW-STORAGE": ("high", "Password sign-in but no password hashing found",
                       "Hash passwords with argon2id, scrypt or bcrypt before storing them, or use a managed auth provider. "
                       "Plaintext passwords turn one database leak into account takeovers everywhere your users reused them.",
                       ["PCI|PCI DSS 8.3.2", "OWASP|OWASP A02:2021", "GDPR|GDPR Art. 32", "SOC2|SOC 2 CC6.1",
                        "ISO27001|ISO 27001 A.8.24"]),
    "INF-HEADERS-APP": ("low", "No security headers set by the app or by a proxy config in this project",
                        "Set HSTS, CSP, nosniff, frame-ancestors and Referrer-Policy in the app (helmet for Express, "
                        "@fastify/helmet, Hono's secureHeaders, flask-talisman) or in the proxy in front. Ignore this if a "
                        "proxy outside the repo already sets them; app_scan.py checks the real response.", MAP_CONFIG),
    "OSS-LICENSE": ("medium", "Dependency license needs review",
                    "Check the obligation before shipping (see the license class in the title).",
                    ["OSS|OpenChain ISO/IEC 5230", "ISO27001|ISO 27001 A.5.32"]),
    "OSS-UNCHECKED": ("info", "Dependency licenses not checked (no lockfile or installed packages)",
                      "Install dependencies (npm ci, pip install) or commit a lockfile and re-run, or run a license "
                      "scanner before shipping.", ["OSS|OpenChain ISO/IEC 5230"]),
}

LICENSE_CLASSES = (
    (c(r"AGPL|SSPL|Commons[- ]Clause|BUSL|Business Source|Elastic-2|PolyForm[- ]Non|CC-BY-NC|NonCommercial", I), "high",
     "network copyleft or non-commercial", "Running it as a service or selling it may oblige you to publish your source "
     "or buy a license. Replace it, or get a commercial license."),
    (c(r"(?<![AL])GPL|EUPL|OSL-", I), "medium", "strong copyleft",
     "Distributing software that includes it (apps, desktop builds, client-side bundles) can oblige you to release "
     "your source under the same license. Replace it or confirm it stays server-side."),
    (c(r"LGPL|MPL|EPL|CDDL|CPL", I), "low", "weak copyleft",
     "Allowed, but keep it a separate module, ship its license text, and publish your changes to it."),
    (c(r"UNLICENSED|SEE LICENSE|UNKNOWN|Proprietary|Custom", I), "low", "no open-source license",
     "No license means no right to use it. Confirm the terms or replace it."),
)
PERMISSIVE = c(r"MIT|BSD|Apache|ISC|0BSD|Unlicense|CC0|Zlib|BlueOak|Python-2|WTFPL", I)


def classify_license(lic):
    s = lic if isinstance(lic, str) else json.dumps(lic)
    if re.search(r"\bOR\b", s) and PERMISSIVE.search(s):
        return None
    for rx, sev, label, fix in LICENSE_CLASSES:
        if rx.search(s):
            return sev, label, fix
    return None


def license_findings(ctx):
    pkgs, checked = {}, False
    for rel in ctx.names:
        if rel.rsplit("/", 1)[-1] != "package-lock.json":
            continue
        data = load_json(os.path.join(ctx.root, rel), {}) if os.path.getsize(os.path.join(ctx.root, rel)) < LOCK_BYTES else {}
        for key, meta in (data.get("packages") or {}).items() if isinstance(data, dict) else ():
            if not key or not isinstance(meta, dict) or meta.get("dev") or meta.get("devOptional"):
                continue
            checked = True
            if meta.get("license"):
                pkgs.setdefault(key.split("node_modules/")[-1], (meta["license"], rel))
    if not checked:
        for d in sorted(ctx.prod):
            src = ctx.dep_src.get(d, "")
            meta = load_json(os.path.join(ctx.root, os.path.dirname(src), "node_modules", d, "package.json"), None)
            if isinstance(meta, dict):
                checked = True
                lic = meta.get("license") or meta.get("licenses") or "UNKNOWN"
                pkgs.setdefault(d, (lic, src))
    for venv in (".venv", "venv", "env"):
        base = os.path.join(ctx.root, venv, "lib")
        if not os.path.isdir(base):
            continue
        for pyver in os.listdir(base):
            sp = os.path.join(base, pyver, "site-packages")
            for dist in os.listdir(sp) if os.path.isdir(sp) else ():
                if not dist.endswith(".dist-info"):
                    continue
                name = re.sub(r"[-_.]+", "-", dist[:-10].rsplit("-", 1)[0]).lower()
                if name not in ctx.prod:
                    continue
                checked = True
                meta = read(os.path.join(sp, dist, "METADATA")) or ""
                m = re.search(r"(?m)^License-Expression:\s*(.+)$", meta) or re.search(r"(?m)^License:\s*(.{1,80})$", meta)
                lic = m.group(1).strip() if m else " ".join(re.findall(r"(?m)^Classifier: License :: (.+)$", meta)) or "UNKNOWN"
                pkgs.setdefault(name, (lic, os.path.join(venv, "lib", pyver, "site-packages", dist)))
    out, counts, weak = [], {}, []
    for name, (lic, rel) in sorted(pkgs.items()):
        cls = classify_license(lic)
        if not cls:
            continue
        sev, label, fix = cls
        if label == "weak copyleft":
            weak.append((name, rel, fix))
            continue
        if sev == "medium" and ctx.has("distributed"):
            sev = "high"
        counts[sev] = counts.get(sev, 0) + 1
        if counts[sev] <= 15:
            out.append(finding("OSS-LICENSE", sev, "Dependency {} is {} ({})".format(name, label, lic if isinstance(lic, str)
                               else json.dumps(lic)), rel, 0, "", fix, PROJECT_RULES["OSS-LICENSE"][3]))
    if weak:
        out.append(finding("OSS-LICENSE", "info", "{} weak-copyleft dependencies (MPL, LGPL, EPL), e.g. {}".format(
            len(weak), ", ".join(n for n, _, _ in weak[:4])), weak[0][1], 0, "", weak[0][2], PROJECT_RULES["OSS-LICENSE"][3]))
    if not checked and (ctx.prod or ctx.dev):
        meta = PROJECT_RULES["OSS-UNCHECKED"]
        out.append(finding("OSS-UNCHECKED", meta[0], meta[1], "", 0, "", meta[2], meta[3]))
    return out


def _git(root, *args):
    try:
        return subprocess.run(["git", "-C", root] + list(args), capture_output=True, timeout=10).returncode
    except (OSError, subprocess.SubprocessError):
        return 128


def _ignored_by_gitignore(root, rel):
    pats = [l.strip() for l in (read(os.path.join(root, ".gitignore")) or "").splitlines()
            if l.strip() and not l.strip().startswith(("#", "!"))]
    base = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(base, p.strip("/").replace("**/", "")) or fnmatch.fnmatch(rel, p.strip("/")) for p in pats)


def _exposure(ctx, rel):
    """How exposed a secret-bearing file is: tracked in git, not ignored, or fine."""
    if _git(ctx.root, "rev-parse", "--is-inside-work-tree") == 0:
        if _git(ctx.root, "ls-files", "--error-unmatch", "--", rel) == 0:
            return "critical", "committed to git"
        if _git(ctx.root, "check-ignore", "-q", "--", rel) == 1:
            return "high", "not covered by .gitignore"
        return None
    return None if _ignored_by_gitignore(ctx.root, rel) else ("medium", "no .gitignore rule covers it")


def _nginx_blocks(text):
    text = re.sub(r"#[^\n]*", "", text)
    root = {"head": "", "dirs": [], "kids": []}
    stack = [root]
    for m in re.finditer(r"([^{};]*)\{|([^{};]*);|\}", text):
        if m.group(1) is not None:
            node = {"head": " ".join(m.group(1).split()), "dirs": [], "kids": []}
            stack[-1]["kids"].append(node)
            stack.append(node)
        elif m.group(2) is not None:
            stack[-1]["dirs"].append(" ".join(m.group(2).split()))
        elif len(stack) > 1:
            stack.pop()
    return root


def _headers(dirs):
    return {d.split()[1].lower() for d in dirs if d.lower().startswith("add_header ") and len(d.split()) > 1}


NGINX_REQUIRED = (("strict-transport-security", "HSTS"), ("content-security-policy", "Content-Security-Policy"),
                  ("x-content-type-options", "X-Content-Type-Options"), ("x-frame-options", "X-Frame-Options"),
                  ("referrer-policy", "Referrer-Policy"))


def nginx_findings(ctx, rel, text):
    out = []
    base = os.path.dirname(os.path.join(ctx.root, rel))

    def expand(node):  # inline `include x.conf;` files that live in the project, one level deep
        for d in list(node["dirs"]):
            m = re.match(r"include\s+(\S+)", d)
            path = m and next((p for p in (os.path.join(base, m.group(1)), os.path.join(ctx.root, m.group(1)))
                               if os.path.isfile(p)), None)
            if path:
                node["dirs"] += _nginx_blocks(read(path) or "")["dirs"]
        for kid in node["kids"]:
            expand(kid)

    def servers(node, inherited):
        for kid in node["kids"]:
            head = kid["head"].split(" ")[0]
            if head == "http":
                servers(kid, _headers(kid["dirs"]) or inherited)
            elif head == "server":
                yield kid, _headers(kid["dirs"]) or inherited

    def locations(node):
        for kid in node["kids"]:
            if kid["head"].startswith("location"):
                yield kid
                yield from locations(kid)

    tree = _nginx_blocks(text)
    expand(tree)
    for srv, own in servers(tree, set()):
        if any(re.match(r"return\s+30[18]", d) for d in srv["dirs"]):
            continue  # redirect-only vhost
        locs = list(locations(srv))
        present = set(own)
        for loc in locs:
            present |= _headers(loc["dirs"])
        csp_frames = any("frame-ancestors" in d.lower() for d in srv["dirs"] + [x for l in locs for x in l["dirs"]])
        tls = any(re.match(r"listen\s.*\b(?:443|ssl)\b", d) for d in srv["dirs"])
        missing = [label for key, label in NGINX_REQUIRED if key not in present and
                   not (key == "x-frame-options" and csp_frames) and not (key == "strict-transport-security" and not tls)]
        name = next((d.split(None, 1)[1] for d in srv["dirs"] if d.startswith("server_name ")), "server")
        meta = PROJECT_RULES["INF-NGINX-HEADERS"]
        if missing:
            out.append(finding("INF-NGINX-HEADERS", meta[0] if tls else "low", "{} ({}): missing {}{}".format(
                meta[1], name, ", ".join(missing), "" if tls else " (plain-HTTP vhost: ignore if the proxy in front sets them)"),
                rel, 0, "", meta[2], meta[3]))
        for loc in locs:
            mine = _headers(loc["dirs"])
            dropped = sorted(own - mine) if mine else []
            if dropped:
                m2 = PROJECT_RULES["INF-NGINX-INHERIT"]
                out.append(finding("INF-NGINX-INHERIT", m2[0], "{} ({} in {}): drops {}".format(
                    m2[1], loc["head"], name, ", ".join(dropped)), rel, 0, "", m2[2], m2[3]))
    return out


def infra_findings(ctx):
    out = []

    def add(rid, path, detail="", sev=None):
        s, title, fix, maps = PROJECT_RULES[rid]
        out.append(finding(rid, sev or s, title + (": " + detail if detail else ""), path, 0, "", fix, maps))

    for rel in ctx.names:
        base = rel.rsplit("/", 1)[-1]
        low = base.lower()
        if ftype(rel) == ".env" and not ENV_TEMPLATE.search(low):
            text = read(os.path.join(ctx.root, rel)) or ""
            if re.search(r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]?[^\s'\"#]", text):
                exp = _exposure(ctx, rel)
                if exp:
                    add("INF-ENV", rel, exp[1], exp[0])
        elif re.search(r"\.(pem|key|p12|pfx|jks|keystore)$|^id_(rsa|ecdsa|ed25519|dsa)$", low):
            text = read(os.path.join(ctx.root, rel), 64 * 1024) or ""
            if "PRIVATE KEY" in text or low.endswith((".p12", ".pfx", ".jks", ".keystore")):
                exp = _exposure(ctx, rel)
                if exp:
                    add("INF-KEYFILE", rel, exp[1], exp[0])
    for rel in ctx.files:
        text = ctx.texts.get(rel)
        if text is None:
            continue
        kind = ftype(rel)
        if kind == "dockerfile":
            m = COPY_ROOT.search(text)
            if not m:
                continue
            web = WEB_DEST.search(m.group(1))
            d = os.path.dirname(rel)
            ign_rel = (d + "/" if d else "") + ".dockerignore"
            ign = read(os.path.join(ctx.root, ign_rel))
            here = [n[len(d) + 1:] if d else n for n in ctx.names if not d or n.startswith(d + "/")]
            has_env = any(ftype(n) == ".env" and not ENV_TEMPLATE.search(n.rsplit("/", 1)[-1]) for n in here)
            has_git = os.path.isdir(os.path.join(ctx.root, d, ".git"))
            has_report = not d or os.path.isdir(os.path.join(ctx.root, d, STATE_DIR))
            if ign is None:
                leaks = [x for x, on in ((".env files", has_env), (".git", has_git), (".compliance (this report)",
                                                                                     web and has_report)) if on]
                if leaks:
                    add("INF-DOCKERIGNORE", rel, "no .dockerignore, so {} ship in the image{}".format(
                        " and ".join(leaks), " and get served publicly" if web else ""),
                        "high" if has_env or has_git else "medium")
                continue
            pats = [l.strip().rstrip("/") for l in ign.splitlines() if l.strip() and not l.strip().startswith("#")]
            allow_list = bool(pats) and pats[0] in ("*", "**")
            covers = lambda *cands: allow_list or any(p in cands for p in pats)
            missing = []
            if has_env and not covers(".env", "**/.env", ".env*", "*.env", "**/*.env", "**/.env*"):
                missing.append(".env")
            if has_git and not covers(".git", "**/.git"):
                missing.append(".git")
            if web and has_report and not covers(".compliance", "**/.compliance", ".*"):
                missing.append(".compliance (this report would be served)")
            if missing:
                add("INF-DOCKERIGNORE", ign_rel, "not excluded: " + ", ".join(missing),
                    "high" if any(x in (".env", ".git") for x in missing) else "medium")
        elif kind == ".conf" and re.search(r"\bserver\s*\{", text):
            out += nginx_findings(ctx, rel, text)
    for rel in ctx.names:
        if rel.rsplit("/", 1)[-1] != "package.json":
            continue
        d = os.path.dirname(rel)
        dirs, cur = [], d
        while True:
            dirs.append(cur)
            if not cur:
                break
            cur = os.path.dirname(cur)
        if not any(os.path.exists(os.path.join(ctx.root, x, lf)) for x in dirs for lf in LOCKFILES):
            data = load_json(os.path.join(ctx.root, rel), {})
            if isinstance(data, dict) and data.get("dependencies"):
                add("INF-LOCKFILE", rel)
    if ctx.has("web_ui") and ctx.has("server", "personal_data") and \
            not any(n.endswith(".well-known/security.txt") for n in ctx.names):
        add("INF-SECTXT", "", sev=None if ctx.has("distributed") else "info")
    return out


def project_findings(ctx):
    out = infra_findings(ctx)
    f = ctx.feats

    def add(rid, key=None, detail="", sev=None):
        s, title, fix, maps = PROJECT_RULES[rid]
        path, line, _ = f.get(key, ("", 0, "")) if key else ("", 0, "")
        out.append(finding(rid, sev or s, title + (": " + detail if detail else ""), path, line, "", fix, maps, key=rid))

    trackers = [k for k in ("ads", "analytics") if k in f]
    if trackers and "cmp" not in f and ctx.market("EU", "UK", "BR"):
        add("PRV-CONSENT", trackers[0], "; ".join(ctx.ev(k) for k in trackers))
    if "personal_data" in f and "privacy_page" not in f and ctx.has("web_ui", "mobile"):
        add("PRV-NOTICE", "personal_data", ctx.ev("personal_data"))
    if "accounts" in f and "deletion" not in f:
        add("PRV-DELETE", "accounts", ctx.ev("accounts"), "high" if "mobile" in f else None)
    if "accounts" in f and "export" not in f:
        add("PRV-EXPORT", "accounts")
    if "ads" in f and "optout" not in f and ctx.market("US"):
        add("PRV-OPTOUT", "ads", ctx.ev("ads"))
    if ("dob" in f or "children" in f) and "age_gate" not in f:
        add("PRV-AGE", "dob" if "dob" in f else "children", ctx.ev("dob" if "dob" in f else "children"))
    if "biometrics" in f and "biometric_consent" not in f:
        add("PRV-BIOMETRIC", "biometrics", ctx.ev("biometrics"))
    if "health" in f and trackers:
        add("PRV-HEALTH-TRACKING", trackers[0], "health signals: {}; tracking: {}".format(ctx.ev("health"), ctx.ev(trackers[0])))
    if "geolocation" in f:
        add("PRV-GEO", "geolocation", ctx.ev("geolocation"))
    if "ai" in f and "chat_ui" in f and "ai_disclosure" not in f and ctx.market("EU"):
        add("AI-DISCLOSE", "chat_ui", ctx.ev("chat_ui"))
    if "ai_media" in f and "ai_label" not in f and ctx.market("EU"):
        add("AI-LABEL", "ai_media", ctx.ev("ai_media"))
    if "ai" in f and "server" in f and "rate_limit" not in f:
        add("AI-COST", "ai", ctx.ev("ai"))
    if "password_store" in f and "accounts" in f and not ctx.has("pw_hashing", "managed_auth"):
        add("SEC-PW-STORAGE", "password_store", ctx.ev("password_store"))
    web_servers = {"express", "fastify", "koa", "hono", "next", "nuxt", "@sveltejs/kit", "@remix-run/node", "@nestjs/core",
                   "flask", "fastapi", "starlette"}
    proxy_headers = any(ftype(r) == ".conf" and "add_header" in t for r, t in ctx.texts.items())
    if ctx.prod & web_servers and not ctx.has("header_mw", "header_code") and not proxy_headers:
        add("INF-HEADERS-APP", "server", ctx.ev("server"))
    if "subscriptions" in f and "cancel" not in f and ctx.consumer():
        add("CON-CANCEL", "subscriptions", ctx.ev("subscriptions"))
    if ("payments" in f or "subscriptions" in f) and "terms_page" not in f and ctx.consumer():
        add("CON-TERMS", "payments" if "payments" in f else "subscriptions")
    if "ugc" in f and "accounts" in f and "ugc_report" not in f:
        add("PLT-REPORT", "ugc", ctx.ev("ugc"))
    if "sms" in f and "sms_consent" not in f:
        add("MKT-SMS", "sms", ctx.ev("sms"))
    if "email_marketing" in f and "unsubscribe" not in f:
        add("MKT-UNSUB", "email_marketing", ctx.ev("email_marketing"))
    return out + license_findings(ctx)


# ---------------------------------------------------------------- frameworks

def _fw(key, name, when, why, manual):
    return {"key": key, "name": name, "when": when, "why": why, "manual": manual}


FRAMEWORKS = [
    _fw("SOC2", "SOC 2", lambda x: True, lambda x: "baseline for any product sold to businesses",
        ["Security policies, access reviews, onboarding and offboarding, vendor list",
         "A Type II audit window (usually 6 to 12 months) with evidence collected throughout"]),
    _fw("ISO27001", "ISO/IEC 27001:2022", lambda x: True, lambda x: "baseline for enterprise and international sales",
        ["ISMS scope, risk assessment and Statement of Applicability", "Certification audit by an accredited body"]),
    _fw("OWASP", "OWASP Top 10 / ASVS", lambda x: x.has("web_ui", "server", "mobile"),
        lambda x: "ships a web or mobile app",
        ["Third-party pentest before launch and yearly after",
         "Dependency audit in CI (npm audit, pip-audit or osv-scanner)"]),
    _fw("SSDF", "NIST SSDF + SBOM", lambda x: True, lambda x: "secure-development evidence buyers and acquirers ask for",
        ["An SBOM (CycloneDX or SPDX) per release", "Documented code review and CI security checks"]),
    _fw("OSS", "Open-source licenses (OpenChain ISO/IEC 5230)", lambda x: bool(x.prod or x.dev),
        lambda x: "ships third-party packages",
        ["NOTICE or attribution file for bundled licenses", "A full license scan before any acquisition or enterprise deal"]),
    _fw("GDPR", "GDPR / UK GDPR", lambda x: x.has("personal_data") and x.market("EU", "UK"),
        lambda x: "collects personal data: " + x.ev("personal_data"),
        ["Records of processing (Art. 30) and a DPIA for risky processing (Art. 35)",
         "DPAs with every processor and SCCs or the Data Privacy Framework for non-EU ones",
         "An EU or UK representative if you have no establishment there (Art. 27)",
         "Breach plan: 72 hours to notify the regulator"]),
    _fw("EPRIVACY", "ePrivacy Directive (cookies)", lambda x: x.has("analytics", "ads") and x.market("EU", "UK"),
        lambda x: "sets tracking: " + x.ev("analytics" if x.has("analytics") else "ads"),
        ["Cookie policy listing every cookie and SDK and what it does"]),
    _fw("CCPA", "CCPA/CPRA + US state privacy laws", lambda x: x.has("personal_data") and x.market("US"),
        lambda x: "collects personal data from US users",
        ["Notice at collection and a privacy policy updated yearly",
         "Service-provider contracts; thresholds apply (CCPA: $26.6M revenue or 100k consumers; other states differ)"]),
    _fw("LGPD", "LGPD (Brazil)", lambda x: x.has("personal_data") and x.market("BR"),
        lambda x: "collects personal data from Brazilian users",
        ["Name an encarregado (DPO) and publish the contact",
         "ANPD standard clauses for transfers; incident notice to the ANPD within 3 business days"]),
    _fw("FTC", "FTC Act 5 + Consumer Reviews Rule", lambda x: x.has("personal_data") and x.market("US"),
        lambda x: "US consumer protection: what you claim has to match what the code does",
        ["Privacy and security claims in marketing match reality", "No fake or undisclosed incentivized reviews"]),
    _fw("COPPA", "Children's privacy (COPPA, GDPR Art. 8, LGPD Art. 14, UK Children's Code)",
        lambda x: x.has("children", "dob"), lambda x: "kids audience or birth dates: " + x.ev("children" if x.has("children") else "dob"),
        ["Decide the audience; if under-13s can use it, get verifiable parental consent before collecting anything",
         "Retention policy and written security program (amended COPPA rule, compliance date April 22, 2026)"]),
    _fw("BIPA", "Biometric laws (BIPA, Texas CUBI, Washington MHMDA)", lambda x: x.has("biometrics"),
        lambda x: "processes biometrics: " + x.ev("biometrics"),
        ["Written consent with purpose and retention period before capture",
         "Public retention schedule: destroy within 3 years of the last interaction at the latest"]),
    _fw("HEALTH", "HIPAA / FTC Health Breach Notification Rule", lambda x: x.has("health"),
        lambda x: "handles health data: " + x.ev("health"),
        ["Decide whether you're a HIPAA covered entity or business associate; if so, BAAs with every vendor touching PHI",
         "Documented risk analysis (45 CFR 164.308)", "Outside HIPAA: breach notice to users and the FTC under the HBNR"]),
    _fw("PCI", "PCI DSS v4.0.1", lambda x: x.has("payments"), lambda x: "takes payments: " + x.ev("payments"),
        ["Confirm the SAQ type (SAQ A if card data never touches your servers)",
         "Annual self-assessment and Attestation of Compliance"]),
    _fw("CONSUMER", "Online consumer law (Brazil CDC + Decreto 7.962, EU Consumer Rights Directive)",
        lambda x: x.has("payments", "subscriptions") and x.market("BR", "EU", "UK") and x.consumer(),
        lambda x: "sells online: " + x.ev("payments" if x.has("payments") else "subscriptions"),
        ["Seller identity (CNPJ or company number), address and contact on the site",
         "Withdrawal right for online purchases: 7 days in Brazil (CDC Art. 49), 14 in the EU and UK"]),
    _fw("MARKETING", "TCPA / CAN-SPAM / CASL", lambda x: x.has("sms", "email_marketing"),
        lambda x: "sends marketing messages: " + x.ev("sms" if x.has("sms") else "email_marketing"),
        ["Consent records with timestamp and source for every marketing contact",
         "Physical postal address in every marketing email (CAN-SPAM)"]),
    _fw("ROSCA", "ROSCA + state auto-renewal laws", lambda x: x.has("subscriptions") and x.consumer(),
        lambda x: "sells subscriptions: " + x.ev("subscriptions"),
        ["Renewal and price-change notices where state law requires them"]),
    _fw("PLATFORM", "DSA / UK Online Safety Act / DMCA", lambda x: x.has("ugc"),
        lambda x: "hosts user content: " + x.ev("ugc"),
        ["Content rules and moderation explained in the terms; a point of contact (DSA Art. 11 and 12)",
         "UK: illegal-content and children's risk assessments", "DMCA agent registered with the US Copyright Office"]),
    _fw("A11Y", "Accessibility: WCAG 2.2 AA (ADA, Section 508, European Accessibility Act, Brazil's LBI)",
        lambda x: x.has("web_ui", "mobile"), lambda x: "has a user interface",
        ["Automated audit (Lighthouse or axe) plus a manual keyboard and screen-reader pass",
         "Accessibility statement; a VPAT/ACR for enterprise and government buyers",
         "EAA exempts micro-enterprises providing services (under 10 staff, 2M euros or less); Brazil's LBI "
         "(Lei 13.146/2015, Art. 63) covers sites of companies based or represented in Brazil"]),
    _fw("AIACT", "EU AI Act", lambda x: x.has("ai") and x.market("EU"), lambda x: "uses AI: " + x.ev("ai"),
        ["Classify each AI feature (prohibited, high-risk, limited, minimal); high-risk duties apply from Dec 2, 2027",
         "If you train or fine-tune a general-purpose model: GPAI documentation and a training-data summary"]),
    _fw("AIRMF", "NIST AI RMF / ISO/IEC 42001", lambda x: x.has("ai"), lambda x: "uses AI: " + x.ev("ai"),
        ["Model and vendor inventory, evals and red-team notes", "Training-data provenance and usage rights"]),
    _fw("CRA", "EU Cyber Resilience Act", lambda x: x.has("distributed") and x.market("EU"),
        lambda x: "distributes software: " + x.ev("distributed"),
        ["Report actively exploited vulnerabilities to ENISA within 24 hours (mandatory since Sept 11, 2026)",
         "At least 5 years of security updates; CE marking by Dec 11, 2027"]),
    _fw("APPSTORE", "Apple App Store / Google Play policies", lambda x: x.has("mobile"),
        lambda x: "ships a mobile app: " + x.ev("mobile"),
        ["Privacy label and Data safety form matching the SDKs this report found",
         "In-app account deletion plus a web deletion link (Google Play)"]),
    _fw("GLBA", "GLBA Safeguards Rule / NYDFS Part 500", lambda x: x.has("fintech") and x.market("US"),
        lambda x: "handles financial data: " + x.ev("fintech"),
        ["Written security program with a named qualified individual",
         "FTC notice within 30 days of a breach affecting 500+ consumers"]),
    _fw("AML", "BSA/AML + money transmission licensing", lambda x: x.has("fintech"),
        lambda x: "moves or holds money: " + x.ev("fintech"),
        ["Money transmitter licenses, or a sponsor bank or BaaS partner that holds them", "KYC and sanctions screening"]),
    _fw("FERPA", "FERPA + state student privacy laws", lambda x: x.has("education") and x.market("US"),
        lambda x: "handles student data: " + x.ev("education"),
        ["Signed data privacy agreement with each district", "No advertising or profiling on student data"]),
    _fw("CANADA", "PIPEDA + Quebec Law 25", lambda x: x.has("personal_data") and x.market("CA"),
        lambda x: "declared market: Canada", ["Privacy officer; privacy impact assessment before Quebec data leaves Quebec"]),
    _fw("CHINA", "PIPL / DSL / CSL", lambda x: x.has("personal_data") and x.market("CN"), lambda x: "declared market: China",
        ["Data localization and CAC filings for cross-border transfers"]),
    _fw("INDIA", "DPDP Act 2023", lambda x: x.has("personal_data") and x.market("IN"), lambda x: "declared market: India",
        ["Consent notices; verifiable parental consent under 18; most duties apply from May 13, 2027"]),
    _fw("TRADE", "Sanctions (OFAC) + export controls (EAR)", lambda x: x.has("payments", "distributed"),
        lambda x: "sells or distributes internationally",
        ["Block embargoed regions at signup and checkout; screen customers against sanctions lists",
         "Classify the product's encryption (usually ECCN 5D992, or 5D002 under License Exception ENC)"]),
    _fw("FEDRAMP", "FedRAMP (NIST SP 800-53) / GovRAMP", lambda x: x.sells_to("government"),
        lambda x: "declared: sells to government", ["FedRAMP authorization (Low, Moderate or High) with a 3PAO"]),
    _fw("CMMC", "CMMC 2.0 / NIST SP 800-171", lambda x: x.sells_to("defense"), lambda x: "declared: defense contracts",
        ["SPRS score now; C3PAO Level 2 certification appears in contracts from Nov 10, 2026"]),
    _fw("NIS2", "NIS2", lambda x: x.sells_to("eu-critical"), lambda x: "declared: EU essential or important entity",
        ["24-hour early warning and 72-hour incident notice; management accountability"]),
    _fw("DORA", "DORA", lambda x: x.sells_to("eu-financial"), lambda x: "declared: sells to EU financial entities",
        ["Art. 30 contract clauses, incident support and exit plans for bank customers"]),
]
KEY_NAMES = {fw["key"]: fw["name"] for fw in FRAMEWORKS}


def frameworks(ctx, findings):
    out = []
    for fw in FRAMEWORKS:
        if not fw["when"](ctx):
            continue
        counts = {}
        for f in findings:
            if f["status"] == "open" and any(m.split("|", 1)[0] == fw["key"] for m in f["maps"]):
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        out.append({"key": fw["key"], "name": fw["name"], "why": fw["why"](ctx), "open": counts, "manual": fw["manual"]})
    return out


# ---------------------------------------------------------------- scan + report

def _served(root):
    """True when a Dockerfile copies ROOT into a web root without excluding .compliance."""
    for name in ("Dockerfile", "Containerfile"):
        m = COPY_ROOT.search(read(os.path.join(root, name)) or "")
        if m and WEB_DEST.search(m.group(1)):
            pats = {l.strip().rstrip("/") for l in (read(os.path.join(root, ".dockerignore")) or "").splitlines()}
            if not pats & {".compliance", "**/.compliance", ".*", "*", "**"}:
                return True
    return False


def report_dir(root):
    """ROOT/.compliance, or a per-user cache dir when ROOT is itself served (a vulnerability list must not be)."""
    root = os.path.abspath(root)
    if not _served(root):
        return os.path.join(root, STATE_DIR)
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    key = hashlib.sha1(root.encode("utf-8")).hexdigest()[:10]
    return os.path.join(base, "claude-compliance", "{}-{}".format(os.path.basename(root) or "root", key))


def scan_project(root, out=None, record=True):
    """Scan ROOT. With record=True, write report.md, findings.json and state.json."""
    root = os.path.abspath(root)
    cfg = os.path.join(root, STATE_DIR)
    out_dir = os.path.abspath(out) if out else report_dir(root)
    profile = load_json(os.path.join(cfg, "profile.json"), {})
    profile = profile if isinstance(profile, dict) else {}
    waivers = load_json(os.path.join(cfg, "waivers.json"), [])
    files, names, truncated = walk(root)
    texts, stats, found = {}, {"suppressed": 0}, []
    for rel in files:
        text = read(os.path.join(root, rel))
        if text is not None:
            texts[rel] = text
            found += scan_text(rel, text, stats=stats)
    ctx = Ctx(root, files, names, texts, profile)
    found += project_findings(ctx)
    if any(f["rule"] == "SEC-FORM-GET" for f in found) and any(
            re.search(r"""addEventListener\(\s*["']submit|\.onsubmit\s*=|\.on\(\s*["']submit""", t)
            for r, t in texts.items() if ftype(r) in JS | MARKUP):
        for f in found:
            if f["rule"] == "SEC-FORM-GET" and f["severity"] == "high":
                f["severity"] = "medium"
                f["title"] += " (a script handles submit, so GET is the no-JS fallback)"
    today = dt.date.today().isoformat()
    for f in found:
        w = next((w for w in waivers if isinstance(w, dict) and w.get("rule") in (f["rule"], "*") and
                  fnmatch.fnmatch(f["path"], w.get("path", "*")) and str(w.get("until", "9999-12-31")) >= today), None)
        f["status"] = "waived" if w else "open"
        if w:
            f["waiver"] = w.get("reason", "")
    state_path = os.path.join(out_dir, "state.json")
    state = load_json(state_path, None)
    seen = set(state.get("seen", [])) if isinstance(state, dict) else set()
    for f in found:
        f["new"] = f["fingerprint"] not in seen
    found.sort(key=lambda f: (RANK[f["severity"]], f["path"], f["line"]))
    result = {
        "version": VERSION, "root": root, "scanned_at": dt.datetime.now().isoformat(timespec="seconds"),
        "files_scanned": len(texts), "truncated": truncated, "suppressed": stats["suppressed"],
        "first_scan": state is None, "markets": sorted(ctx.markets), "markets_declared": ctx.declared,
        "features": {k: list(v) for k, v in sorted(ctx.feats.items())},
        "frameworks": frameworks(ctx, found), "findings": found,
        "report": os.path.join(out_dir, "report.md"), "relocated": not out and out_dir != cfg,
    }
    if record:
        os.makedirs(out_dir, exist_ok=True)
        gi = os.path.join(out_dir, ".gitignore")
        if out_dir == cfg and not os.path.exists(gi):
            with open(gi, "w", encoding="utf-8") as fh:  # the report lists vulnerabilities: keep it out of git
                fh.write("report.md\nfindings.json\nstate.json\napp-*\n*.tmp\n")
        save_json(state_path, {"seen": sorted({f["fingerprint"] for f in found}), "scanned_at": result["scanned_at"]})
        save_json(os.path.join(out_dir, "findings.json"), result)
        with open(result["report"], "w", encoding="utf-8") as fh:
            fh.write(render(result))
    return result


def counts(findings, status="open"):
    out = {}
    for f in findings:
        if f["status"] == status:
            out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def fmt_counts(cnt):
    return ", ".join("{} {}".format(cnt[s], s) for s in SEVERITIES if cnt.get(s)) or "none"


def display_maps(maps):
    return " · ".join(m.split("|", 1)[1] for m in maps)


def where(f):
    return "{}:{}".format(f["path"], f["line"]) if f["line"] else (f["path"] or "project")


FEATURE_LABELS = [("web_ui", "web UI"), ("mobile", "mobile app"), ("server", "backend"), ("accounts", "user accounts"),
                  ("payments", "payments"), ("subscriptions", "subscriptions"), ("analytics", "analytics"),
                  ("ads", "ad pixels"), ("cmp", "consent manager"), ("ai", "AI"), ("ai_media", "generated media"),
                  ("sms", "SMS"), ("email_marketing", "marketing email"), ("health", "health data"),
                  ("biometrics", "biometrics"), ("children", "kids audience"), ("dob", "birth dates"),
                  ("geolocation", "geolocation"), ("ugc", "user content"), ("fintech", "fintech"),
                  ("education", "student data")]


def render(r):
    open_ = [f for f in r["findings"] if f["status"] == "open"]
    waived = [f for f in r["findings"] if f["status"] == "waived"]
    name = os.path.basename(r["root"]) or r["root"]
    lines = ["# Compliance report: " + name, "",
             "Scanned {} · {} files · scanner {}{}".format(r["scanned_at"], r["files_scanned"], r["version"],
                                                          " · file cap hit, partial scan" if r["truncated"] else ""), "",
             *(["> This project's root is copied into a public web root by its Dockerfile, so the report was written "
                "here instead of .compliance/. Add `.compliance` to .dockerignore to keep reports in the repo.", ""]
               if r.get("relocated") else []),
             "> Readiness check, not certification. These are the technical gaps a scanner can see; the \"Still needs "
             "you\" column is what no scanner can check. Nothing here means the product is compliant.", "",
             "## Summary", "",
             "| | Critical | High | Medium | Low | Info |", "|---|---|---|---|---|---|"]
    for label, rows in (("Open", open_), ("New since last scan", [f for f in open_ if f["new"]]), ("Waived", waived)):
        cnt = counts(rows, "waived" if label == "Waived" else "open")
        lines.append("| {} | {} |".format(label, " | ".join(str(cnt.get(s, 0)) for s in SEVERITIES)))
    feats = [label for key, label in FEATURE_LABELS if key in r["features"]]
    lines += ["", "**Detected:** " + (", ".join(feats) or "nothing specific"),
              "**Markets:** " + ", ".join(r["markets"]) +
              ("" if r["markets_declared"] else " (assumed; declare them in .compliance/profile.json to narrow this)"),
              "", "## Frameworks that apply", "", "| Framework | Why | Open findings | Still needs you |", "|---|---|---|---|"]
    for fw in r["frameworks"]:
        lines.append("| {} | {} | {} | {} |".format(fw["name"], fw["why"].replace("|", "/"), fmt_counts(fw["open"]),
                                                  "<br>".join(fw["manual"])))
    lines += ["", "## Findings", ""]
    if not open_:
        lines.append("No open findings from the automated checks.")
    for sev in SEVERITIES:
        group = [f for f in open_ if f["severity"] == sev]
        if not group:
            continue
        lines += ["### {} ({})".format(sev.capitalize(), len(group)), ""]
        for f in group:
            lines.append("- **{}** `{}`{}: {}".format(f["rule"], where(f), " (new)" if f["new"] else "", f["title"]))
            if f["snippet"]:
                lines.append("  - Code: `{}`".format(f["snippet"].replace("`", "'")))
            lines.append("  - Fix: " + f["fix"])
            lines.append("  - Breaks: " + display_maps(f["maps"]))
        lines.append("")
    if waived:
        lines += ["## Accepted risks (waived)", ""]
        for f in waived:
            lines.append("- **{}** `{}`: {} (reason: {})".format(f["rule"], where(f), f["title"], f.get("waiver") or "none given"))
        lines.append("")
    if r["suppressed"]:
        lines += ["{} finding(s) suppressed by inline `compliance-ignore` comments.".format(r["suppressed"]), ""]
    lines += ["## Not covered by this scan", "",
              "- The running app: run `scripts/app_scan.py <url>` and the browser checks in the skill.",
              "- Dependency vulnerabilities: run `npm audit --omit=dev`, `pip-audit` or `osv-scanner`.",
              "- Logic a pattern can't see: authorization on every route, whether deletion really deletes, whether "
              "consent really blocks the tags. The skill's judgment checks cover these.", ""]
    return "\n".join(lines)


def summary(r, top=8):
    open_ = [f for f in r["findings"] if f["status"] == "open"]
    new = [f for f in open_ if f["new"]]
    out = ["Compliance scan: " + r["root"],
           "  {} files · open: {} · new: {} · waived: {} · suppressed inline: {}".format(
               r["files_scanned"], fmt_counts(counts(open_)), len(new), len(r["findings"]) - len(open_), r["suppressed"]),
           "  Frameworks: " + (", ".join(fw["name"] for fw in r["frameworks"]) or "none")]
    for f in open_[:top]:
        out.append("  {:8} {} {}  {}".format(f["severity"].upper(), f["rule"], where(f), f["title"]))
    if len(open_) > top:
        out.append("  ... {} more in the report".format(len(open_) - top))
    out.append("  Report: " + r["report"])
    return "\n".join(out)


def list_rules():
    rows = [(r.id, r.sev, r.title, display_maps(r.maps)) for r in RULES]
    rows += [(k, v[0], v[1], display_maps(v[3])) for k, v in PROJECT_RULES.items()]
    return "\n".join("{:20} {:8} {}\n{:29} {}".format(i, s, t, "", m) for i, s, t, m in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan a codebase for compliance gaps.")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", help="write the report here instead of ROOT/.compliance")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if an open finding is at or above this severity")
    ap.add_argument("--rules", action="store_true", help="list the rules and exit")
    a = ap.parse_args(argv)
    if a.rules:
        print(list_rules())
        return 0
    r = scan_project(a.root, a.out)
    print(json.dumps(r, indent=2, ensure_ascii=False) if a.json else summary(r))
    if a.fail_on and any(f["status"] == "open" and RANK[f["severity"]] <= RANK[a.fail_on] for f in r["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

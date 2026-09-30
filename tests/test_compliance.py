# compliance-ignore-file: fixtures below are deliberately non-compliant.
"""Runnable check for the scanner and both hooks. Stdlib only.

  python3 tests/test_compliance.py

Fake secrets are assembled at runtime so no key-shaped string sits in the repo
(and secret scanners on the host don't trip on this file).
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skills", "Compliance", "scripts")
sys.path.insert(0, SCRIPTS)
import scan  # noqa: E402

STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AWS_ID = "AKIA" + "Q3EGRIVNSGDSJ6XY"


def jwt(payload):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(payload) + "." + "c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


def rules_hit(rel, text):
    return [f["rule"] for f in scan.scan_text(rel, text)]


class LineRules(unittest.TestCase):
    def hit(self, rule, rel, text):
        self.assertIn(rule, rules_hit(rel, text), "expected {} in {!r}".format(rule, text))

    def miss(self, rule, rel, text):
        self.assertNotIn(rule, rules_hit(rel, text), "unexpected {} in {!r}".format(rule, text))

    def test_provider_keys(self):
        self.hit("SEC-KEY", "src/pay.ts", 'const stripe = new Stripe("{}")'.format(STRIPE_LIVE))
        self.hit("SEC-KEY", "config.py", 'AWS_ACCESS_KEY_ID = "{}"'.format(AWS_ID))
        self.hit("SEC-KEY", "deploy/key.yaml", "key: |\n  -----BEGIN " + "RSA PRIVATE KEY-----\n  abc")
        self.miss("SEC-KEY", "src/pay.ts", 'const k = "sk_' + 'live_xxxxxxxxxxxxxxxxxxxxxxxx"')
        self.miss("SEC-KEY", ".env", "STRIPE_SECRET_KEY=" + STRIPE_LIVE)  # .env is where it belongs; INF-ENV guards git

    def test_redaction(self):
        f = scan.scan_text("src/pay.ts", 'const stripe = new Stripe("{}")'.format(STRIPE_LIVE))[0]
        self.assertNotIn(STRIPE_LIVE, f["snippet"])
        self.assertIn("[redacted]", f["snippet"])

    def test_jwt_roles(self):
        found = scan.scan_text("src/db.ts", 'const key = "{}"'.format(jwt({"role": "service_role", "iss": "supabase"})))
        self.assertEqual([(f["rule"], f["severity"]) for f in found], [("SEC-JWT", "critical")])
        self.miss("SEC-JWT", "src/db.ts", 'const key = "{}"'.format(jwt({"role": "anon", "iss": "supabase"})))

    def test_generic_secret(self):
        self.hit("SEC-SECRET", "src/api.js", 'const apiKey = "a8F3kL9qZ2xW7mN4"')
        self.miss("SEC-SECRET", "src/i18n.js", 'password: "Senha"')
        self.miss("SEC-SECRET", "src/api.js", "const apiKey = process.env.API_KEY")
        self.miss("SEC-SECRET", "src/api.js", 'const apiKey = "your-api-key-here-123"')

    def test_fallback_secret(self):
        self.hit("SEC-FALLBACK", "src/auth.js", 'const secret = process.env.JWT_SECRET || "fixture-fallback-secret"')
        self.hit("SEC-FALLBACK", "app/config.py", 'SECRET_KEY = os.getenv("SECRET_KEY", "changeme")')
        self.miss("SEC-FALLBACK", "src/pay.js", 'const pk = process.env.STRIPE_PUBLISHABLE_KEY || "pk_test_1"')
        self.miss("SEC-FALLBACK", "src/auth.js", "const secret = process.env.JWT_SECRET")
        guarded = ("export const env = { JWT_SECRET: process.env.JWT_SECRET || 'fixture-guarded-default' };\n"
                   "if (isProd && env.JWT_SECRET === 'fixture-guarded-default') throw new Error('Set JWT_SECRET');\n")
        self.miss("SEC-FALLBACK", "server/src/env.ts", guarded)  # fail-closed pattern is the fix, not the bug

    def test_client_env(self):
        self.hit("SEC-CLIENT-ENV", ".env", "VITE_OPENAI_API_KEY=sk-123")
        self.miss("SEC-CLIENT-ENV", ".env", "VITE_SUPABASE_ANON_KEY=eyJ...")
        crit = scan.scan_text("src/pay.ts", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY")
        self.assertEqual(crit[0]["severity"], "critical")

    def test_transport(self):
        self.hit("SEC-TLS-OFF", "sync.py", "requests.get(url, verify=False)")
        self.hit("SEC-HTTP", "src/api.ts", 'const r = await fetch("http://api.acme.io/v1/users")')
        self.miss("SEC-HTTP", "src/api.ts", 'const r = await fetch("http://localhost:3000/users")')
        self.miss("SEC-HTTP", "src/icon.tsx", '<svg xmlns="http://www.w3.org/2000/svg">')
        self.miss("SEC-HTTP", "app/providers.py", 'client = make(base_url="http://proxy/v1")')  # docker service name

    def test_crypto(self):
        self.hit("SEC-HASH", "auth.py", "digest = hashlib.md5(password.encode()).hexdigest()")
        self.miss("SEC-HASH", "cache.py", "etag = hashlib.md5(body).hexdigest()")
        self.hit("SEC-RANDOM", "src/reset.js", "const token = Math.random().toString(36).slice(2)")
        self.miss("SEC-RANDOM", "src/anim.js", "const x = Math.random() * width")

    def test_injection(self):
        self.hit("SEC-SQLI", "src/db.js", "db.query(`SELECT * FROM users WHERE id = ${id}`)")
        self.miss("SEC-SQLI", "src/db.js", 'db.query("SELECT * FROM users WHERE id = $1", [id])')
        self.hit("SEC-SQLI", "app/db.py", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
        self.miss("SEC-SQLI", "app/db.py", 'cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))')
        self.hit("SEC-SQLI", "src/db.js", "const q = \"SELECT * FROM users WHERE name = '\" + name + \"'\"")
        self.miss("SEC-SQLI", "src/api.js", "axios.get(`/api/transfer?from=${a}&update=1`)")
        self.hit("SEC-CMDI", "src/run.js", "exec(`ls ${dir}`)")
        self.hit("SEC-CMDI", "tools/clean.py", 'os.system(f"rm -rf {path}")')
        self.miss("SEC-CMDI", "src/parse.js", "const m = re.exec(str)")
        self.hit("SEC-EVAL", "src/calc.js", "const out = eval(userInput)")
        self.miss("SEC-EVAL", "cfg.py", "value = ast.literal_eval(raw)")
        self.hit("SEC-XSS", "src/Post.tsx", "<div dangerouslySetInnerHTML={{ __html: html }} />")
        self.miss("SEC-XSS", "src/Post.tsx", "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />")
        self.miss("SEC-XSS", "src/dom.js", 'el.innerHTML = "";')
        self.miss("SEC-XSS", "src/dom.js", "svg.innerHTML = PATHS[name] || PATHS.folder;")
        self.hit("SEC-XSS", "src/dom.js", "holder.innerHTML = html;")
        many = scan.scan_text("src/dom.js", "a.innerHTML = x;\nb.innerHTML = y;\nc.innerHTML = z;\n")
        self.assertEqual(len(many), 1)
        self.assertIn("(+2 more in this file)", many[0]["title"])

    def test_web_config(self):
        self.hit("SEC-CORS", "server.js", "app.use(cors({ origin: true, credentials: true }))")
        self.miss("SEC-CORS", "server.js", 'app.use(cors({ origin: "https://app.acme.io", credentials: true }))')
        self.hit("SEC-COOKIE", "server.js", 'res.cookie("session", token, { httpOnly: true })')
        self.miss("SEC-COOKIE", "server.js", 'res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" })')
        self.hit("SEC-DEBUG", "mysite/settings.py", "DEBUG = True")
        self.miss("SEC-DEBUG", "mysite/settings_dev.py", "DEBUG = True")
        self.hit("SEC-XFF", "src/ip.js", 'const ip = req.headers["x-forwarded-for"].split(",")[0]')
        self.miss("SEC-XFF", "src/ip.js", 'const ip = req.headers["x-forwarded-for"].split(",").pop()')

    def test_logging_and_urls(self):
        self.hit("SEC-LOG", "src/auth.js", 'console.log("login attempt", req.body)')
        self.hit("SEC-LOG", "app/auth.py", 'logger.info(f"user {user.password}")')
        self.miss("SEC-LOG", "src/auth.js", 'console.log("Password reset email sent")')
        self.hit("PRV-URL", "src/api.js", "fetch(`/api/lookup?email=${email}`)")

    def test_payments_reviews_consent(self):
        self.hit("PCI-CARD", "src/Checkout.jsx", '<input name="cardNumber" autoComplete="cc-number" />')
        self.miss("PCI-CARD", "src/Checkout.jsx", "<CardNumberElement options={opts} />")
        self.hit("PCI-CARD", "server/pay.js", "const { cardNumber, cvv } = req.body; charge({ cvv: cvv })")
        self.miss("PCI-CARD", "src/types.ts", "// no CVV, no expiry is ever requested, held, stored, or transmitted.")
        self.miss("PCI-CARD", "src/About.tsx", "<p>Nunca guardamos número completo, CVV ou validade.</p>")
        self.hit("FTC-RATING", "index.html", '"aggregateRating": {"@type": "AggregateRating", "ratingValue": "4.9"}')
        self.miss("FTC-RATING", "src/seo.ts", "aggregateRating: { ratingValue: stats.avg }")
        self.miss("FTC-RATING", "scraper/out.json", '[{"slug": "x", "rating": 4.5, "reviewCount": 10}]')  # data, not markup
        self.hit("PRV-PRECHECK", "src/Signup.jsx", '<input type="checkbox" name="newsletter" checked />')
        self.hit("PRV-PRECHECK", "src/Signup.jsx", "const [newsletter, setNewsletter] = useState(true)")
        self.miss("PRV-PRECHECK", "src/Login.jsx", '<input type="checkbox" name="remember" checked />')

    def test_accessibility(self):
        self.hit("A11Y-IMG", "index.html", '<img src="hero.png">')
        self.miss("A11Y-IMG", "index.html", '<img src="hero.png" alt="">')
        self.miss("A11Y-IMG", "src/Hero.jsx", '<img\n  src={hero}\n  onLoad={() => setOk(true)}\n  alt="Team photo"\n/>')
        self.hit("A11Y-LANG", "index.html", "<!doctype html>\n<html>\n<head>")
        self.miss("A11Y-LANG", "index.html", '<html lang="pt-BR">')
        self.miss("A11Y-LANG", "src/App.tsx", "{/* Reflects a11y prefs onto <html>; onboarding overlays the app. */}")
        self.miss("A11Y-IMG", "src/Tip.tsx", "//    This URL resolves to a CDN image, so it works as an <img src>")
        self.hit("A11Y-ZOOM", "index.html", '<meta name="viewport" content="width=device-width, maximum-scale=1">')
        self.miss("A11Y-ZOOM", "index.html", '<meta name="viewport" content="width=device-width, maximum-scale=5">')
        self.hit("A11Y-CLICK", "src/Card.jsx", "<div className=\"card\" onClick={go}>")
        self.miss("A11Y-CLICK", "src/Card.jsx", '<div role="button" tabIndex={0} onClick={go} onKeyDown={key}>')


    def test_password_form_get(self):
        self.hit("SEC-FORM-GET", "login.html", '<form>\n  <input type="password" name="password">\n</form>')
        self.miss("SEC-FORM-GET", "login.html", '<form method="post"><input type="password" name="password"></form>')
        self.miss("SEC-FORM-GET", "src/Login.jsx", '<form onSubmit={login}><input type="password" name="pw" /></form>')
        self.miss("SEC-FORM-GET", "admin.html", '<form id="f"><input type="password" id="senha"></form>')  # no name: never sent

    def test_infra_lines(self):
        self.hit("INF-DOCKER-SECRET", "Dockerfile", "FROM node:22\nENV API_KEY=abc123secret\n")
        self.miss("INF-DOCKER-SECRET", "Dockerfile", "FROM node:22\nARG NPM_TOKEN\nRUN npm ci\n")
        self.miss("INF-DOCKER-SECRET", "Dockerfile", "ENV API_KEY=${API_KEY}\n")
        self.hit("INF-DEPLOY-MERGE", "deploy-app.sh", "ssh host 'tar -xzf app.tgz --overwrite -C /srv/app'")

    def test_suppression_and_tests(self):
        self.assertEqual(rules_hit("src/a.tsx", "// compliance-ignore: SEC-XSS sanitized upstream\n"
                                                "<div dangerouslySetInnerHTML={{ __html: x }} />"), [])
        self.assertEqual(rules_hit("src/a.tsx", "<div dangerouslySetInnerHTML={{ __html: x }} />"
                                                " {/* compliance-ignore: SEC-EVAL */}"), ["SEC-XSS"])
        f = scan.scan_text("tests/pay.test.js", 'new Stripe("{}")'.format(STRIPE_LIVE))[0]
        self.assertEqual(f["severity"], "high")  # downgraded one level in test code


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class Project(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="compliance-test-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def base_app(self):
        write(self.root, "package.json", json.dumps({"name": "shop", "dependencies": {
            "react": "^19", "express": "^5", "stripe": "^18", "react-ga4": "^2", "openai": "^5", "twilio": "^5"}}))
        write(self.root, "src/Signup.jsx", '<form><input type="email" name="email" />\n'
                                           '<input type="password" name="password" /></form>')
        write(self.root, "index.html", '<!doctype html><html lang="en"><head>'
                                       '<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
                                       "</head></html>")
        write(self.root, "server.js", 'const app = express();\nconst ai = new OpenAI();\n'
                                      'app.post("/api/signup", createUser);\n'
                                      'app.post("/api/chat", async (req, res) => res.json(await ai.chat.completions.create({})));\n'
                                      "app.listen(3000);\n")

    def rules(self, result, status="open"):
        return {f["rule"] for f in result["findings"] if f["status"] == status}

    def test_privacy_gaps_then_fixes(self):
        self.base_app()
        r = scan.scan_project(self.root)
        got = self.rules(r)
        for rule in ("PRV-CONSENT", "PRV-NOTICE", "PRV-DELETE", "PRV-EXPORT", "AI-COST", "CON-TERMS", "MKT-SMS",
                     "INF-LOCKFILE"):
            self.assertIn(rule, got)
        names = {fw["key"] for fw in r["frameworks"]}
        for key in ("GDPR", "CCPA", "LGPD", "PCI", "AIACT", "MARKETING", "A11Y", "EPRIVACY"):
            self.assertIn(key, names)
        self.assertTrue(r["first_scan"])
        self.assertTrue(os.path.exists(os.path.join(self.root, ".compliance", "report.md")))
        with open(os.path.join(self.root, ".compliance", ".gitignore")) as fh:
            self.assertIn("report.md", fh.read())
        # now fix them
        write(self.root, "package.json", json.dumps({"name": "shop", "dependencies": {
            "react": "^19", "express": "^5", "stripe": "^18", "react-ga4": "^2", "openai": "^5", "twilio": "^5",
            "vanilla-cookieconsent": "^3", "express-rate-limit": "^7"}}))
        write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
        write(self.root, "src/pages/privacy-policy.jsx", "export default () => <h1>Privacy policy</h1>")
        write(self.root, "src/pages/terms.jsx", "export default () => <h1>Terms of service</h1>")
        write(self.root, "src/account.js", 'router.delete("/account", deleteAccount)\nrouter.get("/export", exportUserData)\n'
                                           'const smsConsent = req.body.smsOptIn\n')
        again = self.rules(scan.scan_project(self.root))
        for rule in ("PRV-CONSENT", "PRV-NOTICE", "PRV-DELETE", "PRV-EXPORT", "AI-COST", "CON-TERMS", "MKT-SMS",
                     "INF-LOCKFILE"):
            self.assertNotIn(rule, again)


    def test_project_finding_survives_line_shifts(self):
        write(self.root, "index.html", '<html lang="en"><head>'
                                       '<script async src="https://www.googletagmanager.com/gtag/js?id=G-TEST123"></script>')
        first = scan.scan_project(self.root)
        ev = next(f for f in first["findings"] if f["rule"] == "PRV-CONSENT")
        self.assertIn("G-TEST123", ev["title"])  # evidence keeps its case and isn't cut mid-token
        write(self.root, "index.html", "\n\n\n" + scan.read(os.path.join(self.root, "index.html")))
        again = next(f for f in scan.scan_project(self.root)["findings"] if f["rule"] == "PRV-CONSENT")
        self.assertFalse(again["new"])  # same gap, new line number: not a new finding

    def test_comments_are_not_evidence(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5", "openai": "^5"}}))
        write(self.root, "server.js", "// TODO: add express-rate-limit before launch\nconst app = express();\n"
                                      "app.post('/ai', async (req, res) => res.json(await ai.chat.completions.create({})));\n")
        self.assertIn("AI-COST", self.rules(scan.scan_project(self.root, record=False)))

    def test_password_storage(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5"}}))
        write(self.root, "server.js", 'app.post("/api/signup", (req, res) => {\n'
                                      "  const { email, password } = req.body;\n  users.set(email, { password });\n});\n")
        write(self.root, "src/types.ts", "export interface Login { email: string; password: string }\n")
        self.assertIn("SEC-PW-STORAGE", self.rules(scan.scan_project(self.root, record=False)))
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5", "bcrypt": "^5"}}))
        self.assertNotIn("SEC-PW-STORAGE", self.rules(scan.scan_project(self.root, record=False)))
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5", "@supabase/supabase-js": "^2"}}))
        self.assertNotIn("SEC-PW-STORAGE", self.rules(scan.scan_project(self.root, record=False)))

    def test_client_types_are_not_password_storage(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"react": "^19"}}))
        write(self.root, "src/auth.ts", 'export const signIn = (b: { password: string }) => fetch("/api/login", {})\n')
        self.assertNotIn("SEC-PW-STORAGE", self.rules(scan.scan_project(self.root, record=False)))

    def test_app_security_headers(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5"}}))
        write(self.root, "server.js", "const app = express();\napp.listen(3000);\n")
        self.assertIn("INF-HEADERS-APP", self.rules(scan.scan_project(self.root, record=False)))
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"express": "^5", "helmet": "^8"}}))
        self.assertNotIn("INF-HEADERS-APP", self.rules(scan.scan_project(self.root, record=False)))

    def test_script_handled_get_form_is_medium(self):
        write(self.root, "index.html", '<html lang="en"><form id="f"><input type="password" name="pw"></form>'
                                       '<script src="app.js"></script></html>')
        write(self.root, "app.js", "document.getElementById('f').addEventListener('submit', (e) => e.preventDefault())\n")
        sev = [f["severity"] for f in scan.scan_project(self.root, record=False)["findings"] if f["rule"] == "SEC-FORM-GET"]
        self.assertEqual(sev, ["medium"])

    def test_business_audience_skips_consumer_law(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"stripe": "^18"}}))
        write(self.root, "billing.js", "await stripe.subscriptions.create({ customer, items })\n")
        self.assertIn("CON-CANCEL", self.rules(scan.scan_project(self.root, record=False)))
        self.assertIn("CON-TERMS", self.rules(scan.scan_project(self.root, record=False)))
        write(self.root, "trocas.html", "<h1>Trocas e devoluções</h1>")  # how Brazilian stores publish terms of sale
        self.assertNotIn("CON-TERMS", self.rules(scan.scan_project(self.root, record=False)))
        write(self.root, ".compliance/profile.json", json.dumps({"audience": "business"}))
        r = scan.scan_project(self.root, record=False)
        self.assertNotIn("CON-CANCEL", self.rules(r))
        self.assertNotIn("ROSCA", {fw["key"] for fw in r["frameworks"]})

    def test_new_and_waivers(self):
        write(self.root, "src/Post.tsx", "<div dangerouslySetInnerHTML={{ __html: x }} />")
        first = scan.scan_project(self.root)
        self.assertTrue(all(f["new"] for f in first["findings"]))
        second = scan.scan_project(self.root)
        self.assertFalse(second["first_scan"])
        self.assertFalse(any(f["new"] for f in second["findings"]))
        write(self.root, ".compliance/waivers.json", json.dumps([
            {"rule": "SEC-XSS", "path": "src/*", "reason": "sanitized by the CMS", "until": "2999-01-01"}]))
        self.assertIn("SEC-XSS", self.rules(scan.scan_project(self.root), "waived"))
        write(self.root, ".compliance/waivers.json", json.dumps([
            {"rule": "SEC-XSS", "path": "src/*", "reason": "expired", "until": "2000-01-01"}]))
        self.assertIn("SEC-XSS", self.rules(scan.scan_project(self.root)))

    def test_out_dir_leaves_project_untouched(self):
        write(self.root, "src/a.js", "const x = 1\n")
        out = tempfile.mkdtemp(prefix="compliance-out-")
        try:
            scan.scan_project(self.root, out)
            self.assertFalse(os.path.exists(os.path.join(self.root, ".compliance")))
            self.assertTrue(os.path.exists(os.path.join(out, "report.md")))
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_licenses(self):
        write(self.root, "package.json", json.dumps({"name": "x", "dependencies": {"a": "1", "b": "1", "c": "1"}}))
        write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/a": {"license": "AGPL-3.0-only"}, "node_modules/b": {"license": "(MIT OR GPL-3.0)"},
            "node_modules/c": {"license": "LGPL-2.1"}, "node_modules/d": {"license": "GPL-3.0", "dev": True}}}))
        lic = {f["title"]: f["severity"] for f in scan.scan_project(self.root)["findings"] if f["rule"] == "OSS-LICENSE"}
        self.assertEqual(sorted(lic.values()), ["high", "info"])  # weak copyleft collapses into one info line
        self.assertTrue(any("Dependency a" in t for t in lic))

    def test_docker_and_nginx(self):
        write(self.root, "Dockerfile", "FROM nginx:alpine\nCOPY . /usr/share/nginx/html\n")
        write(self.root, "nginx.conf", "server {\n listen 443 ssl;\n server_name acme.io;\n"
                                       ' add_header Strict-Transport-Security "max-age=63072000" always;\n'
                                       ' add_header X-Content-Type-Options "nosniff" always;\n'
                                       " location / {\n  add_header Content-Security-Policy \"default-src 'self'\";\n"
                                       '  add_header Referrer-Policy "strict-origin" always;\n'
                                       '  add_header X-Frame-Options "DENY" always;\n }\n}\n')
        got = self.rules(scan.scan_project(self.root, record=False))
        self.assertIn("INF-DOCKERIGNORE", got)         # .compliance would be served from the web root
        self.assertIn("INF-NGINX-INHERIT", got)       # location / drops HSTS and nosniff
        self.assertNotIn("INF-NGINX-HEADERS", got)    # every header is set somewhere
        write(self.root, ".dockerignore", ".compliance\n")
        write(self.root, ".env", "API_KEY=abc123\n")
        sev = [f["severity"] for f in scan.scan_project(self.root, record=False)["findings"] if f["rule"] == "INF-DOCKERIGNORE"]
        self.assertEqual(sev, ["high"])                 # a real .env in the build context, not excluded
        write(self.root, ".dockerignore", "**/.env\n.compliance\n")
        self.assertNotIn("INF-DOCKERIGNORE", self.rules(scan.scan_project(self.root, record=False)))

    def test_permissions_policy_is_not_geolocation(self):
        write(self.root, "index.html", '<html lang="en"><body>hi</body></html>')
        write(self.root, "nginx.conf", 'server {\n listen 80;\n add_header Permissions-Policy "geolocation=(), camera=()";\n}\n')
        self.assertNotIn("geolocation", scan.scan_project(self.root, record=False)["features"])

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_env_exposure(self):
        run = lambda *a: subprocess.run(["git", "-C", self.root] + list(a), capture_output=True, check=True)
        run("init", "-q")
        write(self.root, ".env", "STRIPE_SECRET_KEY=" + STRIPE_LIVE + "\n")
        write(self.root, ".env.example", "STRIPE_SECRET_KEY=\n")
        sev = {f["path"]: f["severity"] for f in scan.scan_project(self.root, record=False)["findings"] if f["rule"] == "INF-ENV"}
        self.assertEqual(sev, {".env": "high"})         # untracked and not ignored; the template is fine
        run("add", ".env")
        sev = {f["path"]: f["severity"] for f in scan.scan_project(self.root, record=False)["findings"] if f["rule"] == "INF-ENV"}
        self.assertEqual(sev, {".env": "critical"})     # committed
        run("rm", "-q", "--cached", ".env")
        write(self.root, ".gitignore", ".env\n")
        self.assertNotIn("INF-ENV", self.rules(scan.scan_project(self.root, record=False)))


    def test_fix_recipes_pass_the_scanner(self):
        import re as _re
        doc = scan.read(os.path.join(SCRIPTS, "..", "references", "fixes.md"))
        ext = {"ts": "ts", "python": "py", "html": "html", "js": "js", "nginx": "conf"}
        for i, (lang, body) in enumerate(_re.findall(r"```(\w+)\n(.*?)```", doc, _re.S)):
            if lang in ext:
                name = "snippets/security-headers.conf" if "snippets/security-headers.conf" in body and \
                    "server {" not in body else "recipe{}.{}".format(i, ext[lang])
                if lang == "nginx" and "server {" in body:
                    head, _, rest = body.partition("server {")
                    write(self.root, "snippets/security-headers.conf", head)
                    body = "server {\n listen 443 ssl;" + rest
                write(self.root, "fixes/" + name if lang != "nginx" else name, body)
        write(self.root, "package.json", json.dumps({"name": "r", "dependencies": {
            "express": "^5", "express-rate-limit": "^7", "stripe": "^18", "openai": "^5"}}))
        got = self.rules(scan.scan_project(self.root, record=False))
        for rule in ("SEC-FALLBACK", "SEC-CLIENT-ENV", "PRV-CONSENT", "SEC-XFF", "SEC-COOKIE", "AI-COST", "CON-CANCEL",
                     "INF-NGINX-HEADERS", "INF-NGINX-INHERIT"):
            self.assertNotIn(rule, got, "the {} recipe should pass its own rule".format(rule))


HOOK = os.path.join(SCRIPTS, "hook.py")


class Hooks(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="compliance-hook-")
        self.tmp = tempfile.mkdtemp(prefix="compliance-tmp-")
        self.env = dict(os.environ, TMPDIR=self.tmp, TEMP=self.tmp, TMP=self.tmp, XDG_CACHE_HOME=self.tmp)
        self.env.pop("COMPLIANCE_DISABLE", None)
        write(self.root, "package.json", json.dumps({"name": "app", "dependencies": {"express": "^5"}}))
        write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_hook(self, payload):
        p = subprocess.run([sys.executable, HOOK], input=json.dumps(payload), capture_output=True, text=True,
                           env=self.env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout) if p.stdout.strip() else None

    def edit(self, rel, content, session="s1"):
        write(self.root, rel, content)
        return self.run_hook({"hook_event_name": "PostToolUse", "session_id": session, "tool_name": "Write",
                              "tool_input": {"file_path": os.path.join(self.root, rel), "content": content}})

    def stop(self, session="s1", active=False):
        return self.run_hook({"hook_event_name": "Stop", "session_id": session, "cwd": self.root,
                              "stop_hook_active": active})

    def test_edit_hook_warns_once(self):
        out = self.edit("src/auth.js", "// auth\nconst s = process.env.JWT_SECRET || \"fixture-fallback-secret\"\n")
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUse")
        self.assertIn("SEC-FALLBACK line 2", ctx)
        self.assertIsNone(self.edit("src/auth.js", "// auth\nconst s = process.env.JWT_SECRET || \"fixture-fallback-secret\"\n"))
        self.assertIsNone(self.edit("NOTES.md", "api_key = 'a8F3kL9qZ2xW7mN4'\n"))  # not code
        self.assertIsNone(self.edit("src/ok.js", "export const add = (a, b) => a + b\n"))

    def test_stop_hook_flow(self):
        self.edit("src/app.js", "export const add = (a, b) => a + b\n")
        first = self.stop()
        self.assertTrue(first is None or "decision" not in first)  # first scan never forces rework
        self.assertIsNone(self.stop())                             # nothing touched, nothing changed
        self.edit("src/pay.js", 'const stripe = new Stripe("{}")\n'.format(STRIPE_LIVE))
        blocked = self.stop()
        self.assertEqual(blocked["decision"], "block")
        self.assertIn("SEC-KEY", blocked["reason"])
        self.assertNotIn(STRIPE_LIVE, json.dumps(blocked))         # the key never leaves redacted
        self.assertIn("introduced this turn", blocked["systemMessage"])
        self.assertIsNone(self.stop(active=True))                  # loop guard
        self.edit("src/other.js", "export const x = 1\n")
        again = self.stop()                                        # known issue: a warning line, not a second block
        self.assertNotIn("decision", again)
        self.assertIn("still open", again["systemMessage"])

    def test_first_scan_reports_existing_issues(self):
        write(self.root, "src/legacy.js", 'const k = new Stripe("{}")\n'.format(STRIPE_LIVE))
        self.edit("src/app.js", "export const add = (a, b) => a + b\n")
        out = self.stop()
        self.assertNotIn("decision", out)
        self.assertIn("first scan", out["systemMessage"])

    def test_disabled(self):
        self.env["COMPLIANCE_DISABLE"] = "1"
        self.assertIsNone(self.edit("src/pay.js", 'new Stripe("{}")\n'.format(STRIPE_LIVE)))
        self.assertIsNone(self.stop())

    def test_served_root_report_is_relocated(self):
        write(self.root, "Dockerfile", "FROM nginx:alpine\nCOPY . /usr/share/nginx/html\n")
        os.environ["XDG_CACHE_HOME"] = self.tmp
        try:
            r = scan.scan_project(self.root)
        finally:
            os.environ.pop("XDG_CACHE_HOME", None)
        self.assertTrue(r["relocated"])
        self.assertFalse(os.path.exists(os.path.join(self.root, ".compliance")))
        self.assertTrue(r["report"].startswith(self.tmp))


class AppScan(unittest.TestCase):
    def test_local_site(self):
        import functools
        import http.server
        import threading
        import app_scan
        site = tempfile.mkdtemp(prefix="compliance-site-")
        write(site, "index.html", '<!doctype html><html><head>'
                                  '<meta name="viewport" content="width=device-width, maximum-scale=1">'
                                  '<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
                                  '<script>fbq("init", "123")</script></head><body><img src="hero.png">'
                                  "<p>" + "Handmade crochet pieces. " * 20 + "</p></body></html>")
        write(site, ".env", "API_KEY=abc123\n")
        write(site, ".git/config", "[core]\n\trepositoryformatversion = 0\n")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=site))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = app_scan.scan_app("http://127.0.0.1:{}/".format(srv.server_address[1]))
        finally:
            srv.shutdown()
            srv.server_close()
            shutil.rmtree(site, ignore_errors=True)
        rules = {f["rule"] for f in r["findings"]}
        for rule in ("APP-TRACKERS", "APP-OPTOUT", "APP-PRIVACY", "APP-LANG", "APP-ALT", "APP-ZOOM", "APP-EXPOSED"):
            self.assertIn(rule, rules)
        exposed = sorted(f["title"] for f in r["findings"] if f["rule"] == "APP-EXPOSED")
        self.assertTrue(any("environment file" in x for x in exposed) and any("git config" in x for x in exposed))
        self.assertNotIn("APP-HTTP", rules)  # local URL: transport checks skipped, and said so
        self.assertTrue(any("Local URL" in n for n in r["notes"]))


if __name__ == "__main__":
    unittest.main(verbosity=1)

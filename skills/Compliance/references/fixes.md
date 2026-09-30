# Fixes that are easy to get subtly wrong

Each recipe is the smallest version that actually satisfies the rule, and it passes the
scanner's own checks. Adapt names and frameworks to the project. Don't paste blindly.

## Contents

1. Secrets that fail closed (SEC-FALLBACK)
2. Keys out of the client bundle (SEC-CLIENT-ENV)
3. Analytics that wait for consent (PRV-CONSENT)
4. Global Privacy Control and Do Not Sell or Share (PRV-OPTOUT)
5. The real client IP behind a proxy (SEC-XFF)
6. Rate limits on paid endpoints (AI-COST)
7. Session cookies (SEC-COOKIE)
8. Account deletion that reaches processors (PRV-DELETE)
9. Cancellation with Stripe (CON-CANCEL)
10. nginx headers that survive `location` blocks (INF-NGINX-*)
11. AI disclosure and labels (AI-DISCLOSE, AI-LABEL)
12. Ignore files, and checking what actually ships (INF-ENV, INF-DOCKERIGNORE)
13. Security headers in the app (INF-HEADERS-APP)
14. Password hashing (SEC-PW-STORAGE)

## 1. Secrets that fail closed

No default at all, not even for development. A known dev string turns into a production secret
the day the env var goes missing. Use a random one per process in dev instead.

```ts
import { randomBytes } from "node:crypto";

let secret = process.env.JWT_SECRET;
if (!secret) {
  if (process.env.NODE_ENV === "production") throw new Error("JWT_SECRET is not set: refusing to start");
  secret = randomBytes(32).toString("hex"); // dev only: random per process, never a known string
}
export const JWT_SECRET = secret;
```

```python
import os, secrets, sys

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    if os.environ.get("APP_ENV") == "production":
        sys.exit("JWT_SECRET is not set: refusing to start")
    JWT_SECRET = secrets.token_urlsafe(32)  # dev only: random per process, never a known string
```

## 2. Keys out of the client bundle

`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_` and friends are compiled into JavaScript that
every visitor downloads. Put the call behind your own endpoint, which keeps the key server-side and
gives you a place for auth and a rate limit.

```ts
// server
app.post("/api/generate", requireAuth, perUser, async (req, res) => {
  res.json({ text: await callModel(req.body.prompt) }); // the provider SDK reads its key from process.env
});

// client
const r = await fetch("/api/generate", { method: "POST", headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({ prompt }) });
```

Rotate any key that has already shipped in a bundle. Deleting it from the code doesn't revoke it.

## 3. Analytics that wait for consent

Load nothing until the visitor opts in, make Reject as easy as Accept, remember the choice, and
let them change it later (withdrawing must be as easy as giving, GDPR Art. 7(3)). Storing the
choice itself is strictly necessary, so it needs no consent.

```html
<div id="cookie-banner" hidden>
  <p>We'd like to use analytics cookies to see which pages help. <a href="/privacy">Privacy policy</a></p>
  <button data-choice="reject">Reject</button> <button data-choice="accept">Accept</button>
</div>
<script>
  const analyticsConsent = "analyticsConsent";
  function loadAnalytics() {
    const s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=G-XXXXXXX";
    document.head.appendChild(s);
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { dataLayer.push(arguments); };
    gtag("js", new Date());
    gtag("config", "G-XXXXXXX");
  }
  const saved = localStorage.getItem(analyticsConsent);
  if (saved === "granted") loadAnalytics();
  else if (saved === null) document.getElementById("cookie-banner").hidden = false;
  document.querySelectorAll("#cookie-banner button").forEach((b) => b.addEventListener("click", () => {
    const granted = b.dataset.choice === "accept";
    localStorage.setItem(analyticsConsent, granted ? "granted" : "denied");
    document.getElementById("cookie-banner").hidden = true;
    if (granted) loadAnalytics();
  }));
  // Footer "Cookie settings" link: localStorage.removeItem(analyticsConsent); location.reload();
</script>
```

Google Consent Mode's "advanced" setup still sends pings before consent. Loading nothing until
opt-in, as above, is the reading no EU regulator disputes. A consent manager (Klaro, Cookiebot,
vanilla-cookieconsent) does the same with less code once there are several vendors.

## 4. Global Privacy Control and Do Not Sell or Share

Under the CPRA, ad pixels count as "sharing". Honor GPC as an opt-out, and give a footer link that
does the same.

```js
const doNotSell = navigator.globalPrivacyControl === true || localStorage.getItem("doNotSell") === "1";
if (!doNotSell) loadAdPixels();
// Footer link "Do Not Sell or Share My Personal Information":
//   localStorage.setItem("doNotSell", "1"); location.reload();
```

On the server, `req.get("Sec-GPC") === "1"` carries the same signal. Record it with the account.

## 5. The real client IP behind a proxy

Clients control the first `X-Forwarded-For` entry, so never key limits, bans or audit logs on it.

```nginx
location /api/ {
    proxy_set_header X-Real-IP $remote_addr;   # the address nginx saw: not spoofable
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://app:3000;
}
```

- **Express:** `app.set("trust proxy", 1)` for exactly one proxy in front, then use `req.ip`.
- **FastAPI / Starlette:** `request.headers.get("x-real-ip") or request.client.host`, or run uvicorn
  with `--proxy-headers --forwarded-allow-ips=<proxy address>`.
- **By hand:** with exactly one proxy, the last entry (`xff.split(",")[-1].strip()`) is the one it appended.

## 6. Rate limits on paid endpoints

Auth first, then a per-IP limit for abuse and a per-user limit for cost. Also set a monthly spend
cap in the provider's dashboard: it's the backstop when everything else fails.

```js
import rateLimit from "express-rate-limit";

app.set("trust proxy", 1);
const perIp = rateLimit({ windowMs: 60_000, limit: 20 });
const perUser = rateLimit({ windowMs: 60_000, limit: 10, keyGenerator: (req) => `user:${req.user.id}` });
app.post("/api/generate", perIp, requireAuth, perUser, generate);
```

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)  # behind a proxy, run uvicorn with --proxy-headers
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/generate")
@limiter.limit("10/minute")
async def generate(request: Request, user=Depends(current_user)):
    ...
```

## 7. Session cookies

- **Express:** `res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax", maxAge: 7 * 864e5 })`
- **FastAPI:** `response.set_cookie("session", token, httponly=True, secure=True, samesite="lax", max_age=604800)`
- **Flask:** `app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")`

## 8. Account deletion that reaches processors

Deleting the user row isn't enough. The data also lives in processors, uploads and marketing lists.

```ts
// DELETE /api/account: users delete themselves; admins get a separate, audited path
export async function deleteAccount(req, res) {
  const user = await db.user.findUniqueOrThrow({ where: { id: req.user.id } });
  if (user.stripeCustomerId) await stripe.customers.del(user.stripeCustomerId);
  await mailingList.remove(user.email);
  await storage.deletePrefix(`uploads/${user.id}/`);
  await db.user.delete({ where: { id: user.id } }); // cascade to the rows that hang off it
  res.clearCookie("session").status(204).end();
}
```

Keep what the law makes you keep (invoices for tax) with a documented reason. Let backups expire on
a schedule. Log that a deletion happened, not what was deleted. Mobile apps need this inside the app.

## 9. Cancellation with Stripe

Stripe's hosted customer portal handles cancel, plan changes and payment methods. Turn on
"Cancel subscriptions" in the portal settings.

```ts
app.post("/api/billing/portal", requireAuth, async (req, res) => {
  const session = await stripe.billingPortal.sessions.create({
    customer: req.user.stripeCustomerId,
    return_url: `${process.env.APP_URL}/account`,
  });
  res.redirect(303, session.url);
});
```

Before checkout, show the price, the billing period, when it renews and how to cancel, and email a
receipt that repeats them.

## 10. nginx headers that survive location blocks

Any `add_header` inside a `location` discards every header inherited from the server block. Keep
the set in one include and repeat the include wherever a location adds its own header.

```nginx
# snippets/security-headers.conf
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;

server {
    include snippets/security-headers.conf;
    location /downloads/ {
        include snippets/security-headers.conf;  # this block adds a header, so it must re-include
        add_header Content-Disposition "attachment";
    }
}
```

Build the CSP from what the pages actually load: grep for `fetch(`, `<script src` and `url(` first.
A CSP applied to proxied apps with their own inline scripts will break them, so scope it per location.
Validate with `nginx -t` before deploying.

## 11. AI disclosure and labels

- **Chat (Art. 50(1)):** a line in the chat header, like "You're chatting with an AI assistant. It can make mistakes."
- **Generated media (Art. 50(2)):** embed C2PA Content Credentials (c2patool or the c2pa SDKs), or at
  least IPTC `digitalSourceType = trainedAlgorithmicMedia` metadata. Label deepfakes visibly (Art. 50(4)).

## 12. Ignore files, and checking what actually ships

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
```

```dockerignore
.git
.env*
!.env.example
*.pem
*.key
node_modules
.compliance
```

Then check the artifact, not the ignore file:

```bash
docker build -q -t audit-tmp . && docker run --rm audit-tmp ls -a /usr/share/nginx/html
```

For anything already live, request the file. A 404 is proof; an assumption isn't:

```bash
python3 scripts/app_scan.py https://your-domain.example/
```

## 13. Security headers in the app

When no proxy config in the repo sets them, set them in the app. Tune the CSP to what the
pages load; don't switch it off to make an error go away.

- **Express:** `import helmet from "helmet"; app.use(helmet());`
- **Fastify:** `import helmet from "@fastify/helmet"; await app.register(helmet);`
- **Hono:** `import { secureHeaders } from "hono/secure-headers"; app.use(secureHeaders());`
- **Flask:** `Talisman(app)` from flask-talisman.
- **FastAPI:** a middleware that sets them on every response:

```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.update({
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "frame-ancestors 'none'",
    })
    return response
```

## 14. Password hashing

argon2id through a maintained library. Never a fast hash, never plaintext.

```js
import argon2 from "argon2";
const hash = await argon2.hash(password);   // argon2id by default
const ok = await argon2.verify(hash, attempt);
```

```python
from argon2 import PasswordHasher
ph = PasswordHasher()                        # argon2id with RFC 9106 parameters
hash = ph.hash(password)
ph.verify(hash, attempt)                     # raises VerifyMismatchError on a wrong password
```

An existing app that stored plaintext: hash every stored value in one migration (you have the
plaintext, so no reset is needed), and if that table could ever have leaked, force resets too.

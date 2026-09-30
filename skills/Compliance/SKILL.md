---
name: Compliance
description: >-
  Keep every product you build compliant while you build it, and warn the user when
  it isn't. Scans code and the running app for compliance gaps (leaked or
  client-exposed secrets, injection, trackers before consent, no privacy policy, no
  account deletion, pre-ticked consent boxes, raw card data, copyleft dependencies,
  inaccessible markup, unlabeled AI, no online cancel, exposed .env or .git) and maps
  each to the frameworks it breaks: SOC 2, ISO 27001, OWASP, PCI DSS, GDPR, LGPD,
  CCPA/CPRA, ePrivacy, COPPA, BIPA, HIPAA, TCPA, ROSCA, DSA, WCAG/EAA, EU AI Act, CRA.
  Use it whenever you build, scaffold, extend, ship or deploy an app, site, API, SaaS
  or mobile app, before a launch, release or due diligence, and when the user asks
  "is this compliant", "GDPR/LGPD check", "SOC 2 ready?", "privacy review", "can we
  launch", even without saying "compliance". Its hooks re-check every edit and turn.
---

# Compliance

Build it compliant instead of discovering the gaps in due diligence. This skill scans
what you build, fixes what is mechanical, and tells the user plainly about the rest,
every time, not once before launch.

**Readiness, not certification.** The scanner proves specific technical gaps are
absent. It can't see policies, contracts, audits, or anything outside the code, and
no tool can make a product "SOC 2 compliant" or "GDPR compliant". So never tell the
user a product is compliant. Say which checks pass, which fail, and what still needs
a human (the report's "Still needs you" column). Overclaiming here is how people get
fined: they believed a green checkmark.

## How it runs

| Layer | When | What happens |
|---|---|---|
| Edit hook | after every Write, Edit, MultiEdit | line rules run on the text you just wrote; findings come back to you as context |
| Stop hook | end of a turn that changed code | full project scan; new critical/high findings in files you touched make you continue once to fix or explain them; everything else still open becomes a one-line warning for the user |
| This skill | building, adding a feature, before shipping, or when asked | the workflow below: scan, profile, app scan, judgment checks, fix, report |

The hooks ship with the plugin. If this skill was installed on its own (a copied
folder), nothing runs automatically, so run the workflow at the end of every build.

## Workflow

Paths are relative to this skill's directory.

1. **Scan the code.**
   ```bash
   python3 scripts/scan.py <project-root>
   ```
   It prints a summary and writes `.compliance/report.md` and `findings.json`. The
   report lists what the product does (payments, accounts, analytics, AI...), which
   frameworks apply and why, each open finding with its fix and the controls it
   breaks, and what still needs a human. Read the report, not just the summary.

2. **Confirm the profile, once per project.** Markets decide which laws apply. If
   `.compliance/profile.json` doesn't exist, ask the user once, alongside your first
   report rather than before starting: where are the users (EU, UK, US, BR, CA, IN,
   CN)? Consumers or businesses? Kids? Health, finance, education, government,
   defense? Write the answers there:
   ```json
   {"markets": ["BR", "US"], "children": false, "sectors": [], "sells_to": [], "distributed": false}
   ```
   Until then the scan assumes EU, UK, US and Brazil (the strictest common baseline)
   and says so in the report.

3. **Scan the running app** when there's a dev server or a deployed URL:
   ```bash
   python3 scripts/app_scan.py <url> --out <project-root>/.compliance
   ```
   It checks headers, cookies set before consent, trackers, the privacy link, and
   probes for exposed `.env`, `.git` and backups. Only point it at the user's own app.
   Then do the browser checks below if a browser tool is available: single-page apps
   inject trackers and banners with JavaScript, which only a real browser sees.

4. **Judgment checks.** Patterns can't prove these. Read the code for each one that
   applies:
   - Every route that reads or changes user data checks *who* is asking (authorization,
     not just being logged in).
   - Deletion really deletes: rows, uploads, analytics profiles, and processor records
     (Stripe customer, mailing list), within the legal deadline.
   - Consent really gates: no tag loads and no tracking cookie is set until opt-in;
     Reject is as easy as Accept; the choice is remembered.
   - Only fields a feature uses are collected, and retention has an end (a TTL or a job).
   - Anything that costs money per call (AI, SMS, email) sits behind auth and a rate
     limit keyed on a proxy-set IP.
   - Logs, analytics events and error reports carry no passwords, tokens or personal data.
   - List every third party the code sends personal data to. The user needs that list
     for DPAs and the privacy policy.
   - Dependency vulnerabilities: run `npm audit --omit=dev`, `pip-audit` or `osv-scanner`
     if available.

5. **Fix**, following the split below, then re-run `scan.py` until the fixed findings
   are gone.

6. **Report to the user** in the format below.

## Fix yourself, or ask

**Fix without asking** when the fix is mechanical and keeps behavior: moving a secret to
an env var, failing closed, parameterizing a query, adding headers or cookie flags, alt
text, `lang`, unchecking a pre-ticked box, adding `.env` to `.gitignore` or
`.dockerignore`, rate-limiting a paid endpoint, gating tags behind consent state that
already exists. `references/fixes.md` has the versions that are easy to get subtly wrong.

**Ask first** when the fix changes the product, the law or the money: adding a consent
banner (it changes the UX), writing a privacy policy or terms (draft it, and label it a
draft for their review, because it's legal text), removing a feature or a tracker,
replacing a dependency, picking markets, accepting a risk.

**Never do these for the user; tell them instead:** rotating a leaked key (removing it
from code doesn't revoke it), signing DPAs, registering with regulators, anything that
publishes or deploys.

## Reporting to the user

Keep it short. The report file holds the detail. Lead with what blocks launch.

```
Compliance: <project> (readiness check, not certification)
Fixed: <n>, e.g. JWT secret now fails closed; card fields replaced with Stripe Elements
Needs you:
- [critical] <what>, <why it matters in one line>. <the decision or action needed>
- [high] ...
In scope: GDPR, LGPD, PCI DSS, ... · Still manual: DPAs with 4 processors, privacy policy review
Report: .compliance/report.md
```

Never write "compliant". Write "no automated findings for X" and name what's still manual.

## Severity

| Severity | Means | Do |
|---|---|---|
| critical | a live secret, exposed data, raw card data | fix or escalate now, and tell the user in the same turn |
| high | likely violation or exploitable | fix before shipping |
| medium | gap that needs a fix or a decision | fix, or ask |
| low, info | hygiene and evidence | mention in the report |

Findings in test code are downgraded one level; fake keys in tests are common, real
ones there still leak.

## False positives and accepted risks

- **Wrong finding:** add `compliance-ignore: RULE-ID reason` as a comment on the line or
  the line above. Always give the reason.
- **Accepted risk** (the user decided): `.compliance/waivers.json`, e.g.
  `[{"rule": "SEC-HASH", "path": "src/coturn.ts", "reason": "TURN spec mandates MD5", "until": "2027-01-01"}]`.
  Waived items stay in the report under "Accepted risks". Only add one on the user's say-so.
- **Wrong detection** (say "health" in a dev tool): `"ignore_features": ["health"]` in
  `profile.json`.
- **Off switches:** `COMPLIANCE_DISABLE=1` in the environment, or `"hooks": false` in
  `profile.json`.

Where the report lives: `.compliance/` inside the project, with its own `.gitignore`
(a vulnerability list doesn't belong in git). If the project root is copied into a
public web root by its Dockerfile, the report goes to `~/.cache/claude-compliance/`
instead, and the scan flags the missing `.dockerignore` entry.

## Browser checks

With the built-in browser, Playwright or Chrome DevTools:

1. Open the app in a fresh session. Before clicking anything, list network requests and
   cookies. An analytics or ad domain contacted, or a tracking cookie set, before
   consent is an ePrivacy, GDPR and LGPD violation.
2. Click Reject (or close the banner). Reload and check again: nothing should load.
3. Run an accessibility audit (Lighthouse or axe), then tab through the main flow with
   the keyboard only.
4. Check the footer: privacy policy, terms, cookie settings, and for US ad tags a
   "Do Not Sell or Share" link.
5. Sign up, then find the account deletion path.

## References

| File | Read when |
|---|---|
| `references/frameworks.md` | a framework applies and you need what it requires beyond the scan: triggers, dates, penalties, what evidence looks like |
| `references/fixes.md` | implementing consent gating, GPC, fail-closed secrets, client IP behind a proxy, rate limits, deletion, cancellation, nginx headers |

`python3 scripts/scan.py --rules` lists every rule with the controls it maps to.

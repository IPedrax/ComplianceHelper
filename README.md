<div align="center">
  <img src="assets/icons/shield.svg" width="56" alt="" />
  <h1>Compliance</h1>
  <p><strong>Build it compliant instead of finding the gaps in due diligence. A zero-dependency scanner for code and running apps, mapped to the frameworks buyers and regulators check, with hooks that re-check every edit Claude makes.</strong></p>
</div>

Most products meet compliance for the first time when someone else looks: an enterprise security review, an app store rejection, a regulator's letter, an acquirer's diligence team. By then the leaked key is in git history, the tracking pixel has been firing on every visit for a year, and the fix is a project instead of a line.

**Compliance** moves the check to the moment the code is written. After every edit, it looks at what Claude just wrote. When a turn ends, it re-scans the project, and anything new at critical or high severity makes Claude fix it or tell you about it before handing back control. Everything else still open stays in front of you as one warning line, until it's fixed or you accept the risk.

It checks what a scanner can honestly check, and says so. SOC 2, ISO 27001 and GDPR also need policies, contracts and audits that live outside the code, so each report ends with the part that still needs a human. **It never calls a product compliant.**

Built for **Claude Code** (Windows / macOS / Linux). No dependencies: the scripts are stdlib Python 3.8+.

---

## <img src="assets/icons/settings.svg" width="20" align="absmiddle" alt="" /> How it works

| Layer | When | What happens |
|---|---|---|
| **Edit hook** | after every Write, Edit or MultiEdit | the line rules run on the text Claude just wrote, not the whole file, so old code never triggers nagging; findings go straight back to Claude |
| **Stop hook** | when a turn that changed code ends | full project scan. New critical or high findings in files touched this turn block the stop once, so Claude fixes them or explains. The first scan of an existing project only reports, and never makes Claude rework old code unasked |
| **The skill** | building, adding a feature, before shipping, or when you ask | full workflow: code scan, market profile, running-app scan, judgment checks a pattern can't do, fixes, and a short report |

Reports go to `.compliance/report.md` inside the project, with a `.gitignore` of their own, because a vulnerability list doesn't belong in git. If the project root is itself served publicly (a Dockerfile that copies it into a web root), the report is written to `~/.cache/claude-compliance/` instead, and the scan flags the missing `.dockerignore` entry.

---

## <img src="assets/icons/layers.svg" width="20" align="absmiddle" alt="" /> What it checks

**Code, 33 line rules:** provider keys, JWTs (a Supabase `service_role` key is critical, an `anon` key is fine), hardcoded credentials, secrets that fall back to a default, secrets in `VITE_`/`NEXT_PUBLIC_` variables, disabled TLS checks, cleartext endpoints, MD5/SHA-1 passwords, predictable tokens, SQL and command injection, `eval`, raw HTML sinks, CORS with credentials, session cookie flags, debug mode, spoofable `X-Forwarded-For` client IPs, secrets in logs, personal data in URLs, raw card fields, hardcoded star ratings, pre-ticked consent boxes, accessibility (alt text, `lang`, zoom, keyboard access), secrets in Docker layers, deploys that never delete.

**Project, 26 checks:** `.env` and key files exposed to git, Docker builds that ship `.env` or `.git`, nginx headers (including the `add_header`-inside-`location` inheritance trap), lockfiles, `security.txt`, trackers without consent, a privacy policy, account deletion and export, Do Not Sell or Share with Global Privacy Control, age gates, biometric consent, health data next to ad pixels, AI disclosure and labels, rate limits on paid AI calls, subscription cancellation, terms of sale, reporting for user content, SMS consent, unsubscribe links, and open-source licenses read from the lockfile.

**Running app:** HTTPS and redirects, security headers, cookies set before consent, trackers with no consent manager, a privacy link, `lang`, alt text, zoom, mixed content, forms posting over HTTP, and probes for exposed `.env`, `.git`, keys, dumps and this report itself.

**Frameworks mapped:** SOC 2, ISO/IEC 27001, OWASP Top 10 / ASVS, NIST SSDF, OpenChain, GDPR / UK GDPR, ePrivacy, CCPA/CPRA and US state laws, LGPD, FTC Act 5 and the fake-review rule, COPPA, BIPA, HIPAA and the Health Breach Notification Rule, PCI DSS v4.0.1, ROSCA, Brazilian and EU online consumer law, TCPA / CAN-SPAM / CASL, DSA / UK Online Safety Act / DMCA, WCAG 2.2 / ADA / European Accessibility Act, the EU AI Act, NIST AI RMF / ISO 42001, the Cyber Resilience Act, app store policies, and, when declared, GLBA, AML, FERPA, FedRAMP, CMMC, NIS2, DORA, PIPEDA, PIPL and DPDP. Only the ones that apply show up: the scanner works out from the code whether there are accounts, payments, analytics, AI, health data or a mobile build.

---

## <img src="assets/icons/check.svg" width="20" align="absmiddle" alt="" /> What the testing found

- **29 tests**, every rule proven both ways: it fires on the bad pattern and stays quiet on the safe version of it. The hooks are tested by feeding them the same JSON Claude Code sends. The app scanner is tested against a real local server. The fix recipes in `references/fixes.md` are tested against the scanner itself, so the skill never recommends a fix it would then flag.
- **Calibrated on 14 real apps.** The first pass was noisy: "CVV" in comments, nginx `geolocation=()` headers read as location tracking, `.git` exclusions demanded where no `.git` existed. Fixing those cut high and medium findings from 111 to 40, and every issue that had already been found by hand was still caught.
- A full project scan takes well under a second for a typical app.

---

## <img src="assets/icons/download.svg" width="20" align="absmiddle" alt="" /> Install

### <img src="assets/icons/terminal.svg" width="17" align="absmiddle" alt="" /> Claude Code (any platform)

```bash
claude plugin marketplace add IPedrax/ComplianceHelper
```

```bash
claude plugin install compliance@compliance
```

### <img src="assets/icons/monitor.svg" width="17" align="absmiddle" alt="" /> From a local clone

```bash
claude plugin marketplace add ./ComplianceHelper && claude plugin install compliance@compliance
```

> **Restart Claude Code after installing.** The hooks come with the plugin, so there's nothing to add to `settings.json`. Copying only `skills/Compliance` into `~/.claude/skills/` gives you the skill without the automatic checks.

---

## <img src="assets/icons/chat.svg" width="20" align="absmiddle" alt="" /> How to use it

Build as usual; the hooks run on their own. Or ask:

- "is this compliant?" / "can we launch?" / "GDPR and LGPD check on this repo"
- "are we SOC 2 ready?" / "privacy review before the enterprise deal"
- `/Compliance` for the full workflow

The scripts also run on their own, in CI for instance:

```bash
python3 skills/Compliance/scripts/scan.py path/to/app --fail-on high
```

```bash
python3 skills/Compliance/scripts/app_scan.py https://staging.example.com --out path/to/app/.compliance
```

---

## <img src="assets/icons/globe.svg" width="20" align="absmiddle" alt="" /> Configuration

All optional, in the project's `.compliance/` folder. Commit these two; the reports stay ignored.

```json
{"markets": ["BR", "US"], "children": false, "sectors": ["health"], "sells_to": ["government"], "distributed": false}
```

`profile.json` narrows the laws to where your users are. Undeclared, the scan assumes the EU, UK, US and Brazil, the strictest common baseline, and says so. `ignore_features` corrects a wrong detection, and `"hooks": false` turns the hooks off for one project.

```json
[{"rule": "SEC-HASH", "path": "src/coturn.ts", "reason": "TURN spec mandates MD5", "until": "2027-01-01"}]
```

`waivers.json` records risks you've accepted. They stay visible in the report and expire on the date you set.

A `compliance-ignore: RULE-ID reason` comment on a line, or on the line above it, marks a false positive. `COMPLIANCE_DISABLE=1` in the environment turns every hook off.

---

## <img src="assets/icons/check.svg" width="20" align="absmiddle" alt="" /> Verify

```bash
claude plugin validate .
```

```bash
python3 tests/test_compliance.py
```

```bash
python3 skills/Compliance/scripts/scan.py --rules
```

---

## <img src="assets/icons/file.svg" width="20" align="absmiddle" alt="" /> A note on what this is for

This is an engineering tool. It catches the technical gaps that make products fail security reviews, app store checks and diligence, and it keeps catching them as the code changes.

It is not legal advice, an audit or a certification. A clean scan means the automated checks found nothing, not that a regulator or auditor would agree, and the report's "Still needs you" column is there so nobody mistakes one for the other. For decisions with real legal weight, bring in a lawyer or an auditor, and hand them the report.

---

## <img src="assets/icons/file.svg" width="20" align="absmiddle" alt="" /> License

Compliance is [MIT](LICENSE). Framework names belong to their owners; the rule mappings are summaries, not reproductions of the standards.

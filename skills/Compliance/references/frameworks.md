# Frameworks: what each one needs beyond the scan

Read the entry for each framework the report says applies. Each one covers what triggers
it, which scanner rules already cover it, what only a human can supply, and the dates or
numbers that matter. Dates are as of September 2026. Check the primary source before you
rely on one for a filing.

## Contents

1. Security baselines: SOC 2, ISO 27001, OWASP, NIST SSDF + SBOM, open-source licenses
2. Privacy: GDPR / UK GDPR, ePrivacy, CCPA/CPRA + states, LGPD, FTC Act 5, children, biometrics, health
3. Payments and consumer: PCI DSS, ROSCA, online consumer law (Brazil, EU), TCPA / CAN-SPAM / CASL
4. Platforms and product: DSA / Online Safety Act / DMCA, accessibility, app stores
5. AI: EU AI Act, NIST AI RMF / ISO 42001
6. Sector and government: GLBA, AML, FERPA, FedRAMP, CMMC, NIS2, DORA, Cyber Resilience Act
7. Other markets: Canada, China, India
8. Company and deal level (outside the code)

## 1. Security baselines

### SOC 2
- **Applies:** any product sold to businesses. Enterprise buyers ask for the Type II report.
- **Scanner covers:** secrets (SEC-KEY, SEC-SECRET, SEC-FALLBACK, INF-ENV), transport (SEC-TLS-OFF,
  SEC-HTTP), access config (SEC-CORS, SEC-COOKIE), change control (INF-LOCKFILE, INF-DEPLOY-MERGE).
- **Needs a human:** policies, access reviews, background checks, vendor management, an incident
  response plan, and an audit window (usually 6 to 12 months) with evidence collected throughout.
  Evidence tools (Vanta, Drata and the like) automate that part; this scanner doesn't.

### ISO/IEC 27001:2022
- **Applies:** enterprise and international sales, especially in the EU.
- **Scanner covers:** the Annex A technological controls it can see: A.5.17 authentication
  information, A.8.9 configuration, A.8.12 data leakage, A.8.24 cryptography, A.8.28 secure coding.
- **Needs a human:** ISMS scope, risk assessment, Statement of Applicability, internal audit,
  management review, and certification by an accredited body. Certificates on the 2013 version
  expired Oct 31, 2025.

### OWASP Top 10 / ASVS
- **Applies:** any web or mobile app.
- **Scanner covers:** injection (SEC-SQLI, SEC-CMDI, SEC-EVAL, SEC-XSS), cryptographic failures
  (SEC-HASH, SEC-RANDOM, SEC-TLS-OFF), misconfiguration (SEC-DEBUG, SEC-CORS, INF-NGINX-*),
  authentication failures (SEC-COOKIE and the secret rules).
- **Needs a human:** a third-party pentest before launch and yearly after; authorization logic on
  every route (a judgment check in the skill). Google's CASA assessment, required for apps using
  restricted Gmail or Drive scopes, is built on ASVS.

### NIST SSDF + SBOM
- **Applies:** always as evidence; the EU Cyber Resilience Act makes an SBOM mandatory for products it covers.
- **Scanner covers:** INF-LOCKFILE.
- **Needs a human:** an SBOM per release (`npx @cyclonedx/cyclonedx-npm`, `syft`, `cyclonedx-py`),
  code review records, CI security checks.

### Open-source licenses (OpenChain ISO/IEC 5230)
- **Applies:** every product with dependencies.
- **Scanner covers:** OSS-LICENSE reads production dependencies from `package-lock.json`, or
  installed packages when there's no lockfile. AGPL, SSPL and non-commercial licenses are high,
  GPL is medium (high for distributed apps), and MPL, LGPL and EPL collapse into one info line.
- **Needs a human:** a NOTICE file with attributions. Before an acquisition, a full scan (Black Duck
  or similar) that also catches copied snippets and native code.

## 2. Privacy

### GDPR / UK GDPR
- **Applies:** personal data of people in the EU or UK when you offer them goods or services or
  monitor them, wherever your company is.
- **Scanner covers:** consent (PRV-CONSENT, PRV-PRECHECK), transparency (PRV-NOTICE), rights
  (PRV-DELETE, PRV-EXPORT), security (Art. 32 across the SEC rules, PRV-URL, SEC-LOG), children
  (PRV-AGE), special categories (PRV-BIOMETRIC, PRV-HEALTH-TRACKING).
- **Needs a human:** records of processing (Art. 30); a lawful basis per purpose; a DPIA for
  high-risk processing (Art. 35); DPAs with every processor, plus a transfer mechanism for non-EU
  ones (the EU-US Data Privacy Framework survived its first court challenge in Sept 2025, but keep
  SCCs as the fallback, because both frameworks before it were struck down); an EU or UK
  representative if you have no establishment there (Art. 27); breach notice to the regulator
  within 72 hours; access requests answered within one month. UK: pay the ICO data protection fee.
  The Data (Use and Access) Act 2025 amends UK GDPR.
- **Penalties:** up to 4% of global annual turnover or 20M euros, whichever is higher.

### ePrivacy Directive (cookies)
- **Applies:** storing or reading anything on a user's device in the EU or UK (cookies,
  localStorage, SDK identifiers), unless it is strictly necessary for what the user asked for.
- **Scanner covers:** PRV-CONSENT, PRV-PRECHECK, and app_scan's APP-TRACKERS and APP-COOKIE-TRACKING.
- **Needs a human:** a cookie policy listing each cookie and SDK, and a real-browser check that
  Reject actually blocks. The CNIL fined Amazon 35M euros in 2020 for ad cookies set on arrival.

### CCPA/CPRA and other US state laws
- **Applies (CCPA):** for-profit businesses handling California residents' data that pass one
  threshold: $26.6M annual revenue (2025 adjustment), buying, selling or sharing the personal
  information of 100,000+ consumers or households, or earning half their revenue from selling or
  sharing it. About 20 states have comprehensive laws with their own thresholds, often lower.
- **Scanner covers:** PRV-OPTOUT (Do Not Sell or Share, Global Privacy Control), PRV-NOTICE,
  PRV-DELETE, PRV-EXPORT, PRV-GEO (sensitive data), PRV-PRECHECK (dark patterns).
- **Needs a human:** notice at collection, a privacy policy updated at least yearly, service-provider
  contracts, requests answered within 45 days. The CPPA's rules on automated decision-making, risk
  assessments and cybersecurity audits took effect Jan 1, 2026; audit certifications are due from
  April 1, 2028, largest businesses first. Maryland's law is the strictest on data minimization.

### LGPD (Brazil)
- **Applies:** processing in Brazil, offering goods or services to people in Brazil, or data collected there.
- **Scanner covers:** the same privacy rules as GDPR (LGPD Art. 7, 8, 9, 14, 18, 46).
- **Needs a human:** a named encarregado (DPO) with a public contact; a legal basis per purpose; the
  ANPD's standard clauses for international transfers (the adaptation period ended Aug 2025);
  incident notice to the ANPD and the people affected within 3 business days; access requests
  answered within 15 days.
- **Penalties:** up to 2% of revenue in Brazil, capped at R$50M per infraction.

### FTC Act 5 and the Consumer Reviews Rule (US)
- **Applies:** any US consumer-facing business.
- **Scanner covers:** FTC-RATING (hardcoded ratings in structured data), PRV-HEALTH-TRACKING.
- **Needs a human:** privacy and security claims that match what the code does (saying one thing and
  doing another is the classic FTC deception case); no fake reviews or undisclosed incentivized ones
  (16 CFR 465, in force since Oct 21, 2024). FTC orders usually last 20 years and bind successors,
  and the FTC has ordered companies to delete models trained on improperly collected data.

### Children's privacy (COPPA, GDPR Art. 8, LGPD Art. 14, UK Children's Code, DPDP)
- **Applies:** services directed to children, or that know children use them. The age line is under
  13 in the US, under 16 by default in the EU (member states may lower it to 13), and under 18 in
  India's DPDP Act.
- **Scanner covers:** PRV-AGE (birth dates or a kids audience without an age gate).
- **Needs a human:** decide the audience. Get verifiable parental consent before collecting anything
  from under-13s. The amended COPPA rule (compliance date April 22, 2026) adds separate consent for
  disclosure to third parties, a written retention policy and a written security program. Epic paid
  a $275M COPPA penalty in 2022.

### Biometrics (BIPA, Texas CUBI, Washington My Health My Data Act)
- **Applies:** face geometry, voiceprints, fingerprints, iris scans, including KYC selfies.
- **Scanner covers:** PRV-BIOMETRIC.
- **Needs a human:** written consent that names the purpose and retention period before capture; a
  public retention and destruction schedule (destroy when the purpose ends, and within 3 years of the
  last interaction at the latest); a DPIA under GDPR. BIPA allows private suits at $1,000 per
  negligent and $5,000 per reckless violation. Facebook settled a BIPA class action for $650M, and
  Texas took $1.4B from Meta under CUBI.

### Health data (HIPAA, FTC Health Breach Notification Rule)
- **Applies:** HIPAA if you are a covered entity (provider, health plan, clearinghouse) or one's
  business associate. The FTC's HBNR covers health apps outside HIPAA. Washington's MHMDA covers
  consumer health data and lets people sue.
- **Scanner covers:** PRV-HEALTH-TRACKING, and the HIPAA 164.312 mappings on transport and secret rules.
- **Needs a human:** BAAs with every vendor that touches PHI; a documented risk analysis (45 CFR
  164.308), one of the gaps OCR cites most; breach notification procedures. GoodRx paid $1.5M in
  2023, in the first HBNR case, for sharing health data with ad platforms.

## 3. Payments and consumer law

### PCI DSS v4.0.1
- **Applies:** storing, processing or transmitting cardholder data, or affecting the security of the
  systems that do.
- **Scanner covers:** PCI-CARD (raw card fields), the secret rules, transport.
- **Needs a human:** confirm the SAQ type (SAQ A when card data never touches your servers, as with
  Stripe Checkout or Elements) and complete the annual self-assessment and Attestation of Compliance.
  Every v4 requirement has been mandatory since March 31, 2025.

### ROSCA and state auto-renewal laws (US)
- **Applies:** subscriptions, trials that convert, any negative-option billing.
- **Scanner covers:** CON-CANCEL, CON-TERMS.
- **Needs a human:** material terms disclosed before billing, express informed consent, simple online
  cancellation. The FTC's click-to-cancel rule was vacated in July 2025, but ROSCA stands: Amazon
  agreed to pay $2.5B in Sept 2025 over Prime's sign-up and cancellation flows. California's
  auto-renewal law adds its own notice rules.

### Online consumer law (Brazil CDC + Decreto 7.962/2013, EU Consumer Rights Directive)
- **Applies:** selling online to consumers in Brazil, the EU or the UK.
- **Scanner covers:** CON-TERMS.
- **Needs a human:** seller identity (CNPJ or company number), address and contact on the site; a
  clear summary of the offer before payment; the withdrawal right for online purchases, 7 days in
  Brazil (CDC Art. 49) and 14 days in the EU and UK.

### TCPA, CAN-SPAM, CASL
- **Applies:** marketing texts or calls to US numbers (TCPA), commercial email (CAN-SPAM), commercial
  electronic messages to Canadians (CASL, which needs consent up front).
- **Scanner covers:** MKT-SMS, MKT-UNSUB.
- **Needs a human:** consent records with timestamp and source; a physical postal address in
  marketing email; unsubscribes honored within 10 business days; a one-click List-Unsubscribe header
  for Gmail and Yahoo bulk sending. TCPA damages are $500 per message, trebled to $1,500 if willful.

## 4. Platforms and product

### DSA, UK Online Safety Act, DMCA
- **Applies:** hosting user content in the EU (the DSA scales duties up for platforms and very large
  ones); user-to-user or search services with UK users (OSA); US hosting that wants the DMCA 512 safe harbor.
- **Scanner covers:** PLT-REPORT (user content without a report or moderation path).
- **Needs a human:** content rules and moderation explained in the terms; a notice-and-action process;
  UK illegal-content and children's risk assessments (children's duties, including age assurance,
  apply since July 25, 2025); a DMCA agent registered with the US Copyright Office, renewed every 3 years.

### Accessibility (WCAG 2.2 AA; ADA, Section 508, European Accessibility Act)
- **Applies:** any UI. The EAA applies since June 28, 2025 to e-commerce, banking, e-books, transport
  ticketing and more in the EU (micro-enterprises providing services are exempt). US ADA suits cite
  WCAG; federal buyers require Section 508 and a VPAT/ACR.
- **Scanner covers:** the A11Y rules, plus app_scan's APP-LANG, APP-ALT and APP-ZOOM.
- **Needs a human:** an automated audit (Lighthouse or axe) plus manual keyboard and screen-reader
  testing; an accessibility statement; a VPAT/ACR for enterprise and public-sector buyers.

### Apple App Store and Google Play
- **Applies:** any mobile app.
- **Scanner covers:** PRV-DELETE (high for mobile), PRV-NOTICE.
- **Needs a human:** in-app account deletion (Apple guideline 5.1.1(v); Google Play also wants a web
  deletion link); a privacy label and Data safety form that match every SDK the report lists.

## 5. AI

### EU AI Act
- **Applies:** providing or deploying AI systems in the EU.
- **Scanner covers:** AI-DISCLOSE (Art. 50(1)), AI-LABEL (Art. 50(2) and (4)), AI-COST.
- **Needs a human:** classify each AI feature. The bans have applied since Feb 2, 2025 (the AI
  Omnibus adds nudifier apps and AI-generated CSAM to them); general-purpose model duties since
  Aug 2, 2025; Art. 50 transparency since Aug 2, 2026, with machine-readable marking for systems
  already on the market due by Dec 2, 2026. The AI Omnibus (Regulation (EU) 2026/1744, in force
  July 27, 2026) moved high-risk duties to Dec 2, 2027 for Annex III systems and Aug 2, 2028 for AI
  inside regulated products.

### NIST AI RMF / ISO/IEC 42001
- **Applies:** any AI product. ISO 42001 is certifiable and comes up more and more in AI vendor reviews.
- **Scanner covers:** AI-COST.
- **Needs a human:** a model and vendor inventory, evaluations and red-team notes, training-data
  provenance and rights, incident handling for model failures.

## 6. Sector and government

- **GLBA Safeguards Rule / NYDFS Part 500** (US fintech, lending, insurance): a written security
  program, a named qualified individual, MFA, encryption, and FTC notice within 30 days of a breach
  affecting 500+ consumers.
- **BSA/AML and money transmission** (anything that moves or holds money): FinCEN MSB registration,
  state money transmitter licenses or a sponsor bank, a KYC/AML program. Unlicensed money
  transmission is a federal crime. EU: PSD2 or EMI licensing.
- **FERPA and state student privacy laws** (edtech serving US schools): a signed data privacy
  agreement per district, and no advertising or profiling on student data.
- **FedRAMP / GovRAMP** (US federal cloud; states through GovRAMP, formerly StateRAMP):
  authorization at Low, Moderate or High against NIST SP 800-53 Rev. 5 baselines, with a 3PAO.
  FedRAMP 20x is shortening the path.
- **CMMC 2.0 / NIST SP 800-171** (defense contractors handling CUI): SPRS score and self-assessment
  now; third-party (C3PAO) Level 2 certification starts appearing in contracts Nov 10, 2026.
- **NIS2** (EU cloud, data centers, MSPs, marketplaces, social networks, search; 50+ staff or 10M+
  euros turnover): 24-hour early warning and 72-hour incident notice, management accountability,
  supply-chain security.
- **DORA** (selling to EU banks, insurers, investment firms; applies since Jan 17, 2025): Art. 30
  contract clauses, incident support, exit plans.
- **EU Cyber Resilience Act** (software or hardware sold in the EU; pure SaaS is mostly out): report
  actively exploited vulnerabilities and severe incidents to ENISA within 24 hours (mandatory since
  Sept 11, 2026, including for products already on the market); vulnerability handling, an SBOM and at
  least 5 years of security updates; everything else, CE marking included, from Dec 11, 2027. The
  scanner's INF-SECTXT covers the disclosure contact.

## 7. Other markets (declare them in profile.json)

- **Canada (PIPEDA, Quebec Law 25):** a privacy officer, consent, and a privacy impact assessment
  before Quebec data leaves Quebec. CASL covers marketing messages.
- **China (PIPL, DSL, CSL):** data localization, CAC filings for cross-border transfers, periodic
  PIPL compliance audits.
- **India (DPDP Act 2023):** Rules notified Nov 13, 2025; consent-manager provisions from Nov 13,
  2026; most duties from May 13, 2027. Verifiable parental consent for anyone under 18.

## 8. Company and deal level (outside the code)

The scanner can't see these, but acquirers and enterprise buyers check them:

- **Certifications and reports:** SOC 1 Type II (if you touch customers' financial reporting),
  ISO/IEC 27701 (privacy), ISO/IEC 27017 and 27018 (cloud), ISO 22301 (continuity), CSA STAR,
  HITRUST (US health buyers).
- **Corporate:** SOX 404 readiness under a public acquirer (SEC staff guidance lets it exclude an
  acquired business from its ICFR assessment for up to a year), FCPA and UK Bribery Act successor
  liability, SEC 8-K Item 1.05 breach disclosure within 4 business days of deciding it is material.
- **Trade:** OFAC sanctions screening and geoblocking (the statute of limitations has been 10 years
  since 2024), export classification of your encryption (usually ECCN 5D992, or 5D002 under License
  Exception ENC), and the DOJ Data Security Program if bulk US personal data is reachable from
  countries of concern (in force April 8, 2025).
- **Deal clearance (the buyer's filings):** HSR above $133.9M (2026 threshold), EU Merger Regulation
  and DMA Art. 14 notices for gatekeepers, the UK NSIA for sensitive sectors including AI, CFIUS for
  foreign buyers.

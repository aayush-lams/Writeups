# Passive Recon Case Study — RBB Bank Phishing Kit (Firebase + Vercel)

**Date:** August 2026  
**Target:** `rastriya-banijya-bank.web.app` / `rastriya-banijya-bank.firebaseapp.com`  
**Assessment Type:** Passive Reconnaissance (non-intrusive)  
**Supporting Files:** [`raw_output.json`](../raw_output.json), [`report.md`](../report.md)

---

## Overview

This case study documents the passive reconnaissance of a phishing site impersonating **Rastriya Banijya Bank (RBB)**, a Nepali government-owned commercial bank. The site was discovered in the wild hosted at:

- `rastriya-banijya-bank.web.app`
- `rastriya-banijya-bank.firebaseapp.com`

The phishing kit impersonates RBB's KYC update portal, luring victims with a fake "KYC re-verification" prompt. This is consistent with a documented fraud campaign — RBB issued public warnings in October and November 2025 about fraudulent KYC-update links exploiting the Gen-Z protest aftermath in Nepal. The lure preys on urgency and trust: users believe their bank account will be suspended unless they "re-verify" their identity through the provided link.

The objective of this assessment was to characterize the phishing infrastructure, identify the attacker's hosting choices, analyze the kit's architecture, and determine what data is being harvested — all without interacting with or exposing any real victim data.

---

## Methodology

All techniques employed were **passive and non-intrusive**:

1. **WHOIS** — Domain registration data from public registries.
2. **DNS** — Resource record enumeration (A, AAAA, NS, CNAME, TXT) from public resolvers.
3. **HTTP Headers** — Response header analysis from standard HTTP requests.
4. **TLS Certificate Inspection** — Certificate details extracted from the server's public endpoint.
5. **GeoIP** — IP geolocation via public databases.
6. **robots.txt / sitemap.xml** — Standard crawl directive and URL listing inspection.
7. **Passive Proxy Capture** — Burp Suite with intercept disabled, using fabricated test data to observe outbound traffic patterns without reading or storing any real victim submissions.

No brute forcing, no document-ID enumeration, no database access, and no interaction beyond a single test submission with clearly fabricated data was performed. The rationale for this boundary is detailed in the **Ethical/Legal Boundary** section below.

---

## Key Findings

### 1. Free, Zero-Attribution Hosting

Both `web.app` and `firebaseapp.com` resolve to Google/Firebase Hosting anycast infrastructure:

| Record | Value |
|--------|-------|
| A | `199.36.158.100` |
| AAAA | `2620:0:890::100` |
| GeoIP | Mountain View, CA, US (Fastly, Inc.) |

WHOIS queries for `RASTRIYA-BANIJYA-BANK.FIREBASEAPP.COM` return no match — the domain is a Firebase subdomain, not a separately registered domain. There is **no registrar trail, no registrant data, and no purchase record** to trace. Google's own infrastructure registration is the only information returned.

This is a deliberate choice: Firebase Hosting provides free-tier hosting with zero attribution. The attacker never purchased a domain, never registered with a registrar, and can burn and redeploy the front-end in minutes. DNS and WHOIS provide no attacker-identifying data whatsoever.

### 2. Split Architecture — Disposable Front-End, Persistent Back-End

The phishing kit uses a **split architecture**:

- **Front-end (Firebase):** The credential-harvesting HTML/JS form is hosted on `rastriya-banijya-bank.firebaseapp.com`. This is the disposable component — cheap to create, trivial to redeploy under a new subdomain if taken down.

- **Back-end (Vercel):** The actual data submission goes cross-origin via `fetch()` to a separate Vercel-hosted Express backend at `mero-khata.vercel.app/registerRBB`. This is the persistent component — it survives front-end takedowns and can receive submissions from any new front-end the attacker deploys.

This separation is a hallmark of modern phishing kit design. The front-end is ephemeral; the back-end is the real infrastructure. Disrupting one does not necessarily disrupt the other.

### 3. Backend Stack and Behavior

Response headers from the Vercel endpoint reveal:

| Header | Value |
|--------|-------|
| X-Powered-By | Express |
| Server | Vercel |
| Status | 201 Created |
| Response Body | `{"docID":"<20-char random ID>"}` |

The `201 Created` status with a returned `docID` field indicates the backend writes each submission to a **document database** (Firestore-style), not just relaying data via email. Stolen data is **persistently stored** in the attacker's database, enabling later retrieval, aggregation, and sale.

### 4. Harvested Data Fields — Full KYC Identity Theft

The multipart form fields captured during passive observation were:

| Field | Description |
|-------|-------------|
| `Username` | Bank username / login ID |
| `phoneNumber` | Phone number linked to the account |
| `password` | Account password |
| `transactionPin` | Transaction PIN (authorizes live transfers) |
| `FatherName` | Father's name (KYC identity field) |
| `citizenship` | Citizenship certificate number |
| `nin` | National ID Number |

This goes **beyond login credentials**. The kit is built to capture bank-grade identity verification data and the transaction PIN needed to authorize live transfers. This matches the "KYC re-verification" lure described in RBB's public fraud warnings — the form fields are specifically designed to support full identity theft and unauthorized transactions, not just account takeover.

### 5. Overly Permissive CORS on Backend

The Vercel endpoint at `mero-khata.vercel.app` returns:

```
Access-Control-Allow-Origin: *
```

This means **any origin** can POST to (and likely query) this backend. For a phishing kit, this is a real security weakness — it means:

- Any website can submit data to the attacker's database.
- The backend has no origin validation, making it trivially discoverable and potentially abusable by third parties.
- This is a viable reporting/disruption angle for platform abuse teams (Vercel) — the permissive CORS policy could facilitate unauthorized access to the stored victim data.

### 6. Missing Baseline Security Headers

The automated report ([`report.md`](../report.md)) identified 8 missing or misconfigured security headers on the phishing front-end:

| Severity | Finding |
|----------|---------|
| Medium | Missing Content Security Policy (CSP) |
| Medium | Missing Clickjacking Protection (X-Frame-Options) |
| Medium | TLS Certificate Approaching Expiry (72 days) |
| Low | Missing X-Content-Type-Options |
| Low | Missing Referrer-Policy |
| Low | Missing Permissions-Policy |
| Low | Missing Cross-Origin Isolation Headers |
| Low | Non-Restrictive Cache-Control (`max-age=3600`) |

These are standard hardening gaps and **not unique to malicious sites** — many legitimate sites also lack these headers. However, in this context they support the assessment that this is a hastily built phishing kit with no attention to defensive security posture. The presence of `Strict-Transport-Security` (HSTS) with preload is the only security header present, and this is likely a Firebase Hosting default rather than an attacker configuration choice.

---

## TLS Observations

| Field | Value |
|-------|-------|
| Subject | `firebaseapp.com` |
| Issuer | Google Trust Services (WR4) |
| SANs | `firebaseapp.com`, `*.firebaseapp.com` |
| Valid From | 2026-07-20 |
| Valid Until | 2026-10-18 |
| Days Until Expiry | 72 |

The certificate is a **shared Google Trust Services wildcard** covering all `*.firebaseapp.com` subdomains. It reveals nothing attacker-specific — this is the same certificate served to every Firebase Hosting project. The 72-day expiry window confirms the certificate was recently auto-renewed (Firebase manages TLS automatically). No attacker-specific TLS configuration was observed.

---

## Ethical/Legal Boundary Maintained

All assessment stayed within strict passive and ethical limits:

- **No brute forcing** of any kind.
- **No document-ID enumeration** or database access attempts.
- **No interaction** beyond a single test submission with **fabricated data**:

  | Field | Test Value | Label |
  |-------|------------|-------|
  | Username | `aswin` | Fabricated |
  | phoneNumber | `fake phone` | Fabricated |
  | password | `customerKYC` | Fabricated |
  | transactionPin | `0978` | Fabricated |

- **No real victim data was accessed, read, or stored.**

**Why this boundary matters:** The backend returns Firestore-style 20-character random document IDs on submission. Firestore document IDs are random strings drawn from a keyspace of ~62^20 (approximately 7 × 10^35 possibilities). They are not sequential, not guessable, and not practically enumerable. Any attempt to enumerate or access document IDs beyond the single test submission would risk accessing **real victims' stolen credentials** — a legal and ethical line regardless of intent or authorization. The passive recon scope was sufficient to characterize the kit's architecture, data fields, and infrastructure without crossing this line.

---

## Recommended Takedown/Reporting Actions

| Action | Target | Details |
|--------|--------|---------|
| **Google Safe Browsing Report** | `rastriya-banijya-bank.web.app` / `rastriya-banijya-bank.firebaseapp.com` | Report via [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/) — flag as phishing site impersonating a financial institution. |
| **Firebase/Google Abuse Report** | Firebase Hosting project | Report via [Google Cloud Abuse](https://support.google.com/firebase/answer/1711204) — Firebase subdomain used for phishing. |
| **Vercel Abuse Report** | `mero-khata.vercel.app` | Email `abuse@vercel.com` with evidence of the backend at `/registerRBB` accepting stolen credential submissions. Include the CORS policy (`Access-Control-Allow-Origin: *`) as evidence of the backend's role. |
| **Direct Report to RBB** | Rastriya Banijya Bank | RBB has **publicly solicited** reports of fraudulent sites impersonating the bank. Forward findings directly to their fraud/compliance team. |

---

## Lessons Learned / Skills Demonstrated

| Skill | Application |
|-------|-------------|
| **Domain-level WHOIS/DNS recon** | Queried WHOIS (no match — Firebase subdomain), enumerated A/AAAA/TXT records, identified SPF/DKIM records. |
| **Hosting-platform fingerprinting** | Distinguished Firebase Hosting (front-end) from Vercel (back-end) via response headers, DNS resolution, and URL patterns. |
| **Passive proxy traffic analysis** | Used Burp Suite (intercept off) to capture request/response patterns with fabricated test data. |
| **HTTP response fingerprinting** | Identified Express + Vercel stack via `X-Powered-By` and `Server` headers; noted missing security headers as kit-characterization evidence. |
| **Phishing kit architecture analysis** | Mapped the front-end/back-end split (Firebase → Vercel), identified the cross-origin `fetch()` data exfiltration pattern, and classified the kit as a modern disposable-front-end design. |
| **Sensitive-data-field risk classification** | Analyzed form fields and determined the kit targets full KYC identity theft (citizenship, NID, transaction PIN) beyond simple credential phishing. |
| **IDOR-style enumeration boundary recognition** | Recognized that Firestore's random document ID scheme (~62^20 keyspace) is not practically guessable, and chose not to enumerate — preserving the ethical/legal line. |

---

## Files in This Writeup

| File | Description |
|------|-------------|
| `raw_output.json` | Raw JSON output from the passive recon tool (WHOIS, DNS, GeoIP, headers, TLS, robots/sitemap). |
| `report.md` | Auto-generated markdown report summarizing security header findings and recommendations. |
| `writeup.md` | This document — the full case study writeup. |

---

*This writeup is intended for educational and portfolio purposes. No real victim data, live document IDs, bot tokens, or credentials beyond the documented fabricated test values are included. All infrastructure has been reported through appropriate channels.*

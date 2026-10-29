# Passive Reconnaissance Report

**Target:** rastriya-banijya-bank.firebaseapp.com
**Generation Time (UTC):** 2026-08-07 15:00:55 UTC
**Tool Version:** 1.0.0
**Assessment Type:** Passive Reconnaissance

---

## Executive Summary



The passive reconnaissance of the target identified 8 observation(s) across HTTP security headers, TLS certificate configuration, DNS settings, and domain intelligence.

3 observation(s) were classified as Medium priority.
5 observation(s) were classified as Low priority.

---

## Scope

- Only passive, non-intrusive techniques were employed.
- No exploitation was performed.
- No authentication was attempted.
- No brute forcing was conducted.
- No vulnerability scanning was performed.
- No intrusive testing was carried out.
- All information was obtained from publicly available sources.

---

## Methodology

All information was collected from publicly available sources using passive reconnaissance techniques. No direct interaction with the target infrastructure was performed beyond standard HTTP requests and DNS queries available to any Internet user.

1. WHOIS — Domain registration data from public registries.
2. DNS — Resource record enumeration from public resolvers.
3. HTTP Headers — Response header analysis from public web servers.
4. TLS Certificate — Certificate details from the server's public endpoint.
5. robots.txt — Standard crawl directive file.
6. sitemap.xml — Structured URL listing.
7. GeoIP — IP geolocation from public databases.
8. Public infrastructure — All data sourced from publicly accessible information.

---

## Summary of Findings

Severity | Finding                                 | Category             
-------- | --------------------------------------- | ---------------------
Medium   | Missing Content Security Policy Header  | HTTP Security Headers
Medium   | Missing Clickjacking Protection Header  | HTTP Security Headers
Medium   | TLS Certificate Approaching Expiry      | TLS Certificate      
Low      | Missing X-Content-Type-Options Header   | HTTP Security Headers
Low      | Missing Referrer-Policy Header          | HTTP Security Headers
Low      | Missing Permissions-Policy Header       | HTTP Security Headers
Low      | Missing Cross-Origin Isolation Headers  | HTTP Security Headers
Low      | Non-Restrictive Cache-Control Directive | HTTP Security Headers

---

## Detailed Findings

### Finding SEC-001: Missing Content Security Policy Header

**Severity:** Medium
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include the Content-Security-Policy response header. This header defines approved sources of content that browsers are allowed to load.

**Evidence:**
The Content-Security-Policy header was not present in the HTTP response.
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
Without a content security policy, the application has no browser-enforced restrictions on content sources, which may increase exposure to cross-site scripting and data injection.

**Recommendation:**
Deploy a Content-Security-Policy header. Start with a report-only policy to identify legitimate content sources before enforcing.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
---

### Finding SEC-005: Missing Clickjacking Protection Header

**Severity:** Medium
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include the X-Frame-Options header or a Content-Security-Policy with a frame-ancestors directive. These headers prevent the page from being embedded in frames on other origins.

**Evidence:**
The X-Frame-Options / frame-ancestors header was not present in the HTTP response.
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
The page may be embeddable in frames on third-party sites, which could facilitate clickjacking attacks.

**Recommendation:**
Set the X-Frame-Options header to DENY or SAMEORIGIN, or configure a Content-Security-Policy with an appropriate frame-ancestors directive.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
---

### Finding SEC-008: TLS Certificate Approaching Expiry

**Severity:** Medium
**Category:** TLS Certificate

**Description:**
The TLS certificate will expire within 90 days. While not immediately critical, this should be monitored.

**Evidence:**
Certificate issuer: countryName=US, organizationName=Google Trust Services, commonName=WR4
Valid until: 2026-10-18T15:01:15+00:00
Days remaining: 72

**Impact:**
Certificate expiry may result in service disruption and client-side security warnings.

**Recommendation:**
Renew the TLS certificate before expiry and configure automated renewal to prevent future lapses.
---

### Finding SEC-002: Missing X-Content-Type-Options Header

**Severity:** Low
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include the X-Content-Type-Options response header. This header prevents browsers from MIME-sniffing a response away from the declared content type.

**Evidence:**
The X-Content-Type-Options header was not present in the HTTP response.
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
Browsers may attempt to guess the content type of responses, which could lead to security issues if the guessed type differs from the declared type.

**Recommendation:**
Configure the web server to return X-Content-Type-Options: nosniff.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
---

### Finding SEC-003: Missing Referrer-Policy Header

**Severity:** Low
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include the Referrer-Policy response header. This header controls how much referrer information is included with navigation requests.

**Evidence:**
The Referrer-Policy header was not present in the HTTP response.
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
Full referrer information may be sent to third-party sites on navigation, potentially exposing URL paths, query parameters, or other sensitive data.

**Recommendation:**
Configure the web server to return a Referrer-Policy header such as strict-origin-when-cross-origin or no-referrer.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
---

### Finding SEC-004: Missing Permissions-Policy Header

**Severity:** Low
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include the Permissions-Policy response header. This header restricts which browser features the site can use.

**Evidence:**
The Permissions-Policy header was not present in the HTTP response.
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
Without a permissions policy, the browser grants default access to features such as camera, microphone, and geolocation, which could be exploited via cross-site scripting.

**Recommendation:**
Deploy a Permissions-Policy header that restricts browser features to only those required by the application.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
---

### Finding SEC-006: Missing Cross-Origin Isolation Headers

**Severity:** Low
**Category:** HTTP Security Headers

**Description:**
The HTTP response did not include one or more cross-origin isolation headers (COOP, COEP, CORP, or related policies). These headers reduce the risk of cross-origin side-channel attacks.

**Evidence:**
Missing headers: cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-request-policy, cross-origin-resource-policy
Observed headers:
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload

**Impact:**
Without cross-origin isolation headers, the site may be more susceptible to cross-origin information leakage through side-channel attacks.

**Recommendation:**
Evaluate and deploy Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and Cross-Origin-Resource-Policy headers as appropriate for the application.

**References:**
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Opener_Policy
---

### Finding SEC-007: Non-Restrictive Cache-Control Directive

**Severity:** Low
**Category:** HTTP Security Headers

**Description:**
The Cache-Control header was set without directives that prevent caching of potentially sensitive responses.

**Evidence:**
Cache-Control: max-age=3600

**Impact:**
Responses may be cached by browsers or intermediate proxies, potentially exposing sensitive data to subsequent users.

**Recommendation:**
Include no-store, no-cache, private, or must-revalidate in the Cache-Control header for responses containing sensitive data.

---

## Recommendations

### Medium Priority
- **Missing Content Security Policy Header:** Deploy a Content-Security-Policy header. Start with a report-only policy to identify legitimate content sources before enforcing.
- **Missing Clickjacking Protection Header:** Set the X-Frame-Options header to DENY or SAMEORIGIN, or configure a Content-Security-Policy with an appropriate frame-ancestors directive.
- **TLS Certificate Approaching Expiry:** Renew the TLS certificate before expiry and configure automated renewal to prevent future lapses.

### Low Priority
- **Missing X-Content-Type-Options Header:** Configure the web server to return X-Content-Type-Options: nosniff.
- **Missing Referrer-Policy Header:** Configure the web server to return a Referrer-Policy header such as strict-origin-when-cross-origin or no-referrer.
- **Missing Permissions-Policy Header:** Deploy a Permissions-Policy header that restricts browser features to only those required by the application.
- **Missing Cross-Origin Isolation Headers:** Evaluate and deploy Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and Cross-Origin-Resource-Policy headers as appropriate for the application.
- **Non-Restrictive Cache-Control Directive:** Include no-store, no-cache, private, or must-revalidate in the Cache-Control header for responses containing sensitive data.


---

## Appendix

### Appendix A: DNS Records

```
{
  "status": "ok",
  "records": {
    "A": [
      "199.36.158.100"
    ],
    "AAAA": [
      "2620:0:890::100"
    ],
    "NS": [],
    "CNAME": [],
    "TXT": [
      "\"v=spf1 redirect=_spf.google.com\"",
      "\"v=DKIM1; k=rsa; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPtW5iwpXVPiH5FzJ7Nrl8USzuY9zqqzjE0D1r04xDN6qwziDnmgcFNNfMewVKN2D1O+2J9N14hRprzByFwfQW76yojh54Xu3uSbQ3JP0A7k8o8GutRF8zbFUA8n0ZH2y0cIEjMliXY4W4LwPA7m4q0ObmvSjhd63O9d8z1XkUBwIDAQAB\""
    ]
  }
}
```

### Appendix B: HTTP Headers

```
{
  "status": "ok",
  "final_url": "https://rastriya-banijya-bank.firebaseapp.com/",
  "status_code": 200,
  "redirected": true,
  "headers": {
    "Cache-Control": "max-age=3600",
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31556926; includeSubDomains; preload"
  },
  "redirect_history": []
}
```

### Appendix C: TLS Certificate

```
{
  "status": "ok",
  "subject": "commonName=firebaseapp.com",
  "issuer": "countryName=US, organizationName=Google Trust Services, commonName=WR4",
  "valid_from": "2026-07-20T15:01:16+00:00",
  "valid_until": "2026-10-18T15:01:15+00:00",
  "days_until_expiry": 72,
  "subject_alt_names": [
    "firebaseapp.com",
    "*.firebaseapp.com"
  ]
}
```

### Appendix D: robots.txt

```
# https://www.robotstxt.org/robotstxt.html
User-agent: *
Disallow:

```

### Appendix E: sitemap.xml

_No data available._


---

*This report was generated automatically from publicly available sources. Raw data is available in `raw_output.json`. This is a passive reconnaissance summary and is not a security assessment or list of exploitable vulnerabilities.*
---
layout: default
title: Recon Tool
---

# Building a Passive Recon Tool to Understand Web Security Better

System backend is a vast topic. No two applications share the same mechanism, let alone the same backend. Each one has its own architecture, security posture, and weak points. The more we understand a system’s backend, the more we start to see how its security holds up, things like header policies, TLS configuration, DNS hygiene, and what information it leaks publicly.

I created this simple recon tool to get a better understanding of a web application from a security point of view. This tool uses various passive recon techniques to gather information about a domain for initial security analysis.

The goal was not to create a perfect scanner right from the get-go. It was also not meant to be an exploit tool or a vulnerability scanner. I wanted something simple that helps me understand what kind of public information a normal website exposes and how that information can be connected together.

Passive reconnaissance means collecting information without doing intrusive scanning, exploitation, brute forcing, or anything aggressive. Everything comes from public sources: DNS resolvers, WHOIS registries, the web server’s own HTTP responses, TLS certificates, `robots.txt`, and `sitemap.xml`. It is the same information any normal visitor or public service could get, but collected in one place and turned into a bigger picture.

That is where this tool comes in. Instead of running multiple commands separately and stitching the output together by hand, it does the collection in one flow and produces a proper report with findings, evidence, and recommendations.

## Why I Chose Python and Nix Flakes

I chose Python as the language for this tool because it is simple and quick to get working. For a learning project, that mattered a lot. I wanted to learn the concepts along the way rather than spend too much time trying to make the tool perfect from the beginning.

For environment management, I used a Nix flake to create a shell environment for the Python packages.

I did not use `pyenv` here because I am using NixOS, and I wanted to respect the declarative and controlled nature of the system. I did not want the dependencies to scatter throughout the system. A Nix flake creates a controlled shell environment where the Python packages I install are limited to that shell. It basically does not bleed outside of it.

That made the setup feel cleaner and more reproducible.

## Packages I Used

For the packages, I tried to keep the dependencies minimal while still not implementing everything from scratch.

The main Python packages I used were:

- `dnspython`
- `requests`
- `python-whois`

`python-whois` was necessary for WHOIS lookup, which gives domain registration data from public registrars.

`requests` was used for standard HTTP requests while maintaining convenience and ease of use.

`dnspython` was used for DNS queries like `A`, `AAAA`, `NS`, `CNAME`, and `TXT` records.

This minimal dependency list also kept the project easier to understand. Since the goal was learning, I did not want too much magic hidden behind large frameworks.

## Basic Architecture of the Tool

The tool is separated into two big parts:

1. Recon modules  
2. Reporting engine  

The recon modules are responsible for collecting specific types of information. Each module has one job. The main function of the tool goes through these modules one by one and gathers information about the domain we provide when running the tool.

While writing this logic, I realized that even a seemingly normal website has many layers of public information around it. A domain is not just a domain. It has registration history, DNS records, IP addresses, certificates, HTTP headers, crawler rules, and sometimes small details that can reveal how the infrastructure is set up.

The reporting engine then takes the raw collected data and turns it into something readable. Instead of just dumping JSON into the terminal, it creates a markdown report with a summary, findings, evidence, recommendations, and raw data in the appendix.

That part was important to me because raw data alone is not always useful. A terminal dump may look interesting in the moment, but after a week it becomes hard to remember what mattered. A proper report gives structure to the findings.

The rough flow looks like this:

```text
target domain
  -> main.py runs each recon module
  -> raw results are saved to raw_output.json
  -> report engine analyzes the data
  -> findings are generated with severity, evidence, and recommendation
  -> final markdown report is written to report.md
```

## What the Recon Modules Check

### WHOIS Lookup

WHOIS lookup is used to query domain registry information. It can provide details like:

- registrar
- creation date
- expiration date
- domain age
- name servers
- domain status
- DNSSEC status

This information gives general context about the domain. It can show where the domain is registered, how old it is, when it expires, and whether DNSSEC is enabled.

This does not directly tell us how the application stores user credentials or how the internal backend works, but it does provide useful public context about the domain’s security posture.

For example, a recently registered domain may be worth looking at more carefully in some cases. An expiring domain or missing DNSSEC may also be useful observations depending on the situation.

### DNS Records

After WHOIS, the tool checks DNS records. It currently looks for:

- `A`
- `AAAA`
- `NS`
- `CNAME`
- `TXT`

`A` records give IPv4 addresses, and `AAAA` records give IPv6 addresses. These records help identify where the domain points.

`NS` records show the name servers responsible for the domain.

`CNAME` records can reveal aliases or external services being used.

`TXT` records are also interesting because they often contain verification records or service-related configuration. Sometimes they show information about mail services, domain verification, or third-party tools connected to the domain.

DNS data is one of those things that looks boring at first, but it gives a lot of context once you start reading it properly.

### GeoIP Lookup

The IP address obtained from the DNS `A` record is then sent to a GeoIP lookup. In the current tool, it uses the first available IPv4 address from the `A` records.

This gives approximate location and ISP information related to the visible IP address.

One important thing I learned here is that this does not always mean we are seeing the real origin server location. If the site is behind a CDN like Cloudflare, the IP address may point to the CDN edge instead of the actual server hosting the application.

So GeoIP is useful, but it has to be interpreted carefully. It gives context about the visible public IP, not always the real backend server.

### HTTP Headers

Following the flow, HTTP headers are analyzed. The tool does not keep every single header. It focuses mainly on security-relevant headers.

Some examples are:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cache-Control`
- `Access-Control-Allow-Origin`
- `Server`
- `X-Powered-By`

Headers are a very interesting part of web security because they tell the browser how to behave. Some headers protect against clickjacking, some reduce cross-site scripting risk, some control caching, and some prevent the browser from leaking too much referrer information.

The tool fetches the site over HTTPS by default if no scheme is provided, follows redirects, and records the final URL, status code, redirect state, filtered headers, and security-relevant headers from redirect history.

Missing headers do not always mean the site is directly vulnerable, but they are useful security observations. They tell us about the hardening posture of the web application.

### TLS Certificate Information

The SSL/TLS certificate of the domain is also analyzed. This gives information like:

- certificate subject
- certificate issuer
- valid from date
- valid until date
- days until expiry
- subject alternative names

This is important because TLS certificates are what allow HTTPS to work properly. If a certificate is expired or close to expiry, browsers may show warnings and users may not be able to connect safely.

A certificate nearing expiry is not automatically an exploit, but it is still an operational security issue. It should be tracked and renewed before it causes problems.

### robots.txt and sitemap.xml

The tool also checks `robots.txt` and `sitemap.xml`.

`robots.txt` gives instructions to web crawlers about which parts of the site they are allowed or disallowed to crawl. It is important to understand that `robots.txt` is not an access control mechanism. It does not protect sensitive pages. It only tells well-behaved crawlers what they should avoid.

So if sensitive paths are listed in `robots.txt`, that itself can become useful information. It may reveal areas of the site that the owner did not want crawlers to index.

For `sitemap.xml`, the tool first checks whether `robots.txt` contains a `Sitemap:` entry. If it finds one, it fetches that sitemap URL. If not, it falls back to the common `/sitemap.xml` path.

`sitemap.xml` provides a structured list of URLs that the site wants search engines or crawlers to discover. This can help understand the public structure of the site and identify important entry points.

Again, this is not about attacking the site. It is about understanding what the website publicly exposes.

## From Headers to Security Findings

The project also has a header analysis module. This module compares the headers received from the website against a list of security-related headers and recommended values.

It checks for missing headers and weak or unexpected values. For example:

- missing `Content-Security-Policy`
- missing `Strict-Transport-Security`
- missing `X-Content-Type-Options`
- wildcard `Access-Control-Allow-Origin`
- technology disclosure through `Server` or `X-Powered-By`
- weak cache-control directives

The findings engine uses the header analysis output and turns it into proper report findings. This makes the flow cleaner: one part checks what is missing or weak, and another part explains why it matters in report form.

## From Raw Data to a Report

One thing I wanted to avoid was creating a tool that only dumps raw data. Raw WHOIS data, DNS records, and HTTP headers are useful, but they become much more useful when they are interpreted.

So after collecting the information, `main.py` saves the full raw result into `raw_output.json`.

Then the report engine builds a structured report from that data. The report contains findings with:

- severity
- category
- description
- evidence
- impact
- recommendation
- references where useful

This makes the result easier to understand. Instead of only saying “this header is missing,” the report explains why the header matters, what the impact could be, and what can be done to fix it.

For me, this was one of the most useful parts of the project. It helped me understand not just how to collect information, but also how to communicate security observations properly.

## Report Generation

After getting all the information, `main.py` writes the whole response into a JSON file as raw output.

Then the report generator uses that data to generate a markdown report. The report includes sections like:

- title page
- executive summary
- scope
- methodology
- summary of findings
- detailed findings
- recommendations
- appendix with raw data
- footer

The report generator currently builds markdown directly in Python using helper functions for headings, tables, bullets, numbered lists, and code blocks. I originally thought about it like a template system, but in the current project it is actually a hand-built markdown renderer.

This made the tool feel more complete. A clean report is much more useful than a messy terminal output, especially if the goal is to review it later or share it with someone else.

The report is not meant to say “this website is hacked” or “this is exploitable.” It is more like an initial passive reconnaissance summary. It gives observations that can guide deeper manual review.

## Limitations of the Current Project

This tool is intentionally limited, and that is important to mention.

First, it is passive. It does not scan ports, brute force directories, crawl the full website, test payloads, check login forms, or exploit anything. That keeps it safer and simpler, but it also means the findings are only surface-level observations.

Second, the tool depends on public data sources and basic HTTP responses. If a domain blocks requests, hides behind a CDN, has rate limits, or returns different responses based on region/user-agent, the result may not represent the full infrastructure.

Third, GeoIP is only approximate. The tool currently uses the first `A` record from DNS. If the site uses Cloudflare or another CDN, the location and ISP information may describe the CDN edge, not the actual origin server.

Fourth, missing headers are not always vulnerabilities by themselves. They are security observations. A missing `Content-Security-Policy` or `Permissions-Policy` may matter a lot for one application and less for another depending on what the site actually does.

Fifth, `robots.txt` and `sitemap.xml` only reveal what the site publicly exposes or advertises to crawlers. `robots.txt` is not authorization, and `sitemap.xml` is not a complete map of every possible route.

Sixth, the report is generated as markdown only. That is readable and simple, but there is no PDF export, HTML styling, database storage, or web dashboard yet.

Lastly, the tool is still a learning project. It is useful for understanding passive recon and generating an initial report, but it should not be treated as a complete security assessment.

## What I Learned

While building this tool, I learned that passive reconnaissance is not just about collecting information. It is about understanding what the information means.

A missing header is not always a critical vulnerability. A Cloudflare IP address does not always mean we found the real server. `robots.txt` does not protect anything by itself. A certificate nearing expiry is not an attack, but it can become a problem if ignored.

These small distinctions matter.

I also learned that structuring a tool properly makes it easier to extend. Since the project is separated into modules, analysis, and reporting, adding a new check later should not require rewriting everything.

The rough structure is:

```text
domain
  -> recon modules collect public data
  -> raw output is saved as JSON
  -> analysis engine creates findings
  -> report generator writes markdown report
```

This separation made the project easier to reason about.

## Closing Thoughts

This project started as a simple attempt to understand web applications from a security point of view. But while building it, I realized that even basic passive recon can teach a lot.

It taught me how domains are registered, how DNS records point to infrastructure, how HTTP headers affect browser security, how TLS certificates are managed, and how public files like `robots.txt` and `sitemap.xml` expose site structure.

The tool is still simple, and there are many things that can be improved. But that was the point. I wanted to build something that works, learn the concepts behind it, and slowly improve it over time.

For future improvements, features like better checks, cleaner output, maybe a better CLI, and possibly more recon modules could be added. But for now, this project already gave me a much better understanding of how public-facing web security information can be collected, analyzed, and reported.

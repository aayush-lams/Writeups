---
title: "The SSH login that wasn't a password problem"
slug: ssh-permission-denied-allowusers
date: 2026-06-19
tags: [linux, ssh, networking, kali, nixos, sysadmin]
summary: "Permission denied (publickey,password) on a fresh Kali VM sent me down every wrong path before journalctl handed me the actual answer in one line."
---

> &gt PROBLEM &gt SSH from my NixOS host into a Kali VM. Should've taken thirty seconds. Took an hour.

**the setup**

Recently I was trying to checkout a service i was hosting in my Kali Linux guest on the NAT network inside libvirt/QEMU. I was on a NixOS host. The setup was simple.

```
NixOS Host (192.168.122.1)
        |
   [virbr0 - NAT]
        |
Kali VM (192.168.122.150)
```

I just tried to ssh into the server expecting a password prompt. `ssh asur@192.168.122.150`

Instead got error,

`Permission denied (publickey,password).`

There was no appearent detail on the console to look into, no any hints.

**chasing the obvious suspects**

`Permission denied (publickey,password)` has to be one of the most unhelpful error messages in all of Linux. The frustrating part isn't that it's vague, it's that it's vague in a way that actively misleads you. The exact same message shows up whether your private key doesn't match anything on the server, your password is flat out wrong, the username you typed doesn't exist as an account on the box, or — as I eventually found out — none of those subsystems were even being reached in the first place. SSH just bundles every possible rejection into one generic line and sends you off to guess. So, like most people would, I started working down the obvious checklist of things that usually cause this.

**sshd_config first.**

My first thought was that something in the daemon's own config was disabling authentication outright. Maybe `PasswordAuthentication` or `PubkeyAuthentication` had been flipped off somewhere along the way, possibly during an earlier hardening pass I'd forgotten about.

```bash
sudo grep -i "passwordauth\|pubkeyauth\|usepam" /etc/ssh/sshd_config
#PasswordAuthentication yes
#PubkeyAuthentication yes
```

Both were explicitly enabled. Not it.

**Firewall next.**

Next logical layer down: maybe something was filtering the connection before it even reached sshd, even though the TCP handshake clearly seemed to be completing.

```bash
sudo ufw status
```

UFW was either inactive entirely or had port 22 explicitly opened already. Either way, nothing here was dropping packets. Not it.

**Is sshd even listening?**

At this point I wanted to rule out anything dumb, like the daemon silently not binding to the port I assumed it was on.

```bash
sudo ss -tlnp | grep 22
#LISTEN 0 128 0.0.0.0:22
```

It was bound and listening on all interfaces, exactly as expected. Not it.

**Is the service actually healthy?**

Maybe sshd was technically running but in some degraded or half-restarted state.

```bash
sudo systemctl status sshd
sudo systemctl is-active sshd
active
```

Running clean, no errors in the unit status. Not it.

By this point I'd ruled out config flags, the firewall, the listening port, and the health of the service itself — basically every layer that *commonly* causes this exact error message. And I still had nothing to show for it. So I did the thing you do when you're out of better ideas and have started quietly doubting your own keypair: I generated a brand new one from scratch, just in case the existing key had somehow gotten corrupted or mismatched.

```bash
ssh-keygen -t ed25519
```

Fresh keypair, copied the new public key over, tried again. Same result. Still rejected. Still zero explanation as to why.

**the one command that actually mattered**

Looking back, every single step above was a guess based on what *commonly* causes this error, not based on any actual evidence from the system itself. I was pattern-matching against past experience instead of asking the server directly what it didn't like. What I should have done from the very start was stop guessing and just watch sshd react in real time to the actual failed attempt. So I opened a second terminal into the Kali VM, tailed its logs in follow mode, and fired off the SSH attempt from the NixOS side at the same moment:

```bash
sudo journalctl -u ssh -f
```

The instant I tried to connect, the real reason showed up immediately, sitting right there in plain text:

```
sshd-session[9231]: User asur from 192.168.122.1 not allowed because not listed in AllowUsers
sshd-session[9231]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.122.1 user=asur
sshd-session[9231]: Failed password for invalid user asur from 192.168.122.1 port 59810 ssh2
sshd-session[9231]: Connection closed by invalid user asur 192.168.122.1 port 59810 [preauth]
```

There it was, sitting in the very first line: `not allowed because not listed in AllowUsers`. Everything after that first line was effectively noise — the rest of the log is sshd going through the motions of a failed password attempt, but the real decision had already been made before any of that.

**root cause**


`AllowUsers` in `sshd_config` is a whitelist directive. The moment that directive exists in the config at all, only the exact usernames listed after it are permitted to authenticate over SSH — every other account on the system gets bounced before SSH even bothers checking a public key or prompting for a password. That's precisely why none of my earlier checks caught it: pubkey auth was enabled, password auth was enabled, the firewall was open, the port was listening, the service was healthy — every one of those systems was working correctly and simply never got a chance to run, because the connection was being rejected one step earlier in the pipeline than any of them.

```bash
sudo grep -i allowusers /etc/ssh/sshd_config
#AllowUsers someotheruser
```

`asur` was never anywhere on that list. The VM had accumulated leftover configuration from an earlier user at some point in its history, and nothing about the generic client-side error gave even the faintest indication that a whitelist directive was the actual thing standing in the way.

**the fix**


```bash
sudo nano /etc/ssh/sshd_config
```

From here there are two reasonable paths. Either add the missing user to the existing whitelist:

```
AllowUsers asur
```

or, if there's no real reason to restrict logins to specific accounts, remove the directive entirely so SSH falls back to allowing any valid local account. Whichever you choose, validate the config before restarting the daemon, so a stray typo doesn't lock you out for an entirely new and unrelated reason:

```bash
sudo sshd -t
sudo systemctl restart sshd
```

Tried connecting again from the NixOS host:

```bash
ssh asur@192.168.122.150
#logged in
```

Straight in, password prompt and all, exactly like it should have worked from the very first attempt.

**takeaway**


`Permission denied (publickey,password)` tells you that authentication failed somewhere — it does not tell you *which layer* of the process actually rejected you, and that ambiguity is what makes it such a time sink. Config flags, firewall rules, listening ports, and keypairs are all still reasonable first guesses, and honestly I'd probably check them again in roughly the same order next time, since they're fast to rule out. But the fastest path to the *actual* answer was always going to be the server's own logs, watched live during the real attempt, rather than me cycling through a mental checklist of past failures:

```bash
sudo journalctl -u ssh -f
#or, depending on distro:
sudo tail -f /var/log/auth.log
```

If I'd opened that log first instead of last, this whole thing would've been a thirty-second fix instead of an hour spent chasing the wrong layer of the stack.

**quick reference**


```bash
#follow sshd logs live (run on the server, attempt login from the client)
sudo journalctl -u ssh -f

#or via auth log
sudo tail -f /var/log/auth.log

#check AllowUsers and related directives
sudo grep -i "allowusers\|denyusers\|allowgroups" /etc/ssh/sshd_config

#validate sshd config without restarting
sudo sshd -t

#verbose output on the client side
ssh -vvv user@host
```

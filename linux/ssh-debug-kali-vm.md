# SSH Access Denied — Kali VM (libvirt/QEMU)

**Environment:**
- Host: NixOS (libvirt/QEMU hypervisor)
- Guest: Kali Linux — `192.168.122.150` (NAT network `192.168.122.0/24`)
- Goal: SSH from NixOS host into Kali guest VM

---

## Network Layout

```
NixOS Host (192.168.122.1)
        |
   [virbr0 - NAT]
        |
Kali VM (192.168.122.150)
```

---

## The Problem

Simple goal — SSH from NixOS into the Kali VM. Kept getting:

```
Permission denied (publickey,password).
```

No useful error. Just rejected.

---

## Diagnosis

### Checking sshd Config First

First suspicion was something wrong in `/etc/ssh/sshd_config`. Simple check on authenticated_users and knowhosts in host side. every thing was good and well.

The next suspect was `/etc/ssh/sshd_config` — specifically `PasswordAuthentication` or `PubkeyAuthentication` being off.

```bash
sudo grep -i "passwordauth\|pubkeyauth\|usepam" /etc/ssh/sshd_config
# PasswordAuthentication yes
# PubkeyAuthentication yes
```

Both were enabled. Not the issue.

---

### Checked UFW

```bash
sudo ufw status
```

Firewall either inactive or SSH port was open. Not blocking anything.

---

### Checked Port 22

```bash
sudo ss -tlnp | grep 22
# LISTEN 0 128 0.0.0.0:22
```

sshd listening on 22. Port not the issue.

---

### Checked sshd Service

```bash
sudo systemctl status sshd
sudo systemctl is-active sshd
# active
```

Running fine.

---

### Generated a New SSH Keypair on Kali

At this point suspected maybe the keypair was the issue. Generated a fresh ed25519 key on the Kali VM:

```bash
ssh-keygen -t ed25519
```

Tried again from NixOS — still rejected. Same error.

---

### Followed Live Logs

Nothing obvious so far. Opened `journalctl` on the Kali VM in follow mode and attempted SSH from NixOS simultaneously:

```bash
sudo journalctl -u ssh -f
```

Live output during the login attempt:

```
sshd-session[9231]: User asur from 192.168.122.1 not allowed because not listed in AllowUsers
sshd-session[9231]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.122.1 user=asur
sshd-session[9231]: Failed password for invalid user asur from 192.168.122.1 port 59810 ssh2
sshd-session[9231]: Connection closed by invalid user asur 192.168.122.1 port 59810 [preauth]
```

**There it was.**

---

## Root Cause

`AllowUsers` in `sshd_config` is a whitelist. If the directive exists and your username isn't listed, SSH blocks you completely — before password or key auth even runs. It returns a generic `Permission denied` with no hint that this is the cause.

```bash
sudo grep -i allowusers /etc/ssh/sshd_config
# AllowUsers someotheruser
```

`asur` was never in the list.

---

## Fix

```bash
sudo nano /etc/ssh/sshd_config
# either add asur:
AllowUsers asur
# or remove the line entirely to allow all users

sudo sshd -t                    # validate config
sudo systemctl restart sshd
```

Tried SSH again from NixOS:

```bash
ssh asur@192.168.122.150
# logged in
```

---

## What Actually Caused It

The Kali VM had accumulated state from previous users and config changes. At some point `AllowUsers` had been set for a different user and never updated. Because SSH's error message for this is identical to a wrong password, there was no obvious pointer to look there first.

---

## Takeaway

`journalctl -u ssh -f` while attempting login is the fastest way to find the real rejection reason. Everything else — checking config flags, ports, firewall, regenerating keys — was chasing the wrong layer. The log gave the answer in one line.

---

## Reference

```bash
# follow sshd logs live (run this on the server, attempt login from client)
sudo journalctl -u ssh -f

# or via auth log
sudo tail -f /var/log/auth.log

# check AllowUsers and related directives
sudo grep -i "allowusers\|denyusers\|allowgroups" /etc/ssh/sshd_config

# validate sshd config without restarting
sudo sshd -t

# verbose output on the client side
ssh -vvv user@host
```

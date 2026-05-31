# SSH Auth Failure Diagnosis — Kali Linux VM (libvirt/QEMU)

**Environment:**
- Host: NixOS (libvirt/QEMU hypervisor)
- Guest: Kali Linux — `192.168.122.150` (NAT network `192.168.122.0/24`)
- Auth: ed25519 keypair + password fallback
- Goal: SSH access from host to guest

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

## Diagnosis Flow

### Step 1 — Initial Connection Attempt

```bash
ssh-copy-id asur@192.168.122.150
# Permission denied (publickey,password)
```

Password auth attempted — rejected. Keypair copy never succeeded.

---

### Step 2 — Verify sshd is Running and Config

```bash
sudo systemctl is-active sshd
# active

sudo grep -i "passwordauth\|pubkeyauth\|usepam" /etc/ssh/sshd_config
# PasswordAuthentication yes
# PubkeyAuthentication yes
```

Config looked correct. sshd running. Issue was elsewhere.

---

### Step 3 — Check Auth Logs

```bash
sudo tail -f /var/log/auth.log
```

Attempted SSH from host while tailing. Log output:

```
sshd-session[9231]: User asur from 192.168.122.1 not allowed because not listed in AllowUsers
sshd-session[9231]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.122.1 user=asur
sshd-session[9231]: Failed password for invalid user asur from 192.168.122.1 port 59810 ssh2
sshd-session[9231]: Connection closed by invalid user asur 192.168.122.1 port 59810 [preauth]
```

**Root cause identified: `AllowUsers` directive excluded `asur`.**

---

### Step 4 — Inspect `sshd_config`

```bash
sudo grep -i allowusers /etc/ssh/sshd_config
# AllowUsers someotheruser
```

`AllowUsers` is a whitelist — any user not listed is silently blocked regardless of valid credentials. SSH returns generic `Permission denied` with no indication this is the cause.

**Fix:**

```bash
sudo nano /etc/ssh/sshd_config
# Add asur or remove AllowUsers entirely

sudo sshd -t          # validate config before restarting
sudo systemctl restart sshd
```

---

### Step 5 — Password Auth Still Failing

After fixing `AllowUsers`, password auth was still rejected. Attempted password reset on the VM:

```bash
passwd asur
# passwd: Authentication token manipulation error
# passwd: password unchanged
```

PAM/shadow token corrupted — likely from accumulated system state (orphaned users, broken auth entries).

**Diagnosis:**

```bash
sudo passwd -S asur
# asur L ...    # L = locked
```

**Fix:**

```bash
sudo passwd -u asur     # unlock
sudo passwd asur        # reset as root
```

---

### Step 6 — Keypair Auth Not Working Either

Even after password fix, key auth was failing silently. Inspected `~/.ssh/` on the VM:

```bash
ls -la ~/.ssh/
# drwx------ agent/
# -rw------- id_ed25519
# -rw-r----- id_ed25519.pub
# (no authorized_keys)
```

`authorized_keys` never existed — `ssh-copy-id` had failed at step 1 before it could write the file.

SSH key auth fails silently when:
- `authorized_keys` is missing
- Permissions on `~/.ssh/` or `authorized_keys` are wrong
- File is owned by wrong user

**Fix:**

```bash
# on NixOS host
cat ~/.ssh/id_ed25519.pub
# copy output

# on Kali VM
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA... asur@asur" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Required permissions:**

| Path | Permission | Owner |
|------|-----------|-------|
| `~/.ssh/` | `700` | user |
| `~/.ssh/authorized_keys` | `600` | user |
| `~/.ssh/id_ed25519` | `600` | user |

---

## Resolution

```bash
ssh asur@192.168.122.150
# Enter passphrase for key '/home/asur/.ssh/id_ed25519':
# logged in
```

---

## Issue Summary

| # | Root Cause | Symptom | Fix |
|---|-----------|---------|-----|
| 1 | `AllowUsers` missing `asur` | Generic permission denied, no hint | Add user to `AllowUsers` or remove directive |
| 2 | PAM/shadow token corrupted | `Authentication token manipulation error` | `sudo passwd -u asur && sudo passwd asur` |
| 3 | `authorized_keys` missing | Key auth silently ignored | Manually create with correct perms |
| 4 | Stacked failures masked root cause | Each fix revealed the next layer | Read auth logs first, always |

---

## Key Observations

- **`AllowUsers` fails silently** — SSH returns `Permission denied` with no indication the username is blocked. Always the first thing to check if credentials are definitely correct.
- **Auth logs are non-negotiable** — `/var/log/auth.log` or `journalctl -u ssh -f` shows the exact rejection reason. Skipping logs wastes time.
- **Stacked failures are common** — fixing one issue revealed the next. The actual root cause (`AllowUsers`) was masked by the other broken state.
- **PAM token corruption** is a symptom of accumulated system mess — orphaned users, broken shadow entries. Periodic system cleanup prevents this class of issue.

---

## Reference — Useful Commands

```bash
# follow auth log live
sudo tail -f /var/log/auth.log

# follow sshd via journalctl
sudo journalctl -u ssh -f

# check account status (P=password set, L=locked, NP=no password)
sudo passwd -S username

# unlock account
sudo passwd -u username

# validate sshd config without restarting
sudo sshd -t

# check key directives in sshd_config
sudo grep -i "allowusers\|allowgroups\|denyusers\|passwordauth\|pubkeyauth" /etc/ssh/sshd_config

# fix ~/.ssh permissions in one shot
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && chmod 600 ~/.ssh/id_ed25519

# verbose SSH for client-side debugging
ssh -vvv user@host
```

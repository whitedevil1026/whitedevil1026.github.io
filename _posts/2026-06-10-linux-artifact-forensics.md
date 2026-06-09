---
title: "Linux Artifact Forensics: What to Check When All You Have Is a Raw Image"
date: 2026-06-10
categories: [DFIR, Forensics]
tags: [Linux, Forensics, DFIR, Disk Image, EXT4, Bash History, Syslog, Journald, Incident Response]
mermaid: true
image:
  path: /assets/img/posts/linux-artifact-forensics/banner.png
  alt: Linux Artifact Forensics — What to Check When All You Have Is a Raw Image
---

You have a raw `.img` or `.dd` file. No running system. No documentation. Just bytes. Here is exactly what to check and why — in order of priority.

---

## Rule Zero: Mount Read-Only First

```bash
# Find partition offset (sectors × 512 = byte offset)
fdisk -l suspect.img

# Mount read-only, suppress atime updates
sudo mount -o ro,loop,offset=1048576,noatime suspect.img /mnt/img
```

> Never mount writable. Even a single `ls` will modify access timestamps and corrupt your timeline.
{: .prompt-danger }

---

## The 7 Questions Every Linux Investigation Must Answer

| # | Question | Artifacts |
|:---|:---|:---|
| 1 | Who existed on this system? | `/etc/passwd`, `/etc/shadow` |
| 2 | What commands did they run? | `~/.bash_history` |
| 3 | When did logins happen? | `wtmp`, `btmp`, `auth.log` |
| 4 | How did malware survive reboots? | Cron, systemd units, `.bashrc` |
| 5 | What tools were installed? | `apt/history.log`, `dnf.log` |
| 6 | Was the network used? | `authorized_keys`, `known_hosts` |
| 7 | Was evidence destroyed? | Log gaps, deleted inodes |

---

## Linux Artifact Map — What Is What

![Linux Forensic Artifact Map — six categories of key paths every investigator must know](/assets/img/posts/linux-artifact-forensics/artifact-map.png)

Here's what each category means in plain terms:

- **Identity & Access** — `/etc/passwd`, `/etc/shadow`, `sudoers` — defines *who* the system thinks exists and *what they're allowed to do*.
- **Shell & History** — `.bash_history`, `.bashrc`, `.bash_profile` — records *every command run* and *runs code automatically* on every login or shell open.
- **System Logs** — `auth.log`, `syslog`, `wtmp`, `journal/` — the system's memory of *what happened, when, and who triggered it*.
- **Persistence** — `crontab`, `systemd/system/`, `rc.local` — controls *what survives a reboot* and executes automatically.
- **Network & SSH** — `authorized_keys`, `known_hosts`, `/etc/hosts` — controls *who can connect in*, *where the machine connected out to*, and *how names resolve*.
- **Filesystem** — `/tmp/`, `/var/tmp/`, EXT4 inodes — where attackers *stage payloads*, and where *deleted files leave their ghosts*.

---

## 1. User Accounts — Establish the Cast

```
/etc/passwd       → All accounts (UID, shell, home dir)
/etc/shadow       → Password hashes + last-changed date
/etc/group        → Group memberships
```

**Red flags in `/etc/passwd`:**

```
backdoor:x:0:0::/root:/bin/bash   ← UID 0 = root — this is a planted account
service_acct:x:1001:1001::/home/svc:/bin/bash   ← service account with interactive shell?
```

Any account with `UID 0` besides `root` is almost certainly a backdoor. Check when `/etc/passwd` was last modified:

```bash
stat /mnt/img/etc/passwd
```

---

## 2. Bash History — The Command Diary

```
/home/<user>/.bash_history
/root/.bash_history
/home/<user>/.zsh_history
```

**Entries that immediately matter:**

| Command Pattern | What It Suggests |
|:---|:---|
| `wget` / `curl` to unknown IP | Malware download |
| `nc`, `ncat`, `socat` | Reverse shell or listener |
| `chmod +x` on `/tmp/*` file | Payload execution |
| `history -c` / `rm ~/.bash_history` | Anti-forensics attempt |
| `tar czf /tmp/` + `curl -X POST` | Data staging and exfiltration |
| `useradd` / `passwd` | Account backdooring |
| `crontab -e` | Persistence installation |

> `history -c` clears in-memory history but does **not** erase the `.bash_history` file on disk. Attackers forget this constantly.
{: .prompt-tip }

---

## 3. Logs — The System's Timeline

### `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL)

This single file answers most "who did what" questions.

```
# Critical entries to search for:
grep -E "(Accepted|sudo|useradd|COMMAND)" /mnt/img/var/log/auth.log
```

| Log Pattern | Meaning |
|:---|:---|
| `Accepted password for root` | Root SSH login — almost always suspicious |
| `sudo: john : COMMAND=/bin/bash` | Full root shell via sudo |
| `new user: name=X, UID=0` | Backdoor account created |
| `Failed password` × hundreds | Brute-force attack |

### Other Key Logs

```
/var/log/syslog           → General system activity
/var/log/cron             → Cron job executions
/var/log/dpkg.log         → Package installs (Debian)
/var/log/apt/history.log  → Human-readable apt history
/var/log/journal/         → Binary systemd journal (use journalctl)
```

> **Log gap = red flag.** If `syslog` runs from midnight to 2 AM then jumps to 5 AM, those hours were deleted or the service was intentionally stopped.
{: .prompt-warning }

---

## 4. Persistence — How It Survived Reboots

Check these locations for anything that doesn't belong:

```
/etc/crontab
/var/spool/cron/crontabs/<user>
/etc/cron.d/
/etc/systemd/system/          ← Service unit files
/home/<user>/.config/systemd/user/
/etc/rc.local
/home/<user>/.bashrc          ← Runs on every shell open
/home/<user>/.bash_profile    ← Runs on login
/etc/profile.d/               ← Runs for all users on login
```

**Malicious cron:**
```
* * * * * /tmp/.x > /dev/null 2>&1    ← Every minute, from /tmp, output hidden
```

**Malicious systemd unit:**
```ini
[Service]
ExecStart=/var/tmp/.payload.py
Restart=always          ← Restarts if killed
```

---

## 5. Login Records — Who Was Actually Here

| File | Parse With | Contains |
|:---|:---|:---|
| `/var/log/wtmp` | `last -f wtmp` | All successful logins |
| `/var/log/btmp` | `lastb -f btmp` | Failed login attempts |
| `/var/log/lastlog` | `lastlog -R /mnt/img` | Last login per account |

```bash
last -f /mnt/img/var/log/wtmp | head -20
```

---

## 6. Network Artifacts — Who Did It Talk To?

```
~/.ssh/authorized_keys    ← Planted keys = backdoor SSH access
~/.ssh/known_hosts        ← Every server this user SSH'd to
/etc/hosts                ← Look for AV/security domains redirected to 127.0.0.1
/var/lib/dhcp/dhclient.leases  ← Past IP addresses of this machine
```

**`authorized_keys` planted key:**
```bash
cat /mnt/img/root/.ssh/authorized_keys
# Any key here grants passwordless SSH access as root
```

**`/etc/hosts` hijack:**
```
127.0.0.1    virustotal.com        ← Blocked AV lookups
127.0.0.1    windowsupdate.com     ← Blocked OS updates
```

---

## 7. Filesystem — The Invisible Evidence

### MACB Timestamps on Every File

```bash
stat /mnt/img/tmp/suspicious_file

# Access  (A): last read
# Modify  (M): content changed
# Change  (C): inode/metadata changed
# Birth   (B): file created (EXT4 only)
```

> **Timestomping:** `touch -t 202001010000 file` fakes `mtime` and `atime` — but cannot fake `ctime` or `crtime`. A file claiming 2020 with a 2026 `ctime` was tampered with.
{: .prompt-warning }

### Deleted File Recovery

```bash
# List deleted files (marked with *)
fls -r -l /dev/loop0p1 | grep "^\*"

# Recover by inode number
icat /dev/loop0p1 <inode_number> > recovered_file
```

### SUID Binaries (Privilege Escalation)

```bash
find /mnt/img -perm -4000 -type f 2>/dev/null
# Anything unusual here = check GTFOBins for exploitation path
```

---

## 10-Minute Triage Checklist

```bash
IMG=/mnt/img

# 1. Backdoor accounts (UID 0)?
awk -F: '$3 == 0' $IMG/etc/passwd

# 2. Recent logins
last -f $IMG/var/log/wtmp | head -20

# 3. Root bash history
tail -100 $IMG/root/.bash_history

# 4. All user bash histories
for h in $IMG/home/*; do echo "=== $h ==="; tail -30 "$h/.bash_history" 2>/dev/null; done

# 5. Auth log highlights
grep -E "(Accepted|sudo|useradd)" $IMG/var/log/auth.log | tail -50

# 6. Suspicious temp files
ls -laR $IMG/tmp $IMG/var/tmp 2>/dev/null

# 7. User cron jobs
ls -la $IMG/var/spool/cron/crontabs/

# 8. Planted SSH keys
cat $IMG/root/.ssh/authorized_keys 2>/dev/null
for h in $IMG/home/*; do echo "=== $h ==="; cat "$h/.ssh/authorized_keys" 2>/dev/null; done

# 9. Suspicious SUID binaries
find $IMG -perm -4000 -type f 2>/dev/null | grep -vE "(passwd|sudo|su$|ping|mount)"

# 10. Attack tools installed via apt
grep -iE "(nmap|netcat|hydra|john|hashcat|nikto|sqlmap)" $IMG/var/log/apt/history.log 2>/dev/null
```

---

## Investigation Flow

```mermaid
flowchart TD
    A["Raw Image"] --> B["Mount Read-Only"]
    B --> C["Check /etc/passwd<br>for UID 0 backdoors"]
    B --> D["Read .bash_history<br>for all users"]
    B --> E["auth.log for<br>logins and sudo"]
    C --> F["Correlate suspicious<br>accounts with logs"]
    D --> F
    E --> F
    F --> G["Check persistence:<br>cron, systemd, .bashrc"]
    G --> H["SSH keys and<br>/etc/hosts hijacking"]
    H --> I["Recover deleted files<br>via inode table"]
    I --> J["Build timeline<br>with log2timeline"]
```

---

## Complete Artifact Quick Reference

| Artifact | Path | Key Question |
|:---|:---|:---|
| User list | `/etc/passwd` | Any UID 0 non-root accounts? |
| Password dates | `/etc/shadow` | When were accounts created? |
| Command history | `~/.bash_history` | What did they run? |
| Auth events | `/var/log/auth.log` | Who logged in, sudo usage |
| Logins | `/var/log/wtmp` | When, from what IP |
| Cron jobs | `/var/spool/cron/crontabs/` | Scheduled execution |
| systemd services | `/etc/systemd/system/` | Persistence units |
| Shell init | `~/.bashrc`, `~/.profile` | Code injected into shell |
| SSH backdoors | `~/.ssh/authorized_keys` | Planted access keys |
| SSH destinations | `~/.ssh/known_hosts` | Where they connected to |
| Package installs | `/var/log/apt/history.log` | Attack tools installed |
| Temp malware | `/tmp/`, `/var/tmp/` | Staged payloads |
| SUID binaries | `find -perm -4000` | Priv-esc vectors |
| DNS hijacking | `/etc/hosts` | Security domains blocked |

---

## Tools

| Tool | Use |
|:---|:---|
| **Autopsy** | GUI forensics for disk images |
| **The Sleuth Kit** | `fls`, `icat` for filesystem analysis |
| **log2timeline / Plaso** | Unified multi-source timeline |
| **Arsenal Image Mounter** | Safe mounting on Windows |
| **Volatility** | Memory analysis if RAM dump available |

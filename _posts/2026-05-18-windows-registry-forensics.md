---
title: "Windows Registry Forensics: The Investigator's Guide to What Your PC Is Hiding"
date: 2026-05-18
categories: [DFIR, Forensics]
tags: [Registry, NTUSER.DAT, SAM, SYSTEM, SOFTWARE, ShellBags, UserAssist, USB Forensics, Digital Forensics, DFIR, Anti-Forensics]
image:
  path: /assets/img/posts/windows-registry-forensics/banner.png
  alt: Windows Registry Forensics — Hives, Artifacts, and What Investigators Really Find
---

Every action a Windows user takes — opening a folder, plugging in a USB drive, running a program — leaves a trace. Not in a log file. Not in a browser history. In a **binary database sitting silently on every Windows machine** called the Registry. This guide breaks the Registry down from scratch — no prior knowledge needed.

---

## What Is the Windows Registry?

Think of the Registry as **Windows' brain**. Every setting, every preference, every piece of hardware ever connected, every program ever installed — it's all recorded in one giant structured database that Windows reads and writes to constantly.

For investigators, this is a **goldmine**. Attackers rarely think to clean up Registry traces. Even when they do, the traces they leave behind are often permanent.

> **Analogy:** The Registry is like a hotel's guest ledger. Every room, every guest, every time they checked in or ordered room service — written down. Even if a guest tries to erase their entry, the hotel's backup ledger may still have it.
{: .prompt-tip }

---

## The Five Hives You Must Know

Registry data isn't stored in one file — it's split across multiple **hive files**, each responsible for a different area of the system. Each is a separate binary file on disk.

| Hive File | Location on Disk | What It Stores | Forensic Value |
|:---|:---|:---|:---|
| **SYSTEM** | `\Windows\System32\config\SYSTEM` | Services, device history, hardware config | USB connections, system boot info |
| **SOFTWARE** | `\Windows\System32\config\SOFTWARE` | Installed apps, OS settings, system-wide prefs | What software was installed, when |
| **SAM** | `\Windows\System32\config\SAM` | Local user accounts and password hashes | Who has accounts on this machine |
| **NTUSER.DAT** | `\Users\<username>\NTUSER.DAT` | Per-user settings, activity, preferences | What *this specific user* did |
| **USRCLASS.DAT** | `\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shell settings, folder view preferences | Folder navigation, ShellBags |

> **Important:** `NTUSER.DAT` and `USRCLASS.DAT` are **per-user** — every account on the system has their own copy. `SYSTEM`, `SOFTWARE`, and `SAM` are **system-wide** — one copy for the whole machine.
{: .prompt-info }

**One critical thing beginners miss:** You can't just open these files in Notepad. They're **binary files** and Windows locks them while the OS is running. You need forensic tools to read them.

---

## The Dirty Hive Problem — Why Your Evidence Might Be Incomplete

Here's something almost nobody explains clearly, and it causes real investigative mistakes.

### How Windows Writes to the Registry

Windows doesn't write registry changes directly to the hive file. Instead, it uses a **write-ahead logging** system:

```
Step 1: Change is written to a .LOG file first (the "journal")
Step 2: Windows confirms the log is complete
Step 3: The change is then flushed (committed) to the primary hive file
```

This protects against data corruption during crashes. But it creates a forensic problem.

### What Is a "Dirty" Hive?

If the system was abruptly shut down, crashed, or the hive was captured mid-operation, the primary `.DAT` file **won't have the latest changes** — they're sitting in the transaction log waiting to be committed.

| File | Role | Example |
|:---|:---|:---|
| `NTUSER.DAT` | Primary hive — the committed data | "The book" |
| `NTUSER.DAT.LOG1` | Transaction log 1 — recent uncommitted changes | "Latest chapter draft" |
| `NTUSER.DAT.LOG2` | Transaction log 2 — overflow from LOG1 | "Overflow notes" |

> **🚨 Forensic Trap:** If you only load `NTUSER.DAT` and ignore `.LOG1` / `.LOG2`, you could be missing the **most recent and most relevant activity**. Malware executed minutes before shutdown may only exist in the logs, not the primary hive.
{: .prompt-warning }

### The Fix

When **Registry Explorer** (Eric Zimmerman's tool) loads a hive and warns you it's "dirty," it's telling you: *"The primary hive is incomplete — please also point me to the LOG files."*

```
Registry Explorer → File → Load Hive
  → Select NTUSER.DAT
  → When prompted for transaction logs → select NTUSER.DAT.LOG1 and .LOG2
  → Tool replays the logs → Creates a "clean" merged hive
```

Always collect `.LOG1` and `.LOG2` alongside the hive. They travel as a set.

---

## The Five Artifacts That Solve Most Cases

Now let's get into what's actually *inside* these hives that investigators care about.

---

### Artifact 1: UserAssist — What Programs Were Run

**Location:** `NTUSER.DAT` → `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

Windows tracks every GUI-based program a user launches. Every app opened from the desktop, Start Menu, or taskbar gets logged here — with a **run count** and **last execution timestamp**.

**The twist:** Microsoft obfuscated these entries using **ROT13 encoding**. Every letter is shifted 13 places in the alphabet.

```
ROT13 in action:
  A → N     B → O     E → R     X → K     Z → M
  
Real path:    C:\Windows\notepad.exe
Stored as:    P:\Jvaqbjf\abgrcnq.rkr
                             ↑
                      .exe becomes .rkr
```

Why ROT13? It's not encryption — it's obfuscation. Microsoft used it to prevent users from casually reading program histories in Registry Editor. Forensic tools decode it automatically.

| Entry | What It Reveals |
|:---|:---|
| Decoded path | Full path to the executed program |
| Run count | How many times the user launched it |
| Last run timestamp | When it was last executed |

> **Forensic Use:** A suspect claims they never ran `mimikatz.exe`. UserAssist shows it was run 7 times with the last execution at 2:14 AM. Case closed.
{: .prompt-tip }

---

### Artifact 2: ShellBags — Where They Browsed

**Location:** `NTUSER.DAT` / `USRCLASS.DAT` → `Software\Microsoft\Windows\Shell\BagMRU` and `Bags`

Windows Explorer remembers your folder view preferences — window size, icon layout, sort order — for every folder you ever open. This data is stored in ShellBags.

The forensic gold? **ShellBags persist long after the folder is deleted.**

```
Scenario:
  1. Attacker plugs in USB drive (E:\)
  2. Navigates to E:\Evidence_to_Delete\
  3. Deletes all files
  4. Removes the USB drive

What's left:
  ✅ ShellBag entry for E:\Evidence_to_Delete\
  ✅ Folder existed (Windows Explorer opened it)
  ✅ Timestamps of when user browsed there
```

| What ShellBags Prove | What They Don't Prove |
|:---|:---|
| User browsed to this folder | What files were inside the folder |
| Folder/drive existed at some point | When files were copied |
| User's interest in specific directory | File contents |

> **Think of it like:** ShellBags are a trail of muddy footprints. They prove you walked through a room — even after you cleaned the room. The footprints in the hallway remain.
{: .prompt-tip }

---

### Artifact 3: USB Device History — Who Plugged In What

This is one of the most powerful Registry investigations because it answers: *"Was this USB drive ever plugged into this computer?"* across **four different Registry locations** that must be correlated together.

#### Step 1: Identify the Device — `USBSTOR`

**Location:** `SYSTEM` → `CurrentControlSet\Enum\USBSTOR`

Every USB storage device that has ever connected to the system gets a permanent entry here.

```
USBSTOR
  └─ Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00
       └─ 4C530001180716116282&0
              ↑
         This is the SERIAL NUMBER — unique to each physical device
```

The serial number is the **device fingerprint**. If you find this serial number on multiple machines, you can prove the same physical drive touched all of them.

#### Step 2: Map to a Drive Letter — `MountedDevices`

**Location:** `SYSTEM` → `MountedDevices`

Tells you what drive letter (E:, F:, G:) that USB was assigned when it was connected.

#### Step 3: Link to a User — `MountPoints2`

**Location:** `NTUSER.DAT` → `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`

This is **per-user**. It proves which specific user account had the USB connected during their session.

#### The Full USB Evidence Chain

| Artifact | Evidence It Provides |
|:---|:---|
| `USBSTOR` (SYSTEM hive) | Device identity + serial number |
| `MountedDevices` (SYSTEM hive) | What drive letter was assigned |
| `MountPoints2` (NTUSER.DAT) | Which user was logged in |
| `setupapi.dev.log` (file, not registry) | Exact timestamp of first connection |

> **Real Scenario:** A data theft investigation. Suspect says "I never plugged anything into that laptop." The SYSTEM hive shows a SanDisk Ultra serial number. NTUSER.DAT for the suspect's account has a MountPoints2 entry for that exact drive. `setupapi.dev.log` shows first connection at 11:47 PM on the night of the incident. Three independent sources. Irrefutable.
{: .prompt-warning }

---

### Artifact 4: RunMRU — What They Typed Into Run Dialog

**Location:** `NTUSER.DAT` → `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

Every command a user types into the Windows Run dialog (Win+R) is saved here — in order, with a Most Recently Used (MRU) list.

```
RunMRU entries:
  a = "cmd"
  b = "powershell -ep bypass -e JABz..."
  c = "regedit"
  d = "\\192.168.1.50\c$"
  
MRU Order: b, d, c, a  ← Most recent first
```

> **Forensic Red Flag:** `powershell -ep bypass` means "execute PowerShell, ignore security policies." Combined with a base64-encoded command (`-e JABz...`), this is a textbook malicious command. The MRU shows it was the most recently typed command.
{: .prompt-warning }

---

### Artifact 5: LastWrite Timestamps — When Keys Changed

Every Registry key has exactly one timestamp: its **LastWrite time** — the last time that key or any of its values were modified.

```
Key: SYSTEM\CurrentControlSet\Services\MaliciousService
LastWrite: 2026-05-17 02:33:19 UTC
```

This is **critical for timeline reconstruction**. It tells investigators when a service was installed, when a setting was changed, when a new device was connected.

| What LastWrite Tells You | Limitation |
|:---|:---|
| When this key was last modified | Only shows the *most recent* modification |
| Corroborates timeline of events | Doesn't show *what* changed, only *when* |
| Persistent — survives reboots | Not granular enough to distinguish value-level changes |

---

## Real Attack Scenario: Malware Persistence

An attacker gains access to a machine and installs malware. They use a classic persistence technique: a Registry **autorun key**. Let's trace what they leave behind.

**The Attack:**

```
1. Attacker drops malware to C:\Users\victim\AppData\Local\Temp\svch0st.exe
2. Adds persistence via Run key:
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   "WindowsUpdate" = "C:\Users\victim\AppData\Local\Temp\svch0st.exe"
3. Executes the malware → connects to C2 server
4. Attempts to clean up by deleting the file
```

**What They Left in the Registry:**

| Artifact | What It Shows | Hive |
|:---|:---|:---|
| **Run key LastWrite** | Key was modified at 2:14 AM | NTUSER.DAT |
| **UserAssist** | `svch0st.exe` was executed (decoded from ROT13) | NTUSER.DAT |
| **RunMRU** | `cmd /c del svch0st.exe` typed at 2:31 AM | NTUSER.DAT |
| **ShellBags** | User navigated to `AppData\Local\Temp\` | USRCLASS.DAT |
| **USBSTOR** | USB drive connected at 1:58 AM (initial access vector) | SYSTEM |

The file is gone. The malware is gone. But the **Registry remembers every step**.

> **The attacker's fatal mistake:** Deleting the file doesn't delete the Registry entries. The Run key still has the LastWrite timestamp. UserAssist still has the execution record. The Registry is not a log file — it's not designed to be cleared. Most attackers don't realize this.
{: .prompt-tip }

---

## Dirty Hives in Investigation — A Practical Walk-Through

Let's say you're investigating a laptop. You image the drive and find these files:

```
\Users\john\NTUSER.DAT          ← Primary hive
\Users\john\NTUSER.DAT.LOG1     ← Transaction log 1
\Users\john\NTUSER.DAT.LOG2     ← Transaction log 2
```

**Scenario A — Only load NTUSER.DAT:**
You see a Run key with `malware.exe` added at 10:00 PM. But the key appears to have been deleted — it's gone from the primary hive.

**Scenario B — Load NTUSER.DAT + LOG1 + LOG2:**
Registry Explorer replays the logs. Now you see the *complete picture*:
- Run key added at 10:00 PM
- Key last modified at 10:47 PM (malware updated its C2 address)
- Key still exists in the transaction log even though deleted from primary hive

> **Deleted registry keys can survive in transaction logs.** This is one of the most overlooked evidence sources in DFIR.
{: .prompt-warning }

---

## Quick Reference: What Lives Where

| You Want To Know... | Look In... | Hive |
|:---|:---|:---|
| What programs user ran (GUI) | `UserAssist` (decode ROT13) | NTUSER.DAT |
| What folders user browsed | `ShellBags` / `BagMRU` | NTUSER.DAT / USRCLASS.DAT |
| USB devices ever connected | `USBSTOR` | SYSTEM |
| What drive letter USB got | `MountedDevices` | SYSTEM |
| Which user used the USB | `MountPoints2` | NTUSER.DAT |
| Run dialog history | `RunMRU` | NTUSER.DAT |
| Autorun persistence | `Run` / `RunOnce` keys | NTUSER.DAT / SOFTWARE |
| Installed programs | `Uninstall` key | SOFTWARE |
| Local user accounts | `SAM\Domains\Account\Users` | SAM |
| When a key last changed | `LastWrite` timestamp | Any hive |

---

## 🚨 Red Flags at a Glance

| Pattern | What It Means |
|:---|:---|
| Run key with path in `\Temp\` or `\AppData\` | Likely malware persistence |
| UserAssist entry for unknown executable | Program was run interactively |
| USBSTOR serial number + MountPoints2 entry | Specific user connected specific device |
| RunMRU with base64 PowerShell | Malicious command execution |
| Hive is dirty (LOG files have newer data) | Machine crashed or was imaged mid-operation |
| Deleted key surviving in LOG file | Anti-forensics attempted, failed |

---

## Tools & Workflow

| Tool | Purpose | Cost |
|:---|:---|:---|
| **Registry Explorer** | Parse + navigate all hive types, handles dirty hives | Free |
| **RECmd** | Command-line batch registry processing | Free |
| **ShellBags Explorer** | Dedicated ShellBag visualization | Free |
| **RegRipper** | Plugin-based artifact extraction | Free |
| **KAPE** | Automated hive collection (includes LOG files) | Free |

```
Step 1: Collect → KAPE (or FTK Imager) → grab NTUSER.DAT + .LOG1 + .LOG2 together
Step 2: Load → Registry Explorer → Load Hive → point to LOG files when prompted
Step 3: Navigate → Use bookmarks for UserAssist, ShellBags, Run keys, USBSTOR
Step 4: Export → CSV/JSON → cross-reference timestamps with other artifacts
```

---

## TL;DR

1. **Five key hives:** SYSTEM, SOFTWARE, SAM (system-wide) and NTUSER.DAT, USRCLASS.DAT (per-user)
2. **Dirty hives:** Primary `.DAT` file may be incomplete — always load `.LOG1` and `.LOG2` together
3. **UserAssist** = GUI program execution history (ROT13 encoded, auto-decoded by tools)
4. **ShellBags** = folder navigation history — persists even after folders are deleted
5. **USB forensics** = chain of four artifacts: USBSTOR → MountedDevices → MountPoints2 → setupapi.dev.log
6. **LastWrite** = every key has one — critical for timeline reconstruction
7. **Deleted keys can survive in transaction logs** — never skip the LOG files

---

## Resources

- [Eric Zimmerman's Tools (Registry Explorer, RECmd, ShellBags Explorer)](https://ericzimmerman.github.io/)
- [SANS DFIR — Windows Registry Forensics](https://www.sans.org/blog/computer-forensic-artifacts-windows-7-registry/)
- [13Cubed — Windows Registry Forensics (YouTube)](https://www.youtube.com/@13Cubed)
- [MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [NirSoft RegScanner — Registry Search Tool](https://www.nirsoft.net/utils/regscanner.html)

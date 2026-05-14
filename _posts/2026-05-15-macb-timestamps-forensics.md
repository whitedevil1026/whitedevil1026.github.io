---
title: "MACB Timestamps in Forensics: The Beginner's Guide to File Timeline Analysis"
date: 2026-05-15
categories: [DFIR, Forensics]
tags: [MACB, Timestamps, NTFS, MFT, Digital Forensics, Timestomping, Timeline Analysis, Anti-Forensics]
image:
  path: /assets/img/posts/macb-timestamps-forensics/banner.png
  alt: MACB Timestamps — Modified, Accessed, Changed, Birth — Digital Forensics Guide
---

Every file on your computer silently records **when things happen to it** — every edit, every open, every rename. In forensics, these timestamps are the **backbone of every investigation**. This guide breaks down MACB from scratch — no prior knowledge needed.

---

## What Is MACB?

Four timestamps. Every file. Every folder. Recorded by the file system automatically.

| Letter | Name | Tracks | One-Liner |
|:---:|:---|:---|:---|
| **M** | **Modified** | Last **content** change | Someone edited what's *inside* the file |
| **A** | **Accessed** | Last **read/open** | Someone looked at the file |
| **C** | **Changed** | Last **metadata** change | Something *about* the file changed (not content) |
| **B** | **Birth** | **Creation** time | File's birthday — set once, never changes |

> **Analogy:** Your computer is a librarian who logs every time a book is touched, edited, moved, or first shelved. MACB is that logbook.
{: .prompt-tip }

**Where are they stored?** In the NTFS **Master File Table (MFT)** — in two separate attributes:

| Attribute | Updated By | Fakeable? |
|:---|:---|:---:|
| **$STANDARD_INFORMATION ($SI)** | User programs, Windows APIs | ✅ Easily |
| **$FILE_NAME ($FN)** | Windows Kernel only | ❌ Very hard |

> Attackers fake $SI (what Explorer shows). Forensic investigators compare $SI vs $FN to catch them.
{: .prompt-warning }

---

## A Day in the Life of a File

Follow this row by row like a story — this is the **core example** that makes MACB click.

**Scenario:** You create a file called `report.docx` at 10:00 AM and do various things to it over the next 35 minutes.

| Time | Action | M | A | C | B | Why? |
|:---|:---|:---:|:---:|:---:|:---:|:---|
| 10:00 | Create new file | ✅ 10:00 | ✅ 10:00 | ✅ 10:00 | ✅ 10:00 | New content + new metadata + file created |
| 10:05 | Edit text and save | ✅ 10:05 | ✅ 10:05 | ✅ 10:05 | ❌ 10:00 | Content changed, filesize/metadata also updated |
| 10:10 | Open file read-only | ❌ 10:05 | ✅ 10:10 | ❌ 10:05 | ❌ 10:00 | Only viewed/read |
| 10:15 | Rename file | ❌ 10:05 | ❌ 10:10 | ✅ 10:15 | ❌ 10:00 | Filename metadata changed |
| 10:20 | Change permissions | ❌ 10:05 | ❌ 10:10 | ✅ 10:20 | ❌ 10:00 | Security metadata changed |
| 10:25 | Move file (same NTFS drive) | ❌ 10:05 | ❌ 10:10 | ✅ 10:25 | ❌ 10:00 | Directory metadata changed |
| 10:30 | Copy file to USB | ❌ 10:05 | ✅ 10:30 | ❌ 10:25 | ❌ 10:00 | Original file only accessed for reading |
| 10:35 | New copy appears on USB | ✅ 10:05 | ✅ 10:35 | ✅ 10:35 | ✅ 10:35 | New filesystem object created |

Now let's walk through **each step** so you understand exactly what happened:

### ⏰ 10:00 — Create new file

You right-click → New → Word Document. **All four timestamps get set to 10:00.** This makes sense — new content was written (M), the file was accessed (A), new metadata was created (C), and the file was born (B). Everything starts here.

### ⏰ 10:05 — Edit text and save

You type some text and hit Ctrl+S. The **content inside the file changed** → M updates to 10:05. But here's the thing — when content changes, the filesize also changes, and that's metadata. So **C also updates**. You also opened the file to edit it, so **A updates**. Birth? Still 10:00 — the file wasn't created again, it was just edited.

### ⏰ 10:10 — Open file read-only

You double-click and just *read* the file, then close it. You didn't change a single byte. **Only A updates** because you accessed/read it. M stays at 10:05 (no content change), C stays at 10:05 (no metadata change), B stays at 10:00.

### ⏰ 10:15 — Rename the file

You rename `report.docx` to `final_report.docx`. The **content inside is identical** — not a single byte changed. But the **filename is metadata**, so **only C updates** to 10:15. M doesn't move because you didn't edit the content. This is a perfect example of **C changing without M**.

### ⏰ 10:20 — Change permissions

You right-click → Properties → Security → make it read-only. Again, the **content is untouched**. Permissions are metadata. **Only C updates** to 10:20. M still sits at 10:05.

### ⏰ 10:25 — Move file to another folder (same drive)

You drag the file from `Documents` to `Desktop`. On the same NTFS drive, the file data doesn't move — only its **directory entry** (metadata) changes. **Only C updates** to 10:25. Content hasn't been touched since 10:05.

### ⏰ 10:30 — Copy the file to USB

You copy-paste the file to a USB drive. The **original file** is only *read* during this process (the system reads its bytes to write them elsewhere). So **only A updates** to 10:30 on the original. M and C don't change — you didn't edit content or metadata.

### ⏰ 10:35 — New copy appears on USB

The **copy on the USB** is a completely new filesystem object. It gets a **new Birth (10:35)** and **new Changed (10:35)** because it was just created on a new filesystem. But here's the interesting part — it **inherits the original Modified time (10:05)** because the content is the same content that was last modified at 10:05.

> **🚨 Forensic goldmine:** The USB copy has Modified = 10:05 but Birth = 10:35. A file *modified before it was born?* That's **physically impossible** for an original file. This is exactly how investigators detect copied/moved files.
{: .prompt-tip }

### 📋 What We Learned From This Example

Looking back at our 35-minute story, here are the patterns that matter:

| Pattern From Example | What It Means | Forensic Takeaway |
|:---|:---|:---|
| **10:05 → M, A, C all updated** | Editing content affects everything except Birth | Content changes always ripple into metadata |
| **10:10 → Only A updated** | Reading a file only touches Accessed | Read-only operations leave minimal traces |
| **10:15, 10:20, 10:25 → Only C updated** | Rename, permissions, move = metadata only | **C changes without M** = someone changed things *about* the file, not *inside* it |
| **10:30 → Only A updated on original** | Copying reads the original but doesn't modify it | The source file barely notices it was copied |
| **10:35 → M=10:05 but B=10:35 on USB copy** | Modified is older than Birth | **Impossible for originals** — proves this is a copy |

**The bottom line:** Birth (B) never changed after creation. Modified (M) only moved when content was edited. Changed (C) moved every time *anything about the file* was touched. And Accessed (A) updated whenever the file was even looked at.

## 🔴 Modified (M) vs Changed (C) — The Key Forensic Difference

This is what trips everyone up, and what catches attackers.

![Modified vs Changed — The Core Forensic Difference](/assets/img/posts/macb-timestamps-forensics/modified-vs-changed.png)
_Modified = CONTENT changes. Changed = METADATA changes. This distinction catches attackers._

### Two Golden Rules

**Rule 1 → M changes, C always changes too**

Editing content also affects metadata (filesize, allocation, timestamps). So M ✅ always means C ✅.

**Rule 2 → C can change WITHOUT M**

You can rename, move, or lock a file without touching its content.

| Action | M | C |
|:---|:---:|:---:|
| Edit and save file | ✅ | ✅ |
| Rename file | ❌ | ✅ |
| Change permissions | ❌ | ✅ |
| Move file (same drive) | ❌ | ✅ |
| Change ownership | ❌ | ✅ |

### The Book Analogy 📖

- **Modified (M)** = You rewrote a paragraph. The **book's pages** changed.
- **Changed (C)** = You renamed the book, moved it to another shelf, or put a lock on it. The **pages are untouched**, but the **catalog card** changed.

> **One sentence:** Modified = you changed the *book*. Changed = you changed the *catalog card*.
{: .prompt-info }

---

## Real Attack Scenario: Why This Catches Hackers

An attacker drops malware as `svchost.exe` (mimicking Windows), then **renames** it, **hides** it, **changes permissions**, and **fakes the Modified timestamp** to look old.

| Timestamp | Value | Why? |
|:---|:---|:---|
| **Modified (M)** | `Jan 2022` | ❌ **FAKED** to blend in |
| **Accessed (A)** | `Today` | Recently executed |
| **Changed (C)** | `Today` | 🚨 Rename + permissions updated this |
| **Birth (B)** | `Today` | Just created on this system |

```
Modified:   Jan 2022   ← "I'm an old system file"
Changed:    Today      ← "My metadata was JUST modified"
Birth:      Today      ← "I was JUST created"
```

**Modified before Birth = physically impossible.** This is called **timestomping** — and Changed (C) is what exposes it.

---

## Timestomping: Faking Timestamps & Catching It

![Timestomping Detection — $SI vs $FN Timestamps](/assets/img/posts/macb-timestamps-forensics/timestomping-detection.png)
_Attackers fake $SI timestamps. $FN timestamps (kernel-managed) reveal the truth._

### Three Detection Methods

**1. Compare $SI vs $FN**

```
$SI Modified:   Jan 15, 2022      ← What Explorer shows (FAKED)
$FN Modified:   May 14, 2026      ← What the kernel recorded (REAL)

🚨 4-year gap = TIMESTOMPING
```

**2. Zeroed nanoseconds**

```
Legit:       2026-05-14 10:30:22.4567890
Timestomped: 2022-01-15 08:00:00.0000000  ← All zeros = automated tool
```

NTFS uses 100-nanosecond precision. Timestomping tools only set second-level precision.

**3. Cross-reference other artifacts**

| Artifact | What It Reveals |
|:---|:---|
| **$UsnJrnl** | Real create/rename/delete timestamps |
| **Prefetch** | When executables actually ran |
| **Shimcache / Amcache** | Program execution history |
| **Event Logs** | System events unaffected by timestomping |

> **Never trust a single timestamp.** Always corroborate with at least two independent sources.
{: .prompt-warning }

---

## Quick Reference Cheat Sheet

| Action | M | A | C | B |
|:---|:---:|:---:|:---:|:---:|
| Create new file | ✅ | ✅ | ✅ | ✅ |
| Edit and save | ✅ | ✅ | ✅ | ❌ |
| Read / open | ❌ | ✅ | ❌ | ❌ |
| Rename | ❌ | ❌ | ✅ | ❌ |
| Change permissions | ❌ | ❌ | ✅ | ❌ |
| Move (same drive) | ❌ | ❌ | ✅ | ❌ |
| Copy (original) | ❌ | ✅ | ❌ | ❌ |
| Copy (new copy) | ✅* | ✅ | ✅ | ✅ |

*\*Copy inherits original's M time but gets new B time.*

### 🚨 Red Flags

| Pattern | Meaning |
|:---|:---|
| M older than B | Copied file — or faked timestamps |
| $SI much older than $FN | Timestomping detected |
| Nanoseconds = `0000000` | Automated timestomping tool |
| C recent, M old | Metadata manipulation (rename, permissions, timestomping) |

---

## Tools & Workflow

| Tool | Purpose | Cost |
|:---|:---|:---|
| **MFTECmd** | Parse $MFT → CSV with $SI + $FN timestamps | Free |
| **Timeline Explorer** | View/filter MFTECmd output | Free |
| **FTK Imager** | Extract $MFT from live/imaged drives | Free |
| **Plaso / log2timeline** | Super-timeline from multiple artifacts | Free |

```
Step 1: Extract $MFT → FTK Imager → Obtain Protected Files
Step 2: Parse → MFTECmd.exe -f "$MFT" --csv output/ --csvf mft.csv
Step 3: Analyze → Timeline Explorer → Compare $SI vs $FN → Spot anomalies
```

---

## TL;DR

1. **MACB** = Modified (content), Accessed (read), Changed (metadata), Birth (created)
2. **M changes → C always changes too** (content edits affect metadata)
3. **C can change WITHOUT M** (rename, move, permissions = metadata only)
4. **M older than B** = copied file or faked timestamps
5. **Timestomping** = attackers fake $SI timestamps; detect by comparing $SI vs $FN in MFT
6. **Never trust one timestamp** — always cross-reference with $UsnJrnl, Prefetch, Event Logs

---

## Resources

- [Eric Zimmerman's Tools (MFTECmd, Timeline Explorer)](https://ericzimmerman.github.io/)
- [SANS DFIR — MACB Timestamp Analysis](https://www.sans.org/blog/digital-forensic-sifting-macb-times/)
- [13Cubed — MFT and Timestamps (YouTube)](https://www.youtube.com/@13Cubed)
- [MITRE ATT&CK T1070.006 — Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [Plaso / log2timeline](https://github.com/log2timeline/plaso)

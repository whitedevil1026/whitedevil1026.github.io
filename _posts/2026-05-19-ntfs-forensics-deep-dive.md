---
title: "NTFS Forensics: What Really Happens When You Delete a File"
date: 2026-05-19
categories: [DFIR, Forensics]
tags: [NTFS, MFT, UsnJrnl, LogFile, Alternate Data Streams, File Carving, Slack Space, Digital Forensics, DFIR, Anti-Forensics]
image:
  path: /assets/img/posts/ntfs-forensics-deep-dive/banner.png
  alt: NTFS Forensics Deep Dive — MFT, Journals, ADS and What Deletion Actually Means
---

You hit Delete. You empty the Recycle Bin. You feel safe. But here's the truth — the file is almost certainly still on disk, the file system has recorded every step of its existence across multiple logs, and a competent forensic examiner can reconstruct exactly what happened. This guide explains **how NTFS actually works** — and why that makes it one of the richest forensic evidence sources in existence.

---

## First: What Is NTFS and Why Does It Matter?

NTFS (New Technology File System) is the file system Windows has used by default since Windows NT. It's not just a way to store files — it's a **structured database** with journaling, metadata, access controls, and multiple redundant record systems built in.

> **Analogy:** Think of NTFS as a hotel with a full concierge system. Every guest (file) gets a permanent registration card (MFT record), every event is logged by three separate staff members ($LogFile, $UsnJrnl, $MFT timestamps), and the hotel never truly removes a guest card — it just marks the room as available again.
{: .prompt-tip }

The consequence for investigators? **NTFS is extraordinarily hard to clean.** Files leave traces in at least four separate locations simultaneously.

---

## The Building Blocks: Clusters and Sectors

Before anything else, you need to understand how NTFS physically stores data.

```
Physical Disk
  └─ Sectors (512 bytes each — the smallest physical unit)
       └─ Clusters (groups of sectors — the smallest NTFS unit)
            ├─ Default: 4,096 bytes (8 sectors) on most volumes
            └─ NTFS allocates storage in whole clusters — never partial ones
```

**Why clusters matter forensically:**

When a file is 1,500 bytes and a cluster is 4,096 bytes, NTFS allocates one full cluster. The file uses 1,500 bytes. The remaining **2,596 bytes are called file slack** — and they contain whatever data was sitting in that cluster before. That residual data is called **slack space**, and it can contain fragments of old files that were previously stored there.

| Space Type | What It Is | Forensic Value |
|:---|:---|:---|
| **Allocated space** | Clusters actively used by live files | Current file contents |
| **Unallocated space** | Clusters marked as free in `$Bitmap` | Often contains deleted files in full |
| **File slack** | Unused bytes at the end of a cluster | Fragments of previous file contents |

> **Slack space analogy:** You paint over a wall in a hotel room. The old drawing is still under the paint — not visible normally, but a specialist can find it. Slack space is that old drawing.
{: .prompt-tip }

---

## The Heart of NTFS: The Master File Table ($MFT)

The `$MFT` is the single most important structure in all of NTFS. **Every file and directory on the volume has exactly one record here.** No record = doesn't exist as far as NTFS is concerned.

Each MFT record is exactly **1,024 bytes** and contains not the file data itself, but a structured collection of **attributes** — typed, binary data structures describing everything about the file.

### What Lives Inside One MFT Record

```
MFT Record #1024 (your file: report.docx)
├── Header (fixed 42 bytes)
│   ├── Signature: "FILE"
│   ├── Record number: 1024
│   └── Sequence number (reuse counter)
├── $STANDARD_INFORMATION (0x10)
│   ├── MACB Timestamps ($SI — user-modifiable)
│   ├── File attributes (hidden, read-only, system...)
│   └── Owner SID
├── $FILE_NAME (0x30)
│   ├── MACB Timestamps ($FN — kernel-protected)
│   └── Filename + parent MFT reference
└── $DATA (0x80)
    └── The actual file content (or a pointer to it)
```

### The Two Timestamp Sets You Must Know

Every MFT record carries timestamps in **two separate attributes**, and they behave completely differently:

| Attribute | Who Updates It | Can Attackers Fake It? | What Tools Show |
|:---|:---|:---:|:---|
| **$STANDARD_INFORMATION ($SI)** | Windows API (any program) | ✅ Easily | Windows Explorer, most tools |
| **$FILE_NAME ($FN)** | Windows Kernel only | ❌ Very hard | Requires MFT-level analysis |

> **This is exactly what catches timestomping.** An attacker runs a tool to set the Modified timestamp back to 2019. That changes `$SI`. But `$FN` still shows 2026 — because it takes a kernel-mode driver to touch `$FN`, and almost no timestomping tool goes that deep. Comparing `$SI` vs `$FN` is one of the most reliable anti-forensics detection techniques in DFIR.
{: .prompt-warning }

---

## Resident vs Non-Resident Data: Where Files Actually Live

This is one of the most confusing aspects of NTFS — and one of the most forensically interesting.

### Resident Data (Small Files)

If a file is small enough (generally under ~700 bytes), NTFS stores the **actual file content** directly inside the MFT record itself. No clusters on disk are allocated.

```
MFT Record for tiny_config.txt (200 bytes)
└── $DATA attribute
    └── [RESIDENT FLAG = 0x00]
        └── "username=admin\npassword=Secret123" ← actual content RIGHT HERE in MFT
```

**Forensic implication:** If you're carving for deleted files and find an MFT record marked as deleted, the file's *content* may still be sitting in that 1,024-byte record. You don't need to look at disk clusters at all.

### Non-Resident Data (Larger Files)

Once a file grows beyond the resident threshold, NTFS allocates clusters on disk and stores **data runs** in the MFT record — a map of where the content lives.

```
MFT Record for video.mp4 (500 MB)
└── $DATA attribute
    └── [NON-RESIDENT FLAG = 0x01]
        └── Data Runs (run list):
            ├── Run 1: Start cluster 5000, length 2048 clusters
            ├── Run 2: Start cluster 12500, length 1024 clusters
            └── Run 3: Start cluster 30000, length 512 clusters
                              ↑ File is fragmented across 3 locations
```

**Data runs are a treasure map.** Each run says: "go to cluster X, read Y clusters of data." Forensic tools follow these runs to reconstruct the file.

| Scenario | What Investigators Find |
|:---|:---|
| File is deleted, MFT record survives | Data runs still intact — can reconstruct full file |
| File is deleted, MFT record overwritten | Data runs lost — must carve unallocated space |
| File exists, content is resident | Content inside MFT — recovered even if disk is zeroed |

> **Resident data is remarkably persistent.** Because MFT records are 1 KB and tightly packed, they're rarely individually overwritten. An MFT record for a 200-byte config file containing credentials can survive in forensic images for months after the file was deleted.
{: .prompt-warning }

---

## What Deletion Actually Means in NTFS

This is the single biggest misconception in digital forensics. "Deleting" a file in NTFS does almost nothing to the actual data. Here's the exact sequence:

### Step-By-Step: What Happens When You Delete a File

```
Before deletion:
  MFT Record #1024: [IN USE] report.docx
  $Bitmap: clusters 5000–5004 = [1][1][1][1][1] (allocated)
  $UsnJrnl: last entry = FILE_WRITE at 10:30

User hits Shift+Delete (permanent delete):

  Step 1: MFT Record #1024 flag changes → [NOT IN USE]
          ↑ The record itself stays on disk. All attributes intact.

  Step 2: $Bitmap bits flip → clusters 5000–5004 = [0][0][0][0][0]
          ↑ NTFS now considers those clusters "available"
          ↑ The actual bytes on disk are UNCHANGED

  Step 3: $UsnJrnl gets a new entry → FILE_DELETE at 10:31
          ↑ Permanent record that this deletion occurred

  Step 4: Directory entry is removed
          ↑ File no longer appears in Explorer

What actually changed: four small flags/bits
What didn't change: the file's entire content, still sitting on disk
```

> **Analogy:** Deleting a file in NTFS is like tearing the table of contents page out of a book. The chapters are all still there. You just removed the index that pointed to them.
{: .prompt-tip }

### When Data Actually Gets Overwritten

Data is only gone when Windows writes new data to those clusters. On an active system this could happen in minutes. On a lightly-used or forensically-imaged system, deleted files can sit recoverable for **years**.

| Factor | Effect on Recoverability |
|:---|:---|
| Lightly-used drive | Very high — clusters rarely reused |
| Heavily-used drive | Lower — clusters reused quickly |
| SSD with TRIM enabled | Near-zero — TRIM actively zeros freed clusters |
| Manual wiping (zeros, random) | Zero — data destroyed |

> **SSD caveat:** TRIM is the forensic investigator's enemy. When Windows deletes a file on an SSD with TRIM enabled, it sends a command to the drive firmware to proactively zero those sectors — often within seconds. Traditional NTFS recovery techniques fail almost completely on TRIM-enabled SSDs.
{: .prompt-warning }

---

## The Three Journals: NTFS's Flight Data Recorders

NTFS maintains not one but **three separate logging mechanisms**, each serving a different purpose and providing different forensic value. Most investigators only know about one.

### Journal 1: `$MFT` Timestamps

**What it is:** Every MFT record has MACB timestamps in `$SI` and `$FN`.

**What it tells you:** When the file was created, modified, accessed, and when metadata last changed.

**Limitation:** Easily manipulated via `$SI`. Only stores the *current* state — not history.

---

### Journal 2: `$UsnJrnl` — The Change Journal

**Location:** `\$Extend\$UsnJrnl:$J`

**What it is:** A circular log that records every file system change — every file creation, deletion, rename, attribute change — as a **USN (Update Sequence Number) record**.

```
A USN record contains:
├── USN (sequence number — always incrementing)
├── Timestamp of the event
├── File name
├── MFT record number
├── Parent directory MFT record number
└── Reason flags (what happened)
     ├── FILE_CREATE
     ├── FILE_DELETE
     ├── DATA_OVERWRITE
     ├── RENAME_OLD_NAME / RENAME_NEW_NAME
     ├── BASIC_INFO_CHANGE (timestamps changed — timestomping flag!)
     └── SECURITY_CHANGE
```

**Why it's so powerful:** The journal records events **sequentially and permanently** — even after the file is deleted and the MFT record is overwritten.

```
Example $UsnJrnl sequence for a malicious file:

USN 4821  | 22:14:01 | FILE_CREATE      | svch0st.exe | parent: \Temp\
USN 4822  | 22:14:03 | DATA_OVERWRITE   | svch0st.exe | (file written)
USN 4823  | 22:14:05 | BASIC_INFO_CHANGE | svch0st.exe | ($SI timestamps FAKED)
USN 4824  | 22:31:47 | FILE_DELETE      | svch0st.exe | (attacker deleted it)

The file is gone. The MFT record is reused. But the journal remembers everything.
```

**The `BASIC_INFO_CHANGE` flag is the anti-forensics detection signal.** When an attacker timestomps a file, they write new values to `$STANDARD_INFORMATION`. That triggers a `BASIC_INFO_CHANGE` USN event — a red flag that says "someone just modified the timestamps on this file."

**One critical limitation:** The journal is circular and typically ~32 MB. On a busy system it can roll over in days or even hours, overwriting old entries.

---

### Journal 3: `$LogFile` — The Transaction Log

**Location:** `\$LogFile`

**What it is:** A low-level transaction log that NTFS uses to ensure **data integrity** after crashes. Every metadata write is first written here before being committed to the MFT.

**Think of it as:** The `$UsnJrnl` tells you *what* changed. The `$LogFile` tells you *exactly how* the MFT was modified — byte by byte.

**Forensic use:** Extremely granular. Can reveal deleted keys, partial writes, and intermediate states that exist nowhere else. Harder to parse than `$UsnJrnl` but more detailed.

| Journal | Coverage | Detail Level | Rollover Speed | Best For |
|:---|:---|:---|:---|:---|
| **$MFT timestamps** | Current state only | Low | Never (static) | Quick timeline |
| **$UsnJrnl** | Days to weeks of history | Medium | Days to hours | Event reconstruction |
| **$LogFile** | Minutes to hours | Very high | Hours | Crash recovery, deleted records |

> **Never analyze only one journal.** Correlate all three. Each fills gaps the others leave.
{: .prompt-warning }

---

## Alternate Data Streams: Files Hidden Inside Files

This is one of NTFS's most powerful — and most abused — features.

### How NTFS Actually Stores "A File"

In NTFS, a file isn't just one thing. It's a collection of named **data streams**. The content you normally see (the actual document, the image, the executable) is stored in the **unnamed default stream** — technically called `:$DATA`.

But NTFS allows any number of **additional named streams** to be attached to any file. These are called **Alternate Data Streams (ADS)**, and they are:
- **Completely invisible** to Windows Explorer, `dir`, `ls`, and most tools
- **Not reflected** in the file size shown to users
- **Preserved** by NTFS indefinitely alongside the host file
- **Executable** — you can run code directly from an ADS

```
Visible to users:
  readme.txt   (3 KB)

Reality in NTFS:
  readme.txt:$DATA          ← "Hello, read me!"  (the visible content)
  readme.txt:payload.exe    ← [malicious binary]  (invisible)
  readme.txt:config.dat     ← [C2 config]          (invisible)
```

### The Zone.Identifier Stream — A Forensic Gift

Windows automatically adds a legitimate ADS to every file downloaded from the internet:

```
malware.exe:Zone.Identifier
  [ZoneTransfer]
  ZoneId=3
  ReferringUrl=https://evil-domain.com/tools/
  HostUrl=https://evil-domain.com/tools/malware.exe
```

This stream records **where the file came from** and that it was downloaded from the internet (Zone 3). Attackers who move files via USB or internal shares don't get this marker — which tells investigators a great deal about the file's origin.

| Zone ID | Meaning | Forensic Note |
|:---|:---|:---|
| 0 | Local machine | File created locally |
| 1 | Local intranet | Internal network origin |
| 2 | Trusted sites | Trusted zone download |
| 3 | Internet | Standard internet download |
| 4 | Restricted sites | High-risk download |

**Missing Zone.Identifier = file wasn't downloaded via browser** — it was compiled locally, copied from USB, or the attacker deliberately deleted the stream.

### Detecting ADS

```powershell
# List all streams on all files in a directory
Get-Item -Path .\* -Stream * | Where-Object {$_.Stream -ne ':$Data'}

# Read a specific alternate stream
Get-Content -Path "readme.txt" -Stream "payload.exe"

# Command line (native)
dir /r C:\Temp\

# Sysinternals (most thorough)
streams.exe -s C:\Temp\
```

> **MITRE ATT&CK T1564.004 — NTFS File Attributes:** ADS-based hiding is a documented adversary technique. Tools that don't explicitly scan for alternate streams will miss it entirely.
{: .prompt-warning }

---

## A Day in the Life of a Malicious File (Full NTFS Trace)

Let's follow a real attack scenario and trace every NTFS artifact it creates. An attacker exfiltrates data and tries to clean up.

**The Attack Sequence:**

```
21:00  — Attacker drops loader.exe into C:\Windows\Temp\
21:01  — loader.exe creates malware.exe (hidden in ADS: svchost.exe:payload)
21:03  — Attacker timestomps malware.exe → sets $SI dates to Jan 2020
21:05  — malware.exe exfiltrates data, writes output to collector.zip
21:30  — Attacker runs: del collector.zip, del loader.exe
21:31  — Attacker runs: fsutil usn deletejournal /D C:
```

**What Each Cleanup Step Actually Did — and Didn't — Do:**

| Attacker Action | What It Did | What It Didn't Do |
|:---|:---|:---|
| `del collector.zip` | Flipped MFT flag + $Bitmap bits | Left file content on disk. Left USN records. |
| `del loader.exe` | Same as above | MFT record survives; content survives. |
| Deleted USN journal | Erased recent journal entries | $LogFile still has transaction records. $MFT still has timestamps. |
| Timestomped `$SI` | Changed the "visible" timestamps | `$FN` timestamps unchanged — kernel-protected. |
| ADS hiding | File hidden from Explorer | ADS visible via specialized tools. Zone.Identifier answers "where did this come from?" |

**What an Investigator Finds:**

```
Step 1: Parse $MFT
  → loader.exe [DELETED, MFT record still present]
    $FN timestamps: Created 21:00, Modified 21:01
    $SI timestamps: Jan 2020 (FAKED — $SI != $FN → TIMESTOMPING)
  → malware.exe [exists, hidden in ADS of svchost.exe]
    Zone.Identifier: MISSING (not downloaded from internet — created locally)

Step 2: Carve unallocated space
  → collector.zip recovered from unallocated clusters
  → loader.exe content recovered from former cluster range

Step 3: $LogFile (journal wasn't fully wiped)
  → Transaction records: MFT writes at 21:00–21:05
  → Proves MFT state before cleanup

Step 4: Event logs (not NTFS — but corroborates)
  → 21:31: Process execution of fsutil.exe with "deletejournal" args
  → Red flag: legitimate administrators almost never delete the USN journal
```

> **Deleting the USN journal is itself a red flag.** Normal Windows operations never require it. Security tools (EDR, SIEM) should alert on `fsutil usn deletejournal` — it's an almost certain indicator of anti-forensic activity.
{: .prompt-warning }

---

## NTFS Metadata Files: The Hidden System Files

NTFS stores its own internal bookkeeping in files that start with `$`. These are protected by Windows but are fully accessible in forensic images. Each one is a goldmine.

| File | Location | What It Does | Why Investigators Care |
|:---|:---|:---|:---|
| **$MFT** | `\$MFT` | Records for every file/directory | The master index of the volume |
| **$MFTMirr** | `\$MFTMirr` | Backup of first 4 MFT records | Recovery when MFT is damaged |
| **$LogFile** | `\$LogFile` | Transaction log for crash recovery | Byte-level change history |
| **$UsnJrnl** | `\$Extend\$UsnJrnl` | Change journal ($J stream) | File event history |
| **$Bitmap** | `\$Bitmap` | Cluster allocation map | Shows which clusters are free/used |
| **$Boot** | `\$Boot` | Boot sector + volume geometry | Cluster size, MFT location, volume ID |
| **$BadClus** | `\$BadClus` | Map of bad/unreadable sectors | Anti-forensic hiding spot (advanced) |
| **$Secure** | `\$Secure` | Security descriptor database | ACL and permission history |

> **The `$BadClus` trick:** Some advanced attackers mark clusters as "bad" by adding them to `$BadClus`. Windows treats these clusters as physically damaged and will never write to them or overwrite them — making them a persistent hiding spot. Forensic tools that don't specifically check `$BadClus` entries against actual disk health will miss data stored here.
{: .prompt-warning }

---

## File Carving: When MFT Records Are Gone

Sometimes the MFT record itself has been overwritten. The data runs are gone. There's no roadmap to the file. This is where **file carving** comes in.

### How File Carving Works

Every file format starts with a known **magic byte signature** (file header) and often ends with a known **footer**. Carving tools ignore the file system entirely and scan raw disk sectors looking for these patterns.

```
Common File Signatures (Magic Bytes):
  PDF:    25 4D 46 2D  (%PDF-)
  JPEG:   FF D8 FF E0
  ZIP:    50 4B 03 04  (PK..)
  DOCX:   50 4B 03 04  (also ZIP-based)
  PE/EXE: 4D 5A        (MZ)
  SQLite: 53 51 4C 69  (SQLi)
```

A carver scans the entire drive, sector by sector:
1. Finds a JPEG header → marks it as start
2. Finds a JPEG footer → marks it as end
3. Extracts those bytes → reconstructed file

**Carving limitations:**

| Problem | Explanation |
|:---|:---|
| **Fragmentation** | If file was stored in non-contiguous clusters, carving grabs only one fragment |
| **No metadata** | Recovered file has no filename, timestamps, or path — just raw content |
| **Format-dependent** | Only works for formats with known signatures |
| **Overwritten data** | If clusters were reused, the old file bytes are gone |

---

## Hard Links: One File, Multiple Names

NTFS supports **hard links** — multiple MFT `$FILE_NAME` entries pointing to the same data clusters. From NTFS's perspective, there's only one file. From the user's perspective, there appear to be two.

```
report.docx    →  MFT #1024 → Clusters 5000–5004
backup.docx    →  MFT #1024 (same record!) → Clusters 5000–5004
                              ↑ Two names, one set of data
```

**Forensic implications:**

- The **link count** in the MFT header tells you how many hard links exist. Link count > 1 on a non-system file is unusual and warrants investigation.
- If an attacker deletes `report.docx`, the data is **not freed** because `backup.docx` still points to it. The link count drops from 2 to 1. The file survives.
- Hard link pairs can be used to hide files in obscure locations while keeping an innocuous-looking alias in a visible location.

---

## Quick Reference: NTFS Forensic Cheat Sheet

### Where to Find What

| You Need To Reconstruct... | Primary Source | Secondary Source |
|:---|:---|:---|
| File creation/modification timeline | `$MFT` ($SI + $FN timestamps) | `$UsnJrnl` (event log) |
| Proof a file existed after deletion | `$UsnJrnl` (FILE_DELETE record) | `$MFT` (deleted record, if not overwritten) |
| Timestomping detection | Compare `$SI` vs `$FN` in MFT | `$UsnJrnl` BASIC_INFO_CHANGE record |
| Hidden file streams | `$DATA` attribute in MFT (named streams) | `dir /r`, `Get-Item -Stream *` |
| File origin (internet download) | `Zone.Identifier` ADS | Browser history, proxy logs |
| Deleted file content | Unallocated clusters (if not overwritten) | File carving on raw image |
| Anti-forensic activity | `fsutil` in Event Logs | USN journal deletion gap |
| Cluster allocation state | `$Bitmap` | `$MFT` data runs |

### 🚨 Red Flags at a Glance

| Pattern | What It Means |
|:---|:---|
| `$SI` timestamps much older than `$FN` | Timestomping — `$SI` was manipulated |
| `BASIC_INFO_CHANGE` in `$UsnJrnl` | Timestamps or attributes were modified |
| File with a named ADS (colon in stream name) | Possible data hiding via alternate stream |
| `Zone.Identifier` missing on suspicious executable | Not downloaded — created or moved covertly |
| `fsutil usn deletejournal` in Event Logs | Active anti-forensic cleanup attempt |
| Link count > 1 on non-system file | Hard link — potential obfuscation |
| $BadClus entries that don't match actual bad sectors | Data hidden in "fake bad" clusters |
| MFT entry with sequence number incremented | MFT record was reused — old file was there |

---

## Tools & Workflow

| Tool | What It Does | Cost |
|:---|:---|:---|
| **MFTECmd** | Parse `$MFT` + `$UsnJrnl` → CSV | Free |
| **Timeline Explorer** | Visualize and filter MFTECmd output | Free |
| **FTK Imager** | Acquire disk images, extract protected NTFS files | Free |
| **Autopsy / Sleuth Kit** | Full file system analysis, carving, deleted file recovery | Free |
| **Streams.exe** (Sysinternals) | Enumerate all ADS on files and directories | Free |
| **KAPE** | Triage collection — grabs `$MFT`, `$UsnJrnl`, `$LogFile` automatically | Free |

```
Step 1: Collect
  KAPE → Target: !BasicCollection → grabs $MFT, $UsnJrnl, $LogFile, $Bitmap

Step 2: Parse MFT
  MFTECmd.exe -f "$MFT" --csv .\output\ --csvf mft.csv

Step 3: Parse USN Journal
  MFTECmd.exe -f "$J" --csv .\output\ --csvf usn.csv

Step 4: Analyze in Timeline Explorer
  → Filter by filename, extension, or time range
  → Compare $SI vs $FN timestamps on suspicious files
  → Look for BASIC_INFO_CHANGE entries

Step 5: Recover deleted content
  → Autopsy → Add Data Source → Disk Image
  → Run "Recent Activity" and "File System" ingest modules
  → Check "Deleted Files" section
```

---

## TL;DR

1. **NTFS never truly deletes** — it just marks the MFT record and $Bitmap as free; data stays on disk until overwritten
2. **Every MFT record has two timestamp sets** — `$SI` (fakeable) and `$FN` (kernel-protected); mismatch = timestomping
3. **Resident data** (tiny files) is stored *inside* the MFT record — recoverable even if clusters are wiped
4. **Data runs** are the roadmap to non-resident file content — survives deletion if MFT record isn't overwritten
5. **Three journals** — `$MFT` (current state), `$UsnJrnl` (event history), `$LogFile` (transaction detail)
6. **ADS = files hidden inside files** — invisible to Explorer but fully detectable with forensic tools
7. **Zone.Identifier** reveals file origin — missing on executables is itself a forensic signal
8. **Deleting the USN journal** (`fsutil usn deletejournal`) is a red flag — legitimate administrators never need to do this
9. **SSDs with TRIM** are the great equalizer — NTFS recovery techniques largely fail on them

---

## Resources

- [Eric Zimmerman's Tools (MFTECmd, Timeline Explorer)](https://ericzimmerman.github.io/)
- [SANS DFIR — NTFS Forensics](https://www.sans.org/blog/digital-forensic-sifting-b-tree-indx-file-metadata/)
- [13Cubed — NTFS & MFT Analysis (YouTube)](https://www.youtube.com/@13Cubed)
- [MITRE ATT&CK T1564.004 — NTFS File Attributes (ADS)](https://attack.mitre.org/techniques/T1564/004/)
- [MITRE ATT&CK T1070.006 — Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [The Sleuth Kit / Autopsy](https://www.sleuthkit.org/)
- [NTFS.com — Detailed NTFS Structure Reference](https://www.ntfs.com/ntfs_basics.htm)

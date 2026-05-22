---
title: "Disk Imaging & the E01 Format — How It Really Works"
date: 2026-05-23
categories: [DFIR, Forensics]
tags: [E01, Disk Imaging, Digital Forensics, EnCase, Expert Witness Format, Forensic Acquisition, Segment Pointer]
image:
  path: /assets/img/posts/e01-imaging-format/banner.png
  alt: Disk Imaging and E01 Format — How It Really Works
---

You acquire a 500 GB hard drive at a crime scene. You can't work directly on it — one wrong write and the evidence is gone, and your case along with it. So you **image** it. But what exactly does that mean, and why does the industry almost always reach for E01?

---

## What is Disk Imaging?

Imaging is the process of creating an **exact, bit-for-bit copy** of a storage device — every sector, every byte, every piece of deleted data still hiding in unallocated space.

> A regular file copy takes the documents off the desk.  
> A disk image **photocopies the entire desk** — every drawer, every hidden compartment, every sticky note underneath a folder.

The raw format (`.dd` / `.img`) is just a flat byte dump of the drive — simple, but dumb. No compression. No integrity checks. No metadata. If a bit flips during transfer, you have no idea.

### Step Zero: The Write Blocker

Before any imaging happens, a **write blocker** (hardware or software) is placed between the evidence drive and the forensic workstation. It physically or logically prevents any write command from reaching the original drive — even the OS's automatic "I just mounted a drive" writes.

> Without a write blocker, the moment your OS touches the evidence drive, you have contaminated the evidence. Chain of custody is broken. Court will not accept it.
{: .prompt-warning }

Only after the write blocker is in place do you start the imaging tool.

That's where **E01** comes in.

---

## What is E01?

**E01** (Expert Witness Format) was created by Guidance Software for their EnCase tool. It became the forensic industry standard because it does something a raw `.dd` cannot — it *wraps* the disk image in a smart, verifiable container.

![E01 File Anatomy](/assets/img/posts/e01-imaging-format/e01-anatomy.png)
_Inside a single E01 file — from case metadata at the top to the integrity hash at the bottom._

A single E01 file is made up of several stacked sections:

| Section | What It Stores |
|:---|:---|
| **Header** | Case number, examiner name, acquisition date, device notes |
| **Volume** | Disk geometry — sector size, total sectors, cylinder/head info |
| **Data Chunks** | The actual disk bytes, compressed and integrity-checked |
| **Hash Section** | MD5 + SHA-1 of the entire image |
| **Next Segment** | Pointer to the next E01 file (more on this below) |

### The Key Trick: Chunks

Every **64 sectors (32 KB)** of disk data is bundled into one chunk. Each chunk is:
- Compressed with **DEFLATE**
- Protected by its own **CRC32 checksum**

This matters because you can **random-access** any part of the image. Want to read sector 1,500,000? The tool calculates which chunk contains it, decompresses *only that chunk*, and returns the bytes. You don't touch the other 99% of the image.

> **Key insight:** This chunk table acts like an index. It's why tools like Autopsy can mount a 500 GB E01 and instantly jump to the MFT without reading the whole file.
{: .prompt-info }

---

## The Segment Pointer System

Here's the part most explanations skip. An E01 image is almost never just one file.

A single drive can be 1 TB, 4 TB, or more. Older filesystems (FAT32) cap files at **4 GB**. Even modern tools default to splitting at **640 MB or 2 GB** for easier handling across DVDs, USB drives, and network transfers.

So E01 splits the image into **segments**:

```
image.E01  →  image.E02  →  image.E03  →  ...  →  image.EAA
```

The naming convention rolls over from `.E01–E99` to `.EAA, .EAB...` and so on.

![E01 Segment Chain](/assets/img/posts/e01-imaging-format/segment-chain.png)
_Each segment ends with a pointer to the next filename — the tool follows the chain automatically._

### How the Pointer Works

At the **tail of every segment** (except the last), there is a special section block. It doesn't store a memory address. It stores the **filename string** of the next segment:

```
[image.E01]
 ├── Header
 ├── Data Chunks (compressed)
 └── Next Segment Block → "image.E02"   ← the pointer

[image.E02]
 ├── Header (continuation marker)
 ├── Data Chunks (compressed)
 └── Next Segment Block → "image.E03"

[image.EAA]  ← last segment
 ├── Data Chunks (compressed)
 └── Hash Section (MD5 + SHA-1)         ← no next pointer = end of chain
```

When you open `image.E01` in EnCase, FTK, or Autopsy, the tool:
1. Reads the first segment's header and chunk table
2. Hits the "next segment" block — reads the filename `image.E02`
3. Opens that file, reads its chunk table continuation
4. Repeats until it hits a segment with **no next pointer** (the hash section terminal)

From your perspective as an analyst, it looks like **one single disk image**. The segmentation is completely transparent.

### Why Split At All?

| Reason | Detail |
|:---|:---|
| **FAT32 file size limit** | Cannot store files > 4 GB on older media |
| **Media spanning** | Fit a large image across multiple DVDs or USB drives |
| **Network transfer** | Smaller chunks are easier to move and resume on failure |
| **Parallel acquisition** | Some tools write segments simultaneously to different destinations |

---

## Integrity: The Chain of Trust

This is what separates E01 from a simple zip file. It has **two levels of integrity**:

**Level 1 — Per chunk CRC32**  
Every 32 KB chunk has its own checksum. If a single chunk is corrupted during storage or transfer, you know *exactly* which 32 KB is damaged — without reading the whole image.

**Level 2 — Image-wide MD5 + SHA-1**  
The final segment stores a hash of the *entire uncompressed image*. Before analysis begins, every tool verifies this hash. If it matches the acquisition hash recorded at the scene — the image is forensically intact.

```
Acquisition Hash  (recorded at scene):   5d41402abc4b2a76b9719d911017c592
Verification Hash (checked at lab):      5d41402abc4b2a76b9719d911017c592
                                          ✓ Match — image is untampered
```

> If these hashes ever differ, the image **cannot be used in court**. The integrity of the evidence is broken.
{: .prompt-warning }

---

## Reading E01 in Python (5 Lines)

You don't need EnCase to work with E01. `pyewf` handles the entire format:

```python
import pyewf

# Automatically discovers E01, E02, E03... in the same directory
filenames = pyewf.glob("evidence.E01")

ewf = pyewf.handle()
ewf.open(filenames)            # follows segment pointers transparently

ewf.seek(0x7C00)               # jump to the MBR boot sector
data = ewf.read(512)           # read exactly 512 bytes
print(ewf.get_media_size())    # total size of the original disk in bytes
```

`pyewf.glob()` scans the filesystem for files matching the E01 naming pattern (`.E01`, `.E02`, `.E03`...) and returns the full list. Then `ewf.open()` is what actually reads the embedded segment pointers and assembles the chain in the correct order. No manual stitching required.

---

## E01 vs Raw (.dd) — When to Use What

| Property | E01 | Raw `.dd` |
|:---|:---:|:---:|
| Compression | ✅ DEFLATE | ❌ None |
| Per-chunk CRC | ✅ | ❌ |
| Image-wide hash | ✅ MD5 + SHA-1 | ❌ (add manually) |
| Case metadata | ✅ Built-in | ❌ External sidecar |
| Segment pointers | ✅ | ❌ (split manually) |
| Tool compatibility | ✅ EnCase, FTK, Autopsy, X-Ways | ✅ Universal |
| Random access speed | ✅ Chunk-indexed | ✅ Direct offset |

> Use E01 for court-bound evidence. Use raw `.dd` when you need maximum tool compatibility or are feeding data to a custom pipeline that handles integrity separately.
{: .prompt-tip }

---

## The Full Picture

```mermaid
flowchart LR
    A["💾 Physical Drive"] -->|"bit-for-bit read"| B["Acquisition Tool\n(FTK Imager / dc3dd)"]
    B -->|"compress + CRC"| C["image.E01\n(Header + Chunks)"]
    C -->|"segment pointer"| D["image.E02\n(more chunks)"]
    D -->|"segment pointer"| E["image.EAA\n(last + MD5/SHA1)"]
    E -->|"verify hash"| F["✅ Forensic Workstation"]
```

---

## Do Other Formats Use the Same Pointer System?

Short answer: **no — and that's what makes E01 special.**

Every forensic image format handles segmentation differently. Some embed pointers like E01, some use an external map, and some just rely on blind filename guessing.

| Format | Segmentation Method | How It Finds the Next Part |
|:---|:---|:---|
| **E01** | Built-in next-segment block at tail of each file | Embedded filename string pointer — self-describing |
| **Ex01** (EnCase 7+) | Same as E01, improved chunk size & compression | Same embedded pointer system, larger default chunk size |
| **Raw / DD split** | External split (`.001, .002, .003`) | No pointer — tool increments the filename and hopes it exists |
| **VMDK (VMware)** | Split 2 GB extents | External `.vmdk` descriptor file lists every extent explicitly |
| **VHD (Microsoft)** | Split or fixed | Footer block at end of each file with disk metadata |
| **VHDX (Microsoft)** | Single file with internal log | No chaining — uses an internal log and metadata region |
| **AFF / AFF4** | Single container or named data streams | Index-based, no chain pointer |
| **SMART / S01** | Similar chunk-based architecture to E01 | Embedded segment pointer (different format, same concept) |

### The Key Difference

**Raw/DD** is the most common alternative — and it has **zero built-in segment awareness**. When a tool splits a raw image into `disk.001, disk.002, disk.003`, it's just chopping bytes at a fixed size. When you reassemble it, the tool guesses the next file by incrementing the counter. If `disk.003` is missing or renamed, it fails silently — no integrity check, no warning.

```
Raw split (dumb):         E01 (smart):
disk.001                  image.E01 ──► "next: image.E02"
disk.002  ← blind guess   image.E02 ──► "next: image.E03"
disk.003  ← blind guess   image.E03 ──► "next: image.EAA"
                          image.EAA ──► [MD5/SHA1 terminal]
```

> This is exactly why E01 became the forensic standard. The embedded pointer means the image is **self-describing** — you can hand someone just the `.E01` file and the chain is self-navigating. With raw splits, you need to keep all parts together and know the exact naming convention.
{: .prompt-info }

**VMDK** takes a middle-ground approach — it uses an external descriptor `.vmdk` text file that explicitly lists every extent file. More explicit than raw, but the descriptor is a separate file that can get separated or corrupted independently from the data.

**VHD** is the closest cousin to E01 — it embeds a 512-byte footer at the end of each split file that carries linking metadata, somewhat like E01's next-segment block, but without the full case metadata or integrity hashing that E01 provides.

---

## TL;DR

- **Disk imaging** = a verified, bit-for-bit copy of a storage device, not just a file copy.
- **E01** wraps that copy in a smart container: compressed chunks, per-chunk CRCs, case metadata, and an image-wide integrity hash.
- Each E01 segment ends with a **next segment pointer** — the filename of the next file in the chain.
- The forensic tool follows this chain transparently, presenting the entire disk as if it were one file.
- The **MD5 + SHA-1** at the end of the last segment is your chain-of-custody proof. Match it, and the evidence is sound.

---

## Resources

- [libewf / pyewf — E01 reader (GitHub)](https://github.com/libyal/libewf)
- [FTK Imager — Free acquisition tool (AccessData)](https://www.exterro.com/ftk-imager)
- [dc3dd — DoD forensic imaging tool](https://sourceforge.net/projects/dc3dd/)
- Carrier, B. *File System Forensic Analysis* (Addison-Wesley, 2005)
- [NIST CFReDS — Test disk images for practice](https://cfreds.nist.gov/)

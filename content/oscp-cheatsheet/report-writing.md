---
title: "Report Writing"
date: 2026-06-20
weight: 190
draft: false
summary: "Structure of the report submitted within 24 hours after the exam, and how to organize evidence."
---

Submit the report within 24 hours after the exam ends. Without a report, even 100 points does not pass.

- Source: https://heretek.dev/oscp-cheatsheet/report-writing/ (Jean Romero) — Reconstructed

## Report Format Requirements

- PDF only — archive it in a .7z file (no password, max 200MB)
- Filename: `OSCP-OS-XXXXX-Exam-Report.pdf` (case-sensitive, XXXXX = OS-ID)
- Upload to: upload.offsec.com
- All scripts and PoC code must be inserted as text in the PDF body (no external files) ← important
- The order of machines in the report = grading order

## Report Structure — Follow the template exactly

### 1. Cover Page

- Name, OS-ID, exam date

### 2. Executive Summary (one paragraph)

- Scope, time, and a summary of the methodology used
- Key findings: number of machines compromised, overall security posture

### 3. Per-Machine Sections — repeat for each machine

3 standalone + the AD set. Document all of the following for each machine:

```text
Machine: [IP Address]
OS: [Windows/Linux]
Service Enumeration:
  - nmap results (screenshot + key findings)

Initial Access:
  - Vulnerability identified
  - Steps to exploit (numbered, with screenshots)
  - PoC code/commands used
  - Screenshot: proof of shell (whoami output)

Privilege Escalation:
  - Vulnerability identified
  - Steps to exploit (numbered, with screenshots)
  - PoC code/commands used
  - Screenshot: proof.txt with whoami + hostname + ip/ipconfig

Proof:
  - local.txt: [flag value]
  - proof.txt: [flag value]
```

### 4. AD Set Section

- Document the attack chain across all 3 machines
- Show lateral movement between machines
- Include a credentials table showing where each credential was obtained and where it was used

## Proof Screenshot Requirements — mandatory

All four outputs must appear in a single terminal screenshot:

```bash
# Linux
whoami && hostname && ip a && cat /root/proof.txt

# Windows
whoami && hostname && ipconfig && type C:\Users\Administrator\Desktop\proof.txt
```

Screenshot must contain: flag contents + whoami + hostname + network information — all in the same window. If any is missing, that machine scores 0 ← important

## Documentation-As-You-Go

```bash
# Start terminal logging at exam begin
script -a ~/oscp/exam_log_$(date +%F).txt

# For EACH machine, before you start:
mkdir -p ~/oscp/machine_IP
echo "=== STARTING machine_IP $(date) ===" >> ~/oscp/notes.md

# Take screenshots of:
# 1. Every nmap scan result
# 2. Every vulnerability found
# 3. Every exploit command + output
# 4. Every shell obtained (whoami)
# 5. Every proof flag (the 4-in-1 screenshot)
# 6. Every credential found
```

Use Flameshot for screenshots: `flameshot gui`

## Note-Taking Structure Per Machine

Take notes in the same structure for every machine. Copy them straight into the report.

```text
## Machine [IP]

### Enumeration
- Open ports: 22, 80, 445
- Web server: Apache 2.4.49 (vuln to CVE-2021-41773)
- SMB: anonymous access allowed

### Initial Access
- Vulnerability: CVE-2021-41773 Path Traversal RCE
- Command: curl 'http://IP/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' -d 'echo Content-Type: text/plain; echo; whoami'
- Got shell as: www-data
- Screenshot: [filename.png]

### Privilege Escalation
- Found SUID /usr/bin/find
- Command: find / -exec /bin/bash -p \; -quit
- Got shell as: root
- Screenshot: [filename.png]

### Proof
- local.txt: abc123def456
- proof.txt: 789ghi012jkl

### Credentials Found
- admin:password123 (from /var/www/config.php)
- Sprayed against: [list machines tested]
```

## Common Report Mistakes — immediate fail

- Missing proof screenshot (whoami + hostname + ip + flag must be in one image)
- Violating the PDF/7z filename rules
- Submitting after the 24-hour deadline
- Not enough detail to reproduce the attack
- Screenshots without context (no explanation of what they show)
- Packing multiple concepts into one screenshot — one concept per screenshot
- Omitting failed attempts (they show methodology)

## Report Writing Timeline — 24 hours

- 0–1 hour: organize screenshots and notes per machine
- 1–2 hours: write the AD set section (most complex)
- 2–3 hours: write the Standalone 1 section
- 3–4 hours: write the Standalone 2 section
- 4–5 hours: Standalone 3 section + Executive Summary
- 5–6 hours: review, proofread, export PDF, create 7z, upload

## Tools

```bash
# OffSec report template
# Download from: https://www.offensive-security.com/pwk-online/OSCP-Exam-Report.docx

# Generate PDF from markdown (if using Obsidian/markdown)
pandoc report.md -o report.pdf --pdf-engine=xelatex

# Create 7z archive
7z a OSCP-OS-XXXXX-Exam-Report.7z OSCP-OS-XXXXX-Exam-Report.pdf

# Flameshot for screenshots
flameshot gui
```

## Quick Links (documents in the same folder)

- Exam strategy → [exam-strategy.md](exam-strategy.md)
- Full workflow checklist → [methodology.md](methodology.md)

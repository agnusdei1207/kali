---
title: "Exam Strategy"
date: 2026-06-20
weight: 200
draft: false
summary: "Exam-day time management, tool restrictions, what to do when stuck, and spotting distractors."
---

A cheatsheet covering exam-day time management, tool restrictions, what to do when stuck, and how to spot distractors.

- Source: https://heretek.dev/oscp-cheatsheet/exam-strategy/ (Jean Romero) — Reconstructed

## Exam Structure (2025/2026)

- AD Set: 40 points — 3 machines, assumed breach (domain creds provided)
- Standalone 1: 20 points — independent (initial 10 + root/admin 10)
- Standalone 2: 20 points — independent (initial 10 + root/admin 10)
- Standalone 3: 20 points — independent (initial 10 + root/admin 10)
- 100 points total, 70 to pass

Since November 2024: bonus points are gone. The AD set awards partial credit (10 points per workstation, 20 for the DC).

### Passing combinations

- AD full(40) + standalone full(20) + standalone initial(10) = 70 → pass
- AD partial(30) + standalone full(40) x 2 = 70 → pass
- AD full(40) + standalone full(40) x 2 = 80 → comfortable

## Time Management — 23 hours 45 minutes

- 0–1 hour: scan every machine. Run scans in parallel and read the results. Build the attack plan.
- 1–5 hours: AD set — top priority. 40 points.
- 5–9 hours: standalone 1 — start with the easiest based on recon.
- 9–13 hours: standalone 2.
- 13–16 hours: standalone 3, or retry a stuck machine.
- 16–20 hours: re-attack everything unfinished. With fresh eyes.
- 20–24 hours: organize screenshots, verify flags, start the report notes.

## Rules to Live By

1. Stuck for 45 minutes → pivot. Move to another machine and come back with fresh eyes.
2. Screenshot everything. Every shell, every command, every flag. You need the evidence ← important
3. Take breaks. Walk, eat, hydrate. A 10-minute break prevents 2 hours of tunnel vision.
4. AD first. It is 40 points, and once you find the entry point the chain is usually logical.
5. Do not fall into kernel exploits. They are often not the intended path.
6. Every credential you find → spray it everywhere immediately.

## Tool Restrictions — memorize these

### BANNED — immediate fail

- SQLmap, SQLninja, db_autopwn, browser_autopwn — no automated SQLi
- Nessus, OpenVAS, Nexpose — no vulnerability scanners
- Metasploit Pro, Cobalt Strike, Core Impact, Burp Pro — no commercial tools
- All AI/LLM — ChatGPT, Claude, Copilot, DeepSeek, including OffSec's KAI
- Spoofing/poisoning — ARP, DNS, NBNS, LLMNR, mDNS all banned
  - Responder poisoning = banned. Responder `-A` (analyze/passive) = allowed

### RESTRICTED — Metasploit

- exploit/auxiliary/post modules + Meterpreter on exactly 1 machine only. Choose carefully ← important
- `msfvenom`, `multi/handler`, `pattern_create/offset` → unlimited on all targets
- The `check` command also cannot be used on other targets
- Once you use a module on a target, that is that target's one use.

### ALLOWED

- Nmap + NSE scripts, Nikto, Burp Community, Gobuster, Feroxbuster
- BloodHound, Mimikatz, Impacket suite, NetExec, Rubeus, evil-winrm, PowerView
- LinPEAS/WinPEAS, pspy, Ligolo-ng, Chisel, GodPotato, PrintSpoofer
- Custom scripts in any language
- Open book: personal notes, the internet, the OffSec portal

## When Stuck (general) — in order

1. Re-read the scan output. Missed port? Version? Hostname?
2. Re-run directory brute force with a different wordlist and more extensions
3. Recheck the page source — comments, hidden fields, JS files
4. Try default credentials on every service you found
5. Re-enumerate with the creds you found — password reuse across services
6. Check UDP ports — SNMP(161) hides important data
7. Search the service + version — exploits, default creds, known issues
8. Chain findings together — one piece of information can unlock another
9. Take a 10-minute break. Leave the desk. For real.

## Proof / Screenshot Requirements

```bash
# Linux — all four in ONE terminal screenshot
whoami && hostname && ip a && cat /root/proof.txt

# Windows — all four in ONE terminal screenshot
whoami && hostname && ipconfig && type C:\Users\Administrator\Desktop\proof.txt
```

A single screenshot must show the flag contents + `whoami` + `hostname` + `ip a`/`ipconfig` in the same window ← important

## Pre-Exam Setup Checklist

- [ ] VPN connected and tested
- [ ] Kali updated, every tool verified working
- [ ] Obsidian open with this cheatsheet
- [ ] Screenshot tool ready (Flameshot)
- [ ] Reverse shell one-liners saved
- [ ] HTTP server ready: `python3 -m http.server 80`
- [ ] Wordlists: rockyou.txt, SecLists installed
- [ ] LinPEAS, WinPEAS, pspy64, PowerUp, GodPotato, PrintSpoofer, nc.exe downloaded
- [ ] Ligolo-ng proxy + agents (Linux/Windows) ready
- [ ] Terminal logging: `script -a exam_log.txt`
- [ ] Food and water at the desk
- [ ] Enough sleep the night before
- [ ] Remember: SQLmap = banned, AI/LLM = banned, Metasploit = 1 target ← important

## Report Reminder

- Submit the report within 24 hours after the exam ends ← important
- Use the official OSCP report template
- Document every step with screenshots
- Include failed attempts — they show methodology
- No report = no pass, even with 100 points ← important

## Distractor Recognition

Some hashes, creds, and services in the exam are intentional rabbit holes. Identify them quickly and do not burn time.

### Rabbit Hole Signals

1. Uncrackable hashes

- A Kerberoast hash that resists rockyou + rules for over 30 minutes
- An AS-REP hash with a bizarrely complex password pattern
- Bcrypt/Argon2 in a web app
- Response: move on. If it were intended, it would crack within 10 minutes.

If a Kerberoast hash resists rockyou+rules for over 30 minutes, stop and switch to AS-REP roasting — some are uncrackable hashes meant to steer you toward a different technique.

2. Creds that authenticate nowhere

- A username in a script/config file that does not exist in AD (empty nxc LDAP query, no node in BloodHound)
- A creds file that looks real but every target rejects
- Username variants (john.miller, jmiller, j.m) that fail authentication everywhere

3. Services/ports that look exploitable but are noise

- A default web page on an IP with no real path
- A generic banner service with no end to enumeration

### Time Budget Rules

- Maximum 30 minutes per hash cracking attempt
- Maximum 15 minutes per credential spray, then move on
- No new information from a box for 2 hours → restart enumeration from scratch
- Stuck for more than 4 hours → revert and restart that machine

### Validation Before Burning Hours

Before committing to an attack path, confirm:

- Does this user exist in AD? (nxc ldap + BloodHound)
- Is this hash a type that normally cracks with rockyou?
- Does this service actually respond as the exploit prerequisites require?

If any answer is "no" or "unknown", 5 minutes of validation prevents a 3-hour rabbit hole.

### Exam Application

The OSCP exam rewards systematic enumeration over aggressive exploitation. If creds or hashes look odd, they often are. Move on and come back when you have more context.

## Quick Links (documents in the same folder)

- Full workflow checklist → [methodology.md](methodology.md)
- Report writing → [report-writing.md](report-writing.md)

---
title: "My Enumeration Workflow — What I Run and Why"
date: 2026-03-24
weight: 10
draft: false
tags: ["enumeration", "nmap", "methodology", "smb", "http"]
summary: "What to run, why, and in what order. Judgment criteria for saving time during enumeration."
---

The workflow I settled on after working through 45+ boxes. Not the "correct" one — the one that actually works and doesn't miss things under time pressure.

## Two-Pass Nmap Approach

I used to run one big nmap scan. That was a waste of time. Now I do two passes every time.

### Pass 1 — Quick TCP scan

```bash
nmap -sC -sV -oN scans/initial.nmap $IP
```

Hits the top 1000 ports. Takes about 30 seconds. Gives you something to work with immediately while the full scan runs.

### Pass 2 — Full port scan (background)

```bash
nmap -p- -sV -oN scans/allports.nmap $IP
```

Run it in another terminal. It catches services hiding on weird high ports — there's almost always one. I once went 45 minutes before finding a web app running on 8443 or 50000.

### When to run UDP too

```bash
nmap -sU --top-ports 50 -oN scans/udp.nmap $IP
```

Top 50 ports only. A full UDP scan takes forever and rarely pays off. Ports that matter:

- **53** — DNS (zone transfer)

- **161** — SNMP (community string = free info)

- **389** — LDAP

- **123** — NTP (sometimes useful for domain enumeration)

**Rule:** If it's an AD box, always run UDP. SNMP and UDP DNS have given me the foothold more than once.

---

## Per-Service — What I Actually Check

Order matters. I go through services in the order most likely to give a foothold.

### HTTP/HTTPS (80, 443, 8080, 8443)

The web is almost always the attack surface. Hit it first.

**Check immediately:**

1. Browse the site manually. Read everything. View the source.

2. Check `/robots.txt`, `/sitemap.xml`

3. Identify the tech stack — Wappalyzer or response headers

```bash
whatweb http://$IP
```

**Directory brute forcing:**

```bash
feroxbuster -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -o scans/ferox.txt
```

I use feroxbuster instead of gobuster now. It's recursive by default, faster, and the output is better.

**Extension decision tree:**

- Linux box → `-x php,txt,html,sh`

- Windows box → `-x aspx,asp,txt,html,config`

- Framework identified → add framework-specific extensions (`.jsp`, `.do`, etc.)

**Common mistakes I've made:**

- Not adding hostnames to /etc/hosts. Virtual hosting is everywhere. Anywhere you see a domain name — headers, page content, certificates — add it and rescan.

- Only scanning one wordlist. If `directory-list-2.3-medium` finds nothing, try `raft-medium-words.txt`. Different lists catch different things.

- Ignoring 403s. A 403 means something *exists*. Try bypasses, add extensions, and enumerate deeper on that path.

**Subdomain/vhost enumeration:**

```bash
ffuf -u http://$IP -H "Host: FUZZ.domain.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

The `-fs` flag is critical. Without filtering the default response size, you'll drown in false positives.

---

### SMB (139, 445)

Check this second. SMB leaks information all over the place.

```bash
# Check for null session
smbclient -N -L //$IP/

# Enum4linux (noisy but thorough)
enum4linux -a $IP

# Share list later with credentials
smbmap -H $IP
smbmap -H $IP -u 'guest' -p ''
```

**What I look for:**

- **Readable shares** — download everything. `smbget -R smb://$IP/sharename/`

- **Writable shares** — SCF file attacks, possible payload drops

- **User lists** — RID brute force if null session works

```bash
# RID brute force for usernames
crackmapexec smb $IP -u '' -p '' --rid-brute
```

**Gotcha:** `smbclient -N` and `smbmap` behave differently with null sessions. If one fails, try the other. I've had a box where smbclient showed nothing but smbmap listed shares with `guest` / empty password.

---

### FTP (21)

Quick check. Either useful or not.

```bash
# Anonymous login
ftp $IP
# Username: anonymous
# Password: (blank or anything)
```

**If anonymous works:**

- Download everything: `mget *`

- Check whether uploads are allowed. Upload a test file. If HTTP is also serving, it could be a webshell path.

- Check for hidden files: `ls -la`

**If anonymous doesn't work:** Move on. Come back later with credentials.

---

### DNS (53)

Very important on AD boxes. Less so on standalone.

```bash
# Zone transfer attempt
dig axfr @$IP domain.htb

# Reverse lookup
dig -x $IP @$IP

# All records
dig any domain.htb @$IP
```

Zone transfers are rare in real engagements but come up regularly on HTB/OSCP boxes. Always try it.

**Subdomain brute forcing via DNS:**

```bash
dnsenum --dnsserver $IP --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt domain.htb
```

---

### LDAP (389, 636)

If LDAP is open, it's an AD box. Act accordingly.

```bash
# Anonymous bind
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb"

# Naming contexts first if you don't know the domain
ldapsearch -x -H ldap://$IP -s base namingcontexts
```

**What I want from LDAP:**

- Full user list

- Group memberships

- Description fields (admins like putting passwords in descriptions)

- Service accounts

```bash
# Pull all users
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb" '(objectClass=person)' sAMAccountName description memberOf
```

**Gotcha:** Anonymous bind doesn't always return data. Some DCs allow the bind but return nothing. Try again later with valid users.

---

### Kerberos (88)

If Kerberos is open = AD box. Two things to do immediately, no credentials needed.

**User enumeration:**

```bash
kerbrute userenum -d domain.htb --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

This is not as noisy as brute forcing. It doesn't generate failed logon events for valid users. Good for building a user list.

**AS-REP Roasting (no credentials needed):**

```bash
impacket-GetNPUsers domain.htb/ -dc-ip $IP -usersfile users.txt -no-pass
```

If an account has "Do not require Kerberos preauthentication" set, you get a hash. Crack it.

---

### MSSQL (1433)

```bash
# Default credentials
impacket-mssqlclient sa:sa@$IP
impacket-mssqlclient sa:''@$IP

# Later with found credentials
impacket-mssqlclient domain.htb/user:password@$IP -windows-auth
```

**Once in:**

- Command execution via `xp_cmdshell` (may need to enable it)

- Force authentication / capture hashes via `xp_dirtree`

- Check linked servers — `EXEC sp_linkedservers`

```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

---

### SNMP (161/UDP)

Criminally underrated. SNMP with the "public" community string dumps *everything*.

```bash
# Check community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $IP

# Walk the MIB tree
snmpwalk -v2c -c public $IP 1.3.6.1
```

**Useful OIDs:**

- `1.3.6.1.2.1.25.4.2.1.2` — running processes

- `1.3.6.1.4.1.77.1.2.25` — user accounts

- `1.3.6.1.2.1.25.6.3.1.2` — installed software

Walk specific OIDs with `snmpwalk` instead of the full tree. Faster and less noise.

**Gotcha:** If SNMPv1/v2c is running, the community string is sent in plaintext. The default is almost always `public`. But also try `private`, `manager`, `internal`.

---

### WinRM (5985, 5986)

Little you can do without credentials, but note that it's open. When you get credentials:

```bash
evil-winrm -i $IP -u 'user' -p 'password'
```

If port 5985 is open and you have valid credentials → immediate shell. The go-to for lateral movement on Windows.

---

### SSH (22)

Not much to enumerate without credentials. Note the version (sometimes reveals OS version) and move on.

```bash
# Banner grab
nmap -sV -p22 $IP
```

Come back to found credentials. Try username reuse. Try any keys you find on other services.

**One thing:** If you find a private SSH key anywhere — web directory, SMB share, FTP — immediately try it against every user you know.

---

## Real Workflow

The first 15 minutes of a box look like this:

1. **Terminal 1:** quick nmap scan → start working on results immediately

2. **Terminal 2:** full port scan running in background

3. **Terminal 3:** if HTTP found → open browser, whatweb, feroxbuster running

4. **Notes:** record every finding, every username, every potential credential

```fallback
Target: $IP
Hostname: ???
OS: ???
Domain: ???

Open Ports:
-

Users Found:
-

Credentials:
-

Interesting Findings:
-
```

Keep this running notes file updated. It sounds basic. It's the single biggest time saver.

---

## Push Further vs. Move On

This is the hardest skill and I'm still learning it.

**Push further when:**

- You find a custom web app (almost always has a vulnerability)

- You found a username but no password (time for password spraying)

- A service returned partial information (there's probably more)

- You have one set of credentials but can't get a shell (reuse them everywhere)

**Move on when:**

- Default page, no custom content, directory busting returns nothing after two wordlists

- A service requires authentication and you have no credentials at all

- You've spent 30+ minutes on one service with nothing to show for it

**The biggest time sink:** trying to exploit something before finishing enumeration. I've burned hours trying to get a foothold through one service when the real path was on a port I hadn't scanned yet.

Enumerate everything first. Exploit after. Every time. Breaking this rule is what I regret.

---

## Quick Reference — Actions per Port

| Port | Service | First move |
| --- | --- | --- |
| 21 | FTP | Anonymous login |
| 22 | SSH | Note version, move on |
| 25 | SMTP | User enumeration (VRFY/EXPN) |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP | Browse, tech stack, dir brute |
| 88 | Kerberos | User enum, AS-REP Roast |
| 110/143 | POP3/IMAP | Try default credentials |
| 135 | MSRPC | rpcclient null session |
| 139/445 | SMB | Null session, share list |
| 161 | SNMP | Community string brute, walk |
| 389/636 | LDAP | Anonymous bind, user dump |
| 1433 | MSSQL | Default credentials (sa:sa) |
| 3306 | MySQL | Default credentials (root:root) |
| 5985 | WinRM | Needs credentials → evil-winrm |
| 5432 | PostgreSQL | Default credentials (postgres:postgres) |
| 6379 | Redis | No auth? → RCE |
| 8080 | HTTP Alt | Same as 80 |

---

This workflow isn't perfect. I update it every time I work through a box that teaches me something. The core principle doesn't change: **scan fast, enumerate wide, take notes, and don't exploit until you see the full picture.**

- [Enumeration](https://heretek.dev/tags/enumeration/)
- [Nmap](https://heretek.dev/tags/nmap/)
- [Methodology](https://heretek.dev/tags/methodology/)
- [Smb](https://heretek.dev/tags/smb/)
- [Http](https://heretek.dev/tags/http/)
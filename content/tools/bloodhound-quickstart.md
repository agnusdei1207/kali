---
title: "BloodHound — Setup and Usage Guide"
date: 2026-03-24
weight: 10
draft: false
tags: ["bloodhound", "active-directory", "enumeration"]
summary: "From BloodHound collection to attack path analysis. How to see AD permission relationships at a glance."
description: "From BloodHound collection to attack path analysis. How to see AD permission relationships at a glance."
---

BloodHound maps Active Directory relationships and finds attack paths that manual enumeration won't show. On Forest, it revealed a WriteDACL path through 5 nested groups. I would never have found it by hand.

This is how I set it up, collect data, import it, and find the paths that matter.

## Setup — BloodHound CE on Kali

BloodHound CE (Community Edition) replaces the legacy BloodHound. It runs as a Docker container with a web UI.

### Install and start

```bash
# BloodHound CE pull & start
curl -L https://ghst.ly/getbhce -o docker-compose.yml && docker compose up -d

# First run takes a few minutes to pull images
# Web UI: http://localhost:8080
```

### First login — neo4j password gotcha

On first run, BloodHound CE generates a random admin password. It's printed to the Docker logs and easy to miss.

```bash
# Find the initial password
docker compose logs | grep "Initial Password"
# or scroll back through the logs to find the generated credentials
```

**A gotcha I hit on Active:** the password scrolled past in the terminal and I couldn't find it. I had to dig through the Docker logs. Save it right away.

Default credentials are usually `admin` / `<random>`. You'll be forced to change the password on first login.

### Verify it works

Go to `http://localhost:8080`. You should see the BloodHound CE login page. Log in with the initial credentials and set a new password.

---

## Data collection — bloodhound-python

`bloodhound-python` is a Linux collector. It queries the DC remotely — nothing needs to run on the target.

### The command I use every time

```bash
bloodhound-python -u 'USERNAME' -p 'PASSWORD' -ns $ip -d DOMAIN.local -c All
```

### Flag breakdown

| Flag | What it does |
| --- | --- |
| `-u` | Username |
| `-p` | Password |
| `-ns` | Nameserver (DC IP) — **critical**, tells it where to resolve DNS |
| `-d` | Domain name |
| `-c All` | Collect everything — users, groups, sessions, ACLs, trusts, containers, GPOs |

### Output

Creates several JSON files in the current directory:

```fallback
20260324_computers.json
20260324_domains.json
20260324_groups.json
20260324_users.json
```

### Real examples from my boxes

```bash
# Active — GPP creds
bloodhound-python -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -ns <DC_IP> -d active.htb -c All

# Forest — AS-REP creds
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -ns <DC_IP> -d htb.local -c All

# Blackfield — AS-REP creds
bloodhound-python -u 'support' -p '#00^BlackKnight' -ns $ip -d BLACKFIELD.local -c All
```

### Gotchas

- **`-ns` is effectively required.** Without it, DNS resolution fails because Kali doesn't know how to resolve the domain. Always set it to the DC IP.

- **`-c All` is the right default.** Some guides say to use `-c DCOnly` for stealth. On CTF boxes and OSCP, just grab everything.

- **The domain name matters.** Some boxes use `domain.htb`, others `domain.htb.local`, others `domain.local`. Get it from nmap LDAP output or `nxc smb` output. Wrong domain name = collection silently fails or returns incomplete data.

- If your password has special characters (`$`, `!`, `#`), use **single quotes** in bash.

---

## Importing data into BloodHound CE

1. Log in to BloodHound CE at `http://localhost:8080`

2. Click the **Upload** button (top right, arrow icon)

3. Select all the JSON files from bloodhound-python

4. Wait for ingestion to finish

Done. The graph database is populated. Time to query.

---

## Key Queries

The queries I actually run. In order.

### 1. Shortest Path to Domain Admin

Check this first. Every time.

In BloodHound CE:

- Go to **Explore** → **Pathfinding**

- Start node: the user I've owned

- End node: DOMAIN `ADMINS@DOMAIN.LOCAL`

- Click search

On **Forest**, this showed:

```fallback
svc-alfresco → Service Accounts → Privileged IT Accounts → Account Operators
→ GenericAll over Exchange Windows Permissions
→ WriteDACL over HTB.LOCAL domain
```

Five levels deep through groups. You don't see that without BloodHound.

### 2. Kerberoastable Users

```fallback
MATCH (u:User) WHERE u.hasspn=true RETURN u
```

Or the built-in **"List all Kerberoastable Users"** query from the Analysis tab.

On **Active**, this showed that the Administrator account had an SPN `active/CIFS:445`. Normally you'd Kerberoast a service account, not the real Administrator, but the SPN was there. The password was also weak.

### 3. AS-REP Roastable Users

```fallback
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u
```

Or the built-in **"List all AS-REP Roastable Users"** query.

This is how I found `svc-alfresco` on Forest and `support` on Blackfield.

### 4. Users with DCSync rights

```fallback
MATCH p=(u)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p
```

Shows who can already DCSync without any privilege escalation. If you compromise one of these accounts, go straight to `impacket-secretsdump`.

### 5. Find principals with dangerous permissions

Look at the built-in queries in the **Analysis** tab:

- Shortest path from owned principals

- Find all paths to Domain Admins

- Users with local admin rights

- Group memberships for a specific user

---

## Understanding the Graph — Key Edge Types

When you look at a path in BloodHound, the **edges** (the arrows between nodes) tell you what kind of access someone has. The ones I've actually abused:

### GenericAll

**Full control** over the target object. What you can do:

- Reset the password

- Add to groups

- Modify attributes

- Set SPN (targeted Kerberoasting)

**On Forest**, the group chain from svc-alfresco gave GenericAll over Exchange Windows Permissions. That meant I could add myself to that group.

### WriteDACL

Ability to **modify the access control list** of the target object. This is the big one. WriteDACL on a domain object means you can grant yourself any permission, including DCSync rights.

**On Forest**, Exchange Windows Permissions had WriteDACL on the HTB.LOCAL domain. I added myself to that group, then used PowerView to grant myself DCSync rights:

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync
```

Then `impacket-secretsdump` pulled every hash in the domain.

### ForceChangePassword

**Change the target user's password** without knowing their current one. With rpcclient:

```bash
rpcclient -U 'support%#00^BlackKnight' $ip
rpcclient $> setuserinfo2 audit2020 23 'Password@1234'
```

**On Blackfield**, `support` had ForceChangePassword over `audit2020`. I changed the password, used audit2020's access to get into the forensic share, and grabbed an LSASS dump.

### Other edges worth knowing

| Edge | Meaning | Abuse |
| --- | --- | --- |
| **GenericWrite** | Can modify attributes | Set SPN → Kerberoast, or set logon script |
| **WriteOwner** | Can take ownership | Take ownership → grant yourself GenericAll |
| **AddMember** | Can add users to a group | Add yourself or a compromised user |
| **ReadLAPSPassword** | Can read the LAPS password | Get that machine's local admin password |
| **AllowedToDelegate** | Kerberos delegation | Constrained/unconstrained delegation attacks |

---

## Attack Paths I've Seen

### Path 1: Nested group abuse → DCSync (Forest)

```fallback
Owned User → Group → Group → Group → GenericAll → Target Group → WriteDACL → Domain
```

**Play:** Add yourself to the group with WriteDACL. Use WriteDACL to grant yourself DCSync rights. Run secretsdump.

### Path 2: ForceChangePassword → lateral movement (Blackfield)

```fallback
Owned User → ForceChangePassword → Target User → access to new resources
```

**Play:** Change the target's password. Log in as them. See what they can access that you couldn't before.

### Path 3: Direct Kerberoasting (Active)

```fallback
Owned User → GetUserSPNs → SPN on Administrator → crack TGS → Domain Admin
```

**Play:** BloodHound shows which high-value accounts have SPNs. If Administrator or another DA account has an SPN, Kerberoast it.

---

## My BloodHound Workflow

Every AD box, same process:

1. **Get one valid credential** — null session, AS-REP Roast, creds in a file, password spray, anything

2. **Run bloodhound-python** with `-c All`

3. **Upload** the JSON files to BloodHound CE

4. **Mark your user as owned** — right click → Mark as Owned

5. **Run pathfinding** — owned user → Domain Admins

6. **Check built-in queries** — Kerberoastable, AS-REP Roastable, DCSync rights

7. **Walk the path** BloodHound shows you

Step 5 is where the magic happens. BloodHound traverses every group membership, ACL, and delegation across the domain in a graph search. It finds paths you'd never find manually.

> **Truth:** I've never done an AD box where BloodHound didn't show me something I'd missed. On Forest, the path went through 5 nested groups. On Blackfield, it showed the ForceChangePassword edge. On Active, it pointed to the Administrator SPN. BloodHound isn't optional. It's the map.

- [Bloodhound](https://heretek.dev/tags/bloodhound/)
- [Active-Directory](https://heretek.dev/tags/active-directory/)
- [Enumeration](https://heretek.dev/tags/enumeration/)
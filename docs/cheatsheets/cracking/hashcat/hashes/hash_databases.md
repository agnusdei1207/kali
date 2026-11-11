# Hashcat 데이터베이스 해시

- 데이터베이스 계정 해시 크래킹 모음 — MySQL323(-m 200), MySQL4.1/5(-m 300), PostgreSQL(-m 12/11100), MSSQL 2005/2012(-m 131/1731/12800), Oracle 7+/12+(-m 3100/12300), Sybase ASE(-m 8000)
- SQL 인젝션·권한 상승으로 DB 사용자 해시(mysql.user, pg_shadow, sys.sql_logins)를 덤프했을 때
- hashcat 설치와 DB별 해시 형식 확인 — DB 해시는 salt 포함이 많아 정확한 모드 확인 필수, Oracle T: Type은 느려 시간 제한 권장

MySQL, PostgreSQL, MSSQL, Oracle 계정 해시.

## MySQL323 (-m 200)

```bash
hashcat -m 200 -a 0 mysql323.txt wordlist.txt
```

## MySQL4.1/5 ($*...) (-m 300)

```bash
hashcat -m 300 -a 0 mysql.txt wordlist.txt
```

## PostgreSQL (-m 12, -m 11100)

```bash
# PostgreSQL MD5 -m 12
hashcat -m 12 -a 0 pgsql.txt wordlist.txt

# PostgreSQL Challenge-Response -m 11100
hashcat -m 11100 -a 0 pgsql_cr.txt wordlist.txt
```

## MSSQL 2005 (-m 131) / 2012+ (-m 1731, 12800)

```bash
# MSSQL 2005 -m 131
hashcat -m 131 -a 0 mssql2005.txt wordlist.txt

# MSSQL 2012+ -m 1731
hashcat -m 1731 -a 0 mssql2012.txt wordlist.txt

# MSSQL 2012, 2014 -m 12800
hashcat -m 12800 -a 0 mssql.txt wordlist.txt
```

## Oracle H: Type (-m 3100) / T: Type (-m 12300)

```bash
# Oracle 7+ H: -m 3100
hashcat -m 3100 -a 0 oracle_h.txt wordlist.txt

# Oracle 12+ T: -m 12300
hashcat -m 12300 -a 0 oracle_t.txt wordlist.txt
```

## Sybase ASE (-m 8000)

```bash
hashcat -m 8000 -a 0 sybase.txt wordlist.txt
```

## 해시 추출 예시

```sql
-- MySQL
SELECT user, authentication_string FROM mysql.user;

-- PostgreSQL
SELECT usename, passwd FROM pg_shadow;

-- MSSQL
SELECT name, password_hash FROM sys.sql_logins;
```

## 팁

- DB 해시는 salt 포함이 많음. 정확한 모드 확인 필수
- Oracle T: Type은 느림. 시간 제한 두고 시도
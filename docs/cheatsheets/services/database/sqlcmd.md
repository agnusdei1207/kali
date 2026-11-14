# sqlcmd MSSQL 접속·인증 점검

- sqlcmd — Microsoft SQL Server용 CLI 클라이언트. 이 문서는 go-mssqldb 기반 go-sqlcmd(단일 실행 파일)를 기준으로 접속·인증 점검 흐름을 다룬다.
- 1433 포트 발견 후 SQL 로그인(sa 등)이 수용되는지 확인할 때, 접속 성공 후 @@version·DB 열거로 이어갈 때, 스크립트 파일(-i)로 반복 점검을 돌릴 때.
- Windows 포터블: workspace\services\sqlcmd-windows-amd64\sqlcmd.exe. Linux는 go-sqlcmd 릴리스 바이너리 또는 freetds 계열(tsql)로 대체 가능.

## 기본 명령어 구조

```bash
sqlcmd -S HOST[,PORT] -U USER -P PASSWORD [옵션]
```

## 접속

```bash
sqlcmd -S 10.10.10.10,1433 -U sa -P 'P@ssw0rd'
sqlcmd -S 10.10.10.10 -U appuser -P 'pass' -d AppDB

# Windows 인증 (도메인 세션)
sqlcmd -S 10.10.10.10 -E

# 자체서명 인증서 서버 통과
sqlcmd -S 10.10.10.10,1433 -U sa -P 'pass' -C
```

- -S에서 포트는 콤마로, 명명 인스턴스는 역슬래시(HOST\INSTANCE)로 붙인다.
- go-sqlcmd는 기본적으로 암호화를 요구한다. 자체서명 인증서 서버면 -C(trust server certificate)로 통과하고, 완전 비암호화는 -N false를 쓴다.

## 인증 점검 흐름

```bash
# 1. 접속 가능 여부 (로그인 타임아웃 5초)
sqlcmd -S 10.10.10.10,1433 -U sa -P 'wrongpass' -l 5 -Q "SELECT 1"

# 2. 약한 sa 비밀번호 후보 반복
for p in sa 'password' 'Passw0rd' ''; do
  sqlcmd -S 10.10.10.10,1433 -U sa -P "$p" -l 5 -Q "SELECT 1" >/dev/null 2>&1 && echo "SUCCESS: sa / $p"
done
```

- 쿼리 결과가 출력되고 exit 0면 인증 성공이다. Login failed 에러면 실패다.
- sa 활성화·약한 비밀번호가 첫 대상이고, 도메인 환경은 -E(Windows 인증)와 sysadmin 권한 확인이 이어진다.

## 쿼리 실행 (-Q)

```bash
sqlcmd -S 10.10.10.10,1433 -U sa -P 'pass' -Q "SELECT @@version"
sqlcmd -S 10.10.10.10,1433 -U sa -P 'pass' -Q "SELECT name FROM sys.databases"
sqlcmd -S 10.10.10.10,1433 -U sa -P 'pass' -d AppDB -Q "SELECT name FROM sys.tables"

# 파일 실행, 출력 저장
sqlcmd -S 10.10.10.10,1433 -U sa -P 'pass' -i recon.sql -o result.txt
```

- -Q는 실행 후 즉시 종료, -q는 종료하지 않고 대화형을 유지한다.
- -i는 SQL 파일 입력, -o는 출력 파일이다.

## 접속 후 열거 예시

```bash
# sysadmin 권한 확인
sqlcmd ... -Q "SELECT IS_SRVROLEMEMBER('sysadmin')"

# xp_cmdshell 활성 여부
sqlcmd ... -Q "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"

# 로그인 목록
sqlcmd ... -Q "SELECT name, sysadmin FROM syslogins"
```

## mssql.md와의 역할 구분

- services\database\mssql.md: sqlcmd로 접속한 뒤의 T-SQL 문법 정리(DDL·DML·JOIN·백업·시스템 정보).
- 이 문서(sqlcmd.md): 클라이언트 자체 — 접속 플래그, 인증 점검 절차, 포터블 실행.

## 팁·트러블슈팅

- -E는 현재 도메인 세션 자격으로 trusted connection을 시도한다. 도메인 세션이 없으면 실패한다.
- -l(엘)은 로그인 타임아웃, -t는 쿼리 타임아웃이다. 느린 대상엔 -l 10.
- 명명 인스턴스는 1433이 아닐 수 있다. UDP 1434(SQL Browser) 열거로 인스턴스·포트를 파악한다.
- 접속은 되는데 암호화 에러가 나면 -C 또는 -N false로 구분해 시도한다.

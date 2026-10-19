# Proxychains

개념: TCP 연결을 프록시(SOCKS/HTTP)를 통해 강제로 라우팅해주는 도구. 프록시를 지원하지 않는 도구(nmap, curl 등)를 프록시 뒤로 보낼 때 사용.

## 1. 설치

```bash
# Kali / Debian / Ubuntu
sudo apt update
sudo apt install proxychains4 -y

# (레거시) proxychains (v3)
sudo apt install proxychains -y
```

- `proxychains4` = v4 (권장). 실행 명령은 `proxychains4` 또는 `proxychains` (심볼릭 링크)
- 설정 파일: `/etc/proxychains4.conf` (v4), `/etc/proxychains.conf` (v3)

## 2. 설정 파일 구조

```bash
# /etc/proxychains4.conf

# 동적 체인 (사용 가능한 프록시만 순서대로 시도)  <- 권장
dynamic_chain

# strict_chain   # 모든 프록시 순차 사용 (하나라도 실패 시 중단)
# random_chain   # 랜덤 순서

# DNS 요청도 프록시를 통해 (DNS leak 방지)
proxy_dns

# 타임아웃 (ms)
tcp_read_time_out 15000
tcp_connect_time_out 8000

# 프록시 목록 (맨 아래 [ProxyList])
[ProxyList]
# type  host            port  [user pass]
# http  127.0.0.1      8080
# socks4 127.0.0.1     9050
# socks5 127.0.0.1     1080
```

## 3. 프록시 종류

| 타입 | 용도 | 예시 |
|---|---|---|
| `http` | HTTP 프록시 | Squid(3128), mitmproxy(8080) |
| `socks4` | SOCKS4 프록시 | Tor(9050) |
| `socks5` | SOCKS5 프록시 | SSH 동적 포워딩(-D) |

## 4. 기본 사용법

```bash
# 프록시를 통해 명령 실행
proxychains4 <명령어> [인자...]

# 예시
proxychains4 curl http://ifconfig.me
proxychains4 nmap -sT -Pn -p 80,443 10.0.0.5
proxychains4 ssh user@10.0.0.5
```

- `proxychains` (v3) / `proxychains4` (v4) 둘 다 동작. v4 권장.

## 5. Squid HTTP 프록시(3128)와 연동

Squid는 HTTP 프록시이므로 proxychains의 `http` 타입으로 연결합니다.

### 설정
```bash
# /etc/proxychains4.conf 마지막에 추가
[ProxyList]
http 192.168.199.189 3128
```

### 사용
```bash
# Squid 프록시를 통해 대상 접근
proxychains4 curl http://192.168.199.189/

# 내부망 스캔 (TCP connect 스캔만 가능, SYN 스캔 X)
proxychains4 nmap -sT -Pn -p 80,443,445 10.0.0.0/24
```

⚠️ 주의: Squid는 HTTP 프록시라 SOCKS처럼 모든 TCP를 터널링하지 않습니다. CONNECT 메서드를 허용해야 HTTPS/비HTTP 포트도 가능. Squid 설정에서 `acl SSL_ports`, `http_access allow CONNECT` 확인.

## 6. SSH 동적 포워딩 (SOCKS5) — 가장 안정적인 피벗

```bash
# 1) SSH로 SOCKS5 프록시 생성 (로컬 9050)
ssh -D 9050 -N -f user@<jump_host>

# 2) proxychains 설정
# /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 9050

# 3) 사용
proxychains4 nmap -sT -Pn -p 22,80,443 <internal_target>
```

## 7. Tor와 연동

```bash
# Tor 실행 (9050 포트 SOCKS5)
sudo service tor start

# 설정
[ProxyList]
socks5 127.0.0.1 9050

# 사용
proxychains4 curl https://check.torproject.org
```

## 8. 다중 프록시 체인 (체인)

```bash
# /etc/proxychains4.conf
dynamic_chain
[ProxyList]
socks5 127.0.0.1 9050
http   192.168.199.189 3128
```

- `dynamic_chain`: 살아있는 프록시만 순서대로 통과
- `strict_chain`: 모두 통과해야 함 (하나라도 죽으면 실패)

## 9. 자주 겪는 문제 & 해결

| 문제 | 원인 | 해결 |
|---|---|---|
| `proxychains` 명령 없음 | v4 패키지명 다름 | `apt install proxychains4`, 실행은 `proxychains4` |
| DNS leak | `proxy_dns` 미설정 | 설정 파일에 `proxy_dns` 추가 |
| nmap SYN 스캔 실패 | raw socket은 프록시 불가 | `-sT` (TCP connect) 사용 |
| 연결 느림/타임아웃 | 프록시 지연 | `tcp_connect_time_out` 증가 |
| "Permission denied" | 설정 파일 권한 | `sudo`로 실행 또는 설정 파일 권한 조정 |
| HTTP 프록시에서 HTTPS 실패 | CONNECT 미허용 | 프록시 설정에서 CONNECT 허용 확인 |

## 10. proxychains vs 다른 피벗 도구

| 도구 | 용도 | 특징 |
|---|---|---|
| proxychains | 기존 도구를 프록시 뒤로 | 가장 간단, TCP만 |
| SSH -L / -D | 포트 포워딩/동적 프록시 | 안정적, SOCKS5 제공 |
| chisel | HTTP 터널 | 방화벽 우회에 강함 |
| ligolo-ng | TUN 인터페이스 피벗 | nmap SYN 스캔 가능 (raw) |
| socat | 포트 릴레이 | 단순 릴레이 |

## 11. 실전 예시 (Squid 프록시 피벗)

```bash
# 1) proxychains 설정
sudo sed -i 's/^# dynamic_chain/dynamic_chain/' /etc/proxychains4.conf
# [ProxyList] 섹션에 Squid 추가
echo "http 192.168.199.189 3128" | sudo tee -a /etc/proxychains4.conf

# 2) 내부망 스캔
proxychains4 nmap -sT -Pn -p 22,80,443,445 10.0.0.0/24

# 3) 내부 웹 서비스 접근
proxychains4 curl http://10.0.0.5/

# 4) 내부 SSH 접근
proxychains4 ssh user@10.0.0.5
```

## 12. 한 줄 요약

**proxychains = "프록시를 모르는 도구도 프록시 뒤로 보내는 래퍼"**. 설정 파일에 프록시 등록 → 명령 앞에 `proxychains4` 붙이면 끝. nmap은 반드시 `-sT` 사용.
```

Let me write this file.<|end|><|start|>助手 to=write<|channel|>analysis <|constrain|>xml<|message|><rfl:parameter name="path">
C:\workspace\kali\docs\cheatsheets\05-lateral-movement\pivoting\proxy\proxychains.md
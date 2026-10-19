# Proxychains 치트시트

개념: TCP 연결을 프록시(SOCKS/HTTP)를 통해 강제로 라우팅해주는 도구. 프록시를 지원하지 않는 도구(nmap, curl 등)를 프록시 뒤로 보낼 때 사용.

## 1. 설치

```bash
# Kali / Debian / Ubuntu
sudo apt update
sudo apt install proxychains4 -y
```

- `proxychains4` = v4 (권장). 실행 명령은 `proxychains4` 또는 `proxychains` (심볼릭 링크)
- 설정 파일: `/etc/proxychains4.conf` (v4), `/etc/proxychains.conf` (v3)

## 2. 기본 사용법

```bash
# 프록시를 통해 명령 실행
proxychains4 <명령어> [인자...]

# 예시
proxychains4 curl http://ifconfig.me
proxychains4 nmap -sT -Pn -p 80,443 10.0.0.5
proxychains4 ssh user@10.0.0.5
```

## 3. 설정 파일 구조

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

## 4. 프록시 종류

```bash
# HTTP 프록시 (Squid, mitmproxy 등)
http  192.168.1.10  3128

# SOCKS4 프록시 (Tor 등)
socks4  127.0.0.1  9050

# SOCKS5 프록시 (SSH 동적 포워딩 등)
socks5  127.0.0.1  1080
```

## 5. Squid HTTP 프록시(3128)와 연동

```bash
# /etc/proxychains4.conf 마지막에 추가
[ProxyList]
http 192.168.199.189 3128
```

```bash
# Squid 프록시를 통해 대상 접근
proxychains4 curl http://192.168.199.189/

# 내부망 스캔 (TCP connect 스캔만 가능, SYN 스캔 X)
proxychains4 nmap -sT -Pn -p 80,443,445 10.0.0.0/24
```

- Squid는 HTTP 프록시라 SOCKS처럼 모든 TCP를 터널링하지 않습니다. CONNECT 메서드를 허용해야 HTTPS/비HTTP 포트도 가능. Squid 설정에서 `acl SSL_ports`, `http_access allow CONNECT` 확인.

## 6. SSH 동적 포워딩 (SOCKS5) 피벗

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

## 8. 다중 프록시 체인

```bash
# /etc/proxychains4.conf
dynamic_chain
[ProxyList]
socks5 127.0.0.1 9050
http   192.168.199.189 3128
```

- `dynamic_chain`: 살아있는 프록시만 순서대로 통과
- `strict_chain`: 모두 통과해야 함 (하나라도 죽으면 실패)

## 9. 실전 예시 (Squid 프록시 피벗)

```bash
# 1) proxychains 설정
sudo sed -i 's/^# dynamic_chain/dynamic_chain/' /etc/proxychains4.conf
echo "http 192.168.199.189 3128" | sudo tee -a /etc/proxychains4.conf

# 2) 내부망 스캔
proxychains4 nmap -sT -Pn -p 22,80,443,445 10.0.0.0/24

# 3) 내부 웹 서비스 접근
proxychains4 curl http://10.0.0.5/

# 4) 내부 SSH 접근
proxychains4 ssh user@10.0.0.5
```

## 10. 자주 겪는 문제

```bash
# proxychains 명령 없음 → v4 패키지명 다름
sudo apt install proxychains4
# 실행은 proxychains4

# DNS leak → proxy_dns 미설정
# 설정 파일에 proxy_dns 추가

# nmap SYN 스캔 실패 → raw socket은 프록시 불가
proxychains4 nmap -sT -Pn -p 80,443 <target>   # -sT (TCP connect) 사용

# 연결 느림/타임아웃 → 프록시 지연
# tcp_connect_time_out 값 증가 (ms)

# HTTP 프록시에서 HTTPS 실패 → CONNECT 미허용
# 프록시 설정에서 CONNECT 허용 확인
```

## 10.1 현재 상황 문제 해결 (Tor 9050 → Squid 3128)

proxychains 실행 시 `Strict chain ... 127.0.0.1:9050 ... timeout`이 뜨면 Tor 설정이 남아있는 것. Squid로 전환 필요.

```bash
# 1) 현재 프록시 목록 확인
grep -n "ProxyList" -A 5 /etc/proxychains4.conf

# 2) vim으로 Tor 라인 주석 처리
#   sudo vim /etc/proxychains4.conf
#   /9050  → 9050 라인 검색
#   I#     → 줄 맨 앞에 # 입력 후 Esc
#   G      → 파일 맨 아래로 이동
#   o      → 새 줄 입력 모드
#   http 192.168.199.189 3128  입력 후 Esc
#   :wq    → 저장 후 종료

# 3) 확인
tail -3 /etc/proxychains4.conf
```

- 포트 80은 닫혀있으므로 `curl http://192.168.199.189/`는 Squid가 ERR_CONNECT_FAIL 반환. 3128이나 내부 IP로 테스트.

## 11. 현재 상황 활용 예시 (Squid 프록시 피벗)

대상: 192.168.199.189 (Squid 3128 오픈, 80/443 닫힘). 프록시를 통해 내부망으로 피벗.

```bash
# 1) proxychains 설정 (Squid를 HTTP 프록시로 등록)
sudo sed -i 's/^# dynamic_chain/dynamic_chain/' /etc/proxychains4.conf
echo "http 192.168.199.189 3128" | sudo tee -a /etc/proxychains4.conf
grep -v '^#' /etc/proxychains4.conf | grep -v '^$'

# 2) 프록시 동작 확인
proxychains4 curl -s http://ifconfig.me

# 3) 내부망 호스트/포트 스캔 (TCP connect만 가능)
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389 10.0.0.0/24

# 4) 내부 웹 서비스 접근
proxychains4 curl -s http://10.0.0.5/

# 5) 내부 SSH 접근
proxychains4 ssh user@10.0.0.5

# 6) 내부 SMB 접근 (creds 획득 후)
proxychains4 smbclient //10.0.0.5/share -U user%pass
```

- nmap은 반드시 `-sT` (TCP connect) 사용. SYN 스캔(`-sS`)은 raw socket이라 프록시 통과 불가.
- Squid가 CONNECT를 허용하지 않으면 HTTPS/비HTTP 포트 접근 실패. Squid 설정 확인.

## 12. 관련 도구

- chisel: HTTP 터널, 방화벽 우회에 강함
- ligolo-ng: TUN 인터페이스 피벗, nmap SYN 스캔 가능 (raw)
- socat: 단순 포트 릴레이
- 다음: 피벗 후 내부망 스캔 및 서비스 열거

---

공식 문서: https://github.com/rofl0r/proxychains-ng

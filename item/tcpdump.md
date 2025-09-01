# tcpdump 실용적인 사용법 (OSCP 시험용)

## 기본 형식

```bash
# check interface
ip a s

tcpdump [옵션] [필터 표현식]
```

## 실전 명령어 모음

### 1. 특정 인터페이스 트래픽 캡처

```bash
# 인터페이스 목록 확인
tcpdump -D

# tun0 인터페이스의 트래픽 캡처 (VPN 연결)
tcpdump -i tun0

# eth0 인터페이스의 트래픽 캡처
tcpdump -i eth0
```

### 2. HTTP 트래픽 분석 (웹 취약점 찾기)

```bash
# HTTP 트래픽만 캡처하여 페이로드 확인 (-A: ASCII 출력)
tcpdump -i eth0 -A 'tcp port 80'

# HTTP 트래픽 중 특정 키워드 포함된 패킷만 필터링 (예: 패스워드)
tcpdump -i eth0 -A 'tcp port 80' | grep -i "pass"

# HTTP 헤더와 쿠키 정보 캡처 (XSS, CSRF 토큰 등 확인)
tcpdump -i eth0 -A 'tcp port 80' | grep -i -E "cookie:|set-cookie:|auth:|jwt:"
```

### 3. 패킷 저장 및 분석

```bash
# 패킷을 파일로 저장 (나중에 Wireshark로 분석 가능)
tcpdump -i eth0 -w capture.pcap 'host 10.10.10.10'

# 저장된 패킷 파일 분석
tcpdump -r capture.pcap -A

# 패킷 캡처와 동시에 화면에도 출력 (-l: 라인 버퍼링)
tcpdump -i eth0 -l -A 'host 10.10.10.10' | tee capture.txt
```

### 4. 리버스 쉘 트래픽 모니터링

```bash
# 특정 포트로 들어오는 연결 탐지 (리버스 쉘 포트 확인)
tcpdump -i tun0 'tcp port 4444'

# 네트워크 스캔 탐지 (들어오는 포트 스캔 확인)
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'
```

### 5. SMB/LDAP 트래픽 분석 (윈도우 시스템 공격)

```bash
# SMB 트래픽 캡처 (ID와 패스워드 해시 획득 가능)
tcpdump -i eth0 -s0 'port 445'

# LDAP 트래픽 캡처
tcpdump -i eth0 -s0 'port 389'
```

### 6. DNS 정보 유출 탐지

```bash
# DNS 쿼리 캡처 및 분석
tcpdump -i eth0 -A 'udp port 53'

# DNS 존 트랜스퍼 캡처
tcpdump -i eth0 -A '(tcp port 53) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

### 7. 특정 호스트 타겟팅

```bash
# 특정 IP 주소와의 모든 통신 캡처
tcpdump -i eth0 'host 10.10.10.10'

# 특정 소스 IP에서 오는 트래픽만 캡처
tcpdump -i eth0 'src host 10.10.10.10'

# 특정 타겟 IP로 가는 트래픽만 캡처
tcpdump -i eth0 'dst host 10.10.10.10'
```

### 8. 다양한 프로토콜 분석

```bash
# SSH 트래픽 캡처 (키교환, 인증 시도)
tcpdump -i eth0 'tcp port 22'

# FTP 트래픽 캡처 (파일 업로드/다운로드)
tcpdump -i eth0 -A 'tcp port 21'
```

### 9. 고급 필터링

```bash
# TCP SYN 패킷만 캡처 (포트 스캔 감지)
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and not tcp[tcpflags] & (tcp-ack) != 0'

# ACK 패킷만 캡처
tcpdump -i tun0 'tcp[tcpflags] & (tcp-ack) != 0'

# ICMP 패킷만 캡처 (ping 명령어)
tcpdump -i eth0 'icmp'
```

### 10. 패킷 제한 및 출력 형식 지정

```bash
# 특정 개수의 패킷만 캡처 (-c 옵션)
tcpdump -i eth0 -c 100 'host 10.10.10.10'

# 타임스탬프 형식 지정 (-t 옵션)
tcpdump -i eth0 -tttt 'host 10.10.10.10'  # YYYY-MM-DD HH:MM:SS.ms 형식

# 패킷 헤더만 표시 (페이로드 제외)
tcpdump -i eth0 'host 10.10.10.10'
```

## 자주 사용하는 옵션 정리

| 옵션                         | 설명                                                 |
| ---------------------------- | ---------------------------------------------------- |
| `-i`                         | 패킷을 캡처할 인터페이스 지정                        |
| `-A`                         | ASCII 형태로 패킷 내용 출력 (웹 트래픽 분석 시 유용) |
| `-X`                         | 16진수와 ASCII 형식으로 출력 (바이너리 데이터 분석)  |
| `-n`                         | IP 주소를 호스트명으로 변환하지 않음 (더 빠른 출력)  |
| `-nn`                        | IP 주소와 포트를 변환하지 않음                       |
| `-v`, `-vv`, `-vvv`          | 상세 출력 수준 (verbose)                             |
| `-c`                         | 지정한 개수의 패킷만 캡처                            |
| `-s`                         | 패킷 스냅샷 길이 (0=전체 패킷)                       |
| `-w`                         | 캡처한 패킷을 파일로 저장                            |
| `-r`                         | 저장된 패킷 파일 읽기                                |
| `-l`                         | 라인 버퍼링 모드 (파이프라인에서 유용)               |
| `-t`, `-tt`, `-ttt`, `-tttt` | 타임스탬프 형식 지정                                 |

## 실전 필터 표현식 모음

| 필터                             | 설명                         |
| -------------------------------- | ---------------------------- |
| `host 10.10.10.10`               | 특정 호스트와의 통신         |
| `net 10.10.10.0/24`              | 특정 네트워크 대역과의 통신  |
| `port 80`                        | 특정 포트와의 통신           |
| `src host 10.10.10.10`           | 특정 소스 IP에서 오는 트래픽 |
| `dst host 10.10.10.10`           | 특정 목적지 IP로 가는 트래픽 |
| `tcp port 80 or tcp port 443`    | HTTP 또는 HTTPS 트래픽       |
| `tcp[tcpflags] & (tcp-syn) != 0` | SYN 플래그 포함 패킷         |
| `greater 100`                    | 100바이트보다 큰 패킷        |
| `less 60`                        | 60바이트보다 작은 패킷       |

## 실전 활용 시나리오

### 1. 계정 정보 캡처하기

```bash
# HTTP Basic 인증 정보 캡처
tcpdump -i tun0 -A | grep -i "Authorization: Basic"

# POST 요청에서 패스워드 캡처
tcpdump -i tun0 -A 'tcp port 80' | grep -i "POST" -A 10
```

### 2. 타겟 정찰

```bash
# 타겟 서버가 통신하는 다른 호스트 확인
tcpdump -i tun0 -nn 'src host 10.10.10.10' | awk '{print $5}' | sort | uniq
```

### 3. C2 서버 통신 탐지

```bash
# 불규칙적인 TCP 통신 패턴 탐지 (C2 서버 탐지)
tcpdump -i tun0 -nn 'tcp and (tcp[tcpflags] & (tcp-push) != 0)'
```

### 4. 웹쉘 트래픽 탐지

```bash
# 비정상적인 User-Agent 탐지 (웹쉘 탐지)
tcpdump -i tun0 -A 'tcp port 80' | grep -i "user-agent:"
```

# tcpdump 핵심 사용법

apt install tcpdump

## 기본 사용법

```bash
apt install iproute2
ip a s
apt install net-tools
ifconfig

tcpdump -i [인터페이스] [필터]
```

## 주요 옵션

- `-i` : 인터페이스 지정
- `-A` : ASCII로 패킷 내용 출력
- `-n` : IP/포트 해석 안함 (빠름)
- `-w` : 파일로 저장
- `-r` : 파일에서 읽기
- `-s [number]` : 패킷 길이 0 -> 전체 캡쳐

## 실전 명령어

### HTTP 트래픽 모니터링

```bash
# HTTP 패킷 내용 확인
sudo tcpdump -i tun0 -A 'tcp port 80'
# 파일에서 찾기
tcpdump -r traffic.pcap src host 192.168.124.1 -n | wc
# 패스워드 찾기
tcpdump -i tun0 -A 'tcp port 80' | grep -i "pass"

tcpdump -i eth0 tcp and host 192.168.65.3 and port 80
tcpdump -i eth0 'tcp or udp'
tcpdump -i eth0
tcpdump -i eth0 'ip'
tcpdump -i any tcp port 22
tcpdump -r traffic.pcap icmp -n | wc -l
sudo tcpdump -r traffic.pcap arp and host 192.168.124.137
sudo tcpdump -r traffic.pcap port 53 -c 1
sudo tcpdump -r traffic.pcap 'tcp[tcpflags] == tcp-rst' | wc -l
sudo tcpdump -r traffic.pcap greater 15000 -n

# arp
sudo tcpdump -r traffic.pcap arp -e

# Show packets in both hexadecimal and ASCII formats
tcpdump -r TwoPackets.pcap -X
```

### 특정 호스트 모니터링

```bash
# 특정 IP 모든 트래픽
tcpdump -i tun0 host 10.10.10.10

# 특정 소스/목적지 IP
tcpdump -i tun0 src host 10.10.10.10
tcpdump -i tun0 dst host 10.10.10.10

# 파일로 저장
tcpdump -i tun0 -w capture.pcap host 10.10.10.10
```

### 리버스 쉘 탐지

```bash
# 특정 포트 모니터링
sudo tcpdump tcp port 22
```

### 주요 서비스 모니터링

```bash
# SMB
tcpdump -i tun0 port 445

# DNS
tcpdump -i tun0 port 53

# SSH
tcpdump -i tun0 port 22
```

## 자주 쓰는 필터

```bash
host 10.10.10.10             # 특정 호스트
src host 10.10.10.10         # 출발지 IP
dst host 10.10.10.10         # 목적지 IP
port 80                      # 특정 포트
tcp port 80 or tcp port 443  # HTTP/HTTPS
```

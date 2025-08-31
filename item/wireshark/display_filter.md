## IP

```wireshark
ip.addr == 192.168.0.10        # 특정 IP (src/dst 모두)
ip.src == 192.168.0.1          # 출발지 IP
ip.dst == 8.8.8.8              # 목적지 IP
```

## Port

```wireshark
tcp.port == 80                 # TCP 포트 80
udp.port == 53                 # UDP 포트 53
tcp.port >= 1000 && tcp.port <= 2000   # 포트 범위
```

## Protocol

```wireshark
http                           # HTTP
dns                            # DNS
tls                            # TLS/SSL
icmp                           # ICMP
```

## 문자열 검색

```wireshark
frame contains "hash"          # 패킷 전체에서 문자열
tcp contains "password"        # TCP 페이로드
http.request.uri contains "login"
dns.qry.name contains "example.com"
frame.number == 38 # 38번째
```

## 논리 연산

```wireshark
&&   # AND
||   # OR
!    # NOT
```

예:

```wireshark
ip.src == 192.168.0.1 && tcp.port == 443
ip.src == 192.168.0.1 || ip.src == 192.168.0.2
!arp
```

## 기타

```wireshark
frame.len >= 200               # 패킷 길이 200 이상
eth.addr == aa:bb:cc:dd:ee:ff  # 특정 MAC 주소
icmp.type == 8                 # ICMP Echo Request
http.user_agent contains "Mozilla"
```

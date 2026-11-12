# arp-scan을 이용한 로컬 네트워크 호스트 발견

- arp-scan — ARP 요청을 각 IP에 날려 MAC 주소로 응답하는 호스트만 찾는 L2 스캐너. 호스트 방화벽이 ICMP를 막아도 ARP는 커널이 무조건 답하므로 서브넷 안쪽 호스트 발견에 가장 확실하다.
- 로컬 네트워크(동일 브로드캐스트 도메인)의 살아있는 호스트와 MAC 벤더를 뽑아낼 때. ping 스캔이 조용한 세그먼트의 실제 호스트 수를 확인할 때.
- kali 기본 포함(없으면 sudo apt install arp-scan). ARP는 라우터를 못 넘으므로 같은 서브넷 대상에만 유효하고 sudo가 필요하다.

## 기본 사용법

```bash
sudo arp-scan -l
sudo arp-scan -l --interface=eth0
sudo arp-scan --localnet
```

- `-l`(=--localnet)은 현재 인터페이스의 IP와 넷마스크를 읽어 자동으로 대역 전체를 스캔한다.

## 특정 대역·인터페이스 지정

```bash
sudo arp-scan -I eth0 192.168.1.0/24
sudo arp-scan -I wlan0 --localnet
sudo arp-scan 10.10.10.1 10.10.10.2 10.10.10.3
```

## 주요 옵션

- `-l, --localnet`: 인터페이스 설정 기준 로컬 대역 전체 스캔.
- `-I, --interface=eth0`: 사용할 인터페이스 지정. 테더링·랜이 함께 붙은 멀티홈 환경에서는 반드시 명시한다.
- `-r, --retry=5`: 응답 없는 호스트 재시도 횟수(기본 2). 무선처럼 유실이 잦은 망에서 올린다.
- `-t, --timeout=500`: 호스트별 응답 대기 밀리초(기본 500).
- `-q, --quiet`: IP와 MAC만 출력.

## 출력 해석

```bash
sudo arp-scan -l --retry=3
# 응답한 IP와 MAC, MAC 뒤 벤더 문자열로 장비 종류를 추정한다
# Apple, Dell, VMware, Raspberry Pi Foundation 같은 벤더가 바로 보인다
```

- 하나의 MAC에 여러 IP가 붙어 있으면 가상화 호스트·브리지일 가능성이 높다.
- 하나의 IP에 여러 MAC이 응답하면 이중화(HSRP/VRRP) 구간이나 ARP 스푸핑 의심 구간이다.

## netdiscover와 비교

- netdiscover도 ARP 기반이라는 점은 같지만, 패시브 모드(-p)로 망 트래픽을 엿듣며 수집하는 기능이 있다.
- 정확한 대역 스캔과 벤더 판별은 arp-scan, 패시브 스니핑 병행이나 빠른 훓기는 netdiscover가 편하다.

```bash
sudo netdiscover -r 192.168.1.0/24 -i eth0
```

## 팁과 트러블슈팅

- 인터페이스를 잘못 잡으면 "ARP ping of ... failed"가 나온다. ip a로 인터페이스와 서브넷을 먼저 확인한다.
- 결과에 DHCP 대역의 게이트웨이·호스트만 나온다면 VLAN이 나뉜 것이다. 각 VLAN 인터페이스마다 따로 돌려야 한다.
- 무선 인터페이스(wlan0)에서는 프레임 유실로 누락이 생길 수 있다. -r과 -t 값을 올려 재시도를 늘린다.

# masscan을 이용한 초고속 포트 스캔

- masscan — 자체 TCP/IP 스택으로 SYN 패킷을 쏘아 인터넷 전체급 범위도 분 단위로 스캔하는 초고속 포트 스캐너. SYN 스캔만 지원하며, SYN+ACK 응답이면 포트 열림, RST면 닫힘으로 판단한다.
- 65,536개 전체 포트나 /8 대역을 빠르게 훑어 열린 포트만 뽑아낼 때. 정밀한 서비스·버전 정보는 nmap이 이어서 담당한다.
- kali: sudo apt install masscan. Windows는 Visual Studio(VS10 프로젝트)나 MinGW로 직접 빌드해야 하며 패킷 전송에 Npcap(WinPcap 호환) 드라이버가 필요하다.

## 기본 사용법

```bash
sudo masscan -p80,443 --rate 1000 192.168.1.0/24
sudo masscan -p1-65535 --rate 10000 -oG scan.gnmp 10.0.0.0/8
```

- 포트는 -p 뒤에 콤마·범위로 지정한다(-p0-65535가 전체). 생략 불가다 — masscan에는 기본 포트 세트가 없다.
- 대상은 IP/CIDR만 지원하고 DNS 이름은 안 된다.

## 주요 옵션

- `--rate 10000`: 초당 패킷 수. 기본 100. 내부망은 1만 이하에서 시작하고, 회선·장비 상태를 보며 올린다.
- `--exclude 192.168.1.1`: 스캔에서 제외할 IP·대역. --excludefile exclude.txt로 목록 파일도 된다. 라우터·프린터 같은 장비 IP는 반드시 제외한다.
- `--banners`: 열린 포트에 실제로 접속해 서비스 배너까지 수집. 속도가 나빠진다.
- `--source-ip 192.168.1.200`: 위조 출발지 IP. 응답이 이 IP로 돌아오므로 스캐너가 그 IP를 가져야 한다.
- `--adapter-port 61000`: 출발지 포트 지정. 방화벽 우회용.
- `-oG scan.gnmp`: nmap grepable 출력. -oX(xml), -oJ(json), -oL(리스트)도 지원.

## SYN 스캔 원리와 nmap과의 차이

```bash
# masscan은 항상 -sS -Pn -n 이 켜져 있다 (SYN 스캔, 핑 생략, DNS 역방향 생략)
masscan --nmap   # nmap과 겹치는 옵션 목록을 보여준다
```

- masscan은 커널을 우회해 raw socket으로 자체 스택에서 SYN을 쏜다. 그래서 nmap보다 수십~수백 배 빠르지만 버전 탐지·스크립트는 없다.
- 운용 방식: masscan으로 열린 포트를 뽑고, nmap -sV -sC -p<포트> 로 상세 조사를 넘긴다.

```bash
masscan -p1-65535 --rate 5000 10.10.10.1 -oJ m.json
nmap -sV -sC -p80,443,3306 10.10.10.1
```

## 팁과 트러블슈팅

- rate를 무리하게 올리면 라우터·구형 스위치·프린터가 다운될 수 있다. 내부망에서는 낮은 rate에서 시작해 점차 올리고 장비 IP는 --exclude로 뺀다.
- 결과가 비어 보이면 대부분 방화벽이 응답을 무시하거나 rate가 회선을 초과해 응답이 유실된 경우다. rate를 낮추고 재시도한다.
- Windows와 VM 환경은 초당 30만 패킷 정도가 성능 한계다. Linux 실물에서만 160만 pps에 도달한다.
- 스캔 설정을 재사용하려면 --echo > masscan.conf로 덤프한 뒤 -c masscan.conf로 불러온다.

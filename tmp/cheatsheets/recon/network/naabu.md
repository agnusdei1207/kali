# naabu를 이용한 빠른 포트 스캔

- naabu — ProjectDiscovery의 SYN 기반 포트 스캐너. Go로 만들어져 호스트 목록을 stdin으로 받아 병렬로 빠르게 포트를 스캔하고, -nmap-cli로 nmap 후속 조사까지 이어준다.
- 수백~수천 개 호스트의 열린 포트를 nmap보다 빠르게 뽑을 때. subfinder -> dnsx -> naabu -> httpx/nmap 파이프라인의 포트 스캔 단계.
- naabu 2.7.0 기준. kali: sudo apt install naabu, Windows는 workspace\recon\naabu\naabu.exe. SYN 스캔은 raw socket 권한이 필요하므로 Linux에선 sudo, Windows에선 관리자 콘솔로 실행한다.

## 기본 사용법

```bash
naabu -host 10.10.10.1
naabu -host 10.10.10.0/24 -p 80,443,8000-9000 -silent
naabu -list hosts.txt -top-ports 100 -silent -o ports.txt
```

## 주요 옵션

- `-host`: 대상 IP·CIDR·도메인. 콤마로 다중 지정, -list로 파일 입력.
- `-p 80,443,8000-9000`: 스캔할 포트 지정. 생략하면 상위 100개 포트를 스캔한다.
- `-top-ports 1000`: nmap식 빈도 기준 상위 N개 포트만 스캔.
- `-silent`: 결과만 출력. 파이프 연계에 필수.
- `-nmap-cli 'nmap -sV -sC'`: 찾은 포트를 그대로 nmap 명령에 넘겨 상세 스캔을 자동 실행.
- `-o ports.txt`: 결과 저장. host:port 형식으로 나온다.
- `-exclude-cdn`: CDN(WAF) IP로 확인된 호스트를 포트 스캔에서 제외.

## nmap과의 역할 분담

```bash
# 1) naabu: 빠르게 열린 포트만
naabu -host 10.10.10.1 -top-ports 1000 -silent -o ports.txt
# 2) nmap: 나온 포트만 정밀 조사
nmap -sV -sC -p80,443,8080 10.10.10.1
# 3) 한 방에 연결: naabu 결과를 nmap이 바로 받도록
naabu -host 10.10.10.1 -top-ports 100 -silent -nmap-cli 'nmap -sV -sC'
```

- naabu는 어디 열렸는지만 빨리 알려주는 도구고, 서비스·버전·스크립트 판정은 nmap의 몫이다. 대역 스캔에서 이 둘을 나누면 소요 시간이 크게 줄어든다.

## 파이프라인 연계

```bash
subfinder -d example.com -all -silent | dnsx -silent | naabu -top-ports 100 -silent | httpx-toolkit -title -status-code
```

## 팁과 트러블슈팅

- 관리자 권한 없이 실행하면 SYN 스캔 대신 CONNECT(완전 접속) 스캔으로 느려진다. 권한을 먼저 확인한다.
- 호스트 방화벽이 SYN에 응답하지 않는 대상은 naabu 결과가 비게 된다. 결과가 비었다고 해당 포트가 닫혔다는 확신은 아니다. 의심 대상은 nmap -sT로 재확인한다.
- Windows에서는 naabu.exe를 관리자 PowerShell에서 실행해야 pcap 기반 스캔이 정상 동작한다.

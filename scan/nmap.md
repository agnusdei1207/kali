## 주요 옵션 설명

- `-sS` : SYN 스캔 (Stealth Scan, 빠르고 흔적이 적음)
- `-sT` : TCP Connect 스캔 (SYN 불가 시 사용)
- `-sU` : UDP 스캔 (UDP 서비스 탐지)
- `-sV` : 서비스 버전 탐지
- `-O` : 운영체제(OS) 탐지
- `-A` : 종합 정보 수집 (OS, 버전, 스크립트, traceroute 등)
- `-sC` : 기본 NSE 스크립트 실행
- `--script=<name>` : 특정 NSE 스크립트 실행 (예: `--script=vuln`)
- `-p <포트>` : 특정 포트 지정 (예: `-p 80,443,8080`)
- `-p-` : 모든 포트(1-65535) 스캔
- `-T<0-5>` : 스캔 속도 조절 (0: 느림, 5: 매우 빠름)
- `-Pn` : Ping 없이 스캔 (ICMP 차단 우회)
- `-F` : 빠른 스캔 (기본 포트만)
- `-iL <파일>` : 타겟 목록 파일로 지정
- `-oN <파일>` : 결과를 일반 텍스트로 저장
- `-oX <파일>` : 결과를 XML로 저장
- `-oA <prefix>` : 모든 포맷으로 저장
- `-D <decoy>` : Decoy IP 사용 (탐지 우회)
- `-f` : 패킷 fragment (IDS/IPS 우회)
- `--source-port <포트>` : 소스 포트 지정
- `--reason` : 포트 상태의 이유 출력
- `-vv` : 상세 출력 (verbose)
- `--open` : 열린 포트만 출력
- `--top-ports <N>` : 가장 많이 사용되는 N개 포트만 스캔

---

nmap -sS -sV -sC -Pn --open -p- -T4 -oN full_tcp.txt 10.10.11.68
nmap -p- -T4 -Pn --open 10.10.11.68 -oG open_ports.grep

nmap -sU -Pn --top-ports 200 --open -T4 -oN udp.txt 10.10.11.68
